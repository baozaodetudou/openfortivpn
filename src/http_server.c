/*
 *  Copyright (c) 2025 Rainer Keller
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "http_server.h"
#include "config.h"
#include "http.h"
#include "log.h"
#include "tunnel.h"
#include "saml_policy.h"
#include <openssl/crypto.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <unistd.h>

#include <ctype.h>
#include <string.h>
#include <time.h>

static void print_url(const struct vpn_config *cfg)
{
	char *encoded_realm = NULL;
	char realm[] = "&realm=";
	char *url = NULL;

	// Desired string is
	// https://company.com:port/remote/saml/start?redirect=1(&realm=<str>)
	// with the realm being optional
	static const char uri_pattern[] =
	        "https://%s:%d/remote/saml/start?redirect=1%s%s";

	if (cfg->realm[0] != '\0') {
		// url_encode requires three times the size
		encoded_realm = malloc(strlen(cfg->realm) * 3 + 1);
		if (!encoded_realm) {
			log_error("malloc: %s\n", strerror(errno));
			goto end;
		}
		url_encode(encoded_realm, cfg->realm);
	} else {
		encoded_realm = malloc(1);
		if (!encoded_realm) {
			log_error("malloc: %s\n", strerror(errno));
			goto end;
		}
		encoded_realm[0] = 0;
		realm[0] = 0; // Make realm appear empty when printing as string
	}

	int required_size = 1 + snprintf(NULL,
	                                 0,
	                                 uri_pattern,
	                                 cfg->gateway_host,
	                                 cfg->gateway_port,
	                                 realm,
	                                 encoded_realm);
	url = malloc(required_size);
	if (!url) {
		log_error("malloc: %s\n", strerror(errno));
		goto end;
	}
	snprintf(url,
	         required_size,
	         uri_pattern,
	         cfg->gateway_host,
	         cfg->gateway_port,
	         realm,
	         encoded_realm);

	log_info("Authenticate at '%s'\n", url);

end:
	free(url);
	free(encoded_realm);
}

// Convenience function to send a response with a user readable status message and the
// request URL shown for debug purposes. The response is shown in the user's browser
// after being redirected from the Fortinet Server.
static void send_status_response(int socket, int success,
                                 const char *userMessage)
{
	static const char replyHeader[] = "HTTP/1.1 %s\r\n"
	                                  "Content-Type: text/html\r\n"
	                                  "Content-Length: %zu\r\n"
	                                  "Cache-Control: no-store\r\n"
	                                  "Content-Security-Policy: default-src 'none'\r\n"
	                                  "X-Content-Type-Options: nosniff\r\n"
	                                  "Connection: close\r\n"
	                                  "\r\n";

	static const char replyBody[] = "<!DOCTYPE html>\r\n"
	                                "<html><body>\r\n"
	                                "%s" // User readable message
	                                "</body></html>\r\n";

	char *replyBodyBuffer = NULL;
	char *replyHeaderBuffer = NULL;
	size_t replyBodySize = snprintf(NULL, 0, replyBody, userMessage) + 1;

	replyBodyBuffer = malloc(replyBodySize);
	if (!replyBodyBuffer) {
		log_error("malloc: %s\n", strerror(errno));
		goto end;
	}
	snprintf(replyBodyBuffer, replyBodySize, replyBody, userMessage);

	const char *status = success ? "200 OK" : "400 Bad Request";
	int replyHeaderSize = snprintf(NULL, 0, replyHeader, status,
	                               replyBodySize) + 1;

	replyHeaderBuffer = malloc(replyHeaderSize);
	if (!replyHeaderBuffer) {
		log_error("malloc: %s\n", strerror(errno));
		goto end;
	}
	snprintf(replyHeaderBuffer,
	         replyHeaderSize,
	         replyHeader,
	         status,
	         strlen(replyBodyBuffer));

	// Using two separate writes here to make the code not more complicated assembling
	// the buffers.
	if (write(socket, replyHeaderBuffer, strlen(replyHeaderBuffer)) < 0)
		log_warn("Failed to write: %s\n", strerror(errno));
	if (write(socket, replyBodyBuffer, strlen(replyBodyBuffer)) < 0)
		log_warn("Failed to write: %s\n", strerror(errno));

end:
	free(replyBodyBuffer);
	free(replyHeaderBuffer);
}

static int process_request(int new_socket, unsigned int port, char *id)
{
	log_info("Processing HTTP SAML request\n");

	int flag = 1;

	if (setsockopt(new_socket, IPPROTO_TCP, TCP_NODELAY, &flag,
	               sizeof(flag))) {
		log_error("Failed to set socket options: %s\n", strerror(errno));
		return -1;
	}

	struct timeval timeout = {2, 0};

	if (setsockopt(new_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
	               sizeof(timeout)) != 0 ||
	    setsockopt(new_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout,
	               sizeof(timeout)) != 0)
		return -1;
	char request[OFV_SAML_REQUEST_LIMIT + 1];
	size_t used = 0;
	struct timespec started, current;

	if (clock_gettime(CLOCK_MONOTONIC, &started) != 0)
		return -1;
	while (used < OFV_SAML_REQUEST_LIMIT) {
		if (clock_gettime(CLOCK_MONOTONIC, &current) != 0 ||
		    current.tv_sec - started.tv_sec >= 2)
			break;
		ssize_t got = read(new_socket, request + used,
		                   OFV_SAML_REQUEST_LIMIT - used);

		if (got <= 0)
			break;
		used += (size_t)got;
		request[used] = 0;
		if (memchr(request, 0, used) || strstr(request, "\r\n\r\n"))
			break;
	}
	int valid = saml_parse_request(request, used, port, id,
	                               MAX_SAML_SESSION_ID_LENGTH + 1);

	OPENSSL_cleanse(request, sizeof(request));
	if (valid != 0) {
		log_warn("Rejected invalid SAML callback\n");
		send_status_response(new_socket, 0,
		                     "Invalid SAML redirect. VPN could not be established.");
		return -1;
	}

	send_status_response(new_socket, 1,
	                     "SAML session id received from Fortinet server. VPN will be established...<br>\r\n"
	                     "You may close this browser tab now.<br>\r\n");
	return 0;
}

/**
 * Run a http server to listen for SAML login requests
 *
 * @return 0 in case of success
 *         < 0 in case of error
 */
int wait_for_http_request(struct vpn_config *config)
{
	int server_fd, new_socket;
	struct sockaddr_in address;
	int opt = 1;
	socklen_t addrlen = sizeof(address);

	config->saml_session_id[0] = 0;

	// Creating socket file descriptor
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		log_error("Failed to create socket: %s\n", strerror(errno));
		return -1;
	}

	// Forcefully attaching socket to the port
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt,
	               sizeof(opt))) {
		close(server_fd);
		log_error("Failed to set socket options: %s\n", strerror(errno));
		return -1;
	}

	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons(config->saml_port);

	// Forcefully attaching socket to the port
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		close(server_fd);
		log_error("Failed to bind socket to port %u\n", config->saml_port);
		return -1;
	}

	if (listen(server_fd, 3) < 0) {
		close(server_fd);
		log_error("Failed to listen on socket: %s\n", strerror(errno));
		return -1;
	}

	int max_tries = 5;
	fd_set readfds;
	struct timeval tv;

	log_info("Listening for SAML login on port %u\n", config->saml_port);
	print_url(config);

	while (max_tries > 0) {
		--max_tries;
		FD_ZERO(&readfds);
		FD_SET(server_fd, &readfds);
		// Wait up to ten seconds
		tv.tv_sec = 10;
		tv.tv_usec = 0;

		int retval = select(server_fd + 1, &readfds, NULL, NULL, &tv);

		if (retval == -1) {
			log_error("Failed to wait for connection: %s\n", strerror(errno));
			break;
		} else if (retval > 0) {
			log_debug("Incoming HTTP connection\n");
			new_socket = accept(server_fd,
			                    (struct sockaddr *)&address,
			                    &addrlen);
			if (new_socket < 0) {
				log_error("Failed to accept connection: %s\n",
				          strerror(errno));
				continue;
			}
		} else {
			log_debug("Timeout listening for incoming HTTP connection reached\n");
			continue;
		}

		if ((ntohl(address.sin_addr.s_addr) & 0xff000000u) != 0x7f000000u) {
			close(new_socket);
			continue;
		}
		int result = process_request(new_socket, config->saml_port,
		                             config->saml_session_id);

		close(new_socket);
		if (result == 0)
			break;

		log_warn("Failed to process request\n");
	}

	close(server_fd);

	if (config->saml_session_id[0] == 0) {
		log_error("Finally failed to retrieve SAML authentication token\n");
		return -1;
	}

	return 0;
}
