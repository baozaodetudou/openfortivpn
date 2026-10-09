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
 *
 *  Windows implementation of the embedded HTTP server for SAML login.
 *  Uses Winsock2 recv/send instead of POSIX read/write.
 */

#ifdef _WIN32

#include "http_server.h"
#include "log.h"
#include "saml_policy.h"
#include <openssl/crypto.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define HTTP_BUF_SIZE (OFV_SAML_REQUEST_LIMIT+1)

static const char http_response[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Cache-Control: no-store\r\n"
        "Content-Security-Policy: default-src 'none'\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: close\r\n\r\n"
        "<html><body><h1>SAML session received</h1><p>Return to the application to check the VPN connection.</p></body></html>";

/*
 * Parse SAML cookie and session ID from the HTTP GET request.
 */
static int parse_saml_request(const char *request, size_t length, struct vpn_config *config)
{
    return saml_parse_request(request, length, config->saml_port,
                              config->saml_session_id, sizeof(config->saml_session_id));
}

int wait_for_http_request(struct vpn_config *config)
{
	SOCKET server_sock = INVALID_SOCKET;
	SOCKET client_sock = INVALID_SOCKET;
	struct sockaddr_in addr;
	char buffer[HTTP_BUF_SIZE];
	int ret = -1;
	int opt = 1;
	fd_set read_fds;
	struct timeval timeout;
    int remaining = 5;
    config->saml_session_id[0] = 0;

	/* Create listening socket */
	server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server_sock == INVALID_SOCKET) {
		log_error("socket: %d\n", WSAGetLastError());
		return -1;
	}

    /* Prevent a second listener from intercepting the same callback port. */
	if (setsockopt(server_sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
	           (const char *)&opt, sizeof(opt)) != 0) goto cleanup;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(config->saml_port);

	if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) ==
	    SOCKET_ERROR) {
		log_error("bind: %d\n", WSAGetLastError());
		goto cleanup;
	}

	if (listen(server_sock, 1) == SOCKET_ERROR) {
		log_error("listen: %d\n", WSAGetLastError());
		goto cleanup;
	}

	log_info("Waiting for SAML login on port %d...\n", config->saml_port);
	log_info("Open http://127.0.0.1:%d in your browser to authenticate.\n",
	         config->saml_port);

	/* Wait for connection with timeout */
	while (remaining-- > 0) {
		FD_ZERO(&read_fds);
		FD_SET(server_sock, &read_fds);
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;

		int sel = select(0, &read_fds, NULL, NULL, &timeout);

		if (sel == SOCKET_ERROR) {
			log_error("select: %d\n", WSAGetLastError());
			goto cleanup;
		}
		if (sel == 0) {
			/* Timeout - check if we should stop */
			continue;
		}

        struct sockaddr_in peer;
        int peer_length = sizeof(peer);
		client_sock = accept(server_sock, (struct sockaddr *)&peer, &peer_length);
		if (client_sock == INVALID_SOCKET)
			continue;
        if ((ntohl(peer.sin_addr.s_addr) & 0xff000000u) != 0x7f000000u) {
            closesocket(client_sock); client_sock = INVALID_SOCKET; continue;
        }
        DWORD socket_timeout = 2000;
        if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&socket_timeout, sizeof(socket_timeout)) != 0 ||
            setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&socket_timeout, sizeof(socket_timeout)) != 0) goto cleanup;

		/* Read HTTP request */
        size_t used = 0;
        ULONGLONG started = GetTickCount64();
        while (used < OFV_SAML_REQUEST_LIMIT && GetTickCount64()-started < 2000) {
            int bytes = recv(client_sock, buffer+used, (int)(OFV_SAML_REQUEST_LIMIT-used), 0);
            if (bytes <= 0) break;
            used += (size_t)bytes;
            buffer[used] = 0;
            if (memchr(buffer, 0, used) || strstr(buffer, "\r\n\r\n")) break;
        }

        if (used > 0) {

			/* Parse and extract cookie/session */
			if (parse_saml_request(buffer, used, config) == 0) {
                OPENSSL_cleanse(buffer, sizeof(buffer));
				/* Send success response */
				send(client_sock, http_response,
				     (int)strlen(http_response), 0);
				closesocket(client_sock);
                client_sock = INVALID_SOCKET;
				ret = 0;
				break;
			}

            static const char denied[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n";
            send(client_sock, denied, (int)strlen(denied), 0);
		}
        OPENSSL_cleanse(buffer, sizeof(buffer));

		closesocket(client_sock);
		client_sock = INVALID_SOCKET;
	}

cleanup:
    OPENSSL_cleanse(buffer, sizeof(buffer));
	if (client_sock != INVALID_SOCKET)
		closesocket(client_sock);
	if (server_sock != INVALID_SOCKET)
		closesocket(server_sock);

	return ret;
}

#endif /* _WIN32 */
