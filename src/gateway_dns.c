/* Explicit gateway DNS over TCP. No changes to host DNS or VPN TLS identity. */
#include "gateway_dns.h"

#include <openssl/rand.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
typedef int dns_socket;
#define DNS_INVALID_SOCKET (-1)
#define dns_close close
#else
typedef SOCKET dns_socket;
#define DNS_INVALID_SOCKET INVALID_SOCKET
#define dns_close closesocket
#endif

#define DNS_PACKET_MAX 4096
#define DNS_NAME_MAX 254

static uint16_t read_u16(const unsigned char *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static uint64_t now_ms(void)
{
#ifdef _WIN32
	return GetTickCount64();
#else
	struct timespec time;

	clock_gettime(CLOCK_MONOTONIC, &time);
	return (uint64_t)time.tv_sec * 1000 + time.tv_nsec / 1000000;
#endif
}

static int wait_socket(dns_socket socket, int writing, uint64_t deadline)
{
	for (;;) {
		fd_set ready;
		uint64_t now = now_ms();
		struct timeval timeout;
		int result;

		if (now >= deadline)
			return -1;
		timeout.tv_sec = (long)((deadline - now) / 1000);
		timeout.tv_usec = (long)((deadline - now) % 1000) * 1000;
		FD_ZERO(&ready);
		FD_SET(socket, &ready);
		result = select((int)socket + 1, writing ? NULL : &ready,
		                writing ? &ready : NULL, NULL, &timeout);
		if (result > 0)
			return 0;
#ifdef _WIN32
		if (result == SOCKET_ERROR && WSAGetLastError() == WSAEINTR)
#else
		if (result < 0 && errno == EINTR)
#endif
			continue;
		return -1;
	}
}

static int transfer(dns_socket socket, unsigned char *buffer, size_t length,
                     int writing, uint64_t deadline)
{
	while (length) {
		int result;

		if (wait_socket(socket, writing, deadline))
			return -1;
		if (writing) {
			int flags = 0;

#ifdef MSG_NOSIGNAL
			flags = MSG_NOSIGNAL;
#endif
			result = send(socket, (const char *)buffer, (int)length, flags);
		} else {
			result = recv(socket, (char *)buffer, (int)length, 0);
		}
		if (result <= 0) {
#ifdef _WIN32
			int error = WSAGetLastError();

			if (result < 0 && (error == WSAEINTR || error == WSAEWOULDBLOCK))
#else
			if (result < 0 && (errno == EINTR || errno == EAGAIN ||
			                   errno == EWOULDBLOCK))
#endif
				continue;
			return -1;
		}
		buffer += result;
		length -= result;
	}
	return 0;
}

/* Bounded compression traversal rejects pointer cycles and out-of-range labels. */
static int read_name(const unsigned char *packet, size_t length, size_t *offset,
                      char name[DNS_NAME_MAX])
{
	size_t pos = *offset, output = 0;
	int jumped = 0;

	for (size_t steps = 0; steps < length; steps++) {
		unsigned int label;

		if (pos >= length)
			return -1;
		label = packet[pos++];
		if ((label & 0xc0) == 0xc0) {
			if (pos >= length)
				return -1;
			if (!jumped)
				*offset = pos + 1;
			pos = ((label & 0x3f) << 8) | packet[pos];
			jumped = 1;
			continue;
		}
		if (label & 0xc0 || pos + label > length)
			return -1;
		if (!label) {
			if (!jumped)
				*offset = pos;
			name[output] = '\0';
			return 0;
		}
		if (output + label + (output != 0) >= DNS_NAME_MAX)
			return -1;
		if (output)
			name[output++] = '.';
		for (unsigned int i = 0; i < label; i++) {
			unsigned char c = packet[pos++];

			if (!(isalnum(c) || c == '-' || c == '_'))
				return -1;
			name[output++] = (char)tolower(c);
		}
	}
	return -1;
}

static size_t make_query(const char *host, unsigned char *query)
{
	size_t pos = 12, host_len = strlen(host);
	const char *label = host;

	if (host_len && host[host_len - 1] == '.')
		host_len--;
	if (!host_len || host_len > 253 || host[host_len - 1] == '.')
		return 0;
	memset(query, 0, 12);
	if (RAND_bytes(query, 2) != 1)
		return 0;
	query[2] = 1; /* Recursion desired. */
	query[5] = 1; /* One question. */
	while ((size_t)(label - host) < host_len) {
		const char *end = memchr(label, '.', host_len - (label - host));
		size_t len = end ? (size_t)(end - label) : host_len - (label - host);

		if (!len || len > 63)
			return 0;
		query[pos++] = (unsigned char)len;
		for (size_t i = 0; i < len; i++) {
			unsigned char c = (unsigned char)label[i];

			if (!(isalnum(c) || c == '-' || c == '_'))
				return 0;
			query[pos++] = (unsigned char)tolower(c);
		}
		label += len + (end != NULL);
	}
	query[pos++] = 0;
	query[pos++] = 0;
	query[pos++] = 1; /* A */
	query[pos++] = 0;
	query[pos++] = 1; /* IN */
	return pos;
}

static int parse_reply(const unsigned char *reply, size_t length,
                       const unsigned char *query, size_t query_len,
                       struct in_addr *address)
{
	char expected[DNS_NAME_MAX], name[DNS_NAME_MAX];
	size_t qpos = 12, pos = 12, answers_start;
	unsigned int answers;

	if (length < 12 || memcmp(reply, query, 2) ||
	    (read_u16(reply + 2) & 0xfa0f) != 0x8000 ||
	    read_u16(reply + 4) != 1 ||
	    read_name(query, query_len, &qpos, expected) ||
	    read_name(reply, length, &pos, name) || strcmp(name, expected) ||
	    pos + 4 > length || memcmp(reply + pos, query + qpos, 4))
		return -1;
	pos += 4;
	answers_start = pos;
	answers = read_u16(reply + 6);
	if (answers > length / 11)
		return -1;
	/* Follow only CNAMEs rooted at the question, independent of RR order. */
	for (unsigned int hop = 0; hop <= answers && hop < 16; hop++) {
		char alias[DNS_NAME_MAX] = "";
		struct in_addr candidate;
		int found = 0;

		pos = answers_start;
		for (unsigned int i = 0; i < answers; i++) {
			uint16_t type, class, size;

			if (read_name(reply, length, &pos, name) || pos + 10 > length)
				return -1;
			type = read_u16(reply + pos);
			class = read_u16(reply + pos + 2);
			size = read_u16(reply + pos + 8);
			pos += 10;
			if (pos + size > length)
				return -1;
			if (class == 1 && strcmp(name, expected) == 0) {
				if (type == 1 && size == 4 && !found) {
					memcpy(&candidate, reply + pos, 4);
					found = 1;
				} else if (type == 5) {
					size_t end = pos;

					if (read_name(reply, length, &end, alias) ||
					    end != pos + size)
						return -1;
				}
			}
			pos += size;
		}
		if (found && !alias[0]) {
			*address = candidate;
			return 0;
		}
		if (!alias[0] || found)
			return -1;
		strcpy(expected, alias);
	}
	return -1;
}

int gateway_dns_server_valid(const char *dns)
{
	struct in_addr address;
	uint32_t host;

	if (inet_pton(AF_INET, dns, &address) != 1)
		return 0;
	host = ntohl(address.s_addr);
	return (host >> 24) != 0 && (host >> 24) < 224 && host != 0xffffffff;
}

const char *gateway_dns_query(const char *host, const struct sockaddr_in *server,
                              unsigned int timeout_ms, struct in_addr *address)
{
	unsigned char query[512], reply[DNS_PACKET_MAX], frame[2];
	size_t query_len = make_query(host, query), reply_len;
	dns_socket socket_fd;
	uint64_t deadline = now_ms() + timeout_ms;
	int error = 0, result;
	const char *failure = "Gateway DNS query failed or timed out (TCP port 53)";
#ifdef _WIN32
	u_long nonblocking = 1;
	int error_len = sizeof(error);
#else
	socklen_t error_len = sizeof(error);
#endif

	if (!query_len)
		return "Invalid gateway DNS name (use an ASCII hostname or IPv4 address)";
	socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socket_fd == DNS_INVALID_SOCKET)
		return "Could not create gateway DNS socket";
#ifndef _WIN32
	if (socket_fd >= FD_SETSIZE ||
	    fcntl(socket_fd, F_SETFL, O_NONBLOCK) < 0 ||
	    fcntl(socket_fd, F_SETFD, FD_CLOEXEC) < 0)
		goto done;
#ifdef SO_NOSIGPIPE
	{
		int enabled = 1;

		if (setsockopt(socket_fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
		               sizeof(enabled)) != 0)
			goto done;
	}
#endif
#else
	if (ioctlsocket(socket_fd, FIONBIO, &nonblocking) != 0)
		goto done;
#endif
	result = connect(socket_fd, (const struct sockaddr *)server,
	                 sizeof(*server));
	if (result != 0) {
#ifdef _WIN32
		if (WSAGetLastError() != WSAEWOULDBLOCK)
#else
		if (errno != EINPROGRESS)
#endif
			goto done;
	}
	if (wait_socket(socket_fd, 1, deadline) ||
	    getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, (char *)&error,
	               &error_len) || error)
		goto done;
	frame[0] = (unsigned char)(query_len >> 8);
	frame[1] = (unsigned char)query_len;
	if (transfer(socket_fd, frame, 2, 1, deadline) ||
	    transfer(socket_fd, query, query_len, 1, deadline) ||
	    transfer(socket_fd, frame, 2, 0, deadline))
		goto done;
	reply_len = read_u16(frame);
	if (reply_len < 12 || reply_len > sizeof(reply)) {
		failure = "Invalid or oversized gateway DNS response";
		goto done;
	}
	if (transfer(socket_fd, reply, reply_len, 0, deadline))
		goto done;
	if (parse_reply(reply, reply_len, query, query_len, address))
		failure = "Gateway DNS returned no valid matching IPv4 answer";
	else
		failure = NULL;
done:
	dns_close(socket_fd);
	return failure;
}

const char *gateway_dns_resolve(const char *host, const char *dns,
                                struct in_addr *address)
{
	struct sockaddr_in server = {0};
	struct addrinfo hints = {0}, *result = NULL;

	if (inet_pton(AF_INET, host, &server.sin_addr) == 1) {
		*address = server.sin_addr;
		return NULL;
	}
	if (dns[0]) {
		if (!gateway_dns_server_valid(dns))
			return "Gateway DNS must be a unicast IPv4 address";
		server.sin_family = AF_INET;
		server.sin_port = htons(53);
		inet_pton(AF_INET, dns, &server.sin_addr);
		return gateway_dns_query(host, &server, 5000, address);
	}
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, NULL, &hints, &result) != 0 || !result)
		return "Could not resolve gateway using system DNS";
	*address = ((struct sockaddr_in *)result->ai_addr)->sin_addr;
	freeaddrinfo(result);
	return NULL;
}
