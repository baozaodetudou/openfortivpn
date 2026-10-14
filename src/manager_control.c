#include "manager_control.h"
#include "event.h"
#include "tunnel.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <poll.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#endif

#define CONTROL_LINE_BYTES 4096
static char attempt[37];
static int launch_fd = -1;

int manager_launch_init(const char *descriptor)
{
#ifdef _WIN32
	(void)descriptor;
	return -1;
#else
	char *end;
	long fd;
	struct stat status;

	if (!descriptor || !*descriptor || launch_fd != -1)
		return -1;
	for (const char *p = descriptor; *p; p++)
		if (*p < '0' || *p > '9')
			return -1;
	errno = 0;
	fd = strtol(descriptor, &end, 10);
	if (errno || *end || fd < 3 || fd > INT_MAX
	    || fstat((int)fd, &status) != 0 ||
	    (!S_ISFIFO(status.st_mode) && !S_ISSOCK(status.st_mode)))
		return -1;
	if (fcntl((int)fd, F_SETFD, FD_CLOEXEC) == -1)
		return -1;
	launch_fd = (int)fd;
	return 0;
#endif
}

int manager_launch_wait(void)
{
#ifdef _WIN32
	return 0;
#else
	unsigned char grant = 0;
	int result;
	struct pollfd pipe;

	if (launch_fd == -1)
		return 0;
	pipe.fd = launch_fd;
	pipe.events = POLLIN;
	pipe.revents = 0;
	result = poll(&pipe, 1, 30000);
	result = result > 0 && read(launch_fd, &grant, 1) == 1
	         && grant == 1 ? 0 : -1;
	close(launch_fd);
	launch_fd = -1;
	return result;
#endif
}

int manager_control_init(const char *id)
{
	size_t i;

	if (!id || strlen(id) != 36)
		return -1;
	for (i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (id[i] != '-')
				return -1;
		} else if (!((id[i] >= '0' && id[i] <= '9') ||
		             (id[i] >= 'a' && id[i] <= 'f')))
			return -1;
	}
	memcpy(attempt, id, 37);
	return 0;
}
int manager_control_enabled(void)
{
	return attempt[0] != '\0';
}
const char *manager_control_attempt(void)
{
	return attempt;
}

/* Narrow typed frames avoid feeding a general command/config parser. The
 * inherited anonymous pipe binds the sender; nonce and attempt bind replay.
 */
int manager_control_decode(const char *line, const char *request_id,
                           const char *action, char *response, size_t capacity)
{
	char prefix[160];
	const char *payload;
	size_t length;
	int decoded;
	unsigned char bytes[CONTROL_LINE_BYTES];
	unsigned char canonical[CONTROL_LINE_BYTES];
	int result = -1;

	if (!response || capacity == 0)
		return -1;
	response[0] = '\0';
	if (!line || !request_id || !action || !manager_control_enabled())
		return -1;
	snprintf(prefix, sizeof(prefix), "OFV2 %s %s %s ", attempt, request_id,
	         action);
	if (strncmp(line, prefix, strlen(prefix)) != 0)
		return -1;
	payload = line + strlen(prefix);
	length = strlen(payload);
	if (length == 0 || length > CONTROL_LINE_BYTES - 1 || length % 4)
		return -1;
	for (size_t i = 0; i < length; i++) {
		unsigned char c = (unsigned char)payload[i];

		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		      (c >= '0' && c <= '9') || c == '+' || c == '/' ||
		      (c == '=' && i >= length - 2)))
			return -1;
	}
	decoded = EVP_DecodeBlock(bytes, (const unsigned char *)payload,
	                          (int)length);
	if (decoded < 0)
		goto done;
	if (payload[length - 1] == '=')
		decoded--;
	if (payload[length - 2] == '=')
		decoded--;
	if (decoded <= 0 || (size_t)decoded >= capacity)
		goto done;
	if (EVP_EncodeBlock(canonical, bytes, decoded) != (int)length
	    || memcmp(canonical, payload, length))
		goto done;
	for (int i = 0; i < decoded; i++)
		if (bytes[i] == 0 || bytes[i] == '\r' || bytes[i] == '\n')
			goto done;
	memcpy(response, bytes, (size_t)decoded);
	response[decoded] = '\0';
	result = 0;
done:
	OPENSSL_cleanse(bytes, sizeof(bytes));
	OPENSSL_cleanse(canonical, sizeof(canonical));
	return result;
}

static uint64_t monotonic_ms(void)
{
#ifdef _WIN32
	return GetTickCount64();
#else
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return UINT64_MAX;
	return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
#endif
}

static int read_frame(char *line, size_t capacity,
                      unsigned int timeout_ms)
{
	uint64_t start = monotonic_ms();
	size_t length = 0;

	if (start == UINT64_MAX)
		return -1;
#ifndef _WIN32
	struct stat status;

	if (fstat(STDIN_FILENO, &status) != 0 || (!S_ISFIFO(status.st_mode)
	                && !S_ISSOCK(status.st_mode)))
		return -1;
#endif
	while (monotonic_ms() - start < timeout_ms && length + 1 < capacity) {
		char byte;
#ifdef _WIN32
		HANDLE pipe = GetStdHandle(STD_INPUT_HANDLE);
		DWORD available = 0;
		DWORD consumed = 0;

		if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL))
			return -1;
		if (available == 0) {
			Sleep(25);
			continue;
		}
		if (!ReadFile(pipe, &byte, 1, &consumed, NULL) || consumed != 1)
			return -1;
#else
		struct pollfd pipe = { STDIN_FILENO, POLLIN, 0 };
		int ready = poll(&pipe, 1, 25);
		/* A signal interrupts the pending challenge instead of restarting it. */
		if (ready < 0)
			return -1;
		if (ready == 0)
			continue;
		if (read(STDIN_FILENO, &byte, 1) != 1)
			return -1;
#endif
		if (byte == '\n') {
			line[length] = '\0';
			return 0;
		}
		if (byte == '\0' || byte == '\r')
			return -1;
		line[length++] = byte;
	}
	return -1;
}
static int request_id(char *id)
{
	unsigned char bytes[16];

	if (RAND_bytes(bytes, sizeof(bytes)) != 1)
		return -1;
	for (size_t i = 0; i < sizeof(bytes); i++)
		snprintf(id + 2 * i, 3, "%02x", bytes[i]);
	return 0;
}

int manager_control_otp(const char *prompt, char *response,
                        size_t capacity)
{
	char id[33], escaped[1024], line[CONTROL_LINE_BYTES];
	int result = -1;

	if (!manager_control_enabled() || !response || capacity == 0)
		return -1;
	response[0] = '\0';
	if (request_id(id) != 0)
		return -1;
	json_escape(escaped, sizeof(escaped), prompt);
	event_emit("auth_challenge",
	           "\"requestId\":\"%s\",\"kind\":\"otp\",\"prompt\":\"%s\",\"timeoutMs\":120000,\"maxResponseBytes\":%zu",
	           id, escaped, capacity - 1);
	if (read_frame(line, sizeof(line), 120000) == 0)
		result = manager_control_decode(line, id, "auth_response", response,
		                                capacity);
	OPENSSL_cleanse(line, sizeof(line));
	event_emit("auth_challenge_closed",
	           "\"requestId\":\"%s\",\"accepted\":%s", id,
	           result == 0 ? "true" : "false");
	return result;
}

int manager_control_network_gate(struct tunnel *tunnel)
{
	char id[33], line[CONTROL_LINE_BYTES], answer[16];
	int result;

	if (!manager_control_enabled())
		return 0;
	if (request_id(id) != 0)
		return -1;
	/* PPP can alter networking before its up callback. Require the lease
	 * before adapter creation, even with no-routes/no-dns. This first protocol
	 * step reserves legacy exclusive mutation; native resource plans follow.
	 */
	event_emit("network_plan",
	           "\"requestId\":\"%s\",\"exclusiveRequired\":true,\"resourceProtocol\":%d,\"setRoutes\":%s,\"setDns\":%s,\"timeoutMs\":30000",
	           id,
#ifdef __linux__
	           1,
#else
	           0,
#endif
	           tunnel->config->set_routes ? "true" : "false",
	           tunnel->config->set_dns ? "true" : "false");
	result = read_frame(line, sizeof(line), 30000);
	if (result == 0)
		result = manager_control_decode(line, id, "lease_decision", answer,
		                                sizeof(answer));
	if (result == 0 && strcmp(answer, "grant_native") == 0) {
#if defined(__linux__) && HAVE_USR_SBIN_PPPD
		/* The first native protocol is explicit split networking only. Custom
		 * peers/plugins and full-tunnel physical exceptions need a separate
		 * pre-adapter transaction. PPP implicit changes remain exclusive.
		 */
		if (tunnel->config->pppd_call || tunnel->config->pppd_plugin ||
		    tunnel->config->pppd_use_peerdns ||
		    (tunnel->config->set_routes && (tunnel->ipv4.split_routes == 0
		                                    || tunnel->ipv4.split_routes > 127)))
			result = -1;
		else
			tunnel->manager_native_network = 1;
#else
		result = -1;
#endif
	} else if (result == 0 && strcmp(answer, "grant") != 0)
		result = -1;
	OPENSSL_cleanse(line, sizeof(line));
	OPENSSL_cleanse(answer, sizeof(answer));
	return result;
}

/* Emit bounded resource frames only after validating the whole plan. Nothing
 * here changes routes/DNS; the privileged manager commits before readiness.
 */
int manager_control_network_apply(struct tunnel *tunnel)
{
#ifdef _WIN32
	(void)tunnel;
	return -1;
#else
	char id[33], line[CONTROL_LINE_BYTES], answer[16];
	char local[INET_ADDRSTRLEN], transport[INET_ADDRSTRLEN];
	char domains[1024] = "", servers[96] = "";
	char (*routes)[256] = NULL;
	unsigned int count = 0, dns = 0, index;
	struct sockaddr_in peer;
	socklen_t peer_length = sizeof(peer);
	size_t used = 0;
	int result = -1;
	int cancel_disabled = 0, old_cancel_state = 0;

	if (!manager_control_enabled() || !tunnel || !tunnel->config)
		return -1;
	memset(&peer, 0, sizeof(peer));
	if (getpeername(tunnel->ssl_socket, (struct sockaddr *)&peer,
	                &peer_length) != 0 ||
	    peer.sin_family != AF_INET || peer_length != sizeof(peer)
	    || peer.sin_addr.s_addr == 0)
		return -1;
	index = if_nametoindex(tunnel->ppp_iface);
	if (index == 0 || tunnel->ipv4.ip_addr.s_addr == 0
	    || tunnel->config->gateway_ip.s_addr == 0)
		return -1;
	for (const char *p = tunnel->ppp_iface; *p; p++)
		if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '-'
		      || *p == '.'))
			return -1;
	if (tunnel->config->set_routes) {
		if (tunnel->ipv4.split_routes < 1 || tunnel->ipv4.split_routes > 127)
			return -1;
		count = (unsigned int)tunnel->ipv4.split_routes;
		routes = calloc(count, sizeof(*routes));
		if (!routes)
			return -1;
		for (unsigned int i = 0; i < count; i++) {
			struct rtentry *route = &tunnel->ipv4.split_rt[i];
			uint32_t mask = ntohl(route_mask(route).s_addr);
			uint32_t dest = ntohl(route_dest(route).s_addr);
			unsigned int bits = 0;
			char ip[INET_ADDRSTRLEN], gateway[INET_ADDRSTRLEN], gateway_json[32];

			while (bits < 32 && (mask & (UINT32_C(1) << (31 - bits))))
				bits++;
			if (bits == 0 || mask != (UINT32_MAX << (32 - bits))
			    || (dest & mask) != dest ||
			    (ntohl(tunnel->config->gateway_ip.s_addr) & mask) == dest ||
			    (ntohl(peer.sin_addr.s_addr) & mask) == dest)
				goto done;
			inet_ntop(AF_INET, &route_dest(route), ip, sizeof(ip));
			if (route_gtw(route).s_addr == 0
			    || route_gtw(route).s_addr == tunnel->ipv4.ip_addr.s_addr)
				strcpy(gateway_json, "null");
			else {
				inet_ntop(AF_INET, &route_gtw(route), gateway,
				          sizeof(gateway));
				snprintf(gateway_json, sizeof(gateway_json),
				         "\"%s\"", gateway);
			}
			int n = snprintf(routes[i], sizeof(*routes),
			                 "{\"kind\":\"route\",\"spec\":{\"destination\":\"%s/%u\",\"gateway\":%s,\"interface\":\"%s\",\"metric\":0,\"gatewayException\":false}}",
			                 ip, bits, gateway_json, tunnel->ppp_iface);
			if (n < 0 || (size_t)n >= sizeof(*routes))
				goto done;
		}
	}
	if (tunnel->config->set_dns) {
		const char *suffix = tunnel->ipv4.dns_suffix;

		if (!suffix || !*suffix || strlen(suffix) > MAX_DOMAIN_LENGTH)
			goto done;
		unsigned int parts = 0;

		while (*suffix) {
			const char *end = strchr(suffix, ';');
			size_t length = end ? (size_t)(end - suffix) : strlen(suffix);

			if (length == 0 || length > 253 || ++parts > 32
			    || used + length + 4 >= sizeof(domains))
				goto done;
			if (used)
				domains[used++] = ',';
			domains[used++] = '"';
			for (size_t i = 0; i < length; i++) {
				unsigned char c = (unsigned char)suffix[i];

				if (!((c >= 'A' && c <= 'Z') ||
				      (c >= 'a' && c <= 'z') ||
				      (c >= '0' && c <= '9')
				      || c == '-' || c == '.'))
					goto done;
				domains[used++] = (char)tolower(c);
			}
			domains[used++] = '"';
			domains[used] = '\0';
			if (!end)
				break;
			suffix = end + 1;
			if (!*suffix)
				goto done;
		}
		struct in_addr addresses[] = {
			tunnel->ipv4.ns1_addr, tunnel->ipv4.ns2_addr
		};

		for (unsigned int i = 0; i < 2; i++) {
			char address[INET_ADDRSTRLEN];

			if (addresses[i].s_addr == 0 ||
			    (i == 1 && addresses[i].s_addr == addresses[0].s_addr))
				continue;
			inet_ntop(AF_INET, &addresses[i], address, sizeof(address));
			size_t length = strlen(servers);

			snprintf(servers + length, sizeof(servers) - length, "%s\"%s\"",
			         length ? "," : "",
			         address);
		}
		if (!*servers)
			goto done;
		dns = 1;
	}
	if (request_id(id) != 0)
		goto done;
	inet_ntop(AF_INET, &tunnel->ipv4.ip_addr, local, sizeof(local));
	inet_ntop(AF_INET, &peer.sin_addr, transport, sizeof(transport));
	if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
	                           &old_cancel_state) != 0)
		goto done;
	cancel_disabled = 1;
	memcpy(tunnel->manager_native_request, id, sizeof(id));
	tunnel->manager_native_started = 1;
	tunnel->manager_native_index = index;
	event_emit("network_begin",
	           "\"requestId\":\"%s\",\"resourceCount\":%u,\"binding\":{\"interface\":\"%s\",\"index\":%u,\"localAddress\":\"%s\",\"transportAddress\":\"%s\"}",
	           id, count + dns, tunnel->ppp_iface, index, local, transport);
	for (unsigned int i = 0; i < count; i++)
		event_emit("network_resource",
		           "\"requestId\":\"%s\",\"ordinal\":%u,\"resource\":%s", id,
		           i, routes[i]);
	if (dns)
		event_emit("network_resource",
		           "\"requestId\":\"%s\",\"ordinal\":%u,\"resource\":{\"kind\":\"dns\",\"spec\":{\"interface\":\"%s\",\"servers\":[%s],\"domains\":[%s]}}",
		           id, count, tunnel->ppp_iface, servers, domains);
	event_emit("network_commit", "\"requestId\":\"%s\",\"timeoutMs\":30000",
	           id);
	if (read_frame(line, sizeof(line), 30000) == 0 &&
	    manager_control_decode(line, id, "network_result", answer,
	                           sizeof(answer)) == 0
	    && strcmp(answer, "applied") == 0)
		result = 0;
	OPENSSL_cleanse(line, sizeof(line));
	OPENSSL_cleanse(answer, sizeof(answer));
	event_emit("network_applied", "\"requestId\":\"%s\",\"success\":%s", id,
	           result == 0 ? "true" : "false");
done:
	free(routes);
	if (cancel_disabled)
		pthread_setcancelstate(old_cancel_state, NULL);
	return result;
#endif
}

int manager_control_network_release(struct tunnel *tunnel)
{
	char id[33], line[CONTROL_LINE_BYTES], answer[16];
	int result = -1;

	if (!tunnel->manager_native_started)
		return 0;
	if (request_id(id) != 0)
		return -1;
	event_emit("network_release",
	           "\"requestId\":\"%s\",\"timeoutMs\":30000", id);
	uint64_t start = monotonic_ms();
	unsigned int stale = 0;

	while (start != UINT64_MAX && monotonic_ms() - start < 30000) {
		uint64_t elapsed = monotonic_ms() - start;

		if (elapsed >= 30000)
			break;
		unsigned int remaining = (unsigned int)(30000 - elapsed);

		if (read_frame(line, sizeof(line), remaining) != 0)
			break;
		if (manager_control_decode(line, id, "network_result", answer,
		                           sizeof(answer)) == 0) {
			if (strcmp(answer, "released") == 0)
				result = 0;
			break;
		}
		/* A cancelled/timed-out apply may have one late result queued. Only
		 * its exact attempt/request/action may be drained; arbitrary stale or
		 * malformed input remains a protocol failure, under one total budget.
		 */
		if (stale++ != 0 || !*tunnel->manager_native_request ||
		    manager_control_decode(line, tunnel->manager_native_request,
		                           "network_result", answer,
		                           sizeof(answer)) != 0 ||
		    (strcmp(answer, "applied") != 0 && strcmp(answer, "deny") != 0))
			break;
	}
	OPENSSL_cleanse(line, sizeof(line));
	OPENSSL_cleanse(answer, sizeof(answer));
	if (result == 0)
		tunnel->manager_native_started = 0;
	return result;
}

int manager_control_network_interface_up(struct tunnel *tunnel)
{
#ifdef _WIN32
	(void)tunnel;
	return 0;
#else
	struct ifaddrs *addresses;
	int ready = 0;

	if (if_nametoindex(tunnel->ppp_iface) != tunnel->manager_native_index
	    || getifaddrs(&addresses) != 0)
		return 0;
	for (struct ifaddrs *entry = addresses; entry;
	     entry = entry->ifa_next) {
		if (entry->ifa_addr && entry->ifa_addr->sa_family == AF_INET &&
		    strcmp(entry->ifa_name, tunnel->ppp_iface) == 0 &&
		    (entry->ifa_flags & (IFF_UP | IFF_POINTOPOINT)) ==
		    (IFF_UP | IFF_POINTOPOINT) &&
		    ((struct sockaddr_in *)entry->ifa_addr)->sin_addr.s_addr ==
		    tunnel->ipv4.ip_addr.s_addr)
			ready = 1;
	}
	freeifaddrs(addresses);
	return ready
	       && if_nametoindex(tunnel->ppp_iface) == tunnel->manager_native_index;
#endif
}
