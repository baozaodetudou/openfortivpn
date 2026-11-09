#include "gateway_dns.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <arpa/inet.h>
#endif

int main(int argc, char **argv)
{
	struct in_addr address;
	struct sockaddr_in server = {0};
	const char *error;
	char ip[INET_ADDRSTRLEN];
#ifdef _WIN32
	WSADATA data;

	assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
#endif
	assert(gateway_dns_server_valid("223.5.5.5"));
	assert(gateway_dns_server_valid("114.114.114.114"));
	assert(gateway_dns_server_valid("127.0.0.1"));
	assert(!gateway_dns_server_valid("0.0.0.0"));
	assert(!gateway_dns_server_valid("224.0.0.1"));
	assert(!gateway_dns_server_valid("255.255.255.255"));
	assert(!gateway_dns_server_valid("dns.example.test"));
	assert(!gateway_dns_server_valid("1.1.1.1\n"));
	assert(!gateway_dns_server_valid("::1"));
	/* A literal gateway bypasses all DNS without changing its identity. */
	assert(gateway_dns_resolve("198.18.2.222", "223.5.5.5", &address) == NULL);
	assert(ntohl(address.s_addr) == 0xc61202de);
	assert(gateway_dns_resolve("localhost", "", &address) == NULL);
	assert(ntohl(address.s_addr) == 0x7f000001);
	assert(argc == 4);
	address.s_addr = htonl(0xc0000201);
	if (strcmp(argv[1], "--resolve") == 0) {
		error = gateway_dns_resolve(argv[2], argv[3], &address);
	} else {
		server.sin_family = AF_INET;
		server.sin_port = htons((unsigned short)atoi(argv[2]));
		assert(inet_pton(AF_INET, "127.0.0.1", &server.sin_addr) == 1);
		error = gateway_dns_query(argv[1], &server,
		                          (unsigned int)atoi(argv[3]), &address);
	}
	if (error) {
		assert(ntohl(address.s_addr) == 0xc0000201);
		puts(error);
	} else {
		inet_ntop(AF_INET, &address, ip, sizeof(ip));
		puts(ip);
	}
#ifdef _WIN32
	WSACleanup();
#endif
	return error ? 1 : 0;
}
