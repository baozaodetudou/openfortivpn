#ifndef OPENFORTIVPN_GATEWAY_DNS_H
#define OPENFORTIVPN_GATEWAY_DNS_H

#include "config.h"

/* NULL means success; errors are static strings. Output changes only on success. */
const char *gateway_dns_resolve(const char *host, const char *dns,
                                struct in_addr *address);

/* Also used by isolated loopback transport tests. */
const char *gateway_dns_query(const char *host, const struct sockaddr_in *server,
                              unsigned int timeout_ms, struct in_addr *address);
int gateway_dns_server_valid(const char *dns);

#endif
