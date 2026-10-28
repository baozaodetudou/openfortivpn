#ifndef OPENFORTIVPN_DNS_POLICY_H
#define OPENFORTIVPN_DNS_POLICY_H
#include <stddef.h>
#include <string.h>

/*
 * RFC 2544 reserves 198.18.0.0/15 for network benchmark devices. Proxy
 * clients and TUN DNS implementations commonly use this range for fake-IP
 * answers. This is a diagnostic hint: a working proxy can forward the
 * connection, and benchmark networks may legitimately use these addresses.
 */
static inline int dns_ipv4_is_fake_ip(const unsigned char address[4])
{
	return address != NULL && address[0] == 198 &&
	       (address[1] == 18 || address[1] == 19);
}

/* Non-destructive comparison: every server/domain uses the complete source,
 * so checking one entry cannot consume the lines needed by the next entry.
 */
static inline int dns_line_present(const char *contents,
                                   const char *expected)
{
	size_t expected_len = strlen(expected);

	if (!expected_len)
		return 0;
	while (*contents) {
		const char *end = strchr(contents, '\n');
		size_t length = end ? (size_t)(end - contents) : strlen(contents);

		if (length && contents[length - 1] == '\r')
			length--;
		if (length == expected_len && memcmp(contents, expected, length) == 0)
			return 1;
		if (!end)
			break;
		contents = end + 1;
	}
	return 0;
}
#endif
