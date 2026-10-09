#ifndef OPENFORTIVPN_DNS_POLICY_H
#define OPENFORTIVPN_DNS_POLICY_H
#include <string.h>

/* Non-destructive comparison: every server/domain uses the complete source,
 * so checking one entry cannot consume the lines needed by the next entry. */
static inline int dns_line_present(const char *contents, const char *expected)
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
