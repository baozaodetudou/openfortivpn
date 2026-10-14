#ifndef OPENFORTIVPN_SAML_POLICY_H
#define OPENFORTIVPN_SAML_POLICY_H
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#define OFV_SAML_REQUEST_LIMIT 4096
static inline int saml_ascii_equal(const char *value, size_t length,
                                   const char *expected)
{
	if (length != strlen(expected))
		return 0;
	for (size_t i = 0; i < length; i++) {
		char byte = value[i];

		if (byte >= 'A' && byte <= 'Z')
			byte += 'a' - 'A';
		if (byte != expected[i])
			return 0;
	}
	return 1;
}
static inline const char *saml_line_end(const char *value,
                                        const char *end)
{
	for (; value + 1 < end; value++)
		if (value[0] == '\r' && value[1] == '\n')
			return value;
	return NULL;
}
/* Validate before copying: failed callbacks never mutate a live credential. */
static inline int saml_parse_request(const char *request, size_t length,
                                     unsigned int port, char *id, size_t capacity)
{
	static const char prefix[] = "GET /?id=";

	if (!request || !id || capacity < 2 || port == 0 || port > 65535 ||
	    length < sizeof(prefix) + 16 || length > OFV_SAML_REQUEST_LIMIT ||
	    memchr(request, 0, length)
	    || memcmp(request, prefix, sizeof(prefix) - 1) != 0 ||
	    memcmp(request + length - 4, "\r\n\r\n", 4) != 0)
		return -1;
	const char *end = request + length;
	const char *token = request + sizeof(prefix) - 1;
	const char *cursor = token;

	while (cursor < end && *cursor != ' ') {
		unsigned char byte = (unsigned char)*cursor++;

		if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
		      (byte >= '0' && byte <= '9') || byte == '-'))
			return -1;
	}
	size_t token_length = (size_t)(cursor - token);

	if (!token_length || token_length >= capacity || end - cursor < 11 ||
	    (memcmp(cursor, " HTTP/1.1\r\n", 11) != 0
	     && memcmp(cursor, " HTTP/1.0\r\n", 11) != 0))
		return -1;
	cursor += 11;
	unsigned int hosts = 0, lengths = 0, headers = 0;

	while (cursor < end) {
		const char *line_end = saml_line_end(cursor, end);

		if (!line_end || ++headers > 64)
			return -1;
		if (cursor == line_end) {
			if (line_end + 2 != end || hosts != 1)
				return -1;
			memcpy(id, token, token_length);
			id[token_length] = 0;
			return 0;
		}
		const char *colon = memchr(cursor, ':', (size_t)(line_end - cursor));

		if (!colon || colon == cursor)
			return -1;
		for (const char *p = cursor; p < colon; p++) {
			unsigned char byte = (unsigned char)*p;

			if (!((byte >= 'a' && byte <= 'z') ||
			      (byte >= 'A' && byte <= 'Z') ||
			      (byte >= '0' && byte <= '9') || byte == '-'))
				return -1;
		}
		const char *value = colon + 1, *value_end = line_end;

		while (value < value_end && (*value == ' ' || *value == '\t'))
			value++;
		while (value_end > value && (value_end[-1] == ' '
		                             || value_end[-1] == '\t'))
			value_end--;
		for (const char *p = value; p < value_end; p++)
			if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7e)
				return -1;
		size_t value_length = (size_t)(value_end - value);

		if (saml_ascii_equal(cursor, (size_t)(colon - cursor), "host")) {
			char numeric[64], local[64];

			snprintf(numeric, sizeof(numeric), "127.0.0.1:%u", port);
			snprintf(local, sizeof(local), "localhost:%u", port);
			if (++hosts != 1 ||
			    (!saml_ascii_equal(value, value_length, numeric) &&
			     !saml_ascii_equal(value, value_length, local)))
				return -1;
		} else if (saml_ascii_equal(cursor, (size_t)(colon - cursor),
		                            "transfer-encoding")) {
			return -1;
		} else if (saml_ascii_equal(cursor, (size_t)(colon - cursor),
		                            "content-length")) {
			if (++lengths != 1 || value_length != 1 || *value != '0')
				return -1;
		}
		cursor = line_end + 2;
	}
	return -1;
}
#endif
