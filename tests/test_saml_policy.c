#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include "saml_policy.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

int main(void)
{
	char id[32] = "unchanged";
	const char *valid =
	        "GET /?id=synthetic-token HTTP/1.1\r\nHost: 127.0.0.1:8020\r\nAccept: */*\r\n\r\n";
	assert(saml_parse_request(valid, strlen(valid), 8020, id,
	                          sizeof(id)) == 0);
	assert(strcmp(id, "synthetic-token") == 0);
	static const char *const bad[] = {
		"POST /?id=synthetic-token HTTP/1.1\r\nHost: 127.0.0.1:8020\r\n\r\n",
		"GET /wrong?id=synthetic-token HTTP/1.1\r\nHost: 127.0.0.1:8020\r\n\r\n",
		"GET /?id= HTTP/1.1\r\nHost: 127.0.0.1:8020\r\n\r\n",
		"GET /?id=bad%0A HTTP/1.1\r\nHost: 127.0.0.1:8020\r\n\r\n",
		"GET /?id=good&id=other HTTP/1.1\r\nHost: 127.0.0.1:8020\r\n\r\n",
		"GET /?id=good HTTP/1.1\r\nHost: attacker.test:8020\r\n\r\n",
		"GET /?id=good HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n\r\n",
		"GET /?id=good HTTP/1.1\r\nHost: 127.0.0.1:8020\r\nHost: localhost:8020\r\n\r\n",
		"GET /?id=good HTTP/1.1\r\n\r\n",
		"GET /?id=good HTTP/1.1\r\nHost: 127.0.0.1:8020\r\nTransfer-Encoding: chunked\r\n\r\n",
		"GET /?id=good HTTP/1.1\r\nHost: 127.0.0.1:8020\r\nContent-Length: 1\r\n\r\nx",
		"GET /?id=good HTTP/1.1\r\nHost: 127.0.0.1:8020\r\n",
	};
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		strcpy(id, "unchanged");
		assert(saml_parse_request(bad[i], strlen(bad[i]), 8020, id,
		                          sizeof(id)) != 0);
		assert(strcmp(id, "unchanged") == 0);
	}
	assert(saml_parse_request(valid, strlen(valid), 8020, id, 8) != 0);
	char with_nul[] =
	        "GET /?id=good HTTP/1.1\r\nHost: 127.0.0.1:8020\r\n\0X\r\n";

	assert(saml_parse_request(with_nul, sizeof(with_nul) - 1, 8020, id,
	                          sizeof(id)) != 0);
	return 0;
}
