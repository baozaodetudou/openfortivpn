#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include "dns_policy.h"

int main(void)
{
	const char *contents = "nameserver 192.0.2.1\nnameserver 192.0.2.2\nsearch example.com\n";

	assert(dns_line_present(contents, "nameserver 192.0.2.1"));
	assert(dns_line_present(contents, "nameserver 192.0.2.2"));
	assert(dns_line_present(contents, "search example.com"));
	assert(!dns_line_present(contents, "nameserver 192.0.2.3"));
	assert(!dns_line_present(contents, "nameserver 192.0.2"));
	assert(!dns_line_present("", ""));
	assert(dns_line_present("nameserver 192.0.2.2\r\n", "nameserver 192.0.2.2"));
	return 0;
}
