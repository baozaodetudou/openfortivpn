#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include "dns_policy.h"

int main(void)
{
	static const unsigned char fake_ip[] = {198, 18, 2, 222};
	static const unsigned char fake_ip_upper_bound[] = {198, 19, 255, 255};
	static const unsigned char public_ip[] = {123, 123, 1, 102};
	static const unsigned char private_ip[] = {10, 0, 0, 1};

	assert(dns_ipv4_is_fake_ip(fake_ip));
	assert(dns_ipv4_is_fake_ip(fake_ip_upper_bound));
	assert(!dns_ipv4_is_fake_ip(public_ip));
	assert(!dns_ipv4_is_fake_ip(private_ip));
	assert(!dns_ipv4_is_fake_ip(NULL));

	const char *contents =
	        "nameserver 192.0.2.1\nnameserver 192.0.2.2\nsearch example.com\n";

	assert(dns_line_present(contents, "nameserver 192.0.2.1"));
	assert(dns_line_present(contents, "nameserver 192.0.2.2"));
	assert(dns_line_present(contents, "search example.com"));
	assert(!dns_line_present(contents, "nameserver 192.0.2.3"));
	assert(!dns_line_present(contents, "nameserver 192.0.2"));
	assert(!dns_line_present("", ""));
	assert(dns_line_present("nameserver 192.0.2.2\r\n",
	                        "nameserver 192.0.2.2"));
	return 0;
}
