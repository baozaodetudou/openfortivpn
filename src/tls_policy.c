#include "tls_policy.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <stdio.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define ASN1_STRING_get0_data ASN1_STRING_data
#endif

int tls_defer_verification(int preverify_ok, X509_STORE_CTX *context)
{
	(void)preverify_ok;
	(void)context;
	return 1;
}

int tls_certificate_policy(X509 *cert, long chain_result,
                           const char *host,
                           const struct x509_digest *pins,
                           char digest[SHA256STRLEN])
{
	unsigned char bytes[SHA256LEN];
	unsigned int length = 0;
	ASN1_OCTET_STRING *ip;
	int identity_ok;

	digest[0] = '\0';
	if (!cert || !host || !host[0])
		return 1;
	ip = a2i_IPADDRESS(host);
	if (ip) {
		identity_ok = X509_check_ip(cert, ASN1_STRING_get0_data(ip),
		                            ASN1_STRING_length(ip), 0) == 1;
		ASN1_OCTET_STRING_free(ip);
	} else {
		identity_ok = X509_check_host(cert, host, 0,
		                              X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
		                              NULL) == 1;
	}
	if (chain_result == X509_V_OK && identity_ok)
		return 0;
	if (X509_digest(cert, EVP_sha256(), bytes, &length) != 1
	    || length != SHA256LEN)
		return 1;
	for (unsigned int i = 0; i < length; i++)
		sprintf(digest + i * 2, "%02x", bytes[i]);
	digest[SHA256STRLEN - 1] = '\0';
	for (; pins; pins = pins->next) {
		char normalized[SHA256STRLEN];

		if (strlen(pins->data) != SHA256STRLEN - 1)
			continue;
		for (unsigned int i = 0; i < SHA256STRLEN; i++) {
			char c = pins->data[i];

			normalized[i] = c >= 'A' && c <= 'F' ? c + ('a' - 'A') : c;
		}
		if (CRYPTO_memcmp(digest, normalized, SHA256STRLEN - 1) == 0)
			return 0;
	}
	return 1;
}
