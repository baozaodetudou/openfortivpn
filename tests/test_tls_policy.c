#include "tls_policy.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>

static X509 *certificate(EVP_PKEY **private_key)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY *key = NULL;
	X509 *cert = X509_new();
	X509_EXTENSION *san;

	assert(ctx && cert);
	assert(EVP_PKEY_keygen_init(ctx) == 1);
	assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1);
	assert(EVP_PKEY_keygen(ctx, &key) == 1);
	assert(X509_set_version(cert, 2) == 1);
	assert(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1);
	X509_gmtime_adj(X509_get_notBefore(cert), -60);
	X509_gmtime_adj(X509_get_notAfter(cert), 3600);
	assert(X509_set_pubkey(cert, key) == 1);
	assert(X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC,
	                                (unsigned char *)"vpn.example.com", -1, -1, 0) == 1);
	assert(X509_set_issuer_name(cert, X509_get_subject_name(cert)) == 1);
	san = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,
	                         "DNS:vpn.example.com,IP:192.0.2.1,IP:2001:db8::1");
	assert(san && X509_add_ext(cert, san, -1) == 1);
	X509_EXTENSION_free(san);
	assert(X509_sign(cert, key, EVP_sha256()) > 0);
	if (private_key)
		*private_key = key;
	else
		EVP_PKEY_free(key);
	EVP_PKEY_CTX_free(ctx);
	return cert;
}

static void verify_handshake_policy(X509 *cert, EVP_PKEY *key, int trusted)
{
	SSL_CTX *client_ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX *server_ctx = SSL_CTX_new(SSLv23_server_method());
	SSL *client, *server;
	BIO *client_bio, *server_bio;
	char digest[SHA256STRLEN];
	X509 *peer;

	assert(client_ctx && server_ctx);
	SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, tls_defer_verification);
	if (trusted)
		assert(X509_STORE_add_cert(SSL_CTX_get_cert_store(client_ctx), cert) == 1);
	assert(SSL_CTX_use_certificate(server_ctx, cert) == 1);
	assert(SSL_CTX_use_PrivateKey(server_ctx, key) == 1);
	client = SSL_new(client_ctx);
	server = SSL_new(server_ctx);
	assert(client && server && BIO_new_bio_pair(&client_bio, 0, &server_bio, 0) == 1);
	SSL_set_bio(client, client_bio, client_bio);
	SSL_set_bio(server, server_bio, server_bio);
	SSL_set_connect_state(client);
	SSL_set_accept_state(server);
	for (int i = 0; i < 64 && (!SSL_is_init_finished(client) || !SSL_is_init_finished(server)); i++) {
		SSL *sides[] = {client, server};

		for (int j = 0; j < 2; j++) {
			int result = SSL_do_handshake(sides[j]);

			if (result != 1) {
				int error = SSL_get_error(sides[j], result);

				assert(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
			}
		}
	}
	assert(SSL_is_init_finished(client) && SSL_is_init_finished(server));
	assert((SSL_get_verify_result(client) == X509_V_OK) == trusted);
	peer = SSL_get_peer_certificate(client);
	assert(tls_certificate_policy(peer, SSL_get_verify_result(client), "wrong.example.com", NULL, digest) != 0);
	assert((tls_certificate_policy(peer, SSL_get_verify_result(client), "vpn.example.com", NULL, digest) == 0) == trusted);
	X509_free(peer);
	SSL_free(client);
	SSL_free(server);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
}

int main(void)
{
	EVP_PKEY *key;
	X509 *cert = certificate(&key);
	char digest[SHA256STRLEN];
	struct x509_digest pin = {0};

	assert(tls_certificate_policy(cert, X509_V_OK, "vpn.example.com", NULL, digest) == 0);
	assert(tls_certificate_policy(cert, X509_V_OK, "wrong.example.com", NULL, digest) != 0);
	assert(strlen(digest) == 64);
	assert(tls_certificate_policy(cert, X509_V_OK, "192.0.2.1", NULL, digest) == 0);
	assert(tls_certificate_policy(cert, X509_V_OK, "2001:db8::1", NULL, digest) == 0);
	assert(tls_certificate_policy(cert, X509_V_OK, "192.0.2.2", NULL, digest) != 0);
	assert(tls_certificate_policy(cert, X509_V_ERR_CERT_HAS_EXPIRED, "vpn.example.com", NULL, digest) != 0);
	strcpy(pin.data, digest);
	for (int i = 0; i < 64; i++)
		if (pin.data[i] >= 'a' && pin.data[i] <= 'f')
			pin.data[i] -= 'a' - 'A';
	assert(tls_certificate_policy(cert, X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, "wrong.example.com", &pin, digest) == 0);
	pin.data[0] = pin.data[0] == '0' ? '1' : '0';
	assert(tls_certificate_policy(cert, X509_V_OK, "wrong.example.com", &pin, digest) != 0);
	assert(tls_certificate_policy(NULL, X509_V_OK, "vpn.example.com", NULL, digest) != 0);
	verify_handshake_policy(cert, key, 0);
	verify_handshake_policy(cert, key, 1);
	EVP_PKEY_free(key);
	X509_free(cert);
	return 0;
}
