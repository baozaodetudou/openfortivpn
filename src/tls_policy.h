#ifndef OPENFORTIVPN_TLS_POLICY_H
#define OPENFORTIVPN_TLS_POLICY_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "config.h"

/* Keep handshake diagnostics available for explicit pin/TOFU policy. This
 * callback never authorizes application traffic; tls_certificate_policy does.
 */
int tls_defer_verification(int preverify_ok, X509_STORE_CTX *context);

/* Accept CA + gateway identity, or an explicit SHA-256 pin. insecure-ssl only
 * changes protocol/cipher policy and must never bypass this certificate check.
 * The digest is populated on rejection so managers can offer explicit TOFU.
 */
int tls_certificate_policy(X509 *cert, long chain_result,
                           const char *host,
                           const struct x509_digest *pins,
                           char digest[SHA256STRLEN]);

#endif
