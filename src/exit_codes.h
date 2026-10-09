/*
 *  Copyright (c) 2015 Adrien Vergé
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OPENFORTIVPN_EXIT_CODES_H
#define OPENFORTIVPN_EXIT_CODES_H

enum ofv_exit_code {
	OFV_EXIT_OK             = 0,
	OFV_EXIT_GENERIC        = 1,   /* legacy fallback */
	OFV_EXIT_DNS_FAILED     = 10,
	OFV_EXIT_TCP_FAILED     = 11,
	OFV_EXIT_TLS_FAILED     = 12,
	OFV_EXIT_CERT_FAILED    = 13,
	OFV_EXIT_AUTH_FAILED    = 20,
	OFV_EXIT_OTP_MISSING    = 21,
	OFV_EXIT_SAML_FAILED    = 22,
	OFV_EXIT_ALLOC_DENIED   = 23,
	OFV_EXIT_CONFIG_FAILED  = 30,
	OFV_EXIT_ADAPTER_FAILED = 40,
	OFV_EXIT_TUNNEL_FAILED  = 41,
	OFV_EXIT_PERMISSION     = 50,
	OFV_EXIT_SIGNAL         = 60
};

static inline const char *ofv_exit_reason(int code)
{
	switch (code) {
	case OFV_EXIT_OK: return "OK";
	case OFV_EXIT_DNS_FAILED: return "DNS_FAILED";
	case OFV_EXIT_TCP_FAILED: return "TCP_FAILED";
	case OFV_EXIT_TLS_FAILED: return "TLS_FAILED";
	case OFV_EXIT_CERT_FAILED: return "CERT_FAILED";
	case OFV_EXIT_AUTH_FAILED: return "AUTH_REJECTED";
	case OFV_EXIT_OTP_MISSING: return "OTP_REQUIRED";
	case OFV_EXIT_SAML_FAILED: return "SAML_FAILED";
	case OFV_EXIT_ALLOC_DENIED: return "ALLOCATION_DENIED";
	case OFV_EXIT_CONFIG_FAILED: return "CONFIG_FAILED";
	case OFV_EXIT_ADAPTER_FAILED: return "ADAPTER_FAILED";
	case OFV_EXIT_TUNNEL_FAILED: return "TUNNEL_FAILED";
	case OFV_EXIT_PERMISSION: return "PERMISSION_REQUIRED";
	case OFV_EXIT_SIGNAL: return "SIGNALLED";
	default: return "INTERNAL_ERROR";
	}
}

static inline int ofv_exit_retryable(int code)
{
	return code == OFV_EXIT_DNS_FAILED || code == OFV_EXIT_TCP_FAILED ||
	       code == OFV_EXIT_TUNNEL_FAILED;
}

#endif /* OPENFORTIVPN_EXIT_CODES_H */
