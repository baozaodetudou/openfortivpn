# OpenFortiVPN Manager architecture

## Product boundaries

OpenFortiVPN Manager has three layers:

1. The bundled `openfortivpn` engine owns one tunnel process and its platform
   network adapter.
2. The Rust control plane owns profiles, credentials, privilege state, process
   lifecycle, retry policy, logs and the remote API.
3. The desktop WebView and remote browser console are clients of that control
   plane. They never manipulate routes or VPN processes directly.

A profile may own at most one running tunnel. Different profiles may run at the
same time. This invariant is enforced in the Rust control plane, not only by UI
button state.

## Connection lifecycle

The control plane distinguishes the child process lifetime from its displayed
VPN state. Engine errors can update diagnostics, but only the process monitor
may declare an instance terminal. Per-profile generations prevent delayed
events, stale command responses and old automatic-reconnect timers from
reviving a stopped connection.

On Unix, every tunnel has a dedicated process group and a mode-`0600` runtime
record. Disconnect and application exit signal the complete group and wait for
the bundled engine to restore routes and DNS. A preventable exit is blocked if
authorization has expired, while the native event-loop exit path performs one
final synchronous cleanup before process termination. If that last-chance
cleanup cannot be authorized, the recovery record is deliberately retained.
After an abnormal app termination, the next launch validates recorded command
lines before offering to clean the stale group, so an unrelated process whose
PID was reused is never signalled. The desktop application is single-instance
to avoid two control planes competing for the same profiles and network state.

Automatic reconnect uses bounded exponential backoff. Explicit disconnect,
profile mutation, deletion and a newer connection generation cancel pending
retries. Certificate and authentication failures require explicit correction.

## Remote control security

Remote control is disabled by default. When enabled:

- the server uses HTTPS, including for loopback access;
- first use creates a dedicated self-signed certificate and a 256-bit access
  token;
- the private key and configuration are mode `0600` on Unix;
- the token is stored in the operating-system credential store and is compared
  in constant time;
- API calls require `Authorization: Bearer <token>`;
- no permissive CORS policy is enabled, so browsers use the bundled same-origin
  console;
- the certificate fingerprint is shown by the desktop settings so an operator
  can verify first contact over a separate channel.

Changing the configured bind IP regenerates the self-signed certificate so its
subject alternative names remain valid. Operators must verify the new
fingerprint after that change.

For Internet exposure, put the service behind a managed reverse proxy or a
private overlay network, use a publicly trusted certificate at the proxy, add
network-level access control and rotate the application token. Direct router
port-forwarding is not a supported production deployment.

## Credentials and privileges

VPN passwords are either session-only or stored in macOS Keychain, Windows
Credential Manager or Linux Secret Service. They are never written to the
profile JSON or returned by the remote API.

The current Unix implementation uses a short-lived sudo credential cache. A
native, narrowly scoped privileged helper is the production target for managed
Linux/macOS fleets. It must validate a structured request and may only start or
stop the bundled engine and apply the routes/DNS associated with an approved
profile; it must never expose a general command runner.

## Release gates

A release is not considered production-ready until all applicable gates pass:

- Rust tests, Clippy with warnings denied, Svelte type checks and engine tests;
- macOS app-signature and DMG checksum validation;
- Linux and Windows bundle builds in CI;
- connect, disconnect, reconnect, retry cancellation and certificate-TOFU E2E;
- authenticated HTTPS API tests covering rejected, read-only and mutating calls;
- dependency, secret, license and code-signing review;
- documented upgrade, rollback, backup and incident-response procedures.
