# OpenFortiVPN Manager architecture

## Product boundaries

OpenFortiVPN Manager has three layers:

1. The bundled `openfortivpn` engine owns one tunnel process and its platform
   network adapter. In explicit Linux headless native mode it delegates validated
   split-route/scoped-DNS resources to an owned control-plane worker.
2. The Rust control plane owns profiles, credentials, privilege state, process
   lifecycle, retry policy, logs and the remote API.
3. The desktop WebView and remote browser console are clients of that control
   plane. They never manipulate routes or VPN processes directly.

A profile may own at most one live attempt, including starting, stopping and
recovery. Current managers conservatively reject conflicting network owners
before launch, including implicit PPP changes with explicit route/DNS disabled.
Unix launchers now share a root-owned, durable system authority: helper, headless
and root desktop attempts exclude each other before engine spawn and retain
ownership through reap, output drain and confirmed cleanup. Upgrade operations
use the same authority. Windows desktop now reserves a durable machine-wide
authority before spawn and binds its process creation identity; elevated runtime,
cross-admin and ACL/reparse acceptance remain pending.

Linux headless integrates the resource coordinator with a bounded engine
handshake and a joined native worker for direct split routes and scoped DNS.
Its opt-in, readiness and release proofs are described in
[engine control](engine-control.md). Providers include Linux rtnetlink/resolved,
macOS PF_ROUTE/SystemConfiguration and Windows IP Helper/scoped NRPT. Helper and
desktop native workers, full-tunnel/gateway exceptions and other-platform
handshakes remain unintegrated. Provider implementation and cross-compilation
do not establish runtime support; see [recovery and upgrades](recovery-and-upgrades.md).
Coordinated concurrent networking remains disabled.

## Connection lifecycle

The control plane distinguishes the child process lifetime from its displayed
VPN state. Engine errors can update diagnostics, but only the process monitor
may declare an instance terminal. Per-profile generations prevent delayed
events, stale command responses and old automatic-reconnect timers from
reviving a stopped connection. Attempt sequences distinguish automatic reconnects
within the same generation, even when wall-clock timestamps are equal. Both
managers use shared owned-child and stream-drain primitives. Unix direct
launchers negotiate a separate C startup socket and hold supported engines
until their process group and recovery journals are durable. Parent EOF prevents
startup. Legacy engines keep their original arguments and conservative ownership;
unknown pre-registration recovery remains blocked.
The full business service migration remains incomplete.

Both adapters now use shared typed `ConnectAdmission` while holding the runtime
lock through reservation. Desktop user, startup and automatic retry entries and
headless user/startup entries submit the same ownership facts. Only a healthy,
published user intent may reuse its instance. Stopping, recovery, unpublished
starts, other network owners, repository mutation/recovery and shutdown return
typed errors before reuse or reservation. Process handles, credentials,
generations and cleanup still belong to adapters; this is a shared admission
boundary, with the complete connection use-case migration still pending.

The desktop window lifetime is separate from the Rust control-plane lifetime.
Native window close is intercepted: the default policy hides the window while
the persistent system tray and retry scheduler remain active. Tray profile
actions call the Rust control plane directly and do not depend on a mounted
WebView. Only an explicit application quit begins tunnel shutdown and route/DNS
cleanup. Login autostart is marked with `--autostart`, allowing the process and
tray to start without foregrounding the window.

On Unix, every tunnel has a dedicated process group and a mode-`0600` runtime
record. Disconnect and application exit ask the installed restricted helper to
signal the complete group and wait for the bundled engine to restore routes and
DNS. A preventable exit is blocked if the helper is missing or unhealthy, while
the native event-loop exit path performs one final synchronous cleanup before
process termination. If that last-chance cleanup cannot run, the recovery record
is deliberately retained.
After an abnormal app termination, startup retains ownership until recovery.
Helper stop validates owner, executable, process identity and group; Windows
journals also bind creation time. A reused PID is never accepted as a newly owned
child. The desktop application is single-instance. A separate private
`.repository-owner.lock` is held for the control plane's entire lifetime, so
renamed/development binaries and offline tools cannot open a competing writable
profile repository. Lock-file symlinks are rejected; the UI single-instance
plugin alone is not the storage ownership boundary.

Automatic reconnect uses bounded exponential backoff. Explicit disconnect,
profile mutation, deletion and a newer connection generation cancel pending
retries. Certificate and authentication failures require explicit correction.

Unix machine authority checks native journals under a fixed authority → native
store lock order. A pending transaction, orphan interface binding, malformed
journal or busy worker blocks acquisition, completion, manual acknowledgement
and maintenance. The maintenance guard retains both locks through the operation
and releases the native lock first. An absent global owner does not authorize
headless to delete its local recovery anchor while native evidence remains.

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

Both managers implement the shared `ProfileRepository` port while holding their
adapter locks. Shared profile services validate and normalize saves, check
conditional revisions, prepare complete restore catalogs and validate deletion
before stopping a connection. Auto-connect requires a durable credential;
client credential references and orphan-secret adoption are rejected. Transport
compatibility remains explicit: headless v1 can create a password-less profile,
while desktop remember-password requests require a supplied or existing secret.

Desktop credentials use immutable references and durable intents. Restore stages
the new references, replaces metadata once, publishes the authoritative cache
and then collects unused references. Session-only changes happen after durable
commit. Uncertain metadata writes close the repository gate until explicit
durable reload and recovery. Shared fault injection and actual macOS local
credential/metadata files exercise 11 restore failure boundaries; native Windows
Credential Manager and Linux Secret Service failure acceptance is still pending.
The full shared connection use case remains incomplete, even though profile
save/delete/restore policy is now common.

VPN passwords are either session-only or saved outside the profile JSON.
Windows uses Credential Manager and Linux uses Secret Service. The ad-hoc signed
macOS build uses an app-owned `credentials.json` with a mode-`0700` parent and a
mode-`0600`, current-user-owned regular file. It intentionally never follows a
symlink or automatically opens legacy Keychain VPN items, preventing signature
changes from producing repeated authorization prompts. This is a permission
boundary rather than encryption: the logged-in user, root and same-user
processes can read the file. Profile JSON persists credential references and the non-secret fact that
a credential is expected to exist, and neither profile JSON nor the remote API
returns a password.

Unix installs a narrow helper and matching engine into fixed, root-owned paths.
Its sudoers rule permits only that helper. The helper validates an allowlist of
manager-generated fields, creates a root-only runtime configuration, rejects
engine extension directives, and only stops process groups containing the fixed
engine. It never exposes an engine path, shell, arbitrary command or unrestricted
PID signal operation. The administrator password authorizes installation only
and is not retained. Helper upgrades and removal require authorization again.

## Release gates

A release is not considered production-ready until all applicable gates pass:

- Rust tests, Clippy with warnings denied, Svelte type checks and engine tests;
- macOS app-signature and DMG checksum validation;
- Linux and Windows bundle builds in CI;
- connect, disconnect, reconnect, retry cancellation and certificate-TOFU E2E;
- close-to-tray, background reconnect, tray actions and explicit-quit cleanup;
- authenticated HTTPS API tests covering rejected, read-only and mutating calls;
- dependency, secret, license and code-signing review;
- documented upgrade, rollback, backup and incident-response procedures.
