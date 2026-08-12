# OpenFortiVPN Manager

Tauri desktop application for managing OpenFortiVPN profiles and concurrent
connection processes on Linux, macOS and Windows.

Each profile owns at most one connection at a time. Different profiles can be
connected concurrently. The UI exposes connect, disconnect and reconnect as
state-aware actions; editing and deletion are blocked while that profile is
active. Concurrent profiles should use non-overlapping split routes. Two VPNs
that both replace the default route or global DNS may conflict at the operating
system level and are not advertised as a safe configuration.

## Development

```shell
pnpm install
npm run check
pnpm tauri dev
```

The Tauri development and production commands first build the openfortivpn
engine from the repository root and copy it into the application resources.
Set `OPENFORTIVPN_BIN` to override that bundled engine during development.

The engine build requires CMake, a C compiler and OpenSSL development files.
Windows additionally needs `wintun.dll`; set `WINTUN_DLL` to its full path and
the build script will copy it next to `openfortivpn.exe`. The packaged Windows
application requests administrator privileges through its application manifest.

## Branding and icons

`app-icon.png` is the 1024×1024 transparent master artwork. Regenerate the
macOS ICNS, Windows ICO and platform PNG files from the application directory:

```shell
pnpm tauri icon app-icon.png --output src-tauri/icons
```

The embedded web UI favicon is generated from the same master so installed
packages and browser surfaces use one consistent product identity.

## Profiles and credentials

Ordinary profile fields are persisted in the operating system's application
data directory. On Unix systems, the profile file is created with mode `0600`.
Passwords are never written to `profiles.json`; the file stores only a
`passwordStored` boolean so credential availability remains stable while the
operating-system credential store is loaded on demand.

The **Save password in system credential store** option stores a password in
macOS Keychain, Windows Credential Manager or Linux Secret Service. It can be
disabled for any profile; in that case the password is held in memory and is
available only for the current application session. New profiles enable secure
password storage by default. If a session-only password is missing, **Connect**
opens a focused credential dialog instead of sending the user back through the
complete profile editor.

## Startup and automatic connection

The global **Start application at login** setting is available on Linux, macOS
and Windows. It starts the manager after the user signs in.

Each profile can enable **Connect automatically after application startup**.
Automatic connection requires that profile's password to be saved in the system
credential store so that it is available after an application restart. A
profile without a securely stored password remains disconnected until the user
provides one. On Linux and macOS, profiles that use sudo wait until the startup
system-helper installation described below succeeds; after its one-time
installation they can connect after a cold application start without another
administrator-password prompt.

The separate **Reconnect automatically after an unexpected disconnect** option
uses the password already available in the current app session and retries with
a bounded exponential delay from 3 to 30 seconds. A user-requested disconnect
never triggers automatic reconnection. Authentication and certificate-trust
failures also stop the retry loop so they can be corrected explicitly.

## Privileges

### Linux and macOS

The first connection displays an installation dialog for the computer
administrator password. That password authorizes one installation of a narrow,
root-owned helper and the matching root-owned engine. The password is never
written to a file or credential store and its in-memory value is cleared
immediately. A generated `/etc/sudoers.d/openfortivpn-manager-<uid>` rule permits
only the fixed helper; it does not permit the engine, `kill`, a shell, a writable
wrapper or arbitrary commands.

After installation, application restarts, connect, disconnect, explicit
reconnect, automatic reconnect and auto-connect do not request the administrator
password again. Updating or removing the system helper is a privileged install
operation and deliberately requires administrator authorization again.

The helper validates a strict allowlist of manager-generated VPN fields, copies
the validated data into a root-only temporary configuration, and launches only
the fixed root-owned engine. It rejects extension directives such as
`pppd-plugin` and `pppd-call`. Stop requests are accepted only for a process
group containing that fixed engine.

Each Unix VPN process is placed in its own process group. Disconnect and
application shutdown ask the helper to signal the complete group, wait for the
engine to restore routes and DNS, and only then allow the manager to exit. The
native event-loop exit path also performs a synchronous last-chance cleanup; if
the installed helper is missing or unhealthy, the private recovery record remains
so the next launch can identify and clean the exact process group after helper
recovery.

This administrator password is not the VPN password. The VPN password belongs
to an individual profile and continues to be saved in macOS Keychain or Linux
Secret Service when **Save password in system credential store** is enabled, or
held in memory for only the current application session when it is disabled.
The administrator password is used solely for the one-time helper installation.

Stored VPN passwords are loaded only for startup auto-connect or when a profile
is connected. Ordinary application startup therefore does not enumerate and
unlock every profile credential. Profiles created by older versions are checked
once and migrated to the explicit `passwordStored` metadata.

If policy does not allow the manager to receive an administrator password, an
administrator can deploy the packaged helper through the organization's normal
device-management process. Never replace it with an engine-only `NOPASSWD` rule
or passwordless access to unrestricted `kill`, arbitrary commands, shells,
directories or writable wrapper scripts.

### Windows

Tunnel and route management requires administrator privileges. Windows requests
elevation once through UAC when the application starts, and the manager's child
processes inherit the elevated access. The Linux/macOS administrator-password
dialog is therefore not displayed on Windows. Profiles configured for automatic
connection wait until startup elevation has completed before their engines are
launched.

## Certificate trust (TOFU)

If the first connection to a gateway fails because its self-signed certificate
is not trusted by the operating system, openfortivpn emits a `cert_error` event
containing the certificate's SHA-256 fingerprint. The application displays that
fingerprint for review; the user does not need to discover and copy it from a
terminal manually.

The fingerprint is only a candidate until the user confirms it. After explicit
confirmation, the application saves it as the profile's trusted certificate and
retries the connection. Cancelling the prompt leaves the profile unchanged and
does not reconnect. The application never accepts, saves or reconnects with a
new fingerprint silently.

Automatic connection follows the same TOFU flow. It does not automatically
accept an unknown self-signed certificate or a certificate whose fingerprint
has changed; explicit user confirmation is still required before the profile is
updated and the connection is retried.

TOFU cannot independently prove the identity of a gateway on the first
connection. When possible, compare the displayed fingerprint with a value
provided by the VPN administrator through a separate trusted channel. As
alternatives to the prompt, enter a verified SHA-256 fingerprint manually in
the profile, or use a gateway certificate whose CA is already trusted by the
client system.

## HTTPS remote control

Remote control is disabled by default and listens on `127.0.0.1:18443` when
first enabled. The manager generates a local HTTPS certificate and a 256-bit
access token. The certificate private key is stored with user-only file
permissions and the token is stored in the operating system credential store,
not in the JSON settings file.

The authenticated browser console supports profile creation and editing,
connect, disconnect, explicit reconnect, deletion, instance state and retained
logs. API calls use same-origin HTTPS and Bearer authentication; permissive CORS
is not enabled. The token is retained only in the browser tab's session storage.

The desktop UI shows a certificate SHA-256 fingerprint and reveals a newly
generated token only once. Verify the fingerprint through a trusted channel,
store the token in a password manager and rotate it after suspected disclosure.
Changing the listener IP regenerates the certificate; verify the new
fingerprint before accepting it in another browser.
Prefer a private overlay network or a hardened reverse proxy instead of binding
directly to a public interface.

For safety, remote clients cannot submit a computer administrator password or
approve a newly observed VPN gateway certificate. Complete those operations on
the host's desktop UI. See [`docs/linux.md`](../docs/linux.md) for Linux runtime,
privilege and deployment guidance.
