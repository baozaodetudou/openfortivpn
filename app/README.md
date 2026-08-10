# OpenFortiVPN Manager

Tauri desktop application for managing OpenFortiVPN profiles and concurrent
connection processes on Linux, macOS and Windows.

Each profile owns at most one connection at a time. Different profiles can be
connected concurrently. The UI exposes connect, disconnect and reconnect as
state-aware actions; editing and deletion are blocked while that profile is
active.

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

## Profiles and credentials

Ordinary profile fields are persisted in the operating system's application
data directory. On Unix systems, the profile file is created with mode `0600`.
Passwords are never written to `profiles.json`.

The **Save password in system credential store** option stores a password in
macOS Keychain, Windows Credential Manager or Linux Secret Service. It can be
disabled for any profile; in that case the password is held in memory and is
available only for the current application session.

## Startup and automatic connection

The global **Start application at login** setting is available on Linux, macOS
and Windows. It starts the manager after the user signs in.

Each profile can enable **Connect automatically after application startup**.
Automatic connection requires that profile's password to be saved in the system
credential store so that it is available after an application restart. A
profile without a securely stored password remains disconnected until the user
provides one. On Linux and macOS, profiles that use sudo wait until the startup
privilege unlock described below succeeds or the user chooses an alternative
privilege setup; they do not race ahead while the administrator-password dialog
is pending.

The separate **Reconnect automatically after an unexpected disconnect** option
uses the password already available in the current app session and retries with
a bounded exponential delay from 3 to 30 seconds. A user-requested disconnect
never triggers automatic reconnection. Authentication and certificate-trust
failures also stop the retry loop so they can be corrected explicitly.

## Privileges

### Linux and macOS

When the manager starts, it can display a one-time privilege-unlock dialog for
the computer administrator password. The manager passes that password directly
to `sudo -S -v`, creating a sudo credential cache for the current application
process session. The password is never written to a file, never saved in the
operating system credential store and never retained for future launches. Its
in-memory value is cleared immediately after it has been submitted to sudo.

While the application remains open, it periodically runs `sudo -n -v` to renew
the credential cache without displaying another prompt. Connections whose
profiles enable **Use sudo** then launch the bundled engine with `sudo -n`, so
normal connect, disconnect and reconnect operations do not ask for the computer
administrator password again. The renewal task stops when the application
exits. Sudo remains authoritative: its configured timestamp timeout, cache
scope, revocation and other system policy continue to apply.

This administrator password is not the VPN password. The VPN password belongs
to an individual profile and continues to be saved in macOS Keychain or Linux
Secret Service when **Save password in system credential store** is enabled, or
held in memory for only the current application session when it is disabled.
The administrator password is used solely to unlock the sudo session described
above.

If policy does not allow the manager to receive an administrator password, a
purpose-built native privileged helper is the preferred deployment model once
one is available. An engine-only `NOPASSWD` rule is not sufficient to safely
manage the complete process lifecycle. Do not work around that limitation by
granting passwordless access to unrestricted `kill`, arbitrary commands,
shells, directories or writable wrapper scripts.

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
