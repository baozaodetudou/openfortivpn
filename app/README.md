# OpenFortiVPN Manager

Tauri desktop application for managing OpenFortiVPN profiles and concurrent
connection processes on Linux, macOS and Windows.

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
provides one.

## Privileges

On Linux and macOS, the manager runs a profile's bundled engine through
non-interactive `sudo -n` when elevated network privileges are required. A truly
unattended automatic connection therefore requires a minimal `NOPASSWD` sudoers
rule that authorizes only the specific bundled `openfortivpn` executable. Do not
grant passwordless sudo access to arbitrary commands, shells or writable wrapper
scripts. During development, `sudo -v` can be used to refresh the current sudo
credential instead.

On Windows, tunnel and route management requires the application to run with
administrator privileges. Windows may display a UAC prompt, including when an
automatic connection is requested after application startup.

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
