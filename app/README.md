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

On Linux and macOS, profiles can use non-interactive `sudo -n`; configure a
restricted sudoers rule or run `sudo -v` before connecting during development.

Passwords are kept in memory for the current application session. Native OS
keychain persistence is intentionally deferred until the privilege helper is
implemented.

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

TOFU cannot independently prove the identity of a gateway on the first
connection. When possible, compare the displayed fingerprint with a value
provided by the VPN administrator through a separate trusted channel. As
alternatives to the prompt, enter a verified SHA-256 fingerprint manually in
the profile, or use a gateway certificate whose CA is already trusted by the
client system.
