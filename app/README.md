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
