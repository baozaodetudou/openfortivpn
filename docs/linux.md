# Linux desktop installation

OpenFortiVPN Manager is released as a Debian package. The application bundle
contains the matching `openfortivpn` engine, but Linux must still provide PPP,
sudo, a Secret Service implementation and the normal desktop runtime libraries.

## Ubuntu and Debian

Install the runtime dependencies before opening the package:

```shell
sudo apt-get update
sudo apt-get install -y ppp sudo libsecret-1-0 libwebkit2gtk-4.1-0
sudo apt-get install ./OpenFortiVPN\ Manager_*_amd64.deb
```

AppImage is intentionally not published. The DEB includes the matching engine
and privileged helper in stable package resource paths.

The keyring must be unlocked for stored VPN passwords and the remote-access
token. GNOME Keyring and KDE Wallet normally expose a compatible Secret Service
automatically after graphical login.

## Privileges

Creating PPP interfaces, changing routes and changing DNS require root access.
The first connection asks once for the computer administrator password and uses
it to install the packaged helper and engine under root-owned fixed paths. It
also validates and atomically installs a per-UID sudoers rule that permits only
the fixed helper. Subsequent application launches and VPN operations do not
prompt again.

The administrator password is never persisted. The helper accepts only a strict
VPN configuration allowlist, writes a root-only runtime copy and rejects
`pppd-plugin`, `pppd-call` and other extension fields. Updating or uninstalling
the helper requires administrator authorization again. Do not grant passwordless
access to a shell, arbitrary `kill`, a writable wrapper, the raw engine or an
entire directory.

## Remote Web control

Remote control is disabled by default. Enable it from **Application settings →
HTTPS remote control**. The safe default listens only on `127.0.0.1:18443`.

For access from another machine:

1. use a private overlay network such as Tailscale or WireGuard;
2. bind the manager to the overlay interface's explicit IP address;
3. allow only the required source network in the host firewall;
4. verify the displayed HTTPS certificate SHA-256 fingerprint out of band;
5. keep the 256-bit access token in a password manager and rotate it after any
   suspected disclosure.

The browser cannot install the system helper or silently trust a new VPN gateway
certificate. Those two sensitive confirmations must be completed locally in
the desktop application.

## Diagnostics

Check the bundled engine and required system programs:

```shell
command -v pppd
sudo -n /usr/local/libexec/openfortivpn-manager/helper check
```

The resource path varies between package formats. The desktop UI shows the
engine path and version in its left sidebar. Connection output is retained in
memory and is available in both the desktop and authenticated Web consoles.
