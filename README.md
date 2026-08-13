openfortivpn
============

openfortivpn is a client for PPP+TLS VPN tunnel services.
It spawns a pppd process and operates the communication between the gateway and
this process.

On Windows, it uses an in-process PPP engine with
[wintun](https://www.wintun.net/) instead of pppd.

It is compatible with Fortinet VPNs.

OpenFortiVPN Manager v0.1.5
---------------------------

This repository also ships a complete graphical VPN manager for Linux, macOS
and Windows, plus a headless Linux service. Download the installers from the
[GitHub Releases page](https://github.com/baozaodetudou/openfortivpn/releases).

| System | Download | Install |
| --- | --- | --- |
| macOS Apple Silicon | `macOS-arm64` DMG | Open the DMG and drag the app to `/Applications` |
| macOS Intel | `macOS-x86_64` DMG | Open the DMG and drag the app to `/Applications` |
| Windows x64 | MSI or NSIS EXE | Run the installer and accept the UAC prompt |
| Linux desktop x64 | DEB | `sudo apt install ./openfortivpn-manager_*.deb` |
| Linux server x64 | headless DEB or tar.gz | Install the DEB, or extract the tarball and run `sudo ./install.sh` |

The first Linux/macOS connection asks once for the computer administrator
password to install the restricted system helper. Normal connect, disconnect,
reconnect, automatic reconnect and later application starts do not ask again.
Each VPN profile has its own stored credential and at most one running instance;
different profiles can connect concurrently. Concurrent VPNs should use
non-overlapping split routes and should not both replace the default route or
global DNS.

See the [中文用户指南](docs/user-guide.zh-CN.md), [desktop reference](app/README.md),
[Linux headless guide](headless/README.md), [architecture](docs/architecture.md)
and [build/release guide](docs/release.md).

Desktop manager
---------------

The [`app`](app/) directory contains a Tauri 2 + Svelte desktop manager for
Linux, macOS and Windows. Each profile owns at most one connection, while
different profiles can connect concurrently. It provides profile CRUD,
state-aware connect/reconnect/disconnect actions and structured logs. Its
desktop build compiles this repository's openfortivpn engine and bundles the
resulting binary as an application resource.

The manager also includes an optional authenticated HTTPS Web console for
remote profile and connection management. It is disabled by default, uses a
generated 256-bit token stored in the system credential store and does not
expose administrator-password or first-use certificate approval remotely. See
[`app/README.md`](app/README.md) and [`docs/linux.md`](docs/linux.md).
Build, install, signing, release, upgrade and rollback procedures are documented
in [`docs/release.md`](docs/release.md).

Linux headless manager
----------------------

The [`headless`](headless/) directory contains a WebKit-free Linux CLI and
systemd service for servers without a desktop. Its automatic installer deploys
the manager and matching engine once; the root service then provides multiple
profile instances, automatic reconnect and an HTTPS Web console where an
operator enters the generated access token. The secure default binds only to
`127.0.0.1:18443`; bind to an explicit private interface and add firewall rules
before remote use.

```shell
./headless/scripts/install.sh
sudo openfortivpn-manager-headless token
```

Release CI publishes both a Debian package and a self-contained Linux x86-64
tar archive with `install.sh`. Full commands and API examples are in
[`headless/README.md`](headless/README.md).

```shell
cd app
pnpm install
pnpm check
pnpm tauri dev
```

Windows requires `wintun.dll`; set `WINTUN_DLL` to its full path before running
the Tauri build.

Profile settings are persisted in the operating system's application data
directory. On Unix systems, the profile file is created with mode `0600`.
Passwords are never written to `profiles.json`. Windows uses Credential Manager
and Linux uses Secret Service. Because the distributed macOS app is ad-hoc
signed, it stores VPN passwords in a separate `credentials.json` owned by the
current user, with its parent directory set to `0700` and the file to `0600`.
This avoids repeated Keychain authorization prompts, but the file is not
encrypted and remains readable by the logged-in user, root and same-user
processes. Disabling password saving keeps it only in memory for the current
application session.

The manager can start when the user logs in on Linux, macOS and Windows. Each
profile can also be marked to connect automatically after the application
starts, provided that its password is available from the system credential
store. On Linux and macOS, the manager asks once for the computer administrator
password to install a root-owned, narrowly scoped system helper and matching VPN
engine. The password is cleared immediately after submission and is not written
to disk or a credential store. The helper accepts only validated manager VPN
fields and fixed start/stop operations, while the generated sudoers rule grants
no shell, arbitrary command, engine or unrestricted `kill` access. After that
one-time installation, cold starts, connect, disconnect, auto-connect and
automatic reconnect no longer prompt. Updating or removing the helper still
requires administrator authorization.

Unexpected disconnects can be retried per profile with bounded backoff. A
manual disconnect never enters that retry path, and active profiles cannot be
edited or deleted until their connection has stopped.

The computer administrator password is separate from each profile's VPN
password and is used only for the helper installation. VPN passwords are stored
per profile using the platform policy above or held only for the current
application session. An engine-only `NOPASSWD` rule is not enough to
safely manage the complete process lifecycle; do not compensate with
unrestricted `kill`, arbitrary commands, shells or writable wrapper scripts. On Windows, the
application instead requests UAC elevation once at startup and its child
processes inherit that access, so this administrator-password dialog is not
shown. See [`app/README.md`](app/README.md) for details.

When a first connection encounters a self-signed certificate or another
certificate that the operating system does not trust, the desktop manager uses
the engine's `cert_error` event to display the certificate's SHA-256 fingerprint.
This is a trust-on-first-use (TOFU) prompt: the fingerprint is saved to the
profile and the connection is retried only after the user explicitly confirms
it. The application never silently trusts a certificate. When possible, compare
the displayed fingerprint with one supplied by the VPN administrator over a
separate trusted channel. A fingerprint can also be entered manually, or the
gateway can use a certificate issued by a trusted CA. See
[`app/README.md`](app/README.md#certificate-trust-tofu) for the complete flow.
Automatic connections use the same checks and never accept an unknown or
changed certificate automatically.

Usage
-----

```shell
man openfortivpn
```

Examples
--------

* Simply connect to a VPN:
  ```shell
  openfortivpn vpn-gateway:8443 --username=foo
  ```

* Connect to a VPN using an authentication realm:
  ```shell
  openfortivpn vpn-gateway:8443 --username=foo --realm=bar
  ```

* Store password securely with a pinentry program:
  ```shell
  openfortivpn vpn-gateway:8443 --username=foo --pinentry=pinentry-mac
  ```

* Connect with a user certificate and no password:
  ```shell
  openfortivpn vpn-gateway:8443 --username= --password= --user-cert=cert.pem --user-key=key.pem
  ```

* Connect using SAML login:
  ```shell
  openfortivpn vpn-gateway:8443 --saml-login
  ```

* Don't set IP routes and don't add VPN nameservers to `/etc/resolv.conf`:
  ```shell
  openfortivpn vpn-gateway:8443 -u foo --no-routes --no-dns --pppd-no-peerdns
  ```

* Using a configuration file:
  ```shell
  openfortivpn -c /etc/openfortivpn/my-config
  ```

  With `/etc/openfortivpn/my-config` containing:
  ```ini
  host = vpn-gateway
  port = 8443
  username = foo
  set-dns = 0
  pppd-use-peerdns = 0
  # X509 certificate sha256 sum, trust only this one!
  trusted-cert = e46d4aff08ba6914e64daa85bc6112a422fa7ce16631bff0b592a28556f993db
  ```

* For the full list of config options, see the `CONFIGURATION` section of
  ```shell
  man openfortivpn
  ```

Smartcard
---------

Smartcard support needs `openssl pkcs engine` and `opensc` to be installed.
The pkcs11-engine from libp11 needs to be compiled with p11-kit-devel installed.
Check [#464](https://github.com/adrienverge/openfortivpn/issues/464) for a discussion
of known issues in this area.

Building on Fedora since [this
update](https://src.fedoraproject.org/rpms/openssl/c/13b583a535e62d12521cfeb5088a68e5811eb6e6?branch=rawhide)
will NOT include engine support unless `openssl-devel-engine` is installed. Try
first to use `pkcs11-provider` on OpenSSL >= 3.0.

To make use of your smartcard put at least `pkcs11:` to the user-cert config or commandline
option. It takes the full or a partial PKCS#11 token URI.

```ini
user-cert = pkcs11:
user-cert = pkcs11:token=someuser
user-cert = pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=012345678;token=someuser
username =
password =
```

In most cases `user-cert = pkcs11:` will do it, but if needed you can get the token-URI
with `p11tool --list-token-urls`.

Multiple readers are currently not supported.

Smartcard support has been tested with Yubikey under Linux, but other PIV enabled
smartcards may work too. On Mac OS X Mojave it is known that the pkcs engine-by-id
is not found.

Installing
----------

### Installing existing packages

Some Linux distributions provide `openfortivpn` packages:
* [Fedora / CentOS](https://packages.fedoraproject.org/pkgs/openfortivpn)
* [openSUSE / SLE](https://software.opensuse.org/package/openfortivpn)
* [Gentoo](https://packages.gentoo.org/packages/net-vpn/openfortivpn)
* [NixOS](https://github.com/NixOS/nixpkgs/tree/master/pkgs/by-name/op/openfortivpn)
* [Arch Linux](https://archlinux.org/packages/extra/x86_64/openfortivpn)
* [Debian](https://packages.debian.org/stable/openfortivpn)
* [Ubuntu](https://packages.ubuntu.com/search?keywords=openfortivpn)
* [Solus](https://github.com/getsolus/packages/tree/main/packages/o/openfortivpn)
* [Alpine Linux](https://pkgs.alpinelinux.org/package/edge/testing/x86_64/openfortivpn)

On macOS both [Homebrew](https://formulae.brew.sh/formula/openfortivpn) and
[MacPorts](https://ports.macports.org/port/openfortivpn)
provide an `openfortivpn` package.
Either [install Homebrew](https://brew.sh/) then install openfortivpn:
```shell
# Install 'Homebrew'
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

# Install 'openfortivpn'
brew install openfortivpn
```

or [install MacPorts](https://www.macports.org/install.php) then install openfortivpn:
```shell
# Install 'openfortivpn'
sudo port install openfortivpn
```

A more complete overview can be obtained from [repology](https://repology.org/project/openfortivpn/versions).

### Windows

Windows support uses [wintun](https://www.wintun.net/) (a lightweight TUN
driver from the WireGuard project) instead of pppd. PPP negotiation is handled
in-process.

**Requirements:**
* Windows 10 or later
* Administrator privileges (for TUN adapter and route management)
* [wintun.dll](https://www.wintun.net/) in the same directory as `openfortivpn.exe`
  or in the system PATH

**Building with MinGW-w64 (MSYS2):**

1. Install [MSYS2](https://www.msys2.org/) and open a MinGW64 shell.
2. Install dependencies:
   ```shell
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl mingw-w64-x86_64-ninja
   ```
3. Build:
   ```shell
   mkdir build && cd build
   cmake .. -G Ninja
   ninja
   ```

**Building with MSVC:**

1. Install [Visual Studio](https://visualstudio.microsoft.com/) with C/C++ workload.
2. Install OpenSSL via [vcpkg](https://vcpkg.io/):
   ```shell
   vcpkg install openssl:x64-windows
   ```
3. Build:
   ```shell
   mkdir build && cd build
   cmake .. -DCMAKE_TOOLCHAIN_FILE=[vcpkg root]/scripts/buildsystems/vcpkg.cmake
   cmake --build . --config Release
   ```

**Running:**

Download `wintun.dll` from https://www.wintun.net/ and place it next to
`openfortivpn.exe`, then run from an **Administrator** command prompt:

```shell
openfortivpn vpn-gateway:8443 --username=foo
```

For multiple Windows tunnels, use a unique adapter name for each instance:

```shell
openfortivpn vpn-gateway:8443 --username=foo --pppd-ifname=office-vpn
```

The adapter name is restricted to ASCII letters, digits, `-` and `_`.

### Building and installing from source

For other distros, you'll need to build and install from source:

1.  Install build dependencies.

    * RHEL/CentOS/Fedora: `gcc` `automake` `autoconf` `openssl-devel` `make` `pkg-config`
    * Debian/Ubuntu: `gcc` `automake` `autoconf` `libssl-dev` `make` `pkg-config`
    * Arch Linux: `gcc` `automake` `autoconf` `openssl` `pkg-config`
    * Gentoo Linux: `net-dialup/ppp` `pkg-config`
    * openSUSE: `gcc` `automake` `autoconf` `libopenssl-devel` `pkg-config`
    * macOS (Homebrew): `automake` `autoconf` `openssl@1.1` `pkg-config`
    * FreeBSD: `automake` `autoconf` `libressl` `pkgconf`

    On Linux, if you manage your kernel yourself, ensure to compile those modules:
    ```text
    CONFIG_PPP=m
    CONFIG_PPP_ASYNC=m
    ```

    On macOS, install 'Homebrew' to install the build dependencies:
    ```shell
    # Install 'Homebrew'
    /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

    # Install Dependencies
    brew install automake autoconf openssl@1.1 pkg-config

    # You may need to make this openssl available to compilers and pkg-config
    export LDFLAGS="-L/usr/local/opt/openssl/lib $LDFLAGS"
    export CPPFLAGS="-I/usr/local/opt/openssl/include $CPPFLAGS"
    export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH"
    ```

2.  Build and install.

    ```shell
    ./autogen.sh
    ./configure --prefix=/usr/local --sysconfdir=/etc
    make
    sudo make install
    ```

    If targeting platforms with pppd < 2.5.0 such as current version of macOS,
    we suggest you configure with option --enable-legacy-pppd:

    ```shell
    ./autogen.sh
    ./configure --prefix=/usr/local --sysconfdir=/etc --enable-legacy-pppd
    make
    sudo make install
    ```

    If you need to specify the openssl location you can set the `$PKG_CONFIG_PATH`
    environment variable. For fine-tuning check the available configure arguments
    with `./configure --help` especially when you are cross compiling.

    Finally, install runtime dependency `ppp` or `pppd`.

Running as root?
----------------

openfortivpn needs elevated privileges at three steps during tunnel set up:

* when spawning a `/usr/sbin/pppd` process (Linux/macOS) or creating a TUN
  adapter (Windows);
* when setting IP routes through VPN (when the tunnel is up);
* when adding nameservers to `/etc/resolv.conf` (Linux/macOS) or configuring
  DNS via netsh (Windows).

On **Linux/macOS**, you need to use `sudo openfortivpn`.
If you need it to be usable by non-sudoer users, you might consider adding an
entry in `/etc/sudoers` or a file under `/etc/sudoers.d`.

On **Windows**, run openfortivpn from an Administrator command prompt or
PowerShell.

For example:
```shell
visudo -f /etc/sudoers.d/openfortivpn
```
```text
Cmnd_Alias  OPENFORTIVPN = /usr/bin/openfortivpn

%adm       ALL = (ALL) OPENFORTIVPN
```
Adapt the above example by changing the `openfortivpn` path or choosing
a group different from `adm` - such as a dedicated `openfortivpn` group.

**Warning**: Make sure only trusted users can run openfortivpn as root!
As described in [#54](https://github.com/adrienverge/openfortivpn/issues/54),
a malicious user could use `--pppd-plugin` and `--pppd-log` options to divert
the program's behaviour.

SSO/SAML/2FA
------------

In some cases, the server may require the VPN client to load and interact
with a web page containing JavaScript. Depending on the complexity of the
web page, interpreting the web page might be beyond the reach of a command
line program such as openfortivpn.

In such cases, you may use an external program spawning a full-fledged
web browser such as
[openfortivpn-webview](https://github.com/gm-vm/openfortivpn-webview)
to authenticate and retrieve a session cookie. This cookie can be fed
to openfortivpn using option `--cookie-on-stdin`. Obviously, such a
solution requires a graphic session.

When started using `--saml-login` the program creates a web server that
accepts SAML login requests. To login using SAML you just have to open
`<your-vpn-domain>/remote/saml/start?redirect=1` and follow the login steps.
At the end of the login process the page will be redirected to
`http://127.0.0.1:8020/?id=<session-id>`

Contributing
------------

Feel free to make pull requests!

C coding style should follow the
[Linux kernel coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html).
