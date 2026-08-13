# Desktop product build and release

OpenFortiVPN Manager ships the desktop control plane and the matching VPN
engine as one bundle. Do not distribute a desktop shell without the engine and
its platform runtime files.

## Supported packages

| Platform | CI runner | Packages | Runtime privilege model |
| --- | --- | --- | --- |
| Linux x86-64 | Ubuntu 22.04 | `.deb` | One-time restricted helper installation |
| Linux headless x86-64 | Ubuntu 22.04 | `.deb`, `.tar.gz` | systemd root service; no desktop dependency |
| macOS arm64 | macOS 14 | `.app`, `.dmg` | One-time restricted helper installation |
| macOS x86-64 | macOS Intel | `.app`, `.dmg` | One-time restricted helper installation |
| Windows x86-64 | Windows Server 2022 | `.msi`, NSIS `.exe` | Application manifest requests UAC elevation |

Windows packages include the Windows engine, Wintun and the required MinGW
OpenSSL runtime DLLs. Linux and macOS packages build and embed the Unix engine.

## Local macOS build

Install Node.js 22, pnpm 10, stable Rust, CMake, pkg-config and OpenSSL 3, then:

```shell
cd app
pnpm install --frozen-lockfile
pnpm check
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml --all-targets --all-features
cargo test --manifest-path src-tauri/helper/Cargo.toml --all-targets
APPLE_SIGNING_IDENTITY=- pnpm tauri build --bundles app,dmg
```

The application and DMG are written below
`app/src-tauri/target/release/bundle/`. The default repository configuration
does not embed a distribution identity. Set `APPLE_SIGNING_IDENTITY=-` only for
an internal ad-hoc build.

## Continuous delivery

`App CI` runs frontend checks, Rust formatting, Clippy/tests and a Tauri
no-bundle build on Linux, macOS and Windows for every app change. `Desktop App
Release` first runs the same application checks plus the C engine test suite,
the privileged helper and the headless service tests, then builds the installable
packages on all three operating systems for the
release branch, when manually dispatched, or when a `v*` tag is pushed. The
release workflow installs and starts the Linux DEB and Windows MSI in their
native runners and starts the bundled macOS app before accepting the artifacts.
Every build uploads a platform artifact and a `SHA256SUMS-*.txt` file. A tag
publishes the DMG, DEB, headless tarball, EXE, MSI and checksum files in one complete GitHub
release; the unpacked macOS `.app` remains available as a workflow artifact.

When the protected signing secrets are not configured, a `v*` tag still builds,
installs and smoke-tests every package, but publishes the result as a GitHub
prerelease. The release notes explicitly identify macOS as ad-hoc signed and
Windows as unsigned. Set the repository variable `OFFICIAL_SIGNED_RELEASE=true`
only after all signing and notarization secrets below have been configured.

Before tagging, update the version in `app/src-tauri/tauri.conf.json`,
`app/src-tauri/Cargo.toml` and `headless/Cargo.toml`; the release workflow derives
the Debian metadata and artifact names from the headless crate version. Do not
bump `app/src-tauri/helper/Cargo.toml` merely to match the application version:
changing the helper binary makes an otherwise unnecessary administrator-approved
helper update mandatory. Change the helper crate version only when its code,
dependencies or privileged protocol actually changes. Review release notes and
run the local checks. Create
an annotated tag only from the reviewed commit:

```shell
git tag -a v0.1.0 -m "OpenFortiVPN Manager v0.1.0"
git push origin v0.1.0
```

Do not publish a production release until the CI jobs for all three operating
systems are green and the generated checksums have been compared with the
downloaded installers.

## Signing and trust

The repository does not contain signing secrets. Without them, tagged builds are
published only as prereleases for internal testing: Gatekeeper may reject an
unnotarized downloaded app and SmartScreen does not trust an unsigned installer.
Production releases require a macOS Developer ID Application certificate plus
notarization credentials and a Windows Authenticode certificate plus timestamp
service. After configuring every secret, set the repository variable
`OFFICIAL_SIGNED_RELEASE=true` so the workflow publishes a normal release.

The release workflow expects these protected secrets:

- macOS: `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`,
  `KEYCHAIN_PASSWORD`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID`;
- Windows: `WINDOWS_CERTIFICATE`, `WINDOWS_CERTIFICATE_PASSWORD`,
  `WINDOWS_TIMESTAMP_URL`.

## Installation verification

For every release candidate:

1. Install on a clean supported operating-system account.
2. Confirm the bundled engine version is shown as available.
3. Add two disposable profiles and verify they can run concurrently while each
   profile still owns at most one instance.
4. Test connect, disconnect, explicit reconnect, automatic reconnect and
   cancellation of a pending retry.
5. Verify a successful tunnel reaches an internal test address, then quit the
   app while connected and confirm routes, DNS and all VPN child processes are
   removed.
6. Relaunch after a forced app termination and verify stale-process recovery
   uses the installed helper without another password prompt. Removing or
   damaging the helper must block cleanup and request a fresh helper install.
7. Enable remote access on loopback, verify the certificate fingerprint, test
   rejected and authorized API calls, rotate the token and disable the server.
8. Reboot once to verify the application auto-start option and per-profile
   auto-connect settings independently.

Linux dependencies and package commands are in [`linux.md`](linux.md). On
macOS, drag the app from the DMG to `/Applications`. On Windows, install either
the MSI or NSIS package and accept the UAC prompt when the manager starts.

## Upgrade, backup and rollback

Profiles and remote-access settings live in the operating system's per-user app
data directory for `com.baozaodetudou.openfortivpn`. Passwords and the remote
token live in the operating-system credential store and are intentionally not
included in a plain-file backup.

Before a managed upgrade, disconnect all tunnels and back up the app data
directory. Install the new package over the old version, open it once and verify
profiles, credential availability and the bundled engine. To roll back,
disconnect, uninstall the current package, install the previously verified
installer and restore the matching app-data backup. Never copy plaintext VPN
passwords into the profile JSON.
