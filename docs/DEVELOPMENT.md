# Development and verification

Gateway DNS transport tests require Python 3 and run as part of CTest. They use
only loopback TCP peers and synthetic DNS records; no test changes host DNS or
routes. `ctest --test-dir BUILD_DIR -R gateway_dns_transport --output-on-failure`
checks compression, CNAME ownership, response identity, partial frames, deadlines
and CLI validation. Real public-resolver probes and gateway handshakes are
separate read-only diagnostics, not evidence of successful VPN authentication.

The manager uses Rust, Tauri 2/Svelte 5, and the C openfortivpn engine. macOS development needs Xcode command-line tools, Rust, Node 22, Corepack/pnpm 10.24.0, CMake, pkg-config, and OpenSSL. Linux desktop additionally needs WebKitGTK/Tauri dependencies; headless has no WebView dependency. Windows needs the supported compiler/OpenSSL/Wintun distribution described in the release guide.

Run `zsh scripts/verify-local.zsh` from the repository root. `VERIFY_SKIP_DESKTOP=1` skips the desktop on Linux servers without Tauri dependencies; this is a reduced check, not full validation. `VERIFY_C_BUILD_DIR` can select a CMake build directory. The script fails immediately when a check fails and does not install software or change network settings.

Tests use temporary directories, synthetic certificates, and fake child processes. Real helper installation, route/DNS mutation, PID recovery, installer upgrades, OTP and SAML compatibility require disposable platform VMs and a controlled FortiGate gateway. Record those results separately from local unit tests. Never use production passwords in fixtures.

The implementation task ledger is `.codex-tasks/reliability-control-plane/`. The audit and accepted plan are in `technical-review.zh-CN.md` and `development-plan.zh-CN.md`. A task is complete only when its stated acceptance evidence exists; a compiling scaffold is not a tested platform capability.


Private engine control development is described in `engine-control.md`. It is
currently opt-in in headless `serve --experimental-control`, keeps conservative
network exclusivity, and is not evidence of accepted OTP gateway compatibility
or native concurrent network backends. Desktop/helper OTP channel integration is implemented locally; runtime/gateway
acceptance and SAML integration remain pending in the task ledger.

Run `node scripts/audit-npm.mjs` after a frozen install and `cargo audit --file`
for each Cargo lockfile. Known upstream desktop warnings are recorded in
`dependency-security.md`; successful unit tests do not clear them.

Local verification evidence is retained under
`.codex-tasks/reliability-control-plane/evidence/`. Treat completed logs as
checkpoint evidence; a previous passing log does not cover later edits.

`sh scripts/package-headless.sh MANAGER ENGINE OUTPUT_DIR` builds tar/deb artifacts
from existing Linux x86_64 ELF binaries. It never installs them. Debian payloads
use `/usr/lib` staging so dpkg unpack cannot overwrite the running `/usr/local`
bundle before its transaction records the previous version.
`verify-headless-package.sh` requires an explicitly enabled disposable Docker
container and uses real dpkg transitions with a synthetic systemctl. It does not
establish systemd or gateway acceptance. `scripts/package-test.Dockerfile` supplies
real declared package dependencies and HTTPS apt trust.

For optional macOS cross-builds, `linux-container-linker.zsh` and
`linux-container-ar.zsh` provide gcc/ar from an isolated, network-disabled Linux
container. Set `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER`,
`CC_x86_64_unknown_linux_gnu` and `AR_x86_64_unknown_linux_gnu` to their absolute
paths, and place `TMPDIR` inside `build/`. These are build adapters and cannot
replace native platform execution tests.

## Frontend state and settings

The Svelte page delegates appearance, autostart, desktop preferences, and remote
settings to injectable services under `app/src/lib/services/`. Components keep
their existing props and v1 IPC commands. Appearance updates render and persist
immediately; native theme/zoom operations run in order and coalesce pending
changes. Shared native queues survive page remounts. A new preferences read waits
for an already submitted write, while disposed writes still queued are skipped.
Request generations reject older refreshes and suppress disposed-page replies.
Page continuations also check lifecycle before starting a VPN after privilege
checks or helper setup and before copying/exporting a late configuration reply.

Remote status events remain authoritative over earlier snapshots or command
replies. One-time tokens remain in the current modal's memory, never in browser
storage or status snapshots; close/dispose clears them and late replies cannot
reveal them in a reopened modal. Clipboard results cannot update a closed modal.
Browser opening checks the modal session again after loading the opener module.
Already submitted native IPC or clipboard operations may finish after disposal;
disposal is not proof that they were cancelled.

Run `node --test tests/desktop-state.test.mjs tests/desktop-settings.test.mjs` and
`cd app && corepack pnpm check && corepack pnpm build`. The settings suite covers
20 synthetic asynchronous ordering/failure scenarios, including page remounts
and extracted production page handlers,
and its latest focused evidence is
`.codex-tasks/reliability-control-plane/evidence/desktop-settings-tests.log`.
These tests do not establish native desktop or real gateway acceptance.
