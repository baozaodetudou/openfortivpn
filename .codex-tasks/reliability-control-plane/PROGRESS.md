# Progress

Sections below are chronological checkpoint history. The final checkpoint and current TODO.csv are authoritative; earlier pending statements describe their original checkpoints.

2026-10-09: resumed from completed audit. Created `codex/reliability-control-plane` preserving the audit documents. Added repository rules and local verification entry point. Runtime implementation and regression validation in progress; T01–T24 not yet accepted.

Baseline validation from audit: desktop 44 tests, helper 7, headless 19, Svelte check, format/Clippy, and two CTest targets passed on macOS. These are baseline results only.

## Implementation checkpoint

The task ledger distinguishes `implemented_local`, `partial`, `not_started`, and `awaiting_platform_acceptance`. None means full R3 acceptance. T16 has a transaction core and an actual conservative engine gate; native resource handshake/backends T17–T19 and SAML T21 still need software implementation, independently of missing VMs/gateway credentials. Do not characterize all remaining work as external acceptance.

Implemented increments include shared validation and TLS identity policy, process ownership through reap/drain, conservative network exclusivity, cross-process headless transactions, credential reference journals, durable crash recovery, conditional revisions, private backup/restore, shared v2 operations and log cursors, strict remote sessions, shared bounded logs and allowlisted diagnostics. Desktop and headless now use the same EngineLifecycle; desktop timers use generation-aware RetryTimer. Windows journals bind a PID to creation time and executable; core cross-compilation passed, actual Windows recovery is unverified.

Verification before the latest increments: full local verify passed, including core 11, HTTP 5, headless library 37/binary 4/cross-process 2 (one worker intentionally ignored), helper 7, desktop 45, Svelte check/build, Node 5 and CTest 6. After lifecycle/log/diagnostics increments, core 19 and HTTP 6 passed; desktop 45 and Clippy passed. A fresh full run is still required after the final edit.

Headed Edge DOM evidence: invalid-token login stays on the login form; successful synthetic login opens the console; a new profile form disables and hides unsupported privilege setup; logout returns to the login form. Browser engine confirmed `Edg/154.0.0.0`. The temporary fake API and test browser sessions were closed. The agent-browser native launcher omitted its executable setting; a task-specific agent-browser daemon received the correct Edge environment before CLI operations.

No commits, pushes or release publication performed. Work remains on `codex/reliability-control-plane`.

## Shared identity, private authentication and delivery checkpoint

Desktop/headless use the same locked redo TLS identity store, including cert/key hash metadata, SAN validation, private same-handle reads and crash recovery. Windows private-file ACL validation and replacement checks compile; Windows runtime acceptance is pending. Remote tokens rotate through a shared live token without restarting HTTPS/VPN. Token storage now zeroizes replaced values. Terminal operations/instances have count and seven-day TTL bounds. Headless has an offline allowlisted diagnostics command.

The shared network coordinator implements bounded canonical plans, overlap/domain checks, shared gateway exception reference counts, exact fingerprint cleanup, durable recovery and network epoch invalidation. It is not yet wired to native route/DNS adapters or full resource handshakes. C private mode gates PPP/Wintun creation with a conservative exclusive decision; this is not coordinated multi-tunnel support.

Private OTP is implemented in C, the shared broker, headless owned stdin, remote v2/Web, desktop owned stdin/local IPC/remote adapter, desktop AuthenticationPanel and fixed privileged helper. Helper code changed, so its version is now 0.1.3. Experimental control remains opt-in and advertised managerChallenges/coordinated capabilities remain false. Nonblocking private input has cancellation/write-budget regressions. Windows pipe-mode code requires runtime acceptance. Desktop/headless reject wrong attempts or private protocol downgrades and stop the owned attempt; v2 cannot use text logs as readiness proof.

Headed Edge OTP DOM acceptance used a synthetic API: submission clears input, removes the challenge form and shows Synthetic VPN connected; logout clears input and restores login. Fake server and task browser were closed. No host routes, DNS or installed helper were modified.

Four Cargo audits returned zero vulnerabilities; npm installed graph scan returned zero advisories after compatible lockfile upgrades (rustls 0.23.45 and h2 0.4.16). Desktop GTK 3 glib unsound/unmaintained warnings remain recorded in docs/dependency-security.md. pnpm is pinned to 10.24.0, with corepack used locally. CI includes shared all-feature TLS tests, but has not run on GitHub. Release evidence/SBOM generation was smoke-tested with fixture acceptance attachments, not real installer acceptance.

Prior full verification passed with core 35, HTTP 8, headless library 40/binary 4/cross-process 2, helper 7, desktop 46, Node 12, Svelte check/build and CTest 8. After the desktop increment: OTP fixtures 2 passed, private input tests 2 passed, helper 8 passed, Svelte 0 errors/0 warnings and build passed. Final verification is running in /tmp/ofv-verify-desktop-auth-final.log; Windows core checks use x86_64-pc-windows-msvc (GNU target is not installed). Update counts only after completion.

Next independent software work: network journal faults/automatic rollback; full resource handshake/global privileged coordination; native Linux/macOS/Windows adapters; attempt-bound SAML callback; shared supervisor/use cases/Repository and credential migration/backup/upgrade paths; page modularization/long stress harness; installer upgrade/rollback software. Preserve unresolved ledger items.

## Native providers, recovery and measured stress checkpoint

Linux rtnetlink route ownership and partial-failure rollback passed in an isolated Docker network namespace. A private zbus peer exercises actual D-Bus encoding for resolved DNS; combined route/DNS/store rollback and restart recovery passed (6 native/fake-provider tests). No host networking changed. macOS supplemental DNS has a SystemConfiguration dictionary backend and pure identity tests; macOS route support/integration remain absent. Windows IP Helper routes pass MSVC all-target compilation/Clippy; DNS and runtime tests remain absent. These modules are not manager/helper resource handshakes.

Headless tar installations stage manager/engine/unit as a hash-addressed durable bundle, with interrupted replacement recovery and previous-bundle rollback tests. Debian payloads are overwritten before postinst, so that path is not covered. Offline legacy schema downgrade preserves a private consistent backup pair. Desktop local-only portable export/restore stages credential references and commits metadata once; full credential-backend failure testing remains pending.

Rust SAML loopback broker now has cryptographic state, exact attempt/generation/path/Host, single consumption, expiry/cancellation, bounded HTTP requests and real TCP regressions. C/private-manager/browser flow remains unintegrated and capability stays off. ProfileEditor and BackupPanel are extracted; modalFocus handles Tab/Escape/return focus. Final Edge QA is in progress.

Lifecycle stress harness uses real fake child processes, concurrent admitted connects, cancellation, reaping, journal checks, log bounds and redaction. Earlier dense snapshot runs failed RSS budget at 98/177 seconds. Diagnostic sparse/dense comparison and heap census attribute much of growth to snapshot allocation churn (heap census about 6.5 MiB live at 93 MiB physical footprint); this does not prove long-run stability. Immutable Arc-backed log snapshots now avoid message copies across polling responses while retaining wire shape. A normal 600-second high-frequency run is in progress; no 24-hour pass exists. Diagnostic runs explicitly mark acceptanceEligible=false.

Desktop metadata failures now block further profile writes/new connects/exports until an offline durable reload and intent GC succeeds. This covers replacement-visible but parent-fsync-failed outcomes and prevents stale cache overwrite. Regression tests simulate precommit and post-replacement failure, credential-ref preservation, and cache reload. SaveProfileInput/raw working passwords now zeroize on failure paths. Fresh full verification is still required.

## Shared credential recovery and component upgrade checkpoint

Desktop credential intent creation/recovery/GC now use manager-core::credential_journal. The whole intent batch is bounded and parsed before deletion; invalid or symlink records cause no GC. Three regressions cover pre/post metadata commit, later superseding refs, interrupted GC, backup deferral and malformed records. Desktop metadata uncertainty tests and all 51 desktop tests pass; native credential APIs and full archive restore fault injection remain pending.

Helper version is now 0.1.4 and consumes the shared core without Tauri/HTTP dependencies. Engine/helper/UID-bound sudoers 0440 are staged, durably replaced and rolled back together after visudo. Bundle schema 2 records exact target paths. Shared run guards/exclusive install guards and registered unfinished-instance refusal protect upgrades. Core target-rebinding/mode and lock regressions pass; helper 8 tests and Clippy pass. The pre-registration helper crash gap and signed app/data rollback remain unresolved.

ConnectionPanel, CertificatePrompt, PrivilegeSetup and RemoteSettings are extracted, with shared presentation CSS. Svelte check/build pass. A headed Edge session confirmed Edg/154: editor Tab wraps to close; Escape restores New Profile focus; reopening clears the synthetic password; Settings and remote dialogs trap Tab and close with Escape. Backup/reload controls are present. Browser preview has no real Tauri IPC, so these DOM checks do not establish archive/credential behavior. The task browser is being closed.

The normal macOS 900-second stress failed at 246 seconds / 347 cycles on the unchanged RSS growth budget; physical footprint was 10.4 MiB. Arc snapshots and pre-reserved HTTP serialization reduced actual footprint but did not close T23. Isolated Linux uses the same full snapshot/serialization workload and is running a normal 300-second check. Do not report a 24-hour pass. Full verify is in /tmp/ofv-full-verify-final.log; final counts/status must come from completion output.

## Durable continuation checkpoint: ownership, restore and client races

The previous temporary logs/sessions were lost when the local environment
restarted. Existing source changes remained on `codex/reliability-control-plane`.
All verification for this continuation is retained under `evidence/`; none of the
lost artifacts has been recreated as if it were a new measurement.

Unix launchers now share `network_authority` across headless, helper and root
desktop attempts and maintenance. Helper reserves before spawning, holds its
component lock until reap/drain, and only releases after confirmed cleanup.
Nested per-user instance records block upgrades. Direct launchers create local
journals before the global reservation and hold the actual C engine behind an
inherited launch socket until both process-group journals are durable. Schema 2
marks gated pre-spawn evidence; older unbound records do not gain that proof.
Helper subordinate deletion/fsync precedes global release. Fault tests preserve
that owner after sync failure, and orphan collection parses/checks the entire
bounded user's batch before deletion. Unknown/live/reused groups fail closed.
Helper remains 0.1.5; it has not been installed on the developer host.

Both managers use shared OwnedProcess/AsyncOwnedProcess and output drain
primitives. SAML session delivery now joins the callback worker; a full-suite
intermittent TCP test failure was followed by ten passing focused runs and a
passing full suite after joining. This does not establish gateway compatibility.
Full supervisor/business use-case migration and native resource-mode networking
are still software work, not merely platform acceptance.

Automatic reconnects now carry attemptSequence in addition to profileGeneration
and revision. Desktop services own monotonic merges, bounded logs, typed error
messages, late subscription disposal and snapshot/event authority. A slow
refresh cannot overwrite a newer profile/privilege/remote event or a newer
refresh; disposed pages reject replies. AppSettings and the main dialogs are
extracted. Five client-state regressions pass. Further page business-state
extraction remains pending.

Shared validation now bounds profile IDs/names and reserves the token ID for
both managers. Portable restore rejects internal credential references, orphan
secrets, duplicate profiles, missing auto-connect credentials and invalid bytes.
Whole-catalog version/pin preparation happens before credential staging. Tests
cover monotonic versions, uppercase pins and overflow without partial catalog
writes. Native credential APIs and complete archive fault injection remain pending.

`verify-complete-checkpoint.log` passed: core 75, HTTP 9, headless library 43,
binary 4, cross-process 2 (subprocess worker intentionally ignored), helper 13,
desktop 51, Node 17, Svelte zero errors/warnings and build, CTest 9. Format and
Clippy with warnings denied passed for all graphs. A Windows default-feature
core all-target check passed; this is not Windows runtime or all-feature TLS
acceptance. The normal 300-second stress passed 450 cycles, maxLiveAttempts 1,
RSS high-water 29,868,032 bytes, physical footprint 17,952,768 bytes, no host
network mutation. The historical 900-second pooled pass remains a recorded
observation with a lost artifact; there is no 24-hour pass.

Debian live payload replacement was moved to package-owned /usr/lib staging;
postinst now delegates the grouped /usr/local replacement to the staged manager.
CI and local builds share `scripts/package-headless.sh`, which checks Linux
x86_64 ELF inputs. Real dpkg verification is being prepared with actual declared
ppp/systemd dependencies; systemctl is intentionally synthetic. Linux C build,
package transitions and fresh dependency scans will be appended after completion.
No commits, pushes, signed artifacts or releases have been created.

Linux/package follow-up: the final Linux x86_64 manager cross-build passed. The
actual C engine built against static OpenSSL inside a network-disabled Debian
container and all eight available Linux CTest targets passed (the Node driver
was unavailable in that image; macOS runs its ninth CTest target). The shared
packaging script built real ELF tar/deb inputs. `dpkg-upgrade-rollback.log` passed
initial install, unpack without replacing live targets, configure, exact-hash
manager/engine/unit rollback, token preservation and removal with retained data.
The prior package has explicit synthetic appended payload markers; systemctl is
synthetic, so no real service or VPN is claimed. No host installation occurred.

Fresh cargo-audit 0.22.2 reports zero vulnerabilities in all four lockfiles.
Desktop GTK/glib unsound/unmaintained warnings remain; no advisories were ignored.
The installed 121-package npm graph reports zero advisories. JSON evidence is
retained. Audit tooling was built under ignored build/audit-tool and did not
modify the user's global Cargo tool installation.

Final ownership review additionally preserved local recovery anchors when a
global release fails, and cleaned unstarted reservations on setup/exec failure.
An actual permission-denied exec regression verifies later admission after
cleanup; a corrupt global record retains its local anchor. Launch-gate support
is explicitly negotiated: legacy metadata/version keeps original arguments and
records no gated proof. A legacy fixture rejects the new flag and still connects.
The actual C CLI is now exercised by the Node pipe test before configuration
loading, not just by the extracted C driver. Node waits for stream close before
checking output. These latest changes are covered by verify-final-accepted.log;
its completed result supersedes the earlier checkpoint counts above.

## Native platform and shared profile checkpoint

This checkpoint supersedes earlier implementation/status assertions without
rewriting their historical sections. Evidence below is retained in `evidence/`.
The T01–T24 ledger remains conservative: local implementation and isolated tests
are distinct from actual platform, gateway, signing and long-run acceptance.

Both adapters now implement the shared ProfileRepository port and common
save/delete/restore policy under their storage locks. Shared validation,
conditional revisions, credential/session actions, durable auto-connect
requirements, whole-catalog preparation and pin normalization run before writes.
Desktop immutable credential refs/intents are staged before metadata replacement;
session state changes only after durable commit. Shared ReferenceBackend faults
and actual macOS private local credential/metadata files exercise 11 restore
failure boundaries with synthetic secrets. Desktop additionally holds a private
repository lifetime lock, with busy-owner and symlink regressions. Native Windows
Credential Manager and Linux Secret Service failure acceptance remain missing;
the full shared connection use case is still software work.

Linux headless now supports explicit
`serve --experimental-control --experimental-native-network` with the real C
resource protocol and a native provider worker. The pre-PPP gate requires
resourceProtocol 1 and `grant_native`. Bounded network_begin/resource/commit
frames bind attempt, request, order/count, canonical plan, epoch and the up
point-to-point interface. Transport identity uses getpeername, including the
proxy peer. The native transaction durably stores interface ownership before
inspection/mutation, applies direct IPv4 split routes with metric 0 before scoped
DNS and proves DNS-server egress. Default/full-tunnel routes, transport-covering
CIDRs, gateway exceptions, pppd call/plugins and use-peerdns are rejected.

Readiness requires matching apply success, network_applied acknowledgement and
the final interface-up check. Release validates its frame before mutation; the
C reader drains at most one known matching late apply result under one bounded
deadline. Premature, post-release and arbitrary stale frames fail. cleanup_result
alone cannot release an unreleased native owner. Uncertain creation, lost
interfaces and external replacement retain binding/journal/global ownership.
Worker lifetime survives async cancellation until thread join, and shutdown
joins supervisors and native workers before relinquishing the service lock.
Traditional CLI and legacy grant behavior remain; experimental options default
off and coordinated concurrent networking remains disabled.

macOS has the PF_ROUTE/sysctl route provider plus supplemental DNS. Sixteen
focused parser/fake-table/local Unix transport tests pass without PF_ROUTE
mutation. Snapshots, interface index/AF_LINK/lastchange identity and PID/sequence
ACKs are bounded and checked. Metric 0 global routes are the implemented scope;
scoped routes do not authorize cleanup. Darwin's final external-writer race and
identical-property replacement cannot be eliminated with atomic full-field
compare-and-delete, so native capability acceptance remains off pending VM tests.

Windows implements scoped NRPT policy, IP Helper routes and the durable machine
authority used by desktop spawn and explicit recovery. Protected ProgramData,
SID/executable/creation identity, stable locks and retained uncertainty anchors
are implemented. The NRPT script checks effective/local foreign overlaps, exact
owned properties and DNS egress and joins owned PowerShell processes. The
`windows-implementation-checkpoint.json` records passing MSVC all-target Clippy,
pure supervisor/policy tests, real PowerShell parser and mock DnsClient transport.
It explicitly records no Windows runtime acceptance, elevated DNS mutation,
cross-admin or ACL/reparse acceptance.

`verify-native-platform-increment.log` completed successfully: core 118, shared
HTTP 9, headless library 48/binary 4/cross-process 2 (worker intentionally
ignored), helper 13, desktop 53, Svelte zero errors/warnings and production build,
CTest 9/9. Node has 42 passing tests: desktop state 10, settings 20, remote client
7, release manifest 3 and dependency audit 2. Formatting and all-feature Clippy
with warnings denied pass. This ordinary run intentionally skips the long stress
test and does not establish platform/gateway acceptance.

`linux-native-namespace-tests.log` passes 30 tests, mixing actual namespace
rtnetlink routes, private fake resolved D-Bus and pure lifecycle/policy checks;
do not count these as 30 real-kernel tests. Native C pipe exchanges, Linux C build
and the native manager cross-build have retained evidence. No developer-host
network or installed helper was changed.

The latest normal synthetic stress evidence is
`lifecycle-stress-profile-service.json`: completed/acceptanceEligible true,
300 seconds, 438 cycles, maxLiveAttempts 1, RSS high-water 29,106,176 bytes and
physical footprint 17,084,416 bytes, hostNetworkModified false. The earlier
450-cycle artifact remains historical, and the historical 900-second observation
has no retained successful artifact. No successful 24-hour run exists.

`dpkg-profile-service.log` passes real-ELF package staging, upgrade, grouped
manager/engine/unit rollback, busy-owner refusal, token preservation and removal.
Package-owned /usr/lib staging protects the fixed /usr/local bundle until its
transaction records prior payloads. Prior payload markers and systemctl are
synthetic; this is not a real systemd/VPN or signed installer acceptance result.

Remaining independent software includes the complete shared connection use
case, helper/desktop native resource worker integration, full-tunnel and physical
gateway exceptions, other-platform engine handshakes, SAML browser → manager → C
private flow, further full-page/independent remote Web client work and complete
desktop app/data rollback and signing. Additional gates include actual privileged
macOS/Windows runtime, native credential stores, real systemd/helper/installer
transitions, FortiGate OTP/SAML/network compatibility, formal signing and 24-hour
stress. T01–T24 are not all complete. No commits, pushes or releases were created.

Continuation work is in progress after these accepted logs: native recovery
authority guards, shared connection admission and helper reaper changes require
their own final verification and version update before being recorded as passed.

## Shared connection admission and native ownership checkpoint

The continuation software above is now implemented and has focused evidence;
the final combined verification, refreshed stress and package acceptance are
still being coordinated separately. This checkpoint does not mark all T01–T24
complete or replace remaining software work with external acceptance.

Shared `ConnectAdmission` is integrated into desktop User/Startup/Automatic and
headless User/Startup entries. Adapters retain their runtime lock from fact
collection through reservation. Only healthy, published User intent can reuse
an instance. Stopping, recovery, unpublished startup, other owners, repository
restore/mutation/recovery and shutdown produce typed rejection before reuse.
Headless startup explicitly submits Startup origin. Existing v1/Tauri shapes
and desktop Chinese presentation remain. The full connection use case, child
ownership, credentials, generations and cleanup remain adapter responsibilities.

`connect-admission-checkpoint.json` records RED regressions against the temporary
old desktop reuse policy and completed GREEN verification: core focused 5,
desktop 56, headless library 52/CLI 4/storage integration 2 (two tests intentionally
ignored), format checks and warnings-denied all-feature Clippy for core, desktop
and headless. These are local synthetic regressions, not Windows runtime or
gateway acceptance.

Unix authority now checks `LockedStore::idle_guard` after its machine lock.
The nonblocking native lock, complete journal load and bounded binding-prefix
scan reject any reservation, orphan binding, malformed journal or busy worker.
finish/manual acknowledgement/new acquisition/maintenance cannot bypass that
check; acknowledgement fails before its destructive quiescence callback. The
composite `MaintenanceGuard` retains both locks through maintenance and drops
native before authority. Headless additionally holds an idle native guard
through local recovery-anchor deletion when no global owner remains.

`native-authority-red.log` retains the original erroneous release regression;
`native-maintenance-lock-red.log` retains the guard-lifetime RED failure.
`native-authority-tests.log` then passes 9 authority tests, including held native
lock exclusion, orphan/malformed refusal and callback ordering.
`native-offline-ack-tests.log` passes the missing-global-owner local-anchor
regression. No native platform mutations were used in these tests.

Helper is now 0.1.6. OwnedProcess `wait_reaped` keeps the exact Child and retries
wait errors until successful reap, with capped retry delay. All partial
output-reader setup, identity, signal and registration errors reap and drain/join
already-started readers before guards disappear. A supervisor error retains its
error and recovery state even after wait succeeds; it cannot become successful
cleanup. `helper-owned-reaper-tests.log` passes 14 helper tests,
`helper-owned-reaper-core-tests.log` passes 7 supervisor tests, and
`helper-owned-reaper-clippy.log` passes warnings-denied Clippy. No helper was
installed on the developer host.

At this checkpoint `verify-native-ownership-final.log`, the refreshed normal
300-second stress and final package matrix have not yet been recorded as
completed by the coordinating agent. Their results and final combined counts
will be appended only after exit status and retained evidence are confirmed.

## Final combined native ownership verification

`verify-native-ownership-final.log` completed with exit 0 against the final
software source: core 127, HTTP 9, headless library 52/CLI 4/cross-process storage
2, helper 14 and desktop 56 (264 Rust tests total). The deliberate long-stress
and subprocess-worker ignores are separate from these counts. All four graphs
passed format and all-feature Clippy with warnings denied. Node passed 42 tests,
Svelte reported zero errors and zero warnings, the frontend production build
passed, the real PowerShell mock DnsClient matrix passed, and CTest passed 9/9.

The refreshed normal stress completed with exit 0 after 300 seconds and 423
cycles. It kept maxLiveAttempts at 1, RSS high-water at 29,495,296 bytes and
physical footprint at 17,248,256 bytes; completed/acceptanceEligible are true.
The retained JSON and log are `lifecycle-stress-native-ownership.{json,log}`.
This is a synthetic fake-engine lifecycle/log test and does not establish
24-hour or real VPN acceptance.

The final Linux core test executable passed 35 network regressions in a
network-disabled disposable Docker namespace, including actual rtnetlink/TUN
tests and a private fake resolved D-Bus service. The initial container path
failure is retained separately; it was corrected without source changes or a
repeated compilation. The final Linux manager and C engine rebuilt, and Linux
CTest passed 8/8 (the container does not include the Node driver). The actual
Debian payload matches the rebuilt manager/engine and frozen README exactly.
The isolated dpkg matrix covers staging, upgrade, grouped rollback, busy-owner
refusal, token preservation and removal with synthetic systemctl. Input hash
comparison confirms that final build and package sources did not change.
No host installation, route or DNS mutation took place.

The changed headless lockfile's fresh cargo-audit scan covered 208 dependencies
with zero vulnerabilities and zero warnings. Other graph audits and the
desktop GTK warnings retain their prior evidence; this fresh headless scan
does not reclassify those platform dependencies. `evidence/index.json` indexes
the final results, earlier RED failures, focused regressions and unresolved
acceptance gates.

Full shared connection/lifecycle migration, helper/desktop native workers,
full-tunnel/gateway exception transactions, other-platform handshakes, verified
SAML browser/manager/C association, complete desktop app/data rollback and
signing remain software work. Real gateway/systemd/native credential-store and
macOS/Windows platform tests and 24-hour stress remain acceptance work. The
SAML callback contract has been requested; no unsupported gateway parameter or
weaker callback association has been invented. T01–T24 remain incomplete.
No commit, push, helper/service installation, signed artifact or release was
created.

## Verified checkpoint submission

The user authorized committing and pushing this tested checkpoint. The final
manager, engine and packaging source fingerprints match all 135 recorded
input files. After the completed local verify, only trailing whitespace in a
Svelte type declaration was removed; executable behavior is unchanged. Raw
validation logs are preserved with a narrowly scoped whitespace attribute.
Submission uses the existing `codex/reliability-control-plane` branch with a
Chinese/English commit message. This authorization does not mark remaining
T01–T24 work complete or authorize a release, signing or host installation.

## Merge preparation — 2026-10-14

The user requested merging the previously pushed checkpoint into `master`.
The target still points at the original baseline and has no conflicting commits.
Remote checks revealed OpenSSL/Windows header and pipe-read compatibility issues,
a legacy OpenSSL version API call, mismatched Rust/JavaScript Tauri minor versions,
and platform-sensitive generated newlines and mock JSON-array enumeration.
The fixes retain the existing feature gates and runtime contracts. C formatting
now follows the existing style checks; the kernel checker recognizes the OpenSSL
context typedef and allows POSIX pthread positive errno contracts. Raw external
validation artifacts retain their original endings.

Full `scripts/verify-local.zsh` validation passed with the real PowerShell 7 mock
matrix enabled. The desktop `tauri build --no-bundle --debug` and npm audit also
passed (121 scanned packages, no advisories). Evidence is retained in
`evidence/merge-local-20261014.log`, `evidence/merge-tauri-build-20261014.log`, and
`evidence/merge-npm-audit-20261014.log`. Generated remote output also matches
when the TypeScript system newline is set to CRLF. Windows PowerShell 5.1 and
MinGW execution are left to the PR CI; the mock now enumerates JSON arrays
explicitly and exposes diagnostic errors only for synthetic inputs. No host
network changes, service installation, signed artifact or release is involved.
