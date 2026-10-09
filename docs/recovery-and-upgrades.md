# Recovery and offline upgrades

This describes implemented software and its acceptance limits. Unit tests do
not establish gateway, privileged platform or installer support.

## Metadata and credentials

Both managers accept a legacy array and schema 1 profile metadata. Unknown
schemas/fields fail before mutation. Migration retains `.profiles-schema0-backup.json`;
headless also saves the private consistent `.migration-backup-schema0.json` pair.
Desktop recovery collects intent credentials referenced by neither active
metadata nor schema 0 backup. Backup refs delay collection until the backup is
removed. Portable backups contain independent password copies.

Desktop Settings exports/restores at an absolute path. Export refuses an existing
destination and includes stored passwords; session passwords are excluded.
Restore refuses active, starting, mutating and unfinished attempts. It retains a
private old pair, stages new refs with intents and commits all refs in one metadata
replacement. Interrupted staging leaves old metadata; startup collects orphaned
refs. These commands are local IPC only.

A metadata write error blocks profile reads/writes, exports and new connections:
rename may already be visible even if parent-directory fsync fails. Settings
provides “重新读取并恢复配置仓库”. Stop connections and finish process recovery
first. Reload retries durability, validates disk metadata, performs shared intent
GC, clears session credentials and installs the authoritative disk snapshot.
Failure leaves the gate closed. Active connections can still be stopped.
The shared `ProfileRepository` port and profile services now govern both adapters'
save/delete/restore policy under their storage locks. Portable archive validation,
complete-catalog revision preparation and certificate-pin normalization happen
before staging. Internal credential refs, orphan secrets, duplicate IDs and
revision exhaustion fail before credential writes. Session changes occur only
after durable commit.

Shared ReferenceBackend fault injection and credential-journal regressions cover
interrupted staging, committed metadata, superseding saves, partial GC, retained
migration refs and invalid/symlink records. Desktop restore also exercises 11
failure boundaries with actual private local credential and metadata files and
synthetic passwords. This is evidence for the macOS local-file backend, not
native Windows Credential Manager or Linux Secret Service failure acceptance.
The desktop additionally holds a private, no-symlink repository lifetime lock;
another binary or offline tool receives a busy-owner failure.

Headless has `backup --output PATH` and `restore --input PATH`. Restore requires
the offline service lock and no unfinished runs. Reads validate the opened file,
owner, private permissions and bounds. Use mode 0600 for transferred Unix backups.
Backups contain passwords; never attach them as diagnostics.

## Headless bundle replacement

Install stops the installed service, obtains its offline lock and refuses
unfinished attempts. The fixed manager, engine and unit are staged together with
SHA-256-addressed prior payloads in the private state `bundle` directory.
`pending.json` precedes the first replacement. Later install rolls back interrupted
work before proceeding; `previous.json` retains the prior complete bundle.
Executable modes precede replacement and directories are synced. Corruption or
external replacements block recovery before any restore writes. Uninstall also
requires confirmed stop, offline lock and resolved attempts.

`rollback --no-start` restores the prior manager, engine and unit together. Without
the flag it starts the restored service. Profile data is retained. Before rolling
back to a pre-schema binary, stop the service and run `prepare-legacy-rollback`
using the current binary. It saves a private consistent pair and exports current
schema 0 metadata without changing ID-keyed passwords. Then rollback without
starting, and start the old service. A current binary can migrate that array again.

Debian unpack writes package-owned `/usr/lib/openfortivpn-manager-headless`
staging rather than overwriting the fixed live bundle. Postinst invokes the staged
manager to record and replace the manager/engine/unit as one durable group. The
shared package builder verifies Linux x86_64 ELF inputs. The latest real-ELF
container dpkg matrix passed install, unpack, configure, exact-hash grouped
rollback, busy-owner refusal, token preservation and remove. Its prior payload
markers and systemctl are synthetic; no real systemd service or VPN is claimed.
Evidence is retained in `dpkg-profile-service.log` under the task's evidence directory.

Fault, corruption, external replacement, mode and offline schema tests pass.
Real systemd/installer acceptance and signed installer rollback remain unfinished.

## Desktop privileged components

Helper 0.1.6 stages the fixed engine, helper and invoking user's sudoers rule as
one recoverable bundle under `/var/lib/openfortivpn-manager/components`. Rule
syntax passes visudo before any target changes. Sources use bounded, no-follow,
same-handle reads. Bundle schema 2 binds each entry to the exact target path and
mode, including sudoers 0440, preventing replay onto another user's rule.

Running helpers keep a shared component lock through child reaping and both
output drains. Install, rollback and uninstall require its exclusive lock and
scan the bounded nested instance directories for every user; symlinks fail closed.
Interrupted installations recover before another install. The `rollback` command
must run from the packaged helper with fresh administrator authorization; the
installed passwordless helper cannot replace or roll back itself.

Unix helper, headless and root desktop launchers share the durable root-owned
`/var/lib/openfortivpn-manager/network/active.json` reservation and its stable
file lock. This excludes conflicting managers and upgrades before engine spawn.
Dropping a lock never deletes the record. Only actual reap, output drain and
confirmed engine cleanup release it. Helper records are deleted and parent-synced
before the global reservation; failures retain a recovery path. Helper run setup
failures use exit 72 to avoid generic-exit automatic retry loops.

Helper 0.1.6 owns its child through `OwnedProcess::wait_reaped`: wait inspection
errors retry with a capped delay until actual reap. Partial output-reader setup,
identity, signal and registration failures stop/reap the child and drain/join
every reader already started before component guards are released. Recovery
records remain after an uncertain or forced cleanup. Local helper tests pass 14
cases; real installed-helper execution remains a separate acceptance gate.

Desktop recovery invokes helper `recover-network ATTEMPT --acknowledge-cleanup`.
The privileged adapter verifies owner/attempt and absence of the whole group,
parses the entire bounded instance batch before deletion and syncs the result.
When the global owner is already absent, the same locked command can collect old
subordinate records only if every selected group of that user is provably absent
and cleanup has been explicitly confirmed. Unknown identities, live/reused
process groups, permission errors and corrupt records remain blocked.

Machine authority now acquires the native store nonblocking after its own lock.
Any native transaction reservation, orphan `binding-` record, malformed journal
or busy worker rejects finish, manual acknowledgement, new acquisition and
maintenance before destructive recovery callbacks. A composite maintenance
guard retains both locks until maintenance ends and drops the native lock first.
If `active.json` was lost or its unlink became visible before a sync failure,
headless still holds an idle native guard through local anchor deletion; manual
legacy acknowledgement cannot discard native recovery evidence. Complete native
resource recovery must precede it. Nine authority regressions and one headless
offline-ack regression pass without host network changes.

Root direct launchers durably create their local recovery record before the
system reservation. When explicitly supported by the probed engine, a separate inherited startup
socket holds the C engine until both process-group records are durable; EOF fails
before gateway/network work. Legacy engines receive their original arguments;
exclusive ownership is still durable, but unknown pre-registration recovery
remains blocked. Failed exec/setup releases unstarted reservations before
removing the local recovery anchor; release failure preserves that anchor.
Schema 2 records distinguish this proof from legacy group-zero uncertainty.
This closes the new-record pre-registration window; older unbound records remain
conservative. Linux headless native resource handshakes are now integrated;
helper/desktop native worker integration, other-platform handshakes, real signed
helper installation and complete app-bundle/data rollback remain pending.

Windows desktop uses a durable machine authority in protected ProgramData before
spawn and for explicit recovery. Its stable lock and owner records bind SID,
executable and process creation identity, retain uncertain recovery anchors and
reject reparse paths. MSVC all-target Clippy and pure policy tests pass; actual
elevated cross-admin, ACL and reparse acceptance has not run.

## Native providers and stress

The coordinator has durable transactions, exact fingerprint cleanup, shared
exception-route refs and an OS file lock. Linux headless native mode now connects
the engine's ordered resource handshake to its native transaction worker. It
supports IPv4 direct split routes with metric 0 and scoped DNS, validates an up
point-to-point interface and durably binds it before mutation. Readiness requires
applied resources, engine acknowledgement and an interface-up recheck. Release
failure, uncertain apply or external replacement retains ownership and recovery
state; cancelled callers cannot drop running workers. Shutdown joins supervisors
and native workers before dropping the service lock.

The Linux namespace suite passes 30 tests, including real rtnetlink routes, a
private fake resolved D-Bus service, combined rollback and pure lifecycle/policy
tests. This is not 30 real-kernel tests or a FortiGate acceptance run.
`sh scripts/verify-linux-network.sh` builds unprivileged and runs tests only
inside `sudo -n unshare --net`; the developer host network is never mutated.

macOS has a `sysctl`/`PF_ROUTE` route backend and SystemConfiguration supplemental
DNS. Route tests cover bounded codecs, exact snapshots, interface identity,
PID/sequence ACK matching and local Unix transport; 16 focused tests pass without
PF_ROUTE mutation. Only global routes with metric 0 are implemented. Scoped
routes do not authorize cleanup. Darwin lacks atomic full-field compare-and-delete,
so the final external-writer race and identical-property replacement remain
platform limitations requiring explicit VM acceptance.

Windows has IP Helper routes and scoped local NRPT DNS policy bound to adapter
LUID. It rejects overlapping foreign policy, checks exact effective/local policy
and unknown owned-rule properties, proves DNS-server egress and joins owned
PowerShell processes. MSVC all-target checks, pure policy tests, script parsing
and a mock DnsClient module in a real PowerShell process pass; no actual Windows
DNS policy was changed.

Helper/desktop native resource workers, full-tunnel/physical gateway exceptions
and other-platform engine handshakes still require implementation. Real macOS
route/DNS and elevated Windows route/DNS/authority tests, signed helper execution
and gateway acceptance remain pending. Conservative exclusivity stays enabled;
coordinated concurrent networking remains disabled.

The ignored `lifecycle_stress` test uses real fake processes, with no VPN/network
changes. Set `OFV_STRESS_SECONDS=86400` and an absolute `OFV_STRESS_EVIDENCE` path.
It checks overlap, cancelled retries, journals, redaction, bounded logs and memory
after saturation. `OFV_STRESS_MEASURE_ONLY=1` creates diagnostic evidence with
`acceptanceEligible:false`. Retained log messages use immutable snapshots and
HTTP serialization uses a bounded reusable JSON buffer pool. Response bytes own
the buffer until the last slow reader drops it, preserving v1/v2 wire formats.

An earlier macOS RSS-budget failure at 246 seconds motivated the buffer pool;
the threshold and allocator environment were not relaxed. A historical 900-second
pooled run passed, but its temporary artifact was lost during the environment
restart. The latest retained normal 300-second run passed 438 cycles with
`maxLiveAttempts:1`, 29,106,176-byte RSS high-water and 17,084,416-byte physical
footprint (`lifecycle-stress-profile-service.json`). The earlier retained
450-cycle result remains historical evidence. These synthetic runs never mutate
host networking and cannot establish gateway/platform or 24-hour acceptance.
There is no successful 24-hour evidence yet.
