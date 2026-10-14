# Private engine control protocol (experimental)

`openfortivpn --manager-control=<attempt UUID>` enables bounded, typed input on
an inherited anonymous stdin pipe and adds `attemptId` to event v2. The ordinary
CLI remains interactive. Initial credentials must already be supplied in manager
mode; `--cookie-on-stdin` cannot share the control pipe in either option order.
Authentication/concurrent-network capabilities remain disabled in the engine
capability response pending the complete platform/gateway acceptance matrix.

Desktop opt-in uses `OPENFORTIVPN_EXPERIMENTAL_CONTROL=1` when starting the app.
The local OTP panel and remote v2 use the same challenge broker and owned pipe;
responses never replace stored passwords. Disconnect cancels the pipe and
challenge; reap releases them. Writes are nonblocking and have a five-second
budget. Windows requires successfully verified `PIPE_NOWAIT` mode at runtime;
Windows runtime acceptance is still pending. Helper 0.1.6 accepts only the
canonical optional `--manager-control=UUID` and matching `--owner-attempt=UUID` arguments on its fixed `run CONFIG`
operation and verifies inherited stdin is a pipe. Only the installed engine
parses control frames; administrative commands are absent from that protocol.
The helper update requires the existing administrator-authorized installation
flow and matching installed payload hashes.

Helper 0.1.6 retains the exact owned child and component/network guards when
wait fails, retries until actual reap and drains/joins every already-started
output reader on partial setup, identity, signal or registration failure. Such
errors retain recovery evidence rather than treating a stop request as exit proof.

Every command is a single LF-terminated line:

```text
OFV2 <attempt UUID> <32 lowercase hex request nonce> <action> <standard base64 value>
```

Frames are limited to 4096 bytes. UUID, nonce, exact action and canonical padded
base64 bind the response; NUL/CR/LF in decoded values, excess lengths, replay,
wrong attempts, timeout, interrupted reads and EOF fail. Responses are held in
memory and wiped in C/Rust. The input pipe is separate from engine output,
password configuration, PPP packets and privilege installation prompts.

| Event | Response | Current behavior |
| --- | --- | --- |
| `auth_challenge` | `auth_response` with OTP | 120-second deadline, byte bound, one response per request; rejected input exits authentication |
| `auth_challenge_closed` | none | Clears a matching outstanding challenge |
| `network_plan` | `lease_decision` with `grant`, `grant_native` or `deny` | 30-second deadline; before PPP/Wintun creation; `grant_native` requires resource protocol 1 and Linux headless opt-in |
| `network_begin` | none | Binds request, resource count and interface name/index/local address/transport peer |
| `network_resource` | none | Ordered, bounded route/DNS resources for the same attempt and request |
| `network_commit` | `network_result` with `applied` or failure | Applies only a complete validated native plan |
| `network_applied` | none | Engine acknowledges the matching apply result before readiness |
| `network_release` | `network_result` with `released` or failure | Validates the release request before native cleanup; incomplete release retains ownership |

The original `grant` flow retains conservative exclusive engine networking.
Linux headless also implements an explicit native flow with
`serve --experimental-control --experimental-native-network`. It remains
globally exclusive because implicit PPP networking is still present. The default
systemd service enables neither experimental option. Desktop/helper native
resource workers, other-platform handshakes, full-tunnel plans and physical
gateway exceptions remain software work; concurrent network capabilities stay
disabled.

The native flow accepts at most 128 resources, validates attempt/generation,
request identity, resource order/count, canonical plans and network epoch, and
rejects duplicate or post-commit frames. Its initial scope is IPv4 direct split
routes with metric 0 and scoped DNS. Routes must have nonzero prefixes, exclude
the actual transport peer and provide egress for every leased DNS server. The
transport address comes from `getpeername`, including a proxy peer. Full-tunnel,
gateway routes, pppd call/plugins and use-peerdns configurations fail explicitly.

The Linux worker verifies an up point-to-point interface against its name,
index and local address and durably stores that binding before native inspection
or mutation. It applies routes before DNS through the shared coordinator, which
retains exact created/borrowed resource identities, journals and uncertain
recovery. C emits `tunnel_up` only after a matching `applied` response, its
`network_applied` success acknowledgement and a final interface-up check. The
manager independently requires applied, acknowledged and unreleased native state.

Release has one 30-second deadline and may drain only one known matching late
apply result; arbitrary stale/malformed frames fail. A cleanup log or
`cleanup_result` cannot release a native attempt that has not completed resource
release. Lost interfaces, external replacements and uncertain creation retain
the binding, transaction journal and global owner. Native worker guards survive
async caller cancellation until the plain worker thread joins. Shutdown joins
supervisors and native workers before releasing service ownership.

Machine authority release and manual acknowledgement also require an idle
native store. Under the authority → native lock order, any native reservation,
orphan binding, malformed journal or busy worker blocks the operation before
subordinate recovery records can be deleted. Maintenance holds both locks for
its entire lifetime. Headless retains this native guard through local recovery
anchor deletion even when the global owner record is already absent.

Headless opt-in is `serve --experimental-control`. Its authenticated v2 challenge
API and remote input are connected to the actual owned child pipe. The manager
validates attempt/generation, consumes responses once and cancels them on reap;
stopping attempts cannot accept a reply. A late pipe failure cannot signal a new
attempt. Default service installation leaves the experimental option off.

Local tests include C decoder checks, real C stdin/event pipe exchanges with
denial/stale attempt/EOF and bounded native apply/release responses, Rust
fake-clock identity/deadline tests and fake-engine OTP/native readiness/cleanup
flows. The isolated Linux namespace suite passes 30 tests mixing real kernel
routes, private fake resolved D-Bus and pure lifecycle/policy tests; it does not
modify the developer host network. These checks do not establish a real gateway
handshake or platform acceptance. Desktop/helper OTP adapters are wired and locally tested;
actual helper execution, Windows pipe mode and FortiGate acceptance remain pending.

The legacy SAML parser validates loopback peer, exact Host/port, GET, bounds, token
syntax and no duplicate headers/body. `saml_broker` provides an actual ephemeral
loopback listener with random state, attempt/generation binding, expiry,
cancellation and single consumption; real TCP tests pass. Manager browser/engine
integration is unfinished. FortiGate support for the exact callback URL must be
established before enabling it; fixed legacy redirects do not provide state binding.

Unix direct launchers pass `--manager-launch-fd=N` on a separate inherited
socket only when the engine explicitly advertises `managerLaunchGate:true`.
An absent field/legacy version keeps the original launch arguments and
conservative system exclusivity; its unknown pre-registration recovery remains
blocked. Windows advertises false. This internal hint does not change the
v1 manager EngineInfo response. The C engine validates descriptor type/bounds, marks it close-on-exec,
and waits up to 30 seconds before reading configuration or contacting a gateway.
The only accepted byte is 1, sent after durable local/global process-group
registration. Denial, parent EOF, signals and timeout fail before network work.
This barrier is independent of experimental OTP control and uses no secrets.
Schema 2 system authority records mark this proof explicitly; schema 1 records
cannot acquire it through migration. The ordinary CLI does not require a gate.

SAML callback result delivery now joins the listener worker before returning;
a delivered result alone is not proof that listener/stream ownership ended.
