# Tests

Cross-module fixtures and structural, positive, negative, boundary, fault,
regression, security, reproducibility, and integration tests live here. Test
fixtures are not published empirical evidence.

The bootstrap identity/schema suite is under `schema/`; its immutable inputs and
published expected bytes/IDs are under `fixtures/identity/`.

The adapter suite under `adapters/` exercises strict framed JSON, negotiation,
manifest/source self-verification, exact request bindings, typed octet/scalar/
code-unit materialization, native index preservation, captures, replacements,
splits, native compile failures, unsupported surfaces, process/service failures,
timeouts, output and enumeration limits, malicious SQL text, source symlinks,
and AST-enforced thinness. Provider-aware certification tests independently
prove native adapter memory/CPU containment and the intentionally daemon-side
MySQL resource boundary.

The public-CI trust-boundary suite lives under `ci/`. It deliberately mutates
workflow text to prove that self-hosted runners, dangerous triggers, write
permissions, secret references, and floating action tags fail closed.

The Control Plane foundation suite lives under `control_plane/`. It drives
Linux, Windows, and macOS fixtures through the same controller service, validates
the machine-inventory schema and deterministic JSON, exercises actionable
failure diagnostics, proves unknown telemetry remains unknown, confirms the CLI
is only a client, and runs a read-only real-host smoke test.

The same suite drives native-like and OCI-like environment providers through one
transactional lifecycle. It proves planning is non-mutating; artifact bytes,
runtime identity, smoke probes, and JCS fingerprints gate Ready; operational
transaction identity does not perturb realized identity; and partial acquisition,
artifact substitution, symlinks, capability gaps, admission denial, cancellation,
runtime mismatch, smoke failure, rollback failure, diagnosis outage, and release
failure remain explicit and recoverable.

Resource-planner tests bind provider plans to environment preflight, expose
campaign and shard requirements, and validate the admission schema. Boundary
and adversarial cases cover exact capacity, one-byte shortfall, uncertainty
margins, unknown forecasts, stale/future inventory, wrong units, missing backing
identity, shared-store double spending, active usage, provider/capability/trust
gaps, concurrency pressure, forged reports, cross-policy reuse, and explicit
backpressure or drain outcomes.

Cache and transfer tests prove permutation-stable inventory identity,
deterministic weighted eviction, lease/pin/dependency/spool/rare-artifact
protection, stale and contradictory reality refusal, exact planned-versus-actual
reclamation, cancellation, partial deletion failure, allocated-size accounting,
root confinement, symlink rejection, post-plan substitution defense, corrupted
checkpoint refusal, resumable interrupted downloads, append-only upload
attempts, final digest enforcement, schema authority boundaries, and controller
integration.

Durable-state tests exercise the SQLite store and restart boundary as an
operational safety contract. They cover clean restart and abrupt process exit,
exclusive controller locking, full-batch rollback after an injected partial
write, optimistic generation and epoch conflicts, idempotent command replay,
stale reconciliation plans, missing/stale/future/unverified/wrong-authority and
contradictory source facts, quarantine and recovery, verified tombstones,
payload and migration tampering, future-schema refusal without mutation,
credential persistence refusal, explicit corruption quarantine, full state-loss
rebuild, wire-schema authority boundaries, and controller-service integration.
The Windows symlink test skips only when the host denies unprivileged symlink
creation; the same case remains required on capable/Linux hosts.

Lifecycle-event tests prove deterministic canonical digests, secret refusal,
global and per-stream ordering, exact idempotent replay, terminal immutability,
bounded retention with explicit cursor gaps, restart-safe retry coordinates,
attempt-local rate and ETA, subscription wakeup, controller integration, and
environment/cache/transfer producer coverage. Adversarial cases tamper event
bytes, database columns, stream heads, cursor identity, retention policy,
progress order, resume status, schema authority, and transfer interruption; the
journal must fail closed while infrastructure outcomes remain operational rather
than becoming regex observations.

CLI tests validate the shared command schema, stable outcome/exit-code mapping,
deterministic secret-safe payloads, parity between human and JSON rendering,
canonical JSONL events, default dry-run behavior, two-factor mutation consent,
admission refusal without mutation, post-mutation verification failure, typed
campaign/cache/evidence inputs, duplicate-key and credential-bearing input
rejection, service-unavailable behavior, and omission of unimplemented future
authority surfaces.

Telemetry and containment tests prove that complete numeric measurements
adapt future resource estimates only after a conservative sample threshold,
while partial runs, unrelated keys, tampered databases, credential-bearing
identifiers, and low sample counts fail closed or remain ineligible. Seeded
runaway process trees, timeouts, output floods, diagnostic floods, CPU and
memory pressure, unsupported host limits, launch failures, and concurrent work
demonstrate that provider safety limits remain independent of prediction and
cannot manufacture semantic observations.

The Linux-only foundation acceptance test independently composes these Control
Plane services into one clean-host certification scenario. It proves that host
inspection and dry-run planning precede mutation; insufficient disk is refused;
bounded low-confidence estimates receive their safety margin; interrupted and
identity-mismatched acquisitions roll back; an admitted environment reaches a
verified Ready state; cache protection, transfer resume, durable restart,
structured progress, and process-tree containment survive their fault cases.

Schema tests also validate the governed P17 vertical-slice archetype crosswalk.
They conserve all 19 design-seed candidates; prove that only in-scope subjects
are selected; require standalone, host/runtime, database/embedded, native-build,
native-runtime, and OCI-service coverage; keep the selection non-executable
until exact T02 coordinates exist; and reject collisions, unknown coverage,
convenience selection, false deferrals, and accounting gaps.
