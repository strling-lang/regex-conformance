# Tests

Cross-module fixtures and structural, positive, negative, boundary, fault,
regression, security, reproducibility, and integration tests live here. Test
fixtures are not published empirical evidence.

The bootstrap identity/schema suite is under `schema/`; its immutable inputs and
published expected bytes/IDs are under `fixtures/identity/`.

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
