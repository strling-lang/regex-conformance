# Control Plane

Provider-neutral services for machine inspection, resource planning/admission,
environment lifecycle, cache/transfer management, durable recoverable local
state, lifecycle events, CLI/API surfaces, and hard containment live here. The
Control Plane owns operational orchestration only; it does not own canonical
definitions, empirical evidence, certification truth, or Notion development
status.

The initial implementation is a Python 3.12 standard-library-first service layer
under `python/`, governed by D101. Its controller facade is client-neutral;
machine discovery, diagnostics, models, rendering, and CLI parsing are separate
and independently testable. Versioned JSON is the interoperability boundary, so
future daemon, TUI, CI, dashboard, provider, or alternative-language clients do
not depend on Python object layouts.

## Machine doctor

The first safe operation is read-only machine inspection:

```sh
python control-plane/python/run.py doctor --trust-class development
python control-plane/python/run.py machine inspect --format json --trust-class development
```

The report identifies OS and architecture, explicitly configured trust class,
provider availability, process capabilities, and distinct persistent, cache,
build-scratch, execution-scratch, protected-spool, RAM, swap, and CPU pools.
Every measurement carries source, accuracy, visibility, observation time, and
staleness. Unknown telemetry remains `null`; it is never coerced to zero or
available capacity. Configured pool paths are inspected through their nearest
existing ancestor and are never created by the doctor.

Executable discovery reports `detected_unverified`, not `available`; provider
identity, health, and limits are verified by the separate environment-manager
lifecycle. When logical pools share a physical backing store, the doctor reports
that relationship and explicitly warns that the capacities are not additive.

Trust is never inferred from hardware or installed providers. Set it through
`--trust-class` or `STRLING_REGEX_TRUST_CLASS`. Pool paths may be supplied with
`--pool-path KIND=PATH` or the `STRLING_REGEX_*_PATH` environment variables.
All doctor output declares `inventory_only: true` and
`mutation_permitted: false`.

Run its cross-platform fixtures, boundary tests, and real-host smoke test with:

```sh
python -m unittest discover -s tests/control_plane -v
```

## Transactional environment lifecycle

The environment manager exposes a provider-neutral service API for:

`plan → admit → acquire → verify artifacts → construct → verify runtime →
verify smoke probes → fingerprint → Ready → release`.

Provider descriptors negotiate required and optional capabilities before any
mutation. Plans are explicitly non-mutating. The manager independently reads and
SHA-256-verifies acquired regular files, rejects symlinks and artifact-set
substitution, compares behaviorally relevant runtime/configuration facts, and
requires every recipe smoke probe to pass. A download, install, provider handle,
or version string alone can never produce `Ready`.

Lifecycle records retain every transition, provider failure, verification
failure, rollback outcome, and cleanup-required state. Provider failures remain
operational and never become regex observations. Release failure likewise stays
explicit instead of pretending an environment disappeared. Diagnosis is
available without changing lifecycle state.

Ready records receive an `environment-fingerprint:h` derived from verified
artifacts, provider implementation/capabilities, runtime facts, relevant
configuration, isolation/network policy, and a verification digest. The
fingerprint uses the exact locked RFC 8785 implementation and is cross-checked
against the certified schema identity tooling. Physical transaction IDs are
separate `opid:v1:environment:u7` values and local provider handles/paths do not
enter scientific identity.

P16A-T02 certifies the common contract through materially different native-like
and OCI-like deterministic providers. It does not claim those fixtures are
certified ecosystem environments. Concrete runtime archetypes and minimal
certified environments enter in P17. Global lifecycle events, CLI environment
commands, and hard workload containment remain in their separately gated P16A
tasks.

Local Control Plane state remains operational and non-canonical.

## Predictive resource preflight and admission

Every environment, campaign, and shard now carries a deterministic,
non-mutating resource plan before expensive work begins. Plans distinguish
expected and conservative upper-bound downloads, expanded environments, build
and execution scratch, result spool, RAM, CPU, and transfer volumes. Each
forecast declares `known`, `measured`, `estimated`, `bounded`, or `unknown`
confidence with provenance; unknown never means zero.

The admission engine applies integer basis-point confidence margins and typed
pool safety reserves, rejects stale or ambiguous inventory, verifies provider,
capability, trust, and concurrency constraints, and aggregates logical disk
pools that share a physical backing store. This prevents separately plausible
cache and spool allocations from double-spending the same bytes. Preflight is a
hard gate before environment acquisition. Dynamic re-evaluation returns either
`admitted`, recoverable `backpressure`, or non-recoverable `drain`, with stable
issue codes and concrete remediation.

Environment admission accepts only the exact preflight report produced under
the active policy for the same planned transaction. Admission consumes inventory
without changing it; containment, measured telemetry feedback, and automatic
forecast calibration remain later P16A contracts.

## Cache, cleanup, and transfer management

The cache manager builds a deterministic provider-neutral inventory containing
immutable content digests, realized logical and reclaimable sizes, backing
provider, dependency edges, active and future leases, pins, last use,
reacquisition time and cost, reconstruction difficulty, upstream fragility,
retention class, and verification provenance. This inventory is local
operational state and explicitly cannot claim registry authority.

Cleanup is a two-stage transaction. Planning first reconciles every inventory
entry with provider reality, excludes stale, missing, mismatched, unsafe,
unverified, pinned, leased, dependency-required, protected-spool, and rare
fragile entries, then applies a deterministic weighted score to the remaining
candidates. A refused plan is non-mutating. Execution rechecks protection,
digest, identity, size, accounting basis, and reclaimable bytes immediately
before each deletion; it is cancellable and reports expected versus actual
reclaimed bytes using a bounded observed filesystem free-space delta without
hiding partial failures. The filesystem provider is
root-confined, rejects symlinks and non-regular files, uses no-follow reads, and
rechecks device/inode identity before unlink.

Transfer records bind an immutable expected digest and size to acquire,
download, or upload intent. Every physical attempt is append-only. Resumable
downloads verify the durable partial-file checkpoint before continuing, fsync
each chunk, retain interrupted and failed attempts, and publish with a
non-overwriting atomic link only after exact final verification. A corrupted
checkpoint, destination race, or digest mismatch never becomes a completed
transfer. Structured lifecycle events, CLI commands, and progress rendering
remain owned by their later P16A contracts.

## Durable local state and restart reconciliation

The durable-state service stores only local operational projections in a
single-controller SQLite database. It uses WAL journaling, full synchronous
commits, immutable checksummed migrations, compare-and-swap record generations,
idempotent command IDs, one epoch per atomic batch, and append-only transition
history. Persisted payloads use RFC 8785 bytes plus SHA-256 integrity and reject
credential-bearing keys, locators, authorization values, private keys,
non-finite values, unsafe integers, invalid Unicode, and non-JSON objects.

Every process start creates a supervised session and closes admission until
restart reconciliation passes—even after a clean shutdown. A live process lock
prevents two controllers from claiming one database. An orphaned active session
is recorded as an interrupted shutdown; partial SQL transactions remain rolled
back. Unsupported future schemas, migration checksum changes, unexpected schema
objects, malformed metadata, broken transition chains, tampered payloads,
inconsistent reconciliation reports, and SQLite integrity failures all fail
closed before a new session can operate.

Reconciliation compares the stable snapshot digest with fresh, explicitly
identified repository-manifest, immutable-evidence, and provider-reality facts.
Source authority is constrained by record kind. Missing, stale, future,
unverified, wrong-authority, or contradictory facts quarantine affected local
records and keep admission blocked; they never become provider success or
scientific evidence. Verified absence produces a traceable tombstone. Matching
facts verify state, changed facts supersede the local generation, and missing
state is reconstructed from the supplied sources. The plan is deterministic and
non-mutating; execution rechecks its input snapshot and commits all actions and
the readiness decision atomically.

Corrupt or lost state is never repaired by pretending it was authoritative.
Explicit recovery moves every surviving SQLite file into an access-restricted
quarantine directory, hashes it in a non-canonical manifest, creates a fresh
store, and reconciles from identified external sources. The original bytes are
not deleted. `DurableStateService` exposes snapshot, plan, apply, reconcile,
transaction, health, readiness, and clean/aborted close operations through the
client-neutral controller facade. CLI commands and structured lifecycle events
remain later P16A contracts.
