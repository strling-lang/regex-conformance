# Schemas

Versioned schemas, identity projections, canonicalization declarations, and
cross-language reference fixtures live here. Certified artifacts name exact
schema revisions; mutable `latest` aliases are not certification inputs.

Schema validation and canonicalization tooling is introduced by its separate
bootstrap contract.

## Bootstrap toolchain

- `json/` contains Draft 2020-12 structural schemas.
- `identity-profiles/` contains typed, immutable projection contracts used by
  certified fixtures.
- `tooling/python/` contains validation, projection, identity, collision, and
  fixture tooling.
- `tooling/node/` contains the independent dependency-free JCS oracle.

`json/machine-inventory.schema.json` defines the versioned machine-readable
Control Plane doctor report. Machine inventory is fresh, recoverable operational
state—not canonical evidence—and therefore has no content-derived scientific ID.
Typed resource pools preserve unknown values as `null` and retain discovery
source, time, accuracy, visibility, and staleness.

`json/environment-lifecycle.schema.json` defines the recoverable operational
transaction record for provider-neutral planning, admission, verification,
rollback, Ready, release, and failure states. It cannot validate as Ready without
an admitted plan, non-empty verified artifacts and passing smoke observations,
a runtime identity, verification digest, realized fingerprint, provider handle,
and no failure or rollback.

`json/resource-admission.schema.json` defines deterministic environment,
campaign, and shard forecasts plus preflight/dynamic admission reports. It
preserves confidence and provenance, uses safe integers and basis-point margins,
accounts for typed pools and shared physical stores, and forbids an admitted
report from carrying a blocking issue or failed/unknown evaluation. These are
operational plans and decisions, not canonical observations or evidence.

`json/cache-operations.schema.json` defines three disjoint operational wire
records: non-canonical cache inventories, planned-and-reconciled cleanup
reports, and append-only resumable transfer histories. It forbids local cache
or cleanup state from claiming registry authority, binds every transfer to an
exact digest and size, requires safe integer accounting, and keeps cleanup
planning explicitly non-mutating. Cross-field identity, ordering, and exact
expected/actual reconciliation are additionally enforced by the typed Control
Plane models before serialization.

`json/operational-state.schema.json` defines disjoint non-canonical wire
records for local snapshots, external reconciliation observations,
deterministic reconciliation plans, and applied reports. Snapshots carry the
database schema version, stable store ID, epoch, startup/admission status,
typed generation-bearing records, payload digests, and provenance sources.
Plans bind the exact stable snapshot and observation-set digests; reports bind
the before/after state plus every applied action and unresolved issue. The
schema forbids canonical-authority claims, constrains tombstones and quarantine
states, and keeps safe-integer and UUIDv7 domains explicit. Model/store checks
add JCS integrity, secret rejection, migration/history verification, freshness,
source-authority, and cross-source conflict semantics that JSON Schema alone
cannot express.

`json/lifecycle-event.schema.json` defines the strict machine interface for
individual lifecycle events, durable journal cursors and batches, and derived
progress projections. Events preserve logical stream identity separately from
physical attempt number, require safe integer coordinates, expose explicit
terminal state, and permanently set `canonical_authority` to false. Typed model
and journal checks add RFC 8785 attribute/event digests, secret rejection,
global hash-chain integrity, contiguous stream/attempt rules, exact resume
coordinates, bounded-retention gap detection, and restart-aware rate/ETA
semantics that cannot be expressed as independent JSON fields.

`json/control-plane-command.schema.json` defines the shared non-canonical
command result used by human and automation clients. It binds the selected
command and action to an outcome, stable exit code, dry-run and mutation flags,
secret-safe payload plus SHA-256 digest, and typed issues. The schema forbids
dry-run mutation, mutation by non-execution actions, successful results with
issues, and any claim of canonical authority.

`identity-profiles/environment-fingerprint.v1.json` defines the scientific
identity projection for verified realized environments. It excludes physical
transaction IDs, cache paths, provider handles, and timestamps while binding the
recipe revision, target coordinates, actual artifacts, provider implementation
and capabilities, runtime/configuration facts, isolation/network policy, and
verification digest. Its permanent schema-family ID is
`rcid:v1:schema-family:u7:019ff82c-9517-76fb-a67d-c461e9145384`.

Run all schema and fixture checks from the repository root:

```sh
.venv/bin/python schemas/tooling/python/run.py validate-repository
.venv/bin/python schemas/tooling/python/run.py verify-fixtures
```
