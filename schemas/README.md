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

The architectural vertical-slice executable boundary is defined by
`vertical-slice-coordinates.schema.json`,
`certified-environment-recipe.schema.json`, and
`minimal-environment-certification.schema.json`. Semantic validation binds the
activated selection to one exact coordinate registry, requires complete
release/profile/recipe accounting, derives recipe and isolation identities from
canonical bytes, and rejects mutable acquisition locators.

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

`json/cache-disk-pressure-qualification.schema.json` defines the compact scale
stress-certification report. It fixes the ten deterministic simulated cases,
nine safety invariants, accepted-decision references, exact source bindings,
and permanent non-authority declarations. The report cannot claim Docker use,
target behavior, canonical authority, or mutation of external evidence.

`json/million-scale-capacity-plan.schema.json` defines the compact million-scale
technical plan for a possible 1M campaign. It fixes the exact denominator and
shard ceiling, six-figure qualification measurement bindings, compute/memory/disk budgets, the
8 GB soft and 10 GB hard R2 storage boundaries, request/cost envelopes, exact
secret and variable interface names, official research provenance, and the
mandatory stop-before-execution gates. It cannot authorize Docker, execution,
credential establishment, or production publication.

`json/factorized-evidence-forecast.schema.json` defines the compact factorized-representation
lossless-representation measurement and unchanged-denominator capacity gate.
It binds the exact immutable six-figure manifest/member/count basis, 8 GB/10 GB
limits, deterministic reconstruction and corruption proofs, retained bytes by
evidence class, and owner-only second-stage trimming menu. It cannot claim an
evidence mutation, derived-data authority, Docker or credential use, paid
capacity, material R2 publication, or an implemented scope/retention change.

`json/known-universe-census-forecast.schema.json` defines the compact
declared-cutoff discovery ledger projection and revised factorized-evidence
capacity gate. It binds the external exhaustion-ledger hashes and counts,
keeps roots distinct from executable facilities, preserves unresolved
obligations, verifies bounded release/profile and storage arithmetic, and
cannot authorize publication, paid capacity, or scientific-scope reduction.

`json/evidence-pack-v2-manifest.schema.json` defines the production pack's
immutable manifest and independent content-addressed object catalog.
`json/attempt-diagnostic-envelope-v2.schema.json` defines the complete ordered
attempt diagnostic availability envelope, and
`json/raw-performance-samples-v2.schema.json` keeps benchmark/resource samples
as raw typed arrays rather than derived summaries.
`json/evidence-pack-v2-certification.schema.json` binds the measured six-figure qualification
reconstruction proof, exact pack/report identities, enriched evidence classes,
governed-canary platform forecast, 8 GB/10 GB admission gates, and permanent
no-paid-capacity/no-material-publication classification.

`json/evidence-pack-v3-manifest.schema.json` defines the compact future raw-
evidence manifest, its closed retained-fact contract, deterministic identity
and routine-process derivations, content-addressed blocks, bounded lookup,
ordered routine-stdout commitment, and exact omission allowlist.
`json/evidence-pack-v3-capacity-certification.schema.json` separates
lossless structural savings from the minimum retained-information change and
binds the measured million-corpus byte model to the declared-cutoff lower,
expected, and conservative 8 GB/10 GB capacity forecast.

The downstream synchronization family consists of strict Lab and Compatibility
projection schemas plus the Coverage Shard checkpoint and monotonic index
schemas. Cross-artifact validation checks canonical bytes, content and file
digests, contiguous predecessor linkage, frozen semantic/profile membership,
profile and coordinate reconciliation, evidence/exclusion/limitation trace
rules, and deterministic index reconstruction. Unknown cannot validate as
Unsupported, and low-level execution shards cannot enter the synchronization
index.

The regex semantic corpus, projection, vector-requirements, and denominator
schemas define the content-addressed semantic authority and its executable
consumer boundary. The companion compiler adds uniqueness, relation,
candidate-conservation, declared facet-template structural closure,
attribution, deterministic
profile-allocation, denominator arithmetic, and digest checks that cannot be
expressed as independent JSON fields. Those construction checks are not
independent evidence of researched semantic completeness.

`json/regex-semantic-corpus-v2.schema.json` governs the researched semantic
successor, together with its normalized feature research ledger and
deterministic research-completeness report. These schemas make semantic state,
scope, source binding, derivation, and stable scientific identity explicit;
they do not regenerate the accepted obligation or vector-requirement
populations.

`json/regex-semantic-corpus-v4.schema.json` and the semantic-universe audit,
candidate, source-coverage, freeze-manifest, authority-index, and identity-
allocation schemas govern the declared-cutoff freeze. The compiler adds
cross-artifact candidate closure, source-orphan detection, duplicate ownership
checks, parent/reference validation, bounded supersession semantics, and exact
predecessor-denominator byte commitments.

`json/semantic-knowledge-foundation-allocation.schema.json`,
`json/semantic-knowledge-foundation-manifest.schema.json`, and
`json/semantic-knowledge-foundation-acceptance.schema.json` govern the
integration gate over that freeze. The gate binds the frozen semantic and
research authorities, checks their non-overlapping ownership, verifies that
the structured semantic states are sufficient inputs to successor obligation
derivation, and preserves exact byte commitments to the predecessor
obligation, requirement, projection, and forecast artifacts.

`json/generated-assertion-derivation-catalog.schema.json` defines the shared
provenance contract for assertion-like generated fields. It requires
class-specific metadata for measurement, calculation, research-derived,
external-evidence, inference, constant-by-construction, and manual-decision
records. Semantic validation binds stable typed derivation handles to
content-derived method revisions, rejects dangling or stale references and
inappropriate gate strength, reconciles declared counts with named
populations, and requires deterministic complete inventory coverage.

`json/execution-provenance-policy.schema.json`,
`json/physical-attempt-evidence-v2.schema.json`,
`json/terminal-observation-content-v2.schema.json`,
`json/logical-execution-disposition.schema.json`, and
`json/execution-lineage-set.schema.json` define the prospective attempt and
terminal-outcome lineage. Cross-artifact validation enforces immediate
predecessors, checkpoint agreement, exact execution context, closed reset and
retry policy, fail-closed target attribution, first-terminal anti-laundering,
content-derived observation identity, repeat-signature grouping, and precise
population counts.

`json/scientific-identity-catalog.schema.json` and the semantic identity
validator define the permanent assigned-ID lock over current features,
variants, modifiers, operations, manifestations, interactions, obligations,
and requirements. The `production-vector-revision`,
`applicability-coordinate`, and `scientific-lineage` identity profiles define
the exact content-derived constructors for future production artifacts and
migration records. Legacy generated semantic products remain immutable and
resolve their readable keys through the catalog.

The certification schema family defines the versioned predicate contract,
digest-bound input set, deterministic C1-C7 report, separate authority index,
and adversarial fixture set. Contract, input-set, and report identities use
the existing content-derived identity architecture under permanent schema
family `rcid:v1:schema-family:u7:01a079d7-bff3-79f7-bd14-3184c831b9f5`;
issuance and authority actions retain assigned typed identities.

`json/scale-warehouse-reconciliation.schema.json` defines the compact six-figure warehouse
reconciliation report. It binds the certified campaign, evidence manifest,
execution report, recovery hash chain, both non-crediting infrastructure
segments, full-row commitments, immutable derived warehouse identity, and
permanent no-Docker/no-execution/no-authority declarations.

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

The JSON restart-resume qualification schema defines the deterministic 14-case governed recovery matrix, while the restart-resume execution schema validates live external interruption evidence. Both schemas permanently deny canonical, normative, and semantic authority. The typed scheduler adds exact transition, identity, canonical payload, hash-chain, commit-receipt, private-path, and secret-rejection checks.

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

`json/operational-telemetry.schema.json` defines separate, explicitly
non-canonical telemetry samples and deterministic calibration snapshots.
Samples contain only typed numeric operational measurements, bind an exact
attempt and calibration key, and distinguish complete from partial runs.
Snapshots become eligible only after a governed sample threshold and publish
conservative expected and upper bounds without acquiring semantic or evidence
authority. Typed models additionally enforce metric-name uniqueness,
cross-field bounds, RFC 8785 determinism, secret rejection, and append-only
sample identity.

`json/sustained-operating-envelope.schema.json` defines the tracked multi-day
qualification policy, external predecessor-linked measurement checkpoints, and
deterministically derived report. Typed validation additionally enforces one
logical execution across recovery attempts, exact cumulative counters,
required portable resource coverage, explicit unavailable temperature
telemetry, stability and overhead arithmetic, and report equality with the
complete checkpoint chain.

`json/vertical-slice-selection.schema.json` defines the governed vertical-slice archetype
crosswalk. It requires three in-scope root surfaces spanning standalone,
host/runtime, and database/embedded APIs; requires native-build,
native-runtime, and OCI-service environment strategies; conserves the complete
19-candidate design-seed ledger; and permanently keeps the selection
non-executable until exact release/profile/environment coordinates are supplied
by certified environment realization. Semantic validation additionally rejects identity collisions,
candidate-accounting overlap, nondeterministic ordering, unknown coverage,
disposition/reason mismatch, and missing architecture diversity.

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
