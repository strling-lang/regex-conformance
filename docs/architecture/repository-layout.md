# Repository Layout and Architecture Traceability

This scaffold realizes the certified pre-implementation architecture without
selecting an implementation language, environment provider, storage vendor, or
regex engine as a design center. The root README and module READMEs define the
current lightweight Git boundary.

## Module map

| Root | Repository-owned responsibility | Certified lineage | Must not contain |
| --- | --- | --- | --- |
| `schemas/` | Versioned schema families, identity projections, canonicalization declarations, and reference fixtures | Canonical Identity & Schema System; all artifact models | Runtime artifacts, raw observations, or mutable `latest` certification inputs |
| `registries/` | Discovery definitions, Universe Registry records, systems/components/releases, profile families, concrete profiles, and namespace metadata | Universe Discovery; Universe Registry; Release & Profile Modeling | Undispositioned scope hidden from snapshots or flattened engine-only profiles |
| `ontology/` | Immutable Knowledge snapshot references, qualified crosswalks, executable projections, and expectation references | Feature/Ontology Integration | A competing semantic taxonomy or copied external IDs presented as local ownership |
| `vectors/` | Probe families, executable vectors, operations, observation requests, and vector provenance | Conformance Vector Model | Universal truth inferred from engine-specific behavior |
| `applicability/` | Pure applicability rules, capability references, relevant-dimension expansion, and exclusion explanations | Applicability & Matrix Semantics | Opaque filters or unaccounted exclusions |
| `protocol/` | Language-neutral adapter request/response, capability, encoding, native-index, error, diagnostic, and evolution contracts | Adapter Protocol; Result & Evidence Model | Conformance judgments embedded in adapter transport |
| `adapters/` | Thin runtime adapters and adapter conformance fixtures | Adapter Protocol; Distributed Runner & Security | Environment acquisition, scheduling policy, or trusted-evidence decisions |
| `environments/` | Reproducible recipes, acquisition policies, provider contracts, and verification definitions | Environment & Provenance; Control Plane Architecture | Realized environments, downloaded toolchains, images, or mutable cache state |
| `matrix/` | Deterministic compilation of exact applicable logical execution coordinates and exclusion ledgers | Applicability & Matrix Semantics; Scheduler Design | Physical attempts or scheduler-local assignments |
| `control-plane/` | Provider-neutral machine, resource, environment, cache, state, event, CLI/API, and containment services | Control Plane Architecture | Canonical evidence or provider-specific policy disguised as a common guarantee |
| `scheduler/` | Deterministic sharding, capability-aware placement, checkpoints, retries, and resumability logic | Scheduler, Sharding & Resumability | Overwriting attempts or treating assignments as scientific evidence |
| `campaigns/` | Campaign definitions, frozen manifest inputs, and compact campaign metadata | Scheduler Design; Validation & Certification | Large result shards, raw diagnostics, or local checkpoints |
| `verifier/` | Structural, provenance, result, evidence-integrity, reconciliation, and discrepancy verification source | Result & Evidence Model; Validation & Certification | Mutation of published observations or normative claim ownership |
| `warehouse/` | Regenerable warehouse schemas, transforms, partition/compaction declarations, and query source | Storage & Warehouse Architecture | Authoritative raw evidence or committed large analytical datasets |
| `reports/` | Compact generated coverage, reproducibility, differential, and certification report definitions/outputs | Storage & Warehouse; Validation & Certification | Hand-maintained claims that diverge from canonical inputs |
| `certification/` | Certification definitions, input-set rules, pass/fail gates, revocation, and supersession metadata | Scope & Completeness; Validation & Certification | Declared waivers or mutable certification history |
| `tests/` | Cross-module fixtures and structural, negative, boundary, fault, security, and reproducibility tests | All certified artifact gates; Repository Bootstrap | Production evidence presented as a test fixture |
| `docs/` | Repository architecture, operations, contribution, reproduction, and publication guidance | Program Constitution; Repository Bootstrap | Duplicate program status, normative research truth, or raw evidence |

The distributed-runner security architecture is represented by
`.github/`, `control-plane/`, adapter/worker capability contracts, and
security tests. Workflow implementation and repository protections are a
separate bootstrap contract; the scaffold does not enroll trusted runners or add
credentials.

## Dependency direction

1. `schemas/` constrains every versioned machine-operational artifact.
2. `registries/`, `ontology/`, `vectors/`, `applicability/`,
   `environments/`, and `protocol/` provide frozen definitions.
3. `matrix/` compiles logical scope; `control-plane/`, `adapters/`, and
   `scheduler/` plan and execute physical work without changing that scope.
4. `verifier/` qualifies outputs and preserves target outcomes separately from
   infrastructure failures.
5. Immutable external evidence feeds regenerable `warehouse/` projections and
   compact `reports/`; warehouse rows never replace evidence authority.
6. `certification/` evaluates exact input sets and immutable evidence against
   C1-C7 as a conjunction.

Dependencies may point to stable contracts earlier in this sequence. Provider,
adapter, scheduler, warehouse, report, and CLI implementations must not reach
backward to redefine identity, applicability, evidence, or certification
semantics.

## Explicit external boundaries

The following are intentionally absent from the scaffold:

- raw physical-run records, observations, result shards, large diagnostics, and
  certified evidence objects, which belong in immutable evidence storage;
- OCI images, binaries, VM disks, emulators, SDKs, and downloaded toolchains,
  which belong in approved artifact stores or machine caches;
- realized environments and environment cache entries, which are operational or
  evidence provenance rather than repository source;
- Parquet partitions and large warehouse datasets, which live in analytical
  storage and remain regenerable;
- local machine inventory, transfers, assignments, checkpoints, processes,
  spools, telemetry, and ETA state, which are non-canonical Control Plane state;
- Notion task/decision/risk records; and
- canonical normative concepts, researched claims, and primary-source evidence
  owned by the Regex Knowledge Program.

## Traceability checklist

- [x] Every root named by the Repository Bootstrap contract is present.
- [x] P01-P15 and P12A machine-operational responsibilities map to an explicit
  repository root or documented external authority.
- [x] Registry profiles remain component graphs with behaviorally relevant
  facets.
- [x] Ontology projections remain immutable consumers of qualified Knowledge
  references.
- [x] Probes, expectations, logical executions, physical attempts, observations,
  infrastructure failures, and findings remain distinct.
- [x] Environment recipes are separated from realized instances.
- [x] Raw evidence and large analytical/runtime artifacts have no Git root.
- [x] Local Control Plane state has no canonical repository root.
- [x] Trusted execution has no public-fork route or credential surface in this
  scaffold.
- [x] No implementation language, provider, vendor, platform, or regex engine is
  selected by directory structure.
