# Generated, external, and derived artifacts

This document is the navigation map for source, generated, external, evidence,
and derived data in this repository. It supplements the
[repository layout](repository-layout.md); schemas and the producing code remain
machine authority for exact fields and validation.

## Authority flow

```text
primary sources → semantic-corpus snapshot → immutable ontology projection
                                      ↓
                         scientific identity catalog
                                      ↓
profile / vector / campaign / applicability / schema source
→ compiler or fixture materializer
→ compact tracked manifest, fixture, or report
→ external immutable logical segments
→ authorized physical attempts and observations
→ verifier assessment and admission
→ regenerable warehouse or compact public projection
```

An arrow records derivation, not authority elevation. Empirical output never
becomes a normative regex guarantee merely because it is deterministic,
verified, or published.

The scientific identity catalog is an additive binding over legacy semantic
keys. An enclosing generated-artifact digest may change while its internal
scientific entity IDs remain stable. Generators must resolve existing entities
from the catalog and fail on missing, reused, retired, or mutated bindings;
they never mint replacement IDs because ordering, generator version, or file
layout changed. See [Scientific identity and migration contract](scientific-identities.md).

The generated-assertion derivation catalog is a separate companion binding
over assertion-like fields in generated artifacts. It records whether each
assertion is measured, calculated, researched, externally evidenced, inferred,
constant by construction, or a manual decision. This metadata does not enter
the scientific entity identities. See
[Generated assertion derivation contract](generated-assertion-derivations.md).

## Tracked authored sources

- `registries/profiles/`, `vectors/definitions/`, `applicability/policies/`, and
  `campaigns/definitions/` contain reviewed operational inputs.
- `schemas/json/`, `schemas/formats/`, and `schemas/identity-profiles/` define
  machine shape, invariants, canonicalization, and identity projections.
- Compiler and verifier source under `campaigns/python/`, `matrix/python/`,
  `schemas/tooling/`, `verifier/python/`, and `warehouse/python/` implements
  those declared contracts. Implementation cannot silently redefine them.

## Tracked fixtures

Identity fixtures under `tests/fixtures/identity/` are deterministic repository
test material. Their manifest is materialized with:

```sh
python schemas/tooling/python/run.py materialize-fixtures
```

Verify the result with `verify-fixtures`, the schema tests, and a clean fixture
diff. Fixtures are not production observations or published evidence.

## Compact campaign products

| Source family | Producer | Tracked product | Verification |
| --- | --- | --- | --- |
| Frozen semantic products plus the permanent identity lock | `tools/identity/freeze_scientific_identities.py` | `registries/identity/scientific-identities.v1.json` | typed namespace validation, source reconciliation, immutable fingerprint history, lineage graph, key ownership, retirement and reuse checks, and catalog digest |
| Generated assertion inventory | `tools/provenance/compile_generated_assertion_derivations.py` | `registries/provenance/generated-assertion-derivations.v1.json` | exact source digests, assertion coverage, class-specific metadata, typed handles and content-derived revisions, evidence-strength gates, count/population reconciliation, and deterministic canonical bytes |
| Declared-cutoff semantic census, frozen profile bounds, and certified Evidence Pack v3 measurement | `tools/semantics/compile_semantic_baseline.py` | semantic-corpus snapshot, executable ontology projection, vector-requirement ledger, and `reports/scale/regex-semantic-denominator-forecast.json` | schema validation, candidate conservation, feature/relation integrity, declared facet-template structural closure, deterministic bounded applicability expansion, denominator arithmetic, content digests, fail-closed capacity gate, and derivation-strength validation |
| First vertical-slice definition, profiles, vectors, applicability, schemas | `tools/campaigns/compile_vertical_slice.py` | `campaigns/compiled/first-vertical-slice.v1.json` | repository validation and campaign tests |
| Small-scale qualification inputs | `tools/campaigns/compile_small_scale.py` | `campaigns/compiled/small-scale-qualification.v1.json`; `reports/small-scale/qualification-coverage.json` | compiler read-after-write checks and `test_small_scale_qualification.py` |
| 100K qualification definition plus frozen small-scale basis | `tools/campaigns/compile_100k_qualification.py` | `campaigns/compiled/100k-qualification.v1.json`; `reports/scale/100k-qualification-design.json` | compiler verification and `test_100k_qualification_design.py` |
| Closed deliberate-fault matrix | `tools/campaigns/compile_fault_classification.py` | `reports/small-scale/fault-classification.json` | schema validation and deterministic rebuild |
| Closed restart/resume matrix | `tools/campaigns/compile_restart_resume_qualification.py` | `reports/small-scale/restart-resume-qualification.json` | schema validation and deterministic rebuild |
| Seeded evidence-corruption matrix | `tools/campaigns/compile_evidence_verification_qualification.py` | `reports/small-scale/evidence-verification-qualification.json` | verifier/schema validation and focused campaign tests |
| Cache and disk-pressure qualification | `tools/control_plane/compile_cache_disk_pressure_qualification.py` | `reports/scale/cache-disk-pressure-qualification.json` | schema validation, deterministic rebuild, source bindings, and focused Control Plane tests |
| Sustained operating-envelope qualification | tracked Control Plane policy plus the producer and report compiler under `tools/control_plane/` | external immutable machine/workload bindings, append-only checkpoints, and a non-canonical report | exact source/input/machine binding, canonical-byte validation, predecessor-chain continuity, logical/physical attempt separation, governed resource-boundary and cumulative measurement reconciliation, explicit unavailable temperature telemetry, deterministic stability/overhead arithmetic, and exact report rebuild |
| 100K warehouse reconciliation | `tools/campaigns/reconcile_100k_warehouse.py` | `reports/scale/100k-warehouse-reconciliation.json` | read-only evidence/ledger reconciliation, immutable warehouse row commitments, schema validation, and focused campaign tests |
| Million-scale capacity and cost plan | `tools/campaigns/compile_million_scale_capacity_plan.py` | `reports/scale/million-scale-capacity-plan.json` | schema validation, deterministic rebuild, six-figure qualification source bindings, budget arithmetic, and focused campaign tests |
| Full known-universe planning index, measured six-figure raw corpus, and storage policy | `tools/campaigns/compile_full_known_universe_forecast.py` | `reports/scale/full-known-universe-corpus-forecast.json` | index/report schema validation, deterministic rebuild, latest-stable release-line profile bounds, lossless-compression measurements, source bindings, budget arithmetic, and focused campaign tests |
| Declared-cutoff universe exhaustion ledger and factorized-evidence capacity reforecast | external read-only research ledger plus `tools/campaigns/verify_known_universe_census.py` | `reports/scale/known-universe-census-forecast.json` | exact external ledger hashes and row counts when supplied, catalog and candidate disposition closure, schema validation, canonical report identity, source bindings, material-surface bounds, release/profile projection, Evidence Pack scaling, byte/request arithmetic, and fail-closed capacity tests |
| Factorized raw-evidence model and unchanged-denominator capacity gate | `tools/campaigns/compile_factorized_evidence_forecast.py` | `reports/scale/factorized-raw-evidence-forecast.json` | exact 807-member reconstruction, deterministic binary rebuild, identity/hash recomputation, corruption injection, bounded random lookup, schema validation, unchanged full-universe denominator arithmetic, and focused campaign tests |
| Production Evidence Pack v2 and enriched capacity gate | `tools/campaigns/compile_evidence_pack_v2.py` | `reports/scale/evidence-pack-v2-certification.json` | exact 807-member reconstruction, two identical encodings, legacy identity/hash recomputation, corruption injection, bounded lookup, attempt/observation independence, expanded diagnostic/performance contracts, governed-canary forecast, schema validation, and focused publisher tests |
| Compact Evidence Pack v3 and declared-cutoff capacity certification | `tools/campaigns/certify_compact_evidence.py` | `reports/scale/evidence-pack-v3-capacity-certification.json` | read-only million-corpus migration, exact semantic and exception-fact reconstruction, deterministic routine-process reconstruction plus ordered stdout commitment, deterministic coordinate identities, corruption injection, bounded lookup, exact separation of lossless and retention-contract savings, schema validation, and fail-closed 8 GB/10 GB arithmetic |
| Local million-scale publication preparation | `tools/campaigns/prepare_million_partition.py` and `tools/campaigns/finalize_million_local_artifacts.py` | external partition preparation records, staged content-addressed pack bytes, and an external local-readiness report | two identical encodings per partition, exact reconstruction, corruption detection, manifest-last staging, all-partition identity and interruption reconciliation, zero cloud requests, and capacity admission before later publication |
| Coverage Shard synchronization | certified evidence/projection producers plus `tools/downstream/compile_checkpoint_index.py` | `downstream/lab/coverage-shard-NNNN.v1.json`, `downstream/compatibility/coverage-shard-NNNN.v1.json`, `downstream/checkpoints/coverage-shard-NNNN.v1.json`, and `downstream/checkpoints/index.v1.json` | canonical bytes, frozen source bindings, exact profile/coordinate reconciliation, evidence/exclusion/limitation trace rules, predecessor-chain continuity, immutable-prefix enforcement, and deterministic index rebuild |

Edit the source and run the listed producer; do not hand-maintain these outputs.
A compact report is a traceable projection, not raw evidence or independent
truth.

An enclosing artifact digest may change when derivation or reporting metadata
changes. That does not mint new scientific identities for unchanged entities
inside it. Historical immutable artifacts retain their original bytes; the
companion derivation catalog records their assertion semantics prospectively.

## Downstream synchronization products

A low-level execution shard is never a publication signal. One coherent
Coverage Shard may contain many execution shards, but it emits downstream
artifacts only after exact reconciliation, Evidence Pack v3 publication and
read-back verification, downstream projection validation, capacity admission,
and certification all pass. The matching checkpoint commit is the sole Git
synchronization signal. Lab and Compatibility workflows consume the monotonic
index independently; this repository records no downstream workflow cursor and
does not wait for either consumer.

## External logical segments

The 100K compiler may materialize 402 immutable content-addressed logical-plan
segments when given `--segment-root`. That root must resolve outside the
repository. Git retains only the compact plan, ordered-ID commitment, segment
hashes, distribution proof, and design report. Segment materialization is not
target execution.

## Operational state, physical runs, and observations

- Control Plane state, provider handles, caches, builds, images, containers,
  execution scratch, protected spools, sustained operating-envelope
  checkpoints/reports, and diagnostics remain outside Git.
- Physical attempts are append-only operational/evidence records. A retry adds
  an attempt while retaining the same logical-execution identity.
- Raw observations and evidence objects are immutable and content-addressed.
  Infrastructure failures stay distinct from target timeout, crash, rejection,
  match, or no-match observations.
- Evidence Pack v3 is the authoritative physical representation for new raw
  evidence. Shared immutable values may be stored once, but every independently
  executed observation and every physical attempt remains independently
  identifiable. Existing v2 packs remain immutable and authoritative under
  their original manifest. See [Compact Evidence Pack v3](../campaigns/evidence-pack-v3.md).
- `run_vertical_slice.py`, environment/adapter certification, fault exercises,
  restart exercises, and `run_100k_qualification.py` require explicit execution
  authorization and external roots. Their presence is not authorization.

## Verification and admission

`verifier/` creates separate assessments for structural validity, provenance,
completeness, consistency, integrity, reconciliation, replication, and
discrepancy. A result may be admitted, quarantined, invalidated, superseded, or
replaced without altering the original bytes. Analytical admission does not
imply trusted execution or certification eligibility.

## Warehouse and public projections

`warehouse/` builds regenerable analytical data only from a qualifying immutable
manifest and a fresh integrity assessment. Warehouse databases and large
partitions remain outside Git and never outrank evidence. `reports/` may retain
compact schema-validated coverage, reproducibility, differential, execution,
or certification projections when repository architecture assigns them there.
The six-figure scale warehouse is a separate external derived artifact; its tracked
report binds the complete source row set without adding logical credit or
changing the certified campaign root.

## Validation ladder

Use only the level the change requires:

```text
schema or focused unit test
→ deterministic compiler/design test
→ repository source baseline
→ authorized environment or adapter qualification
→ authorized vertical execution
→ authorized scale or certification campaign
```

Never select Docker, a trusted runner, vertical execution, or 100K execution to
validate an ordinary source, documentation, schema, or compact-plan change.
