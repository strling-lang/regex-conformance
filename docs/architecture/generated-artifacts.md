# Generated, external, and derived artifacts

This document is the navigation map for source, generated, external, evidence,
and derived data in this repository. It supplements the
[repository layout](repository-layout.md); schemas and the producing code remain
machine authority for exact fields and validation.

## Authority flow

```text
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
| First vertical-slice definition, profiles, vectors, applicability, schemas | `tools/campaigns/compile_vertical_slice.py` | `campaigns/compiled/first-vertical-slice.v1.json` | repository validation and campaign tests |
| Small-scale qualification inputs | `tools/campaigns/compile_small_scale.py` | `campaigns/compiled/small-scale-qualification.v1.json`; `reports/small-scale/qualification-coverage.json` | compiler read-after-write checks and `test_small_scale_qualification.py` |
| 100K qualification definition plus frozen small-scale basis | `tools/campaigns/compile_100k_qualification.py` | `campaigns/compiled/100k-qualification.v1.json`; `reports/scale/100k-qualification-design.json` | compiler verification and `test_100k_qualification_design.py` |
| Closed deliberate-fault matrix | `tools/campaigns/compile_fault_classification.py` | `reports/small-scale/fault-classification.json` | schema validation and deterministic rebuild |
| Closed restart/resume matrix | `tools/campaigns/compile_restart_resume_qualification.py` | `reports/small-scale/restart-resume-qualification.json` | schema validation and deterministic rebuild |
| Seeded evidence-corruption matrix | `tools/campaigns/compile_evidence_verification_qualification.py` | `reports/small-scale/evidence-verification-qualification.json` | verifier/schema validation and focused campaign tests |
| Cache and disk-pressure qualification | `tools/control_plane/compile_cache_disk_pressure_qualification.py` | `reports/scale/cache-disk-pressure-qualification.json` | schema validation, deterministic rebuild, source bindings, and focused Control Plane tests |

Edit the source and run the listed producer; do not hand-maintain these outputs.
A compact report is a traceable projection, not raw evidence or independent
truth.

## External logical segments

The 100K compiler may materialize 402 immutable content-addressed logical-plan
segments when given `--segment-root`. That root must resolve outside the
repository. Git retains only the compact plan, ordered-ID commitment, segment
hashes, distribution proof, and design report. Segment materialization is not
target execution.

## Operational state, physical runs, and observations

- Control Plane state, provider handles, caches, builds, images, containers,
  execution scratch, protected spools, and diagnostics remain outside Git.
- Physical attempts are append-only operational/evidence records. A retry adds
  an attempt while retaining the same logical-execution identity.
- Raw observations and evidence objects are immutable and content-addressed.
  Infrastructure failures stay distinct from target timeout, crash, rejection,
  match, or no-match observations.
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
