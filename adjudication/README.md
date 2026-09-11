# Adjudication

This module owns the versioned observation-to-claim contract and its current
authority index. It combines exact references to a semantic requirement,
profile revision, applicability evaluation, admissible expectation basis,
expected outcome, execution lineage, admitted observations, discrepancies,
waivers, and quarantine records. It does not own or mutate any of those
upstream facts.

Claims are regenerable `finding` / `finding-revision` products. Discrepancies
use the same durable finding lineage and retain every claimant revision.
Waivers use `certification-action` identities and can change only an exact
gate decision. Quarantine is an operational overlay that preserves the
scientific result and all attempt and observation evidence.

The current authority is [current-authority.v1.json](current-authority.v1.json).
Its fixtures are synthetic and create no production coordinate, observation,
coverage credit, or compatibility projection. See the
[architecture contract](../docs/architecture/observation-to-claim-adjudication.md).

Verify the tracked artifacts with:

```text
python tools/adjudication/compile_adjudication.py --check
```
