# Oracle authority

This directory contains the prospective, versioned oracle contract and its
digest-bound current-authority index. Oracle records explain why a semantic
requirement may have a scoped expected result or relation; they are not
observations, adjudications, waivers, or production vectors.

Regenerate or verify the artifacts with
`tools/oracle/compile_oracle_foundation.py`. The `evidence/` authority index and
the evidence-admissibility contract are materialized with
`tools/oracle/compile_evidence_admissibility.py`; they determine which exact
evidence roles may support which epistemic uses without changing the oracle
taxonomy. See
[`../docs/architecture/oracle-hierarchy.md`](../docs/architecture/oracle-hierarchy.md)
for the epistemic classes, conclusion boundaries, dependency traversal, and
circularity guards, and
[`../docs/architecture/evidence-admissibility.md`](../docs/architecture/evidence-admissibility.md)
for normative-versus-characterization evidence boundaries.
