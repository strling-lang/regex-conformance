# Scientific foundation acceptance

This directory contains the compact, machine-checkable acceptance reference for
the repository's scientific identity, assertion-derivation, execution-truth,
and certification-truth foundations. It is an integration qualification, not a
full Regex Conformance data certification.

- `scientific-foundation.v1.json` binds the exact four foundation systems,
  their canonical artifacts and digests, their non-overlapping authority
  domains, the accepted scientific-input baseline, and historical schema
  routing.
- `scientific-foundation-acceptance.v1.json` records the deterministic
  integration checks, adversarial execution and integrity cases, semantic
  migration simulations, and the separate current C1-C7 result.

The acceptance reference binds source commit
`167ebd5c55065f33191fe5843be902db53f3187e`, the revision at which all four
foundation implementations were present together. The commit that adds this
acceptance reference is recorded by repository promotion and program evidence;
embedding that commit in its own bytes would create an impossible
self-reference.

Validate the immutable acceptance record or re-evaluate it against the bound
current inputs without running a target:

```sh
python tools/foundation/certify.py --history
python tools/foundation/certify.py --check
python schemas/tooling/python/run.py verify-foundation
```

The historical check proves the reference remains internally valid. The
current check additionally reconstructs the manifest and acceptance report
from the repository and must fail on authority overlap, evidence-strength
escalation, execution/certification disagreement, certification bypass,
unexplained identity drift, or accepted-input churn.

Later semantic work may create new versioned snapshots, requirements, and
derivation revisions. It must preserve this acceptance reference, use the
identity lineage and certification supersession contracts, and make the
transition explicit instead of rewriting these files.
