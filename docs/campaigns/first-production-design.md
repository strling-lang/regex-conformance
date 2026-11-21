# First production campaign design

The design compiler checks the complete candidate manifest against its pinned
digest, reconstructs each vector's identity and coverage, and joins the exact
family digest to its [source-backed basis](../../vectors/expectations/production-candidate-basis.v1.json).
Interaction comparisons require paired controls with the same obligation,
profile scope and operation, complementary outcomes, and opposite evidence
roles. Native diagnostic characterization retains a null verdict.

The initial design carries the PCRE2 10.47 ordinary 8-bit coordinate from the
earlier vertical slice as a proposed profile. It binds the release, environment
recipe, profile registry digest, candidate manifest, candidate basis, and
supplemental identity catalog. It also binds the existing adapter manifest and
its source commitment as a proposed mapping. The mapped adapter transmits exact
octets and reports octet spans. UTF-8 candidates retain their exact byte
sequences and select UTF mode in the stimulus. The design reports a candidate selection count,
an absent production denominator, and execution eligibility set to false.
The other declared scopes retain their basis records for future profile work.

```sh
python tools/campaigns/compile_first_production_design.py vector-candidates.json \
  --expected-digest "$CANDIDATE_MANIFEST_SHA256" --output first-production-design.json
```

Run again with `--check first-production-design.json` to verify the exact output.
The production inputs still required are reviewed oracle and expectation
bindings, a frozen production profile capability snapshot with evaluated
applicability, qualified runtime and operation mapping, and authorization of
the exact executable campaign. Publication requires separately verified
operator evidence and follows the existing [R2 handoff](cloudflare-r2-operator-handoff.md).
