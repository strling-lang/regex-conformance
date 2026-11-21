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
Use `--transport-preflight` with a different output path to compile the same
verified selection into offline request previews and a readiness row for every
requirement. The row records candidate presence, required oracle capability,
binding and applicability status, execution eligibility, observation state, and
credit from the preflight. The adapter-request contract requires one subject
slot even for compile requests. The preflight places an empty octet buffer in
that slot on the compile path, which returns before reading the slot. The
original stimulus and revision identity retain zero subjects. The preflight
rejects inputs without an exact transport mapping and issues no observations
or certification credit.

The preview includes sums of the request caps for one attempt per selected
candidate. Those bounds exclude retries, isolation and runner overhead, and
evidence storage. The production execution and capacity estimates still
require realized profiles, evaluated applicability, and measured evidence.

The production inputs still required are reviewed oracle and expectation
bindings, a frozen production profile capability snapshot with evaluated
applicability, qualified runtime and operation mapping, and authorization of
the exact executable campaign. Publication requires separately verified
operator evidence and follows the existing [R2 handoff](cloudflare-r2-operator-handoff.md).

The [expectation-basis validator](../../schemas/tooling/python/regex_conformance_schema/evidence_admissibility.py)
currently resolves oracle references in its validation fixture. Production
admission needs a reviewed resolver for a pinned production oracle collection.
Each binding must establish the exact vector, requirement, profile, operation,
and campaign scope. The oracle collection's conflict check compares conventional
results at requirement/profile/operation scope. A production representation
must also distinguish different stimuli within that scope, for example by
freezing an independently sourced rule and its vector-specific projection.
Candidate output values carry no oracle authority.
