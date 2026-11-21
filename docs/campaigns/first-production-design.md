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

The production inputs still required are admission of the exact oracle packet,
a frozen production profile capability snapshot with evaluated applicability,
qualified runtime and operation mapping, and authorization of the exact
executable campaign. Publication requires separately verified
operator evidence and follows the existing [R2 handoff](cloudflare-r2-operator-handoff.md).

The [PCRE2 oracle review compiler](../../tools/campaigns/compile_pcre2_oracles.py)
resolves the pinned candidate manifest and independently checks the request
preflight digest. It verifies the archived PCRE2 10.47 manual against the
document SHA-256 and binds six documentation-scoped expectations and ten
same-profile relational premises. The exact vector, requirement, operation,
profile graph, release, and candidate campaign scope are pinned. Conflicts
are detected per stimulus, with every claimant retained and no winner chosen.
An O4 binding contains its controls and permitted terminal values. A satisfied
relation can establish only relation satisfaction.

With no manual, the report retains all 16 rows as oracle inputs unavailable.
When the archived source tar and detached signature are supplied, the compiler
verifies both recipe byte commitments and compares the tar's manual to the
pinned Git document. This comparison is a byte check. Environment realization
checks the recipe digests before extraction. Production admission also needs a
detached-signature verification receipt and fresh runtime qualification.

The [capability review](../../schemas/tooling/python/regex_conformance_schema/production_admission.py)
replays the canonical applicability evaluator using exact historical adapter
operation declarations. It preserves unresolved feature, modifier, and
manifestation inputs under the open-world contract. The result gives every
blocked coordinate a trace and keeps the runnable set empty until the current
realization and exact authorization are established. The original
expectation-basis fixture verifier retains its historical behavior. New
production observation-to-claim admission remains a separate reviewed
integration.
