# Oracle hierarchy and circularity guards

An oracle is a versioned explanation of why a particular semantic requirement
may have an expected result or a narrower comparison condition. It is not an
observation, verdict, waiver, or confidence score. The canonical contract is
`oracle/contracts/regex-conformance-oracles-2026-09-10.v1.json`; the current
authority index binds its exact identity and digest.

The contract preserves this authority flow:

```text
source proposition
→ researched claim
→ normative expectation
→ vector or probe
→ logical execution
→ physical attempt
→ observation
→ comparison, discrepancy, or finding
```

An arrow is a dependency, not permission to collapse adjacent object types.
In particular, an observation never acquires expectation authority merely by
being preserved, repeated, popular, or projected through another artifact.

## Epistemic classes

The O-number is a stable class label, not a rank. There is no rule equivalent
to `O1 > O2 > … > O8`.

| Class | Epistemic function | Permitted conclusion boundary |
| --- | --- | --- |
| O1 — normative source | A pinned normative proposition directly determines the scoped behavior. | Normative expectation and conformance/non-conformance only for the exact edition, locator, claim revision, and satisfied scope. |
| O2 — formal derivation | An independently checked construction determines a result under recorded assumptions and domain restrictions. | Formal expectation and model satisfaction/violation; it is not automatically conformance to an external specification. |
| O3 — data-derived | A pinned authoritative dataset plus deterministic algorithm determines a data-scoped result. | Data-scoped expectation and agreement/disagreement for the exact data and algorithm versions. |
| O4 — metamorphic/relational | A necessary relation connects two or more executions of the same applicable profile. | Relation violation may establish a discrepancy. Relation satisfaction proves only that relation, not full correctness. |
| O5 — designated intra-family reference | A governed reference profile supports a family-relative comparison. | Family equivalence, divergence, regression, or change only. It is not universal correctness authority. |
| O6 — implementation documentation | Pinned implementation documentation states what that exact implementation claims. | Agreement or contradiction with the implementation's own documentation; external normative conformance remains separate. |
| O7 — historical characterization | A preserved historical observation is the object being studied. | Historical reproduction, divergence, or fact only; never normative truth. |
| O8 — characterization only | No admissible correctness oracle exists. | Observation, descriptive differential, and research-gap recording only; no expected result or conformance verdict. |

Each class has an exact provenance field set, admissible semantic-requirement
capabilities, scope kind, and permitted judgment vocabulary. A record requesting
a judgment outside its class fails validation.

## Resolution and multiple authorities

Oracle resolution is one of `oracle-established`, `oracle-inapplicable`,
`expectation-ambiguous`, `expectation-under-specified`,
`conflicting-authoritative-expectations`, `oracle-inputs-unavailable`, or
`characterization-only`. Missing or ambiguous authority is not a failed target
execution.

Multiple applicable oracles are evaluated independently for their declared
purposes. Compatible claims may be bound together only by an immutable
projection naming every exact oracle revision. Incompatible conventional
expectations require a conflict record containing all claims and no selected
winner. Selection by class number is forbidden. A later adjudication contract
may interpret that conflict; this contract only preserves it.

## Dependency and independence model

Every oracle record contains a directed provenance graph. Nodes identify their
input kind, semantic role, exact version and digest, upstream dependencies,
subject profiles, and stable semantic `authority_domain_id`. Wrappers, command
line tools, modules, and processes backed by the same implementation must share
one authority domain, so presenting the same library through two tools does not
create false independence.

Validation performs a full graph walk. It rejects dangling roots, dangling
edges, duplicate node identities, cycles, and prohibited transitive inputs.
This catches a chain such as observation → research claim → expectation
projection even when the oracle never names the observation directly.

The dependency role is also material. A generator may appear as
`stimulus-only`, and an observation may appear as a preserved
`promotion-source`, without becoming an `expected-basis`. O4, O5, O7, and O8
may use empirical or reference inputs only within their restricted conclusion
types.

## Constitutional guards

The contract makes eight guards mandatory:

1. An observation cannot be an expectation basis. A deliberate promotion is a
   separate reviewed event and must identify a newly established independent
   basis.
2. Consensus and majority vote are descriptive statistics, never oracle
   classes or correctness sources.
3. A generator or evaluator in the generator's semantic authority domain
   cannot oracle its own stimuli.
4. Silence does not imply rejection, unsupported behavior, or absence of an
   extension.
5. Conflicting legitimate authorities survive as separate immutable claims.
6. Prohibited influence propagates transitively through claims and projections.
7. A designated reference profile remains intra-family and cannot become
   universal truth.
8. A campaign freezes exact contract, oracle, and expectation-binding IDs and
   digests; later revisions cannot mutate historical meaning.

## Vector integration and history

`oracle-vector-binding.v1` is the prospective vector integration point. It
binds a content-derived vector revision and semantic requirement to exact
oracle record IDs/digests, the exact oracle contract, a resolution state, and
the campaign revision that froze them. Mutable `latest` aliases are forbidden.
The binding is separate from vector stimulus identity, so a future campaign can
adopt a new oracle revision without rewriting the historical vector or its old
campaign interpretation.

Existing probe and qualification vector schemas are unchanged. They remain
explicitly non-normative and gain no oracle authority from this contract.

## Validation and regeneration

Run:

```text
python tools/oracle/compile_oracle_foundation.py --check
python -m unittest tests.schema.test_oracle_foundation
```

The reference fixtures contain one legitimate O1–O8 record, an immutable
campaign-binding canary, and prohibited consensus, target-self-reference,
generator-self-reference, ungrounded promotion, transitive observation,
universalized reference, silence inference, historical-normative, missing
provenance, and graph-cycle cases. They are synthetic validation material, not
production expectations or observations.

Applicability, discrepancy adjudication, claims, waivers, production vectors,
and profile expansion remain separate later contracts. The authoritative
semantic denominator remains 2,390 obligations and 3,378 requirements.
