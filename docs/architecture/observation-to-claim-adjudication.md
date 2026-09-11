# Observation-to-claim adjudication

The adjudication system determines which derived statement, if any, follows
from exact immutable inputs. It preserves this authority direction:

```text
semantic requirement
  + exact profile and applicability evaluation
  + admissible oracle / expectation basis
  + frozen expected outcome
  + immutable execution lineage and observations
  + discrepancy, waiver, and quarantine context
  -> comparison trace -> coordinate state -> derived claim
```

Applicability, expectations, observations, and claims remain different record
types and authorities. Comparison creates a new record; it never annotates or
rewrites either side. A claim is a reproducible projection, not a third source
of semantic truth.

## Closed state algebra

The contract defines thirteen coordinate states. `not-applicable`,
`applicability-unresolved`, and `applicability-invalid` preserve the exact
four-state applicability result. `not-tested` means an applicable coordinate
has no physical attempt. `unobserved` means attempts exist but no admitted,
target-attributable terminal observation exists. `inconclusive` means admitted
observations exist but the oracle boundary or expected-outcome state permits no
correctness judgment.

`satisfied` and `violated` describe agreement or disagreement inside the exact
epistemic scope of a frozen expectation. `permitted-divergence` is a
disagreement inside a positively authorized range. `conflicting-evidence` and
`conflicting-authority` preserve incompatible observations or authorities.
`quarantined` and `waived-for-gate` are visible overlay states; each retains a
separate underlying scientific state.

The result therefore exposes three dimensions rather than one overloaded
status:

- scientific state: applicability, evidence availability, comparison, or
  conflict;
- operational state: `normal` or `quarantined`;
- gate state: `unaffected`, `waived`, or `blocked-by-quarantine`.

In particular, not tested, unknown, not applicable, unsupported,
inconclusive, non-conformant, and waived are not synonyms.

## Deterministic decision rules

The adjudicator validates every exact reference and fails closed. A
not-applicable requirement produces no conformance judgment. Unresolved or
invalid applicability produces no semantic pass or failure. Missing or
inadmissible observation evidence is unobserved, not non-conformant.
Infrastructure, harness, adapter, protocol, and environment dispositions do
not become implementation behavior.

The adjudicator delegates evidence admission to the existing versioned
evidence-admissibility evaluator. O1–O3 can support their allowed
expectation-bearing judgments, O4 only relation judgments, O5 only
family-relative judgments, O6 exact implementation-documentation judgments,
O7 historical characterization, and O8 characterization-only findings.
Evidence quality remains distinct from role. Inadmissible records remain
available for investigation but are excluded from the claim input set.

Every path emits structured reason codes and an ordered trace. The result
answers applicability, expectation availability, observation availability,
permitted claim type, agreement, discrepancy, permitted divergence, waiver
effect, final state, and exact immutable input identity.

## Claim taxonomy and bindings

Claims use `finding` as the stable identity and a content-derived
`finding-revision` for the exact adjudication. The closed taxonomy distinguishes
normative conformance and non-conformance; implementation-documentation
conformance and non-conformance; formal-model satisfaction and violation;
authoritative-data agreement and disagreement; metamorphic-relation
satisfaction and violation; family-relative equivalence and divergence;
historical characterization; characterization-only findings; and
permitted-divergence findings.

Each claim revision binds the requirement and snapshot, profile and profile
revision, applicability result, adjudication contract, frozen basis and
expectation, evidence-admission result, logical execution, admitted
observations and physical attempts, discrepancy revisions, waiver effects,
quarantine effects, trace, and any predecessor claim revision. No generic
Boolean `pass` can substitute for the epistemic kind.

## Discrepancy and permitted divergence

A discrepancy is a first-class `finding` with append-only revisions. Its
claimants contain exact identity, revision, kind, scope, and supporting
evidence. Supported relations cover specification versus implementation
documentation, expectation versus observation, formal derivation versus
observation, authoritative data versus observation, documentation versus its
implementation, observation versus observation, historical versus later
behavior, and specification versus formal derivation.

Classification is independent of existence. The closed classifications are
implementation defect, specification defect, specification ambiguity,
documentation defect, vector/test defect, harness defect, environment defect,
data-version/source mismatch, permitted variation, profile/dialect difference,
historical regression/change, and unresolved conflict. Resolution appends a
revision that preserves the committed claimant set; it never deletes or edits
a claimant.

Permitted divergence requires admissible positive authority establishing
optional, permitted, implementation-defined, conditional, profile-specific,
or otherwise bounded behavior. Majority behavior, popularity, stability,
repetition, specification silence, absence of prohibition, and waivers cannot
establish permission. `unspecified`, `ambiguous`, and
`silent-not-established` remain non-permission states.

## Waiver and quarantine boundaries

Waivers are reviewed, scoped, dated `SPEC`, `VECTOR`, `HARNESS`, or
`ENVIRONMENT` certification actions. Their deterministic selector names exact
requirements, profiles, coordinate evaluations, and gates. Each revision
records owner, reviewer, justification, issue, creation date, mandatory review
or expiry, status, and supersession or revocation lineage.

A waiver may alter certification gating, campaign blocking, quarantine, or an
acceptance workflow. It cannot alter applicability, an expectation, an
observation, discrepancy existence, or scientific result. A waived normative
violation remains `violated`; its visible coordinate overlay is
`waived-for-gate`.

Quarantine has its own finding lineage, issue, review date, selector, and gate
policy. A safe coordinate normally remains executable and queryable. The
quarantine overlay cannot delete an attempt or observation and is never
evidence of conformance.

## Expected outcomes and execution lineage

Expected outcomes support exact values, one-of choices, optional alternatives,
permitted sets, numeric ranges, conditional branches, and relation-based
expectations. Conditions bind governed contracts and pre-evaluated condition
identities; they cannot execute arbitrary code. Optional or
implementation-defined behavior is not forced into an arbitrary single value.

Execution derivation is explicit:

```text
physical attempts
  -> attempt dispositions
  -> eligible observation set
  -> oracle-bound comparison
  -> adjudicated coordinate and claim
```

A physical retry is not a new logical coordinate. Later success preserves all
earlier attempts. Multiple incompatible admitted terminal results produce
`conflicting-evidence`; they are not collapsed into a flaky pass.

## History and circularity

Campaign requests bind exact requirement, applicability, basis, expectation,
lineage, and contract revisions. A newer expectation cannot silently replace
an older campaign input. Claims, discrepancy revisions, waiver revisions, and
quarantine revisions carry predecessor links, so every historical
adjudication remains reconstructable.

Dependency traversal includes predecessor evidence graphs, expectation
dependencies, applicability dependencies, and claim inputs. It rejects direct
and indirect observation-to-claim-to-expectation cycles, claim-to-profile-fact
applicability cycles, and a claim acting as its own authority.

## Verification and scientific boundary

Run:

```text
python tools/adjudication/compile_adjudication.py --check
python -m unittest discover -s tests/schema -p test_adjudication.py -v
```

The generated acceptance report covers all O1–O8 roles, every coordinate
state, all expected-outcome forms, all waiver types, permitted divergence,
unresolved and resolved discrepancy history, retry instability, and the
required adversarial cases. The fixtures are synthetic. The canonical
denominator remains 2,390 obligations and 3,378 requirements, comprising 1,406
unconditional and 1,972 conditional requirements. No real profile coordinate
or production coverage credit is created, and C4 remains `FAIL — 0/3378`.
