# Normative and characterization evidence admissibility

The evidence-admissibility contract answers one narrow question:

> What epistemic proposition may this exact evidence support, for this exact
> scope, and what is it forbidden from establishing?

It extends the [oracle hierarchy](oracle-hierarchy.md) without changing its
eight classes. Knowledge sources remain authoritative for their own exact
propositions. Evidence records preserve immutable inputs and allowed uses.
Oracle records describe the scoped epistemic function. Observations remain
empirical. Applicability, comparison, discrepancy, and adjudication remain
separate later operations.

## Role is not quality

Evidence has one epistemic role corresponding to O1 through O8:

| Evidence role | Oracle | May establish |
| --- | --- | --- |
| Normative source | O1 | an external normative expectation selected by exact source language |
| Formal derivation | O2 | a result inside an explicit, independently checked formal model |
| Authoritative data-derived | O3 | a data-version-scoped result when pinned data, semantic rule, and algorithm all close |
| Relational/metamorphic | O4 | necessary-relation satisfaction or violation, not full correctness from satisfaction |
| Family-relative reference | O5 | equivalence, divergence, regression, or change inside one declared implementation family |
| Implementation documentation | O6 | what an exact implementation revision documents about itself |
| Historical empirical | O7 | what an exact historical profile did and whether reproduction agreed |
| Characterization-only | O8 | observation, differential description, or a research gap |

Integrity, preservation, and reproducibility are orthogonal quality axes. A
reproduced characterization remains characterization. A normative source with
incomplete preservation remains normative in role but is inadmissible as a
certified expectation input until its provenance closes. The contract forbids
numeric confidence scores because reliability cannot elevate epistemic role.

## Admissibility decision

An admissibility request names exact evidence identities and digests, one
epistemic use, requested conclusion, oracle class, and requested semantic
scope. The evaluator fails closed unless all of these conditions hold:

1. the role is admitted for the requested use;
2. the requested conclusion is permitted by both the use and role;
3. the evidence binds the matching O1–O8 oracle and fixed oracle contract;
4. the evidence scope covers the request;
5. expectation-bearing evidence is verified and immutably preserved;
6. source-based evidence pins an exact revision, digest, and locator;
7. source language permits the requested conclusion;
8. the complete dependency graph is acyclic and contains no prohibited
   expectation basis; and
9. any independence requirement is met by distinct upstream semantic
   authority domains, not merely different wrappers.

The same material may therefore be admissible for one use and inadmissible for
another. Python implementation documentation may establish a Python
self-documentation expectation and support research, but it cannot establish
an external normative requirement.

When several oracle classes are available, each evidence/use request is
evaluated independently. There is no class rank or automatic winner. Compatible
results may be bound by an explicit later projection; conflicting legitimate
expectations remain separate under the oracle foundation's conflict state for
later adjudication.

## Normative source language

Source propositions record one of: `required`, `prohibited`, `permitted`,
`optional`, `conditional`, `implementation-defined`, `unspecified`,
`informative-non-normative`, `ambiguous`, `silent-not-established`, or
`not-applicable`.

Only the first five can establish a corresponding concrete expectation. Their
meanings remain distinct: permission is not obligation, optional support is
not required support, and a conditional proposition applies only when its
condition holds. Implementation-defined and unspecified language preserve
under-specification. Ambiguity remains ambiguity. Informative prose and silence
cannot establish mandatory or rejected behavior.

## Provenance and independence

Every evidence record binds exact source authority, source revision, digest,
locator, semantic scope, requirement and assertion revisions, derivation, and
upstream dependencies. The graph uses the oracle foundation's dependency kinds
and authority domains. Validation traverses every expected-basis path, rejects
cycles, and propagates observation, historical observation, consensus, target
output, generator evaluator, and absence-of-authority taint through intervening
claims or projections.

Two CLIs, libraries, mirrors, transformed datasets, or generators are not
independent when they share the same upstream semantic authority domain. For
data-derived evidence, an authoritative dataset is necessary but insufficient:
an independently established semantic rule and deterministic algorithm are
also mandatory.

## Immutable expectation basis

The prospective expectation-basis schema freezes exact evidence and oracle
IDs/digests, the requirement, scope, use, conclusion, and timestamp. Mutable
aliases such as `latest`, `current`, `main`, or `HEAD` are invalid certified
inputs. Later Knowledge revisions may support new campaigns, but cannot rewrite
the basis against which an historical campaign ran.

Run the deterministic compiler with:

```text
python tools/oracle/compile_evidence_admissibility.py --check
```

The current report proves evidence-role and admissibility closure only. It does
not evaluate profile applicability, adjudicate discrepancies, issue waivers or
public claims, author vectors, or change the 2,390-obligation / 3,378-requirement
semantic denominator.
