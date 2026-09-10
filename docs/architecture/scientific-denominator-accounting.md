# Scientific denominator accounting

The current semantic-side denominator contains 2,390 scientific obligations
and 3,378 minimum attributable requirements. This document defines how those
populations are counted and audited. It does not define an exact profile count
or a final logical-execution denominator.

The machine authority is the accounting contract at
`ontology/denominator/regex-semantic-denominator-accounting-2026-09-10.v1.json`.
The independent report at
`reports/semantics/regex-semantic-denominator-audit-2026-09-10.v1.json` binds
the exact semantic, obligation, requirement, migration, certification, and
profile-handoff inputs. The current audit pointer is
`ontology/authority/current-semantic-denominator-audit.v1.json`.

## Orthogonal accounting axes

The requirements are partitioned independently. Each base axis sums to 3,378;
values from different axes must not be added together.

| Axis | Mutually exclusive members | Counts |
| --- | --- | --- |
| Semantic applicability | required; conditional | 1,406; 1,972 |
| Scientific purpose | conformance-capable; relational/metamorphic candidate; characterization-only | 3,071; 228; 79 |
| Execution disposition | executable conformance; executable relational; executable characterization; non-executable informative; prohibited; unresolved | 3,071; 228; 79; 0; 0; 0 |
| Evidence role | positive; negative; boundary; characterization | 1,785; 1,394; 120; 79 |

`Executable` is a rollup of the three executable disposition members and is
3,378. `Informative` is an overlapping rollup of the 228 relational and 79
characterization questions, or 307. These rollups answer different questions
and are not a partition to cross-sum.

Prohibited means an explicit safety, semantic, authority, or applicability
rule forbids execution or credit. It is not a synonym for a suppressed
feature/facet decision or for not-applicable. Unresolved means required
upstream authority is absent. Both populations are zero in the current
canonical requirement snapshot.

## Scenarios without planning multipliers

The lower requirement count is the unconditional semantic minimum: 1,406.
The conservative semantic ceiling is 3,378, calculated as 1,406 required plus
1,972 conditional requirements. The ceiling provisions for every current
condition; it does not assert that every condition applies to one future
profile.

No accepted empirical profile-applicability expectation model exists at this
cutoff. Expected is therefore represented symbolically:

```text
1,406 + sum(P(profile facts satisfy conditional predicate r))
```

Its exact semantic-side bounds are 1,406 through 3,378; it has no authoritative
numeric point estimate. The obligation scenarios follow the same rule with a
1,058 lower bound, 1,332 conditional members, and a 2,390 conservative ceiling.

The historical 251-by-48 obligation grid and profile/archetype planning factors
remain immutable evidence about the former plan. They do not feed current
denominator authority. The complete feature-by-facet decision grid is a
structural audit: 2,470 of its 4,035 decisions suppress obligation creation,
and the accepted decisions produce 85 distinct feature shapes. Operation
memberships are explicit identity sets, not an operation multiplier.

## Cardinality and independent recomputation

Every obligation starts with one minimum attributable evidence role. The
accepted archetype polarity rules give 988 obligations a second independent
role, so `2,390 + 988 = 3,378`. The audit reconstructs those roles directly
from the rule contract, rather than trusting snapshot counts.

The audit path does not call the primary obligation materializer. It reads the
committed snapshots and independently:

- reconstructs every prospective obligation identity basis from dry-run
  decisions and detects both missing and extra objects;
- partitions stable requirement IDs on each accounting axis;
- validates all closed capability predicates and rejects empty, contradictory,
  tautological, mutable-name, or dangling references;
- reconstructs evidence-role cardinality from obligation archetypes;
- proves complete predecessor and successor migration closure;
- samples inclusions and suppressions across every facet and operation, each
  applicability and evidence role, feature-size bands, successor features, and
  typed interactions;
- rejects current profile, platform, repetition, and planning multipliers.

Run or inspect it with:

```sh
python tools/semantics/audit_scientific_denominator.py --check
python tools/semantics/audit_scientific_denominator.py --explain <requirement-id-or-key>
```

Every count and conclusion in the report binds the calculation derivation
revision. Generator closure is structural evidence, not empirical conformance
evidence.

## Profile expansion handoff

The profile handoff at
`ontology/projections/regex-semantic-profile-expansion-handoff-2026-09-10.v1.json`
normalizes the 354 distinct predicates and binds every requirement to its
feature, obligation, operation scope, and predicate. Future profile authority
must supply canonical feature, operation, manifestation, variant, and modifier
capability facts. An unknown fact stays unresolved; it is not silently treated
as unsupported or not-applicable.

Only after empirical profile freeze can the repository evaluate:

```text
exact profile capability facts
  × conditional requirement predicates
  → profile-specific applicability coordinates
```

The exact profile count and final logical-execution denominator are therefore
explicit null/deferred values. No historical multiplier substitutes for them.
The 3,378 count is the canonical semantic requirement denominator, not the
final profile-expanded execution count.

## Certification placement

Expensive regeneration, independent recomputation, migration closure, and
certification evaluation run once on the controlled local machine. The local
certification manifest binds their exact source tree, artifacts, catalogs,
test-result root, and PASS result using the existing JCS/SHA-256 conventions.

Hosted Linux performs bounded integrity verification. It checks the exact
source/envelope relationship, every committed artifact, schema, catalog and
contract binding, cheap cross-sums, C4 at `0/3378`, migration totals, and
verifier canaries. It retains veto authority without replaying the expensive
materializer or full audit. See [Local authoritative certification and hosted
integrity verification](local-authoritative-certification.md).
