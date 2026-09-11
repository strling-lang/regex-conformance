# Conditional requirement applicability

The conditional applicability system decides whether an already-existing
semantic requirement engages one exact profile revision. It does not create or
remove semantic requirements. It also does not establish expected results,
feature support, observations, exclusions, or conformance judgments.

The current semantic denominator remains 2,390 obligations and 3,378
requirements: 1,406 requirements are unconditional in the frozen semantic
model and 1,972 retain profile-dependent conditions. Profile expansion is a
later projection over that denominator, not a rewrite of it.

“Unconditional” means no profile-contingent variant or manifestation gate is
attached to the semantic requirement. The predecessor handoff still records its
feature and operation scope so a later coordinate builder cannot assign the
question outside the candidate coordinate's declared surface. Eighty required
bindings also name an intrinsic modifier already attached to their canonical
feature; the audit verifies every one of those references against the feature
record. No required binding contains an unexplained capability dependency.

## Authority and inputs

The versioned contract is
`applicability/contracts/regex-conformance-conditional-applicability-2026-09-10.v1.json`.
It consumes the current requirement snapshot and the exact predecessor
requirement-to-profile handoff. A future authoritative evaluation also binds:

- one immutable requirement and predicate revision;
- one exact profile identity and profile revision;
- one content-derived frozen capability-fact snapshot;
- every capability fact read by the evaluation; and
- the exact evaluator contract revision.

The capability-fact interface is deliberately prospective. Synthetic fixtures
prove its shape, but this repository has not guessed real profile capability
facts or an exact profile count. Future profile research can populate the same
interface without changing the predicate language.

Applicability and oracle authority remain separate:

```text
semantic requirement + frozen profile facts -> applicability
independent expectation basis               -> oracle
controlled target execution                 -> observation
```

An `applicable` result never supplies an expected result. A
`not-applicable` result never means empirically unsupported.

## Total state algebra

Predicate evaluation uses internal values `true`, `false`, `unknown`, and
`invalid`. Canonical outcomes are:

| Truth | Result | Meaning |
| --- | --- | --- |
| `true` | `applicable` | Admissible frozen facts establish the predicate. |
| `false` | `not-applicable` | Admissible frozen facts affirmatively refute the predicate. |
| `unknown` | `unresolved` | Required facts are missing, conflicting, inadmissible, unresolved, or outside the frozen model. |
| `invalid` | `invalid` | The input, identity, dependency graph, or predicate contract is malformed. |

`invalid` is diagnostic and fail-closed; it cannot enter an authoritative
coordinate set. Missing information is never converted to false.

AND, OR, and NOT use strong Kleene uncertainty semantics. A known false child
decides an AND even when another child is unknown; a known true child decides
an OR. Negating unknown remains unknown.

## Predicate language

Predicates are pure typed ASTs. They allow bounded `all`, `any`, `not`, and
boolean constants plus allowlisted field operators. The current five fields
are stable-ID sets for features, operations, manifestations, semantic variants,
and modifiers. Their current predicates use `contains` and `intersects`; the
contract reserves typed complements and scalar comparisons for later
versioned field-registry additions.

No predicate may execute code, evaluate a regex, import a module, read the
host, filesystem, environment, or network, or depend on evaluator-specific
side effects. All fields, types, operators, value sources, comparators, depth,
node count, and set size are allowlisted.

Commutative `all`/`any` children and `in` members are normalized by JCS byte
order, exactly matching the frozen predecessor identity contract. Other equivalent
rewrites require a versioned predicate-identity migration. Existing predicate
IDs therefore recompute without churn.

## Open-world facts

Capability facts are open-world by default:

```text
not known present != known absent
```

A membership test is false only when an admissible `member-absent` fact or an
explicit, versioned, exact-profile field-closure rule proves absence. There is
no global closed-world assumption. Conflicting present and absent facts remain
unresolved.

Facts record their authority class, authority state, exact source identity,
revision, digest, locator, and dependencies. Admitted authority can come from
an exact registry profile, Knowledge projection, certified adapter or
environment capability, frozen campaign policy, or reviewed empirical
promotion. A raw target observation, mutable host discovery, untrusted
self-report, or contributor assertion cannot directly decide applicability.

## Dependency and exclusion guards

The validator traverses capability-fact dependencies and rejects cycles,
dangling fact references, target-observation dependencies, applicability-result
dependencies, and semantic-requirement self-justification. An execution result
from a proposed coordinate therefore cannot prove that the coordinate should
have existed.

Ad hoc skip or exclusion lists are not applicability inputs. Operational
quarantine, safety policy, infrastructure inability, and other execution
dispositions remain separate records. A `not-applicable` result requires an
exact predicate, exact frozen facts, and this versioned evaluator.

## Explainability and history

Each evaluation emits a structured normalized-AST trace. Trace nodes record the
operator, truth value, reason code, child traces, and exact fact IDs read.
Unresolved leaves identify the field, target, and minimum unresolved reason.
Human explanations are projections of this structure rather than authority in
free-form prose.

Later capability research creates a new snapshot and new evaluation identity.
It never mutates a historical result. The prospective expansion interface is:

```text
sum over exact frozen profiles(
  requirements whose exact predicates evaluate applicable
)
```

Operation and vector expansion rules remain separate. The exact profile count
and final logical-execution denominator remain unknown until empirical profile
freeze.

## Verification

Run:

```text
python tools/applicability/compile_conditional_applicability.py --check
```

The acceptance report proves `1,972 / 1,972` conditional requirement coverage,
stable predicate identity, typed reference closure, open-world truth-table
behavior, prohibited dependency rejection, unchanged denominator counts, and
explicit deferral of real profile expansion.
