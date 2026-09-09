# Canonical semantic obligations and requirements

The current semantic denominator is derived from the frozen 269-feature
semantic snapshot and the versioned explainable-rule contract. It replaces the
former uniform facet grid as current obligation and requirement authority while
preserving that grid as immutable history.

## Authority chain

```text
frozen semantic assertion
  → explicit facet and operation rule revision
  → canonical semantic obligation
  → cardinality rule and evidence role
  → canonical semantic requirement
  → later declarative vector attribution
```

The current authority index is
`ontology/authority/current-semantic-denominator.v1.json`. It binds the exact
obligation snapshot, requirement snapshot, compact projection, migration
ledger, materialization report, and current certification evaluation. The
profile-expanded execution denominator is explicitly deferred until capability
predicates can be evaluated against the empirically frozen profile universe.

The canonical populations are 2,390 obligations and 3,378 minimum attributable
requirements. Of the obligations, 1,058 are unconditional and 1,332 retain an
explicit profile-capability predicate. The requirement population contains
1,406 unconditional and 1,972 conditional requirements. Seventy-nine questions
are explicitly characterization-only; they do not acquire a normative expected
answer through materialization.

No concrete production vector is created by this architecture. Every current
requirement therefore remains `missing`, and the current certification
evaluation reports C4 as `FAIL` at `0/3378`.

## Identity and explainability

Obligations and requirements use the permanent assigned-identity namespaces.
Their one-time allocations are recorded in
`ontology/derivations/semantic-denominator-identities-2026-09-08.v1.json`.
Mutable names, paths, descriptions, ordering, and generator versions are not
identity inputs. The scientific identity catalog contains active successor
objects and keeps every retired, merged, split, superseded, or unresolved
predecessor identity reserved.

Each obligation binds its feature, facet, archetype, operation scope,
structured semantic assertions, rule revision, question type, profile
condition, cardinality contract, and predecessor identities. Each requirement
then binds its obligation, evidence role, execution mode, future oracle
capability, exact attribution rule, condition, and predecessor identities.

Inspect either object by key or scientific ID:

```sh
python tools/semantics/generate_obligation_snapshots.py --explain <identifier>
```

The explanation reconstructs why the semantic question exists, why it is
unconditional or conditional, and why its archetype requires that particular
minimum evidence role. A later vector family may satisfy a requirement only by
naming its stable requirement and obligation identities; incidental feature
co-occurrence earns no coverage credit.

## Cardinality and conditionality

A semantic obligation is the distinct behavior that must be known. A semantic
requirement is one minimum independently attributable evidence role needed to
answer it. A concrete vector is a later executable or otherwise admissible
instantiation. These populations are deliberately not one-to-one.

Cardinality is derived from the obligation archetype. Defining behavior and
grammar questions may need separate positive and negative witnesses; boundary
questions may need a boundary role; permitted variation needs a
characterization role. The requirement count is not tuned to a target size.

Conditional predicates use canonical scientific IDs for profile features,
operations, manifestations, variants, and modifiers. Until a future profile
authority evaluates those predicates, conditional does not mean required for
all profiles, unsupported, or not applicable.

## Historical reconciliation

The migration ledger accounts for all 12,048 predecessor obligations and all
9,506 predecessor requirements. It distinguishes retained scientific identity,
semantically equivalent successor, split, merge, retirement for lack of a
researched trigger, and historically unresolved mapping. Every current object
also records whether it descends from predecessor objects or answers a question
the old grid did not represent.

The old projection, requirement ledger, storage forecast, and certification
evaluation remain byte-identical and historically resolvable. Advancing current
authority does not reinterpret an old C4 report. Certification contract 1.1.0
accepts the successor requirement-snapshot input mode while retaining the same
C1–C7 predicate meanings.

## Reproduction

Materialization is design compilation only. Expensive deterministic closure is
authoritative on the controlled local machine and is bound into the tracked
local certification manifest:

```sh
python tools/semantics/generate_obligation_snapshots.py --check
python tools/certification/evaluate.py --check
python tools/identity/freeze_scientific_identities.py --check
python tools/provenance/compile_generated_assertion_derivations.py --check
python tools/ci/certify_local.py --root .
```

The verifier regenerates the snapshots, validates total migration and exact
cardinality, checks every explanation and conditional predicate, verifies the
identity/lineage lock, and confirms the historical denominator hashes. It does
not execute a target, author a vector, expand a profile universe, or estimate
final retained production storage.

Hosted Linux follows the bounded integrity role described by the
[local authoritative certification architecture](local-authoritative-certification.md):
it verifies the exact source/envelope relationship, every referenced digest and
closure, identity and derivation bindings, and cheap aggregate predicates. It
does not repeat this expensive materialization.
