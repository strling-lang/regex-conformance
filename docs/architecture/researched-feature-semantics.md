# Researched feature semantics

The canonical researched successor to the declared-cutoff semantic snapshot
replaces mechanically repeated feature fields with source-bound, structured
semantic decisions. It covers the same 251 scientific features; it does not
add features, regenerate obligations, author vectors, or change empirical
evidence.

The three authoritative products are:

- the immutable feature research ledger in
  `semantic-corpus/research/regex-semantic-feature-research-2026-09-07.v1.json`;
- the content-addressed successor snapshot in
  `semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v2.json`; and
- the deterministic completeness report in
  `reports/semantics/researched-feature-semantics-2026-09-07.v1.json`.

They are rebuilt by `tools/semantics/compile_researched_semantics.py`. The
compiler consumes the accepted snapshot and permanent scientific-identity
catalog as immutable inputs. It cannot reach the legacy obligation generator.

## Research standard

Every feature was reviewed against its exact source identities. Evidence is
preferred in this order: normative specification, official implementation
documentation, official source or tests, authoritative standards or data,
primary technical literature, then explicitly identified inference. Behavior
shared by several engines is not authority merely because it is common.

Each substantive assertion contains:

- a semantic field;
- a structured knowledge state;
- its scope;
- a shared researched rule;
- a feature-specific conclusion;
- one or more source identities; and
- the registered research derivation handle.

The shared rule catalog removes duplicated boilerplate without weakening
feature-level review: a rule applies only where the research ledger explicitly
assigns it to a feature and binds that assignment to sources. The derivation
catalog records the exact method revision used to publish these assertions.

## Semantic states and scopes

The snapshot does not use empty prose to blur different knowledge states. It
distinguishes:

- `known`;
- `no-feature-specific-implication`;
- `not-applicable`;
- `implementation-defined`;
- `intentionally-under-specified`; and
- `unresolved`.

These states are not interchangeable. In particular, no feature-specific
effect does not mean that research was not performed, and not-applicable does
not mean unknown. Assertions separately declare whether their scope is a
canonical invariant, manifestation-specific, variant-specific,
profile-dependent, or operation-specific.

The ten reconstructed dimensions are canonical definition, syntax and
grammar, capture and result behavior, diagnostics and errors, replacement,
resources and termination, Unicode and encoding, search and iteration,
options and state, and host operations. Test concepts name the material
dimensions to probe; they are not production vectors.

## Variant and manifestation isolation

Canonical feature assertions describe only the stable scientific concept.
Every one of the existing semantic variants now has a source-bound statement
of its actual differentiating rule. Variant behavior is not silently promoted
to the parent feature.

Each syntax or API manifestation identifies its permanent scientific ID,
source, manifestation-specific scope, and canonical feature owner. An engine's
spelling or host restriction therefore cannot redefine the cross-system
concept.

## Identity and immutable history

All 251 feature identities, 88 semantic-variant identities, and 304
manifestation identities are reused from the permanent identity catalog. The
changes are better understanding of the same scientific concepts, so no
feature successor was required. A future material correction must use the
existing successor and lineage contract instead of mutating historical
meaning.

The predecessor snapshot remains byte-identical and resolvable. The successor
has its own content-derived ontology-snapshot identity. Editing a semantic
assertion changes the snapshot identity while leaving the stable scientific
entity ID inside the snapshot unchanged unless the scientific concept itself
changes.

The scientific-foundation acceptance manifest is an immutable historical
baseline, so this successor does not rewrite it to claim that its old digests
are current. Historical acceptance remains verifiable; a strict current-file
comparison intentionally reports the semantic and derivation revisions as
versioned evolution.

## Obligation boundary

The accepted projection still contains 12,048 uniform obligation templates,
and its requirement ledger still contains 9,506 requirements. Both remain
bound to the predecessor snapshot until the dedicated semantic-applicability
and denominator work. The researched successor supplies trustworthy input to
that future derivation but does not pre-empt it.

Use these checks for deterministic reconstruction:

```sh
python tools/semantics/compile_researched_semantics.py --check
python tools/provenance/compile_generated_assertion_derivations.py --check
python tools/foundation/certify.py --history
```
