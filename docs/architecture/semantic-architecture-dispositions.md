# Semantic architecture dispositions

The current semantic architecture is the content-addressed successor snapshot
[regex-semantic-features-2026-09-07.v3.json](../../semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v3.json).
It follows the feature-by-feature researched snapshot and records the result of
an explicit omission, operation, source, and taxonomy review. The
[candidate ledger](../../semantic-corpus/research/regex-semantic-architecture-candidates-2026-09-07.v1.json)
is the review authority: every candidate remains present with its sources,
distinctness test, disposition, identity effect, and downstream consequence.

This snapshot is not a completeness certificate. It closes the known candidate
set and is the input to a separate adversarial exhaustion review.

## Canonical dimensions

The semantic model contains fifteen identified dimensions. Twelve preserve the
existing syntax, match, search/boundary, capture, Unicode/encoding,
option/state, host API, replacement, diagnostics, resource/termination,
interaction, and version/platform dimensions. Three additions make previously
implicit distinctions machine-readable:

| Dimension | What it records | What it must not mean |
| --- | --- | --- |
| Semantic phase | build/source generation, compile, match/search, replacement/substitution, stream/session, or serialization/deserialization | a compile rejection is not a match result |
| Complexity guarantee | documented worst-case time, memory, conditional-subset, or budget guarantee | an observed timeout is not an algorithmic guarantee |
| Security context | trust of pattern, subject, or serialized input; injection boundary; denial-of-service posture | generic security prose or an inferred semantic result |

Each facet has a typed assigned identity and a closed vocabulary. Later
obligation derivation may consume only evidence-backed applicability; it must
not expand every feature over all fifteen dimensions merely because the
dimensions exist.

## Operation taxonomy

The twenty-two predecessor operations remain canonical. Eleven materially
distinct host operations are added:

- pattern escaping and replacement escaping;
- compiled-pattern serialization and deserialization;
- compiled-pattern introspection;
- stream open, close, reset, copy, compress, and expand.

Pattern compilation remains the existing compile operation; stream feed
remains stream-scan; subexpression extraction and position remain the existing
extract and position operations. Static minimum/maximum match information is an
introspection manifestation rather than another vendor-named operation. Vendor
method names map to manifestations of these thirty-three contracts.

## Accepted semantic concepts

Seventeen canonical features were added after primary-source comparison:

- inline modifier directives and scoped modifier groups, with leading/global,
  group-tail, unset, reset, and mutually-exclusive behavior represented as
  semantic variants;
- expression-level intersection, difference, and complement;
- empty-language, universal-language, numeric-interval, and named-automaton
  atoms;
- numeric Unicode code-point escapes, Unicode line-break boundaries, and
  enumerated and numeric Unicode property values;
- non-atomic positive lookbehind, recursion-level-qualified backreferences,
  and captured-substring assertions; and
- typed capture result shape.

Expression algebra remains distinct from character-class set algebra and from
logical combination of independently reported multi-pattern results.
Replacement spellings remain manifestations/profile properties rather than
duplicate features. Byte, code-unit, code-point, grapheme, and string-language
domains remain explicit and non-interchangeable.

Two existing result-span mutators were relocated from the anchor category to
host operations/results without changing their scientific identities. No
existing feature was merged, split, superseded, retired, or renamed. Potential
capture-tree interpretation is deferred to the later oracle/adjudication
authority; package catalogues remain profile-discovery inputs rather than
semantic authorities.

## Source authority

Source authority remains proposition-scoped. Normative specifications own
their normative statements; official implementation documentation owns exact
implementation behavior. Secondary catalogues are discovery leads only.

The successor adds ten exact authorities for Lucene automaton expressions,
SMT-LIB regular languages, Swift Regex and RegexBuilder, Unicode line breaking
and property data, PCRE2 serialization and pattern information, and Perl
Unicode boundary escapes. Vim and Emacs were already represented. General
package indexes were deliberately deferred to profile discovery.

Cross-engine majority behavior is never used as authority. Every new
substantive assertion binds the semantic-architecture research derivation and
one or more source identities. Shared semantic rules are permitted only when a
feature-level source-bound applicability decision makes the shared consequence
true.

## Identity and history

The 251 predecessor feature identities are unchanged. Additions allocate
typed, persistent identities for fifteen facets, eleven operations, seventeen
features, five variants, and twenty manifestations. The identity catalog
therefore grows additively from the accepted 22,359-identity foundation
baseline to 22,427 identities. Retired identities are not reused.

The predecessor researched snapshot and the original snapshot remain immutable
and resolvable. The current namespace registry is an additive successor of the
accepted registry; it adds only the semantic-facet assigned namespace.

## Denominator boundary

The successor changes semantic knowledge, not the executable denominator.
These predecessor artifacts remain byte-identical:

- 12,048 obligation templates in the semantic projection;
- 9,506 vector requirements in the requirement ledger; and
- the existing scale and storage forecast.

The dedicated denominator derivation will supersede those artifacts only after
the semantic universe has passed adversarial exhaustion. No production vector,
profile expansion, campaign, Evidence Pack redesign, or storage-policy change
is performed by this architecture update.

## Reproduction

The compiler is deterministic and performs no regex execution:

    python tools/semantics/compile_semantic_architecture.py --check
    python tools/identity/freeze_scientific_identities.py --check
    python tools/provenance/compile_generated_assertion_derivations.py --check

The compact
[disposition report](../../reports/semantics/semantic-architecture-disposition-2026-09-07.v1.json)
reconciles candidate, architecture, identity, source, derivation, and immutable
denominator counts.
