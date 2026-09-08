# Explainable obligation derivation

The frozen semantic snapshot defines what is known. The obligation-derivation
contract defines which distinct scientific questions that knowledge requires.
It is the only prospective bridge from current semantic authority to a future
obligation denominator.

The current contract is
`ontology/derivations/regex-obligation-derivation-rules-2026-09-08.v1.json`.
Its evaluator is `tools/semantics/define_obligation_derivation.py`. The tracked
dry run is analysis only: it neither mints canonical obligation identities nor
advances denominator authority.

## Concept boundaries

- A **semantic obligation** is one distinct behavior or scientific question
  that must be known.
- A **vector requirement** states the minimum executable or otherwise
  admissible evidence needed to satisfy one or more explicitly attributed
  obligations.
- A **concrete generated vector** is one deterministic instantiation. It does
  not acquire obligation identity and may earn only declared attribution.

These populations are deliberately not one-to-one. One obligation can require
several positive, negative, boundary, or mode cases. One vector family may
cover closely related obligations only while each attribution remains
independently testable.

## Total decision function

The evaluator makes exactly one decision for every frozen feature/facet pair:

| Decision | Meaning |
| --- | --- |
| `required` | Researched semantics directly require a scientific question. |
| `conditionally-required` | The question exists only under an explicit semantic, manifestation, variant, operation, or profile-capability condition. |
| `not-applicable` | Research establishes that the semantic dimension does not apply. |
| `not-required-by-feature-semantics` | The dimension exists, but this feature has no feature-specific implication. |
| `blocked-by-unresolved-semantics` | A material unresolved semantic fact prevents a defensible obligation shape. |

There is no generic fallback. An unknown facet, semantic state, operation,
identity, or predicate vocabulary entry fails validation.

Structured semantic states retain their distinctions:

- `known` may trigger a required question;
- `no-feature-specific-implication` suppresses the facet without pretending it
  is unknown;
- `not-applicable` records researched exclusion;
- `implementation-defined` and `profile-dependent` retain explicit conditions;
- `intentionally-under-specified` creates a characterization question without
  inventing a universal expected result; and
- `unresolved` blocks affected derivation.

The calculation cannot strengthen its inputs. A documented implementation
claim remains implementation-documentation-capable; an under-specified region
remains characterization-only; a prospective relational question remains a
metamorphic candidate until a later oracle contract admits it.

## Facet rules

All 15 semantic facets have explicit rules:

| Facet | Trigger and suppression rule |
| --- | --- |
| Syntax/grammar | Accepted, rejected, ambiguous, or mode-specific grammar; suppressed when syntax is not applicable. |
| Core match | Minimal defining behavior for every canonical feature, with a negative contrast only for classes where it is meaningful. |
| Search/iteration | Start, selection, advancement, repetition, cursor, or terminal-state effects only. |
| Capture/result | Capture existence, numbering, value, history, tree, span, or result shape only. |
| Unicode/encoding | Text domain, property, folding, boundary, malformed-input, code-unit/code-point/grapheme, or index-unit semantics only. |
| Options/state | Material mode, scope, cursor, region, or state transitions only. |
| Host operation | A distinct invocation, state, or result contract exposed through canonical operations. |
| Replacement | Substitution-visible capture, output, span, template/callback, or empty-match advancement semantics only. |
| Diagnostics/errors | Scientifically meaningful acceptance, rejection, unsupported, runtime, or target-attributable outcome classes. |
| Resource/termination | Documented target limits, resource states, or termination semantics, never generic performance variation. |
| Interaction | Explicit typed relations, prerequisites, or modifiers only; no feature-pair cross-product. |
| Differential | Analysis-only projection over independently evidenced facts; it contributes no separate obligation. |
| Phase | Behavior that differs across build, compile, match, replacement, stream, or serialization lifecycle phases. |
| Complexity guarantee | Documented algorithmic guarantees or subset restrictions, never a timing observation alone. |
| Security context | Concrete quoting, trust, injection, serialized-input, or denial-of-service boundaries, never a generic checklist. |

## Operation applicability

The 33 canonical operations form seven disjoint families:

- construction: compile, pattern escaping, replacement escaping;
- single-match: test, prefix match, full match, search, partial match;
- iteration/result: next match, find all, overlapping find, extract, count,
  position, analyze;
- replacement: replace first/all/callback, expand replacement, split;
- multi-pattern: set match, block scan, vector scan;
- stream/session: scan, open, close, reset, copy, compress, expand; and
- serialization: serialize, deserialize, inspect.

Ordinary operation relevance comes from a feature's researched supported
operations. Newer operation-only surfaces use closed selectors: escaping is
limited to the relevant feature identities, serialization requires a
compilable feature, inspection uses declared feature classes, and stream
lifecycle operations require stream capability. Vendor method names never
create canonical operations.

Profile predicates use scientific identities, not mutable labels. Their closed
fields cover feature, operation, manifestation, semantic-variant, and modifier
scientific identities; their operators are `contains` and `intersects`.
Missing profile facts leave a conditional question visible. They do not turn
it into `not-applicable`.

Variant-specific questions carry the variant scientific identity and source
binding. Manifestation-specific assertions add a manifestation-scientific-ID
condition. Interaction questions carry the target feature or modifier
scientific identity and require that target capability. Mutable operation,
variant, manifestation, and feature labels remain diagnostics only.

## Obligation archetypes

The contract defines 16 scientific question shapes:

- defining positive and defining negative behavior;
- grammar acceptance and grammar rejection;
- semantic boundary behavior;
- state transition and repeated iteration;
- alternative semantic mode;
- host result and replacement output;
- resource-limit or target-termination behavior;
- permitted variation/characterization;
- explicit interaction behavior;
- phase-specific behavior;
- documented complexity guarantee; and
- concrete security boundary.

An archetype is not a fixed case count. It states the question a later vector
requirement must answer, whether positive and negative subjects may be needed,
whether parameterized generation is permitted, and whether the question can
contribute to coverage.

## Explainability and identity

Every prospective obligation trace records:

```text
semantic assertion and structured state
→ content-derived rule revision
→ semantic facet and scientific archetype
→ canonical operation/profile condition
→ prospective obligation identity basis
```

The prospective identity basis contains feature and facet scientific IDs,
operation scientific IDs, question type, relevant semantic selectors, and any
variant or interaction scientific identity. It excludes display names, reason
prose, file paths, report order, and operation labels. The analysis key is a
review aid, not a canonical scientific identity. Canonical obligation IDs are
reserved for the dedicated denominator materialization step, where stable
identity and migration rules can be applied to the accepted population.

Explain one feature without changing artifacts:

```sh
python tools/semantics/define_obligation_derivation.py --explain feature.unicode-line-break-boundary
```

Examples of decisions include:

- `feature.absent-expression` has no capture-specific implication, so the
  capture facet is explicitly suppressed;
- `feature.unicode-line-break-boundary` requires Unicode boundary questions;
- `feature.append-replacement-state` requires replacement-output and repeated
  advancement questions;
- `feature.atomic-group` has a profile-dependent capture consequence and is
  conditional;
- a deliberately under-specified fixture yields characterization rather than
  a fabricated conformance result; and
- `feature.assertion-conditional` receives a bounded interaction question tied
  to its exact prerequisite identity.

## Legacy analysis and dry-run authority

The legacy report reconstructs all 12,048 predecessor obligation cases. It
classifies 3,088 as supported by a current feature-specific question, 7,585 as
uniform template output without a feature-specific trigger, and 1,375 as
having ambiguous historical rationale. It also identifies 440 current
feature/facet pairs whose semantics are not represented by the old grid.

The deterministic dry run evaluates all 269 features across all 15 facets. It
produces 4,035 explicit decisions and 2,390 provisional obligations across 85
distinct feature shapes. The minimum/median/p95/maximum obligations per feature
are 4/9/15/21. Of the provisional questions, 1,058 are required and 1,332 are
conditional. These are design metrics, not a new denominator or certification
claim.

The predecessor projection, 12,048 obligation templates, 9,506 vector
requirements, and storage forecast remain byte-locked. Current certification
continues to use that predecessor denominator until a separately reviewed
materialization advances authority.

## Regeneration

Materialize the contract and analysis artifacts:

```sh
python tools/semantics/define_obligation_derivation.py
python tools/provenance/compile_generated_assertion_derivations.py
```

Verify deterministic bytes and all prerequisite foundations:

```sh
python tools/semantics/define_obligation_derivation.py --check
```

This tooling performs no target execution, profile expansion, vector
authoring, evidence publication, or denominator promotion.
