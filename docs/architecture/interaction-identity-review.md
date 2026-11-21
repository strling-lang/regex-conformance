# Interaction identities requiring review

The current denominator includes six interaction obligations with no assigned
`semantic-interaction` identity in the [identity catalog](../../registries/identity/scientific-identities.v1.json).
Each obligation has a positive and a negative requirement. Their relation
bases enter the denominator through `modifier_ids` or
`prerequisite_feature_ids` in the [frozen semantic snapshot](../../semantic-corpus/snapshots/regex-semantic-features-2026-09-08.v4.json).
Identity catalog construction reads the legacy interaction population. None
of the six keys resolves as a current key or a former key. Each endpoint
already has a scientific identity.

This is a review proposal. The suffixes below identify rows in the
[obligation snapshot](../../ontology/obligations/regex-semantic-obligations-2026-09-08.v1.json)
and [requirement snapshot](../../vectors/requirements/regex-semantic-vector-requirements-2026-09-08.v2.json).
Requirement suffixes appear in positive, then negative order.

| Proposed disposition | Source feature | Relation and target | Obligation UUID suffix | Requirement UUID suffixes |
| --- | --- | --- | --- | --- |
| Allocate after review | `feature.inline-modifier-directive` | `modified-by` → `modifier.caseless-restrict` | `c3d936a73ed3` | `c2fb69075286`, `75b42b5defd6` |
| Allocate after review | `feature.simple-case-folding` | `modified-by` → `modifier.caseless-restrict` | `db4c631fd77a` | `54c5aa32d6b9`, `491dfebafb11` |
| Allocate after review | `feature.numeric-escape-disambiguation` | `prerequisite` → `feature.numbered-backreference` | `937937e59a0f` | `d33ed1ced941`, `40e3c3a19a44` |
| Allocate after review | `feature.numeric-escape-disambiguation` | `prerequisite` → `feature.invalid-group-reference` | `a394b517f50a` | `ef9d29be1ceb`, `71d4b0cd3350` |
| Review relation semantics before allocation | `feature.numeric-escape-disambiguation` | `prerequisite` → `feature.escaped-literal` | `b6923815f743` | `61804daaa43a`, `37c33ef21bfe` |
| Review relation semantics before allocation | `feature.numeric-escape-disambiguation` | `prerequisite` → `feature.numeric-unicode-code-point-escape` | `a7dbde722dab` | `a71b3c02b3cc`, `2ec587f39fe3` |

1. **Inline restriction.** PCRE2 documents `(?r)` as an in-pattern spelling
   for caseless restriction. This supports the inline directive relationship
   in a profile that exposes that spelling. The start-of-pattern directive
   and the compile-context option are separate forms. [PCRE2 pattern specification](https://www.pcre.org/current/doc/html/pcre2pattern.html)
2. **Restricted simple folding.** In PCRE2 Unicode caseless modes the option
   suppresses the K/Kelvin sign and S/long s equivalences. Unicode UTS #18
   supplies the independent definition of simple folding. The restriction
   comes from PCRE2's documented profile semantics. [PCRE2 pattern specification](https://www.pcre.org/current/doc/html/pcre2pattern.html) · [UTS #18 revision 25](https://www.unicode.org/reports/tr18/tr18-25.html#Simple_Loose_Matches)
3. **Numbered backreference.** PCRE2's decimal escape parsing uses capture
   count when deciding whether a digit sequence denotes a reference. Python's
   octal rule supplies a useful comparison with a different disambiguation
   rule. The prerequisite is scoped to the reference branch of the exact
   grammar. [PCRE2 non-printing characters and backreferences](https://www.pcre.org/current/doc/html/pcre2pattern.html) · [Python 3.14 regular expression syntax](https://docs.python.org/3.14/library/re.html#regular-expression-syntax)
4. **Invalid reference.** ECMAScript's `DecimalEscape` early error distinguishes
   a reference beyond the pattern's capture count. Annex B separately alters
   legacy grammar. The existing applicability boundary must preserve those
   distinctions. [ECMAScript RegExp early errors](https://tc39.es/ecma262/2026/multipage/text-processing.html#sec-patterns-static-semantics-early-errors) · [ECMAScript Annex B RegExp extensions](https://tc39.es/ecma262/2026/multipage/additional-ecmascript-features-for-web-browsers.html#sec-regular-expressions-patterns)
5. **Literal fallback.** The target feature currently means quoting a
   metacharacter. ECMAScript Annex B documents legacy octal and
   non-octal-decimal escapes. It does not establish that the fallback requires
   metacharacter quoting. Ask whether the interaction should name a governed
   fallback feature or be suppressed with explicit disposition. [ECMAScript Annex B RegExp extensions](https://tc39.es/ecma262/2026/multipage/additional-ecmascript-features-for-web-browsers.html#sec-regular-expressions-patterns)
6. **Numeric character interpretation.** A bare digit sequence can produce an
   octal character escape in the documented grammars. ECMAScript's `\u`
   code-point forms are distinct productions. Confirm whether the existing
   target denotes the relevant bare numeric escape in the researched model
   before requiring its capability as an applicability prerequisite. [Python 3.14 regular expression syntax](https://docs.python.org/3.14/library/re.html#regular-expression-syntax) · [ECMAScript RegExp grammar](https://tc39.es/ecma262/2026/multipage/text-processing.html#sec-patterns)

The Program Owner can review the four straightforward allocations together
and separately disposition the two questioned prerequisite edges in the same
decision. Use the existing assigned UUIDv7 `semantic-interaction` namespace
and persist one identity per accepted source, relation, and target triple.
Catalog construction should reconcile all three governed relation sources and
detect duplicate triples. Adding identities to retained triples preserves the
existing obligation and requirement IDs, cardinality, and predicates. Changing
a relation or its applicability requires reviewed semantic lineage and a
recomputed successor denominator, including explicit mappings for the old
obligation and requirements. All twelve current rows retain their blocked
dispositions until the corresponding approved change is recorded. [Scientific identity and migration contract](scientific-identities.md) · [Governance](../../GOVERNANCE.md)
