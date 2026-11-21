# Interaction identity allocations and successor proposals

The current denominator includes six interaction obligations absent from the
[frozen base catalog](../../registries/identity/scientific-identities.v1.json).
Each obligation has a positive and a negative requirement. Their relation
bases enter the denominator through `modifier_ids` or
`prerequisite_feature_ids` in the [frozen semantic snapshot](../../semantic-corpus/snapshots/regex-semantic-features-2026-09-08.v4.json).
Identity catalog construction reads the legacy interaction population. Each
endpoint already has a scientific identity. On 2026-11-21 the Program Owner
approved the four source-supported allocations. The verified
[supplemental catalog](../../registries/identity/production-interaction-allocations.v1.json)
binds their assigned UUIDv7 identities to the existing base catalog and
obligation snapshot.

The suffixes below identify rows in the
[obligation snapshot](../../ontology/obligations/regex-semantic-obligations-2026-09-08.v1.json)
and [requirement snapshot](../../vectors/requirements/regex-semantic-vector-requirements-2026-09-08.v2.json).
Requirement suffixes appear in positive, then negative order.

| Disposition | Source feature | Relation and target | Obligation UUID suffix | Requirement UUID suffixes |
| --- | --- | --- | --- | --- |
| Allocated | `feature.inline-modifier-directive` | `modified-by` → `modifier.caseless-restrict` | `c3d936a73ed3` | `c2fb69075286`, `75b42b5defd6` |
| Allocated | `feature.simple-case-folding` | `modified-by` → `modifier.caseless-restrict` | `db4c631fd77a` | `54c5aa32d6b9`, `491dfebafb11` |
| Allocated | `feature.numeric-escape-disambiguation` | `prerequisite` → `feature.numbered-backreference` | `937937e59a0f` | `d33ed1ced941`, `40e3c3a19a44` |
| Allocated | `feature.numeric-escape-disambiguation` | `prerequisite` → `feature.invalid-group-reference` | `a394b517f50a` | `ef9d29be1ceb`, `71d4b0cd3350` |
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

## Proposed successors for the disputed prerequisites

For `b6923815f743`, replace `escaped-literal` with `literal-unit`, scoped to
the legacy digit fallback. In ECMAScript Annex B without Unicode mode and
without a corresponding capture, `\8` can enter the source-character
identity-escape production and consume the digit `8`. Compare this with
Unicode mode, where the missing group is an early error. Capability to quote
a regexp metacharacter supplies neither branch. The successor predicate needs
an exact legacy grammar capability in addition to `literal-unit`. Preserve the
positive and negative roles from `61804daaa43a` and `37c33ef21bfe` in their
respective successor requirements. [ECMAScript Annex B RegExp grammar](https://tc39.es/ecma262/2026/multipage/additional-ecmascript-features-for-web-browsers.html#sec-regular-expressions-patterns) · [ECMAScript early errors](https://tc39.es/ecma262/2026/multipage/text-processing.html#sec-patterns-static-semantics-early-errors)

For `a7dbde722dab`, replace `numeric-unicode-code-point-escape` with a dedicated
octal character escape capability. PCRE2 10.47 with its Perl rules can treat
`\11` as tab below the capture threshold and as a decimal reference when
eleven captures precede it. The rule works in octet mode. PCRE2's Python-octal
option has a different digit rule. The existing Unicode feature's canonical
manifestation is the hexadecimal notation of UTS #18. The new predicate should
select the exact octal branch and applicable grammar. Preserve the positive
and negative roles from `a71b3c02b3cc` and `2ec587f39fe3` in their respective
successor requirements. [PCRE2 10.47, Octal escapes and back references](https://raw.githubusercontent.com/PCRE2Project/pcre2/pcre2-10.47/doc/pcre2pattern.3#L501) · [UTS #18, Hex Notation](https://www.unicode.org/reports/tr18/tr18-25.html#Hex_notation)

The proposals retain both testing obligations. For the interaction-only
replacement, map 2,388 obligations and 3,374 requirements to themselves, then
map the two named predecessor obligations and four predecessor requirements
to one successor each. Additional obligations derived from a new feature must
be counted independently before acceptance of a successor snapshot.
The four retained allocations change no existing obligation, requirement,
predicate, or cardinality. The two disputed interactions still block their four
requirements in the accepted 2,390-obligation and 3,378-requirement snapshots.
[Scientific identity and migration contract](scientific-identities.md) · [Governance](../../GOVERNANCE.md)
