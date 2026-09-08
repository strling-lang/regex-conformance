# Declared-cutoff semantic universe freeze

The current semantic authority is the content-addressed
[frozen snapshot](../../semantic-corpus/snapshots/regex-semantic-features-2026-09-08.v4.json).
It makes a bounded scientific claim:

> The semantic universe is exhaustive against the declared research cutoff,
> audited source universe, explicit scope, and documented discovery
> methodology, with every encountered candidate dispositioned.

The cutoff is `2026-09-08T00:14:25Z`. This is not a claim of timeless
completeness, every future regex concept, or complete product/profile
discovery. A new authoritative source, a material correction, a reopened
blocking candidate, or a changed scope creates a versioned successor. It never
rewrites this snapshot.

## Authority and artifacts

The [current authority index](../../semantic-corpus/authority/current.v1.json)
points to exactly one semantic snapshot and its
[freeze manifest](../../semantic-corpus/freeze/regex-semantic-universe-2026-09-08.v1.json).
The manifest closes over:

- the [adversarial audit plan](../../semantic-corpus/research/regex-semantic-universe-adversarial-plan-2026-09-08.v1.json);
- the [final candidate ledger](../../semantic-corpus/research/regex-semantic-universe-candidates-2026-09-08.v1.json);
- the frozen snapshot;
- the [feature-level source-coverage report](../../reports/semantics/regex-semantic-source-coverage-2026-09-08.v1.json); and
- the [adversarial audit report](../../reports/semantics/regex-semantic-universe-adversarial-audit-2026-09-08.v1.json).

Each reference binds a content identity and digest. The authority index also
keeps the three predecessor snapshots resolvable and separately states that
semantic authority advanced without advancing the old obligation denominator.

## Adversarial method

The audit used five deliberately different strategies: source-first,
ontology-first, operation-first, test-corpus-first, and terminology-first. Its
164 structured review units covered 16 categories, 15 facets, 33 operations,
19 representative system families, eight revision-pinned authoritative test
corpora, and all 73 prior candidate dispositions.

The test corpora were discovery inputs, not automatic semantic authorities.
The scan included [Test262](https://github.com/tc39/test262),
[PCRE2](https://github.com/PCRE2Project/pcre2),
[Rust regex](https://github.com/rust-lang/regex),
[ICU](https://github.com/unicode-org/icu),
[Oniguruma](https://github.com/kkos/oniguruma),
[Onigmo](https://github.com/k-takata/Onigmo),
[Go regexp](https://github.com/golang/go), and
[Perl](https://github.com/Perl/perl5). Exact revisions and scanned areas live
in the audit plan.

The first pass found 18 residual candidates: seven source-first, four
test-corpus-first, three ontology-first, three operation-first, and one
terminology-first. A structurally independent second pass found no additional
material candidate after those 18 were resolved. Zero yield is recorded as an
audit result, not emitted as a construction constant.

## Accepted residual semantics

Two residual candidates changed the universe:

- **Numeric escape disambiguation** is a canonical grammar feature. It owns
  resolution of a digit-following backslash among a group reference, numeric
  character escape, literal, or syntax error. This was missing even though the
  possible outcomes were already modeled individually. The rule is supported
  by ECMAScript, PCRE2, and Python primary documentation.
- **Restricted caseless folding** is a modifier, not a second case-folding
  feature. PCRE2's `(?r)` / `(*CASELESS_RESTRICT)` prevents Unicode caseless
  equivalences from crossing the ASCII/non-ASCII boundary. Its spelling is a
  manifestation of the existing inline-modifier feature.

Rust regex-automata's earliest-search instruction was not promoted. Its own
documentation says the result depends on the selected engine and is not a
consistent match semantic. It remains visible as a profile-specific execution
parameter candidate. Flex trailing context, scanner start conditions,
ECMAScript escaping adjacency, legacy escape rules, Turkish casing, Hamming
distance, reverse search, start-of-match horizons, and host-object species were
likewise placed in existing concepts or narrower owning layers with evidence.
The official flex 2.6.4 manual is registered as the primary authority for the
two scanner dispositions rather than treating POSIX syntax as evidence of
flex-specific lifecycle behavior.

The frozen universe therefore contains 269 features, 33 operations, 15
facets, 60 source identities, 93 semantic variants, 326 manifestations, and 33
modifiers; the 108 typed interactions remain unchanged. No feature was merged,
superseded, or retired. The permanent
identity lock gained one feature, two manifestations, and one modifier.

## Source and overcount checks

All 269 accepted features have registered authority. There are zero
source-orphaned and zero secondary-only features. Fifty-four features have
independent cross-authority corroboration; 215 have one authority, which is
valid for source-specific concepts. Multiple sources are not manufactured
where only one implementation owns the behavior.

The overcount review retained scientifically distinct boundaries including
capture history versus capture stack, empty pattern versus empty language,
ordered alternation versus leftmost-first selection, operations versus
features, and Unicode properties versus text domains. No merge was justified.

## Machine closure and denominator boundary

`tools/semantics/freeze_semantic_universe.py` validates source and parent
references, unique canonical ownership, researched assertion coverage,
candidate closure, exact source coverage, content identities, the freeze
manifest, and deterministic bytes. Adversarial fixtures prove that a source
orphan, duplicate feature, or blocking candidate fails closed.

The snapshot is now the semantic input to obligation derivation. It does not
partially derive obligations. The historical projection remains at 12,048
obligations, the requirement ledger remains at 9,506 requirements, and their
forecast remains byte-identical. Advancing those authorities requires the
dedicated denominator workflow after the semantic-knowledge acceptance gate.

Regenerate or check the freeze with:

```sh
python tools/semantics/freeze_semantic_universe.py --check
```
