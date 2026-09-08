# Regex Semantic Feature Corpus

This directory is the primary repository-backed authority for canonical,
researched regex semantic concepts. Normative publishers remain authoritative
for their own standards; the corpus records exact source identities and the
reviewed cross-source semantic model.

The authority boundary is deliberate:

- `semantic-corpus/snapshots/` contains immutable, content-addressed semantic
  snapshots, including feature identities, definitions, variants, aliases,
  manifestations, modifiers, operations, typed interactions, candidate
  dispositions, discovery scans, and provenance.
- `ontology/projections/` contains immutable executable projections of an exact
  snapshot. A projection cannot redefine its source feature.
- empirical observations describe an exact runtime/profile under exact
  conditions and cannot silently alter semantic meaning;
- STRling language and compiler contracts may consume the corpus but remain
  product-language authority; and
- public products derive views from the corpus plus Conformance evidence. They
  do not maintain another feature taxonomy.

The former Notion-based Knowledge program is retired. Recoverable claims were
validated and provenance-bound. Nine provisional bridge identities that are no
longer recoverable remain explicit unresolved candidates; they were not guessed
from names or memory.

## Frozen declared-cutoff semantic snapshot

The current semantic knowledge authority is
[`snapshots/regex-semantic-features-2026-09-08.v4.json`](snapshots/regex-semantic-features-2026-09-08.v4.json).
It contains 269 features after five independent adversarial search strategies
revalidated all 73 prior candidates and dispositioned 18 newly discovered
candidates. Its bounded cutoff, search plan, source coverage, negative space,
and invalidation rules are closed by
[`freeze/regex-semantic-universe-2026-09-08.v1.json`](freeze/regex-semantic-universe-2026-09-08.v1.json).
See the [declared-cutoff semantic universe freeze](../docs/architecture/semantic-universe-freeze.md).
The integrated [semantic knowledge architecture acceptance](../docs/architecture/semantic-knowledge-architecture.md)
binds this authority, its research evidence, source coverage, identities,
derivations, and denominator-input contract in one deterministic report.

The expanded researched predecessor remains
[`snapshots/regex-semantic-features-2026-09-07.v3.json`](snapshots/regex-semantic-features-2026-09-07.v3.json).
Its 268 features and 73-candidate architecture ledger remain immutable and
resolvable. See [Semantic architecture dispositions](../docs/architecture/semantic-architecture-dispositions.md).

The predecessor researched snapshot is
[`snapshots/regex-semantic-features-2026-09-07.v2.json`](snapshots/regex-semantic-features-2026-09-07.v2.json).
It reconstructed all 251 accepted features with structured, source-bound
semantics while retaining their permanent scientific identities. Its research
ledger remains
[`research/regex-semantic-feature-research-2026-09-07.v1.json`](research/regex-semantic-feature-research-2026-09-07.v1.json).
See [Researched feature semantics](../docs/architecture/researched-feature-semantics.md)
for the knowledge-state, scope, evidence, identity, and regeneration contracts.

## Accepted predecessor snapshot

The original declared-cutoff snapshot is
[`snapshots/regex-semantic-features-2026-08-22.v1.json`](snapshots/regex-semantic-features-2026-08-22.v1.json).
Its semantic corpus digest is
`350bfea4c3da07b3426d885aa8ff645ac55539bbb1294a2ea35dd5319541d6c7`.

That snapshot is exhaustive to the strongest defensible 2026-08-22 cutoff. It
does not claim timeless omniscience. A successor is additive and versioned; do
not mutate a published snapshot in place.

## Reproduction and validation

The compiler performs design compilation only. It does not execute a regex
engine, realize an environment, access Docker, publish evidence, or run a
campaign.

```sh
python tools/semantics/compile_semantic_baseline.py --check
python tools/semantics/compile_researched_semantics.py --check
python tools/semantics/compile_semantic_architecture.py --check
python tools/semantics/freeze_semantic_universe.py --check
python tools/semantics/certify_semantic_knowledge.py --check
python tools/semantics/define_obligation_derivation.py --check
python tools/semantics/generate_obligation_snapshots.py --check
```

The predecessor compiler's generated products are:

- the semantic snapshot in this directory;
- `ontology/projections/regex-semantic-projection-2026-08-22.v1.json`;
- `vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json`;
- `reports/scale/regex-semantic-denominator-forecast.json`.

Each product is validated by a versioned schema and an additional semantic
verifier that checks identity uniqueness, relation targets, candidate
conservation, declared facet-template structural closure, vector attribution,
profile-bound allocation, arithmetic closure, content digests, and generated
assertion derivations. Structural closure means that the compiler emitted the
declared template; it is not evidence that the declared facets are a complete
scientific model.

The researched-semantics compiler publishes only a successor snapshot, its
research ledger, and a research-completeness report. It deliberately does not
regenerate the predecessor projection, obligation templates, requirement
ledger, or denominator forecast.

The semantic-architecture compiler publishes the next successor snapshot,
candidate ledger, typed identity allocation, and disposition report. It also
leaves the predecessor denominator artifacts byte-identical.

The semantic-universe freeze compiler publishes a final adversarial audit plan,
revalidated candidate ledger, source-coverage report, frozen successor
snapshot, freeze manifest, and current authority index. It adds no obligation
or vector requirement and preserves every predecessor snapshot.

The semantic knowledge acceptance compiler publishes a content-derived
foundation manifest and acceptance report. It validates integration and
denominator readiness without emitting obligations or advancing denominator
authority.

The explainable-obligation compiler consumes that accepted semantic authority
and publishes a versioned rule contract, a complete analysis of the predecessor
fixed grid, and a non-authoritative dry run. It makes one explicit decision per
feature/facet pair, binds conditions to scientific identities, and has no
uniform fallback. Its analysis keys are not canonical obligation IDs, and it
does not regenerate or supersede the predecessor denominator.

The semantic-denominator materializer consumes those accepted decisions,
allocates permanent obligation and requirement identities, and publishes the
current 2,390-obligation / 3,378-requirement snapshots plus total predecessor
reconciliation and a compact downstream projection. The original 12,048/9,506
artifacts remain immutable historical authority for their own earlier reports.
No concrete vector or profile-expanded coordinate is produced.

Published semantic artifacts remain immutable. The companion derivation
inventory records that legacy fixed audit, discovery, facility-reconciliation,
and facet-template statements are construction output where appropriate,
without rewriting their bytes. See
[`../docs/architecture/generated-assertion-derivations.md`](../docs/architecture/generated-assertion-derivations.md).
