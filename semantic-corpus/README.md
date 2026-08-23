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

## Frozen snapshot

The declared-cutoff snapshot is
[`snapshots/regex-semantic-features-2026-08-22.v1.json`](snapshots/regex-semantic-features-2026-08-22.v1.json).
Its semantic corpus digest is
`350bfea4c3da07b3426d885aa8ff645ac55539bbb1294a2ea35dd5319541d6c7`.

The snapshot is exhaustive to the strongest defensible 2026-08-22 cutoff. It
does not claim timeless omniscience. A successor is additive and versioned; do
not mutate a published snapshot in place.

## Reproduction and validation

The compiler performs design compilation only. It does not execute a regex
engine, realize an environment, access Docker, publish evidence, or run a
campaign.

```sh
python tools/semantics/compile_semantic_baseline.py --check
```

The generated products are:

- the semantic snapshot in this directory;
- `ontology/projections/regex-semantic-projection-2026-08-22.v1.json`;
- `vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json`;
- `reports/scale/regex-semantic-denominator-forecast.json`.

Each product is validated by a versioned schema and an additional semantic
verifier that checks identity uniqueness, relation targets, candidate
conservation, twelve-facet completeness, vector attribution, profile-bound
allocation, arithmetic closure, and content digests.
