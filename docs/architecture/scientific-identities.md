# Scientific identity and migration contract

This is the permanent repository contract for scientific identity. It extends
the existing typed `rcid` architecture; it does not introduce UUIDs as an
untyped key space, replace content-derived identities, or make readable names
canonical. Every identifier is validated against a registered namespace and
mode.

The current declared-cutoff semantic products predate this separation. Their
readable keys remain valid compatibility references under their original
schemas. The additive catalog at
`registries/identity/scientific-identities.v1.json` binds every current
scientific semantic entity to a permanent assigned `rcid`. Future schema
revisions and generated products must serialize those scientific IDs and may
carry the readable keys only as labels or compatibility keys.

## Three identity roles

**Scientific identity** names the entity that scientific claims are about. An
assigned `rcid:v1:<namespace>:u7:<uuid>` survives wording improvements,
category and file moves, display-name and slug changes, and taxonomy
refinements that do not change the entity's meaning. The UUIDv7 payload is
allocated once through the typed namespace registry and persisted in the
catalog. It is never regenerated from a label.

**Semantic or content identity** names exact immutable content. It uses
`rcid:v1:<namespace>:h:jcs-sha256-v1:<digest>`, a registered identity profile,
an assigned schema-family ID, NFC-aware typed projection, RFC 8785 JSON
canonicalization, UTF-8, and SHA-256. A meaning-bearing field change creates a
different revision or artifact identity.

**Human-readable keys and labels** include slugs, names, categories,
descriptions, file paths, selection keys, and presentation ordering. They are
mutable metadata. A former key remains resolvable through the catalog, but a
key is never accepted where a scientific `rcid` is required.

An entity whose meaning changes materially receives a new scientific ID or a
new content revision as specified below. Historical IDs remain permanently
reserved and resolvable.

## Identity-class inventory

The mechanism column is canonical. An assigned entity may additionally have a
content-derived revision. A qualified external identity stays under its
publisher's authority and is not recast as a repository ID.

| Class | Canonical mechanism and namespace | Readable metadata | Immutable evidence / downstream use |
| --- | --- | --- | --- |
| System | assigned `system`; content revision `system-revision` | system key, display name | profiles, universe snapshots, environments |
| Component | assigned `component`; content revision `component-revision` | component key, kind | component-graph profiles and releases |
| Release | assigned `release`; content revision `release-revision`; qualified upstream identity retained | version, channel, release name | profiles, recipes, logical executions |
| Profile family | assigned `profile-family`; content revision `profile-family-revision` | selection key, family name | profile registry and universe accounting |
| Profile | assigned `profile`; content revision `profile-revision` over the component graph | selection key, display description | applicability, campaign coordinates, evidence |
| Feature | assigned `feature` in the scientific catalog | `feature.*` key, name, category | future semantic projections, claims, checkpoints |
| Manifestation | assigned `manifestation` in the scientific catalog | `manifestation.*` key, syntax/API display | semantic projections and vector derivation |
| Semantic variant | assigned `semantic-variant` in the scientific catalog | `variant.*` key and name | semantic projections and differential claims |
| Alias | no independent scientific ID; `alias-of` lineage targets one scientific ID | alias spelling and label history | compatibility lookup only |
| Modifier | assigned `modifier` in the scientific catalog | `modifier.*` key and name | semantic and vector definitions |
| Operation | assigned `operation` in the scientific catalog | `operation.*` key and name | requirements, coordinates, observations |
| Typed interaction / relation | assigned `semantic-interaction` in the scientific catalog | `interaction.*` key and relation label | requirements and vector attribution |
| Semantic requirement | assigned `semantic-requirement` in the scientific catalog | legacy `vector-requirement.*` key | vector derivation and claim completeness |
| Obligation | assigned `obligation` in the scientific catalog | legacy `obligation.*` key, facet and case labels | vectors, coordinates, evidence attribution |
| Vector definition | assigned `vector` handle plus content-derived `vector-revision` | vector key, display name, authoring location | campaigns and longitudinal comparisons |
| Generated vector instance | the same `vector-revision` content contract; generator provenance is derivation metadata, not another identity | generator name/version and expansion ordinal | logical coordinates and evidence |
| Applicability coordinate | content-derived `applicability-coordinate` | display order and file placement | applicability ledger and claim denominator |
| Logical execution | content-derived `logical-execution` | trace reference and scheduling label | immutable plans, attempts, observations |
| Physical attempt | assigned `physical-run` plus attempt number and reset provenance | worker/process labels | append-only attempt evidence |
| Observation | assigned `observation` with content-derived `observation-content` | display summaries | evidence manifests, adjudication, claims |
| Environment recipe / realization | assigned `environment-recipe` plus content-derived `environment-recipe-revision`; assigned `environment-realization` plus content-derived `environment-fingerprint` | provider and recipe labels | execution provenance and reproducibility |
| Adapter release | assigned `adapter-release` plus content-derived `adapter-release-manifest` | adapter name/version | logical execution and observation provenance |
| Campaign | assigned `campaign` and `campaign-definition`; content revisions and manifest are content-derived | campaign name and working paths | execution denominator and evidence root |
| Partition | content-derived artifact/shard identity; external ordinal is layout metadata | partition ordinal and location | scale plans and publication receipts |
| Execution shard | content-derived `shard` over exact members and locality contract | shard ordinal and worker label | scheduling, recovery, result segments |
| Coverage Shard | content-derived `shard` checkpoint commitment; sequence is append-only ordering, not identity | publication sequence and projection filenames | downstream synchronization |
| Evidence object / block | raw and stored SHA-256 content addresses | object key and block ordinal | Evidence Pack lookup and corruption proof |
| Evidence manifest | content-derived `evidence-manifest` or exact manifest digest under its versioned pack contract | publication location | evidence admission and downstream checkpoints |
| Downstream checkpoint | content-derived checkpoint digest and `shard` identity | sequence and relative paths | monotonic downstream index |
| Certification contract / input / report | content-derived `certification-definition`, `certification-input-set`, and `certification-report`; issued certification and authority actions use assigned `certification` and `certification-action` | contract title, report display, authority-index ordering | exact predicate version, source set, evaluation, supersession, and revocation |
| Claim, divergence, waiver | not yet implemented; must use assigned scientific IDs with explicit content revisions and lineage when introduced | titles, issue labels, reviewer prose | adjudication and certification; never infer IDs from labels |
| Schema family / revision | assigned `schema-family`; content-derived `schema-revision` | schema filename and version string | every content constructor and compatibility edge |
| Operational local state | `opid` in the registered local namespace | process, cache, transfer, telemetry labels | never scientific or evidence authority |

Namespace validation and collision protection are implemented by
`NamespaceRegistry`, registered identity profiles, and `CollisionGuard`.
Semantic binding, reuse, fingerprint, and lineage validation are implemented
by `scientific_identity.py`. Schemas remain structural authority; the semantic
validators add namespace, graph, content, and cross-artifact invariants.

## Accepted foundation baseline and additive successor

The first catalog generation binds the existing corpus without changing its
ontology:

| Class | Bound entities |
| --- | ---: |
| Feature | 251 |
| Semantic variant | 88 |
| Modifier | 32 |
| Operation | 22 |
| Manifestation | 304 |
| Typed interaction | 108 |
| Obligation | 12,048 |
| Semantic requirement | 9,506 |
| **Total** | **22,359** |

The expanded researched semantic architecture preserves every baseline binding
and adds 68 typed identities: 15 semantic facets, 11 operations, 17 features,
5 semantic variants, and 20 manifestations. The current lock therefore
contains 22,427 identities. The table above remains the accepted foundation
baseline; additive versioned evolution does not rewrite it.

Each binding records its current key, former keys, status, source role, and an
append-only semantic-fingerprint history. The fingerprint excludes display
name, category, aliases, source-file location, documentation provenance, and
presentation order. It includes meaning-bearing semantic contracts and replaces
cross-entity readable references with the target scientific IDs. Obligation
fingerprints include the feature, semantic facet/case, classification,
operation IDs, normalized applicability predicate, expected observation
contract, and credit rule. Requirement fingerprints include the feature,
obligation, role/facet, operation IDs, and attribution contract; vector coverage
status is excluded.

The catalog is both migration map and persistent identity lock. Verification
fails on an unbound current entity, duplicate owner, reused ID, wrong namespace,
retired-ID reuse, unexplained fingerprint change, missing lineage target,
lineage cycle, count mismatch, source-artifact mismatch, or catalog-digest
mismatch. New bindings may be appended deliberately; verification never
allocates an ID.

## Change and lineage rules

The catalog's machine-readable lineage records support `renamed-from`,
`corrected-without-semantic-change`, `supersedes`, `superseded-by`,
`split-from`, `merged-from`, `deprecated`, and `alias-of`.

- A spelling, wording, category, documentation, file, or equivalent-predicate
  correction retains the scientific ID. A changed semantic fingerprint needs
  a reviewed retained-identity record that binds the prior and current
  fingerprints. A rename also moves the old key to `former_keys`.
- A material meaning change creates a successor ID. The predecessor stays in
  the catalog with a historical disposition and an explicit supersession edge.
- A split retains the predecessor as historical, assigns a distinct ID to each
  successor, and records one predecessor to multiple successors.
- A merge retains every predecessor as historical, assigns a new ID to the
  merged entity, and records multiple predecessors to one successor. No
  predecessor is arbitrarily reused as the merged identity.
- Deprecation changes status, not identity. Removal from the current corpus
  requires a resolvable historical disposition such as superseded, merged,
  erroneous historical classification, out of scope, or unresolved.
- An alias is a readable lookup for one scientific identity. It cannot encode
  semantic replacement, participate as a second canonical owner, or acquire
  evidence independently.

No retired scientific ID may be reused, even if its former label becomes
available. No published artifact is deleted or rewritten to apply a newer
identity contract.

## Content-derived vector identity

The production constructor is the identity profile
`production-vector-revision.v1.json`, schema-family ID
`rcid:v1:schema-family:u7:01a0779c-5485-7240-b0ee-4846554fd816`.
Its `vector-revision` identity includes exactly:

- domain and typed pattern;
- the ordered subject sequence;
- replacement and callback fixture, including explicit `null` absence;
- scientific operation ID and initial state;
- options as an unordered set of typed values;
- requested observations as a set;
- semantic requirement, obligation, and interaction IDs as sets;
- applicability preconditions; and
- deterministic intrinsic limits.

It excludes vector handle, key, display name, description, author, file path,
generator name/version, expansion ordinal, and cosmetic ordering. Generated and
authored vectors with identical canonical scientific content therefore share a
revision identity; a semantic content change produces a different identity.

The canonical projection hashes each typed nested member under a fixed inner
domain before applying the registered identity profile. Nested members
normalize text and member names to Unicode NFC, reject lone surrogates and
binary floating-point numbers, retain explicit `null`, retain array order, and
require interoperable integers. Unordered option members and profile `set`
members are deduplicated and sorted by canonical RFC 8785 bytes. The outer
envelope contains those sub-content digests and is itself UTF-8 RFC 8785 JSON
and SHA-256 under `jcs-sha256-v1`.

Existing qualification and probe assets remain verifiable under their original
vector-revision schema family. They are historical operational inputs, not
production semantic vectors, and are not rewritten by this contract.

## Content-derived applicability coordinates

The production constructor is
`applicability-coordinate.v1.json`, schema-family ID
`rcid:v1:schema-family:u7:01a0779c-55e6-7dff-ac38-09757c679707`.
Its identity includes exactly the profile revision, target release revision,
vector revision, semantic requirement set, obligation set, operation,
applicability rule-set revision, and all meaning-bearing applicability inputs.
Sets use canonical set ordering. An operation or applicability-semantic change
therefore creates a different coordinate; display ordering, projection path,
generator version, and unrelated added entities do not.

An execution plan then derives `logical-execution` identity from the admitted
coordinate plus the exact adapter, environment, protocol, policy, and request
semantics required by that execution contract. Retries retain the logical ID
and add physical attempts.

## Generated artifacts and historical compatibility

A generator must resolve every entity through the scientific catalog. A
generator upgrade, ordering change, file move, or unrelated entity addition may
change an enclosing artifact digest, but cannot allocate or change an existing
internal entity ID. Missing bindings and unexplained fingerprint changes fail
closed. This separation is checked by the semantic compiler and repository
validation.

The frozen semantic snapshot, executable projection, requirement ledger,
qualification assets, completed campaign artifacts, and historical evidence
retain their original bytes and schema contracts. Their readable semantic keys
resolve through the catalog. Successor artifact schemas must serialize the
scientific IDs directly while optionally retaining those keys as labels.

Allocate missing bindings only during an explicitly reviewed identity change:

```sh
python tools/identity/freeze_scientific_identities.py --initialize --effective-date YYYY-MM-DD
```

Ordinary validation is read-only:

```sh
python tools/identity/freeze_scientific_identities.py --check
python tools/semantics/compile_semantic_baseline.py --check
```

The first command never rewrites an existing fingerprint. A semantic change
must be adjudicated into retained-identity history or successor lineage before
the check can pass.
