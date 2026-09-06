# Generated assertion derivation contract

A generated conclusion must disclose why the repository is entitled to make
it. Determinism alone does not turn a constructed value into scientific,
discovery, audit, completeness, or certification evidence.

The canonical machine-readable inventory is
`registries/provenance/generated-assertion-derivations.v1.json`. Its schema is
`schemas/json/generated-assertion-derivation-catalog.schema.json`, and
`schemas/tooling/python/regex_conformance_schema/derivation.py` is the common
compiler and evidence-strength authority. Generators must use this contract;
they must not create local provenance taxonomies with different meanings.

## Derivation classes

| Class | Required basis | What it can establish |
| --- | --- | --- |
| `measurement` | Identified measured inputs and procedure/version | The observed or measured state, within the procedure's scope |
| `calculation` | Explicit input references and a formula or named procedure | Arithmetic closure over already qualified inputs |
| `research-derived` | Source identities, research artifact, and methodology | A reviewed semantic or discovery conclusion within the cited research scope |
| `external-evidence` | An authoritative external source reference | A restatement with no more authority than its source |
| `inference` | Supporting evidence references and the inference rule | A visibly advisory conclusion, not a mechanically entailed measurement |
| `constant-by-construction` | The constructor and exact construction rule | A structural invariant only |
| `manual-decision` | The governing decision reference and its scope | A policy, selection, disposition, or planning constraint |

An empty class label is not provenance. The schema requires the class-specific
metadata above. Semantic validation additionally rejects contradictory class
and metadata values, inappropriate evidence strength, duplicate handles,
dangling references, stale revisions, and bindings whose derivations disagree.

## Bindings and shared records

A stable assigned `assertion-derivation` handle names a derivation method. Its
material method basis has a content-derived
`assertion-derivation-revision` identity. A method revision binds the class,
method key and version, inputs, authority references, allowed gate kinds, and
whether it is independent evidence. Explanatory titles and notes are excluded
from the revision projection, so prose editing cannot churn the identity. A
material method or authority change creates a new revision.

Each inventoried artifact records its exact byte digest, lifecycle, producer,
schema, and assertion bindings. A selector binds a group of assertions to one
shared derivation revision; thousands of uniform rows therefore do not repeat
the same metadata. More-specific selectors override a broad artifact binding,
and equally specific incompatible bindings fail closed.

The current inventory scans assertion-like scalar keys and assertion
containers, plus explicit selectors for domain-specific fields. Every selected
assertion must resolve to exactly one most-specific derivation. Count contracts
separately name the declared field, counted population, input selectors,
calculation rule, and resolution of any legacy ambiguity.

At this revision the inventory covers all 36 tracked generated or governed
assertion surfaces in the semantic snapshot/projection/requirement family,
identity lock, universe and profile registries, adapter qualification
manifests, sustained-qualification policy, campaign plans, scale and
qualification reports, forecasts, and downstream checkpoint index. It binds
508,174 assertion occurrences through 168 shared groups and validates 53 count
contracts. Of those occurrences, 270,682 are marked as having had legacy
evidence-strength or counted-population ambiguity; the large majority are the
uniform generated obligation template.

## Evidence strength and consumers

Consumers request a gate kind rather than treating any truthy field as
evidence. The common validator enforces these boundaries:

- construction constants can satisfy `structural-integrity` only;
- calculations can satisfy arithmetic, forecast, or structural closure, but
  cannot validate their inputs;
- measurements can satisfy empirical or independent-evidence gates within
  their measured scope;
- researched claims can satisfy discovery or semantic-completeness gates only
  with their source and methodology bindings;
- external evidence retains the scope of the cited authority;
- inference can satisfy an advisory-inference gate only; and
- manual decisions can satisfy governance-policy gates only.

Code consuming one assertion should resolve its binding with `find_binding`
and call `require_assertion_gate`. A construction invariant must never be
passed to a gate requiring independent discovery or semantic evidence.

## Corrected false-evidence hazards

The published semantic products remain byte-for-byte immutable, but the
companion inventory now gives their legacy claims their actual strength:

- `major_category_omission_count` and the fixed adversarial-pass conclusions
  are compiler literals, classified `constant-by-construction`;
- “all encountered candidates dispositioned” is emitted unconditionally for
  every source scan and cannot close an independent discovery gate;
- uniform facility-family reconciliation prose is a construction rule, not
  facility-specific evidence;
- category sparsity notes are threshold-based `inference`, so “no suspicious
  sparsity” is not a completeness measurement; and
- the declared facet/case expansion is a structural template invariant. The
  generator proving that it emitted every declared facet does not prove that
  the declared facets are scientifically complete.

The legacy `counts.discovery_scans` value is 130, while the named
`discovery_scans` collection has 49 rows. The value counts three distinct
populations: 49 source scans, 77 facility-family reconciliations, and four
adversarial pass records. The immutable field is retained, while its count
contract names all three populations and marks the legacy name ambiguous.

The six-figure qualification workload also contains overlapping category
views. Count closure therefore uses the disjoint base-template population,
rather than summing overlapping analytical categories.

## Forecasts and policy

Planning profile counts, architecture multipliers, obligation-archetype
bounds, retry rates, reserves, and diagnostic/performance growth allowances
remain unchanged planning assumptions. Forecast totals calculated from them
are `calculation`; measured corpus or compression bases are `measurement`.
The 8,000,000,000-byte soft stop, 10,000,000,000-byte hard ceiling, and
no-paid-capacity rule are `manual-decision` policy, not empirical results.

This separation permits later empirical work to replace an assumption without
rewriting the historical forecast that used it.

## Identity and artifact compatibility

Derivation metadata is a companion authority and does not participate in the
frozen scientific identities inside semantic snapshots, projections,
requirements, vectors, coordinates, observations, manifests, or evidence
blocks. Regenerating the companion catalog may change its own artifact digest
while leaving every referenced scientific entity untouched.

Published semantic products and historical evidence are not rewritten to add
this metadata. Their exact bytes remain independently verifiable under their
original schemas. New or mutable generated products must either carry an
assertion-level derivation or be covered by an artifact binding in the common
catalog.

## Reproduction

Build or check the catalog from the repository root:

```sh
python tools/provenance/compile_generated_assertion_derivations.py
python tools/provenance/compile_generated_assertion_derivations.py --check
```

The compiler validates all inventoried source digests and count contracts,
performs two independent builds when writing, and compares canonical bytes.
Repository validation and semantic compilation both verify the tracked
catalog. Adding an assertion-like field without a derivation binding therefore
fails the source baseline.
