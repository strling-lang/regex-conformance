# Conformance Vectors

Executable probes, vector families, semantic obligations, operation inputs,
observation requests, and provenance references live here. A vector asks a
question; it does not make an engine-independent normative claim.

The small-scale qualification bundle adds typed operations, state, options,
replacements, observation requests, and intrinsic limits. Its category labels
are operational coverage only and grant no normative or C4 feature credit.

`requirements/` contains generated missing-vector ledgers bound to an exact
semantic projection. A future production vector receives semantic credit only
when it names the exact obligation and requirement and binds an admissible,
scope-compatible oracle record or explicitly remains characterization-only.
Expected outcomes use the prospective `oracle-vector-binding.v1` contract;
they cannot be supplied by the vector generator, target observation, consensus,
or a mutable `latest` alias.

## Candidate production families

`families/` contains declarative stimuli tied to the current semantic
requirements. A family selects one exact requirement and operation, an
optional in-scope manifestation, an input exemplar, and bounded expansion axes.
The compiler derives feature, facet, obligation, variant, and interaction
attribution from the frozen semantic inputs. A family can also enumerate all
words in a prefix-free finite alphabet over a specified length interval.

Stimulus fields carry lowercase hexadecimal bytes and an explicit encoding.
This preserves decomposed and precomposed Unicode and allows malformed encoded
code units to be authored without relying on a JSON parser to retain them.
`unicode-scalars` accepts strictly valid UTF-8. `encoded-code-units` retains
whole units at the declared width. It preserves malformed UTF-8 sequences and
unpaired UTF-16 surrogates for native input handling. Use the octet domain
to probe byte-level truncation inside an individual wide unit.

Compile the checked-in families or provide selected definition files. The
output path must be new. `--check` rebuilds and compares a previously emitted
manifest byte for byte.

```sh
python tools/vectors/compile_production_vectors.py \
  vectors/families/*.json --output vector-candidates.json
```

Supply `--verify vector-candidates.json --expected-digest <pinned SHA-256>` with
the same definitions to verify the manifest without running the generator. The
verifier recomputes vector identities and checks family membership, expansion
cardinality, and every requirement row against the current denominator.

The manifest binds each family definition digest, exact content-derived vector
revisions, the two denominator snapshots, and one coverage row per semantic
requirement. Candidate rows await reviewed expectation or characterization
bindings, operation and profile execution recipes, and adequacy evidence before
they can contribute to C4. Uncovered requirements retain `missing` rows.
Requirements whose obligation names an interaction with no assigned scientific
ID remain visible as `interaction-identity-unresolved`. Their rows identify the
exact relations that require an identity allocation before vector attribution.
The [candidate basis](expectations/production-candidate-basis.v1.json) binds
source locators and scoped premises to exact family definition digests. The
[campaign design](../docs/campaigns/first-production-design.md) validates this
binding and the paired interaction controls before selecting candidates.
It also checks that exact split and replacement premises describe one stimulus
with the matching operation and requested observation. The CPython 3.14.6
candidates include line-end controls, captured separators at subject edges,
zero-width splitting, and distinct literal, escaped, and group-expanded
replacement outputs. [Tagged CPython regular-expression documentation](https://raw.githubusercontent.com/python/cpython/v3.14.6/Doc/library/re.rst)

Additional CPython families cover wildcard newline boundaries, text whitespace,
alternation under full matching, and the empty-expression distinction between
empty and nonempty subjects. Their source locators bind the exact CPython
release commit. [CPython 3.14.6 regular-expression documentation](https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/re.rst)

The seven CPython quantifier pairs partition every string over `a` and `b`
through length five into positive and negative full-match candidates. Each
pair holds the repeated literal fixed and varies subject membership and
length. The 441 candidates cover fourteen exact requirements. The upper
bound with omitted lower count follows the parser's default of zero.
[CPython quantifier documentation](https://raw.githubusercontent.com/python/cpython/v3.14.6/Doc/library/re.rst#L109) · [CPython quantifier parser](https://raw.githubusercontent.com/python/cpython/v3.14.6/Lib/re/_parser.py#L614)

The numbered-reference families use `([ab])\1` and the four two-octet words
over `a` and `b`. The subjects distinguish reference equality from merely
consuming another member of the class. The malformed-reference family uses a
single-digit reference to an absent capture, with and without an earlier
capture. The documented spelling and interpretation are specific to the
profile's grammar. [PCRE2 pattern specification, Backreferences](https://www.pcre.org/current/doc/html/pcre2pattern.html)
