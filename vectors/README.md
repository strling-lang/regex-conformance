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
`unicode-scalars` accepts strictly valid UTF-8. `encoded-code-units` retains the
declared encoding and exact bytes for native input handling.

Compile the checked-in families or provide selected definition files. The
output path must be new. `--check` rebuilds and compares a previously emitted
manifest byte for byte.

```sh
python tools/vectors/compile_production_vectors.py \
  vectors/families/line-start-positive.v1.json \
  vectors/families/line-start-negative.v1.json \
  vectors/families/numeric-escape-diagnostics.v1.json \
  --output vector-candidates.json
```

The manifest binds each family definition digest, exact content-derived vector
revisions, the two denominator snapshots, and one coverage row per semantic
requirement. Candidate rows await reviewed expectation or characterization
bindings, operation and profile execution recipes, and adequacy evidence before
they can contribute to C4. Uncovered requirements retain `missing` rows.
