# Small-Scale Qualification Slice

The small-scale qualification slice expands the frozen architectural vertical
slice without
rewriting its inputs or evidence. It adds one behaviorally distinct profile,
`pcre2-dfa`, and twelve richer operational probe vectors covering success,
rejection, captures, Unicode, replacement, errors, timeouts, iteration, and a
matcher-profile differential.

## Scientific boundary

This is an operational qualification surface. Its vectors ask executable
questions but provide no normative expectation, Knowledge Program feature
credit, C4 semantic-obligation credit, or conformance verdict. The timeout
vector is a planned bounded execution coordinate; deliberate fault and timeout
qualification owns empirical
timeout and deliberate-fault classification. Infrastructure failures must
remain distinct from target observations.

The vertical-slice coordinate registry, recipes, manifests, compiled campaign, reports,
and evidence remain byte-stable. The qualification layer binds their exact
coordinate-file digest and adds its own overlay, recipe directory, adapter
manifest directory, campaign definition, and coverage report.

## Profile materiality

`pcre2-dfa` is a separate component-graph profile because it selects PCRE2's
public `pcre2_dfa_match_8` API and exposes leftmost-longest alternatives rather
than the ordinary backtracking matcher's single alternative. The thin adapter
preserves native octet spans, returns only group zero, explicitly records that
subgroups are not exposed, and rejects unsupported operations instead of
fabricating ordinary-matcher behavior.

The recipe pins PCRE2 10.47 source bytes and verifies that the realized shared
library exports `pcre2_dfa_match_8`. The adapter manifest pins both the engine
version and matcher API, source files, aggregate source digest, protocol
revision, target release, and profile.

## Deterministic denominator

The compiler evaluates four profiles against twelve vectors, producing 48
candidate coordinates. Explicit applicability yields 26 included logical
executions and 22 preserved exclusions, with zero invalid or unresolved
coordinates. Included work is partitioned into five bounded
selection-locality shards. The generated coverage report requires all nine
qualification categories to have at least one included coordinate.

Every compiled request contains the complete typed pattern, subjects,
replacement or callback fixture, operation, state, options, requested
observations, environment dimensions, and intrinsic limits. Logical identities
bind the exact request semantics, adapter manifest, profile, target release,
environment recipe revision, applicability policy, protocol revision, and
vector revision.

## Reproduce

From the repository root:

```sh
.venv/bin/python tools/campaigns/compile_small_scale.py
PYTHONPATH=campaigns/python:matrix/python:scheduler/python:schemas/tooling/python \
  .venv/bin/python -m unittest discover -s tests/campaign \
  -p 'test_small_scale_qualification.py' -v
```

The compiler writes canonical bytes atomically, performs a read-after-write
check, then recompiles independently and rejects any source, request,
candidate-proof, denominator, or shard substitution. Repository validation
also checks the overlay's frozen-base digest, exact profile/release/recipe
bindings, assigned-ID collisions, recipe revision, manifest content identity,
source hashes, and complete file accounting.
