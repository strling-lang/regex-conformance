# P17 Vertical-Slice Archetype Selection

This selection is a crosswalk from the governed Notion seed registry
`P04-SEED-DESIGN-2026-08-11-r1`. It tests architecture diversity; it is not a
claim that the easiest installed runtimes were chosen. The machine-readable
record is `vertical-slice-archetypes.v1.json` and repository validation rejects
unaccounted seed candidates, pending targets, missing coverage, or a false
execution-eligibility claim.

## Selected root surfaces

| Selection | Governed registry subject | Root surface and graph | Required environment shape | Architecture purpose |
| --- | --- | --- | --- | --- |
| `pcre2-ordinary` | `seed:p04:pcre2` (`in-scope`) | Standalone PCRE2 ordinary library API with explicit engine, matcher, dialect, text, and platform nodes | Reproducible native source build | Exercise a standalone C/library boundary, code-unit-native indexing, source provenance, and the ordinary matcher path. |
| `python-re` | `seed:p04:python-re` (`in-scope`) | Python standard-library `re` host surface with runtime, Unicode/text, replacement, and result/error ownership | Verified native language runtime | Exercise host-owned API semantics, runtime-bound Unicode, string-versus-bytes inputs, and host result/error transformation. |
| `mysql-regex` | `seed:p04:mysql-regex` (`in-scope`) | MySQL SQL regex functions/operators with database host transformations and an exact embedded-backend node | Reproducible OCI service | Exercise a stateful database/process boundary, SQL serialization, collation/text transformation, service readiness, and embedded-engine non-inheritance. |

Together these subjects cover the required standalone, host/runtime, and
embedded/API-distinct shapes. Their source-build, native-runtime, and OCI
service strategies also force materially different acquisition, verification,
startup, containment, and cleanup paths through the same Control Plane.

## Registry accounting and deferrals

All 19 seed candidates remain accounted for: three selected root targets and 16
explicit deferrals. ICU remains in scope and must be bound as the exact backend
node of the selected MySQL profile, but it is not a fourth root surface because
that would add another library shape instead of a new integration boundary.
The three standards remain normative-only authorities. The other 12 candidates
remain pending investigation and cannot be promoted into executable targets by
this selection task.

PCRE2 DFA is also not selected as an additional root family in the minimal
slice. Its result/capture semantics remain a required later expansion; the
ordinary and DFA families must never be collapsed merely because they share a
release.

## T02 hard handoff

This record deliberately allocates no candidate, system, component, release,
profile-family, profile, recipe, or environment IDs and remains
`execution_eligible=false`. P17-T02 must, for every selected surface:

1. verify an exact stable public release from qualified primary provenance;
2. materialize the complete required component graph and every material facet;
3. create a pinned environment recipe without embedding realized-instance
   identity;
4. acquire and verify the environment through the certified Control Plane; and
5. retain the realized fingerprint and verification evidence outside Git while
   committing only legitimate compact definitions.

No later task may replace a selected root target merely because acquisition is
inconvenient. A genuine provenance, licensing, or reproducibility failure must
remain explicit and follow program governance.
