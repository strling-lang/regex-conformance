# Release and Profile Registry

Systems, components, releases, profile families, component graphs, concrete
profiles, material facets, and platform policies belong here.

The architectural vertical-slice selection is recorded in
`vertical-slice-archetypes.v1.json` with its human audit in
`vertical-slice-archetypes.md`. It crosswalks every governed design-seed
candidate. `vertical-slice-coordinates.v1.json` assigns the exact stable
releases, component-graph profile families/profiles, systems, components, and
environment recipe bindings for the three selected archetypes. The selection
is execution-eligible only while its canonical source path and the complete
coordinate/recipe cross-record invariants validate.

`small-scale-qualification.v1.json` binds the exact frozen coordinate-file
digest and adds the behaviorally distinct PCRE2 DFA matcher profile. It is an
overlay, not a rewrite of the vertical-slice coordinate universe.
