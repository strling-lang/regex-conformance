# Campaigns

Campaign definitions, frozen input references, compact manifests, and campaign
policy live here. Raw result shards, diagnostics, and worker spools remain in
immutable evidence or operational storage.

`small-scale-qualification.v1.json` expands the frozen P17 campaign through a
digest-bound overlay. Its 48 candidates reconcile to 26 included logical
executions and 22 explicit exclusions. See the [qualification design and
reproduction procedure](../docs/campaigns/small-scale-qualification.md).
nThe deliberate-fault qualification surface classifies target timeout and crash separately from adapter, worker, network, and storage failures. The deliberate-faults documentation defines the closed reference cases and reproduction procedure.
