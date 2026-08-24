# Downstream projections and checkpoints

This tree contains compact, deterministic Git artifacts emitted only after a
coherent Coverage Shard has passed evidence reconciliation, capacity admission,
and certification. It does not contain primary evidence, execution spools,
physical-attempt records, warehouse data, or website-owned presentation.

A Coverage Shard is a scientific profile/release increment and may contain many
low-level execution shards. Execution shards are scheduler/storage units and are
never downstream synchronization signals. The only synchronization signal is a
sealed `coverage-shard-NNNN.v1.json` checkpoint committed with its referenced Lab
and Compatibility projections and the updated monotonic index.

The two downstream consumers advance independently from the checkpoint index.
Conformance neither inspects nor waits for their workflow state.

- `checkpoints/` owns the append-only checkpoint chain and index.
- `lab/` owns generated profile/runtime selector and eligibility projections.
- `compatibility/` owns generated evidence-backed compatibility projections.

All three artifact families are derived. Compatibility truth is never authored
by hand, and these Git projections never replace immutable Evidence Pack v3
authority.
