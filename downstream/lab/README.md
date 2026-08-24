# Lab projections

Each certified Coverage Shard produces one
`coverage-shard-NNNN.v1.json` Lab projection. It contains the exact profile and
release selector hierarchy, supported operation/options surface, immutable
environment and adapter source bindings, and explicit eligibility or
ineligibility for every profile in the shard.

Lab projections are deterministic derived data. They are committed together
with the matching checkpoint and are never edited to reflect downstream UI or
workflow state.
