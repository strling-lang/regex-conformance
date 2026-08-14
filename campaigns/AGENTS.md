# Campaign agent guidance

`campaigns/` owns campaign definitions, compilers, compact manifests, frozen
references, and campaign policy. Read [README.md](README.md), the applicable
document under `../docs/campaigns/`, and
[../docs/architecture/generated-artifacts.md](../docs/architecture/generated-artifacts.md).

The flow is:

```text
definition/profile/vector/applicability/schema
→ deterministic compiler
→ compact tracked plan/report
→ external immutable logical segments
→ authorized physical attempts and observations
```

Compiling and validating a design is not execution authorization. Keep raw
result shards, diagnostics, spools, state, evidence, and warehouses outside
Git. Preserve logical-execution identity across retries. Start with the focused
compiler/design test; do not realize environments, use Docker, execute a
vertical slice, or run the 100K campaign without explicit authorization.
