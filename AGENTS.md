# Agent navigation

## Repository ownership

This repository owns empirical regex execution, operational profiles and
vectors, observations, evidence qualification, compatibility analysis, and
certification. It does not create normative regex knowledge or product-language
semantics. `research-intelligence` owns research synthesis;
`strling` owns language contracts and compiler implementation; `website` owns
public presentation; `.github` owns organization defaults.

## Repository identifier hygiene

Planning identifiers belong only in the external program tracker. Do not add
phase, task, gate, milestone, decision, risk, or similar tracker codes to
repository documentation, source comments or docstrings, configuration
comments, generated public documentation, or user-facing examples. Use durable
descriptive terminology instead. Do not rewrite immutable evidence,
identity-bound generated artifacts, or third-party material merely to remove a
historical tracker identifier.

## Authority and entrypoints

- Start with [README.md](README.md), [GOVERNANCE.md](GOVERNANCE.md), and
  [SECURITY.md](SECURITY.md).
- Use [docs/architecture/README.md](docs/architecture/README.md) and
  [docs/architecture/repository-layout.md](docs/architecture/repository-layout.md)
  for system boundaries.
- Use [docs/architecture/generated-artifacts.md](docs/architecture/generated-artifacts.md)
  for canonical, generated, and external artifact relationships.
- Read the nearest nested `AGENTS.md` before changing schemas, campaigns,
  Control Plane, or verifier code.

Empirical observations describe an exact runtime/profile under exact
conditions; they are not normative guarantees. Infrastructure failure is not
target behavior. Logical executions remain distinct from retryable physical
attempts, and retries never add another logical completion.

## Evidence and execution safety

Raw evidence, physical attempts, operational state, realized environments,
immutable logical segments, large diagnostics, and warehouse data belong
outside Git. Only architecture-assigned compact definitions, manifests,
reports, references, schemas, and hashes may be tracked. Published evidence and
correction history are immutable and additive: invalidate, supersede, or
replace with traceability; never rewrite an observation.

Campaign execution, environment realization, adapter qualification, Docker
access, trusted credentials, and scale/certification runs require explicit
authorization. Design compilation or unit validation does not authorize
execution. Never select the 100K runner automatically.

## Validation and Git

Use the smallest relevant level:

```text
focused test
→ affected suite or campaign-design validation
→ repository source baseline
→ environment or adapter qualification
→ vertical execution
→ scale or certification campaign
```

The source baseline is schema/fixture validation plus the affected suites under
`tests/schema`, `tests/adapters`, `tests/campaign`, `tests/control_plane`, and
`tests/ci`. Higher levels require their documented external roots and explicit
authorization.

Inspect branch, status, staged changes, and recent history before editing.
Program work uses a `codex/**` branch and a coherent verified commit. Promotion
through `tools/ci/promote_verified.py` is a separate authorized operation;
never promote, push, merge, reset, clean, or rewrite history automatically.

Copilot file scopes live in [.github/instructions](.github/instructions) and
reusable prompts in [.github/prompts](.github/prompts).
