# Control Plane

Provider-neutral services for machine inspection, resource planning/admission,
environment lifecycle, cache/transfer management, durable recoverable local
state, lifecycle events, CLI/API surfaces, and hard containment live here. The
Control Plane owns operational orchestration only; it does not own canonical
definitions, empirical evidence, certification truth, or Notion development
status.

The initial implementation is a Python 3.12 standard-library-first service layer
under `python/`, governed by D101. Its controller facade is client-neutral;
machine discovery, diagnostics, models, rendering, and CLI parsing are separate
and independently testable. Versioned JSON is the interoperability boundary, so
future daemon, TUI, CI, dashboard, provider, or alternative-language clients do
not depend on Python object layouts.

## Machine doctor

The first safe operation is read-only machine inspection:

```sh
python control-plane/python/run.py doctor --trust-class development
python control-plane/python/run.py machine inspect --format json --trust-class development
```

The report identifies OS and architecture, explicitly configured trust class,
provider availability, process capabilities, and distinct persistent, cache,
build-scratch, execution-scratch, protected-spool, RAM, swap, and CPU pools.
Every measurement carries source, accuracy, visibility, observation time, and
staleness. Unknown telemetry remains `null`; it is never coerced to zero or
available capacity. Configured pool paths are inspected through their nearest
existing ancestor and are never created by the doctor.

Executable discovery reports `detected_unverified`, not `available`; provider
identity, health, and limits are verified by the separate environment-manager
lifecycle. When logical pools share a physical backing store, the doctor reports
that relationship and explicitly warns that the capacities are not additive.

Trust is never inferred from hardware or installed providers. Set it through
`--trust-class` or `STRLING_REGEX_TRUST_CLASS`. Pool paths may be supplied with
`--pool-path KIND=PATH` or the `STRLING_REGEX_*_PATH` environment variables.
All doctor output declares `inventory_only: true` and
`mutation_permitted: false`.

Run its cross-platform fixtures, boundary tests, and real-host smoke test with:

```sh
python -m unittest discover -s tests/control_plane -v
```

Local Control Plane state remains operational and non-canonical. This task does
not yet implement environment acquisition, admission, cache mutation, durable
state, events, or workload containment; those enter through their separately
gated P16A contracts.
