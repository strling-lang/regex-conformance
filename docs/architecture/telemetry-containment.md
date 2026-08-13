# Telemetry Calibration and Hard Containment

Operational telemetry improves resource forecasts but never changes regex
semantics, profile identity, normative expectations, or empirical
observations. It lives in a separate local SQLite store, uses append-only
sample identities, rejects credentials, and is explicitly non-canonical.
Derived calibration snapshots are reproducible from their ordered source
sample IDs and policy digest inputs.

A calibration requires at least three complete samples for the same operation,
calibration key, metric, typed pool, and unit. By default, its expected value is
the nearest-rank median. Its upper bound is the nearest-rank 95th percentile
plus 25 percent headroom. Partial or mismatched samples remain preserved but
cannot influence a recommendation. The planner retains the original forecast
until a snapshot is eligible, then records a measured estimate whose source
binds the calibration digest. Admission margins still apply afterward.

Prediction is never containment. `ContainedProcessSupervisor` establishes a
new process tree, launches commands without a shell, and independently enforces
wall-clock, stdout, stderr, and concurrency limits. Native POSIX execution also
supports address-space and CPU-time limits. A requested limit that the current
provider cannot enforce is rejected before launch. OCI limit compilation binds
memory and process-tree controls to explicit launch arguments while retaining
supervisor-owned wall and output limits.

The native supervisor currently certifies POSIX process groups and resource
limits. It refuses Windows execution before launch until a Job Object adapter
can provide equivalent no-race process-tree ownership; best-effort `taskkill`
fallbacks are intentionally not treated as containment. The OCI adapter
compiles provider arguments but is not executable through the native
supervisor.

Limit-triggered, non-zero, failed-launch, and partial runs are operational
outcomes rather than regex observations. Raw captured output is bounded and is
excluded from serialized containment metadata; only counts and SHA-256 digests
cross that interface. The controller or adapter layer may later classify a
completed target result, but containment itself has no scientific authority.

The local store is a calibration aid, not an evidence source. Deleting it loses
adaptive history but cannot delete or rewrite published evidence. Rebuilding
it from retained operational measurements must reproduce the same snapshot.
