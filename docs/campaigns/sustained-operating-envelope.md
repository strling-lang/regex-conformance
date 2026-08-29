# Sustained operating-envelope qualification

The sustained operating-envelope protocol measures whether the Executioner can
hold stable throughput over a multi-day workload while preserving resource
boundaries, integrity, containment, and exact restart semantics. It is operational
qualification only. It cannot establish regex behavior, semantic authority,
normative authority, canonical evidence, or campaign authorization.

The tracked policy is
[`control-plane/qualification/sustained-operating-envelope.v1.json`](../../control-plane/qualification/sustained-operating-envelope.v1.json).
It requires at least 48 hours of stability windows, including at least 12 hours
after recovery from an explicit interruption. At least 48 stability windows
must be retained. The minimum window throughput may degrade by no more than 20
percent from the deterministic median, and cumulative sampling overhead may
consume no more than one percent of stability time.

The producer takes a five-minute idle baseline, samples at one-minute
intervals, limits each workload invocation to 30 minutes, and emits nominally
hourly stability windows. Environment cache is capped at 10 GB; execution
scratch and result spool are each capped at 6 GB; process-group RAM is capped
at 8 GiB; and persistent disk must retain at least 40 GB free. An observed
processor temperature above 90 degrees Celsius is a boundary failure. Hosts
without portable temperature telemetry retain an explicit `unavailable`
diagnostic and are not assigned an invented temperature.

Every measurement window accounts for CPU utilization, RAM working set,
environment-cache size, execution-scratch size, protected-spool size, and
persistent-disk availability. Those portable measurements are required.
Processor temperature is also required as a field but may be marked
`unavailable` with a bounded diagnostic; it must never be invented as zero.

## Qualified storage and host topology

Sustained Evidence Pack work must read its immutable corpus from native,
persistent Linux storage. Windows-mounted, network, FUSE, overlay, and
temporary filesystems are not qualified input locations. Before a new
qualification identity is created, stage the source tree once and retain the
no-overwrite receipt outside Git:

```sh
python tools/control_plane/stage_sustained_operating_envelope_input.py \
  --source /mnt/c/immutable/million/publication-staging \
  --destination /durable/regex-conformance/inputs/million-staging \
  --receipt /durable/regex-conformance/inputs/million-staging-receipt.json \
  --execute --yes
```

The staging tool rejects a non-native destination, links, special filesystem
nodes, empty trees, identity mismatches, and any destination or receipt that
already exists. It computes the same canonical relative-file digest used by
the workload binding, verifies the copied tree byte-for-byte by identity,
publishes it read-only, and records both source and destination identities.
The producer independently re-hashes the staged tree when it creates or
resumes the workload binding.

The Windows host and Linux guest must also be free of unrelated sustained CPU,
I/O, Docker, indexing, antivirus-scan, or VM work before the baseline begins.
Record the host/guest process snapshot and active Windows power policy with the
external qualification materials. Do not terminate an unrelated workload to
satisfy this preflight without explicit authority. A host that cannot be
isolated is not eligible for the sustained qualification.

## Resumable checkpoint chain

Checkpoint files are external, immutable, canonical JSON named
`checkpoint-NNNNNN.json`. Sequence numbers are contiguous. Each checkpoint
binds the tracked plan digest and the digest of its predecessor. All
checkpoints also retain the immutable workload-binding digest and one
logical-execution ID. The workload binding commits the exact clean Git
revision, command arguments, input-tree identities, machine-inventory digest,
and external measurement paths. A recovery checkpoint alone may
advance the session number and physical-attempt ID, and it must immediately
follow an interruption. A retry therefore adds a physical attempt without
adding a logical completion.

Baseline, steady-load, and post-recovery checkpoints contain bounded
measurement summaries and exact work, duration, and sampler-overhead totals.
Interruption, recovery, and completion checkpoints are explicit events without
measurement windows. Cumulative counters reconcile at every step. Integrity,
containment, resource-boundary, or duplicate-completion failures remain
visible and prevent a passing result.

The checkpoint root, report, local telemetry database, raw diagnostics,
realized environments, and any workload state remain outside Git. The protocol
stores no credentials or provider handles. Checkpoints and reports permanently
declare that they are non-canonical operational qualification artifacts.

## Validation and report compilation

The Linux producer requires explicit mutation acknowledgement and only accepts
external non-link roots. The same command resumes the immutable workload after
an interruption:

```sh
python tools/control_plane/run_sustained_operating_envelope.py \
  --checkpoint-root /durable/regex-conformance/operating-envelope \
  --environment-cache-root /durable/regex-conformance/cache \
  --execution-scratch-root /durable/regex-conformance/scratch \
  --persistent-disk-root / \
  --input-binding million-staging=/durable/regex-conformance/inputs/million-staging \
  --execute --yes -- \
  /qualified/python tools/campaigns/certify_compact_evidence.py \
  --check --million-staging /durable/regex-conformance/inputs/million-staging \
  --pack-output /durable/regex-conformance/cache/evidence-pack-v3
```

The producer commits one controlled interruption midway through the stability
windows and exits with status 75. Re-running the exact command records a new
physical attempt and recovery without adding a second logical completion. A
crash after the terminal checkpoint but before report publication is also
recoverable: the report is regenerated from the immutable chain and is never
overwritten with different bytes.

The report compiler is read-only unless an explicit new external report path
is provided:

```sh
python tools/control_plane/compile_sustained_operating_envelope.py \
  --checkpoint-root /durable/regex-conformance/operating-envelope

python tools/control_plane/compile_sustained_operating_envelope.py \
  --checkpoint-root /durable/regex-conformance/operating-envelope \
  --report /durable/regex-conformance/reports/operating-envelope.json
```

It rejects repository-local operational roots, non-canonical files, gaps,
substitutions, broken predecessor links, implicit retries, missing required
measurements, false zeroes for unavailable telemetry, resource-boundary counter
drift, other cumulative-counter drift, and report overwrites. The report is
rebuilt solely from the ordered checkpoint chain and tracked plan. An
unfinished but internally valid chain reports `in-progress`; only a terminal
chain satisfying every criterion reports `passed`.

Creating the source contract or compiling fixtures does not authorize a
multi-day workload, environment realization, adapter qualification, Docker
container execution, trusted credentials, evidence publication, or promotion.
Those remain separate explicit gates.
