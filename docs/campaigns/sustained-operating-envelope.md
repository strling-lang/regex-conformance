# Sustained operating-envelope qualification

The sustained operating-envelope protocol measures whether the Executioner can
hold stable throughput over a multi-day workload while preserving resource
floors, integrity, containment, and exact restart semantics. It is operational
qualification only. It cannot establish regex behavior, semantic authority,
normative authority, canonical evidence, or campaign authorization.

The tracked policy is
[`control-plane/qualification/sustained-operating-envelope.v1.json`](../../control-plane/qualification/sustained-operating-envelope.v1.json).
It requires at least 48 hours of stability windows, including at least 12 hours
after recovery from an explicit interruption. At least 48 stability windows
must be retained. The minimum window throughput may degrade by no more than 20
percent from the deterministic median, and cumulative sampling overhead may
consume no more than one percent of stability time.

Every measurement window accounts for CPU utilization, RAM working set,
environment-cache size, execution-scratch size, protected-spool size, and
persistent-disk availability. Those portable measurements are required.
Processor temperature is also required as a field but may be marked
`unavailable` with a bounded diagnostic; it must never be invented as zero.

## Resumable checkpoint chain

Checkpoint files are external, immutable, canonical JSON named
`checkpoint-NNNNNN.json`. Sequence numbers are contiguous. Each checkpoint
binds the tracked plan digest and the digest of its predecessor. All
checkpoints retain one logical-execution ID. A recovery checkpoint alone may
advance the session number and physical-attempt ID, and it must immediately
follow an interruption. A retry therefore adds a physical attempt without
adding a logical completion.

Baseline, steady-load, and post-recovery checkpoints contain bounded
measurement summaries and exact work, duration, and sampler-overhead totals.
Interruption, recovery, and completion checkpoints are explicit events without
measurement windows. Cumulative counters reconcile at every step. Integrity,
containment, protected-resource-floor, or duplicate-completion failures remain
visible and prevent a passing result.

The checkpoint root, report, local telemetry database, raw diagnostics,
realized environments, and any workload state remain outside Git. The protocol
stores no credentials or provider handles. Checkpoints and reports permanently
declare that they are non-canonical operational qualification artifacts.

## Validation and report compilation

The compiler is read-only unless an explicit new external report path is
provided:

```sh
python tools/control_plane/compile_sustained_operating_envelope.py \
  --checkpoint-root /durable/regex-conformance/operating-envelope

python tools/control_plane/compile_sustained_operating_envelope.py \
  --checkpoint-root /durable/regex-conformance/operating-envelope \
  --report /durable/regex-conformance/reports/operating-envelope.json
```

It rejects repository-local operational roots, non-canonical files, gaps,
substitutions, broken predecessor links, implicit retries, missing required
measurements, false zeroes for unavailable telemetry, counter drift, and report
overwrites. The report is rebuilt solely from the ordered checkpoint chain and
tracked plan. An unfinished but internally valid chain reports `in-progress`;
only a terminal chain satisfying every criterion reports `passed`.

Creating the source contract or compiling fixtures does not authorize a
multi-day workload, environment realization, adapter qualification, Docker
container execution, trusted credentials, evidence publication, or promotion.
Those remain separate explicit gates.
