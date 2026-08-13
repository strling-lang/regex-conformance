# 100K qualification campaign design

The P19 campaign is an operational scale qualification, not a semantic or
normative expansion. It deterministically expands every one of the 26 eligible
P18 logical templates into a balanced set of planned repetitions. A planned
repetition is a distinct logical execution with its own content identity;
retries of that logical execution remain separate append-only physical
attempts.

The resulting denominator is exactly 100,000 logical executions. The first
four base logical IDs in code-point order receive 3,847 repetitions and the
other 22 receive 3,846. This difference of at most one prevents workload
selection from silently favoring a familiar engine, profile, vector, or result
class. All four representative profile coordinates, all twelve vectors, and
all nine P18 operational categories receive nonzero work.

## Compact manifest and external segments

Git retains the frozen definition, deterministic compiler, schemas, compact
campaign manifest, every shard/segment content reference, the ordered-logical
ID commitment, and the design report. It does not retain the expanded 100,000
records.

The compiler partitions by selection locality and logical ID under a maximum
of 250 executions per shard. Each shard's ordered logical records are encoded
as canonical JSON in an immutable content-addressed segment outside Git. The
compact manifest records the exact path, byte count, SHA-256, shard identity,
selection, first and last logical ID, member count, and ordered-member digest
for every segment. An independent process can reconstruct every exact adapter
request from the frozen P18 request template, planned repetition, campaign
identity, and segment record.

This representation preserves the controlling storage and identity contracts:

- the full ordered logical set is explicit in referenced immutable segments;
- Git remains limited to lightweight definitions, hashes, indexes, and compact
  reports;
- logical execution identity never depends on worker assignment or retry;
- sharding optimizes locality but does not alter the logical set;
- infrastructure failures cannot become regex observations;
- the campaign remains probe-only, operational, and non-authoritative.

## Stress rationale

The frozen plan creates 402 bounded shards across MySQL regex, PCRE2 DFA,
PCRE2 ordinary, and Python `re`. This is large enough to exercise sustained
scheduling, environment locality, spool publication, warehouse ingestion, and
hash reconciliation while keeping retry exposure bounded.

Three planned interruptions occur only after durable shard commits: controller
restart after shard 100, worker-process kill after shard 201, and a second
controller restart after shard 300. P19-T02 must preserve every interrupted
attempt, use new physical-run identities where retry policy requires them, and
still reconcile exactly 100,000 logical completions.

## Reproduce

Compile only the compact Git artifacts:

```sh
.venv/bin/python tools/campaigns/compile_100k_qualification.py
```

Materialize and verify all immutable logical-execution segments outside Git:

```sh
.venv/bin/python tools/campaigns/compile_100k_qualification.py \
  --segment-root /tmp/strling-regex-100k-plan
```

Run the design qualification:

```sh
.venv/bin/python -m unittest discover -s tests/campaign \
  -p 'test_100k_qualification_design.py' -v
```

Re-running compilation must reproduce the compact plan, design report, and all
402 segment objects byte-for-byte. Missing, truncated, substituted,
noncanonical, linked, in-repository, or unmanifested segments fail closed.
