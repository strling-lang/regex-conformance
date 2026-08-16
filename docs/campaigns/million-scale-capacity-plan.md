# Million-scale capacity and cost plan

> This initial million-scale plan records the planning basis before the
> factorized-evidence and governed-canary policy. Its repetitive raw
> object layout and unconditional platform multiplication are superseded by the
> production [Evidence Pack v2](evidence-pack-v2.md) certification. The accepted
> policy preserves
> full historical semantics, adopts governed canaries with targeted semantic
> expansion, and retains the same 8 GB soft stop and 10 GB hard cap.

This is a technical planning artifact for a possible 1,000,000-logical-
execution campaign. It does not authorize the campaign, execute a target, use
Docker, establish credentials, publish to Cloudflare R2, or mutate external
evidence. The compact machine plan is
[`reports/scale/million-scale-capacity-plan.json`](../../reports/scale/million-scale-capacity-plan.json),
and the operator boundary is
[`cloudflare-r2-operator-handoff.md`](cloudflare-r2-operator-handoff.md).

## Measured basis and deterministic workload

The plan scales only measured six-figure qualification quantities. The certified 100K campaign
contains 100,000 logical completions, 100,500 physical attempts, 402 credited
result shards, 402 logical-plan segments, two non-crediting attempt-only
segments, and three reconciled planned interruptions. Its tracked execution
report, evidence manifest, warehouse reconciliation, and cache/disk-pressure
qualification are source-bound by SHA-256 in the compact plan.

The proposed denominator and profile allocation are an exact tenfold expansion:

| Selection | Logical executions | Shards at no more than 250 |
| --- | ---: | ---: |
| MySQL regex | 230,780 | 924 |
| PCRE2 DFA | 115,380 | 462 |
| PCRE2 ordinary | 192,310 | 770 |
| Python `re` | 461,530 | 1,847 |
| **Total** | **1,000,000** | **4,003** |

The measured 0.5% six-figure qualification retry rate produces a 1,005,000-attempt planning
expectation. Admission reserves 1,020,000 attempts (2% retry overhead) and
pauses for a new decision at 1,050,000 attempts (5%). A logical execution may
have at most three physical attempts. Infrastructure failures remain
non-crediting, and retry ordinal continuity never creates a second logical
completion.

## Runtime, CPU, and memory

The six-figure qualification session history measured 10.152 active-session hours and 13.030
calendar hours. A strictly linear tenfold extrapolation is therefore 101.521
active hours or 130.300 calendar hours. These are measurements multiplied by
ten, not promises about future throughput.

The working target is 48–72 elapsed hours, with a mandatory pause and replan at
168 hours. That range is explicitly an assumption: it depends on four local
workers plus no more than two optional hosted workers, stable provider latency,
and the absence of sustained backpressure. If hosted protected execution is
not available, the linear 101.521/130.300-hour estimates are the safer basis.
The proposed assignment is 800,000 local and 200,000 hosted logical executions;
hosted execution is optional and restricted to trusted protected revisions.

Default local concurrency is four workers. Each worker receives a conservative
6 GiB upper bound, while controller/provider overhead receives 8 GiB. The
campaign working-set upper bound is 32 GiB, with an additional protected 8 GiB
reserve, so admission requires at least 40 GiB available RAM. Eight workers is
a hard concurrency ceiling, not a default, and requires fresh telemetry. At
least four logical CPU threads remain reserved for the host.

## Disk, cache, and backpressure

All figures below are explicit decimal-byte policy budgets except the GiB RAM
figures above:

- environment cache: 60 GB soft / 70 GB hard;
- protected active spool: 4 GB soft / 6 GB hard;
- analytical cache: 10 GB hard;
- build and execution scratch: 12 GB hard; and
- protected free-space floor: 40 GB.

The backing store therefore needs at least 138 GB to hold all hard reservations
while retaining the floor. Admission uses fresh provider inventory and the
existing Control Plane resource contracts. Crossing a soft threshold stops new
shards and drains work. Crossing a hard threshold, losing fresh capacity
telemetry, or failing to restore the protected floor refuses new work. Active
spool and committed evidence are never eviction candidates.

## Evidence and R2 storage envelope

The six-figure qualification used 317,157,279 bytes of evidence objects and 69,698,118 bytes of logical
segments. Tenfold uncompressed growth is 3,868,553,970 remote bytes. The
immutable derived warehouse is local-only; its tenfold allowance raises the
expected local evidence/logical/warehouse total to 6,123,524,850 bytes.

The remote conservative envelope is 1.5 times measured evidence/logical growth
plus a 1 GB contingency, or 6,802,830,955 bytes. Publication stops softly at
8,000,000,000 bytes and fails closed at the regex-conformance project cap of
10,000,000,000 bytes. Compression receives no planning credit. The warehouse,
caches, diagnostics, and execution scratch are not R2 publication inputs.

Cloudflare documents R2 buckets as having no provider storage quota, so the
10 GB cap is a program-enforced client contract, not a Cloudflare limit. The
future publisher must use a dedicated private bucket, exact manifest sizes, a
durable committed-byte ledger, and exclusive write authority. It must pause
before a new object if the resulting committed total would exceed the soft or
hard bound. Cloudflare's current [R2 limits](https://developers.cloudflare.com/r2/platform/limits/)
and [bucket creation rules](https://developers.cloudflare.com/r2/buckets/create-buckets/)
are controlling provider references.

## Object and request envelope

The expected publication set is 4,003 logical segments, 4,003 result segments,
20 attempt-only segments at the measured retry rate, and three compact control
objects: 8,029 objects. The 5% hard retry boundary permits up to 200
attempt-only segments, for a hard total of 8,209 objects.

Every measured result object is under 1 MB. The plan therefore uses one
single-part conditional `PutObject` per object and sets the multipart threshold
to 100 MiB. Any unexpectedly larger object pauses for replanning before
multipart is used. Cloudflare recommends single uploads for small/medium files
and documents multipart for larger resumable uploads in its
[upload guide](https://developers.cloudflare.com/r2/objects/upload-objects/).

Normal publication requires no `ListObjects` calls. Its expected budget is
8,029 Class A writes and 8,029 Class B read-back verifications, with hard
ceilings of 10,000 each. A durable local journal identifies the exact next key;
recovery uses only that key and its receipt. Repeated bucket scans, polling,
redundant `HEAD` plus `GET`, and synthetic load tests are forbidden.

Objects use immutable content-addressed keys. The publisher sends
`If-None-Match: *`, supplies `Content-MD5`, then immediately `GET`s the object
and recomputes its exact byte length and SHA-256. The ETag is retained only as
provider metadata, never scientific identity. A `412 PreconditionFailed`
causes an exact-key read and hash comparison, not an overwrite. Cloudflare
documents conditional `PutObject`, checksum behavior, and S3 region `auto` in
the [S3 compatibility matrix](https://developers.cloudflare.com/r2/api/s3/api/),
and documents strongly consistent direct S3 reads in the
[consistency model](https://developers.cloudflare.com/r2/reference/consistency/).

The final evidence manifest is written last only after every referenced object
has a verified durable receipt. Restart resumes from those receipts. It never
re-credits a logical completion and never treats an infrastructure attempt as
an observation.

## Cost envelope

The plan uses Standard storage and assumes no free-tier credit, because the
Cloudflare account may have other R2 usage. At current published rates—$0.015
per GB-month, $4.50 per million Class A requests, and $0.36 per million Class B
requests—the expected remote bytes cost no more than about $0.0581/month, the
conservative bytes about $0.1021/month, and the 10 GB hard cap $0.15/month.
Expected write/read requests add less than $0.0391; their hard budget adds
$0.0486. The hard first-month incremental envelope is therefore $0.1986 before
any free allowance. Revalidate these rates immediately before the million-scale campaign against
Cloudflare's [R2 pricing](https://developers.cloudflare.com/r2/pricing/).

## Checkpoint and stop contract

Each shard has a deterministic logical range and immutable result boundary.
The recovery ledger commits physical attempts append-only, and publication
adds a separate durable receipt only after read-back verification. New work
backpressures on RAM, disk, retry, runtime, R2 byte, or request thresholds.
Cleanup never rewrites committed evidence.

The million-scale campaign remains planned until all three conditions are true:

1. this research and operator handoff is complete;
2. the Program Owner confirms the exact bucket/configuration and both secrets
   have been established without disclosing their values; and
3. the R2 publication integration is implemented and verified against these
   request, storage, integrity, and recovery contracts.

The capacity-planning task stops here and requests only the second confirmation.
No 1M execution is authorized.
