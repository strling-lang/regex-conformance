# Distributed 1M qualification

The million-scale qualification expands the frozen, verified 100K denominator
by exactly ten. The
tracked master plan contains 1,000,000 independent logical executions in 4,003
content-addressed shards. It preserves the six-figure qualification profile distribution:

| Profile | Logical executions |
| --- | ---: |
| MySQL regex | 230,780 |
| PCRE2 DFA | 115,380 |
| PCRE2 ordinary | 192,310 |
| Python `re` | 461,530 |

The master plan is compiled from
`campaigns/million/definitions/million-qualification.v1.json`. Its source set
binds the frozen six-figure plan, compiler, controller, Evidence Pack v2 codec,
publisher, recovery and finalization tools, schemas, and the trusted workflow.
The 1M logical inputs are materialized only outside Git. Each worker derives
its exact partition locally from the tracked master plan; GitHub Actions does
not retain or transfer the large logical-input corpus. Git retains the compact
master plan and exact shard commitments.

## Hosted partition execution

The campaign uses 64 closed, non-overlapping, contiguous shard partitions.
Each contains at most 63 shards and 16,000 logical executions. At most 20
GitHub-hosted Ubuntu 24.04 jobs execute concurrently. Standard public runners
are used so runner time is not billed, and the only Actions artifacts are tiny
partition receipts and the final compact report. The workflow is manual,
`main`-only, read-only with respect to repository contents, and uses exact-SHA
actions and hash-locked Python dependencies.

GitHub documents standard hosted runners as free and unlimited for public
repositories, while Actions artifact storage consumes the account's separate
shared allowance. The local derivation design therefore avoids large retained
input artifacts rather than relying on unapproved storage overage.[^github-actions]

Each partition uses the already certified target providers through ordinary
host-runner Docker. The controller is a normal trusted process and never
mounts `/var/run/docker.sock`; the expired six-figure-campaign Docker-daemon
authorization is neither needed nor
inherited. Provider-created targets retain their pinned artifacts, resource
limits, capability controls, isolation, and post-session cleanup checks.

Every partition proves three planned restart boundaries: controller restart at
25%, a forced target-worker kill at 50%, and controller restart at 75%. The
forced kill creates one non-crediting infrastructure attempt for the next
shard. Across all 64 partitions this plans exactly 16,000 infrastructure
attempt facts while preserving exactly 1,000,000 crediting logical
observations. Unplanned target/provider failure remains a non-crediting
physical attempt and is retried only within the frozen three-attempt limit.

## Evidence Pack v2 publication and recovery

A completed partition is deterministically encoded and independently
certified before publication. Certification includes exact source
reconstruction, corruption detection, independent observation and physical
attempt counts, and manifest-last structure. Each partition pack has a closed
8,000,000-byte allocation; 64 maximum allocations plus the 461-byte production
Evidence Pack v2 canary remain far below the program's 8 GB soft stop and 10 GB
hard cap.

Pack objects and pack manifests use immutable content-addressed keys. After a
pack manifest is verified, the publisher conditionally creates one immutable
partition-coordinate receipt at:

```text
regex-conformance/evidence-pack-v2/campaigns/<master-sha256>/partitions/<index>/receipt.json
```

That coordinate is coordination and integrity evidence, not an observation
payload. Its bytes are canonical, schema-validated, and bound to the exact
master and partition manifests. A conflicting pre-existing receipt fails
closed. On a workflow rerun, each worker performs one exact `GET` for its known
coordinate; a verified receipt skips execution and publication. A missing
coordinate starts the partition. Recovery therefore uses no `LIST`, no polling,
and cannot turn a repeated workflow dispatch into duplicate logical credit.

The final job requires exactly 64 receipts, verifies every coordinate receipt,
pack manifest, and distinct content object by exact key, and reconstructs every
pack structure. It then reconciles the closed partition indexes and exact
1,000,000 denominator, computes actual unique retained bytes and Class A/Class
B requests, enforces the capacity policy, and conditionally publishes a final
content-addressed aggregate manifest last. The resulting compact execution
report is safe to retain as a workflow artifact; raw evidence remains in R2.

## Local-first preparation boundary

The campaign may instead execute all partitions against one governed local
Linux host and stop before object-store access. Each completed partition is
encoded twice, reconstructed exactly, corruption-tested, and written into an
immutable local tree using the same content-addressed keys planned for R2.
`prepare_million_partition.py` records the exact pack identity without claiming
that a cloud request occurred. `finalize_million_local_artifacts.py` then
requires all 64 preparations and execution reports, verifies every staged
object and pack structure, reconciles the million logical executions and all
192 planned interruptions, and performs the 8 GB/10 GB capacity admission.

The resulting local readiness report deliberately records zero cloud requests
and defers partition-coordinate receipts and the aggregate publication
manifest. Those objects depend on the later exact-key R2 integrity check and
must not be manufactured as if local filesystem writes were cloud
publication. A ready local corpus can therefore be reviewed before any
credentialed request, and a later uploader can read the already certified
bytes rather than recomputing empirical evidence.

The local orchestrator requires its recovery-state root separately from the
evidence root. Recovery state must be durable native Linux storage that
enforces POSIX `0700` directory and `0600` SQLite-file modes; a Windows-mounted
directory that reports permissive synthetic modes is rejected before target
execution. Raw evidence, exact pack bytes, handoffs, and the final readiness
report remain in the declared durable external evidence root.

## Reproduction boundaries

Plan compilation and source validation are non-executing:

```sh
python tools/campaigns/compile_million_qualification.py --check
python tools/ci/verify_public_ci.py --root .
```

The production-sized local proof is deliberately excluded from ordinary test
discovery because two deterministic preset-9 encodes exceed the 30-minute
public-validation budget. Run it explicitly before campaign promotion:

```sh
STRLING_RUN_MILLION_PRODUCTION_PROOF=1 python -m unittest \
  tests.campaign.test_million_qualification.MillionQualificationTests.test_complete_partition_recovers_and_certifies_evidence_pack_v2
```

Materialization, target execution, authenticated publication, and final remote
verification occur only in the trusted manual workflow. Do not invoke the
partition runner casually: it performs governed target execution. Do not pass
credentials on command lines or expose values in logs. The publisher accepts
only the six approved environment variable names and never issues a normal
bucket listing.

[^github-actions]: [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
