# 100K qualification results

The P19-T02 qualification campaign completed on 2026-08-14. These results are
empirical observations of the exact frozen runtime profiles and execution
conditions. They are operational qualification evidence, not normative regex
semantics.

## Certified anchors

- Campaign manifest: `rcid:v1:campaign-manifest:h:jcs-sha256-v1:3a2df1d804fa11b7c6e30af6995bb88a5574ca8c89d5a32a9436a4590fbcc9a8`
- Evidence manifest: `rcid:v1:evidence-manifest:h:jcs-sha256-v1:1572476aa1b968530356d3a310ab78eb267a3d775e3f10d760ab76e600b7cb34`
- Evidence-manifest object SHA-256: `a2d8d1c460d7822bc2212df41d41842e02202961caad7bc17ca1b68204ae07fa`
- Evidence root digest: `ae4d5296b44ef3b72fb4773f4aef0fa8b02a1cab82f5b865f7fe066db96885a5`
- Compact report: [`reports/scale/100k-execution.json`](../../reports/scale/100k-execution.json)
- Compact-report SHA-256: `b89f65fea9e58d6fe1869f9e696227f2fc46d6af4160580119129f684fee12e8`
- Recovery-ledger hash-chain tail: `8e4ecb970440c2305ec58618bb7e67d48906a9df181883326447636531d99408`

The external campaign-root name is
`100k-qualification-20260814-3a2df1d8`. Raw segments, physical attempts,
sessions, operational state, the recovery ledger, and the evidence manifest
remain outside Git.

## Exact accounting

The terminal session `d56e13f7-58cc-4872-a7cd-cdb601151146` ran from
`2026-08-14T16:22:09.802Z` through `2026-08-14T21:43:31.813Z` and ended
`completed`.

- 402 result shards cover exactly 100,000 unique logical executions.
- 404 immutable segment objects comprise 402 results and 2 attempt-only
  infrastructure segments.
- 100,500 unique physical attempts comprise 100,000 target observations and
  500 infrastructure failures.
- All three planned interruptions occurred at committed-result boundaries 100,
  201, and 300.
- Retry ordinals are contiguous, no logical execution completed twice, and
  infrastructure failures received no logical completion credit.

## Attempt-only segments and recovery

The planned forced-worker-kill path affected MySQL shard
`rcid:v1:shard:h:jcs-sha256-v1:84cfde71cc983e6148650a7371b2040131e286a7a4a173dbf4dff32b774b97f5`.
Commit ordinal 202 recorded attempt 1 as object
`c851577db573d32654d76f70751f2717f12fa0abc920f9110265a60a0de57221`:
250 `forced-worker-process-kill` rows, no observations, and no credit. Commit
ordinal 203 recorded attempt 2 as result object
`264e5b9baf3bee2656e820cf26af1fbf5ff8de83b09222974baacb6a40266100`,
which completed the same 250 logical executions once.

The second operational retry affected CPython shard
`rcid:v1:shard:h:jcs-sha256-v1:ef24422b863442ccccd60575f28470e776ddc73a79861643a5b2f431435ab2bf`.
Commit ordinal 362 recorded attempt 1 as object
`d734662713263961e83a2fd725810cb1eef5c50e9a3e64f8ae3898d8bad4a55e`:
the isolated CPython target process ended at the outer
`wall-time-limit/-15` before a qualified observation, producing 250
`scale-shard-infrastructure-failure` rows, no observations, and no credit.
Commit ordinal 363 recorded attempt 2 as result object
`31819cb48e1baf0a7b2030a2e0ae615c4286640587cd00a25d942e695c4bf55c`,
which completed the same 250 logical executions once. The recovered attempt is
valid append-only operational history, not a denominator defect.

## Verification and source binding

The official evidence-manifest verifier rebuilt the manifest from all 404
immutable segment objects. An independent read-only SQLite reconciliation
validated database integrity, the 404-entry canonical hash chain, all session
outcomes and interruption digests, retry ordering, manifest references, and
the exact report projection.

The campaign plan hashes raw source bytes. The Windows worktree used for the
campaign retained CRLF spellings in seven bound files and a mixed-EOL spelling
in `tools/campaigns/run_100k_qualification.py`, even though Git's text filter
had normalized the corresponding blobs to LF. The executed bytes were
reconstructed exactly from the immutable local implementation history: all 38
plan source digests match, including the runner's CRLF spelling with lines
80–87 retained as LF. The P19-T02 closure commit marks these eight paths
unfiltered and stores the exact executed bytes so a clean checkout of the
certified SHA reproduces the frozen plan. Any later source change must bind a
new campaign plan; it does not rewrite this result.

No campaign rerun, new evidence root, raw-evidence mutation, recovery-ledger
mutation, or Docker authority was used during final reconciliation. Decision
D102 expired with P19-T02 and grants no authority to P19-T03 or later work.
