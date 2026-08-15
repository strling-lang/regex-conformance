# Cache and disk-pressure qualification

P19-T03 qualifies the existing provider-neutral Control Plane cache and resource
contracts under deterministic Executioner-like pressure. It does not execute a
regex target, mutate the certified 100K evidence, or authorize an environment
provider. The qualification is explicitly simulated operational evidence:
`target_behavior=false`, `docker_used=false`, and
`external_evidence_mutated=false`.

The compact report is
[`reports/scale/cache-disk-pressure-qualification.json`](../../reports/scale/cache-disk-pressure-qualification.json).
Its canonical qualification digest is
`a771fe9b1f1262d6ff19b0fd0bf1a16699750b9ab9c946767b9a2f45d847baf7`;
the tracked report file SHA-256, including its terminating newline, is
`5cb2370a561fe5268b909d123debeaae014a6c8c981eb39345d40053a061f238`.

## Certified behavior

Ten independently named cases cover the accepted D024, D026, D030, D081,
D085, and D089 contracts:

- weighted project-aware eviction selects a cheap reconstructible asset ahead
  of an older expensive asset and remains permutation-stable;
- pinned, active-leased, future-required, dependency-required,
  protected-spool, and rare-fragile assets are excluded with explicit reasons;
- cleanup is refused without mutation when protected candidates cannot restore
  the required margin;
- provider reality that differs from cached inventory fails closed before
  deletion;
- partial and interrupted cleanup preserve exact mutation boundaries and resume
  from fresh inventory without deleting an entry twice;
- logical size is never substituted for provider-reconciled reclaimable size;
- pressure arriving after successful preflight produces dynamic backpressure
  on the shared cache/scratch/spool backing store;
- work resumes only after a refreshed inventory restores the configured safety
  floor;
- low-confidence forecasts receive their conservative margin, while unknown
  capacity drains until exact telemetry becomes available; and
- protected spool and an out-of-cache committed-evidence sentinel remain
  available after cleanup.

The aggregate churn ledger spans seven executed cleanup reports: four
completed, one partial, one cancelled, and one refused. Six verified deletions,
one failed deletion, and one cancelled candidate reconcile 32,768 expected
physical-plan bytes to 24,576 actually reclaimed bytes. The 8,192-byte
difference remains explicit at the seeded failure/cancellation boundaries;
fresh recovery plans reclaim those remaining bytes without duplicate deletion.

The focused filesystem test additionally creates a bounded temporary cache and
a sibling immutable-evidence sentinel. The root-confined provider deletes only
the verified cache file, keeps actual reclamation bounded by the observed
filesystem free-space delta, and leaves the evidence bytes unchanged. This is
a local safety fixture, not a target observation or scale campaign.

## Reproduction

From the repository root with the locked environment installed:

```powershell
.\.venv\Scripts\python.exe tools\control_plane\compile_cache_disk_pressure_qualification.py
.\.venv\Scripts\python.exe -m unittest tests.control_plane.test_cache_disk_pressure_qualification -v
.\.venv\Scripts\python.exe -m unittest tests.control_plane.test_cache_manager tests.control_plane.test_resource_planner -v
.\.venv\Scripts\python.exe schemas\tooling\python\run.py validate-repository
```

The compiler validates the report against
`cache-disk-pressure-qualification.v1`, writes canonical bytes through an
fsynced temporary file and atomic replacement, verifies the read-back bytes,
and independently rebuilds the report to prove determinism. The report binds
the exact cache, resource-admission, schema, and compiler sources by SHA-256.

## Qualification boundary

The qualification proves that the Control Plane does not knowingly consume its
protected free-space floor and cannot select committed evidence or protected
spool data for cache eviction. It also proves explicit backpressure, drain,
refusal, partial-state accounting, and safe recovery. It does not claim that a
specific runtime or Docker provider exhibits any regex behavior, and D102's
expired P19-T02 authorization is not reused.
