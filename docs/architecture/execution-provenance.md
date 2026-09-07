# Physical-attempt and terminal-outcome provenance

This contract governs new execution evidence. It makes every terminal result
traceable to the physical attempt that produced it while preserving the
logical execution as the single unit of required scientific work. Historical
evidence remains valid under the schema revision that originally governed it.

## Lineage and identity

```text
logical execution
  -> physical attempt 1 (terminal or inconclusive)
  -> physical attempt 2 (retry or authorized repeat, when permitted)
  -> terminal observation
  -> logical execution disposition
```

The logical-execution ID remains the content-derived identity of planned work.
Every physical attempt has a distinct assigned `physical-run` ID and immutable,
append-only record. Every admissible target result has a distinct assigned
`observation` ID plus a content-derived `observation-content` ID. These reuse
the existing typed namespaces; this contract introduces no alternate identity
system.

The prospective v2 attempt record binds an ordinal, immediate predecessor,
timestamps, the exact execution context, resource budget, expected-
intermittence declaration, reset, retry or repeat authorization, checkpoint
context, process and protocol status, fault attribution, semantic result, and
separate physical-telemetry references. The execution context references exact
profile, target release, vector, applicability coordinate, environment,
adapter, campaign, shard/work unit, harness, control-plane, protocol, and
policy revisions. Descriptive copies are not identity authority.

Migration is prospective and routed by schema version. The policy records the
exact digests of the v1 attempt and observation schemas and the v2/v3 Evidence
Pack manifest schemas. Those records remain valid under their originating
contracts and are never rewritten or claimed to contain provenance that was
not recorded at the time.

## Terminality

One attempt satisfies a logical execution only when it produces a complete,
target-attributable observation:

- match, no-match, compile rejection, target error, or unsupported requires a
  valid, complete target response;
- target crash, target timeout, or target resource termination requires proof
  that target invocation began plus bounded target-layer attribution evidence;
- process symptoms alone never establish target behavior.

Adapter crashes, malformed or lost responses, supervisor failures,
environment-realization failures, pre-target network failures, storage
publication failures, and unresolved attribution are inconclusive attempts.
They produce no terminal observation and cannot satisfy the logical execution.
Exhausting a permitted retry budget leaves the logical execution unresolved;
it does not fabricate a target failure.

The first admissible terminal observation is the satisfaction evidence. A
later automatic retry may not replace it simply because a preferred result was
obtained. This anti-laundering rule is enforced across the whole lineage.

## Retry and reset contract

The canonical policy in
`registries/provenance/execution-provenance-policy.v1.json` is digest-bound.
Each retry names the inconclusive predecessor, exact reason, authorizing rule
and policy revision, and authorization kind. The closed rules are:

| Inconclusive cause | Maximum total attempts | Required reset | Environment realization |
| --- | ---: | --- | --- |
| adapter process failure | 3 | adapter process | same |
| environment realization failure | 2 | environment realization | replacement allowed and required when reset |
| attribution remains inconclusive | 1 | none | same; no retry permitted |
| interrupted target invocation | 3 | target process | same |
| lost unattributed response | 2 | target process | same |
| malformed adapter response | 2 | adapter process | same |
| network failure before target invocation | 2 | none | same |
| worker or supervisor failure | 3 | environment processes | same |
| storage publication failure | 1 | none | continue publication; do not rerun target |

The reset vocabulary is deliberately limited to states the present execution
architecture can establish: `none`, `target-process`, `adapter-process`,
`environment-processes`, `container`, and `environment-realization`. A
non-`none` reset requires evidence. Every retry remains a new append-only
attempt and does not add a second logical completion.

Retry itself does not increase or decrease scientific confidence; it only
resolves uncertainty after an inconclusive attempt. Confidence and flakiness
interpretation remain later adjudication concerns.

A legitimate terminal result is never retryable as an unfavorable semantic
result. Additional admissible observations require an explicit repeat purpose:
operator remeasurement, qualification repeat, or recovery validation. Repeat
rules require operator or qualification authorization and bind the predecessor
observation, policy revision, and unchanged environment realization. Automatic
repeat is forbidden.

## Repeat agreement and observation provenance

Each terminal observation binds its terminal attempt and the ordered attempt
prefix that existed when it was recorded. Its result signature is the RFC 8785
SHA-256 digest of exactly the outcome class and semantic result. Display text,
physical telemetry, timing, and storage layout do not enter the signature.

Multiple authorized observations may coexist. The logical disposition groups
observation IDs by result signature and reports both the terminal-attempt count
and the distinct signature count. This can state that three observations
contain two equivalent signatures and one divergent signature without calling
the coordinate flaky, conformant, waived, or divergent. Those interpretations
belong to later adjudication policy.

Semantic results and physical telemetry are provenance-distinct. Match state,
spans, captures, target errors, target-reported limits, and attributable target
termination are semantic evidence. Wall time, CPU, RSS, disk, supervisor timing,
and host contention are physical telemetry references. Telemetry may explain
an attempt but cannot silently redefine its semantic outcome.

## Checkpoint and recovery behavior

The attempt predecessor chain and checkpoint predecessor chain must agree. A
recovered retry retains the interrupted predecessor, obtains a new physical-
run ID, records the required reset, and binds the recovery checkpoint. A
committed terminal attempt is never rerun automatically or overwritten.
Uncommitted interrupted work remains an inconclusive attempt when its
invocation can be identified; if no attempt record was committed, recovery
must not invent a terminal observation.

This extends, rather than replaces, the existing scheduler checkpoint machine.
The historical interruption and recovery qualifications remain immutable
regression evidence under their original schemas.

## Retention and generated reports

Evidence Pack v3 retains the lineage as shared `physical_attempt_facts` plus
separate terminal observations, semantic results, telemetry, and anomaly
blocks. Stable references avoid duplicating the full execution context per
observation, while every attempt and anomaly remains recoverable. The richer
prospective lineage does not rewrite v1 attempt evidence or v2/v3 historical
packs and does not adopt a new compression policy.

Generated summaries must name their population precisely: logical executions,
physical attempts, terminal attempts, inconclusive attempts, retry attempts,
repeat-measurement attempts, recovered attempts, or terminal observations.
These are deterministic calculations over the retained lineage; an ambiguous
generic `executions` count is not acceptable. The lineage set binds these
counts to the shared non-independent reconciliation-calculation derivation
revision rather than presenting them as measurements.

## Machine authority and reproduction

The schemas under `schemas/json/`, the digest-bound policy, and the cross-
artifact validator in `regex_conformance_schema.execution_provenance` are the
machine authority. The deterministic tracked reference set includes ordinary
success, compile rejection after recovery, attributable target crash, exhausted
malformed-response retries, and divergent authorized repeat observations.

Build or verify the prospective contract without executing a target:

```sh
python tools/provenance/compile_execution_provenance.py
python tools/provenance/compile_execution_provenance.py --check
```

The compiler is a design/fixture operation. It authorizes no environment
realization, adapter invocation, campaign, or qualification run.
