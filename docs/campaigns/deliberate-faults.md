# Deliberate Fault and Timeout Qualification

The small-scale fault harness proves that a process symptom is not, by itself, a regex
observation. The classifier consumes a closed set of facts about the injection
point, last protocol checkpoint, adapter response, containment outcome,
environment health, supervisor health, network acquisition, and evidence
publication. Missing or contradictory attribution fails closed as an
inconclusive physical attempt.

## Reference cases

The deterministic report covers seven controlled cases:

- target invocation exceeds its verified wall-time limit;
- target invocation terminates by signal;
- adapter process terminates by signal;
- worker process is killed;
- adapter returns a malformed frame;
- acquisition transport fails before target invocation; and
- evidence publication fails after a valid response.

Only the first two are target-attributed terminal outcomes and therefore may
satisfy C5 when the campaign's trust, replication, requested-observation, and
provenance policy also passes. The other five remain preserved infrastructure
or protocol attempts and cannot become target timeout, crash, no-match, or
non-conformance.

This is an operational qualification surface. It has no normative or semantic
authority and does not implement retry/resume policy, which belongs to the next
small-scale task.

## Reproduce

Materialize the deterministic reference report:

```sh
.venv/bin/python tools/campaigns/compile_fault_classification.py
```

Execute the allowlisted local fault set and write immutable raw evidence
outside Git:

```sh
.venv/bin/python tools/campaigns/exercise_faults.py \
  --evidence-dir /tmp/strling-regex-fault-evidence
```

The live harness uses the same hard containment supervisor as campaign
adapters, the strict adapter-frame decoder, deterministic injected transport
and `ENOSPC` failures, read-after-write verification, and content-addressed
external evidence.
