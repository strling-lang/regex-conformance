# Certification

Regex Conformance certification is a deterministic evaluation over explicit,
digest-bound inputs. A prose statement, campaign completion flag, percentage,
or generated declaration cannot issue an authoritative certification.

The canonical artifacts are:

- `contracts/regex-conformance-certification.v1.json`: the versioned C1-C7
  predicate contract;
- `inputs/current-repository.v1.json`: the exact current repository inputs and
  their byte digests;
- `reports/current-repository.v1.json`: a freshly recomputable evaluation; and
- `current-authority.v1.json`: the separate issuance, supersession, and
  revocation authority index.

The canonical schemas are under `schemas/json/`. The evaluator and semantic
validation live in
`schemas/tooling/python/regex_conformance_schema/certification.py`. Compact
adversarial fixtures live under `tests/fixtures/certification/`.

## Authority boundary

The canonical program workspace owns governance intent, Program Owner
decisions, and later policy amendments. This repository owns the exact
versioned encoding of the accepted policy: schemas, predicates, evaluator,
fixtures, and deterministic reports. Changing an accepted meaning requires a
new recorded governance decision and a new contract revision; evaluator code
cannot silently reinterpret it.

The current contract uses the accepted meanings:

| Criterion | Exact governed population | Passing condition |
| --- | --- | --- |
| C1 | Every candidate in the frozen universe snapshot | Every candidate has a valid non-pending disposition and valid ownership/lineage |
| C2 | Every governed in-scope release line at the cutoff, including accepted historic exceptions | Every line has one valid, provenance-bound active representative |
| C3 | Every concrete-profile reproducibility obligation derived from C2 | The ledger accounts for every obligation in a controlled state; the exact reproducible ratio is reported and need not be 100 percent |
| C4 | Every applicable semantic requirement/obligation | Every member has certified explicit vector attribution or an approved machine-readable unperformable disposition |
| C5 | Every logical execution in the frozen campaign | Every logical execution has admissible target-attributable terminal observation evidence |
| C6 | Every official observation, including invalidated and superseded history | Every member passes the applicable integrity and correction-graph validators |
| C7 | Every discrepancy detected by a completed reconciliation pass | Every discrepancy has proof-bearing triage, or a completed detection manifest certifies an empty result set |

Exact stable-ID denominator and numerator sets, their SHA-256 commitments, and
their exact ratio are authoritative. Rounded percentages are display-only.
C1, C2, and C4 cannot pass with an empty denominator. C7 can pass at `0/0`
only when an independently evidenced completed detection manifest proves that
zero discrepancies were found.

## Result states and composition

Each criterion is evaluated independently:

- `PASS` means the predicate is true over complete admissible inputs;
- `FAIL` means sufficient inputs prove the predicate false or invalid; and
- `BLOCKED` means authoritative prerequisites are absent, provisional, or
  unresolved, so no semantic failure conclusion is made.

Missing evidence is not converted to unsupported behavior or target failure.
Likewise, infrastructure failure cannot satisfy C5. Final certification is the
conjunction of every required criterion: any `FAIL` makes the final state
`FAIL`; otherwise any `BLOCKED` makes it `BLOCKED`; only seven passes produce
`PASS`. A passing evaluation is merely eligible for issuance when its input
explicitly requests authority over a certification-candidate scope. Issuance
is recorded separately in the authority index.

## Evidence strength

Criterion inputs reference revisions from the common generated-assertion
derivation catalog. Each criterion lists the admitted classes. Qualifying
scientific members require independent `measurement`, `research-derived`, or
`external-evidence` support within the criterion's rules.

`constant-by-construction` never satisfies an independent requirement.
`calculation` proves arithmetic over its inputs but not the truth of those
inputs. `manual-decision` establishes governance only. `inference` remains
advisory unless a future governed contract explicitly says otherwise. The
evaluator rejects class escalation rather than treating a truthy assertion as
evidence.

C5 delegates attempt and terminal-observation validity to the canonical
execution-provenance validator, then counts logical-execution IDs exactly
once. Inconclusive retries and repeat measurements cannot inflate completion.
C6 consumes proof-bearing outputs from the existing Evidence Pack, manifest,
schema, digest, readback, and correction-graph validators; the certification
evaluator does not reimplement those integrity algorithms.

## Versioning and historical authority

The contract, input set, and report have separate content-derived identities
and digests. The contract also binds the exact evaluator, identity/lineage
validators, and structural schemas by byte digest, so implementation drift
cannot retain the same predicate authority. A new semantic snapshot,
universe/profile registry, requirement
set, evidence contract, or certification contract supersedes the former scope
without changing the old report. Proven corruption, invalidated inputs, or a
predicate defect revokes or invalidates current authority through an
append-only action. Historical reports remain immutable and resolvable under
their original contract and schema.

The current-authority index is deliberately separate from reports. It can move
the current pointer or record a revocation without rewriting a historical
`PASS` report.

## Current repository evaluation

The current repository does not certify. C1-C3 and C5-C7 are `BLOCKED` because
their production canonical populations do not yet exist. C4 is `FAIL` at
`0/9506`: all current frozen semantic requirements lack certified production
vector attribution. This result is intentional and must not be weakened to
make an incomplete corpus pass.

## Reproduction

Materialize or verify the tracked artifacts without executing a target:

```sh
python tools/certification/evaluate.py
python tools/certification/evaluate.py --check
python schemas/tooling/python/run.py verify-certification
```

Repository validation also verifies the contract, current input, current
report, authority index, adversarial fixtures, derivation bindings, identity
lock, and execution-lineage contract.
