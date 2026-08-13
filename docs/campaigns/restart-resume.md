# Restart, Resume, and Duplicate-Attempt Qualification

Campaign recovery follows the accepted D090 boundary exactly:

`leased → environment-ready → running → observation-finalized → spooled → segment-finalized → uploaded → verified → manifest-committed → acknowledged`

Each checkpoint is appended transactionally to a private SQLite journal. The
record stores canonical payload bytes and their SHA-256, the previous checkpoint
digest, the controller session, exact campaign/logical/physical identities, and
the recorded time. The resulting hash chain and SQLite integrity check are
verified before every recovery or transition. Local recovery state is explicitly
operational and non-canonical; it cannot create empirical or normative truth.

Recovery is conservative:

- a restart before target invocation continues the same physical run;
- a restart at `running` preserves the interrupted attempt and creates a new
  physical-run ID for the retry;
- finalized, spooled, uploaded, or verified material continues publication
  without rerunning the target;
- a verified immutable manifest commit satisfies the logical execution even if
  scheduler acknowledgment was interrupted;
- duplicate delivery in the same controller session is idempotent;
- corruption, plan mismatch, identity collision, non-contiguous transitions,
  missing commit receipts, linked database paths, or credential-bearing payloads
  fail closed.

The deterministic 14-case policy matrix is stored at
`reports/small-scale/restart-resume-qualification.json`. Regenerate it with:

```console
.venv/bin/python tools/campaigns/compile_restart_resume_qualification.py
```

The live closed harness reopens the durable journal after every checkpoint,
forces one child process to exit abruptly after target invocation, repeats three
retries for one logical execution, injects an uncommitted transaction, corrupts
a checkpoint chain, and proves exactly one commit without reused physical-run
identity. Raw execution evidence remains outside Git:

```console
.venv/bin/python tools/campaigns/exercise_restart_resume.py /tmp/recovery-evidence
```

The journal accepts a manifest digest only at `manifest-committed`. Verification
of the referenced immutable publication is the evidence verifier's responsibility;
P18-T04 hardens that validation and diagnostic quarantine boundary.
