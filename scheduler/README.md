# Scheduler

Deterministic sharding, capability-aware placement, checkpointing, retry,
idempotent commit, and resumability source lives here. Assignments and
checkpoints are operational state; retries create new physical attempts.

The recovery journal implements the governed restart/resume checkpoint sequence as private, non-canonical operational state. Hash-chained canonical payloads, exact typed identities, private singly linked storage, transactional commit receipts, and fail-closed startup audit preserve every physical attempt while giving each post-invocation retry a new physical-run ID. See docs/campaigns/restart-resume.md.
