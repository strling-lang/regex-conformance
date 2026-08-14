# Control Plane agent guidance

`control-plane/` owns provider-neutral planning, inspection, admission,
environment lifecycle, recovery, cache/transfer management, durable local
state, events, and containment. It does not own scientific definitions,
evidence truth, or research conclusions. Read [README.md](README.md) and the
applicable architecture document before editing.

Preserve `plan → inspect/admit → execute → verify` boundaries. Planning and
machine inspection are non-mutating; unknown capacity is never zero, trust is
never inferred, and provider or infrastructure failures never become regex
observations. Mutation requires the command's explicit execution flags and
separate user authorization. Keep state roots and spools outside Git, retain
append-only attempts and recovery evidence, reject secrets, and fail closed on
identity, integrity, containment, or reconciliation ambiguity.

Run the narrow test first, then the affected pattern under
`tests/control_plane`; environment, provider, or Docker qualification is a
separate authorized tier.
