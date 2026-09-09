# Local authoritative certification and hosted integrity verification

Expensive deterministic repository certification runs on the controlled local
machine. Hosted Linux independently verifies the resulting commitments and
retains veto authority, but does not repeat generation, migration,
explainability, environment realization, adapter qualification, or campaign
execution that the local certificate already binds.

The architecture is named **Local Authoritative Certification / Hosted
Integrity Verification**.

## Authority and trust boundary

The local certifier starts only from a clean committed source tree. It runs the
canonical denominator regeneration check, migration and explainability checks,
identity and derivation validation, foundation gates, certification evaluation,
schema and fixture validation, identifier hygiene, and the affected policy
suite. A failed command prevents a local PASS.

The generated manifest binds the exact source commit and tree plus the current
certification contract, semantic snapshot, obligation snapshot, requirement
snapshot, migration ledger, identity catalog, derivation catalog, authority
indexes, generated-artifact closure root, test-result closure root, and current
scientific certification result. Every file and closure uses RFC 8785 JCS and
SHA-256 through the repository's existing content-identity conventions.

A SHA proves integrity and identity, not correctness. The hosted verifier
therefore validates the complete result structure, exact source and tree,
artifact bytes, contract and catalog bindings, test-result closure, and cheap
independently recomputed obligation, requirement, predecessor, and C4
aggregates. Schema, fixture, identifier, and trust-boundary checks plus a small
adversarial verifier canary run separately. Stale, malformed, mismatched,
corrupted, or incompletely bound certificates are vetoed.

## Non-self-referential commit envelope

A tracked file cannot contain the SHA of the commit that contains that file.
Certification therefore uses two commits:

1. A clean source commit contains every scientific artifact and certifier
   implementation. Local authoritative checks run against this exact commit.
2. A single-parent envelope commit adds only
   `certification/local/current-local-certification.v1.json`.

The manifest binds the first commit. The promotion command binds and promotes
the exact second commit and verifies that its parent is the certified source and
that the manifest is its only change. Promotion requires both the envelope SHA
and the caller-recorded local certification root.

```sh
python tools/ci/certify_local.py --root .
git add -- certification/local/current-local-certification.v1.json
git commit -m "cert(certification): bind local authoritative result"
python tools/ci/verify_local_certification.py --root . \
  --expected-envelope-sha <envelope-sha> --expected-root <certification-root>
python tools/ci/promote_verified.py --verified-sha <envelope-sha> \
  --local-certification-manifest certification/local/current-local-certification.v1.json \
  --local-certification-root <certification-root>
```

Hosted verification is deliberately bounded to minutes. Pull requests, which
cannot carry a locally authoritative program certificate by definition, receive
the schema, fixture, identifier, policy, and verifier-smoke subset without an
authority claim. Main and explicitly dispatched exact envelope revisions must
also close the local-certificate verifier.

This policy changes certification execution placement, not the scientific
meaning, identity, derivation, migration, or C1–C7 semantics of the obligation
and requirement snapshots.
