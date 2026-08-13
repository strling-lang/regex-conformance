# Verifier

Structural, provenance, result, evidence-integrity, reconciliation, replication,
and discrepancy verification source lives here. Verification qualifies immutable
inputs and never rewrites an observation.

`ImmutableEvidenceStore.qualify_manifest` creates a separate content-addressed
integrity assessment. Clean, complete evidence is analytically admitted but is not
thereby trusted or certification-admissible; malformed, truncated, inconsistent,
semantically impossible, indirect, or substituted evidence is quarantined without
mutating its source. See the evidence verification and quarantine procedure in
`docs/campaigns/evidence-verification.md`.
