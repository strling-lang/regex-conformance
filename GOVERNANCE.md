# Governance

STRling Regex Conformance uses consequence-based governance. Routine,
reversible implementation work is delegated; changes that alter scientific
meaning, certification, identity, or a trusted execution boundary require
explicit review at the level of their consequences.

This document summarizes repository-facing governance. The controlling charter,
program state, accepted decisions, and risk records remain in the canonical
[program hub][program-hub] and its linked registers.

## Roles

- **Program Owner:** Timothy Macfarlane (`@TheCyberLocal`) is the bootstrap
  Program Owner and final approval authority for constitutional scope,
  governance policy, consequential canonical-schema or identity changes,
  evidence policy, certification policy, and trusted-execution security policy.
- **Maintainers:** review and merge changes within established policy, enforce
  repository quality, and route consequential proposals for the required
  approval.
- **Domain stewards:** may approve work within an explicitly delegated domain;
  delegation does not transfer constitutional or cross-domain authority.
- **Trusted operators:** may execute approved campaigns on approved revisions
  and infrastructure. Operator access grants no policy or evidence-correction
  authority.
- **Contributors:** may propose changes and supply reviewable evidence. A
  contribution does not become canonical until it passes the applicable review,
  validation, and merge controls.
- **Certifiers/reviewers:** independently challenge gate evidence and record the
  certification basis. A failing gate cannot be waived by declaration.

`CODEOWNERS` routes review; it does not itself delegate Program Owner authority
or authorize trusted execution.

## Review classes

### Routine changes

Reversible implementation, tests, documentation, fixtures, and generated
artifacts that stay within accepted contracts may be approved by maintainers or
the responsible domain steward. They still require objective verification and a
coherent reviewed diff.

### Consequential changes

The following require a recorded decision before, or atomically with, the
canonical change and require Program Owner approval:

- constitutional scope, source-of-truth ownership, or governance policy;
- durable identity rules or consequential canonical schema changes;
- completeness denominators or applicability semantics;
- evidence classes, immutability, correction, trust, or provenance policy;
- certification definitions, gates, or waiver semantics; and
- trusted-runner eligibility, protected-revision policy, credentials, or other
  trusted-execution security boundaries.

Accepted decisions are superseded explicitly. They are never silently rewritten.

### Emergency changes

A credential, runner, publication surface, or campaign may be suspended to
contain an active integrity or security threat. Emergency action is narrow,
recorded, and followed by normal consequential review before restoration or a
permanent policy change.

## Change and evidence integrity

Repository-changing work is committed only after the task objective and relevant
positive, negative, boundary, fault, regression, security, structural, and
reproducibility checks pass. Generated artifacts must be internally consistent,
and temporary state, credentials, runtime images, caches, large spools, and raw
large evidence remain outside Git.

Published observations are immutable. A correction creates traceable
invalidation, supersession, or replacement state and retains the original
physical attempt and observation. Retries add physical attempts; they never
overwrite earlier attempts. Derived analytical data may be regenerated but may
not replace or mutate its immutable evidence authority.

## Trusted execution

Public contribution validation uses disposable, untrusted infrastructure with no
evidence or publication credentials. Trusted self-hosted execution accepts only
protected definitions and approved manifests through a pull-based assignment
path, verifies immutable artifact identities, and uses scoped, preferably
ephemeral credentials. No fork or pull-request workflow may select a trusted
self-hosted runner or execute arbitrary contributor code there.

[program-hub]: https://app.notion.com/p/3ba7d9406475810db8eec9b5c449ffb7?pvs=204
