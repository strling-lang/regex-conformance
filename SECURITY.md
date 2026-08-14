# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or evidence-integrity
incident. Use a private [GitHub Security Advisory][advisory] for this repository.
If that is unavailable, email
[strlinglang@gmail.com](mailto:strlinglang@gmail.com) before public disclosure.

Include the affected revision, component, reproduction conditions, expected
security boundary, observed behavior, and whether credentials, trusted runners,
published evidence, or upstream artifact identity may be affected. Do not attach
live credentials, personal data, or unnecessarily sensitive evidence.

## Supported state

The repository has not issued a stable release. Security fixes apply to the
current protected default branch unless a release-specific policy is published.

## Trust boundaries

- Public forks and pull requests are untrusted and may run only on disposable
  infrastructure without evidence or publication credentials.
- Trusted self-hosted execution never runs arbitrary public contribution code.
- Trusted campaigns use approved manifests and protected revisions, verify exact
  artifact identities, enforce process/resource/output containment, and use
  least-privilege credentials.
- Target timeouts, crashes, compile rejection, and no-match results may be valid
  observations. Infrastructure and containment failures remain separate and do
  not become regex non-conformance.
- Published evidence is immutable. Suspected corruption or misclassification is
  quarantined and corrected through traceable invalidation, supersession, or
  replacement metadata.

Security shortcuts invalidate certification even when functional tests pass.

The executable public-CI trust contract, required branch controls, and settings
audit procedure are defined in the
[repository protection policy](docs/governance/repository-protection-policy.md).
Any change that introduces pull_request_target, a self-hosted label, write
permission, a secret reference, an unpinned action, or an artifact handoff into
the public workflow is rejected by repository tests.

[advisory]: https://github.com/strling-lang/regex-conformance/security/advisories/new
