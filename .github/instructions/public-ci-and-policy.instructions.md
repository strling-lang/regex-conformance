---
applyTo: ".github/workflows/**,.github/policies/**,tools/ci/**"
---

# Public CI and delivery-policy guidance

Public validation is disposable and untrusted. Preserve read-only repository
permissions, pinned actions/dependencies, secretless execution, and exclusion
of trusted self-hosted runners, evidence credentials, publication credentials,
and cross-zone artifacts. Keep workflow behavior aligned with
[.github/policies/main-protection.json](../policies/main-protection.json) and
[docs/governance/repository-protection-policy.md](../../docs/governance/repository-protection-policy.md).
Promotion is a separate operator-authorized fast-forward operation; never run
it merely because validation or documentation changed.
