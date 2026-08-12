# Contributing

Thank you for helping build a reproducible empirical regex corpus. Contributions
are welcome when they preserve the program's scientific and security boundaries.

## Before proposing a change

Read [README.md](README.md), [GOVERNANCE.md](GOVERNANCE.md), and
[SECURITY.md](SECURITY.md). Open a public issue for ordinary design discussion.
Report suspected vulnerabilities privately as described in the security policy.

If a proposal changes constitutional scope, durable identity, consequential
schemas, completeness semantics, evidence or correction policy, certification,
or trusted execution, it must be recorded in the canonical Decision Register and
receive the required governance approval. A pull request alone cannot authorize
such a change.

## Contribution requirements

- Keep normative research separate from empirical observation. This repository
  may reference Knowledge Program identifiers and expectations but must not
  create a competing normative taxonomy.
- Make applicability and unsupported operations explicit. Do not manufacture
  Cartesian-product coordinates that have no semantic meaning.
- Keep adapters thin and preserve runtime-native behavior and index units.
- Distinguish logical executions, physical attempts, target behavior, and
  infrastructure failures.
- Preserve published evidence and correction history. Never edit an observation
  in place to make a result look cleaner.
- Pin or verify mutable upstream inputs and retain reproduction provenance.
- Do not commit secrets, credentials, personal data, runtime images, downloaded
  toolchains, caches, local Control Plane state, large diagnostics, execution
  spools, raw campaign evidence, or machine-local configuration.

## Pull requests

A pull request should explain the objective, affected authority boundary,
validation performed, failure and boundary cases exercised, and any generated
artifact changes. Keep each change coherent and exclude unrelated edits.

Use substantive conventional commit subjects that describe the permanent
outcome, for example `feat(matrix): compile deterministic applicable execution
coordinates`. Do not use task identifiers or progress bookkeeping as commit
subjects.

Fork and pull-request validation is untrusted and disposable. It must not request
trusted self-hosted labels, evidence credentials, publication credentials, or
protected-environment access. Passing public CI is necessary but does not make a
run trusted evidence.

## Verification

Run every repository-provided formatter, schema validator, test suite, generated
artifact consistency check, and security check affected by the change. Include
negative and boundary cases appropriate to the objective. If code changes after
final verification, rerun the affected checks before committing.

The repository is still in bootstrap; exact commands will be documented as the
validation toolchain is introduced. Until then, reviewers must at minimum verify
links, ownership, licensing, repository cleanliness, and the complete diff.
