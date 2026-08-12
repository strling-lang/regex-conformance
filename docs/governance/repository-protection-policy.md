# Repository Protection Policy

This policy implements the program's public-validation trust zone. It is
controlled by accepted decisions D019 and D091–D094 and by sections 21 and 22
of the Foundation Specification.

## Public contribution boundary

The public-validation workflow is the only public contribution workflow at
repository bootstrap. It runs pull requests, protected-main pushes, and manual
validation events exclusively on GitHub-hosted ubuntu-24.04. It uses read-only
repository permission and retains no checkout credential. It has no secret
reference, OIDC permission, artifact upload, publication step, reusable-
workflow handoff, privileged trigger, or self-hosted runner route.

The workflow validates untrusted source. Its outputs are never empirical
evidence, trusted executables, environment inputs, or publication authority.
A future protected evidence workflow must be a separate trust zone with local
admission; it may not extend or call this workflow across the boundary.

The public-CI verifier makes this contract executable and fail-closed. The CI
dependency lock pins exact Linux wheels by SHA-256. Every action is pinned to a
full commit SHA and recorded with its audited release in the machine-readable
main protection policy.

## Required default-branch state

Repository administrators apply the following state to main:

- active ruleset with no bypass actor;
- changes enter through a pull request;
- required public-validation status check on the current revision;
- required conversation resolution and linear history;
- branch deletion and force-push blocked;
- zero required approvals during the single-authority bootstrap period;
- default workflow token permission contents: read;
- workflows cannot approve pull requests; and
- action policy admits organization-owned actions and only the exact audited
  external actions used by the workflow, with full-length SHA pinning required
  for every action. The bootstrap workflow currently uses no organization-owned
  action.

Zero approvals is intentional, not a waiver: the repository currently has one
authorized owner, who cannot supply an independent approval of their own change.
The pull-request boundary, required check, ownership routing, and conversation
resolution remain mandatory. Review requirements must increase when another
authorized reviewer becomes available; they must never be satisfied by fake or
self approval.

## Verification procedure

After any settings or workflow change:

1. Run the public-CI verifier and CI test suite.
2. Inspect Actions settings for read-only default workflow permission, disabled
   workflow PR approval, and no public-validation self-hosted route.
3. Inspect the active main ruleset against every field in the desired-state
   record.
4. Open a pull request from a public fork that changes only a harmless fixture
   input or documentation line.
5. Confirm public-validation runs on a GitHub-hosted runner, receives no
   secrets, emits no repository artifact, and passes.
6. Confirm a deliberately policy-violating workflow mutation fails in the
   verifier before it can alter the trust boundary.
7. Close the test pull request without merging and preserve its URL and workflow
   run as task evidence.

Failure of any step keeps repository bootstrap uncertified.
