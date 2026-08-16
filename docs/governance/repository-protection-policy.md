# Repository Delivery and Public CI Policy

This policy implements the program's disposable public-validation trust zone and
verified local fast-forward promotion boundary. It is controlled by the
accepted disposable-validation, least-privilege automation, and verified
fast-forward promotion decisions and by sections 21 and 22 of the Foundation
Specification. The existing filename is retained as a stable documentation and
tooling path; this policy does not require GitHub branch protection.

## Public contribution boundary

The public-validation workflow is the only public contribution workflow at
repository bootstrap. Its source-validation job runs external pull requests,
`main` pushes, and manual validation events exclusively on GitHub-hosted
ubuntu-24.04. A separate job realizes the three minimal certified environments
on `main` pushes and manual events after source validation; it never runs pull
request code. Both jobs use
read-only repository permission and retain no checkout credential. They have no
secret reference, OIDC permission, artifact upload, publication step,
reusable-workflow handoff, privileged trigger, or self-hosted runner route.

The workflow validates untrusted source. Its outputs are never empirical
production evidence, trusted executables, reusable environment inputs, or
publication authority. Ephemeral certification evidence is destroyed with the
hosted worker after its digest and compact result are emitted to the job log. A
future protected evidence workflow must be a separate trust zone with local
admission; it may not extend or call this workflow across the boundary.

The public-CI verifier makes this contract executable and fail-closed. The CI
dependency lock pins exact Linux wheels by SHA-256. Every action is pinned to a
full commit SHA and recorded with its audited release in the machine-readable
policy.

## Program-owned delivery boundary

Program-owned changes use a dedicated local `codex/**` branch and do not use a
pull request. Safety is established before promotion:

- satisfy the task objective and all applicable positive, negative, boundary,
  fault, regression, structural, security, determinism, and integration checks;
- inspect the complete diff and exclude unrelated changes, secrets, caches,
  runtime state, execution spools, and generated junk;
- create one substantive commit and record its full 40-character SHA;
- require a clean working tree and a fast-forward descendant of current
  `origin/main`, with no merge commit in the promotion range;
- synchronize local `main` using `git pull --ff-only`, then integrate only with
  `git merge --ff-only`;
- push local `main` normally, never by force; and
- fetch again and require the local, remote-tracking, and observed remote main
  SHAs to equal the verified commit.

The working branch need not be pushed. GitHub pull-request approval,
conversation resolution, rulesets, legacy branch protection, browser
administration, and Administration:write credentials are not prerequisites for
ordinary program delivery. If a real existing remote rule rejects the normal
push, stop and report the specific restriction; do not invent a workaround.

The repository currently has one authorized promotion authority. The verified
fast-forward promotion policy must be reviewed if authority becomes multi-party,
public contributors enter the trusted
promotion path, a later task independently requires server enforcement, or a
real remote restriction changes the delivery boundary.

## Verification and promotion procedure

After completing a coherent repository-changing task:

1. Run every affected local verifier, test, lint, security, reproducibility,
   generated-artifact, and integration check.
2. Inspect `git status`, the complete diff, and the exact staged diff; commit
   only the coherent verified task result with a substantive subject.
3. Record the exact verified commit: `VERIFIED_SHA=$(git rev-parse HEAD)`.
4. Run `python tools/ci/promote_verified.py --verified-sha "$VERIFIED_SHA"
   --dry-run` and inspect the JSON plan.
5. Run the same command without `--dry-run`. It fetches origin, switches to
   `main`, pulls with `--ff-only`, merges the verified SHA with `--ff-only`,
   pushes `main`, fetches again, and verifies all main SHAs.
6. Independently compare `git rev-parse main`, `git rev-parse origin/main`, and
   `git ls-remote origin refs/heads/main` with the recorded verified SHA.
7. Confirm the resulting main public-validation run used the disposable hosted
   runner, requested no secrets or write permission, and produced no artifact.
8. Update canonical Notion evidence only after repository and remote state agree.

Any failure keeps the task incomplete. The promotion tool deliberately surfaces
Git's remote rejection diagnostic so a real server-side restriction can be
reported without bypassing it.
