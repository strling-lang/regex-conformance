# Repository Delivery and Public CI Policy

This policy implements the program's bounded hosted-integrity trust zone and
locally certified fast-forward promotion boundary. It is controlled by the
accepted disposable-validation, least-privilege automation, and verified
fast-forward promotion decisions and by sections 21 and 22 of the Foundation
Specification. The existing filename is retained as a stable documentation and
tooling path; this policy does not require GitHub branch protection.

## Public contribution boundary

The public-validation workflow is the only public contribution workflow at
repository bootstrap. Its bounded job runs external pull requests, `main`
pushes, and manual validation events exclusively on GitHub-hosted ubuntu-24.04.
It uses read-only repository permission and retains no checkout credential. It has no
secret reference, OIDC permission, artifact upload, publication step,
reusable-workflow handoff, privileged trigger, or self-hosted runner route.

The workflow validates untrusted structure and independently verifies a tracked
local certification envelope on `main` and manual exact-revision runs. It does
not repeat expensive deterministic generation, environment realization,
adapter qualification, or campaign execution. Its outputs are never empirical
production evidence, trusted executables, reusable environment inputs, or
publication authority.

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
- create one substantive source commit, certify it locally from a clean tree,
  then create one manifest-only certification-envelope commit;
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
3. Run `python tools/ci/certify_local.py --root .`, record its certification
   root, stage only its manifest, and commit the certification envelope.
4. Record the exact envelope SHA and run `python tools/ci/promote_verified.py
   --verified-sha "$VERIFIED_SHA" --local-certification-manifest
   certification/local/current-local-certification.v1.json
   --local-certification-root "$LOCAL_CERTIFICATION_ROOT" --dry-run`.
5. Run the same command without `--dry-run`. It fetches origin, switches to
   `main`, pulls with `--ff-only`, merges the verified SHA with `--ff-only`,
   pushes `main`, fetches again, and verifies all main SHAs.
6. Independently compare `git rev-parse main`, `git rev-parse origin/main`, and
   `git ls-remote origin refs/heads/main` with the recorded verified SHA.
7. Confirm the resulting bounded hosted-integrity run verified the exact
   envelope and local certification root, used the disposable hosted runner,
   requested no secrets or write permission, and produced no artifact.
8. Update canonical Notion evidence only after repository and remote state agree.

Any failure keeps the task incomplete. The promotion tool deliberately surfaces
Git's remote rejection diagnostic so a real server-side restriction can be
reported without bypassing it.

The complete trust boundary and non-self-referential envelope are documented in
the [local certification architecture](../architecture/local-authoritative-certification.md).
