"""Fail-closed local fast-forward promotion for one verified commit."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

FULL_SHA = re.compile(r"[0-9a-f]{40}")


class PromotionPolicyError(RuntimeError):
    """Raised when a candidate cannot be promoted without weakening policy."""


@dataclass(frozen=True)
class PromotionPlan:
    remote: str
    source_branch: str
    source_sha: str
    verified_sha: str
    target_branch: str
    target_sha_before: str

    def as_json(self, *, promoted: bool) -> str:
        payload = asdict(self)
        payload["promoted"] = promoted
        payload["target_sha_after"] = self.source_sha if promoted else None
        return json.dumps(payload, indent=2, sort_keys=True)


class Git:
    def __init__(self, root: Path) -> None:
        self.root = root

    def run(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                ["git", *arguments],
                cwd=self.root,
                check=check,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as error:
            detail = (error.stderr or error.stdout or "no diagnostic").strip()
            command = " ".join(arguments)
            raise PromotionPolicyError(f"git {command} failed: {detail}") from error

    def output(self, *arguments: str) -> str:
        return self.run(*arguments).stdout.strip()


def remote_branch_sha(git: Git, remote: str, branch: str) -> str:
    line = git.output("ls-remote", "--exit-code", remote, f"refs/heads/{branch}")
    fields = line.split()
    if len(fields) != 2 or fields[1] != f"refs/heads/{branch}" or FULL_SHA.fullmatch(fields[0]) is None:
        raise PromotionPolicyError(f"remote {branch} did not resolve to one full commit SHA")
    return fields[0]


def build_plan(
    root: Path,
    *,
    verified_sha: str,
    source_branch: str | None = None,
    target_branch: str = "main",
    remote: str = "origin",
) -> PromotionPlan:
    if target_branch != "main":
        raise PromotionPolicyError("the authorized target branch is main")
    if remote != "origin":
        raise PromotionPolicyError("the authorized Git remote is origin")
    if FULL_SHA.fullmatch(verified_sha) is None:
        raise PromotionPolicyError("verified SHA must be a full lowercase 40-character commit SHA")

    git = Git(root)
    if git.output("status", "--porcelain=v1"):
        raise PromotionPolicyError("the repository must be clean before promotion")

    current_branch = git.output("branch", "--show-current")
    source = source_branch or current_branch
    if current_branch != source:
        raise PromotionPolicyError("the source branch must be checked out")
    if not source.startswith("codex/"):
        raise PromotionPolicyError("the source branch must begin with codex/")

    source_sha = git.output("rev-parse", "HEAD")
    if source_sha != verified_sha:
        raise PromotionPolicyError("the checked-out commit does not equal the caller-recorded verified SHA")

    git.run("fetch", "--prune", remote)
    target_sha = git.output("rev-parse", f"refs/remotes/{remote}/{target_branch}")
    if source_sha == target_sha:
        raise PromotionPolicyError("the verified commit is already the remote main commit")
    ancestry = git.run("merge-base", "--is-ancestor", target_sha, source_sha, check=False)
    if ancestry.returncode != 0:
        raise PromotionPolicyError("the verified commit is not a fast-forward descendant of remote main")
    if git.output("rev-list", "--merges", f"{target_sha}..{source_sha}"):
        raise PromotionPolicyError("the promotion range contains a merge commit")

    return PromotionPlan(
        remote=remote,
        source_branch=source,
        source_sha=source_sha,
        verified_sha=verified_sha,
        target_branch=target_branch,
        target_sha_before=target_sha,
    )


def promote(root: Path, plan: PromotionPlan) -> None:
    git = Git(root)
    if git.output("status", "--porcelain=v1"):
        raise PromotionPolicyError("the repository became dirty after preflight")
    if git.output("branch", "--show-current") != plan.source_branch:
        raise PromotionPolicyError("the source branch is no longer checked out")
    if git.output("rev-parse", "HEAD") != plan.source_sha:
        raise PromotionPolicyError("the source branch changed after preflight")
    if plan.verified_sha != plan.source_sha:
        raise PromotionPolicyError("the plan no longer identifies the verified source commit")
    if remote_branch_sha(git, plan.remote, plan.target_branch) != plan.target_sha_before:
        raise PromotionPolicyError("remote main changed after preflight")

    git.run("switch", plan.target_branch)
    git.run("pull", "--ff-only", plan.remote, plan.target_branch)
    if git.output("rev-parse", "HEAD") != plan.target_sha_before:
        raise PromotionPolicyError("local main did not synchronize exactly to preflighted origin/main")

    git.run("merge", "--ff-only", plan.source_sha)
    if git.output("rev-parse", "HEAD") != plan.source_sha:
        raise PromotionPolicyError("local fast-forward did not preserve the verified commit")
    if git.output("status", "--porcelain=v1"):
        raise PromotionPolicyError("the repository became dirty during local fast-forward")

    git.run("push", plan.remote, plan.target_branch)
    git.run("fetch", "--prune", plan.remote)
    local_sha = git.output("rev-parse", f"refs/heads/{plan.target_branch}")
    tracked_sha = git.output("rev-parse", f"refs/remotes/{plan.remote}/{plan.target_branch}")
    observed_sha = remote_branch_sha(git, plan.remote, plan.target_branch)
    if {local_sha, tracked_sha, observed_sha} != {plan.source_sha}:
        raise PromotionPolicyError("local main and origin/main do not identify the verified commit after push")
