from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "tools" / "ci"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from promotion_policy import PromotionPolicyError, PromotionPlan, build_plan, promote


class PromotionArgumentTests(unittest.TestCase):
    def test_non_main_target_is_rejected_before_git_access(self) -> None:
        with self.assertRaisesRegex(PromotionPolicyError, "target branch"):
            build_plan(Path("/does/not/exist"), verified_sha="a" * 40, target_branch="release")

    def test_non_origin_remote_is_rejected_before_git_access(self) -> None:
        with self.assertRaisesRegex(PromotionPolicyError, "Git remote"):
            build_plan(Path("/does/not/exist"), verified_sha="a" * 40, remote="upstream")

    def test_abbreviated_verified_sha_is_rejected_before_git_access(self) -> None:
        with self.assertRaisesRegex(PromotionPolicyError, "full lowercase"):
            build_plan(Path("/does/not/exist"), verified_sha="a" * 12)


class PromotionMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.origin = self.base / "origin.git"
        self.work = self.base / "work"
        self.git("init", "--bare", str(self.origin), cwd=self.base)
        self.git("init", "--initial-branch=main", str(self.work), cwd=self.base)
        self.git("config", "user.name", "Promotion Test", cwd=self.work)
        self.git("config", "user.email", "promotion@example.invalid", cwd=self.work)
        (self.work / "README.md").write_text("seed\n", encoding="utf-8")
        self.git("add", "README.md", cwd=self.work)
        self.git("commit", "-m", "seed", cwd=self.work)
        self.git("remote", "add", "origin", str(self.origin), cwd=self.work)
        self.git("push", "-u", "origin", "main", cwd=self.work)
        self.main_sha = self.output("rev-parse", "HEAD", cwd=self.work)
        self.git("switch", "-c", "codex/example", cwd=self.work)
        (self.work / "change.txt").write_text("verified\n", encoding="utf-8")
        self.git("add", "change.txt", cwd=self.work)
        self.git("commit", "-m", "verified change", cwd=self.work)
        self.source_sha = self.output("rev-parse", "HEAD", cwd=self.work)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def git(*arguments: str, cwd: Path) -> None:
        subprocess.run(["git", *arguments], cwd=cwd, check=True, capture_output=True, text=True)

    @staticmethod
    def output(*arguments: str, cwd: Path) -> str:
        return subprocess.run(
            ["git", *arguments],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def plan(self) -> PromotionPlan:
        return build_plan(self.work, verified_sha=self.source_sha)

    def remote_main(self) -> str:
        return self.output("ls-remote", "origin", "refs/heads/main", cwd=self.work).split()[0]

    def test_plan_does_not_require_pushing_the_working_branch(self) -> None:
        plan = self.plan()
        self.assertEqual(plan.source_sha, self.source_sha)
        remote_source = subprocess.run(
            ["git", "ls-remote", "--exit-code", "origin", "refs/heads/codex/example"],
            cwd=self.work,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(remote_source.returncode, 0)

    def test_wrong_verified_sha_is_rejected(self) -> None:
        with self.assertRaisesRegex(PromotionPolicyError, "caller-recorded"):
            build_plan(self.work, verified_sha="f" * 40)
        self.assertEqual(self.remote_main(), self.main_sha)

    def test_dirty_repository_is_rejected_during_preflight(self) -> None:
        (self.work / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(PromotionPolicyError, "clean"):
            build_plan(self.work, verified_sha=self.source_sha)
        self.assertEqual(self.remote_main(), self.main_sha)

    def test_non_working_branch_source_is_rejected(self) -> None:
        self.git("switch", "main", cwd=self.work)
        with self.assertRaisesRegex(PromotionPolicyError, "codex/"):
            build_plan(self.work, verified_sha=self.main_sha)

    def test_merge_commit_in_promotion_range_is_rejected(self) -> None:
        self.git("switch", "-c", "topic", cwd=self.work)
        (self.work / "topic.txt").write_text("topic\n", encoding="utf-8")
        self.git("add", "topic.txt", cwd=self.work)
        self.git("commit", "-m", "topic", cwd=self.work)
        self.git("switch", "codex/example", cwd=self.work)
        self.git("merge", "--no-ff", "topic", "-m", "merge topic", cwd=self.work)
        merge_sha = self.output("rev-parse", "HEAD", cwd=self.work)
        with self.assertRaisesRegex(PromotionPolicyError, "merge commit"):
            build_plan(self.work, verified_sha=merge_sha)
        self.assertEqual(self.remote_main(), self.main_sha)

    def test_promotion_updates_local_and_remote_main_to_exact_verified_sha(self) -> None:
        plan = self.plan()
        promote(self.work, plan)
        self.assertEqual(self.output("branch", "--show-current", cwd=self.work), "main")
        self.assertEqual(self.output("rev-parse", "main", cwd=self.work), self.source_sha)
        self.assertEqual(self.output("rev-parse", "origin/main", cwd=self.work), self.source_sha)
        self.assertEqual(self.remote_main(), self.source_sha)

    def test_dirty_repository_after_preflight_is_rejected_without_remote_mutation(self) -> None:
        plan = self.plan()
        (self.work / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(PromotionPolicyError, "dirty"):
            promote(self.work, plan)
        self.assertEqual(self.remote_main(), self.main_sha)

    def test_changed_source_after_preflight_is_rejected_without_remote_mutation(self) -> None:
        plan = self.plan()
        (self.work / "change.txt").write_text("changed again\n", encoding="utf-8")
        self.git("add", "change.txt", cwd=self.work)
        self.git("commit", "-m", "unverified change", cwd=self.work)
        with self.assertRaisesRegex(PromotionPolicyError, "changed after preflight"):
            promote(self.work, plan)
        self.assertEqual(self.remote_main(), self.main_sha)

    def test_divergent_local_main_is_rejected_without_remote_mutation(self) -> None:
        plan = self.plan()
        self.git("switch", "main", cwd=self.work)
        (self.work / "local-main.txt").write_text("not remote\n", encoding="utf-8")
        self.git("add", "local-main.txt", cwd=self.work)
        self.git("commit", "-m", "divergent local main", cwd=self.work)
        self.git("switch", "codex/example", cwd=self.work)
        with self.assertRaisesRegex(PromotionPolicyError, "synchronize exactly"):
            promote(self.work, plan)
        self.assertEqual(self.remote_main(), self.main_sha)

    def test_remote_main_race_is_rejected_before_local_integration(self) -> None:
        plan = self.plan()
        self.git("push", "origin", f"{self.source_sha}:refs/heads/main", cwd=self.work)
        with self.assertRaisesRegex(PromotionPolicyError, "remote main changed"):
            promote(self.work, plan)
        self.assertEqual(self.output("branch", "--show-current", cwd=self.work), "codex/example")


if __name__ == "__main__":
    unittest.main()
