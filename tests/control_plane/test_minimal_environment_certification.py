from __future__ import annotations

import os
from pathlib import Path
import runpy
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HARNESS = runpy.run_path(str(ROOT / "tools" / "environments" / "certify_minimal.py"))
exclusive_certification_lock = HARNESS["_exclusive_certification_lock"]
outside_repository = HARNESS["_outside_repository"]
write_compact = HARNESS["_write_compact"]


class MinimalEnvironmentCertificationTests(unittest.TestCase):
    def test_same_state_root_rejects_concurrent_certification_and_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_root = Path(temporary) / "state"
            with exclusive_certification_lock(state_root):
                with self.assertRaisesRegex(RuntimeError, "already active"):
                    with exclusive_certification_lock(state_root):
                        self.fail("the nested lock unexpectedly succeeded")
            with exclusive_certification_lock(state_root):
                pass
            lock_path = state_root.parent / f".{state_root.name}.minimal-certification.lock"
            self.assertTrue(stat.S_ISREG(lock_path.stat().st_mode))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o600)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires no-follow open support")
    def test_symbolic_lock_path_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "state"
            target = root / "target"
            target.write_text("do not modify", encoding="utf-8")
            lock_path = root / ".state.minimal-certification.lock"
            lock_path.symlink_to(target)
            with self.assertRaises(OSError):
                with exclusive_certification_lock(state_root):
                    self.fail("a symbolic lock path unexpectedly succeeded")
            self.assertEqual(target.read_text(encoding="utf-8"), "do not modify")

    def test_external_symbolic_path_into_repository_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            link = Path(temporary) / "repository-reports"
            try:
                link.symlink_to(ROOT / "reports", target_is_directory=True)
            except OSError as error:
                if getattr(error, "winerror", None) != 1314:
                    raise
                subprocess.run(
                    (
                        "cmd",
                        "/d",
                        "/c",
                        "mklink",
                        "/J",
                        str(link),
                        str(ROOT / "reports"),
                    ),
                    check=True,
                    capture_output=True,
                    text=True,
                )
            with self.assertRaisesRegex(ValueError, "outside the Git repository"):
                outside_repository(link / "state", "state root")

    def test_compact_report_boundary_and_temp_symlinks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            external = temporary_root / "outside.json"
            write_compact(external, {"ok": True})
            self.assertEqual(external.read_bytes(), b'{"ok":true}\n')
            with self.assertRaisesRegex(ValueError, "inside reports"):
                write_compact(ROOT / ".codex-disallowed-compact.json", {"ok": True})

            function_globals = write_compact.__globals__
            original_root = function_globals["ROOT"]
            isolated_root = temporary_root / "repository"
            reports = isolated_root / "reports"
            reports.mkdir(parents=True)
            destination = reports / "compact.json"
            target = temporary_root / "do-not-overwrite"
            target.write_text("preserve", encoding="utf-8")
            temporary_report = destination.with_suffix(".json.tmp")
            try:
                temporary_report.symlink_to(target)
            except OSError as error:
                if getattr(error, "winerror", None) != 1314:
                    raise
                os.link(target, temporary_report)
            function_globals["ROOT"] = isolated_root
            try:
                with self.assertRaises(FileExistsError):
                    write_compact(destination, {"ok": True})
            finally:
                function_globals["ROOT"] = original_root
            self.assertEqual(target.read_text(encoding="utf-8"), "preserve")
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
