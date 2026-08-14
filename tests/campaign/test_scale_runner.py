from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "scale_runner_under_test",
    ROOT / "tools" / "campaigns" / "run_100k_qualification.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the scale runner")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class ScaleRunnerTests(unittest.TestCase):
    def test_official_runner_rejects_ephemeral_external_roots(self) -> None:
        for path in (
            Path("/tmp/scale-evidence"),
            Path("/var/tmp/scale-state"),
        ):
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(RuntimeError, "durable external storage"),
            ):
                RUNNER._require_durable_external(path, "qualification artifact")
        RUNNER._require_durable_external(
            Path("/srv/strling-regex-conformance/evidence"), "qualification artifact"
        )

    def test_forced_worker_kill_uses_windows_process_api(self) -> None:
        process = Mock()
        process.pid = 1234
        with patch.object(RUNNER.os, "name", "nt"):
            RUNNER._kill_forced_worker(process)
        process.kill.assert_called_once_with()

    def test_shared_provider_names_remain_selection_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            worker = RUNNER.CertifiedScaleWorker(Path(temporary), "development")
            try:
                expected = {
                    "mysql-regex",
                    "pcre2-dfa",
                    "pcre2-ordinary",
                    "python-re",
                }
                self.assertEqual(set(worker.providers), expected)
                self.assertEqual(set(worker.managers), expected)
                self.assertEqual(
                    len({id(item) for item in worker.managers.values()}), 4
                )
                self.assertEqual(
                    worker.providers["pcre2-dfa"].descriptor.name,
                    worker.providers["pcre2-ordinary"].descriptor.name,
                )
                self.assertEqual(worker.ready, {})
            finally:
                worker.close()


if __name__ == "__main__":
    unittest.main()
