from __future__ import annotations

from contextlib import redirect_stderr
from io import StringIO
import os
import runpy
import unittest
from unittest.mock import patch

from support import ROOT

HARNESS = runpy.run_path(str(ROOT / "tools" / "adapters" / "certify_minimal.py"))
adapter_process_limits = HARNESS["_adapter_process_limits"]
report_failure = HARNESS["_report_failure"]


class MinimalAdapterCertificationTests(unittest.TestCase):
    def test_failure_reporting_is_machine_readable_and_workflow_safe(self) -> None:
        output = StringIO()
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), redirect_stderr(output):
            report_failure(RuntimeError("line one%\nline two"))

        lines = output.getvalue().splitlines()
        self.assertEqual(
            lines[0],
            '{"diagnostic":"line one%\\nline two","error_type":"RuntimeError","ok":false}',
        )
        self.assertEqual(
            lines[1],
            "::error title=Minimal adapter certification failed::RuntimeError: line one%25%0Aline two",
        )

    def test_mysql_client_does_not_inherit_daemon_memory_or_cpu_limits(self) -> None:
        limits = adapter_process_limits("mysql-regex")
        self.assertIsNone(limits.memory_bytes)
        self.assertIsNone(limits.cpu_time_seconds)
        self.assertEqual(limits.wall_time_ms, 120_000)
        self.assertEqual(limits.stdout_bytes, 4 * 1024 * 1024)
        self.assertEqual(limits.stderr_bytes, 1 * 1024 * 1024)

    def test_native_adapters_retain_exact_memory_and_cpu_containment(self) -> None:
        pcre = adapter_process_limits("pcre2-ordinary")
        python = adapter_process_limits("python-re")
        self.assertEqual((pcre.memory_bytes, pcre.cpu_time_seconds), (4_294_967_296, 120))
        self.assertEqual((python.memory_bytes, python.cpu_time_seconds), (2_147_483_648, 120))


if __name__ == "__main__":
    unittest.main()
