from __future__ import annotations

from contextlib import redirect_stderr
from io import StringIO
import hashlib
import os
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from support import ROOT

HARNESS = runpy.run_path(str(ROOT / "tools" / "adapters" / "certify_minimal.py"))
adapter_process_limits = HARNESS["_adapter_process_limits"]
report_failure = HARNESS["_report_failure"]
adapter_failure_code = HARNESS["_adapter_failure_code"]
run_adapter_process_attempts = HARNESS["_run_adapter_process_attempts"]


def execution(*, exit_code: int, stderr: bytes = b"") -> SimpleNamespace:
    value = SimpleNamespace(
        outcome="completed",
        exit_code=exit_code,
        stderr=stderr,
    )
    value.to_dict = lambda: {
        "outcome": value.outcome,
        "exit_code": value.exit_code,
        "stderr_sha256": hashlib.sha256(value.stderr).hexdigest(),
    }
    return value


class MinimalAdapterCertificationTests(unittest.TestCase):
    def test_mysql_transient_identity_failure_retries_once_and_preserves_both_attempts(self) -> None:
        failed = execution(
            exit_code=2,
            stderr=b'{"error":{"code":"runtime-identity-failed","message":"query failed"},"ok":false}\n',
        )
        succeeded = execution(exit_code=0)
        pending = [failed, succeeded]

        selected, attempts = run_adapter_process_attempts("mysql-regex", lambda: pending.pop(0))

        self.assertIs(selected, succeeded)
        self.assertEqual(pending, [])
        self.assertEqual([item["attempt_number"] for item in attempts], [1, 2])
        self.assertEqual([item["selected"] for item in attempts], [False, True])
        self.assertEqual(attempts[0]["failure_code"], "runtime-identity-failed")
        self.assertIsNone(attempts[1]["failure_code"])

    def test_semantic_or_malformed_failures_are_never_retried(self) -> None:
        for selection_key, stderr in (
            ("mysql-regex", b'{"error":{"code":"runtime-identity-mismatch"},"ok":false}\n'),
            ("mysql-regex", b"not-json\n"),
            ("python-re", b'{"error":{"code":"runtime-identity-failed"},"ok":false}\n'),
        ):
            with self.subTest(selection_key=selection_key, stderr=stderr):
                calls = [execution(exit_code=2, stderr=stderr)]
                with self.assertRaises(RuntimeError):
                    run_adapter_process_attempts(selection_key, lambda: calls.pop(0))
                self.assertEqual(calls, [])

    def test_failure_code_requires_exact_machine_readable_adapter_error(self) -> None:
        self.assertEqual(
            adapter_failure_code(
                b'{"error":{"code":"runtime-identity-failed","message":"query failed"},"ok":false}\n'
            ),
            "runtime-identity-failed",
        )
        self.assertIsNone(adapter_failure_code(b'{"error":{"code":3},"ok":false}\n'))
        self.assertIsNone(adapter_failure_code(b'{"error":{"code":"runtime-identity-failed"},"ok":true}\n'))

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
