from __future__ import annotations

import runpy
import unittest

from support import ROOT

HARNESS = runpy.run_path(str(ROOT / "tools" / "adapters" / "certify_minimal.py"))
adapter_process_limits = HARNESS["_adapter_process_limits"]


class MinimalAdapterCertificationTests(unittest.TestCase):
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
