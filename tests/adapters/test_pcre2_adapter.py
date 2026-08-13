from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import shutil
import subprocess
import unittest

from support import manifest, octets, request, validate_schema
from regex_conformance_adapters.pcre2 import Pcre2Backend
from regex_conformance_adapters.server import AdapterServer


def system_pcre2() -> tuple[Path, str] | None:
    executable = shutil.which("pcre2-config")
    candidates = sorted(Path("/usr/lib").glob("**/libpcre2-8.so.*"))
    if executable is None or not candidates:
        return None
    version = subprocess.check_output((executable, "--version"), text=True).strip()
    return candidates[0].resolve(), version


class Pcre2AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        runtime = system_pcre2()
        if runtime is None:
            raise unittest.SkipTest("system PCRE2 8-bit shared library is unavailable")
        library, version = runtime
        package = replace(manifest("pcre2-ordinary"), runtime_constraints=(("engine-version", version),))
        cls.backend = Pcre2Backend(package, library)

    def response(self, value):
        result = AdapterServer(self.backend).execute(value)
        validate_schema(result, "adapter-response.schema.json")
        return result

    def test_octet_nul_and_native_byte_spans_are_preserved(self) -> None:
        result = self.response(
            request(self.backend.manifest, pattern=octets(b"\x00a"), subject=octets(b"x\x00ay"))
        )
        span = result["observation"]["matches"][0]["span"]
        self.assertEqual((span["start"], span["end"], span["basis"], span["unit_width_bits"]), (1, 3, "octet", 8))

    def test_utf_mode_still_reports_native_octet_offsets(self) -> None:
        result = self.response(
            request(
                self.backend.manifest,
                pattern=octets("😀".encode()),
                subject=octets("A😀B".encode()),
                options=[{"name": "ucp", "value": True}, {"name": "utf", "value": True}],
            )
        )
        span = result["observation"]["matches"][0]["span"]
        self.assertEqual((span["start"], span["end"], span["basis"]), (1, 5, "octet"))

    def test_native_compile_error_remains_completed_target_observation(self) -> None:
        result = self.response(request(self.backend.manifest, pattern=octets(b"("), subject=octets(b"")))
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["observation"]["compile_status"], "rejected")
        self.assertEqual(result["observation"]["native_error"]["class"], "pcre2_compile_error")

    def test_unset_and_empty_captures_remain_distinct(self) -> None:
        result = self.response(
            request(
                self.backend.manifest,
                operation="capture-extraction",
                pattern=octets(b"(a)?(b*)"),
                subject=octets(b""),
                observations=["capture-history", "captures", "match-state", "runtime-identity", "spans"],
            )
        )
        captures = result["observation"]["matches"][0]["captures"]
        self.assertEqual(captures[1]["participation"], "unmatched")
        self.assertIsNone(captures[1]["value"])
        self.assertEqual(captures[2]["participation"], "matched")
        self.assertEqual(captures[2]["value"]["data"], "")

    def test_zero_length_iteration_terminates_and_advances(self) -> None:
        value = request(
            self.backend.manifest,
            operation="find-all",
            pattern=octets(b""),
            subject=octets(b"ab"),
            observations=["captures", "cursor", "match-state", "runtime-identity", "spans"],
        )
        result = self.response(value)
        spans = [item["span"] for item in result["observation"]["matches"]]
        self.assertEqual([(item["start"], item["end"]) for item in spans], [(0, 0), (1, 1), (2, 2)])

    def test_full_match_does_not_rewrite_the_pattern(self) -> None:
        matched = self.response(
            request(self.backend.manifest, operation="full-match", pattern=octets(b"a+"), subject=octets(b"aaa"))
        )
        unmatched = self.response(
            request(self.backend.manifest, operation="full-match", pattern=octets(b"a+"), subject=octets(b"aaab"))
        )
        self.assertEqual(matched["observation"]["match_state"], "match")
        self.assertEqual(unmatched["observation"]["match_state"], "no-match")

    def test_scalar_domain_is_explicitly_unsupported_not_utf8_guessed(self) -> None:
        value = request(self.backend.manifest)
        result = self.response(value)
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["failure"]["code"], "datum-domain-unsupported")


if __name__ == "__main__":
    unittest.main()
