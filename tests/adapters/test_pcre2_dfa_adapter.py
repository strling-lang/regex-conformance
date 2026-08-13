from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from support import ROOT, manifest, octets, request, validate_schema
from regex_conformance_adapters.errors import AdapterError
from regex_conformance_adapters.pcre2_dfa import Pcre2DfaBackend
from regex_conformance_adapters.qualification_manifest import load_qualification_manifest
from regex_conformance_adapters.server import AdapterServer


def system_pcre2() -> tuple[Path, str] | None:
    executable = shutil.which("pcre2-config")
    candidates = sorted(Path("/usr/lib").glob("**/libpcre2-8.so.*"))
    if executable is None or not candidates:
        return None
    version = subprocess.check_output((executable, "--version"), text=True).strip()
    return candidates[0].resolve(), version


class Pcre2DfaAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        runtime = system_pcre2()
        if runtime is None:
            raise unittest.SkipTest("system PCRE2 8-bit shared library is unavailable")
        library, version = runtime
        package = replace(
            manifest("pcre2-dfa"),
            runtime_constraints=(("engine-version", version), ("matcher-api", "pcre2-dfa-match-8")),
        )
        cls.library = library
        cls.version = version
        cls.backend = Pcre2DfaBackend(package, library)

    def response(self, value):
        result = AdapterServer(self.backend).execute(value)
        validate_schema(result, "adapter-response.schema.json")
        return result

    def test_governed_manifest_self_verifies_exact_sources_and_bindings(self) -> None:
        package = load_qualification_manifest(ROOT, "pcre2-dfa")
        self.assertEqual(package.profile_id, self.backend.manifest.profile_id)
        self.assertEqual(package.target_release_id, self.backend.manifest.target_release_id)
        self.assertEqual(
            package.runtime_constraints,
            (("engine-version", "10.47"), ("matcher-api", "pcre2-dfa-match-8")),
        )
        self.assertIn("matcher-dfa", package.capabilities)

    def test_runtime_loader_rejects_a_symbolic_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                "adapters/python",
                "adapters/qualification-manifests",
                "protocol",
                "schemas/json",
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(ROOT / relative, destination)
            source = (
                root
                / "adapters/python/regex_conformance_adapters/pcre2_dfa.py"
            )
            outside = root / "outside.py"
            outside.write_text("pass\n", encoding="utf-8")
            source.unlink()
            source.symlink_to(outside)
            with self.assertRaisesRegex(AdapterError, "adapter-source-path-unsafe"):
                load_qualification_manifest(root, "pcre2-dfa")

    def test_dfa_exposes_longest_first_alternatives_with_native_spans(self) -> None:
        result = self.response(
            request(self.backend.manifest, pattern=octets(b"a|aa"), subject=octets(b"aa"))
        )
        matches = result["observation"]["matches"]
        self.assertEqual(
            [(item["span"]["start"], item["span"]["end"]) for item in matches],
            [(0, 2), (0, 1)],
        )
        self.assertTrue(all(item["span"]["basis"] == "octet" for item in matches))
        self.assertTrue(all(len(item["captures"]) == 1 for item in matches))
        self.assertIn(
            {"field": "matches.captures.subgroups", "reason": "not-exposed"},
            result["observation"]["absences"],
        )

    def test_compile_rejection_is_a_completed_target_observation(self) -> None:
        result = self.response(
            request(self.backend.manifest, pattern=octets(b"("), subject=octets(b""))
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["observation"]["compile_status"], "rejected")
        self.assertEqual(result["observation"]["native_error"]["class"], "pcre2_compile_error")

    def test_full_match_is_anchored_at_both_boundaries(self) -> None:
        matched = self.response(
            request(
                self.backend.manifest,
                operation="full-match",
                pattern=octets(b"a+"),
                subject=octets(b"aaa"),
            )
        )
        unmatched = self.response(
            request(
                self.backend.manifest,
                operation="full-match",
                pattern=octets(b"a+"),
                subject=octets(b"aaab"),
            )
        )
        self.assertEqual(matched["observation"]["match_state"], "match")
        self.assertEqual(unmatched["observation"]["match_state"], "no-match")

    def test_capture_extraction_and_noninitial_occurrence_fail_explicitly(self) -> None:
        unsupported = self.response(
            request(
                self.backend.manifest,
                operation="capture-extraction",
                pattern=octets(b"(a)"),
                subject=octets(b"a"),
            )
        )
        self.assertEqual(unsupported["status"], "unsupported")
        self.assertEqual(unsupported["failure"]["code"], "operation-unsupported")

        occurrence = request(
            self.backend.manifest,
            pattern=octets(b"a"),
            subject=octets(b"a"),
        )
        occurrence["initial_state"]["occurrence"] = 2
        rejected = self.response(occurrence)
        self.assertEqual(rejected["status"], "unsupported")
        self.assertEqual(rejected["failure"]["code"], "occurrence-unsupported")

    def test_runtime_identity_requires_exact_manifest_facets(self) -> None:
        wrong_api = replace(
            manifest("pcre2-dfa"),
            runtime_constraints=(("engine-version", self.version), ("matcher-api", "ordinary")),
        )
        backend = Pcre2DfaBackend(wrong_api, self.library)
        result = AdapterServer(backend).execute(
            request(backend.manifest, pattern=octets(b"a"), subject=octets(b"a"))
        )
        validate_schema(result, "adapter-response.schema.json")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure"]["code"], "runtime-identity-mismatch")

        extra = replace(
            manifest("pcre2-dfa"),
            runtime_constraints=(
                ("engine-version", self.version),
                ("matcher-api", "pcre2-dfa-match-8"),
                ("unexpected", "value"),
            ),
        )
        backend = Pcre2DfaBackend(extra, self.library)
        result = AdapterServer(backend).execute(
            request(backend.manifest, pattern=octets(b"a"), subject=octets(b"a"))
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure"]["code"], "runtime-identity-mismatch")


if __name__ == "__main__":
    unittest.main()
