from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_qualification import (
    QualificationCompileError,
    build_coverage_report,
    compile_qualification,
    verify_compiled_qualification,
    verify_coverage_report,
)
from regex_conformance_schema.jsonio import canonical_bytes, canonical_text, load_strict


class SmallScaleQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compiled = compile_qualification(ROOT)

    def test_compilation_is_deterministic_and_denominator_is_closed(self) -> None:
        again = compile_qualification(ROOT)
        self.assertEqual(canonical_bytes(self.compiled), canonical_bytes(again))
        self.assertEqual(
            self.compiled["denominator"],
            {
                "candidate_count": 48,
                "excluded_count": 22,
                "included_count": 26,
                "invalid_count": 0,
                "unresolved_count": 0,
            },
        )
        self.assertEqual(len(self.compiled["shards"]), 5)
        self.assertEqual(
            {item["selection_key"] for item in self.compiled["logical_executions"]},
            {"mysql-regex", "pcre2-dfa", "pcre2-ordinary", "python-re"},
        )
        self.assertFalse(self.compiled["classification"]["normative_authority"])
        self.assertTrue(self.compiled["classification"]["probe_only"])

    def test_coverage_report_exercises_every_required_operational_category(self) -> None:
        report = build_coverage_report(ROOT, self.compiled)
        categories = {item["category"]: item for item in report["categories"]}
        self.assertEqual(
            set(categories),
            {
                "capture",
                "error",
                "iteration",
                "profile-differential",
                "rejection",
                "replacement",
                "success",
                "timeout",
                "unicode",
            },
        )
        self.assertTrue(all(item["logical_execution_count"] > 0 for item in categories.values()))
        self.assertEqual(categories["timeout"]["selection_keys"], ["mysql-regex", "python-re"])
        self.assertEqual(report["added_profile_keys"], ["pcre2-dfa"])
        self.assertFalse(report["classification"]["normative_authority"])
        self.assertFalse(report["classification"]["semantic_authority"])

    def test_requests_preserve_typed_semantics_and_native_limits(self) -> None:
        requests = [item["request"] for item in self.compiled["logical_executions"]]
        self.assertTrue(any(item["operation"]["name"] == "replace-all" for item in requests))
        self.assertTrue(any(item["operation"]["name"] == "capture-extraction" for item in requests))
        self.assertTrue(any(item["limits"]["wall_time_ms"] == 5 for item in requests))
        self.assertTrue(any(item["pattern"]["domain"] == "octets" for item in requests))
        self.assertTrue(any(item["pattern"]["domain"] == "unicode-scalars" for item in requests))
        self.assertTrue(all(item["replacement"] is None or "domain" in item["replacement"] for item in requests))

    def test_request_candidate_and_source_substitution_fail_closed(self) -> None:
        request = deepcopy(self.compiled)
        request["logical_executions"][0]["request"]["limits"]["wall_time_ms"] += 1
        with self.assertRaises(QualificationCompileError):
            verify_compiled_qualification(ROOT, request)

        candidate = deepcopy(self.compiled)
        candidate["candidates"][0]["proof"]["outcome_source"] = "forged"
        with self.assertRaises(QualificationCompileError):
            verify_compiled_qualification(ROOT, candidate)

        source = deepcopy(self.compiled)
        key = sorted(source["source_digests"])[0]
        source["source_digests"][key] = "f" * 64
        with self.assertRaises(QualificationCompileError):
            verify_compiled_qualification(ROOT, source)

    def test_assigned_vector_identity_collision_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "repository"
            shutil.copytree(
                ROOT,
                fixture,
                ignore=shutil.ignore_patterns(
                    ".git", ".venv", "__pycache__", "*.pyc"
                ),
            )
            source = (
                fixture
                / "vectors/definitions/small-scale-qualification.v1.json"
            )
            vectors = load_strict(source)
            vectors["vectors"][1]["vector_id"] = vectors["vectors"][0]["vector_id"]
            source.write_text(canonical_text(vectors), encoding="utf-8")
            with self.assertRaisesRegex(
                QualificationCompileError, "vector IDs contain a collision"
            ):
                compile_qualification(fixture)

    def test_public_report_divergence_and_source_traversal_fail_closed(self) -> None:
        report = build_coverage_report(ROOT, self.compiled)
        report["categories"][0]["logical_execution_count"] += 1
        with self.assertRaises(QualificationCompileError):
            verify_coverage_report(ROOT, self.compiled, report)

        traversal = deepcopy(self.compiled)
        traversal["source_digests"]["../../../../etc/hosts"] = "0" * 64
        with self.assertRaisesRegex(
            QualificationCompileError, "source path is unsafe or absent"
        ):
            verify_compiled_qualification(ROOT, traversal)

    def test_shard_and_denominator_tampering_fail_closed(self) -> None:
        shard = deepcopy(self.compiled)
        shard["shards"][0]["logical_execution_ids"][0] = shard["shards"][1][
            "logical_execution_ids"
        ][0]
        with self.assertRaises(QualificationCompileError):
            verify_compiled_qualification(ROOT, shard)

        denominator = deepcopy(self.compiled)
        denominator["denominator"]["excluded_count"] -= 1
        with self.assertRaises(QualificationCompileError):
            verify_compiled_qualification(ROOT, denominator)


if __name__ == "__main__":
    unittest.main()
