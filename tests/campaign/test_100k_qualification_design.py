from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import os
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

from regex_conformance_scale import (
    ScaleCompileError,
    build_design_report,
    compile_scale_plan,
    reconstruct_request,
    verify_design_report,
    verify_materialized_segments,
    verify_scale_plan,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance


class ScaleQualificationDesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = load_strict(ROOT / "campaigns/compiled/100k-qualification.v1.json")
        cls.segment_temporary = tempfile.TemporaryDirectory()
        cls.external = Path(cls.segment_temporary.name) / "segments"
        materialized = compile_scale_plan(
            ROOT, segment_root=cls.external, _verify=False
        )
        if canonical_bytes(cls.plan) != canonical_bytes(materialized):
            raise AssertionError("checked-in and materialized scale plans disagree")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.segment_temporary.cleanup()

    def test_plan_is_deterministic_closed_balanced_and_representative(self) -> None:
        again = compile_scale_plan(ROOT, _verify=False)
        self.assertEqual(canonical_bytes(self.plan), canonical_bytes(again))
        verify_scale_plan(ROOT, self.plan)
        self.assertEqual(
            self.plan["denominator"],
            {
                "candidate_count": 100000,
                "excluded_count": 0,
                "included_count": 100000,
                "invalid_count": 0,
                "unresolved_count": 0,
            },
        )
        self.assertEqual(len(self.plan["shards"]), 402)
        self.assertEqual(
            sum(item["logical_execution_count"] for item in self.plan["shards"]),
            100000,
        )
        self.assertTrue(
            all(
                1 <= item["logical_execution_count"] <= 250
                for item in self.plan["shards"]
            )
        )
        distribution = self.plan["workload_distribution"]
        base_counts = [
            item["logical_execution_count"]
            for item in distribution["base_logical_templates"]
        ]
        self.assertEqual(len(base_counts), 26)
        self.assertLessEqual(max(base_counts) - min(base_counts), 1)
        self.assertEqual(
            {item["key"] for item in distribution["profiles"]},
            {"mysql-regex", "pcre2-dfa", "pcre2-ordinary", "python-re"},
        )
        self.assertEqual(
            {item["key"] for item in distribution["categories"]},
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
        self.assertTrue(
            all(
                item["logical_execution_count"] > 0
                for item in distribution["categories"]
            )
        )
        self.assertFalse(self.plan["classification"]["normative_authority"])
        self.assertFalse(self.plan["classification"]["semantic_authority"])

    def test_materialized_segments_are_exact_external_and_reconstruct_requests(
        self,
    ) -> None:
        verify_materialized_segments(ROOT, self.plan, self.external)
        files = sorted(
            (self.external / "logical-execution-segments" / "sha256").glob("*.json")
        )
        self.assertEqual(len(files), 402)
        self.assertGreater(sum(path.stat().st_size for path in files), 20_000_000)
        first = load_strict(files[0])
        record = first["logical_executions"][0]
        base = load_strict(
            ROOT / "campaigns/compiled/small-scale-qualification.v1.json"
        )
        base_by_id = {
            item["logical_execution_id"]: item for item in base["logical_executions"]
        }
        request = reconstruct_request(
            self.plan["campaign_id"],
            record,
            base_by_id[record["base_logical_execution_id"]],
        )
        validate_instance(
            request,
            load_strict(ROOT / "schemas/json/adapter-request.schema.json"),
            source="reconstructed 100K request",
        )
        self.assertEqual(request["correlation_id"], record["logical_execution_id"])
        self.assertIn(self.plan["campaign_id"], request["trace_reference"])

    def test_segment_corruption_and_indirection_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            external = base / "segments"
            shutil.copytree(self.external, external)
            reference = self.plan["shards"][0]
            path = external / reference["relative_path"]
            original = path.read_bytes()
            path.write_bytes(original[:-1])
            with self.assertRaisesRegex(ScaleCompileError, "size differs"):
                verify_materialized_segments(ROOT, self.plan, external)
            path.write_bytes(original)
            target = base / "indirect"
            target.mkdir()
            path.unlink()
            path.symlink_to(target / path.name)
            (target / path.name).write_bytes(original)
            with self.assertRaisesRegex(
                ScaleCompileError, "escapes its root|direct regular file"
            ):
                verify_materialized_segments(ROOT, self.plan, external)

        with tempfile.TemporaryDirectory() as temporary:
            external = Path(temporary) / "segments"
            shutil.copytree(self.external, external)
            directory = external / "logical-execution-segments" / "sha256"
            (directory / "unmanifested").write_text("not evidence", encoding="utf-8")
            with self.assertRaisesRegex(ScaleCompileError, "unmanifested"):
                verify_materialized_segments(ROOT, self.plan, external)

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            external = base / "segments"
            shutil.copytree(self.external, external)
            reference = self.plan["shards"][0]
            path = external / reference["relative_path"]
            source = base / "hard-linked-segment.json"
            path.replace(source)
            os.link(source, path)
            with self.assertRaisesRegex(ScaleCompileError, "hard-linked"):
                verify_materialized_segments(ROOT, self.plan, external)

    def test_plan_report_and_source_substitution_fail_closed(self) -> None:
        report = build_design_report(ROOT, self.plan)
        verify_design_report(ROOT, self.plan, report)
        forged_plan = deepcopy(self.plan)
        forged_report = deepcopy(report)
        forged_id = f"{self.plan['campaign_manifest_id'][:-64]}{'0' * 64}"
        forged_plan["campaign_manifest_id"] = forged_id
        forged_report["campaign_manifest_id"] = forged_id
        with self.assertRaisesRegex(ScaleCompileError, "identities disagree"):
            verify_design_report(ROOT, forged_plan, forged_report)

        divergent_report = deepcopy(report)
        divergent_report["shard_count"] += 1
        with self.assertRaises(ScaleCompileError):
            verify_design_report(ROOT, self.plan, divergent_report)

        substituted = deepcopy(self.plan)
        substituted["shards"][0]["sha256"] = "0" * 64
        with self.assertRaises(ScaleCompileError):
            verify_scale_plan(ROOT, substituted)

        traversal = deepcopy(self.plan)
        traversal["source_digests"] = dict(traversal["source_digests"])
        traversal["source_digests"]["../../../../etc/hosts"] = "0" * 64
        with self.assertRaisesRegex(ScaleCompileError, "unsafe or absent"):
            verify_scale_plan(ROOT, traversal)

    def test_frozen_base_digest_and_external_storage_boundary_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "repository"
            shutil.copytree(
                ROOT,
                fixture,
                ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", "*.pyc"),
            )
            base = fixture / "campaigns/compiled/small-scale-qualification.v1.json"
            base.write_bytes(base.read_bytes() + b" ")
            with self.assertRaisesRegex(ScaleCompileError, "base campaign digest"):
                compile_scale_plan(fixture, _verify=False)

        inside = ROOT / "reports" / "scale" / "forbidden-segments"
        with self.assertRaisesRegex(ScaleCompileError, "outside Git"):
            compile_scale_plan(ROOT, segment_root=inside, _verify=False)
        self.assertFalse(inside.exists())


if __name__ == "__main__":
    unittest.main()
