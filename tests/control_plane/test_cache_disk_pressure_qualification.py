from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "control-plane" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_control_plane.cache_manager import CacheManager, FilesystemCacheProvider
from regex_conformance_control_plane.cache_models import CacheEntry, EvictionPolicy
from regex_conformance_control_plane.disk_pressure_qualification import (
    OBSERVED_AT,
    build_cache_disk_pressure_reference_report,
)
from regex_conformance_schema.jsonio import load_strict


SCHEMA = ROOT / "schemas" / "json" / "cache-disk-pressure-qualification.schema.json"
REPORT = ROOT / "reports" / "scale" / "cache-disk-pressure-qualification.json"


class CacheDiskPressureQualificationTests(unittest.TestCase):
    def test_reference_report_is_deterministic_schema_valid_and_matches_tracked(self) -> None:
        first = build_cache_disk_pressure_reference_report(ROOT)
        second = build_cache_disk_pressure_reference_report(ROOT)
        self.assertEqual(first, second)
        Draft202012Validator(
            load_strict(SCHEMA),
            format_checker=FormatChecker(),
        ).validate(first)
        self.assertEqual(load_strict(REPORT), first)

        claimed_digest = first["qualification_digest_sha256"]
        digest_input = dict(first)
        del digest_input["qualification_digest_sha256"]
        self.assertEqual(hashlib.sha256(rfc8785.dumps(digest_input)).hexdigest(), claimed_digest)

    def test_report_binds_every_source_and_covers_every_required_invariant(self) -> None:
        report = build_cache_disk_pressure_reference_report(ROOT)
        for binding in report["source_bindings"]:
            self.assertEqual(
                hashlib.sha256((ROOT / binding["path"]).read_bytes()).hexdigest(),
                binding["sha256"],
            )
        case_keys = {item["case_key"] for item in report["cases"]}
        self.assertEqual(report["summary"]["passed_case_count"], len(case_keys))
        self.assertTrue(all(item["status"] == "passed" for item in report["cases"]))
        self.assertTrue(all(item["status"] == "passed" for item in report["invariants"]))
        self.assertTrue(
            all(set(item["case_keys"]) <= case_keys for item in report["invariants"])
        )
        self.assertFalse(report["classification"]["docker_used"])
        self.assertFalse(report["classification"]["external_evidence_mutated"])
        self.assertFalse(report["classification"]["target_behavior"])
        self.assertTrue(report["classification"]["simulated_disk_pressure"])
        self.assertEqual(
            report["cache_churn"],
            {
                "cancelled_candidate_count": 1,
                "cancelled_cleanup_count": 1,
                "cleanup_report_count": 7,
                "completed_cleanup_count": 4,
                "executed_plan_actual_reclaim_bytes": 24_576,
                "executed_plan_expected_reclaim_bytes": 32_768,
                "failed_deletion_count": 1,
                "partial_cleanup_count": 1,
                "protected_exclusion_count": 3,
                "provider_divergence_exclusion_count": 1,
                "refused_cleanup_count": 1,
                "successful_deletion_count": 6,
            },
        )

    def test_schema_rejects_authority_or_target_behavior_forgery(self) -> None:
        validator = Draft202012Validator(load_strict(SCHEMA), format_checker=FormatChecker())
        report = build_cache_disk_pressure_reference_report(ROOT)
        for key in ("canonical_authority", "docker_used", "external_evidence_mutated", "target_behavior"):
            forged = json.loads(json.dumps(report))
            forged["classification"][key] = True
            self.assertTrue(list(validator.iter_errors(forged)), key)

    def test_filesystem_cleanup_is_root_bounded_and_preserves_committed_evidence(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary)

            class Clock:
                def now(self):
                    from datetime import datetime

                    return datetime.fromisoformat("2026-08-14T22:00:30+00:00")

            class Ids:
                def new_cleanup_id(self) -> str:
                    return "opid:v1:cache-cleanup:u7:019fff29-c7c4-7422-a341-9ae9af130001"

                def new_transfer_id(self) -> str:
                    raise AssertionError

            cache_root = root / "cache"
            evidence_root = root / "immutable-evidence"
            evidence_root.mkdir()
            evidence = evidence_root / "committed.json"
            evidence.write_bytes(b"committed immutable evidence")
            evidence_before = hashlib.sha256(evidence.read_bytes()).hexdigest()

            provider = FilesystemCacheProvider(cache_root, clock=Clock())
            cache_file = cache_root / "objects" / "reclaim.bin"
            cache_file.parent.mkdir(parents=True)
            cache_file.write_bytes(b"x" * 4096)
            metadata = cache_file.stat()
            reclaimable, accounting_basis = provider._allocated_bytes(metadata)
            entry = CacheEntry(
                cache_key="filesystem-reclaim",
                kind="artifact",
                content_id=(
                    "rcid:v1:artifact-revision:h:jcs-sha256-v1:"
                    + hashlib.sha256(cache_file.read_bytes()).hexdigest()
                ),
                sha256=hashlib.sha256(cache_file.read_bytes()).hexdigest(),
                relative_path="objects/reclaim.bin",
                size_bytes=metadata.st_size,
                reclaimable_bytes=reclaimable,
                accounting_basis=accounting_basis,
                provider_name="filesystem-cache",
                retention_class="reacquirable",
                pinned=False,
                active_leases=(),
                future_dependencies=(),
                dependencies=(),
                last_used_at="2026-08-14T20:00:00Z",
                reacquisition_time_seconds=1,
                reacquisition_cost_microunits=0,
                reconstruction_difficulty=1,
                upstream_fragility=1,
                verification_status="verified",
                verified_at=OBSERVED_AT,
                observed_at=OBSERVED_AT,
                source="bounded-filesystem-test",
                staleness_seconds=0,
            )

            manager = CacheManager(clock=Clock(), id_generator=Ids())
            inventory = manager.inventory((entry,), observed_at=OBSERVED_AT)
            policy = EvictionPolicy(100, 10, 5, 3, 20, 30, 10_000, 300)
            plan = manager.plan_cleanup(
                inventory,
                manager.reconcile(inventory, provider),
                reclaimable,
                policy,
            )
            report = manager.execute_cleanup(plan, inventory, provider)

            self.assertFalse(cache_file.exists())
            self.assertTrue(evidence.exists())
            self.assertEqual(hashlib.sha256(evidence.read_bytes()).hexdigest(), evidence_before)
            self.assertIn(report.state, {"completed", "partial"})
            self.assertLessEqual(report.actual_reclaim_bytes, reclaimable)
            self.assertFalse(report.registry_authority_mutated)


if __name__ == "__main__":
    unittest.main()
