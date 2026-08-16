from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns/python",
    ROOT / "matrix/python",
    ROOT / "scheduler/python",
    ROOT / "schemas/tooling/python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_scale.million_reconciliation import (
    MillionReconciliationError,
    verify_million_final_artifacts,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")


class MillionReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        master_id = f"rcid:v1:campaign-manifest:h:jcs-sha256-v1:{_sha('master')}"
        cls.compiled = SimpleNamespace(
            plan={
                "campaign_manifest_id": master_id,
                "denominator": {"included_count": 1_000_000},
            }
        )
        cls.partitions = tuple(
            {
                "campaign_manifest_id": (
                    "rcid:v1:campaign-manifest:h:jcs-sha256-v1:"
                    + _sha(f"partition-{index}")
                ),
                "denominator": {"included_count": 15_625},
                "parent_campaign_manifest_id": master_id,
                "partition_count": 64,
                "partition_index": index,
                "planned_interruptions": [{}, {}, {}],
                "shards": [{}] * (63 if index < 35 else 62),
            }
            for index in range(64)
        )

    def _verify(self, report_path: Path, receipts_root: Path) -> dict[str, object]:
        with patch(
            "regex_conformance_scale.million_reconciliation.compile_million_scale_plan",
            return_value=self.compiled,
        ), patch(
            "regex_conformance_scale.million_reconciliation.build_partition_plans",
            return_value=self.partitions,
        ):
            return verify_million_final_artifacts(ROOT, report_path, receipts_root)

    def _fixture(self, root: Path) -> tuple[Path, Path]:
        receipts_root = root / "receipts"
        receipts: list[dict[str, object]] = []
        executions: list[dict[str, object]] = []
        for partition in self.partitions:
            index = partition["partition_index"]
            logical = partition["denominator"]["included_count"]
            attempts = logical + 250
            evidence_sha = _sha(f"evidence-{index}")
            manifest_sha = _sha(f"manifest-{index}")
            receipt = {
                "attempt_count": attempts,
                "campaign_manifest_id": partition["campaign_manifest_id"],
                "class_a_requests": 3,
                "class_b_requests": 4,
                "created_objects": 8,
                "evidence_manifest_sha256": evidence_sha,
                "logical_execution_count": logical,
                "manifest_key": f"regex-conformance/evidence-pack-v2/manifests/sha256/{manifest_sha}.json",
                "manifest_sha256": manifest_sha,
                "object_count": 8,
                "pack_digest_sha256": _sha(f"pack-{index}"),
                "parent_campaign_manifest_id": self.compiled.plan[
                    "campaign_manifest_id"
                ],
                "partition_count": 64,
                "partition_index": index,
                "physical_attempt_count": attempts,
                "recovered_existing_objects": 0,
                "retained_bytes": 1_000 + index,
                "schema_version": "million-scale-partition-publication-receipt.v1",
                "source_member_count": 10,
                "verification": {
                    "corruption_detected": True,
                    "deterministic": True,
                    "exact_reconstruction": True,
                    "independent_attempts": True,
                    "independent_observations": True,
                    "list_requests": 0,
                },
            }
            execution = {
                "accepted_observation_count": logical,
                "attempt_count": attempts,
                "campaign_manifest_id": partition["campaign_manifest_id"],
                "evidence_manifest_id": f"rcid:v1:evidence-manifest:h:jcs-sha256-v1:{evidence_sha}",
                "evidence_manifest_reference": {
                    "category": "scale-manifests",
                    "relative_path": f"scale-manifests/sha256/{evidence_sha}.json",
                    "sha256": evidence_sha,
                    "size_bytes": 100,
                },
                "infrastructure_failure_attempt_count": 250,
                "interruption_count": 3,
                "logical_execution_count": logical,
                "parent_campaign_manifest_id": self.compiled.plan[
                    "campaign_manifest_id"
                ],
                "partition_count": 64,
                "partition_index": index,
                "reconciliation": "exact",
                "result_shard_count": len(partition["shards"]),
                "schema_version": "million-scale-partition-execution-report.v1",
                "session_summary": {
                    "active": 0,
                    "completed": 1,
                    "failed": 0,
                    "forced_interruption": 3,
                    "total": 4,
                },
                "trust_class": "trusted_executioner",
            }
            directory = receipts_root / f"million-receipt-{index:03d}"
            _write(directory / "partition-receipt.json", receipt)
            _write(directory / "execution-report.json", execution)
            receipts.append(receipt)
            executions.append(execution)

        logical_count = sum(item["logical_execution_count"] for item in receipts)
        attempt_count = sum(item["attempt_count"] for item in receipts)
        infrastructure = sum(
            item["infrastructure_failure_attempt_count"] for item in executions
        )
        result_shards = sum(item["result_shard_count"] for item in executions)
        receipt_bytes = sum(len(canonical_bytes(item) + b"\n") for item in receipts)
        upper_before_aggregate = (
            461 + sum(item["retained_bytes"] for item in receipts) + receipt_bytes
        )
        unique_before_aggregate = 1_000_000
        aggregate = {
            "accepted_observation_count": logical_count,
            "attempt_count": attempt_count,
            "campaign_manifest_id": self.compiled.plan["campaign_manifest_id"],
            "capacity": {
                "canary_bytes": 461,
                "hard_cap_bytes": 10_000_000_000,
                "projected_upper_bound_bytes": upper_before_aggregate,
                "soft_stop_bytes": 8_000_000_000,
                "unique_campaign_bytes": unique_before_aggregate,
            },
            "infrastructure_failure_attempt_count": infrastructure,
            "logical_execution_count": logical_count,
            "normal_list_requests": 0,
            "partition_receipts": receipts,
            "result_shard_count": result_shards,
            "schema_version": "million-scale-evidence-pack-aggregate-manifest.v1",
        }
        aggregate_bytes = canonical_bytes(aggregate) + b"\n"
        aggregate_sha = hashlib.sha256(aggregate_bytes).hexdigest()
        unique_pack_objects = 9
        report = {
            "accepted_observation_count": logical_count,
            "aggregate_manifest_key": f"regex-conformance/evidence-pack-v2/manifests/sha256/{aggregate_sha}.json",
            "aggregate_manifest_sha256": aggregate_sha,
            "attempt_count": attempt_count,
            "campaign_manifest_id": self.compiled.plan["campaign_manifest_id"],
            "capacity": {
                "canary_bytes": 461,
                "hard_cap_bytes": 10_000_000_000,
                "projected_upper_bound_bytes": upper_before_aggregate
                + len(aggregate_bytes),
                "soft_stop_bytes": 8_000_000_000,
                "unique_campaign_bytes": unique_before_aggregate
                + len(aggregate_bytes),
            },
            "class_a_requests": sum(item["class_a_requests"] for item in receipts)
            + 64
            + 1,
            "class_b_requests": sum(item["class_b_requests"] for item in receipts)
            + 128
            + 128
            + unique_pack_objects
            + 1,
            "infrastructure_failure_attempt_count": infrastructure,
            "logical_execution_count": logical_count,
            "object_count": unique_pack_objects + 64 + 64 + 1,
            "pack_manifest_count": 64,
            "partition_count": 64,
            "reconciliation": "exact",
            "result_shard_count": result_shards,
            "schema_version": "million-scale-execution-report.v1",
            "verification": {
                "duplicate_logical_completion": False,
                "manifest_last": True,
                "normal_list_requests": 0,
                "pack_structures": 64,
                "partition_indexes": "0-63-exact",
                "physical_attempt_distinction": True,
                "source_reconstruction_certified": True,
            },
        }
        report_path = root / "million-final-report.json"
        _write(report_path, report)
        return report_path, receipts_root

    def test_reconstructs_aggregate_and_all_partition_accounting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path, receipts_root = self._fixture(Path(temporary))
            result = self._verify(report_path, receipts_root)
        self.assertEqual(result["logical_execution_count"], 1_000_000)
        self.assertEqual(result["physical_attempt_count"], 1_016_000)
        self.assertEqual(result["infrastructure_failure_attempt_count"], 16_000)
        self.assertEqual(result["interruption_count"], 192)
        self.assertTrue(all(result["verification"].values()))

    def test_rejects_aggregate_identity_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path, receipts_root = self._fixture(Path(temporary))
            report = load_strict(report_path)
            report["aggregate_manifest_sha256"] = "0" * 64
            report["aggregate_manifest_key"] = (
                "regex-conformance/evidence-pack-v2/manifests/sha256/"
                + "0" * 64
                + ".json"
            )
            _write(report_path, report)
            with self.assertRaisesRegex(
                MillionReconciliationError, "digest does not reconstruct"
            ):
                self._verify(report_path, receipts_root)

    def test_rejects_receipt_execution_attempt_disagreement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path, receipts_root = self._fixture(Path(temporary))
            execution_path = (
                receipts_root / "million-receipt-000" / "execution-report.json"
            )
            execution = load_strict(execution_path)
            execution["attempt_count"] += 1
            _write(execution_path, execution)
            with self.assertRaisesRegex(
                MillionReconciliationError, "physical attempts disagree"
            ):
                self._verify(report_path, receipts_root)

    def test_rejects_missing_interruption_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path, receipts_root = self._fixture(Path(temporary))
            (
                receipts_root / "million-receipt-000" / "execution-report.json"
            ).unlink()
            with self.assertRaisesRegex(
                MillionReconciliationError, "exactly 64 execution reports"
            ):
                self._verify(report_path, receipts_root)


if __name__ == "__main__":
    unittest.main()
