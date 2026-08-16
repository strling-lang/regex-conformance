from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns/python",
    ROOT / "matrix/python",
    ROOT / "scheduler/python",
    ROOT / "schemas/tooling/python",
    ROOT / "tests/campaign",
    ROOT / "verifier/python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from evidence_support import completed_response
from regex_conformance_scale.distributed_execution import (
    DistributedLogicalStore,
    DistributedPartitionController,
)
from regex_conformance_scale.evidence_pack_v2 import build_evidence_pack, certify_pack
from regex_conformance_scale.execution import PlannedInterruption
from regex_conformance_scale.factorized_evidence import (
    build_semantic_corpus,
    discover_scale_corpus,
)
from regex_conformance_scale.million_compiler import (
    MillionScaleCompileError,
    build_partition_plans,
    compile_million_scale_plan,
    materialize_partition_inputs,
    verify_million_scale_plan,
    verify_partition_plan,
)
from regex_conformance_scale.r2_publication import HARD_CAP_BYTES, SOFT_STOP_BYTES
from regex_conformance_scheduler import ScaleRecoveryLedger
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_verifier import ScaleEvidenceStore


TRACKED = ROOT / "campaigns/million/compiled/million-qualification.v1.json"


class SuccessfulPartitionWorker:
    def execute_shard(self, selection_key, logical_executions):
        return [completed_response(item) for item in logical_executions], {
            "adapter_release_manifest_id": logical_executions[0]["request"][
                "adapter_release_manifest_id"
            ],
            "selection_key": selection_key,
        }

    def force_kill(self, selection_key):
        return {
            "ended_at": "2026-08-16T06:00:01.000Z",
            "exit_code": -9,
            "forced": True,
            "selection_key": selection_key,
            "started_at": "2026-08-16T06:00:00.000Z",
            "trust_class": "trusted_executioner",
        }


class MillionQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiled = compile_million_scale_plan(ROOT)
        cls.plan = cls.compiled.plan
        cls.partitions = build_partition_plans(ROOT, cls.compiled)

    def test_master_plan_is_deterministic_and_exactly_one_million(self) -> None:
        tracked = load_strict(TRACKED)
        self.assertEqual(canonical_bytes(tracked), canonical_bytes(self.plan))
        verify_million_scale_plan(ROOT, tracked, deterministic=False)
        self.assertEqual(self.plan["denominator"]["included_count"], 1_000_000)
        self.assertEqual(len(self.plan["shards"]), 4_003)
        self.assertEqual(
            {
                item["key"]: item["logical_execution_count"]
                for item in self.plan["workload_distribution"]["profiles"]
            },
            {
                "mysql-regex": 230_780,
                "pcre2-dfa": 115_380,
                "pcre2-ordinary": 192_310,
                "python-re": 461_530,
            },
        )

    def test_partitions_are_closed_non_overlapping_and_bounded(self) -> None:
        self.assertEqual(len(self.partitions), 64)
        self.assertEqual(
            [item["partition_index"] for item in self.partitions], list(range(64))
        )
        shard_ids = [
            shard["shard_id"] for item in self.partitions for shard in item["shards"]
        ]
        self.assertEqual(shard_ids, [item["shard_id"] for item in self.plan["shards"]])
        self.assertEqual(len(shard_ids), len(set(shard_ids)))
        self.assertEqual(
            sum(item["denominator"]["included_count"] for item in self.partitions),
            1_000_000,
        )
        self.assertLessEqual(max(len(item["shards"]) for item in self.partitions), 63)
        self.assertLessEqual(
            max(item["denominator"]["included_count"] for item in self.partitions),
            16_000,
        )
        for item in self.partitions:
            verify_partition_plan(ROOT, self.plan, item, self.compiled.logical_ids_by_shard)
            self.assertEqual(len(item["planned_interruptions"]), 3)
            self.assertEqual(
                sum(value["action"] == "worker-process-kill" for value in item["planned_interruptions"]),
                1,
            )

    def test_capacity_and_docker_authority_are_fail_closed(self) -> None:
        self.assertEqual(SOFT_STOP_BYTES, 8_000_000_000)
        self.assertEqual(HARD_CAP_BYTES, 10_000_000_000)
        self.assertLess(64 * 8_000_000 + 461, SOFT_STOP_BYTES)
        workflow = (
            ROOT / ".github/workflows/trusted-million-qualification.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("/var/run/docker.sock", workflow)
        self.assertNotIn("self-hosted", workflow.casefold())
        self.assertNotIn("million-input-", workflow)
        self.assertEqual(workflow.count("uses: actions/upload-artifact@"), 2)
        self.assertEqual(workflow.count("uses: actions/download-artifact@"), 1)
        self.assertIn("max-parallel: 20", workflow)
        self.assertIn('--partition-index "${{ matrix.partition }}"', workflow)
        self.assertIn("recover_million_partition.py", workflow)
        self.assertEqual(
            workflow.count("steps.partition-recovery.outputs.completed != 'true'"),
            2,
        )

    def test_partition_substitution_is_rejected(self) -> None:
        forged = deepcopy(self.partitions[0])
        forged["denominator"]["included_count"] += 1
        with self.assertRaises(MillionScaleCompileError):
            verify_partition_plan(ROOT, self.plan, forged)

        forged = deepcopy(self.partitions[0])
        forged["classification"]["semantic_authority"] = True
        with self.assertRaises(MillionScaleCompileError):
            verify_partition_plan(ROOT, self.plan, forged)

        forged = deepcopy(self.partitions[0])
        forged["shards"] = deepcopy(self.partitions[1]["shards"])
        forged["campaign_manifest"]["shards"] = deepcopy(forged["shards"])
        with self.assertRaises(MillionScaleCompileError):
            verify_partition_plan(ROOT, self.plan, forged)

    @unittest.skipUnless(
        os.environ.get("STRLING_RUN_MILLION_PRODUCTION_PROOF") == "1",
        "production-sized million partition proof is explicit opt-in",
    )
    def test_complete_partition_recovers_and_certifies_evidence_pack_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            campaign_root = Path(temporary) / "partition-materialization"
            selected = materialize_partition_inputs(
                ROOT,
                self.compiled,
                campaign_root,
                partition_indexes=(0,),
            )
            self.assertEqual(len(selected), 1)
            partition = selected[0]
            partition_root = campaign_root / "partition-000"
            logical_store = DistributedLogicalStore(
                ROOT,
                self.plan,
                partition,
                partition_root / "logical",
            )
            evidence = ScaleEvidenceStore(ROOT, partition_root / "evidence")
            worker = SuccessfulPartitionWorker()
            interruptions = 0
            with ScaleRecoveryLedger(
                Path(temporary) / "state.sqlite",
                partition["campaign_manifest_id"],
            ) as ledger:
                while True:
                    controller = DistributedPartitionController(
                        ROOT,
                        self.plan,
                        partition,
                        logical_store,
                        ledger,
                        evidence,
                        worker,
                    )
                    try:
                        _manifest, report = controller.execute("trusted_executioner")
                        break
                    except PlannedInterruption:
                        interruptions += 1
            self.assertEqual(interruptions, 3)
            self.assertEqual(report["logical_execution_count"], 15_750)
            self.assertEqual(report["accepted_observation_count"], 15_750)
            self.assertEqual(report["infrastructure_failure_attempt_count"], 250)
            self.assertEqual(report["attempt_count"], 16_000)

            source = discover_scale_corpus(partition_root)
            semantic = build_semantic_corpus(ROOT, source, plan=partition)
            pack = build_evidence_pack(ROOT, source, semantic)
            repeated = build_evidence_pack(ROOT, source, semantic)
            self.assertEqual(pack.manifest_bytes, repeated.manifest_bytes)
            self.assertEqual(pack.object_map(), repeated.object_map())
            self.assertLess(pack.retained_bytes, 8_000_000)
            certification = certify_pack(ROOT, source, semantic, pack)
            self.assertTrue(certification["byte_complete_legacy_reconstruction"])
            self.assertTrue(certification["corruption_injection_detected"])
            self.assertEqual(
                certification["independent_observation_count"],
                15_750,
            )
            self.assertEqual(
                certification["independent_physical_attempt_count"],
                16_000,
            )


if __name__ == "__main__":
    unittest.main()
