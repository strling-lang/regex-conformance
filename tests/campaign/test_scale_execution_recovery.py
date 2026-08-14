from __future__ import annotations

from pathlib import Path
import hashlib
import os
import sqlite3
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
    ROOT / "verifier" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from evidence_support import completed_response
from regex_conformance_campaign.compiler import _content_id
from regex_conformance_scale.execution import ScaleCampaignController
from regex_conformance_scheduler import ScaleRecoveryError, ScaleRecoveryLedger
from regex_conformance_schema.identity import NamespaceRegistry
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_verifier import EvidenceIntegrityError, ScaleEvidenceStore


CAMPAIGN = load_strict(
    ROOT / "campaigns" / "compiled" / "small-scale-qualification.v1.json"
)
CAMPAIGN_MANIFEST_ID = CAMPAIGN["campaign_manifest_id"]


def compact_shard(index: int, logical: dict) -> dict:
    logical_ids = [logical["logical_execution_id"]]
    return {
        "category": "logical-execution-segments",
        "first_logical_execution_id": logical_ids[0],
        "last_logical_execution_id": logical_ids[-1],
        "logical_execution_count": len(logical_ids),
        "logical_execution_ids_sha256": hashlib.sha256(
            canonical_bytes(logical_ids)
        ).hexdigest(),
        "relative_path": f"logical-execution-segments/sha256/{index:064x}.json",
        "selection_key": logical["selection_key"],
        "sha256": f"{index:064x}",
        "shard_id": _content_id(
            ROOT,
            "shard",
            "scale-recovery-test-shard-v1",
            {"index": index, "logical_execution_ids": logical_ids},
        ),
        "size_bytes": 1,
    }


def attempts(
    logicals: list[dict], attempt_number: int, *, infrastructure_failure: bool
) -> list[dict]:
    registry = NamespaceRegistry.load(
        ROOT / "registries" / "identity" / "namespaces.v1.json"
    )
    failure = (
        {
            "code": "forced-worker-process-kill",
            "message": "deliberate test interruption",
        }
        if infrastructure_failure
        else None
    )
    return ScaleCampaignController._attempts(
        registry,
        logicals,
        attempt_number,
        started_at="2026-08-13T12:00:00.000Z",
        ended_at="2026-08-13T12:00:01.000Z",
        infrastructure_failure=failure,
    )


def target_timeout(logical: dict) -> dict:
    request = logical["request"]
    return {
        "adapter_release_manifest_id": request["adapter_release_manifest_id"],
        "canonical_authority": False,
        "logical_execution_id": logical["logical_execution_id"],
        "outcome": "target-timeout",
        "process_execution": {
            "canonical_authority": False,
            "diagnostic": None,
            "exit_code": 0,
            "outcome": "completed",
            "provider_plan": {
                "canonical_authority": False,
                "enforced_limits": [
                    "cpu-time",
                    "memory",
                    "process-tree",
                    "stderr",
                    "stdout",
                    "wall-time",
                ],
                "launch_arguments": [],
                "process_tree_containment": True,
                "provider": "native",
                "semantic_authority": False,
            },
            "semantic_authority": False,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "stderr_total_bytes": 0,
            "stdout_sha256": "1" * 64,
            "stdout_total_bytes": 1,
            "wall_time_ms": 5,
        },
        "profile_id": request["profile_id"],
        "runtime_identity": {
            "facts": [
                {"name": "implementation", "value": "cpython"},
                {"name": "python-version", "value": "3.14.6"},
                {"name": "unicode-version", "value": "16.0.0"},
            ]
        },
        "schema_version": "scale-target-timeout.v1",
        "semantic_authority": False,
        "target_release_id": request["target_release_id"],
        "timer": {
            "implementation": "posix-itimer-real",
            "wall_time_ms": request["limits"]["wall_time_ms"],
        },
        "trace_reference": request["trace_reference"],
    }


class ScaleExecutionRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.logicals = CAMPAIGN["logical_executions"][:3]
        self.shards = [
            compact_shard(index, logical)
            for index, logical in enumerate(self.logicals, start=1)
        ]
        self.plan = {
            "campaign_manifest_id": CAMPAIGN_MANIFEST_ID,
            "planned_interruptions": [
                {
                    "action": "controller-restart",
                    "after_committed_shards": 1,
                    "key": "controller-restart-a",
                },
                {
                    "action": "worker-process-kill",
                    "after_committed_shards": 2,
                    "key": "worker-kill",
                },
                {
                    "action": "controller-restart",
                    "after_committed_shards": 3,
                    "key": "controller-restart-b",
                },
            ],
            "shards": self.shards,
        }

    def _publish(self, base: Path):
        evidence = ScaleEvidenceStore(ROOT, base / "evidence")
        database = base / "state" / "scale.sqlite"
        logical_by_shard = {
            shard["shard_id"]: [logical]
            for shard, logical in zip(self.shards, self.logicals, strict=True)
        }
        with ScaleRecoveryLedger(database, CAMPAIGN_MANIFEST_ID) as ledger:
            for index, (shard, logical) in enumerate(
                zip(self.shards, self.logicals, strict=True)
            ):
                logicals = [logical]
                if index == 1:
                    failed = evidence.write_result_segment(
                        plan=self.plan,
                        shard=shard,
                        logicals=logicals,
                        attempt_number=1,
                        attempts=attempts(logicals, 1, infrastructure_failure=True),
                        results=[],
                        provenance={"forced_interruption": "worker-kill"},
                        segment_kind="attempt",
                    )
                    ledger.commit_segment(shard["shard_id"], "attempt", 1, failed)
                attempt_number = 2 if index == 1 else 1
                result = evidence.write_result_segment(
                    plan=self.plan,
                    shard=shard,
                    logicals=logicals,
                    attempt_number=attempt_number,
                    attempts=attempts(
                        logicals, attempt_number, infrastructure_failure=False
                    ),
                    results=[completed_response(logical)],
                    provenance={"selection_key": shard["selection_key"]},
                    segment_kind="result",
                )
                ledger.commit_segment(
                    shard["shard_id"], "result", attempt_number, result
                )
            for planned in self.plan["planned_interruptions"]:
                session_id = str(uuid.uuid4())
                ledger.begin_session(session_id)
                worker = (
                    {
                        "exit_code": -9,
                        "forced": True,
                        "selection_key": self.shards[1]["selection_key"],
                    }
                    if planned["action"] == "worker-process-kill"
                    else None
                )
                ledger.record_interruption(
                    interruption_key=planned["key"],
                    action=planned["action"],
                    after_committed_shards=planned["after_committed_shards"],
                    controller_session_id=session_id,
                    worker_process=worker,
                )
                ledger.end_session(session_id, "forced-interruption")
            completed_session = str(uuid.uuid4())
            ledger.begin_session(completed_session)
            ledger.end_session(completed_session, "completed")
            manifest = evidence.publish_manifest(
                self.plan,
                ledger.segments(),
                ledger.interruptions(),
                lambda shard: logical_by_shard[shard["shard_id"]],
            )
            summary = ledger.session_summary()
        return evidence, database, manifest, logical_by_shard, summary

    def test_retry_history_reconciles_without_duplicate_credit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence, _database, manifest, logical_by_shard, summary = self._publish(
                Path(temporary)
            )
            self.assertEqual(manifest["logical_execution_count"], 3)
            self.assertEqual(manifest["accepted_observation_count"], 3)
            self.assertEqual(manifest["attempt_count"], 4)
            self.assertEqual(manifest["infrastructure_failure_attempt_count"], 1)
            self.assertEqual(manifest["result_shard_count"], 3)
            self.assertEqual(len(manifest["segments"]), 4)
            self.assertEqual(
                summary,
                {
                    "active": 0,
                    "completed": 1,
                    "failed": 0,
                    "forced_interruption": 3,
                    "total": 4,
                },
            )
            evidence.verify_manifest(
                self.plan,
                manifest,
                lambda shard: logical_by_shard[shard["shard_id"]],
            )

    def test_evidence_indirection_and_ledger_corruption_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            evidence, database, manifest, logical_by_shard, _summary = self._publish(
                base
            )
            reference = manifest["segments"][0]
            path = evidence.evidence_root / reference["relative_path"]
            link = base / "evidence-link.json"
            os.link(path, link)
            with self.assertRaisesRegex(EvidenceIntegrityError, "non-linked"):
                evidence.verify_manifest(
                    self.plan,
                    manifest,
                    lambda shard: logical_by_shard[shard["shard_id"]],
                )
            link.unlink()

            connection = sqlite3.connect(database)
            connection.execute(
                "UPDATE segment_commits SET commit_sha256 = ? WHERE ordinal = 1",
                ("0" * 64,),
            )
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(ScaleRecoveryError, "hash chain"):
                ScaleRecoveryLedger(database, CAMPAIGN_MANIFEST_ID)

    def test_compact_shard_commitment_rejects_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = ScaleEvidenceStore(ROOT, Path(temporary) / "evidence")
            shard = dict(self.shards[0])
            shard["logical_execution_ids_sha256"] = "0" * 64
            with self.assertRaisesRegex(
                EvidenceIntegrityError, "compact shard commitment"
            ):
                evidence.write_result_segment(
                    plan=self.plan,
                    shard=shard,
                    logicals=[self.logicals[0]],
                    attempt_number=1,
                    attempts=attempts(
                        [self.logicals[0]], 1, infrastructure_failure=False
                    ),
                    results=[completed_response(self.logicals[0])],
                    provenance={},
                    segment_kind="result",
                )

    def test_target_timeout_is_terminal_only_with_exact_contained_binding(self) -> None:
        logical = next(
            item
            for item in CAMPAIGN["logical_executions"]
            if item["selection_key"] == "python-re"
            and item["request"]["limits"]["wall_time_ms"] <= 1_000
        )
        shard = compact_shard(99, logical)
        with tempfile.TemporaryDirectory() as temporary:
            evidence = ScaleEvidenceStore(ROOT, Path(temporary) / "evidence")
            reference = evidence.write_result_segment(
                plan=self.plan,
                shard=shard,
                logicals=[logical],
                attempt_number=1,
                attempts=attempts([logical], 1, infrastructure_failure=False),
                results=[target_timeout(logical)],
                provenance={"selection_key": "python-re"},
                segment_kind="result",
            )
            payload = evidence.verify_segment(reference, self.plan, shard, [logical])
            self.assertEqual(
                payload["physical_attempts"][0]["outcome"],
                "target-observation",
            )
            self.assertEqual(
                payload["observations"][0]["result"]["outcome"],
                "target-timeout",
            )

            substituted_timer = target_timeout(logical)
            substituted_timer["timer"]["wall_time_ms"] += 1
            with self.assertRaisesRegex(
                EvidenceIntegrityError, "exact contained request"
            ):
                evidence.write_result_segment(
                    plan=self.plan,
                    shard=shard,
                    logicals=[logical],
                    attempt_number=1,
                    attempts=attempts([logical], 1, infrastructure_failure=False),
                    results=[substituted_timer],
                    provenance={},
                    segment_kind="result",
                )

            substituted_provider = target_timeout(logical)
            substituted_provider["process_execution"]["provider_plan"]["provider"] = (
                "oci"
            )
            with self.assertRaisesRegex(
                EvidenceIntegrityError, "exact contained request"
            ):
                evidence.write_result_segment(
                    plan=self.plan,
                    shard=shard,
                    logicals=[logical],
                    attempt_number=1,
                    attempts=attempts([logical], 1, infrastructure_failure=False),
                    results=[substituted_provider],
                    provenance={},
                    segment_kind="result",
                )

    def test_abrupt_sessions_recover_without_losing_forced_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state" / "scale.sqlite"
            failed_session = str(uuid.uuid4())
            forced_session = str(uuid.uuid4())
            with ScaleRecoveryLedger(database, CAMPAIGN_MANIFEST_ID) as ledger:
                ledger.begin_session(failed_session)
            with ScaleRecoveryLedger(database, CAMPAIGN_MANIFEST_ID) as ledger:
                self.assertEqual(ledger.recover_active_sessions(), 1)
                ledger.begin_session(forced_session)
                ledger.record_interruption(
                    interruption_key="worker-kill",
                    action="worker-process-kill",
                    after_committed_shards=2,
                    controller_session_id=forced_session,
                    worker_process={
                        "exit_code": -9,
                        "forced": True,
                        "selection_key": self.shards[1]["selection_key"],
                    },
                )
            with ScaleRecoveryLedger(database, CAMPAIGN_MANIFEST_ID) as ledger:
                self.assertEqual(ledger.recover_active_sessions(), 1)
                ledger.verify(CAMPAIGN_MANIFEST_ID)
                summary = ledger.session_summary()
                self.assertEqual(summary["active"], 0)
                self.assertEqual(summary["failed"], 1)
                self.assertEqual(summary["forced_interruption"], 1)
                self.assertEqual(summary["total"], 2)
                self.assertEqual(
                    ledger.interruptions()[0]["controller_session_id"],
                    forced_session,
                )


if __name__ == "__main__":
    unittest.main()
