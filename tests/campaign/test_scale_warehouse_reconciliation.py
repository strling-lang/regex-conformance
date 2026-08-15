from __future__ import annotations

from pathlib import Path
import hashlib
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
    ROOT / "warehouse" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from evidence_support import completed_response
from regex_conformance_campaign.compiler import _content_id
from regex_conformance_scale.execution import ScaleCampaignController
from regex_conformance_scheduler import ScaleRecoveryLedger
from regex_conformance_schema.identity import NamespaceRegistry
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_verifier import ScaleEvidenceStore
from regex_conformance_warehouse import (
    ScaleWarehouseReconciliationError,
    reconcile_scale_warehouse,
)


BASE = load_strict(ROOT / "campaigns" / "compiled" / "small-scale-qualification.v1.json")


def _attempts(logicals: list[dict], number: int, infrastructure: bool) -> list[dict]:
    failure = (
        {"code": "forced-worker-process-kill", "message": "deliberate test interruption"}
        if infrastructure
        else None
    )
    return ScaleCampaignController._attempts(
        NamespaceRegistry.load(ROOT / "registries" / "identity" / "namespaces.v1.json"),
        logicals,
        number,
        started_at="2026-08-14T12:00:00.000Z",
        ended_at="2026-08-14T12:00:01.000Z",
        infrastructure_failure=failure,
    )


class ScaleWarehouseReconciliationTests(unittest.TestCase):
    def _fixture(self, base: Path) -> tuple[Path, Path, Path]:
        campaign_root = base / "campaign"
        logical_root = campaign_root / "logical"
        logical_directory = logical_root / "logical-execution-segments" / "sha256"
        logical_directory.mkdir(parents=True)
        logicals = BASE["logical_executions"][:3]
        shards: list[dict] = []
        full_by_shard: dict[str, list[dict]] = {}
        for index, logical in enumerate(logicals, start=1):
            compact = {
                "base_logical_execution_id": logical["logical_execution_id"],
                "logical_execution_id": logical["logical_execution_id"],
                "planned_repetition": 1,
                "profile_id": logical["request"]["profile_id"],
                "request_template_sha256": hashlib.sha256(
                    canonical_bytes(
                        {
                            key: value
                            for key, value in logical["request"].items()
                            if key not in {"correlation_id", "trace_reference"}
                        }
                    )
                ).hexdigest(),
                "selection_key": logical["selection_key"],
                "target_release_id": logical["request"]["target_release_id"],
                "vector_revision_id": logical["vector_revision_id"],
            }
            logical_ids = [logical["logical_execution_id"]]
            shard_id = _content_id(
                ROOT,
                "shard",
                "scale-warehouse-test-shard-v1",
                {"index": index, "logical_execution_ids": logical_ids},
            )
            payload = {
                "logical_executions": [compact],
                "schema_version": "logical-execution-segment.v1",
                "selection_key": logical["selection_key"],
                "shard_id": shard_id,
            }
            encoded = canonical_bytes(payload) + b"\n"
            digest = hashlib.sha256(encoded).hexdigest()
            path = logical_directory / f"{digest}.json"
            path.write_bytes(encoded)
            shard = {
                "category": "logical-execution-segments",
                "first_logical_execution_id": logical_ids[0],
                "last_logical_execution_id": logical_ids[-1],
                "logical_execution_count": 1,
                "logical_execution_ids_sha256": hashlib.sha256(
                    canonical_bytes(logical_ids)
                ).hexdigest(),
                "relative_path": f"logical-execution-segments/sha256/{digest}.json",
                "selection_key": logical["selection_key"],
                "sha256": digest,
                "shard_id": shard_id,
                "size_bytes": len(encoded),
            }
            shards.append(shard)
            full_by_shard[shard_id] = [logical]
        shards.sort(key=lambda item: item["shard_id"])
        ordered_ids = [
            logical["logical_execution_id"]
            for logical in sorted(
                logicals,
                key=lambda item: (item["selection_key"], item["logical_execution_id"]),
            )
        ]
        plan = {
            "campaign_manifest_id": BASE["campaign_manifest_id"],
            "logical_execution_index": {
                "logical_execution_count": 3,
                "ordered_ids_sha256": hashlib.sha256(canonical_bytes(ordered_ids)).hexdigest(),
                "ordering": "selection-key-then-logical-id-v1",
                "segment_count": 3,
            },
            "planned_interruptions": [
                {"action": "controller-restart", "after_committed_shards": 1, "key": "controller-restart-a"},
                {"action": "worker-process-kill", "after_committed_shards": 2, "key": "worker-kill"},
                {"action": "controller-restart", "after_committed_shards": 3, "key": "controller-restart-b"},
            ],
            "shards": shards,
        }
        plan_path = base / "plan.json"
        plan_path.write_bytes(canonical_bytes(plan) + b"\n")
        evidence = ScaleEvidenceStore(ROOT, campaign_root / "evidence")
        ledger_path = campaign_root / "state" / "scale-recovery.sqlite"
        with ScaleRecoveryLedger(ledger_path, BASE["campaign_manifest_id"]) as ledger:
            for index, shard in enumerate(shards):
                members = full_by_shard[shard["shard_id"]]
                if index == 1:
                    attempt = evidence.write_result_segment(
                        plan=plan,
                        shard=shard,
                        logicals=members,
                        attempt_number=1,
                        attempts=_attempts(members, 1, True),
                        results=[],
                        provenance={"forced_interruption": "worker-kill"},
                        segment_kind="attempt",
                    )
                    ledger.commit_segment(shard["shard_id"], "attempt", 1, attempt)
                number = 2 if index == 1 else 1
                result = evidence.write_result_segment(
                    plan=plan,
                    shard=shard,
                    logicals=members,
                    attempt_number=number,
                    attempts=_attempts(members, number, False),
                    results=[completed_response(members[0])],
                    provenance={"selection_key": shard["selection_key"]},
                    segment_kind="result",
                )
                ledger.commit_segment(shard["shard_id"], "result", number, result)
            for interruption in plan["planned_interruptions"]:
                session_id = str(uuid.uuid4())
                ledger.begin_session(session_id)
                worker = (
                    {"exit_code": -9, "forced": True, "selection_key": shards[1]["selection_key"]}
                    if interruption["action"] == "worker-process-kill"
                    else None
                )
                ledger.record_interruption(
                    interruption_key=interruption["key"],
                    action=interruption["action"],
                    after_committed_shards=interruption["after_committed_shards"],
                    controller_session_id=session_id,
                    worker_process=worker,
                )
                ledger.end_session(session_id, "forced-interruption")
            completed_session = str(uuid.uuid4())
            ledger.begin_session(completed_session)
            ledger.end_session(completed_session, "completed")
            manifest = evidence.publish_manifest(
                plan,
                ledger.segments(),
                ledger.interruptions(),
                lambda shard: full_by_shard[shard["shard_id"]],
            )
            session_summary = ledger.session_summary()
        report = {
            "accepted_observation_count": manifest["accepted_observation_count"],
            "attempt_count": manifest["attempt_count"],
            "campaign_manifest_id": plan["campaign_manifest_id"],
            "evidence_manifest_id": manifest["evidence_manifest_id"],
            "evidence_manifest_reference": manifest["manifest_reference"],
            "infrastructure_failure_attempt_count": manifest["infrastructure_failure_attempt_count"],
            "interruption_count": 3,
            "logical_execution_count": 3,
            "reconciliation": "exact",
            "result_shard_count": 3,
            "schema_version": "scale-execution-report.v1",
            "session_summary": session_summary,
            "trust_class": "development",
        }
        report_path = campaign_root / "reports" / "scale-execution-report.json"
        report_path.parent.mkdir()
        report_path.write_bytes(canonical_bytes(report) + b"\n")
        return campaign_root, plan_path, ledger_path

    def test_builds_and_reuses_exact_non_crediting_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            campaign_root, plan_path, ledger_path = self._fixture(base)
            immutable_before = {
                path: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in campaign_root.rglob("*")
                if path.is_file() and path.suffix in {".json", ".sqlite"}
            }
            report = reconcile_scale_warehouse(
                ROOT,
                campaign_root,
                base / "warehouse",
                plan_path=plan_path,
                enforce_p19_100k=False,
            )
            self.assertEqual(report["reconciliation"]["counts"]["logical_executions"], 3)
            self.assertEqual(report["reconciliation"]["counts"]["physical_attempts"], 4)
            self.assertEqual(report["reconciliation"]["counts"]["selected_observations"], 3)
            self.assertEqual(len(report["reconciliation"]["attempt_only_segments"]), 1)
            self.assertEqual(report["reconciliation"]["attempt_only_segments"][0]["observation_count"], 0)
            database = base / "warehouse" / report["warehouse"]["warehouse_filename"]
            connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM selected_observation").fetchone()[0], 3)
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM physical_attempt WHERE outcome='infrastructure-failure'"
                    ).fetchone()[0],
                    1,
                )
            finally:
                connection.close()
            reused = reconcile_scale_warehouse(
                ROOT,
                campaign_root,
                base / "warehouse",
                plan_path=plan_path,
                reuse_existing=True,
                enforce_p19_100k=False,
            )
            self.assertEqual(reused["warehouse"], report["warehouse"])
            immutable_after = {
                path: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in immutable_before
            }
            self.assertEqual(immutable_after, immutable_before)
            self.assertEqual(hashlib.sha256(ledger_path.read_bytes()).hexdigest(), immutable_before[ledger_path])

    def test_manifested_object_digest_substitution_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            campaign_root, plan_path, _ledger_path = self._fixture(base)
            segment = next((campaign_root / "evidence" / "scale-result-segments" / "sha256").glob("*.json"))
            segment.write_bytes(segment.read_bytes() + b" ")
            with self.assertRaisesRegex(
                ScaleWarehouseReconciliationError, "canonical|size or digest"
            ):
                reconcile_scale_warehouse(
                    ROOT,
                    campaign_root,
                    base / "warehouse",
                    plan_path=plan_path,
                    enforce_p19_100k=False,
                )


if __name__ == "__main__":
    unittest.main()
