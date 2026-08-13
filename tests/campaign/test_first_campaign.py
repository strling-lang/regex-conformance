from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "control-plane" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
    ROOT / "verifier" / "python",
    ROOT / "warehouse" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from evidence_support import completed_response
from regex_conformance_campaign import CampaignCompileError, compile_vertical_slice, verify_compiled_campaign
from regex_conformance_control_plane.campaign_manager import CampaignCoordinator, CampaignExecutionError
from regex_conformance_schema.identity import NamespaceRegistry
from regex_conformance_schema.jsonio import canonical_bytes
from regex_conformance_verifier import EvidenceIntegrityError, ImmutableEvidenceStore
from regex_conformance_warehouse import build_warehouse


class FakeWorker:
    def __init__(self, *, fail_selection: str | None = None) -> None:
        self.fail_selection = fail_selection

    def execute_shard(self, selection_key, logical_executions):
        if selection_key == self.fail_selection:
            return [
                {
                    "logical_execution_id": item["logical_execution_id"],
                    "infrastructure_failure": {"code": "deliberate-fault", "message": "test fault"},
                    "provenance": {"selection_key": selection_key},
                }
                for item in logical_executions
            ]
        return [
            {
                "logical_execution_id": item["logical_execution_id"],
                "provenance": {"selection_key": selection_key},
                "response": completed_response(item),
            }
            for item in logical_executions
        ]


class CapturingSink:
    def __init__(self, delegate):
        self.delegate = delegate
        self.manifest = None

    def publish(self, compiled, attempts_by_shard):
        self.manifest = self.delegate.publish(compiled, attempts_by_shard)
        return self.manifest


class FirstCampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compiled = compile_vertical_slice(ROOT)
        self.coordinator = CampaignCoordinator(
            NamespaceRegistry.load(ROOT / "registries" / "identity" / "namespaces.v1.json")
        )

    def test_compilation_is_byte_deterministic_and_denominator_is_explicit(self) -> None:
        again = compile_vertical_slice(ROOT)
        self.assertEqual(canonical_bytes(self.compiled), canonical_bytes(again))
        self.assertEqual(
            self.compiled["denominator"],
            {
                "candidate_count": 6,
                "excluded_count": 2,
                "included_count": 4,
                "invalid_count": 0,
                "unresolved_count": 0,
            },
        )
        self.assertEqual(len(self.compiled["shards"]), 3)
        self.assertTrue(self.compiled["classification"]["probe_only"])
        self.assertFalse(self.compiled["classification"]["normative_authority"])

    def test_tampered_manifest_and_denominator_are_rejected(self) -> None:
        manifest = deepcopy(self.compiled)
        manifest["campaign_manifest"]["logical_execution_ids"].reverse()
        with self.assertRaises(CampaignCompileError):
            verify_compiled_campaign(ROOT, manifest)
        denominator = deepcopy(self.compiled)
        denominator["denominator"]["excluded_count"] = 1
        with self.assertRaises(CampaignCompileError):
            verify_compiled_campaign(ROOT, denominator)

    def test_complete_attempts_publish_immutable_evidence_and_reconcile_warehouse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            store = ImmutableEvidenceStore(ROOT, base / "evidence")
            manifest = self.coordinator.execute(self.compiled, FakeWorker(), store)
            warehouse = build_warehouse(ROOT, base / "warehouse", self.compiled, manifest, store)
            self.assertTrue(manifest["complete"])
            self.assertEqual(manifest["accepted_observation_count"], 4)
            self.assertEqual(manifest["infrastructure_failure_count"], 0)
            self.assertEqual(warehouse["counts"]["observations"], 4)
            physical_runs = [item["physical_run_id"] for item in manifest["attempts"]]
            self.assertEqual(len(physical_runs), len(set(physical_runs)))
            reference = manifest["observations"][0]
            path = base / "evidence" / reference["relative_path"]
            original = path.read_bytes()
            path.write_bytes(original + b" ")
            with self.assertRaises(EvidenceIntegrityError):
                store.read_artifact(reference)

    def test_infrastructure_failure_is_preserved_and_cannot_complete_denominator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ImmutableEvidenceStore(ROOT, Path(temporary) / "evidence")
            capture = CapturingSink(store)
            with self.assertRaises(CampaignExecutionError):
                self.coordinator.execute(
                    self.compiled,
                    FakeWorker(fail_selection="python-re"),
                    capture,
                )
            self.assertIsNotNone(capture.manifest)
            assert capture.manifest is not None
            self.assertFalse(capture.manifest["complete"])
            self.assertEqual(capture.manifest["infrastructure_failure_count"], 2)
            self.assertEqual(len(capture.manifest["attempts"]), 4)
            self.assertEqual(capture.manifest["accepted_observation_count"], 2)

    def test_raw_evidence_and_warehouse_are_refused_inside_git(self) -> None:
        with self.assertRaises(EvidenceIntegrityError):
            ImmutableEvidenceStore(ROOT, ROOT / "evidence" / "forbidden")
        with tempfile.TemporaryDirectory() as temporary:
            store = ImmutableEvidenceStore(ROOT, Path(temporary) / "evidence")
            manifest = self.coordinator.execute(self.compiled, FakeWorker(), store)
            with self.assertRaises(Exception):
                build_warehouse(ROOT, ROOT / "warehouse" / "forbidden", self.compiled, manifest, store)


if __name__ == "__main__":
    unittest.main()
