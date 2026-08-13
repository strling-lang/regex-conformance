from __future__ import annotations

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

from regex_conformance_campaign import compile_vertical_slice
from regex_conformance_control_plane.campaign_manager import CampaignCoordinator
from regex_conformance_schema.identity import NamespaceRegistry
from regex_conformance_verifier import EvidenceIntegrityError, ImmutableEvidenceStore
from regex_conformance_warehouse import build_warehouse


class SuccessfulWorker:
    def execute_shard(self, selection_key, logical_executions):
        return [
            {
                "logical_execution_id": item["logical_execution_id"],
                "provenance": {"selection_key": selection_key},
                "response": {
                    "canonical_authority": False,
                    "correlation_id": item["logical_execution_id"],
                    "observation": {"match_state": "match"},
                    "semantic_authority": False,
                    "status": "completed",
                },
            }
            for item in logical_executions
        ]


class EvidenceReconciliationTests(unittest.TestCase):
    def test_corrupted_result_shard_blocks_warehouse_derivation(self) -> None:
        compiled = compile_vertical_slice(ROOT)
        coordinator = CampaignCoordinator(
            NamespaceRegistry.load(ROOT / "registries" / "identity" / "namespaces.v1.json")
        )
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            store = ImmutableEvidenceStore(ROOT, base / "evidence")
            manifest = coordinator.execute(compiled, SuccessfulWorker(), store)
            reference = manifest["result_shards"][0]
            artifact = base / "evidence" / reference["relative_path"]
            artifact.write_bytes(artifact.read_bytes() + b" ")
            with self.assertRaises(EvidenceIntegrityError):
                build_warehouse(ROOT, base / "warehouse", compiled, manifest, store)

    def test_supplied_manifest_substitution_blocks_warehouse_derivation(self) -> None:
        compiled = compile_vertical_slice(ROOT)
        coordinator = CampaignCoordinator(
            NamespaceRegistry.load(ROOT / "registries" / "identity" / "namespaces.v1.json")
        )
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            store = ImmutableEvidenceStore(ROOT, base / "evidence")
            manifest = coordinator.execute(compiled, SuccessfulWorker(), store)
            manifest["root_digest"] = "0" * 64
            with self.assertRaises(EvidenceIntegrityError):
                build_warehouse(ROOT, base / "warehouse", compiled, manifest, store)


if __name__ == "__main__":
    unittest.main()
