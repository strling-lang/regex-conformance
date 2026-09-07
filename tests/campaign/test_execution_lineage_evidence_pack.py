from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    sys.path.insert(0, str(source))

import regex_conformance_scale.evidence_pack_v3 as pack_v3  # noqa: E402
from regex_conformance_schema.execution_provenance import FIXTURE_PATH  # noqa: E402
from regex_conformance_schema.jsonio import load_strict  # noqa: E402


class ExecutionLineageEvidencePackTests(unittest.TestCase):
    def test_richer_lineage_round_trips_as_one_shared_attempt_facts_block(self) -> None:
        lineage_set = load_strict(ROOT / FIXTURE_PATH)
        block = pack_v3.RetainedBlock(
            "physical_attempt_facts",
            "execution-lineage-set-v1",
            0,
            lineage_set,
        )
        pack = pack_v3.build_evidence_pack(
            [block],
            campaign_manifest_sha256="8" * 64,
            counts={
                "logical_executions": lineage_set["counts"]["logical_execution_count"],
                "observations": lineage_set["counts"]["terminal_observation_count"],
                "physical_attempts": lineage_set["counts"]["physical_attempt_count"],
            },
            canonical_input_derivation="execution-lineage-set-v1",
        )
        self.assertEqual(pack_v3.decode_evidence_pack(pack.manifest, pack.objects), [block])


if __name__ == "__main__":
    unittest.main()
