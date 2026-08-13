from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
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

from regex_conformance_campaign import CampaignCompileError, compile_vertical_slice, verify_compiled_campaign


class CompiledCampaignIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compiled = compile_vertical_slice(ROOT)

    def test_candidate_proof_substitution_is_rejected(self) -> None:
        tampered = deepcopy(self.compiled)
        tampered["candidates"][0]["proof"]["outcome_source"] = "forged"
        with self.assertRaises(CampaignCompileError):
            verify_compiled_campaign(ROOT, tampered)

    def test_request_substitution_is_rejected_even_when_denominator_is_unchanged(self) -> None:
        tampered = deepcopy(self.compiled)
        tampered["logical_executions"][0]["request"]["limits"]["wall_time_ms"] += 1
        with self.assertRaises(CampaignCompileError):
            verify_compiled_campaign(ROOT, tampered)

    def test_shard_identity_substitution_is_rejected(self) -> None:
        tampered = deepcopy(self.compiled)
        tampered["shards"][0]["shard_id"] = tampered["shards"][1]["shard_id"]
        with self.assertRaises(CampaignCompileError):
            verify_compiled_campaign(ROOT, tampered)


if __name__ == "__main__":
    unittest.main()
