from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_scheduler import RecoveryJournal
from regex_conformance_schema.identity import NamespaceRegistry, generate_assigned_id
from regex_conformance_schema.jsonio import load_strict

COMPILED = load_strict(ROOT / "campaigns" / "compiled" / "small-scale-qualification.v1.json")
CAMPAIGN_ID = COMPILED["campaign_manifest_id"]
LOGICAL_ID = sorted(item["logical_execution_id"] for item in COMPILED["logical_executions"])[0]


class RestartResumePayloadAccessTests(unittest.TestCase):
    def test_reopened_controller_reads_exact_verified_resume_payload(self) -> None:
        registry = NamespaceRegistry.load(
            ROOT / "registries" / "identity" / "namespaces.v1.json"
        )
        factory = lambda: generate_assigned_id(registry, "rcid", "physical-run")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            with RecoveryJournal(
                path,
                campaign_manifest_id=CAMPAIGN_ID,
                logical_execution_ids=(LOGICAL_ID,),
                controller_session_id="before-restart",
                physical_run_id_factory=factory,
            ) as before:
                started = before.start_or_resume(LOGICAL_ID)
                assert started.physical_run_id is not None
                before.checkpoint(
                    started.physical_run_id,
                    "environment-ready",
                    {"environment_fingerprint_sha256": "a" * 64},
                )
            with RecoveryJournal(
                path,
                campaign_manifest_id=CAMPAIGN_ID,
                logical_execution_ids=(LOGICAL_ID,),
                controller_session_id="after-restart",
                physical_run_id_factory=factory,
            ) as after:
                resumed = after.start_or_resume(LOGICAL_ID)
                assert resumed.physical_run_id is not None
                self.assertEqual(resumed.action, "continue")
                self.assertEqual(
                    after.latest_checkpoint_payload(resumed.physical_run_id),
                    {"environment_fingerprint_sha256": "a" * 64},
                )


if __name__ == "__main__":
    unittest.main()
