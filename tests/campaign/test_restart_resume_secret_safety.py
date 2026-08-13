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

from regex_conformance_scheduler import RecoveryConflictError, RecoveryJournal
from regex_conformance_schema.identity import NamespaceRegistry, generate_assigned_id
from regex_conformance_schema.jsonio import load_strict

COMPILED = load_strict(ROOT / "campaigns" / "compiled" / "small-scale-qualification.v1.json")
CAMPAIGN_ID = COMPILED["campaign_manifest_id"]
LOGICAL_ID = sorted(item["logical_execution_id"] for item in COMPILED["logical_executions"])[0]


class RestartResumeSecretSafetyTests(unittest.TestCase):
    def test_credentials_never_enter_durable_checkpoint_payloads(self) -> None:
        registry = NamespaceRegistry.load(
            ROOT / "registries" / "identity" / "namespaces.v1.json"
        )
        with tempfile.TemporaryDirectory() as temporary:
            with RecoveryJournal(
                Path(temporary) / "state.sqlite3",
                campaign_manifest_id=CAMPAIGN_ID,
                logical_execution_ids=(LOGICAL_ID,),
                controller_session_id="secret-test",
                physical_run_id_factory=lambda: generate_assigned_id(
                    registry, "rcid", "physical-run"
                ),
            ) as value:
                started = value.start_or_resume(LOGICAL_ID)
                assert started.physical_run_id is not None
                for payload in (
                    {"authorization": "Bearer abcdefghijklmnop"},
                    {"nested": {"api_key": "not-persisted"}},
                    {"source": "https://user:password@example.test/archive"},
                    {"source": "https://example.test/archive?X-Amz-Signature=secret"},
                    {"key": "-----BEGIN PRIVATE KEY-----"},
                ):
                    with self.subTest(payload=payload), self.assertRaisesRegex(
                        RecoveryConflictError, "credential-bearing"
                    ):
                        value.checkpoint(
                            started.physical_run_id,
                            "environment-ready",
                            payload,
                        )
                self.assertEqual(value.attempts()[0].latest_state, "leased")
                value.audit()


if __name__ == "__main__":
    unittest.main()
