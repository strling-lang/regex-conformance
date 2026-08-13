from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import stat
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

from regex_conformance_scheduler import (
    CHECKPOINT_STATES,
    RecoveryConflictError,
    RecoveryIntegrityError,
    RecoveryJournal,
)
from regex_conformance_schema.identity import NamespaceRegistry, generate_assigned_id
from regex_conformance_schema.jsonio import load_strict

COMPILED = load_strict(ROOT / "campaigns" / "compiled" / "small-scale-qualification.v1.json")
CAMPAIGN_ID = COMPILED["campaign_manifest_id"]
LOGICAL_ID = sorted(item["logical_execution_id"] for item in COMPILED["logical_executions"])[0]
MANIFEST_SHA256 = hashlib.sha256(b"commit receipt integrity").hexdigest()


class Factory:
    def __init__(self, fixed: str | None = None) -> None:
        self.fixed = fixed
        self.registry = NamespaceRegistry.load(
            ROOT / "registries" / "identity" / "namespaces.v1.json"
        )

    def __call__(self) -> str:
        if self.fixed is not None:
            value, self.fixed = self.fixed, None
            return value
        return generate_assigned_id(self.registry, "rcid", "physical-run")


def open_journal(path: Path, session: str, factory: Factory) -> RecoveryJournal:
    return RecoveryJournal(
        path,
        campaign_manifest_id=CAMPAIGN_ID,
        logical_execution_ids=(LOGICAL_ID,),
        controller_session_id=session,
        physical_run_id_factory=factory,
    )


def commit(value: RecoveryJournal, physical_run_id: str) -> None:
    for state in CHECKPOINT_STATES[1:-1]:
        if state == "manifest-committed":
            value.checkpoint(
                physical_run_id,
                state,
                {"manifest": MANIFEST_SHA256},
                manifest_sha256=MANIFEST_SHA256,
            )
        else:
            value.checkpoint(physical_run_id, state, {"state": state})


class RestartResumeIntegrityTests(unittest.TestCase):
    def test_payload_substitution_and_missing_commit_receipt_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "payload.sqlite3"
            factory = Factory()
            with open_journal(path, "session-1", factory) as value:
                value.start_or_resume(LOGICAL_ID)
            connection = sqlite3.connect(path)
            connection.execute(
                "UPDATE checkpoints SET payload_json = '{}' WHERE checkpoint_ordinal = 1"
            )
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(RecoveryIntegrityError, "payload"):
                open_journal(path, "session-2", factory)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.sqlite3"
            factory = Factory()
            with open_journal(path, "session-1", factory) as value:
                started = value.start_or_resume(LOGICAL_ID)
                assert started.physical_run_id is not None
                commit(value, started.physical_run_id)
            connection = sqlite3.connect(path)
            connection.execute("DELETE FROM logical_commits")
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(RecoveryIntegrityError, "commit receipts"):
                open_journal(path, "session-2", factory)

    def test_database_is_private_and_hard_links_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "state.sqlite3"
            factory = Factory()
            with open_journal(path, "session", factory):
                pass
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            linked = root / "linked.sqlite3"
            os.link(path, linked)
            with self.assertRaisesRegex(RecoveryIntegrityError, "singly linked"):
                open_journal(linked, "session-2", factory)

    def test_wrong_typed_physical_identity_rolls_back_without_an_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            with open_journal(path, "session", Factory("unsafe-run")) as value:
                with self.assertRaisesRegex(RecoveryConflictError, "typed identity"):
                    value.start_or_resume(LOGICAL_ID)
                self.assertEqual(value.attempts(), ())
                value.audit()


if __name__ == "__main__":
    unittest.main()
