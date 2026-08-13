from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
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
    build_restart_resume_reference_report,
)
from regex_conformance_schema.identity import NamespaceRegistry, generate_assigned_id
from regex_conformance_schema.jsonio import load_strict


COMPILED = load_strict(ROOT / "campaigns" / "compiled" / "small-scale-qualification.v1.json")
CAMPAIGN_ID = COMPILED["campaign_manifest_id"]
LOGICAL_ID = sorted(item["logical_execution_id"] for item in COMPILED["logical_executions"])[0]
LOGICAL_IDS = (LOGICAL_ID,)
MANIFEST_SHA256 = hashlib.sha256(b"verified immutable manifest").hexdigest()


class IdFactory:
    def __init__(self, *fixed: str) -> None:
        self.fixed = list(fixed)
        self.registry = NamespaceRegistry.load(
            ROOT / "registries" / "identity" / "namespaces.v1.json"
        )

    def __call__(self) -> str:
        if self.fixed:
            return self.fixed.pop(0)
        return generate_assigned_id(self.registry, "rcid", "physical-run")


def journal(path: Path, session: str, factory: IdFactory) -> RecoveryJournal:
    return RecoveryJournal(
        path,
        campaign_manifest_id=CAMPAIGN_ID,
        logical_execution_ids=LOGICAL_IDS,
        controller_session_id=session,
        physical_run_id_factory=factory,
    )


def advance(journal_value: RecoveryJournal, physical_run_id: str, target_state: str) -> None:
    current = journal_value.attempts(LOGICAL_ID)[-1].latest_state
    for state in CHECKPOINT_STATES[CHECKPOINT_STATES.index(current) + 1 :]:
        if state == "acknowledged":
            journal_value.acknowledge(physical_run_id)
        elif state == "manifest-committed":
            journal_value.checkpoint(
                physical_run_id,
                state,
                {"publication": "read-after-write-verified"},
                manifest_sha256=MANIFEST_SHA256,
            )
        else:
            journal_value.checkpoint(physical_run_id, state, {"state": state})
        if state == target_state:
            break


class RestartResumeTests(unittest.TestCase):
    def test_reference_matrix_covers_every_boundary_and_failure_case(self) -> None:
        report = build_restart_resume_reference_report()
        self.assertEqual(report["summary"], {
            "case_count": 14,
            "committed_case_count": 2,
            "continue_case_count": 9,
            "quarantine_case_count": 1,
            "retry_case_count": 2,
        })
        by_key = {item["case_key"]: item for item in report["cases"]}
        self.assertEqual(by_key["restart-after-running"]["expected_action"], "retry")
        self.assertEqual(
            by_key["restart-after-manifest-committed"]["expected_action"], "committed"
        )
        self.assertEqual(by_key["corrupt-checkpoint-chain"]["expected_action"], "quarantine")

    def test_restart_at_every_checkpoint_reaches_one_exact_commit(self) -> None:
        for stage in CHECKPOINT_STATES:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "recovery.sqlite3"
                factory = IdFactory()
                with journal(path, "session-before", factory) as before:
                    started = before.start_or_resume(LOGICAL_ID)
                    assert started.physical_run_id is not None
                    original_run = started.physical_run_id
                    if stage != "leased":
                        advance(before, original_run, stage)
                with journal(path, "session-after", factory) as after:
                    recovered = after.start_or_resume(LOGICAL_ID)
                    if stage == "running":
                        self.assertEqual(recovered.action, "retry")
                        self.assertNotEqual(recovered.physical_run_id, original_run)
                    elif stage in {"manifest-committed", "acknowledged"}:
                        self.assertEqual(recovered.action, "committed")
                        self.assertEqual(recovered.physical_run_id, original_run)
                    else:
                        self.assertEqual(recovered.action, "continue")
                        self.assertEqual(recovered.physical_run_id, original_run)
                    assert recovered.physical_run_id is not None
                    if recovered.resume_state != "acknowledged":
                        if recovered.resume_state == "manifest-committed":
                            after.acknowledge(recovered.physical_run_id)
                        else:
                            advance(after, recovered.physical_run_id, "acknowledged")
                    final = after.start_or_resume(LOGICAL_ID)
                    self.assertEqual(final.action, "committed")
                    attempts = after.attempts(LOGICAL_ID)
                    self.assertEqual(sum(item.disposition == "committed" for item in attempts), 1)
                    self.assertEqual(len({item.physical_run_id for item in attempts}), len(attempts))
                    after.audit()

    def test_same_session_duplicate_delivery_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            factory = IdFactory()
            with journal(Path(temporary) / "state.sqlite3", "same-session", factory) as value:
                first = value.start_or_resume(LOGICAL_ID)
                duplicate = value.start_or_resume(LOGICAL_ID)
                self.assertEqual(duplicate.action, "continue")
                self.assertEqual(duplicate.reason_code, "duplicate-delivery")
                self.assertEqual(duplicate.physical_run_id, first.physical_run_id)
                self.assertEqual(len(value.attempts(LOGICAL_ID)), 1)

    def test_repeated_interrupted_invocations_preserve_distinct_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            factory = IdFactory()
            with journal(path, "session-1", factory) as first:
                decision = first.start_or_resume(LOGICAL_ID)
                assert decision.physical_run_id is not None
                advance(first, decision.physical_run_id, "running")
            for number in range(2, 5):
                with journal(path, f"session-{number}", factory) as resumed:
                    decision = resumed.start_or_resume(LOGICAL_ID)
                    self.assertEqual(decision.action, "retry")
                    self.assertEqual(decision.attempt_number, number)
                    assert decision.physical_run_id is not None
                    if number < 4:
                        advance(resumed, decision.physical_run_id, "running")
                    else:
                        advance(resumed, decision.physical_run_id, "acknowledged")
                        attempts = resumed.attempts(LOGICAL_ID)
                        self.assertEqual(
                            [item.disposition for item in attempts],
                            ["interrupted", "interrupted", "interrupted", "committed"],
                        )
                        self.assertEqual(len({item.physical_run_id for item in attempts}), 4)

    def test_invalid_transition_payload_and_colliding_retry_roll_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            factory = IdFactory()
            with journal(path, "session-1", factory) as value:
                started = value.start_or_resume(LOGICAL_ID)
                assert started.physical_run_id is not None
                with self.assertRaisesRegex(RecoveryConflictError, "exact next"):
                    value.checkpoint(started.physical_run_id, "running")
                with self.assertRaisesRegex(RecoveryConflictError, "canonicalizable"):
                    value.checkpoint(
                        started.physical_run_id,
                        "environment-ready",
                        {"non_finite": float("nan")},
                    )
                self.assertEqual(value.attempts(LOGICAL_ID)[0].latest_state, "leased")
                advance(value, started.physical_run_id, "running")
                colliding_run = started.physical_run_id
            with journal(path, "session-2", IdFactory(colliding_run)) as resumed:
                with self.assertRaisesRegex(RecoveryConflictError, "collided"):
                    resumed.start_or_resume(LOGICAL_ID)
                attempts = resumed.attempts(LOGICAL_ID)
                self.assertEqual(len(attempts), 1)
                self.assertEqual(attempts[0].disposition, "active")
                resumed.audit()

    def test_hash_chain_corruption_and_plan_mismatch_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            factory = IdFactory()
            with journal(path, "session-1", factory) as value:
                value.start_or_resume(LOGICAL_ID)
            connection = sqlite3.connect(path)
            connection.execute(
                "UPDATE checkpoints SET checkpoint_sha256 = ? WHERE checkpoint_ordinal = 1",
                ("0" * 64,),
            )
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(RecoveryIntegrityError, "hash chain"):
                journal(path, "session-2", factory)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            factory = IdFactory()
            with journal(path, "session-1", factory):
                pass
            with self.assertRaisesRegex(RecoveryIntegrityError, "metadata"):
                RecoveryJournal(
                    path,
                    campaign_manifest_id=(CAMPAIGN_ID.rsplit(":", 1)[0] + ":" + "0" * 64),
                    logical_execution_ids=LOGICAL_IDS,
                    controller_session_id="session-2",
                    physical_run_id_factory=factory,
                )

    def test_uncommitted_database_transaction_does_not_advance_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            factory = IdFactory()
            with journal(path, "session-1", factory) as value:
                started = value.start_or_resume(LOGICAL_ID)
                assert started.physical_run_id is not None
            raw = sqlite3.connect(path, isolation_level=None)
            raw.execute("BEGIN IMMEDIATE")
            raw.execute(
                "UPDATE attempts SET owner_session_id = 'uncommitted-owner' WHERE physical_run_id = ?",
                (started.physical_run_id,),
            )
            raw.close()
            with journal(path, "session-2", factory) as recovered:
                decision = recovered.start_or_resume(LOGICAL_ID)
                self.assertEqual(decision.action, "continue")
                self.assertEqual(decision.physical_run_id, started.physical_run_id)

    def test_symbolic_link_database_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.sqlite3"
            target.touch()
            link = root / "linked.sqlite3"
            link.symlink_to(target)
            with self.assertRaisesRegex(RecoveryIntegrityError, "symbolic-link"):
                journal(link, "session", IdFactory())


if __name__ == "__main__":
    unittest.main()
