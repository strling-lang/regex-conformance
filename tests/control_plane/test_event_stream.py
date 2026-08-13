from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2] if "tests" in Path(__file__).parts else None
if ROOT is None or not (ROOT / "control-plane").exists():
    ROOT = Path("/root/personal/strling-lang/regex-conformance")
sys.path.insert(0, str(ROOT / "control-plane" / "python"))
sys.path.insert(0, str(ROOT / "tests" / "control_plane"))

from regex_conformance_control_plane.event_models import (  # noqa: E402
    EventCursor,
    EventDraft,
    EventModelError,
    LifecycleEvent,
    ProgressAggregator,
)
from regex_conformance_control_plane.event_store import (  # noqa: E402
    EventCursorGapError,
    EventJournal,
    EventJournalConflictError,
    EventJournalCorruptionError,
)
from regex_conformance_control_plane.state_models import SecretMaterialError  # noqa: E402
from regex_conformance_control_plane.cache_manager import CacheManager, TransferManager  # noqa: E402
from regex_conformance_control_plane.controller import ControlPlaneController, ControlPlaneServices  # noqa: E402
from regex_conformance_control_plane.environment_manager import EnvironmentManager  # noqa: E402
from regex_conformance_control_plane.environment_models import AdmissionDecision  # noqa: E402
from regex_conformance_control_plane.environment_providers import ProviderRegistry  # noqa: E402
from test_cache_manager import (  # noqa: E402
    BytesSource,
    FixedClock as CacheClock,
    FixedIds as CacheIds,
    StaticProvider,
    entry,
    policy,
)
from test_environment_manager import (  # noqa: E402
    FIXTURES as ENVIRONMENT_FIXTURE,
    FixedClock as EnvironmentClock,
    FixedIds as EnvironmentIds,
    FixtureProvider,
    recipe,
)


BASE = datetime(2026, 8, 13, 3, 0, tzinfo=timezone.utc)


def opid(namespace: str, sequence: int) -> str:
    return f"opid:v1:{namespace}:u7:019ff82c-9517-76fb-a67d-{sequence:012x}"


class FixedIds:
    def __init__(self) -> None:
        self.sequence = 1

    def new_event_id(self) -> str:
        value = opid("lifecycle-event", self.sequence)
        self.sequence += 1
        return value

    def new_journal_id(self) -> str:
        value = opid("event-journal", self.sequence)
        self.sequence += 1
        return value


class TickingClock:
    def __init__(self, seconds: tuple[int, ...] = (0, 1, 2, 3, 4, 5)) -> None:
        self.values = iter(seconds)

    def now(self) -> datetime:
        return BASE + timedelta(seconds=next(self.values))


def draft(
    *,
    stream: int = 100,
    status: str = "running",
    current: int | None = 0,
    total: int | None = 100,
    attempt: int = 1,
    terminal: bool = False,
    attributes: dict[str, object] | None = None,
) -> EventDraft:
    return EventDraft(
        stream_id=opid("transfer", stream),
        operation_kind="transfer",
        event_type="progress" if current is not None else "lifecycle",
        phase="transfer",
        status=status,
        attempt=attempt,
        current=current,
        total=total if current is not None else None,
        unit="bytes" if current is not None else None,
        message=f"transfer {status}",
        attributes=attributes or {"provider": "fixture"},
        terminal=terminal,
    )


def event(sequence: int, second: int, current: int, *, attempt: int = 1, status: str = "running", terminal: bool = False) -> LifecycleEvent:
    selected = draft(status=status, current=current, attempt=attempt, terminal=terminal)
    return LifecycleEvent.build(
        event_id=opid("lifecycle-event", sequence),
        stream_sequence=sequence,
        occurred_at=(BASE + timedelta(seconds=second)).isoformat().replace("+00:00", "Z"),
        draft=selected,
    )


class EventStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema = json.loads((ROOT / "schemas" / "json" / "lifecycle-event.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        cls.validator = Draft202012Validator(schema)

    def open_journal(self, path: Path, *, maximum: int = 10, seconds: tuple[int, ...] = tuple(range(30))) -> EventJournal:
        return EventJournal.open(path, maximum_events=maximum, clock=TickingClock(seconds), id_generator=FixedIds())

    def test_event_canonicalization_digest_and_secret_refusal(self) -> None:
        one = EventDraft(**{**draft().__dict__, "attributes": {"z": 2, "a": 1}})
        two = EventDraft(**{**draft().__dict__, "attributes": {"a": 1, "z": 2}})
        first = LifecycleEvent.build(
            event_id=opid("lifecycle-event", 1), stream_sequence=1, occurred_at="2026-08-13T03:00:00Z", draft=one
        )
        second = LifecycleEvent.build(
            event_id=opid("lifecycle-event", 1), stream_sequence=1, occurred_at="2026-08-13T03:00:00Z", draft=two
        )
        self.assertEqual(first.event_digest, second.event_digest)
        self.assertFalse(first.to_dict()["canonical_authority"])
        with self.assertRaises(SecretMaterialError):
            draft(attributes={"access_token": "must-not-persist"})
        forged = first.__dict__.copy()
        forged["event_digest"] = "a" * 64
        with self.assertRaises(EventModelError):
            LifecycleEvent(**forged)

    def test_journal_orders_streams_and_idempotently_replays_exact_event_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = self.open_journal(Path(directory) / "events.sqlite3")
            event_id = opid("lifecycle-event", 500)
            first = journal.publish(draft(current=0), event_id=event_id)
            replay = journal.publish(draft(current=0), event_id=event_id)
            self.assertEqual(first, replay)
            second = journal.publish(draft(current=25))
            other = journal.publish(draft(stream=200, current=2, total=10))
            self.assertEqual([item.event.stream_sequence for item in (first, second, other)], [1, 2, 1])
            batch = journal.read()
            self.assertEqual([item.offset for item in batch.events], [1, 2, 3])
            self.assertEqual(batch.cursor.offset, 3)
            self.assertFalse(batch.has_more)
            with self.assertRaises(EventJournalConflictError):
                journal.publish(draft(current=26), event_id=event_id)
            journal.close()

    def test_bounded_retention_reports_explicit_cursor_gap_and_health(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.sqlite3"
            journal = self.open_journal(path, maximum=3)
            initial = journal.cursor()
            for current in (0, 10, 20, 30, 40):
                journal.publish(draft(current=current))
            with self.assertRaises(EventCursorGapError) as caught:
                journal.read(initial)
            self.assertEqual(caught.exception.oldest_available_offset, 3)
            retained = journal.read()
            self.assertEqual([item.offset for item in retained.events], [3, 4, 5])
            self.assertEqual(journal.health_check()["retained_event_count"], 3)
            projection = ProgressAggregator.project(journal.read_stream(opid("transfer", 100)))
            self.assertFalse(projection.history_complete)
            self.assertEqual(projection.current, 40)
            journal.close()
            reopened = self.open_journal(path, maximum=3)
            self.assertEqual([item.offset for item in reopened.read().events], [3, 4, 5])
            reopened.close()

    def test_interrupted_stream_resumes_from_durable_coordinate_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.sqlite3"
            journal = self.open_journal(path, seconds=(0, 1))
            journal.publish(draft(current=40), event_id=opid("lifecycle-event", 800))
            journal.publish(
                draft(status="interrupted", current=40),
                event_id=opid("lifecycle-event", 801),
            )
            journal.close()

            reopened = self.open_journal(path, seconds=(10, 12))
            reopened.publish(
                draft(status="resumed", current=40, attempt=2),
                event_id=opid("lifecycle-event", 802),
            )
            reopened.publish(
                draft(status="completed", current=100, attempt=2, terminal=True),
                event_id=opid("lifecycle-event", 803),
            )
            projection = ProgressAggregator.project(reopened.read_stream(opid("transfer", 100)))
            self.assertTrue(projection.history_complete)
            self.assertTrue(projection.terminal)
            self.assertEqual(projection.attempt, 2)
            self.assertEqual(projection.current, 100)
            reopened.close()

    def test_stream_invariants_reject_backward_progress_bad_resume_and_post_terminal_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = self.open_journal(Path(directory) / "events.sqlite3")
            journal.publish(draft(current=50))
            with self.assertRaises(EventJournalConflictError):
                journal.publish(draft(current=49))
            with self.assertRaises(EventJournalConflictError):
                journal.publish(draft(current=50, attempt=2, status="running"))
            journal.publish(draft(current=50, attempt=2, status="resumed"))
            journal.publish(draft(current=100, attempt=2, status="completed", terminal=True))
            with self.assertRaises(EventJournalConflictError):
                journal.publish(draft(current=100, attempt=2, status="completed", terminal=True))
            journal.close()

    def test_progress_projection_calculates_integer_rate_eta_and_resume_boundaries(self) -> None:
        projection = ProgressAggregator.project((event(1, 0, 0), event(2, 2, 40), event(3, 4, 80)))
        self.assertEqual(projection.percent_basis_points, 8000)
        self.assertEqual(projection.rate_milliunits_per_second, 20_000)
        self.assertEqual(projection.eta_seconds, 1)
        resumed = ProgressAggregator.project(
            (
                event(1, 0, 0),
                event(2, 2, 40),
                event(3, 5, 40, attempt=2, status="resumed"),
                event(4, 7, 60, attempt=2),
            )
        )
        self.assertEqual(resumed.rate_milliunits_per_second, 10_000)
        self.assertEqual(resumed.eta_seconds, 4)
        with self.assertRaises(EventModelError):
            ProgressAggregator.project((event(1, 0, 20), event(2, 1, 10)))

    def test_subscription_wakes_on_publish_and_advances_its_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = self.open_journal(Path(directory) / "events.sqlite3")
            subscription = journal.subscribe(journal.cursor())
            published: list[int] = []

            def producer() -> None:
                time.sleep(0.05)
                published.append(journal.publish(draft()).offset)

            thread = threading.Thread(target=producer)
            thread.start()
            batch = subscription.next_batch(timeout_seconds=1)
            thread.join()
            self.assertEqual([item.offset for item in batch.events], published)
            self.assertEqual(subscription.next_batch(timeout_seconds=0).events, ())
            journal.close()

    def test_tampered_retained_event_is_detected_on_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.sqlite3"
            journal = self.open_journal(path)
            journal.publish(draft())
            journal.close()
            connection = sqlite3.connect(path)
            row = connection.execute("SELECT event_json FROM lifecycle_events").fetchone()
            value = json.loads(row[0])
            value["message"] = "forged but valid event message"
            connection.execute("UPDATE lifecycle_events SET event_json = ?", (json.dumps(value, separators=(",", ":"), sort_keys=True),))
            connection.commit()
            connection.close()
            with self.assertRaises(EventJournalCorruptionError):
                self.open_journal(path)

    def test_incompatible_table_layout_and_orphan_stream_head_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            schema_path = Path(directory) / "schema.sqlite3"
            journal = self.open_journal(schema_path)
            journal.close()
            connection = sqlite3.connect(schema_path)
            connection.execute("ALTER TABLE lifecycle_events ADD COLUMN unexpected TEXT")
            connection.commit()
            connection.close()
            with self.assertRaises(EventJournalCorruptionError):
                self.open_journal(schema_path)

            head_path = Path(directory) / "head.sqlite3"
            journal = self.open_journal(head_path)
            journal.close()
            connection = sqlite3.connect(head_path)
            connection.execute(
                "INSERT INTO event_stream_heads "
                "(stream_id, operation_kind, last_sequence, attempt, current_value, total_value, unit, terminal) "
                "VALUES (?, ?, 1, 1, 0, 1, 'items', 0)",
                (opid("transfer", 991), "transfer"),
            )
            connection.commit()
            connection.close()
            with self.assertRaises(EventJournalCorruptionError):
                self.open_journal(head_path)

    def test_tampered_row_mirror_missing_head_and_malformed_metadata_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for name, statement, parameters in (
                (
                    "mirror.sqlite3",
                    "UPDATE lifecycle_events SET draft_sha256 = ?",
                    ("a" * 64,),
                ),
                (
                    "missing-head.sqlite3",
                    "DELETE FROM event_stream_heads",
                    (),
                ),
                (
                    "metadata.sqlite3",
                    "UPDATE journal_metadata SET value = ? WHERE key = 'last_offset'",
                    ("not-an-integer",),
                ),
                (
                    "row-coordinate.sqlite3",
                    "UPDATE lifecycle_events SET stream_sequence = ?",
                    ("not-an-integer",),
                ),
            ):
                path = Path(directory) / name
                journal = self.open_journal(path)
                journal.publish(draft())
                journal.close()
                connection = sqlite3.connect(path)
                connection.execute(statement, parameters)
                connection.commit()
                connection.close()
                with self.assertRaises(EventJournalCorruptionError):
                    self.open_journal(path)

    def test_wrong_journal_cursor_and_retention_policy_changes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.sqlite3"
            journal = self.open_journal(path, maximum=3)
            with self.assertRaises(EventJournalConflictError):
                journal.read(EventCursor(opid("event-journal", 999), 0))
            with self.assertRaisesRegex(EventJournalConflictError, "ahead"):
                journal.read(EventCursor(journal.journal_id, 1))
            journal.close()
            with self.assertRaises(EventJournalConflictError):
                self.open_journal(path, maximum=4)

    def test_public_schema_accepts_event_batch_and_projection_and_rejects_authority_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = self.open_journal(Path(directory) / "events.sqlite3")
            stored = journal.publish(draft(current=20))
            batch = journal.read()
            projection = ProgressAggregator.project((stored.event,))
            self.validator.validate(stored.event.to_dict())
            self.validator.validate(batch.to_dict())
            self.validator.validate(projection.to_dict())
            forged = stored.event.to_dict()
            forged["canonical_authority"] = True
            self.assertTrue(list(self.validator.iter_errors(forged)))
            forged = stored.event.to_dict()
            forged["unexpected"] = True
            self.assertTrue(list(self.validator.iter_errors(forged)))
            journal.close()

    def test_fixture_documents_event_and_retention_vocabulary(self) -> None:
        fixture = json.loads(
            (ROOT / "tests" / "control_plane" / "fixtures" / "lifecycle_events.json").read_text(encoding="utf-8")
        )
        self.assertEqual(set(fixture["expected_event_types"]), {"checkpoint", "diagnostic", "lifecycle", "metric", "progress"})
        self.assertEqual(set(fixture["expected_terminal_statuses"]), {"cancelled", "completed", "failed", "partial", "refused"})
        self.assertFalse(fixture["retention_semantics"]["local_events_are_canonical_evidence"])

    def test_resumable_transfer_events_are_the_only_input_to_progress_rate_and_eta(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = self.open_journal(root / "events.sqlite3", seconds=tuple(range(100)))
            manager = TransferManager(
                root / "transfers",
                clock=CacheClock(),
                id_generator=CacheIds(),
                event_publisher=journal,
            )
            try:
                payload = b"abcdefgh"
                digest = __import__("hashlib").sha256(payload).hexdigest()
                record = manager.plan(
                    operation="download",
                    locator="fixture://payload",
                    expected_sha256=digest,
                    expected_size_bytes=len(payload),
                    relative_path="objects/payload.bin",
                )
                record = manager.resume_download(record, BytesSource(payload), chunk_size=2, maximum_chunks=2)
                self.assertEqual(record.state, "interrupted")
                record = manager.resume_download(record, BytesSource(payload), chunk_size=2)
                self.assertEqual(record.state, "completed")
                events = journal.read_stream(record.requirement.transfer_id)
                self.assertEqual([item.attempt for item in events], [1, 1, 1, 1, 1, 2, 2, 2, 2])
                self.assertEqual(events[5].status, "resumed")
                projection = ProgressAggregator.project(events)
                self.assertTrue(projection.terminal)
                self.assertEqual(projection.current, len(payload))
                self.assertEqual(projection.percent_basis_points, 10_000)
                self.assertIsNotNone(projection.rate_milliunits_per_second)
            finally:
                journal.close()

    def test_cleanup_events_account_for_plan_mutations_and_terminal_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = self.open_journal(Path(directory) / "events.sqlite3", seconds=tuple(range(100)))
            manager = CacheManager(clock=CacheClock(), id_generator=CacheIds(), event_publisher=journal)
            selected = entry("event-fixture")
            inventory = manager.inventory((selected,), observed_at=selected.observed_at)
            provider = StaticProvider((selected,))
            reconciliation = manager.reconcile(inventory, provider)
            plan = manager.plan_cleanup(inventory, reconciliation, selected.reclaimable_bytes, policy())
            report = manager.execute_cleanup(plan, inventory, provider)
            self.assertEqual(report.state, "completed")
            events = journal.read_stream(plan.cleanup_id)
            self.assertEqual([item.status for item in events], ["planned", "running", "running", "completed"])
            self.assertEqual(ProgressAggregator.project(events).percent_basis_points, 10_000)
            journal.close()

    def test_partial_cleanup_is_terminal_and_accounts_for_failed_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = self.open_journal(Path(directory) / "events.sqlite3", seconds=tuple(range(100)))
            manager = CacheManager(clock=CacheClock(), id_generator=CacheIds(), event_publisher=journal)
            selected = entry("event-failure")
            inventory = manager.inventory((selected,), observed_at=selected.observed_at)
            provider = StaticProvider((selected,), failures={selected.cache_key})
            reconciliation = manager.reconcile(inventory, provider)
            plan = manager.plan_cleanup(inventory, reconciliation, selected.reclaimable_bytes, policy())
            report = manager.execute_cleanup(plan, inventory, provider)
            self.assertEqual(report.state, "partial")
            events = journal.read_stream(plan.cleanup_id)
            self.assertEqual([item.status for item in events], ["planned", "running", "running", "partial"])
            projection = ProgressAggregator.project(events)
            self.assertTrue(projection.terminal)
            self.assertEqual(projection.current, 1)
            journal.close()

    def test_invalid_external_completion_cannot_poison_resumable_event_stream(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = self.open_journal(root / "events.sqlite3", seconds=tuple(range(100)))
            manager = TransferManager(
                root / "transfers",
                clock=CacheClock(),
                id_generator=CacheIds(),
                event_publisher=journal,
            )
            payload = b"abcd"
            digest = __import__("hashlib").sha256(payload).hexdigest()
            record = manager.plan(
                operation="upload",
                locator="fixture://external",
                expected_sha256=digest,
                expected_size_bytes=len(payload),
                relative_path="objects/external.bin",
            )
            record = manager.record_external_attempt(
                record,
                bytes_completed=2,
                checkpoint_sha256=__import__("hashlib").sha256(payload[:2]).hexdigest(),
                outcome="interrupted",
                code="fixture-interruption",
                detail="fixture interruption",
            )
            before = journal.read_stream(record.requirement.transfer_id)
            with self.assertRaisesRegex(ValueError, "immutable expected digest"):
                manager.record_external_attempt(
                    record,
                    bytes_completed=len(payload),
                    checkpoint_sha256="0" * 64,
                    outcome="completed",
                    code="forged-completion",
                    detail="invalid completion",
                )
            self.assertEqual(journal.read_stream(record.requirement.transfer_id), before)
            record = manager.record_external_attempt(
                record,
                bytes_completed=len(payload),
                checkpoint_sha256=digest,
                outcome="completed",
                code="verified-completion",
                detail="verified completion",
            )
            events = journal.read_stream(record.requirement.transfer_id)
            self.assertEqual([item.attempt for item in events], [1, 1, 2, 2])
            self.assertEqual([item.status for item in events], ["planned", "interrupted", "resumed", "completed"])
            self.assertTrue(ProgressAggregator.project(events).terminal)
            journal.close()

    @unittest.skipIf(os.name == "nt", "environment fixture paths require the hosted/Linux validation platform")
    def test_environment_lifecycle_events_cover_plan_through_verified_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected_case = json.loads(ENVIRONMENT_FIXTURE.read_text(encoding="utf-8"))[0]
            journal = self.open_journal(root / "events.sqlite3", seconds=tuple(range(200)))
            provider = FixtureProvider(selected_case, root / "provider")
            manager = EnvironmentManager(
                ProviderRegistry((provider,)),
                clock=EnvironmentClock(),
                id_generator=EnvironmentIds(),
                event_publisher=journal,
            )
            record = manager.plan(recipe(selected_case), provider.descriptor.name)
            record = manager.admit(record, AdmissionDecision(True, "fixture-admission", "fixture capacity approved"))
            record = manager.realize(record)
            self.assertEqual(record.state, "ready")
            record = manager.release(record)
            self.assertEqual(record.state, "released")
            events = journal.read_stream(record.transaction_id)
            self.assertEqual(events[0].phase, "planned")
            self.assertEqual(events[-1].status, "completed")
            self.assertTrue(events[-1].terminal)
            self.assertGreaterEqual(len(events), 10)
            journal.close()

    def test_environment_plan_uses_recipe_identity_as_data_and_denial_is_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected_case = json.loads(ENVIRONMENT_FIXTURE.read_text(encoding="utf-8"))[0]
            journal = self.open_journal(root / "events.sqlite3", seconds=tuple(range(100)))
            provider = FixtureProvider(selected_case, root / "provider")
            manager = EnvironmentManager(
                ProviderRegistry((provider,)),
                clock=EnvironmentClock(),
                id_generator=EnvironmentIds(),
                event_publisher=journal,
            )
            record = manager.plan(recipe(selected_case), provider.descriptor.name)
            planned = journal.read_stream(record.transaction_id)[0]
            self.assertIsNone(planned.correlation_id)
            self.assertEqual(planned.attributes["recipe_revision_id"], record.recipe.recipe_revision_id)
            record = manager.admit(record, AdmissionDecision(False, "fixture-denial", "fixture capacity denied"))
            events = journal.read_stream(record.transaction_id)
            self.assertEqual(events[-1].status, "refused")
            self.assertTrue(events[-1].terminal)
            journal.close()

    def test_environment_states_are_normalized_to_event_phase_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected_case = json.loads(ENVIRONMENT_FIXTURE.read_text(encoding="utf-8"))[0]
            journal = self.open_journal(root / "events.sqlite3", seconds=tuple(range(100)))
            provider = FixtureProvider(selected_case, root / "provider")
            manager = EnvironmentManager(
                ProviderRegistry((provider,)),
                clock=EnvironmentClock(),
                id_generator=EnvironmentIds(),
                event_publisher=journal,
            )
            record = manager.plan(recipe(selected_case), provider.descriptor.name)
            manager._transition(record, "verifying_artifacts", "fixture transition")
            events = journal.read_stream(record.transaction_id)
            self.assertEqual(events[-1].phase, "verifying-artifacts")
            self.assertEqual(events[-1].attributes["to_state"], "verifying_artifacts")
            journal.close()

    def test_controller_exposes_events_subscriptions_health_and_progress_without_rendering(self) -> None:
        class NullDoctor:
            def inspect(self, configuration: object) -> object:
                raise AssertionError("doctor is not used")

        with tempfile.TemporaryDirectory() as directory:
            journal = self.open_journal(Path(directory) / "events.sqlite3")
            controller = ControlPlaneController(ControlPlaneServices(machine_doctor=NullDoctor(), event_journal=journal))
            stored = controller.publish_lifecycle_event(draft(current=10))
            self.assertEqual(controller.read_lifecycle_events().events[0], stored)
            self.assertEqual(controller.inspect_progress(stored.event.stream_id).current, 10)
            self.assertEqual(controller.inspect_event_journal_health()["retained_event_count"], 1)
            self.assertEqual(controller.subscribe_lifecycle_events(journal.cursor()).next_batch(timeout_seconds=0).events, ())
            controller.close_event_journal()
        missing = ControlPlaneController(ControlPlaneServices(machine_doctor=NullDoctor()))
        with self.assertRaisesRegex(RuntimeError, "event journal"):
            missing.read_lifecycle_events()


if __name__ == "__main__":
    unittest.main()
