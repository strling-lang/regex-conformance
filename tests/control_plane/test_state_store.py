from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "control-plane" / "python"
if str(CONTROL_PLANE) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE))

from regex_conformance_control_plane.controller import ControlPlaneController, ControlPlaneServices
from regex_conformance_control_plane.state_models import (
    ReconciliationObservation,
    SecretMaterialError,
    StateModelError,
    StateMutation,
    StateSourceReference,
    canonical_object,
)
from regex_conformance_control_plane.state_store import (
    DurableStateService,
    IncompatibleStateVersionError,
    LocalStateStore,
    StaleReconciliationPlanError,
    StateAdmissionError,
    StateConflictError,
    StateCorruptionError,
    StateReconciler,
    StateRecovery,
    StateStoreBusyError,
    UnsafeStatePathError,
)

FIXTURE = ROOT / "tests" / "control_plane" / "fixtures" / "operational_state.json"
SCHEMA = ROOT / "schemas" / "json" / "operational-state.schema.json"
NOW = "2026-08-13T01:30:00+00:00"
OBSERVED = "2026-08-13T01:30:00Z"


class FixedClock:
    def now(self) -> datetime:
        return datetime.fromisoformat(NOW)


class FixedIds:
    def __init__(self) -> None:
        self.sequence = 1

    def _new(self, namespace: str) -> str:
        value = f"opid:v1:{namespace}:u7:019ff82c-9517-76fb-a67d-{self.sequence:012x}"
        self.sequence += 1
        return value

    def new_store_id(self) -> str:
        return self._new("control-plane-state")

    def new_session_id(self) -> str:
        return self._new("control-plane-session")

    def new_reconciliation_id(self) -> str:
        return self._new("state-reconciliation")


class NullDoctor:
    def inspect(self, configuration: object) -> object:
        raise AssertionError("machine inspection is not used by state tests")


def command_id(sequence: int) -> str:
    return f"opid:v1:state-command:u7:019ff82c-9517-76fb-a67d-{sequence:012x}"


def local_source(sequence: int = 1) -> StateSourceReference:
    return StateSourceReference("local-operation", command_id(sequence), OBSERVED, True)


def mutation(
    *,
    record_kind: str = "environment-instance",
    record_id: str = "environment/demo",
    lifecycle_state: str = "ready",
    payload: dict[str, object] | None = None,
    expected_generation: int | None = None,
    source_sequence: int = 1,
) -> StateMutation:
    return StateMutation.from_payload(
        record_kind=record_kind,
        record_id=record_id,
        lifecycle_state=lifecycle_state,
        verification_status="provisional",
        payload=payload or {"provider_handle": "fixture:demo"},
        sources=(local_source(source_sequence),),
        expected_generation=expected_generation,
    )


def provider_observation(
    *,
    record_kind: str = "environment-instance",
    record_id: str = "environment/demo",
    lifecycle_state: str = "ready",
    payload: dict[str, object] | None = None,
    observed_at: str = OBSERVED,
    source_id: str = "provider://fixture/environment/demo",
    verified: bool = True,
) -> ReconciliationObservation:
    return ReconciliationObservation.present(
        record_kind=record_kind,
        record_id=record_id,
        lifecycle_state=lifecycle_state,
        payload=payload or {"provider_handle": "fixture:demo"},
        observed_at=observed_at,
        source_kind="provider-reality",
        source_id=source_id,
        verified=verified,
    )


class DurableStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        cls.validator = Draft202012Validator(cls.schema, format_checker=FormatChecker())
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def validate(self, value: dict[str, object]) -> None:
        errors = sorted(self.validator.iter_errors(value), key=lambda item: list(item.absolute_path))
        if errors:
            self.fail(errors[0].message)

    @staticmethod
    def open_store(path: Path, ids: FixedIds) -> LocalStateStore:
        return LocalStateStore.open(path, clock=FixedClock(), id_generator=ids)

    @staticmethod
    def make_ready(store: LocalStateStore, ids: FixedIds) -> object:
        plan = StateReconciler(clock=FixedClock(), id_generator=ids).plan(store.snapshot(), ())
        return store.apply_reconciliation(plan)

    def test_new_store_fails_closed_until_empty_reconciliation_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ids = FixedIds()
            store = self.open_store(Path(directory) / "state.sqlite3", ids)
            snapshot = store.snapshot()
            self.assertEqual(snapshot.admission_state, "reconciliation-required")
            self.assertEqual(snapshot.prior_shutdown, "new")
            self.assertFalse(snapshot.to_dict()["canonical_authority"])
            with self.assertRaises(StateAdmissionError):
                store.require_ready()
            plan = StateReconciler(clock=FixedClock(), id_generator=ids).plan(snapshot, ())
            self.assertTrue(plan.ready_after_apply)
            report = store.apply_reconciliation(plan)
            self.assertEqual(report.status, "ready")
            self.validate(snapshot.to_dict())
            self.validate(plan.to_dict())
            self.validate(report.to_dict())
            self.assertEqual(store.health_check()["quick_check"], "ok")
            store.close()
            reopened = self.open_store(Path(directory) / "state.sqlite3", ids)
            self.assertEqual(reopened.snapshot().prior_shutdown, "clean")
            self.assertEqual(reopened.snapshot().admission_state, "reconciliation-required")
            reopened.close()

    def test_atomic_compare_and_swap_idempotency_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ids = FixedIds()
            store = self.open_store(Path(directory) / "state.sqlite3", ids)
            self.make_ready(store, ids)
            before = store.snapshot()
            first_mutation = mutation()
            first = store.apply_batch(
                (first_mutation,),
                command_id=command_id(1),
                reason_code="environment-ready",
                expected_epoch=before.epoch,
            )
            self.assertEqual(first.records[0].generation, 1)
            repeated = store.apply_batch(
                (first_mutation,),
                command_id=command_id(1),
                reason_code="environment-ready",
                expected_epoch=before.epoch,
            )
            self.assertEqual(repeated.epoch, first.epoch)
            self.assertEqual(repeated.records[0].generation, 1)
            with self.assertRaisesRegex(StateConflictError, "reused"):
                store.apply_batch(
                    (mutation(payload={"provider_handle": "different"}),),
                    command_id=command_id(1),
                    reason_code="environment-ready",
                    expected_epoch=before.epoch,
                )
            with self.assertRaisesRegex(StateConflictError, "epoch changed"):
                store.apply_batch(
                    (mutation(record_id="environment/other"),),
                    command_id=command_id(2),
                    reason_code="environment-ready",
                    expected_epoch=before.epoch,
                )
            second = store.apply_batch(
                (
                    mutation(
                        lifecycle_state="releasing",
                        payload={"provider_handle": "fixture:demo", "release_started": True},
                        expected_generation=1,
                        source_sequence=2,
                    ),
                ),
                command_id=command_id(2),
                reason_code="release-started",
                expected_epoch=first.epoch,
            )
            self.assertEqual(second.records[0].generation, 2)
            history = store.transition_history("environment-instance", "environment/demo")
            self.assertEqual([item["to_generation"] for item in history], [1, 2])
            self.assertEqual([item["reason_code"] for item in history], ["environment-ready", "release-started"])
            store.close()

    def test_injected_failure_after_first_sql_mutation_rolls_back_entire_batch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ids = FixedIds()
            store = self.open_store(Path(directory) / "state.sqlite3", ids)
            self.make_ready(store, ids)
            before = store.snapshot()
            changes = (
                mutation(record_id="environment/alpha"),
                mutation(record_id="environment/beta", source_sequence=2),
            )
            original = store._persist_mutation
            calls = 0

            def fail_after_first(*args: object, **kwargs: object) -> object:
                nonlocal calls
                calls += 1
                result = original(*args, **kwargs)
                if calls == 2:
                    raise OSError("seeded power loss before commit")
                return result

            with patch.object(store, "_persist_mutation", side_effect=fail_after_first):
                with self.assertRaisesRegex(OSError, "seeded power loss"):
                    store.apply_batch(
                        changes,
                        command_id=command_id(1),
                        reason_code="batch-test",
                        expected_epoch=before.epoch,
                    )
            after = store.snapshot()
            self.assertEqual(after.epoch, before.epoch)
            self.assertEqual(after.records, ())
            self.assertEqual(store.transition_history("environment-instance", "environment/alpha"), ())
            store.close()

    def test_payload_canonicalization_and_secret_refusal(self) -> None:
        one = canonical_object({"z": 2, "a": {"b": 1}})
        two = canonical_object({"a": {"b": 1}, "z": 2})
        self.assertEqual(one, two)
        for payload in (
            {"access_token": "not-persistable"},
            {"locator": "https://user:pass@example.invalid/object"},
            {"locator": "https://example.invalid/object?token=not-persistable"},
            {"header": "Bearer abcdefghijklmnop"},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(SecretMaterialError):
                    mutation(payload=payload)
        with self.assertRaises(StateModelError):
            mutation(payload={"unsafe": 2**54})
        with self.assertRaises(StateModelError):
            mutation(payload={"unsafe": float("nan")})
        with self.assertRaisesRegex(StateModelError, "external provenance"):
            StateMutation.from_payload(
                record_kind="environment-instance",
                record_id="environment/forged-verified",
                lifecycle_state="ready",
                verification_status="verified",
                payload={"provider_handle": "fixture:demo"},
                sources=(local_source(),),
                expected_generation=None,
            )

    def test_process_lock_refuses_a_second_live_controller(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            first = self.open_store(path, FixedIds())
            with self.assertRaises(StateStoreBusyError):
                self.open_store(path, FixedIds())
            first.close()
            second = self.open_store(path, FixedIds())
            second.close()

    def test_forced_process_exit_retains_state_and_marks_prior_shutdown_unclean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            code = f"""
import os
from pathlib import Path
from regex_conformance_control_plane.state_models import StateMutation, StateSourceReference
from regex_conformance_control_plane.state_store import LocalStateStore, StateReconciler
path = Path({str(path)!r})
store = LocalStateStore.open(path)
store.apply_reconciliation(StateReconciler().plan(store.snapshot(), ()))
snapshot = store.snapshot()
source = StateSourceReference('local-operation', 'opid:v1:state-command:u7:019ff82c-9517-76fb-a67d-000000000099', snapshot.observed_at, True)
change = StateMutation.from_payload(record_kind='environment-instance', record_id='environment/forced-exit', lifecycle_state='ready', verification_status='provisional', payload={{'provider_handle':'fixture:forced'}}, sources=(source,), expected_generation=None)
store.apply_batch((change,), command_id='opid:v1:state-command:u7:019ff82c-9517-76fb-a67d-000000000099', reason_code='forced-exit-fixture', expected_epoch=snapshot.epoch)
os._exit(23)
"""
            environment = dict(os.environ)
            environment["PYTHONPATH"] = os.pathsep.join(
                item for item in (str(CONTROL_PLANE), environment.get("PYTHONPATH", "")) if item
            )
            process = subprocess.run([sys.executable, "-c", code], env=environment, check=False)
            self.assertEqual(process.returncode, 23)
            reopened = LocalStateStore.open(path)
            snapshot = reopened.snapshot()
            self.assertEqual(snapshot.prior_shutdown, "unclean")
            self.assertEqual(snapshot.admission_state, "reconciliation-required")
            self.assertEqual(snapshot.records[0].record_id, "environment/forced-exit")
            reopened.close()

    def test_stale_reality_quarantines_then_fresh_reality_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ids = FixedIds()
            path = Path(directory) / "state.sqlite3"
            store = self.open_store(path, ids)
            self.make_ready(store, ids)
            snapshot = store.snapshot()
            store.apply_batch(
                (mutation(),),
                command_id=command_id(1),
                reason_code="seed-state",
                expected_epoch=snapshot.epoch,
            )
            store.close()
            store = self.open_store(path, ids)
            reconciler = StateReconciler(clock=FixedClock(), id_generator=ids)
            stale = provider_observation(observed_at="2026-08-13T01:00:00Z")
            plan = reconciler.plan(store.snapshot(), (stale,), maximum_observation_age_seconds=300)
            self.assertEqual(plan.issues[0].code, "stale-reality")
            self.assertEqual(plan.actions[0].action, "quarantine")
            report = store.apply_reconciliation(plan)
            self.assertEqual(report.status, "blocked")
            self.assertEqual(store.snapshot().records[0].verification_status, "quarantined")
            fresh_plan = reconciler.plan(store.snapshot(), (provider_observation(),))
            self.assertEqual(fresh_plan.actions[0].action, "replace")
            self.assertEqual(store.apply_reconciliation(fresh_plan).status, "ready")
            recovered = store.snapshot().records[0]
            self.assertEqual(recovered.lifecycle_state, "ready")
            self.assertEqual(recovered.verification_status, "verified")
            store.close()

    def test_conflicting_verified_sources_block_without_inventing_a_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ids = FixedIds()
            store = self.open_store(Path(directory) / "state.sqlite3", ids)
            provider = provider_observation(
                record_kind="transfer",
                record_id="transfer/demo",
                payload={"bytes_completed": 10},
                source_id="provider://fixture/transfer/demo",
            )
            evidence = ReconciliationObservation.present(
                record_kind="transfer",
                record_id="transfer/demo",
                lifecycle_state="completed",
                payload={"bytes_completed": 20},
                observed_at=OBSERVED,
                source_kind="immutable-evidence",
                source_id="rcid:v1:evidence-manifest:h:jcs-sha256-v1:" + "a" * 64,
            )
            plan = StateReconciler(clock=FixedClock(), id_generator=ids).plan(
                store.snapshot(), (provider, evidence)
            )
            self.assertEqual(plan.issues[0].code, "source-conflict")
            self.assertEqual(plan.actions, ())
            self.assertEqual(store.apply_reconciliation(plan).status, "blocked")
            self.assertEqual(store.snapshot().records, ())
            store.close()

    def test_wrong_authority_and_unverified_reality_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ids = FixedIds()
            store = self.open_store(Path(directory) / "state.sqlite3", ids)
            wrong = ReconciliationObservation.present(
                record_kind="environment-instance",
                record_id="environment/demo",
                lifecycle_state="ready",
                payload={"provider_handle": "fixture:demo"},
                observed_at=OBSERVED,
                source_kind="repository-manifest",
                source_id="rcid:v1:campaign-manifest:h:jcs-sha256-v1:" + "b" * 64,
            )
            plan = StateReconciler(clock=FixedClock(), id_generator=ids).plan(store.snapshot(), (wrong,))
            self.assertEqual(plan.issues[0].code, "wrong-source-authority")
            self.assertEqual(store.apply_reconciliation(plan).status, "blocked")
            unverified = provider_observation(verified=False)
            plan = StateReconciler(clock=FixedClock(), id_generator=ids).plan(store.snapshot(), (unverified,))
            self.assertEqual(plan.issues[0].code, "unverified-reality")
            self.assertEqual(store.apply_reconciliation(plan).status, "blocked")
            store.close()

    def test_verified_absence_creates_traceable_tombstone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ids = FixedIds()
            store = self.open_store(Path(directory) / "state.sqlite3", ids)
            self.make_ready(store, ids)
            before = store.snapshot()
            store.apply_batch(
                (mutation(),),
                command_id=command_id(1),
                reason_code="seed-state",
                expected_epoch=before.epoch,
            )
            absent = ReconciliationObservation.absent(
                record_kind="environment-instance",
                record_id="environment/demo",
                observed_at=OBSERVED,
                source_kind="provider-reality",
                source_id="provider://fixture/environment/demo",
            )
            plan = StateReconciler(clock=FixedClock(), id_generator=ids).plan(store.snapshot(), (absent,))
            self.assertEqual(plan.actions[0].action, "tombstone")
            self.assertEqual(store.apply_reconciliation(plan).status, "ready")
            record = store.snapshot().records[0]
            self.assertTrue(record.tombstoned)
            self.assertEqual(record.lifecycle_state, "absent")
            self.assertEqual(record.payload, {})
            self.assertEqual(len(store.transition_history(record.record_kind, record.record_id)), 2)
            store.close()
            restarted = self.open_store(Path(directory) / "state.sqlite3", ids)
            missing = StateReconciler(clock=FixedClock(), id_generator=ids).plan(restarted.snapshot(), ())
            self.assertEqual(missing.issues[0].code, "missing-reality")
            self.assertEqual(missing.actions[0].action, "quarantine")
            self.assertEqual(restarted.apply_reconciliation(missing).status, "blocked")
            restarted.close()

    def test_state_loss_rebuilds_from_verified_reality_without_canonical_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ids = FixedIds()
            path = Path(directory) / "lost-state.sqlite3"
            result = StateRecovery.rebuild(
                path,
                (provider_observation(),),
                reason_code="state-loss",
                clock=FixedClock(),
                id_generator=ids,
            )
            self.assertIsNone(result.quarantine_manifest)
            self.assertEqual(result.report.status, "ready")
            snapshot = result.store.snapshot()
            self.assertFalse(snapshot.canonical_authority)
            self.assertEqual(snapshot.records[0].verification_status, "verified")
            self.validate(snapshot.to_dict())
            result.store.close()

    def test_corruption_is_preserved_then_explicitly_rebuilt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ids = FixedIds()
            path = Path(directory) / "corrupt-state.sqlite3"
            corrupted = b"not-a-sqlite-database\x00with-preserved-bytes"
            path.write_bytes(corrupted)
            with self.assertRaises(StateCorruptionError):
                self.open_store(path, ids)
            self.assertEqual(path.read_bytes(), corrupted)
            result = StateRecovery.rebuild(
                path,
                (provider_observation(),),
                reason_code="corrupt-database",
                clock=FixedClock(),
                id_generator=ids,
            )
            self.assertEqual(result.report.status, "ready")
            self.assertIsNotNone(result.quarantine_manifest)
            manifest_path = result.quarantine_manifest
            assert manifest_path is not None
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            expected_digest = hashlib.sha256(corrupted).hexdigest()
            self.assertEqual(manifest["files"][0]["sha256"], expected_digest)
            quarantined_file = manifest_path.parent / manifest["files"][0]["name"]
            self.assertEqual(quarantined_file.read_bytes(), corrupted)
            result.store.close()

    def test_newer_database_version_is_refused_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "future.sqlite3"
            connection = sqlite3.connect(path)
            connection.execute("PRAGMA user_version = 999")
            connection.close()
            before = path.read_bytes()
            with self.assertRaises(IncompatibleStateVersionError):
                self.open_store(path, FixedIds())
            self.assertEqual(path.read_bytes(), before)

    def test_tampered_payload_is_detected_before_a_session_starts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ids = FixedIds()
            path = Path(directory) / "state.sqlite3"
            store = self.open_store(path, ids)
            self.make_ready(store, ids)
            before = store.snapshot()
            store.apply_batch(
                (mutation(),),
                command_id=command_id(1),
                reason_code="seed-state",
                expected_epoch=before.epoch,
            )
            store.close()
            connection = sqlite3.connect(path)
            connection.execute(
                "UPDATE operational_records SET payload_json = ? WHERE record_id = ?",
                ('{"forged":true}', "environment/demo"),
            )
            connection.commit()
            connection.close()
            with self.assertRaises(StateCorruptionError):
                self.open_store(path, ids)

    def test_migration_checksum_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            store = self.open_store(path, FixedIds())
            store.close()
            connection = sqlite3.connect(path)
            connection.execute("DROP TRIGGER immutable_migrations_update")
            connection.execute("UPDATE schema_migrations SET sha256 = ? WHERE version = 1", ("0" * 64,))
            connection.commit()
            connection.close()
            with self.assertRaises(StateCorruptionError):
                self.open_store(path, FixedIds())

    def test_valid_but_altered_provenance_is_detected_by_record_history_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            ids = FixedIds()
            store = self.open_store(path, ids)
            self.make_ready(store, ids)
            observation = provider_observation()
            report = store.apply_reconciliation(StateReconciler(clock=FixedClock(), id_generator=ids).plan(
                store.snapshot(),
                (observation,),
            ))
            self.assertEqual(report.status, "ready")
            store.close()
            connection = sqlite3.connect(path)
            connection.execute(
                "UPDATE operational_records SET sources_json = REPLACE(sources_json, ?, ?)",
                ("provider://fixture/environment/demo", "provider://fixture/environment/other"),
            )
            connection.commit()
            connection.close()
            with self.assertRaises(StateCorruptionError):
                self.open_store(path, FixedIds())

    def test_stale_reconciliation_plan_cannot_overwrite_newer_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ids = FixedIds()
            store = self.open_store(Path(directory) / "state.sqlite3", ids)
            self.make_ready(store, ids)
            reconciler = StateReconciler(clock=FixedClock(), id_generator=ids)
            stale_plan = reconciler.plan(store.snapshot(), ())
            before = store.snapshot()
            store.apply_batch(
                (mutation(),),
                command_id=command_id(1),
                reason_code="newer-state",
                expected_epoch=before.epoch,
            )
            with self.assertRaises(StaleReconciliationPlanError):
                store.apply_reconciliation(stale_plan)
            self.assertEqual(store.snapshot().records[0].record_id, "environment/demo")
            store.close()

    def test_controller_exposes_supervisor_ready_state_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ids = FixedIds()
            store = self.open_store(Path(directory) / "state.sqlite3", ids)
            service = DurableStateService(
                store,
                StateReconciler(clock=FixedClock(), id_generator=ids),
                maximum_observation_age_seconds=300,
            )
            controller = ControlPlaneController(ControlPlaneServices(NullDoctor(), local_state=service))
            self.assertEqual(controller.inspect_local_state().admission_state, "reconciliation-required")
            plan = controller.plan_restart_reconciliation(())
            self.assertEqual(controller.apply_restart_reconciliation(plan).status, "ready")
            before = controller.inspect_local_state()
            committed = controller.commit_local_state(
                (mutation(),),
                command_id=command_id(1),
                reason_code="controller-commit",
                expected_epoch=before.epoch,
            )
            self.assertEqual(committed.records[0].generation, 1)
            controller.require_local_state_ready()
            self.assertEqual(controller.inspect_local_state_health()["quick_check"], "ok")
            controller.close_local_state()

    def test_schema_rejects_canonical_claim_and_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ids = FixedIds()
            store = self.open_store(Path(directory) / "state.sqlite3", ids)
            value = store.snapshot().to_dict()
            value["canonical_authority"] = True
            with self.assertRaises(ValidationError):
                self.validator.validate(value)
            value = store.snapshot().to_dict()
            value["unexpected"] = True
            with self.assertRaises(ValidationError):
                self.validator.validate(value)
            store.close()

    def test_symlink_database_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.sqlite3"
            target.write_bytes(b"")
            link = root / "link.sqlite3"
            try:
                link.symlink_to(target)
            except (NotImplementedError, OSError):
                self.skipTest("platform does not permit unprivileged symlink creation")
            with self.assertRaises(UnsafeStatePathError):
                self.open_store(link, FixedIds())

    def test_hardlinked_database_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original.sqlite3"
            original.write_bytes(b"")
            linked = root / "linked.sqlite3"
            try:
                os.link(original, linked)
            except (NotImplementedError, OSError):
                self.skipTest("platform does not permit unprivileged hard-link creation")
            with self.assertRaises(UnsafeStatePathError):
                self.open_store(linked, FixedIds())

    def test_hardlinked_sqlite_sidecar_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "state.sqlite3"
            store = self.open_store(path, FixedIds())
            store.close()
            target = root / "unexpected-wal-material"
            target.write_bytes(b"not-a-real-wal")
            os.link(target, Path(f"{path}-wal"))
            with self.assertRaises(UnsafeStatePathError):
                self.open_store(path, FixedIds())

    def test_recovery_preflights_every_file_before_moving_the_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "state.sqlite3"
            store = self.open_store(path, FixedIds())
            store.close()
            target = root / "multiply-linked-sidecar"
            target.write_bytes(b"not-a-real-wal")
            os.link(target, Path(f"{path}-wal"))
            with self.assertRaises(UnsafeStatePathError):
                StateRecovery.rebuild(path, (), reason_code="seeded-corruption", id_generator=FixedIds())
            self.assertTrue(path.is_file())
            self.assertFalse((root / "state.sqlite3.quarantine").exists())

    def test_timezone_free_session_history_is_treated_as_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            store = self.open_store(path, FixedIds())
            store.close()
            connection = sqlite3.connect(path)
            connection.execute("UPDATE controller_sessions SET ended_at = '2026-08-12T12:00:00'")
            connection.commit()
            connection.close()
            with self.assertRaises(StateCorruptionError):
                self.open_store(path, FixedIds())

    def test_reconciliation_observation_matches_the_public_schema(self) -> None:
        self.validate(provider_observation().to_dict())

    def test_fixture_documents_every_fail_closed_reason_and_action(self) -> None:
        self.assertEqual(
            set(self.fixture["expected_restart_actions"].values()),
            {"create", "quarantine", "replace", "tombstone", "verify"},
        )
        self.assertEqual(
            set(self.fixture["expected_blocking_codes"]),
            {
                "future-reality",
                "missing-reality",
                "source-conflict",
                "stale-reality",
                "unverified-reality",
                "wrong-source-authority",
            },
        )


if __name__ == "__main__":
    unittest.main()
