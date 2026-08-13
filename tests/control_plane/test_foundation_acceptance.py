from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2] if "tests" in Path(__file__).parts else None
if ROOT is None or not (ROOT / "control-plane").exists():
    ROOT = Path("/root/personal/strling-lang/regex-conformance")
CONTROL_PLANE = ROOT / "control-plane" / "python"
CONTROL_TESTS = ROOT / "tests" / "control_plane"
for source in (CONTROL_PLANE, CONTROL_TESTS):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_control_plane.cache_manager import TransferManager  # noqa: E402
from regex_conformance_control_plane.containment import ContainedProcessSupervisor, ExecutionLimits  # noqa: E402
from regex_conformance_control_plane.controller import ControlPlaneController, ControlPlaneServices  # noqa: E402
from regex_conformance_control_plane.environment_manager import EnvironmentManager  # noqa: E402
from regex_conformance_control_plane.environment_models import AdmissionDecision  # noqa: E402
from regex_conformance_control_plane.environment_providers import ProviderRegistry  # noqa: E402
from regex_conformance_control_plane.event_models import ProgressAggregator  # noqa: E402
from regex_conformance_control_plane.event_store import EventJournal  # noqa: E402
from regex_conformance_control_plane.resource_models import ResourceEstimate  # noqa: E402
from regex_conformance_control_plane.resource_planner import ResourcePlanner  # noqa: E402
from regex_conformance_control_plane.state_store import LocalStateStore, StateReconciler  # noqa: E402

from test_cache_manager import (  # noqa: E402
    BytesSource,
    FixedClock as CacheClock,
    FixedIds as CacheIds,
    StaticProvider as CacheProvider,
    entry as cache_entry,
    manager as cache_manager,
    policy as cache_policy,
)
from test_cli import StubControl, invoke as invoke_cli, recipe as cli_recipe, write_json  # noqa: E402
from test_environment_manager import (  # noqa: E402
    FixedClock as EnvironmentClock,
    FixedIds as EnvironmentIds,
    FixtureProvider,
    recipe as environment_recipe,
)
from test_event_stream import FixedIds as EventIds, TickingClock, draft, opid  # noqa: E402
from test_machine_doctor import controller as doctor_controller  # noqa: E402
from test_resource_planner import (  # noqa: E402
    FixedClock as ResourceClock,
    FixedReservationIds,
    inventory as resource_inventory,
    planned_environment,
    policy as resource_policy,
)
from test_state_store import (  # noqa: E402
    FixedClock as StateClock,
    FixedIds as StateIds,
    command_id,
    mutation,
    provider_observation,
)


class StaticDoctor:
    def __init__(self, report: object) -> None:
        self.report = report

    def inspect(self, configuration: object) -> object:
        return self.report


@unittest.skipUnless(os.name == "posix", "full foundation certification runs on disposable Ubuntu")
class ControlPlaneFoundationAcceptanceGate(unittest.TestCase):
    """Independent clean-host and fault-recovery proof for the P16A hard gate."""

    def test_clean_host_fault_recovery_and_safe_admission(self) -> None:
        report: dict[str, object] = {}
        machine_case = json.loads(
            (ROOT / "tests" / "control_plane" / "fixtures" / "machines.json").read_text(encoding="utf-8")
        )[0]
        doctor, configuration, discovery = doctor_controller(machine_case)
        path_state_before = {
            str(path): path.exists()
            for _, path in configuration.pool_paths
        }
        machine = doctor.inspect_machine(configuration)
        self.assertEqual(machine.status, "healthy")
        self.assertEqual(discovery.calls, 1)
        self.assertFalse(machine.to_dict()["safety_configuration"]["mutation_permitted"])
        self.assertEqual(path_state_before, {str(path): path.exists() for _, path in configuration.pool_paths})
        report["machine-inspection"] = "healthy-and-non-mutating"

        resource_fixture = json.loads(
            (ROOT / "tests" / "control_plane" / "fixtures" / "resource_admission.json").read_text(
                encoding="utf-8"
            )
        )
        planner = ResourcePlanner(
            resource_policy(resource_fixture),
            clock=ResourceClock(),
            id_generator=FixedReservationIds(100),
        )
        planned = planned_environment()
        environment_plan = planner.environment_plan(
            planned,
            machine_provider_name="native-runtime",
            required_capabilities=("process-tree-termination",),
            eligible_trust_classes=("development",),
        )
        self.assertFalse(environment_plan.mutation_permitted)
        insufficient = planner.preflight(environment_plan, resource_inventory(disk_available=200))
        self.assertEqual(insufficient.outcome, "rejected")
        self.assertIn("resource-capacity-insufficient", {item.code for item in insufficient.issues})
        report["insufficient-disk"] = "rejected-before-acquisition"

        low_confidence_plan = planner.workload_plan(
            operation_kind="campaign",
            operation_id="rcid:v1:campaign-manifest:h:jcs-sha256-v1:" + "9" * 64,
            estimates=(
                ResourceEstimate(
                    "low-confidence-spool",
                    "result_spool",
                    "bytes",
                    100,
                    200,
                    "bounded",
                    "acceptance-fixture",
                ),
            ),
            eligible_trust_classes=("development",),
        )
        low_confidence = planner.preflight(low_confidence_plan, resource_inventory())
        spool = next(
            item for item in low_confidence.resource_evaluations if item.pool_kind == "result_spool"
        )
        self.assertEqual(spool.margin, 50)
        self.assertEqual(low_confidence.outcome, "admitted")
        report["low-confidence"] = "25-percent-margin-admitted"

        environment_cases = json.loads(
            (ROOT / "tests" / "control_plane" / "fixtures" / "environment_lifecycles.json").read_text(
                encoding="utf-8"
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            interrupted_provider = FixtureProvider(
                environment_cases[1], root / "interrupted", failure_stage="partial-acquire"
            )
            interrupted_manager = EnvironmentManager(
                ProviderRegistry((interrupted_provider,)),
                clock=EnvironmentClock(),
                id_generator=EnvironmentIds(200),
            )
            interrupted_control = ControlPlaneController(
                ControlPlaneServices(StaticDoctor(resource_inventory()), interrupted_manager)
            )
            interrupted_planned = interrupted_control.plan_environment(
                environment_recipe(environment_cases[1]), interrupted_provider.descriptor.name
            )
            self.assertFalse(interrupted_provider.root.exists())
            interrupted_admitted = interrupted_control.admit_environment(
                interrupted_planned, AdmissionDecision(True, "gate-admission", "fault injection admitted")
            )
            interrupted = interrupted_control.realize_environment(interrupted_admitted)
            self.assertEqual((interrupted.state, interrupted.failure.code), ("failed", "partial-acquisition"))
            self.assertTrue(interrupted.rollback.succeeded)
            self.assertFalse(interrupted_provider.root.exists())
            report["interrupted-acquisition"] = "rolled-back-with-evidence"

            mismatch_provider = FixtureProvider(
                environment_cases[0], root / "mismatch", corrupt_artifact="runtime"
            )
            mismatch_manager = EnvironmentManager(
                ProviderRegistry((mismatch_provider,)),
                clock=EnvironmentClock(),
                id_generator=EnvironmentIds(300),
            )
            mismatch_control = ControlPlaneController(
                ControlPlaneServices(StaticDoctor(resource_inventory()), mismatch_manager)
            )
            mismatch_planned = mismatch_control.plan_environment(
                environment_recipe(environment_cases[0]), mismatch_provider.descriptor.name
            )
            mismatch_admitted = mismatch_control.admit_environment(
                mismatch_planned, AdmissionDecision(True, "gate-admission", "fault injection admitted")
            )
            mismatch = mismatch_control.realize_environment(mismatch_admitted)
            self.assertEqual((mismatch.state, mismatch.failure.code), ("failed", "artifact-identity-mismatch"))
            self.assertTrue(mismatch.rollback.succeeded)
            self.assertIsNone(mismatch.environment_fingerprint_id)
            report["identity-mismatch"] = "rejected-and-rolled-back"

            ready_provider = FixtureProvider(environment_cases[0], root / "ready")
            ready_manager = EnvironmentManager(
                ProviderRegistry((ready_provider,)),
                clock=EnvironmentClock(),
                id_generator=EnvironmentIds(400),
            )
            ready_control = ControlPlaneController(
                ControlPlaneServices(
                    machine_doctor=StaticDoctor(resource_inventory()),
                    environment_manager=ready_manager,
                    resource_planner=planner,
                )
            )
            ready_planned = ready_control.plan_environment(
                environment_recipe(environment_cases[0]), ready_provider.descriptor.name
            )
            ready_resource_plan = ready_control.plan_environment_resources(
                ready_planned,
                machine_provider_name="native-runtime",
                required_capabilities=("process-tree-termination",),
                eligible_trust_classes=("development",),
            )
            ready_preflight = ready_control.preflight_resources(ready_resource_plan, resource_inventory())
            self.assertEqual(ready_preflight.outcome, "admitted")
            self.assertEqual(ready_provider.calls, ["plan"])
            ready_admitted = ready_control.admit_environment_from_preflight(ready_planned, ready_preflight)
            ready = ready_control.realize_environment(ready_admitted)
            self.assertEqual(ready.state, "ready")
            self.assertIsNotNone(ready.environment_fingerprint_id)
            report["safe-admission"] = "verified-ready-after-preflight"

            reclaimable = cache_entry("gate-reclaimable")
            protected = cache_entry("gate-protected", pinned=True)
            cache = cache_manager()
            cache_inventory = cache.inventory((reclaimable, protected))
            cache_provider = CacheProvider((reclaimable, protected))
            cleanup = cache.plan_cleanup(
                cache_inventory,
                cache.reconcile(cache_inventory, cache_provider),
                reclaimable.reclaimable_bytes,
                cache_policy(),
            )
            self.assertEqual(tuple(item.cache_key for item in cleanup.selected), ("gate-reclaimable",))
            cleanup_report = cache.execute_cleanup(cleanup, cache_inventory, cache_provider)
            self.assertEqual(cleanup_report.state, "completed")
            self.assertEqual(cleanup_report.actual_reclaim_bytes, reclaimable.reclaimable_bytes)
            self.assertEqual(cache_provider.deleted, ["gate-reclaimable"])
            report["cache-reclamation"] = "planned-reconciled-protected"

            payload = b"foundation-gate-transfer"
            transfers = TransferManager(root / "transfers", clock=CacheClock(), id_generator=CacheIds())
            transfer = transfers.plan(
                operation="download",
                locator="fixture://foundation-gate",
                expected_sha256=hashlib.sha256(payload).hexdigest(),
                expected_size_bytes=len(payload),
                relative_path="objects/foundation.bin",
            )
            partial = transfers.resume_download(transfer, BytesSource(payload), chunk_size=8, maximum_chunks=1)
            completed = transfers.resume_download(partial, BytesSource(payload), chunk_size=8)
            self.assertEqual([attempt.outcome for attempt in completed.attempts], ["interrupted", "completed"])
            self.assertEqual(completed.state, "completed")
            report["transfer-resume"] = "distinct-attempts-exact-digest"

            state_path = root / "state.sqlite3"
            state_ids = StateIds()
            state = LocalStateStore.open(state_path, clock=StateClock(), id_generator=state_ids)
            reconciler = StateReconciler(clock=StateClock(), id_generator=state_ids)
            self.assertEqual(state.apply_reconciliation(reconciler.plan(state.snapshot(), ())).status, "ready")
            before_state = state.snapshot()
            state.apply_batch(
                (mutation(),),
                command_id=command_id(700),
                reason_code="foundation-gate-ready",
                expected_epoch=before_state.epoch,
            )
            state.close()
            reopened = LocalStateStore.open(state_path, clock=StateClock(), id_generator=state_ids)
            restart = reopened.snapshot()
            self.assertEqual(restart.prior_shutdown, "clean")
            self.assertEqual(restart.admission_state, "reconciliation-required")
            self.assertEqual(restart.records[0].record_id, "environment/demo")
            reconciled = reconciler.plan(restart, (provider_observation(),))
            self.assertEqual(reopened.apply_reconciliation(reconciled).status, "ready")
            self.assertEqual(reopened.snapshot().records[0].verification_status, "verified")
            reopened.close()
            report["durable-restart"] = "retained-and-reconciled"

            event_path = root / "events.sqlite3"
            journal = EventJournal.open(
                event_path,
                maximum_events=20,
                clock=TickingClock((0, 1)),
                id_generator=EventIds(),
            )
            journal.publish(draft(current=40), event_id=opid("lifecycle-event", 8000))
            journal.publish(
                draft(status="interrupted", current=40), event_id=opid("lifecycle-event", 8001)
            )
            journal.close()
            journal = EventJournal.open(
                event_path,
                maximum_events=20,
                clock=TickingClock((10, 12)),
                id_generator=EventIds(),
            )
            journal.publish(
                draft(status="resumed", current=40, attempt=2),
                event_id=opid("lifecycle-event", 8002),
            )
            journal.publish(
                draft(status="completed", current=100, attempt=2, terminal=True),
                event_id=opid("lifecycle-event", 8003),
            )
            progress = ProgressAggregator.project(journal.read_stream(opid("transfer", 100)))
            self.assertTrue(progress.terminal)
            self.assertTrue(progress.history_complete)
            self.assertEqual((progress.attempt, progress.current, progress.percent_basis_points), (2, 100, 10_000))
            journal.close()
            report["structured-progress"] = "restart-resume-terminal-complete"

            recipe_path = write_json(root, "cli-recipe.json", cli_recipe())
            cli_control = StubControl()
            code, output, error = invoke_cli(
                [
                    "env", "acquire", "--recipe", str(recipe_path), "--provider", "fixture-native",
                    "--machine-provider", "fixture-native", "--format", "json",
                ],
                cli_control,
            )
            document = json.loads(output)
            self.assertEqual((code, error), (0, ""))
            self.assertTrue(document["dry_run"])
            self.assertFalse(document["changed"])
            self.assertEqual(
                [name for name, _ in cli_control.calls],
                ["plan_environment", "plan_environment_resources", "inspect_machine", "preflight_resources"],
            )
            report["cli-dry-run"] = "same-plan-no-mutation"

            contained = ContainedProcessSupervisor().run(
                (sys.executable, "-c", "import time; time.sleep(30)"),
                limits=ExecutionLimits(100, 128, 128),
            )
            self.assertEqual(contained.outcome, "wall-time-limit")
            self.assertLess(contained.wall_time_ms, 2_000)
            self.assertFalse(contained.to_dict()["semantic_authority"])
            report["unsafe-workload"] = "process-tree-wall-limit"

        expected_sections = {
            "machine-inspection", "insufficient-disk", "low-confidence", "interrupted-acquisition",
            "identity-mismatch", "safe-admission", "cache-reclamation", "transfer-resume",
            "durable-restart", "structured-progress", "cli-dry-run", "unsafe-workload",
        }
        self.assertEqual(set(report), expected_sections)


if __name__ == "__main__":
    unittest.main()
