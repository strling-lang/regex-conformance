from __future__ import annotations

import json
import sys
import unittest
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "control-plane" / "python"
if str(CONTROL_PLANE) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE))

from regex_conformance_control_plane.controller import ControlPlaneController, ControlPlaneServices
from regex_conformance_control_plane.environment_manager import EnvironmentManager
from regex_conformance_control_plane.environment_models import (
    ArtifactRequirement,
    EnvironmentLifecycleRecord,
    EnvironmentRecipe,
    LifecycleTransition,
    NamedValue,
    ProviderCapability as EnvironmentProviderCapability,
    ProviderDescriptor,
    ProviderPlan,
)
from regex_conformance_control_plane.environment_providers import ProviderRegistry
from regex_conformance_control_plane.models import (
    Capability,
    DoctorReport,
    MachineIdentity,
    ProviderCapability,
    ResourcePool,
    SafetyConfigurationView,
    TrustObservation,
)
from regex_conformance_control_plane.resource_models import (
    ActiveResourceUsage,
    AdmissionContext,
    AdmissionIssue,
    AdmissionPolicy,
    ConfidenceMargin,
    PoolSafetyReserve,
    ResourceAdmissionReport,
    ResourceEstimate,
    TransferForecast,
)
from regex_conformance_control_plane.resource_planner import ResourcePlanner

FIXTURE = ROOT / "tests" / "control_plane" / "fixtures" / "resource_admission.json"
SCHEMA = ROOT / "schemas" / "json" / "resource-admission.schema.json"
OBSERVED = "2026-08-12T23:00:00Z"
VALID_UNTIL = "2026-08-12T23:05:00Z"
ENVIRONMENT_ID = "opid:v1:environment:u7:019ff82c-9517-76fb-a67d-c461e9140001"


class FixedClock:
    def __init__(self, value: str = "2026-08-12T23:00:30+00:00") -> None:
        self.value = datetime.fromisoformat(value)

    def now(self) -> datetime:
        return self.value


class FixedReservationIds:
    def __init__(self, start: int = 1) -> None:
        self.value = start

    def new_resource_reservation_id(self) -> str:
        result = f"opid:v1:resource-reservation:u7:019ff82c-9517-76fb-a67d-c461e915{self.value:04x}"
        self.value += 1
        return result


class NullDoctor:
    def inspect(self, configuration: object) -> object:
        raise AssertionError("machine inspection is supplied directly by this test")


def policy(fixture: dict[str, object]) -> AdmissionPolicy:
    value = fixture["policy"]
    return AdmissionPolicy(
        confidence_margins=tuple(
            ConfidenceMargin(name, int(amount))
            for name, amount in value["confidence_margins"].items()
        ),
        pool_reserves=tuple(
            PoolSafetyReserve(name, int(item["minimum_units"]), int(item["capacity_basis_points"]))
            for name, item in value["pool_reserves"].items()
        ),
        max_concurrency=int(value["max_concurrency"]),
        inventory_max_age_seconds=int(value["inventory_max_age_seconds"]),
    )


def estimate(value: dict[str, object]) -> ResourceEstimate:
    return ResourceEstimate(
        name=str(value["name"]),
        pool_kind=str(value["pool_kind"]),
        unit=str(value["unit"]),
        expected=value["expected"],
        upper_bound=value["upper_bound"],
        confidence=str(value["confidence"]),
        source=str(value["source"]),
        diagnostic=value.get("diagnostic"),
    )


def transfer(value: dict[str, object]) -> TransferForecast:
    return TransferForecast(
        name=str(value["name"]),
        direction=str(value["direction"]),
        expected_bytes=value["expected_bytes"],
        upper_bound_bytes=value["upper_bound_bytes"],
        confidence=str(value["confidence"]),
        source=str(value["source"]),
        diagnostic=value.get("diagnostic"),
    )


def planned_environment(transaction_id: str = ENVIRONMENT_ID) -> EnvironmentLifecycleRecord:
    recipe = EnvironmentRecipe(
        recipe_revision_id="rcid:v1:environment-recipe-revision:h:jcs-sha256-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        target_profile_id="rcid:v1:profile-revision:h:jcs-sha256-v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        target_release_id="rcid:v1:release-revision:h:jcs-sha256-v1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        strategy="native-host",
        artifacts=(
            ArtifactRequirement(
                "runtime",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                10,
                "native-binary",
                ("fixture://runtime",),
            ),
        ),
        expected_runtime_facts=(NamedValue("runtime-version", "1.0"),),
        expected_configuration=(NamedValue("locale", "C.UTF-8"),),
        required_capabilities=(),
        smoke_probe_ids=("runtime-identity",),
        isolation_policy_digest="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        network_policy="offline",
    )
    descriptor = ProviderDescriptor(
        "fixture-native",
        "native-host",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        (EnvironmentProviderCapability("runtime-identity", "supported"),),
    )
    plan = ProviderPlan("fixture-native", "fixture-plan", 100, 200, 150, ("fixture resource plan",))
    transition = LifecycleTransition(1, None, "planned", OBSERVED, "environment planned")
    return EnvironmentLifecycleRecord(
        transaction_id=transaction_id,
        state="planned",
        recipe=recipe,
        provider=descriptor,
        plan=plan,
        admission=None,
        provider_handle=None,
        verified_artifacts=(),
        runtime_identity=None,
        smoke_observations=(),
        verification_digest=None,
        environment_fingerprint_id=None,
        transitions=(transition,),
    )


def inventory(
    *,
    disk_available: int = 5_000,
    disk_capacity: int = 10_000,
    ram_available: int | None = 6_000,
    provider_availability: str = "available",
    provider_accuracy: str = "exact",
    capability_status: str = "supported",
    capability_accuracy: str | None = None,
    trust_class: str = "development",
    trust_configured: bool = True,
    observed_at: str = OBSERVED,
    component_observed_at: str | None = None,
    valid_until: str = VALID_UNTIL,
    share_disk: bool = True,
) -> DoctorReport:
    component_observed_at = component_observed_at or observed_at
    disk_kinds = (
        "persistent_disk",
        "environment_cache",
        "build_scratch",
        "execution_scratch",
        "result_spool",
    )
    resources = [
        ResourcePool(
            kind=kind,
            unit="bytes",
            status="observed",
            capacity=disk_capacity,
            used=disk_capacity - disk_available,
            reserved=0,
            available=disk_available,
            source="fixture-disk",
            accuracy="exact",
            visibility="process",
            observed_at=component_observed_at,
            staleness_seconds=0,
            configured_path=f"/fixture/{kind}",
            observed_path=f"/fixture/{kind}",
            backing_store="device:fixture" if share_disk else f"device:{kind}",
        )
        for kind in disk_kinds
    ]
    if ram_available is None:
        resources.append(
            ResourcePool(
                "ram",
                "bytes",
                "unknown",
                None,
                None,
                0,
                None,
                "fixture-memory",
                "unknown",
                "process",
                component_observed_at,
                0,
                diagnostic="seeded unknown RAM",
            )
        )
    else:
        resources.append(
            ResourcePool(
                "ram",
                "bytes",
                "observed",
                8_000,
                8_000 - ram_available,
                0,
                ram_available,
                "fixture-memory",
                "exact",
                "process",
                component_observed_at,
                0,
            )
        )
    resources.extend(
        (
            ResourcePool(
                "swap",
                "bytes",
                "unknown",
                None,
                None,
                0,
                None,
                "fixture-memory",
                "unknown",
                "process",
                component_observed_at,
                0,
                diagnostic="swap is intentionally unknown",
            ),
            ResourcePool(
                "cpu",
                "logical_cpu",
                "partial",
                8,
                None,
                0,
                None,
                "fixture-affinity",
                "bounded",
                "process",
                component_observed_at,
                0,
                diagnostic="free CPU is controlled through admission accounting",
            ),
        )
    )
    capability_accuracy = capability_accuracy or ("unknown" if capability_status == "unknown" else "exact")
    return DoctorReport(
        status="healthy",
        observed_at=observed_at,
        valid_until=valid_until,
        machine=MachineIdentity("linux", "Fixture Linux", "1", "x86_64", "x86_64", "CPython", "3.12"),
        trust=TrustObservation(trust_class, "fixture", trust_configured),
        resources=tuple(resources),
        providers=(
            ProviderCapability(
                "native-runtime",
                provider_availability,
                ("native-host",),
                "fixture-provider",
                component_observed_at,
                accuracy=provider_accuracy,
            ),
        ),
        capabilities=(
            Capability(
                "process-tree-termination",
                capability_status,
                "fixture-capability",
                component_observed_at,
                True if capability_status == "supported" else None,
                accuracy=capability_accuracy,
            ),
        ),
        safety_configuration=SafetyConfigurationView(
            True,
            False,
            300,
            {kind: f"/fixture/{kind}" for kind in disk_kinds},
        ),
        diagnostics=(),
    )


class ResourcePlannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.validator = Draft202012Validator(
            json.loads(SCHEMA.read_text(encoding="utf-8")),
            format_checker=FormatChecker(),
        )

    def planner(self, *, clock: str = "2026-08-12T23:00:30+00:00") -> ResourcePlanner:
        return ResourcePlanner(
            policy(self.fixture),
            clock=FixedClock(clock),
            id_generator=FixedReservationIds(),
        )

    def validate(self, report: ResourceAdmissionReport) -> None:
        errors = sorted(
            self.validator.iter_errors(report.to_dict()),
            key=lambda error: list(error.absolute_path),
        )
        self.assertEqual(errors, [], "\n".join(error.message for error in errors))

    def campaign_plan(self, planner: ResourcePlanner, **overrides: object):
        value = self.fixture["campaign"]
        arguments = {
            "operation_kind": "campaign",
            "operation_id": value["operation_id"],
            "estimates": tuple(estimate(item) for item in value["estimates"]),
            "transfers": tuple(transfer(item) for item in value["transfers"]),
            "provider_name": "native-runtime",
            "provider_strategy": "native-host",
            "required_capabilities": tuple(value["required_capabilities"]),
            "eligible_trust_classes": ("development", "trusted_executioner"),
            "requested_concurrency": int(value["requested_concurrency"]),
        }
        arguments.update(overrides)
        return planner.workload_plan(**arguments)

    def test_environment_preflight_binds_provider_plan_and_is_only_admission_path(self) -> None:
        planner = self.planner()
        planned = planned_environment()
        work = planner.environment_plan(
            planned,
            machine_provider_name="native-runtime",
            required_capabilities=("process-tree-termination",),
        )
        self.assertFalse(work.mutation_permitted)
        self.assertEqual([item.expected for item in work.estimates[:3]], [100, 200, 150])
        self.assertEqual(work.transfers[0].expected_bytes, 100)
        report = planner.preflight(work, inventory())
        self.assertEqual(report.outcome, "admitted")
        cache = next(item for item in report.resource_evaluations if item.pool_kind == "environment_cache")
        self.assertEqual((cache.expected, cache.upper_bound, cache.margin, cache.required), (300, 300, 150, 450))
        self.validate(report)

        manager = EnvironmentManager(ProviderRegistry(()))
        control = ControlPlaneController(ControlPlaneServices(NullDoctor(), manager, planner))
        admitted = control.admit_environment_from_preflight(planned, report)
        self.assertEqual(admitted.state, "admitted")
        self.assertEqual(admitted.admission.decision_id, report.reservation_id)

    def test_campaign_plan_exposes_disk_ram_transfer_concurrency_and_margins(self) -> None:
        planner = self.planner()
        work = self.campaign_plan(planner)
        report = planner.preflight(work, inventory())
        self.assertEqual(report.outcome, "admitted")
        evaluations = {item.pool_kind: item for item in report.resource_evaluations}
        self.assertEqual(evaluations["execution_scratch"].required, 100)
        self.assertEqual(evaluations["result_spool"].required, 450)
        self.assertEqual(evaluations["ram"].required, 550)
        self.assertEqual(work.requested_concurrency, 2)
        self.assertEqual(work.transfers[0].upper_bound_bytes, 300)
        self.assertEqual(report.backing_store_evaluations[0].required, 550)
        self.validate(report)

    def test_resource_plan_and_report_serialization_is_permutation_stable(self) -> None:
        first_planner = self.planner()
        first = self.campaign_plan(first_planner)
        second_planner = self.planner()
        second = replace(
            self.campaign_plan(second_planner),
            estimates=tuple(reversed(first.estimates)),
            transfers=tuple(reversed(first.transfers)),
            required_capabilities=tuple(reversed(first.required_capabilities)),
            eligible_trust_classes=tuple(reversed(first.eligible_trust_classes)),
        )
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(
            first_planner.preflight(first, inventory()).to_dict(),
            second_planner.preflight(second, inventory()).to_dict(),
        )

    def test_exact_capacity_boundary_admits_and_one_unit_short_rejects(self) -> None:
        planner = self.planner()
        at_boundary = planner.workload_plan(
            operation_kind="shard",
            operation_id="rcid:v1:shard:h:jcs-sha256-v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            estimates=(ResourceEstimate("shard-scratch", "execution_scratch", "bytes", 900, 900, "known", "fixture"),),
        )
        admitted = planner.preflight(at_boundary, inventory(disk_available=1_000))
        self.assertEqual(admitted.outcome, "admitted")
        self.assertEqual(admitted.resource_evaluations[0].post_admission_available, 0)

        too_large = replace(
            at_boundary,
            estimates=(ResourceEstimate("shard-scratch", "execution_scratch", "bytes", 901, 901, "known", "fixture"),),
        )
        rejected = planner.preflight(too_large, inventory(disk_available=1_000))
        self.assertEqual(rejected.outcome, "rejected")
        self.assertIn("resource-capacity-insufficient", {item.code for item in rejected.issues})

    def test_shared_backing_store_prevents_logical_pool_double_spend(self) -> None:
        planner = self.planner()
        work = planner.workload_plan(
            operation_kind="campaign",
            operation_id=self.fixture["campaign"]["operation_id"],
            estimates=(
                ResourceEstimate("execution", "execution_scratch", "bytes", 600, 600, "known", "fixture"),
                ResourceEstimate("spool", "result_spool", "bytes", 600, 600, "known", "fixture"),
            ),
        )
        report = planner.preflight(work, inventory(disk_available=1_000))
        self.assertTrue(all(item.status == "pass" for item in report.resource_evaluations))
        self.assertEqual(report.backing_store_evaluations[0].status, "fail")
        self.assertIn("backing-store-capacity-insufficient", {item.code for item in report.issues})
        self.assertEqual(report.outcome, "rejected")

    def test_unknown_and_low_confidence_forecasts_fail_or_receive_conservative_margin(self) -> None:
        planner = self.planner()
        unknown = planner.workload_plan(
            operation_kind="shard",
            operation_id="rcid:v1:shard:h:jcs-sha256-v1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            estimates=(ResourceEstimate("unknown-spool", "result_spool", "bytes", None, None, "unknown", "fixture", "not sampled"),),
        )
        rejected = planner.preflight(unknown, inventory())
        self.assertEqual(rejected.outcome, "rejected")
        self.assertEqual(rejected.resource_evaluations[0].status, "unknown")
        self.assertIn("resource-estimate-unknown", {item.code for item in rejected.issues})

        estimated = replace(
            unknown,
            estimates=(ResourceEstimate("estimated-spool", "result_spool", "bytes", 400, 600, "estimated", "fixture"),),
        )
        boundary = planner.preflight(estimated, inventory(disk_available=1_000))
        evaluation = boundary.resource_evaluations[0]
        self.assertEqual((evaluation.upper_bound, evaluation.margin, evaluation.required), (600, 300, 900))
        self.assertEqual(boundary.outcome, "admitted")

    def test_dynamic_admission_backpressures_transient_capacity_and_concurrency(self) -> None:
        planner = self.planner()
        work = self.campaign_plan(planner)
        context = AdmissionContext(3)
        report = planner.dynamic_admit(work, inventory(), context)
        self.assertEqual(report.outcome, "backpressure")
        self.assertIn("concurrency-limit-reached", {item.code for item in report.issues})
        resumed = planner.dynamic_admit(work, inventory(), AdmissionContext(0))
        self.assertEqual(resumed.outcome, "admitted")
        self.validate(report)
        self.validate(resumed)

    def test_aggregate_safe_integer_overflow_fails_closed(self) -> None:
        planner = self.planner()
        work = self.campaign_plan(planner, requested_concurrency=2**53 - 1)
        report = planner.dynamic_admit(
            work,
            inventory(),
            AdmissionContext(active_concurrency=1),
        )
        self.assertEqual(report.outcome, "drain")
        self.assertIn("concurrency-plan-overflow", {item.code for item in report.issues})
        self.validate(report)

        shared = planner.workload_plan(
            operation_kind="shard",
            operation_id="rcid:v1:shard:h:jcs-sha256-v1:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            estimates=(
                ResourceEstimate(
                    "scratch",
                    "execution_scratch",
                    "bytes",
                    2**53 - 1,
                    2**53 - 1,
                    "known",
                    "fixture",
                ),
            ),
        )
        report = planner.preflight(
            shared,
            inventory(disk_available=2**53 - 1, disk_capacity=2**53 - 1),
            AdmissionContext(active_usage=(ActiveResourceUsage("result_spool", "bytes", 1),)),
        )
        self.assertEqual(report.outcome, "rejected")
        self.assertIn("backing-store-plan-overflow", {item.code for item in report.issues})
        self.validate(report)

    def test_dynamic_admission_drains_on_stale_unknown_or_untrusted_infrastructure(self) -> None:
        planner = self.planner()
        work = self.campaign_plan(planner)
        scenarios = (
            (inventory(provider_availability="detected_unverified"), "provider-not-verified-available"),
            (inventory(provider_accuracy="estimated"), "provider-availability-ambiguous"),
            (inventory(capability_status="unknown"), "required-capability-unavailable"),
            (inventory(capability_accuracy="estimated"), "required-capability-ambiguous"),
            (inventory(trust_class="untrusted_public"), "trust-class-ineligible"),
            (inventory(trust_configured=False), "trust-class-unconfigured"),
            (
                inventory(observed_at="2026-08-12T22:00:00Z", valid_until="2026-08-12T22:01:00Z"),
                "inventory-stale",
            ),
            (inventory(ram_available=None), "resource-capacity-unknown"),
            (
                inventory(component_observed_at="2026-08-12T22:00:00Z"),
                "provider-inventory-stale",
            ),
        )
        for machine, code in scenarios:
            with self.subTest(code=code):
                report = planner.dynamic_admit(work, machine)
                self.assertEqual(report.outcome, "drain")
                self.assertIn(code, {item.code for item in report.issues})

    def test_active_usage_is_counted_on_logical_and_shared_capacity(self) -> None:
        planner = self.planner()
        work = planner.workload_plan(
            operation_kind="shard",
            operation_id="rcid:v1:shard:h:jcs-sha256-v1:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            estimates=(ResourceEstimate("scratch", "execution_scratch", "bytes", 400, 400, "known", "fixture"),),
        )
        context = AdmissionContext(0, (ActiveResourceUsage("result_spool", "bytes", 600),))
        report = planner.dynamic_admit(work, inventory(disk_available=1_000), context)
        self.assertEqual(report.resource_evaluations[0].status, "pass")
        self.assertEqual(report.backing_store_evaluations[0].active_usage, 600)
        self.assertEqual(report.outcome, "backpressure")

    def test_environment_admission_rejects_wrong_transaction_and_dynamic_report(self) -> None:
        planner = self.planner()
        planned = planned_environment()
        work = planner.environment_plan(planned, machine_provider_name="native-runtime")
        report = planner.preflight(work, inventory())
        with self.assertRaisesRegex(ValueError, "different environment"):
            planner.environment_decision(planned_environment(ENVIRONMENT_ID[:-1] + "2"), report)
        dynamic = planner.dynamic_admit(work, inventory())
        with self.assertRaisesRegex(ValueError, "preflight"):
            planner.environment_decision(planned, dynamic)

    def test_model_and_schema_reject_unsafe_numbers_and_forged_admission(self) -> None:
        with self.assertRaisesRegex(ValueError, "safe integer"):
            ResourceEstimate("too-large", "ram", "bytes", 2**53, 2**53, "known", "fixture")
        with self.assertRaisesRegex(ValueError, "null amounts"):
            ResourceEstimate("false-unknown", "ram", "bytes", 1, None, "unknown", "fixture", "unknown")
        with self.assertRaisesRegex(ValueError, "equal expected"):
            ResourceEstimate("false-known", "ram", "bytes", 1, 2, "known", "fixture")
        with self.assertRaisesRegex(ValueError, "exactly once"):
            AdmissionPolicy((ConfidenceMargin("known", 0),), (), 1, 60)

        planner = self.planner()
        report = planner.preflight(self.campaign_plan(planner), inventory())
        forged = report.to_dict()
        forged["issues"] = [
            {
                "available": 1,
                "category": "resource",
                "code": "forged",
                "message": "forged issue",
                "pool_kind": "ram",
                "recoverable": True,
                "remediation": "do not forge reports",
                "required": 2,
            }
        ]
        self.assertTrue(list(self.validator.iter_errors(forged)))
        forged_dynamic = report.to_dict()
        forged_dynamic["stage"] = "dynamic"
        forged_dynamic["outcome"] = "backpressure"
        forged_dynamic["issues"] = [
            {
                "available": None,
                "category": "plan",
                "code": "fatal",
                "message": "fatal issue",
                "pool_kind": None,
                "recoverable": False,
                "remediation": "repair",
                "required": None,
            }
        ]
        self.assertTrue(list(self.validator.iter_errors(forged_dynamic)))
        forged_unit = report.to_dict()
        forged_unit["resource_evaluations"][0]["unit"] = "logical_cpu"
        self.assertTrue(list(self.validator.iter_errors(forged_unit)))
        with self.assertRaisesRegex(ValueError, "blocking issues"):
            replace(
                report,
                issues=(
                    AdmissionIssue(
                        "forged",
                        "resource",
                        "forged issue",
                        "do not forge reports",
                        True,
                        "ram",
                        2,
                        1,
                    ),
                ),
            )

        with self.assertRaisesRegex(ValueError, "logical_cpu"):
            ActiveResourceUsage("cpu", "bytes", 1)
        with self.assertRaisesRegex(ValueError, "only recoverable"):
            replace(
                report,
                stage="dynamic",
                outcome="backpressure",
                issues=(AdmissionIssue("fatal", "plan", "fatal issue", "repair", False),),
            )
        with self.assertRaisesRegex(ValueError, "non-recoverable"):
            replace(
                report,
                stage="dynamic",
                outcome="drain",
                issues=(AdmissionIssue("capacity", "resource", "capacity pressure", "wait", True),),
            )

    def test_environment_admission_rejects_a_report_from_another_policy(self) -> None:
        planner = self.planner()
        planned = planned_environment()
        work = planner.environment_plan(planned, machine_provider_name="native-runtime")
        report = planner.preflight(work, inventory())
        other_policy = replace(policy(self.fixture), max_concurrency=3)
        with self.assertRaisesRegex(ValueError, "exact admission policy"):
            ResourcePlanner(other_policy).environment_decision(planned, report)

    def test_future_inventory_and_missing_backing_identity_fail_closed(self) -> None:
        planner = self.planner()
        work = self.campaign_plan(planner)
        future = planner.preflight(
            work,
            inventory(observed_at="2026-08-13T00:00:00Z", valid_until="2026-08-13T00:05:00Z"),
        )
        self.assertIn("inventory-observed-in-future", {item.code for item in future.issues})
        separate = inventory(share_disk=False)
        resources = tuple(
            replace(item, backing_store=None) if item.kind == "execution_scratch" else item
            for item in separate.resources
        )
        missing = planner.preflight(work, replace(separate, resources=resources))
        self.assertIn("backing-store-identity-unknown", {item.code for item in missing.issues})

    def test_controller_without_resource_planner_fails_explicitly(self) -> None:
        control = ControlPlaneController(ControlPlaneServices(NullDoctor()))
        with self.assertRaisesRegex(RuntimeError, "resource planner"):
            control.preflight_resources(self.campaign_plan(self.planner()), inventory())


if __name__ == "__main__":
    unittest.main()
