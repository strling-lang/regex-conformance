from __future__ import annotations

import ast
import io
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from unittest.mock import call, patch

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "control-plane" / "python"
if str(CONTROL_PLANE) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE))

from regex_conformance_control_plane.cli import main as cli_main
from regex_conformance_control_plane.configuration import DoctorConfiguration, POOL_KINDS
from regex_conformance_control_plane.controller import ControlPlaneController, ControlPlaneServices
from regex_conformance_control_plane.discovery import (
    StandardLibraryMachineDiscovery,
    _cpu_pool,
    _memory_pools,
    _parse_macos_memory,
    _process_capabilities,
)
from regex_conformance_control_plane.doctor import MachineDoctor
from regex_conformance_control_plane.models import (
    Capability,
    Diagnostic,
    DiscoverySnapshot,
    MachineIdentity,
    ProviderCapability,
    ResourcePool,
)
from regex_conformance_control_plane.rendering import render_json

FIXTURES = ROOT / "tests" / "control_plane" / "fixtures" / "machines.json"
SCHEMA = ROOT / "schemas" / "json" / "machine-inventory.schema.json"


class FixedClock:
    def __init__(self, value: str) -> None:
        self.value = datetime.fromisoformat(value.replace("Z", "+00:00"))

    def now(self) -> datetime:
        return self.value


class FixtureDiscovery:
    def __init__(self, snapshot: DiscoverySnapshot) -> None:
        self.snapshot = snapshot
        self.calls = 0

    def discover(self, configuration: DoctorConfiguration, observed_at: str) -> DiscoverySnapshot:
        self.calls += 1
        if observed_at != self.snapshot.observed_at:
            raise AssertionError("fixture clock and snapshot must identify one instant")
        return self.snapshot


def configuration(case: dict[str, object], trust_class: str | None = None) -> DoctorConfiguration:
    case_name = str(case["case"])
    paths = tuple((kind, Path("/fixture") / case_name / kind) for kind in POOL_KINDS)
    return DoctorConfiguration(
        trust_class=trust_class or str(case["trust_class"]),
        trust_source="fixture",
        inventory_max_age_seconds=300,
        pool_paths=paths,
    )


def snapshot(case: dict[str, object]) -> DiscoverySnapshot:
    observed_at = str(case["observed_at"])
    disk = dict(case["disk"])
    resources: list[ResourcePool] = []
    for kind in POOL_KINDS:
        resources.append(
            ResourcePool(
                kind=kind,
                unit="bytes",
                status="observed",
                capacity=int(disk["capacity"]),
                used=int(disk["used"]),
                reserved=0,
                available=int(disk["available"]),
                source="fixture",
                accuracy="exact",
                visibility="process",
                observed_at=observed_at,
                staleness_seconds=0,
                configured_path=f"/fixture/{case['case']}/{kind}",
                observed_path=f"/fixture/{case['case']}",
                backing_store=str(disk["backing_store"]),
            )
        )
    for kind in ("ram", "swap"):
        values = dict(case[kind])
        resources.append(
            ResourcePool(
                kind=kind,
                unit="bytes",
                status=str(values["status"]),
                capacity=values["capacity"],
                used=values["used"],
                reserved=0,
                available=values["available"],
                source="fixture",
                accuracy=str(values["accuracy"]),
                visibility="process",
                observed_at=observed_at,
                staleness_seconds=0,
                diagnostic="fixture intentionally leaves this value unknown" if values["status"] == "unknown" else None,
            )
        )
    resources.append(
        ResourcePool(
            kind="cpu",
            unit="logical_cpu",
            status="partial",
            capacity=int(case["cpu_capacity"]),
            used=None,
            reserved=0,
            available=None,
            source="fixture",
            accuracy="bounded",
            visibility="process",
            observed_at=observed_at,
            staleness_seconds=0,
            diagnostic="free CPU capacity is not inferred",
        )
    )
    providers = tuple(
        ProviderCapability(
            name=str(item["name"]),
            availability=str(item["availability"]),
            strategies=tuple(item["strategies"]),
            source="fixture",
            observed_at=observed_at,
            executable=item.get("executable"),
        )
        for item in case["providers"]
    )
    capabilities = tuple(
        Capability(
            name=str(item["name"]),
            status=str(item["status"]),
            source="fixture",
            observed_at=observed_at,
            value=item["value"],
            diagnostic="fixture leaves this capability unknown" if item["status"] == "unknown" else None,
            accuracy="unknown" if item["status"] == "unknown" else "exact",
        )
        for item in case["capabilities"]
    )
    return DiscoverySnapshot(
        observed_at=observed_at,
        machine=MachineIdentity(**case["machine"]),
        resources=tuple(resources),
        providers=providers,
        capabilities=capabilities,
    )


def controller(case: dict[str, object], *, trust_class: str | None = None) -> tuple[ControlPlaneController, DoctorConfiguration, FixtureDiscovery]:
    source = FixtureDiscovery(snapshot(case))
    doctor = MachineDoctor(source, FixedClock(str(case["observed_at"])))
    return ControlPlaneController(ControlPlaneServices(doctor)), configuration(case, trust_class), source


class MachineDoctorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = json.loads(FIXTURES.read_text(encoding="utf-8"))
        cls.validator = Draft202012Validator(
            json.loads(SCHEMA.read_text(encoding="utf-8")),
            format_checker=FormatChecker(),
        )

    def validate(self, value: dict[str, object]) -> None:
        errors = sorted(self.validator.iter_errors(value), key=lambda error: list(error.absolute_path))
        self.assertEqual(errors, [], "\n".join(error.message for error in errors))

    def test_cross_platform_fixtures_are_schema_valid_and_byte_stable(self) -> None:
        for case in self.cases:
            with self.subTest(case=case["case"]):
                control, config, source = controller(case)
                first = control.inspect_machine(config)
                second = control.inspect_machine(config)
                self.assertEqual(render_json(first), render_json(second))
                self.assertEqual(first.status, case["expected_status"])
                self.assertEqual(first.machine.os_family, case["machine"]["os_family"])
                self.assertEqual({pool.kind for pool in first.resources}, set(POOL_KINDS) | {"ram", "swap", "cpu"})
                self.assertEqual([provider.name for provider in first.providers], sorted(provider.name for provider in first.providers))
                self.assertIn("resource-pools-share-backing-store", {item.code for item in first.diagnostics})
                for provider in first.to_dict()["providers"]:
                    self.assertEqual(provider["staleness_seconds"], 0)
                    self.assertIn(provider["accuracy"], {"exact", "unknown"})
                self.assertNotIn("hostname", first.to_dict()["machine"])
                self.validate(first.to_dict())
                self.assertEqual(source.calls, 2)

    def test_unknown_telemetry_remains_null_instead_of_zero(self) -> None:
        windows = next(case for case in self.cases if case["case"] == "windows-hyperv")
        control, config, _ = controller(windows)
        report = control.inspect_machine(config)
        swap = next(pool for pool in report.resources if pool.kind == "swap")
        self.assertEqual(swap.status, "unknown")
        self.assertIsNone(swap.capacity)
        self.assertIsNone(swap.used)
        self.assertIsNone(swap.available)

    def test_missing_swap_probe_remains_unknown_instead_of_zero(self) -> None:
        observed_at = "2026-08-12T12:00:00Z"
        memory = (16 * 1024**3, 8 * 1024**3, 8 * 1024**3, None, None, None)
        with patch("regex_conformance_control_plane.discovery._parse_macos_memory", return_value=memory):
            ram, swap = _memory_pools("macos", observed_at)
        self.assertEqual(ram.capacity, 16 * 1024**3)
        self.assertEqual(swap.status, "unknown")
        self.assertIsNone(swap.capacity)
        self.assertEqual(swap.accuracy, "unknown")

    def test_macos_memory_probe_uses_fixed_system_executables(self) -> None:
        outputs = [
            "17179869184",
            "Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 100.\nPages inactive: 200.",
            "total = 1024.00M  used = 256.00M  free = 768.00M",
        ]
        with patch("regex_conformance_control_plane.discovery._run_text", side_effect=outputs) as run:
            measurements = _parse_macos_memory()
        self.assertIsNotNone(measurements)
        self.assertEqual(
            run.call_args_list,
            [
                call("/usr/sbin/sysctl", "-n", "hw.memsize"),
                call("/usr/bin/vm_stat"),
                call("/usr/sbin/sysctl", "-n", "vm.swapusage"),
            ],
        )

    def test_unsupported_os_and_unconfigured_trust_are_actionable(self) -> None:
        case = self.cases[0]
        original = snapshot(case)
        unsupported = replace(original, machine=replace(original.machine, os_family="unknown", os_name="Plan 9"))
        source = FixtureDiscovery(unsupported)
        control = ControlPlaneController(ControlPlaneServices(MachineDoctor(source, FixedClock(str(case["observed_at"])))))
        report = control.inspect_machine(configuration(case, "unknown"))
        self.assertEqual(report.status, "unsupported")
        diagnostics = {item.code: item for item in report.diagnostics}
        self.assertIn("unsupported-operating-system", diagnostics)
        self.assertIn("trust-class-unconfigured", diagnostics)
        self.assertTrue(diagnostics["unsupported-operating-system"].remediation)
        self.assertTrue(diagnostics["trust-class-unconfigured"].remediation)

    def test_invalid_trust_class_fails_closed_to_unknown(self) -> None:
        case = self.cases[0]
        control, config, _ = controller(case, trust_class="root")
        report = control.inspect_machine(config)
        self.assertEqual(report.status, "unsupported")
        self.assertEqual(report.trust.trust_class, "unknown")
        self.assertIn("invalid-trust-class", {item.code for item in report.diagnostics})

    def test_negative_resource_values_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-negative"):
            ResourcePool(
                kind="ram",
                unit="bytes",
                status="observed",
                capacity=1,
                used=-1,
                reserved=0,
                available=1,
                source="test",
                accuracy="exact",
                visibility="process",
                observed_at="2026-08-12T12:00:00Z",
                staleness_seconds=0,
            )

    def test_resource_accounting_over_capacity_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "exceeds capacity"):
            ResourcePool(
                kind="ram",
                unit="bytes",
                status="observed",
                capacity=10,
                used=8,
                reserved=3,
                available=0,
                source="test",
                accuracy="exact",
                visibility="process",
                observed_at="2026-08-12T12:00:00Z",
                staleness_seconds=0,
            )

    def test_cli_doctor_and_machine_inspect_share_one_json_contract(self) -> None:
        case = self.cases[0]
        control, _, _ = controller(case)
        outputs = []
        for arguments in (
            ["doctor", "--format", "json", "--trust-class", str(case["trust_class"])],
            ["machine", "inspect", "--format", "json", "--trust-class", str(case["trust_class"])],
        ):
            stdout = io.StringIO()
            stderr = io.StringIO()
            self.assertEqual(cli_main(arguments, controller=control, environment={}, stdout=stdout, stderr=stderr), 0)
            self.assertEqual(stderr.getvalue(), "")
            outputs.append(stdout.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        self.validate(json.loads(outputs[0]))

    def test_human_output_is_derived_from_the_same_report(self) -> None:
        case = self.cases[2]
        control, _, _ = controller(case)
        stdout = io.StringIO()
        result = cli_main(
            ["doctor", "--trust-class", str(case["trust_class"])],
            controller=control,
            environment={},
            stdout=stdout,
            stderr=io.StringIO(),
        )
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        self.assertIn("Machine doctor: healthy", output)
        self.assertIn("apple-virtualization: detected_unverified", output)
        self.assertIn("Resource pools:", output)

    def test_malformed_pool_override_is_rejected_before_discovery(self) -> None:
        case = self.cases[0]
        control, _, source = controller(case)
        stderr = io.StringIO()
        result = cli_main(["doctor", "--pool-path", "broken"], controller=control, environment={}, stdout=io.StringIO(), stderr=stderr)
        self.assertEqual(result, 2)
        self.assertIn("KIND=PATH", stderr.getvalue())
        self.assertEqual(source.calls, 0)

    def test_compact_human_output_is_rejected_before_discovery(self) -> None:
        case = self.cases[0]
        control, _, source = controller(case)
        stderr = io.StringIO()
        result = cli_main(["doctor", "--compact"], controller=control, environment={}, stdout=io.StringIO(), stderr=stderr)
        self.assertEqual(result, 2)
        self.assertIn("only with --format json", stderr.getvalue())
        self.assertEqual(source.calls, 0)

    def test_real_host_smoke_is_read_only_and_schema_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "not-created"
            overrides = {kind: root / kind for kind in POOL_KINDS}
            config = DoctorConfiguration.from_environment(
                {},
                trust_override="development",
                pool_overrides=overrides,
                inventory_max_age_seconds=60,
            )
            control = ControlPlaneController(
                ControlPlaneServices(MachineDoctor(StandardLibraryMachineDiscovery(), FixedClock("2026-08-12T12:00:00Z")))
            )
            report = control.inspect_machine(config)
            self.assertIn(report.machine.os_family, {"linux", "windows", "macos"})
            self.assertFalse(root.exists(), "machine inspection must not create configured pool paths")
            self.assertFalse(report.safety_configuration.mutation_permitted)
            self.validate(report.to_dict())

    def test_service_container_keeps_cli_out_of_discovery_modules(self) -> None:
        source = (CONTROL_PLANE / "regex_conformance_control_plane" / "cli.py").read_text(encoding="utf-8")
        imported = {
            node.module
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        self.assertNotIn("discovery", imported)
        self.assertNotIn("doctor", imported)
        self.assertNotIn("models", imported)

    def test_nonfinite_machine_output_is_rejected(self) -> None:
        case = self.cases[0]
        control, config, _ = controller(case)
        report = control.inspect_machine(config)
        bad = replace(
            report,
            capabilities=report.capabilities
            + (Capability("bad", "supported", "test", report.observed_at, float("nan")),),
        )
        with self.assertRaisesRegex(ValueError, "JSON compliant"):
            render_json(bad)

    def test_configuration_requires_every_typed_disk_pool(self) -> None:
        with self.assertRaisesRegex(ValueError, "each typed disk pool"):
            DoctorConfiguration("development", "test", 300, (("persistent_disk", Path("/tmp")),))

    def test_unknown_capability_requires_unknown_accuracy(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown capability"):
            Capability(
                "thermal",
                "unknown",
                "test",
                "2026-08-12T12:00:00Z",
            )

    def test_schema_rejects_semantically_false_unknowns(self) -> None:
        case = self.cases[0]
        control, config, _ = controller(case)
        value = control.inspect_machine(config).to_dict()
        value["resource_pools"][0]["status"] = "unknown"
        value["resource_pools"][0]["accuracy"] = "unknown"
        self.assertTrue(list(self.validator.iter_errors(value)), "unknown resource measurements must be null")

        value = control.inspect_machine(config).to_dict()
        value["capabilities"][0]["status"] = "unsupported"
        self.assertTrue(list(self.validator.iter_errors(value)), "unsupported capabilities must not retain values")

        value = control.inspect_machine(config).to_dict()
        value["safety_configuration"]["configured_pool_paths"].pop("result_spool")
        self.assertTrue(list(self.validator.iter_errors(value)), "every typed disk pool path is required")

    def test_unobservable_portable_capabilities_fail_closed_without_crashing(self) -> None:
        observed_at = "2026-08-12T12:00:00Z"
        with patch("regex_conformance_control_plane.discovery.os.cpu_count", return_value=None), patch(
            "regex_conformance_control_plane.discovery.os.sched_getaffinity", side_effect=OSError("hidden")
        ), patch("regex_conformance_control_plane.discovery.socket.if_nameindex", side_effect=OSError("hidden")):
            cpu, cpu_capability = _cpu_pool(observed_at)
            capabilities = _process_capabilities("unknown", observed_at)
        self.assertEqual(cpu.status, "unknown")
        self.assertEqual(cpu.accuracy, "unknown")
        self.assertEqual(cpu_capability.status, "unknown")
        self.assertEqual(cpu_capability.accuracy, "unknown")
        unknown = {item.name: item for item in capabilities if item.status == "unknown"}
        self.assertEqual(unknown["process_tree_termination"].accuracy, "unknown")
        self.assertEqual(unknown["network_interface_visibility"].accuracy, "unknown")

    def test_duplicate_discovery_identities_are_rejected_by_doctor(self) -> None:
        case = self.cases[0]
        original = snapshot(case)
        duplicated = replace(
            original,
            resources=original.resources + (original.resources[0],),
            capabilities=original.capabilities + (original.capabilities[0],),
        )
        source = FixtureDiscovery(duplicated)
        control = ControlPlaneController(ControlPlaneServices(MachineDoctor(source, FixedClock(str(case["observed_at"])))))
        report = control.inspect_machine(configuration(case))
        self.assertEqual(report.status, "unsupported")
        codes = {item.code for item in report.diagnostics}
        self.assertIn("resource-pool-identity-collision", codes)
        self.assertIn("capability-identity-collision", codes)


if __name__ == "__main__":
    unittest.main()
