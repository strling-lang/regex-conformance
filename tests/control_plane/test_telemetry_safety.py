from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2] if "tests" in Path(__file__).parts else None
if ROOT is None or not (ROOT / "control-plane").exists():
    ROOT = Path("/root/personal/strling-lang/regex-conformance")
sys.path.insert(0, str(ROOT / "control-plane" / "python"))

from regex_conformance_control_plane.containment import (  # noqa: E402
    ContainedExecutionResult,
    ContainedProcessSupervisor,
    ExecutionLimits,
    NativeSafetyLimitAdapter,
    OciSafetyLimitAdapter,
    ProviderLimitPlan,
    UnsupportedContainmentError,
)
from regex_conformance_control_plane.controller import (  # noqa: E402
    ControlPlaneController,
    ControlPlaneServices,
    ControlPlaneServiceUnavailable,
)
from regex_conformance_control_plane.resource_models import (  # noqa: E402
    AdmissionPolicy,
    ConfidenceMargin,
    ResourceEstimate,
)
from regex_conformance_control_plane.resource_planner import ResourcePlanner  # noqa: E402
from regex_conformance_control_plane.state_models import SecretMaterialError, canonical_json  # noqa: E402
from regex_conformance_control_plane.telemetry_collector import OperationalTelemetryCollector  # noqa: E402
from regex_conformance_control_plane.telemetry_models import (  # noqa: E402
    CalibrationPolicy,
    TelemetryMetric,
    TelemetrySample,
    build_calibration,
)
from regex_conformance_control_plane.telemetry_store import (  # noqa: E402
    TelemetryStore,
    TelemetryStoreConflictError,
    TelemetryStoreCorruptionError,
    UnsafeTelemetryPathError,
)


def opid(namespace: str, sequence: int) -> str:
    return f"opid:v1:{namespace}:u7:019ff82c-9517-76fb-a67d-{sequence:012x}"


def sample(
    sequence: int,
    value: int,
    *,
    quality: str = "complete",
    calibration_key: str = "recipe:python-3-14",
) -> TelemetrySample:
    return TelemetrySample(
        sample_id=opid("telemetry", sequence),
        operation_kind="environment",
        calibration_key=calibration_key,
        attempt_id=opid("environment", sequence),
        observed_at=f"2026-08-12T00:00:{sequence:02d}Z",
        quality=quality,
        source="environment-manager",
        metrics=(
            TelemetryMetric(
                "environment-build-scratch",
                "resource-usage",
                "bytes",
                value,
                "build_scratch",
            ),
        ),
    )


def admission_policy() -> AdmissionPolicy:
    return AdmissionPolicy(
        confidence_margins=tuple(
            ConfidenceMargin(name, amount)
            for name, amount in (
                ("known", 0),
                ("measured", 500),
                ("estimated", 2500),
                ("bounded", 5000),
            )
        ),
        pool_reserves=(),
        max_concurrency=4,
        inventory_max_age_seconds=300,
    )


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 8, 12, tzinfo=timezone.utc)


class FixedIds:
    def __init__(self) -> None:
        self.sequence = 900

    def next_id(self) -> str:
        self.sequence += 1
        return opid("telemetry", self.sequence)


class NullDoctor:
    def inspect(self, configuration: object) -> object:
        raise AssertionError("machine discovery is outside these controller integration checks")


class TelemetryModelTests(unittest.TestCase):
    def test_sample_is_deterministic_numeric_and_non_authoritative(self) -> None:
        record = sample(1, 512)
        self.assertEqual(
            canonical_json(record.to_dict()),
            canonical_json(TelemetrySample.from_dict(record.to_dict()).to_dict()),
        )
        self.assertFalse(record.to_dict()["canonical_authority"])
        self.assertFalse(record.to_dict()["semantic_authority"])

    def test_duplicate_metrics_and_mismatched_units_fail(self) -> None:
        metric = TelemetryMetric("usage", "resource-usage", "bytes", 1, "ram")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            TelemetrySample(
                opid("telemetry", 2), "execution", "key", opid("execution-attempt", 2),
                "2026-08-12T00:00:00Z", "complete", "supervisor", (metric, metric),
            )
        with self.assertRaisesRegex(ValueError, "unit"):
            TelemetryMetric("cpu", "resource-usage", "bytes", 1, "cpu")

    def test_credentials_are_rejected_from_persistable_references(self) -> None:
        with self.assertRaises(SecretMaterialError):
            sample(3, 1, calibration_key="https://user:password@example.invalid/resource")

    def test_attempt_identity_cannot_be_replaced_by_a_scientific_identity(self) -> None:
        document = sample(3, 1).to_dict()
        document["attempt_id"] = f"rcid:v1:execution-attempt:h:jcs-sha256:{'0' * 64}"
        with self.assertRaisesRegex(ValueError, "operational"):
            TelemetrySample.from_dict(document)

    def test_partial_and_mismatched_samples_do_not_calibrate(self) -> None:
        snapshot = build_calibration(
            (sample(1, 100), sample(2, 200, quality="partial"), sample(3, 300, calibration_key="other")),
            operation_kind="environment",
            calibration_key="recipe:python-3-14",
            metric_name="environment-build-scratch",
            pool_kind="build_scratch",
            unit="bytes",
            policy=CalibrationPolicy(),
        )
        self.assertFalse(snapshot.eligible)
        self.assertEqual(snapshot.sample_count, 1)
        self.assertIsNone(snapshot.upper_bound)

    def test_rare_observed_peak_cannot_fall_above_calibrated_upper_bound(self) -> None:
        records = tuple(sample(sequence, 10_000 if sequence == 21 else 100) for sequence in range(1, 22))
        snapshot = build_calibration(
            records,
            operation_kind="environment",
            calibration_key="recipe:python-3-14",
            metric_name="environment-build-scratch",
            pool_kind="build_scratch",
            unit="bytes",
            policy=CalibrationPolicy(),
        )
        self.assertEqual(snapshot.maximum, 10_000)
        self.assertEqual(snapshot.upper_bound, 10_000)


class TelemetryStoreAndPlanningTests(unittest.TestCase):
    def test_append_only_store_calibrates_and_planner_uses_measured_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "telemetry.sqlite3"
            with TelemetryStore.open(path) as store:
                self.assertTrue(store.append(sample(1, 100)))
                self.assertFalse(store.append(sample(1, 100)))
                self.assertFalse(store.calibration(
                    operation_kind="environment",
                    calibration_key="recipe:python-3-14",
                    metric_name="environment-build-scratch",
                    pool_kind="build_scratch",
                    unit="bytes",
                ).eligible)
                store.append(sample(2, 200))
                store.append(sample(3, 1000))
                snapshot = store.calibration(
                    operation_kind="environment",
                    calibration_key="recipe:python-3-14",
                    metric_name="environment-build-scratch",
                    pool_kind="build_scratch",
                    unit="bytes",
                )
                self.assertTrue(snapshot.eligible)
                self.assertEqual(
                    (snapshot.minimum, snapshot.expected, snapshot.maximum, snapshot.upper_bound),
                    (100, 200, 1000, 1250),
                )
                planner = ResourcePlanner(admission_policy(), calibrator=store)
                plan = planner.workload_plan(
                    operation_kind="environment",
                    operation_id=opid("environment", 20),
                    estimates=(ResourceEstimate(
                        "environment-build-scratch", "build_scratch", "bytes", 1, 1, "estimated", "seed",
                    ),),
                    calibration_key="recipe:python-3-14",
                )
                self.assertEqual(plan.estimates[0].confidence, "measured")
                self.assertEqual((plan.estimates[0].expected, plan.estimates[0].upper_bound), (200, 1250))
                self.assertIn(snapshot.calibration_digest, plan.estimates[0].source)
            with TelemetryStore.open(path) as reopened:
                self.assertEqual(len(reopened.samples(
                    operation_kind="environment", calibration_key="recipe:python-3-14"
                )), 3)
                rebuilt = reopened.calibration(
                    operation_kind="environment",
                    calibration_key="recipe:python-3-14",
                    metric_name="environment-build-scratch",
                    pool_kind="build_scratch",
                    unit="bytes",
                )
                self.assertEqual(rebuilt.calibration_digest, snapshot.calibration_digest)

    def test_immutable_identity_conflict_and_database_tampering_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "telemetry.sqlite3"
            with TelemetryStore.open(path) as store:
                store.append(sample(1, 100))
                with self.assertRaises(TelemetryStoreConflictError):
                    store.append(sample(1, 101))
            connection = sqlite3.connect(path)
            connection.execute("UPDATE samples SET payload_sha256 = ?", ("0" * 64,))
            connection.commit()
            connection.close()
            with self.assertRaises(TelemetryStoreCorruptionError):
                TelemetryStore.open(path)

    def test_index_tampering_and_incompatible_schema_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            indexed = Path(directory) / "indexed.sqlite3"
            with TelemetryStore.open(indexed) as store:
                store.append(sample(1, 100))
            connection = sqlite3.connect(indexed)
            connection.execute("UPDATE samples SET calibration_key = 'substituted'")
            connection.commit()
            connection.close()
            with self.assertRaises(TelemetryStoreCorruptionError):
                TelemetryStore.open(indexed)

            incompatible = Path(directory) / "incompatible.sqlite3"
            connection = sqlite3.connect(incompatible)
            connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT) STRICT")
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES ('schema_version', 'operational-telemetry-store.v1')"
            )
            connection.execute("CREATE TABLE samples(sample_id TEXT PRIMARY KEY) STRICT")
            connection.commit()
            connection.close()
            if os.name != "nt":
                os.chmod(incompatible, 0o600)
            with self.assertRaises(TelemetryStoreCorruptionError):
                TelemetryStore.open(incompatible)

    @unittest.skipIf(os.name == "nt", "hard-link identity semantics are validated on POSIX CI")
    def test_hard_linked_store_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "telemetry.sqlite3"
            with TelemetryStore.open(path):
                pass
            linked = Path(directory) / "linked.sqlite3"
            os.link(path, linked)
            with self.assertRaises(UnsafeTelemetryPathError):
                TelemetryStore.open(linked)

    def test_collector_persists_containment_as_partial_operational_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with TelemetryStore.open(Path(directory) / "telemetry.sqlite3") as store:
                collector = OperationalTelemetryCollector(store=store, clock=FixedClock(), id_generator=FixedIds())
                empty_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                result = ContainedExecutionResult(
                    "wall-time-limit", -15, 50, b"", b"", 0, 0, empty_digest, empty_digest,
                    ProviderLimitPlan("native", ("process-tree", "stderr", "stdout", "wall-time")),
                )
                record = collector.collect_containment(
                    result, calibration_key="probe:runaway", attempt_id=opid("execution-attempt", 50)
                )
                self.assertEqual(record.quality, "partial")
                self.assertEqual(len(store.samples(operation_kind="execution", calibration_key="probe:runaway")), 1)
                self.assertFalse(any(item.metric_kind == "resource-usage" for item in record.metrics))

    def test_controller_exposes_telemetry_and_containment_without_semantic_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with TelemetryStore.open(Path(directory) / "telemetry.sqlite3") as store:
                controller = ControlPlaneController(
                    ControlPlaneServices(
                        machine_doctor=NullDoctor(),
                        telemetry_collector=OperationalTelemetryCollector(
                            store=store, clock=FixedClock(), id_generator=FixedIds()
                        ),
                        process_supervisor=ContainedProcessSupervisor(),
                    )
                )
                recorded = controller.record_operational_telemetry(
                    operation_kind="environment",
                    calibration_key="recipe:controller",
                    attempt_id=opid("environment", 80),
                    source="environment-manager",
                    metrics=(TelemetryMetric("ram-peak", "resource-usage", "bytes", 4096, "ram"),),
                )
                self.assertFalse(recorded.semantic_authority)
                if os.name == "posix":
                    contained = controller.run_contained_process(
                        (sys.executable, "-c", "print('bounded')"),
                        limits=ExecutionLimits(2_000, 64, 64),
                    )
                    self.assertEqual(contained.outcome, "completed")
                else:
                    with self.assertRaises(UnsupportedContainmentError):
                        controller.run_contained_process(
                            (sys.executable, "-c", "print('bounded')"),
                            limits=ExecutionLimits(2_000, 64, 64),
                        )
            unavailable = ControlPlaneController(ControlPlaneServices(machine_doctor=NullDoctor()))
            with self.assertRaises(ControlPlaneServiceUnavailable):
                unavailable.run_contained_process(
                    (sys.executable, "-c", "pass"), limits=ExecutionLimits(1_000, 64, 64)
                )


class HardContainmentTests(unittest.TestCase):
    def test_provider_plan_and_result_models_reject_forged_safety_claims(self) -> None:
        with self.assertRaisesRegex(ValueError, "enforced limits"):
            ProviderLimitPlan("native", ("semantic-result",))
        plan = ProviderLimitPlan("native", ("process-tree", "stderr", "stdout", "wall-time"))
        with self.assertRaisesRegex(ValueError, "digest"):
            ContainedExecutionResult(
                "completed", 0, 1, b"x", b"", 1, 0, "0" * 64,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", plan,
            )
        with self.assertRaisesRegex(ValueError, "exit code"):
            ContainedExecutionResult(
                "launch-failed", 1, 1, b"", b"", 0, 0,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", plan,
            )

    @unittest.skipUnless(os.name == "posix", "native execution is certified by hosted POSIX validation")
    def test_completed_output_is_bounded_and_raw_bytes_do_not_serialize(self) -> None:
        result = ContainedProcessSupervisor().run(
            (sys.executable, "-c", "import sys; sys.stdout.write('ok'); sys.stderr.write('note')"),
            limits=ExecutionLimits(2_000, 32, 32),
        )
        self.assertEqual(
            (result.outcome, result.exit_code, result.stdout, result.stderr),
            ("completed", 0, b"ok", b"note"),
        )
        self.assertNotIn("stdout", result.to_dict())
        self.assertNotIn("stderr", result.to_dict())

    @unittest.skipUnless(os.name == "posix", "native execution is certified by hosted POSIX validation")
    def test_stdout_and_diagnostic_floods_terminate_independently(self) -> None:
        supervisor = ContainedProcessSupervisor()
        stdout = supervisor.run(
            (sys.executable, "-c", "import os,time; os.write(1,b'x'*65536); time.sleep(5)"),
            limits=ExecutionLimits(5_000, 64, 64),
        )
        stderr = supervisor.run(
            (sys.executable, "-c", "import os,time; os.write(2,b'y'*65536); time.sleep(5)"),
            limits=ExecutionLimits(5_000, 64, 64),
        )
        self.assertEqual(stdout.outcome, "stdout-limit")
        self.assertEqual(stderr.outcome, "stderr-limit")
        self.assertEqual((len(stdout.stdout), len(stderr.stderr)), (64, 64))

    @unittest.skipUnless(os.name == "posix", "native execution is certified by hosted POSIX validation")
    def test_timeout_terminates_runaway(self) -> None:
        result = ContainedProcessSupervisor().run(
            (sys.executable, "-c", "import time; time.sleep(30)"),
            limits=ExecutionLimits(50, 64, 64),
        )
        self.assertEqual(result.outcome, "wall-time-limit")
        self.assertLess(result.wall_time_ms, 2_000)

    @unittest.skipUnless(os.name == "posix", "POSIX process-group proof runs in hosted Linux CI")
    def test_timeout_kills_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "child.pid"
            script = (
                "import pathlib,subprocess,sys,time; "
                "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); time.sleep(30)"
            )
            result = ContainedProcessSupervisor().run(
                (sys.executable, "-c", script, str(pid_path)),
                limits=ExecutionLimits(250, 64, 64),
            )
            self.assertEqual(result.outcome, "wall-time-limit")
            child_pid = int(pid_path.read_text())
            deadline = time.monotonic() + 2
            while Path(f"/proc/{child_pid}").exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            if Path(f"/proc/{child_pid}/stat").exists():
                state = Path(f"/proc/{child_pid}/stat").read_text().split()[2]
                self.assertEqual(state, "Z", "runaway descendant remained live after group containment")

    @unittest.skipUnless(os.name == "posix", "POSIX rlimit proof runs in hosted Linux CI")
    def test_cpu_and_memory_limits_are_provider_enforced(self) -> None:
        cpu = ContainedProcessSupervisor().run(
            (sys.executable, "-c", "while True: pass"),
            limits=ExecutionLimits(5_000, 64, 64, cpu_time_seconds=1),
        )
        self.assertEqual(cpu.outcome, "cpu-time-limit")
        memory = ContainedProcessSupervisor().run(
            (sys.executable, "-c", "x=bytearray(256*1024*1024)"),
            limits=ExecutionLimits(5_000, 1024, 1024, memory_bytes=64 * 1024 * 1024),
        )
        self.assertIn("memory", memory.provider_plan.enforced_limits)
        self.assertNotEqual(memory.exit_code, 0)

    def test_unsupported_limit_and_bad_command_fail_before_launch(self) -> None:
        with mock.patch("regex_conformance_control_plane.containment.os.name", "nt"):
            with self.assertRaises(UnsupportedContainmentError):
                NativeSafetyLimitAdapter().plan(ExecutionLimits(1_000, 64, 64, memory_bytes=1024))
        marker = Path(tempfile.gettempdir()) / f"should-not-exist-{time.time_ns()}"
        with self.assertRaises(ValueError):
            ContainedProcessSupervisor().run(
                f"{sys.executable} -c open('{marker}','w')",  # type: ignore[arg-type]
                limits=ExecutionLimits(1_000, 64, 64),
            )
        self.assertFalse(marker.exists())
        if os.name == "posix":
            with self.assertRaisesRegex(ValueError, "stdin"):
                ContainedProcessSupervisor().run(
                    (sys.executable, "-c", "pass"),
                    limits=ExecutionLimits(1_000, 64, 64),
                    stdin=b"x" * (16 * 1024 * 1024 + 1),
                )
        else:
            with self.assertRaises(UnsupportedContainmentError):
                ContainedProcessSupervisor().run(
                    (sys.executable, "-c", "pass"), limits=ExecutionLimits(1_000, 64, 64)
                )

    @unittest.skipUnless(os.name == "posix", "native execution is certified by hosted POSIX validation")
    def test_launch_failure_is_typed_and_secret_safe(self) -> None:
        result = ContainedProcessSupervisor().run(
            ("definitely-not-a-real-strling-executable",),
            limits=ExecutionLimits(1_000, 64, 64),
        )
        self.assertEqual(result.outcome, "launch-failed")
        self.assertNotIn("definitely-not", result.diagnostic or "")

    def test_oci_adapter_refuses_false_cpu_time_claims(self) -> None:
        plan = OciSafetyLimitAdapter().plan(ExecutionLimits(1_000, 64, 64, memory_bytes=4096))
        self.assertEqual(plan.provider, "oci")
        self.assertIn("--network=none", plan.launch_arguments)
        with self.assertRaises(UnsupportedContainmentError):
            OciSafetyLimitAdapter().plan(ExecutionLimits(1_000, 64, 64, cpu_time_seconds=1))
        with self.assertRaises(UnsupportedContainmentError):
            ContainedProcessSupervisor(adapter=OciSafetyLimitAdapter()).run(  # type: ignore[arg-type]
                (sys.executable, "-c", "pass"), limits=ExecutionLimits(1_000, 64, 64)
            )

    @unittest.skipUnless(os.name == "posix", "native execution is certified by hosted POSIX validation")
    def test_concurrency_cap_serializes_physical_processes(self) -> None:
        supervisor = ContainedProcessSupervisor(maximum_concurrency=1)
        starts: list[float] = []
        finishes: list[float] = []

        def run() -> None:
            starts.append(time.monotonic())
            supervisor.run(
                (sys.executable, "-c", "import time; time.sleep(0.15)"),
                limits=ExecutionLimits(2_000, 64, 64),
            )
            finishes.append(time.monotonic())

        threads = [threading.Thread(target=run), threading.Thread(target=run)]
        began = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(finishes), 2)
        self.assertGreaterEqual(max(finishes) - began, 0.25)

    @unittest.skipUnless(os.name == "posix", "native execution is certified by hosted POSIX validation")
    def test_underprediction_cannot_relax_hard_output_limit(self) -> None:
        tiny_prediction = ResourceEstimate(
            "execution-output", "result_spool", "bytes", 1, 1, "measured", "telemetry-calibration:test"
        )
        self.assertEqual(tiny_prediction.upper_bound, 1)
        result = ContainedProcessSupervisor().run(
            (sys.executable, "-c", "import os,time; os.write(1,b'x'*4096); time.sleep(2)"),
            limits=ExecutionLimits(2_000, 32, 32),
        )
        self.assertEqual(result.outcome, "stdout-limit")


class TelemetrySchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema_path = ROOT / "schemas" / "json" / "operational-telemetry.schema.json"
        cls.validator = Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))

    def test_sample_and_snapshot_validate(self) -> None:
        records = (sample(1, 100), sample(2, 200), sample(3, 300))
        snapshot = build_calibration(
            records,
            operation_kind="environment",
            calibration_key="recipe:python-3-14",
            metric_name="environment-build-scratch",
            pool_kind="build_scratch",
            unit="bytes",
            policy=CalibrationPolicy(),
        )
        self.validator.validate(records[0].to_dict())
        self.validator.validate(snapshot.to_dict())

    def test_schema_rejects_authority_and_ineligible_bounds(self) -> None:
        document = sample(1, 100).to_dict()
        document["semantic_authority"] = True
        self.assertTrue(list(self.validator.iter_errors(document)))
        snapshot = build_calibration(
            (sample(1, 100),),
            operation_kind="environment",
            calibration_key="recipe:python-3-14",
            metric_name="environment-build-scratch",
            pool_kind="build_scratch",
            unit="bytes",
            policy=CalibrationPolicy(),
        ).to_dict()
        snapshot["upper_bound"] = 100
        self.assertTrue(list(self.validator.iter_errors(snapshot)))


if __name__ == "__main__":
    unittest.main()
