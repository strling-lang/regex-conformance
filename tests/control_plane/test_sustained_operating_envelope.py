from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "control-plane" / "python"
if str(CONTROL_PLANE) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE))

from regex_conformance_control_plane.operating_envelope import (  # noqa: E402
    CHECKPOINT_SCHEMA_VERSION,
    CLASSIFICATION,
    COUNTER_FIELDS,
    OperatingEnvelopeError,
    build_report,
    canonical_artifact_bytes,
    finalize_checkpoint,
    load_checkpoint_chain,
    load_plan,
    validate_checkpoint_chain,
    validate_plan,
    validate_report,
    verify_plan_source_bindings,
)


PLAN_PATH = ROOT / "control-plane" / "qualification" / "sustained-operating-envelope.v1.json"
SCHEMA_PATH = ROOT / "schemas" / "json" / "sustained-operating-envelope.schema.json"


def opid(namespace: str, sequence: int) -> str:
    return f"opid:v1:{namespace}:u7:019fffff-0000-7000-8000-{sequence:012x}"


def measurement_summaries(*, thermal_available: bool = False) -> list[dict[str, object]]:
    values: list[dict[str, object]] = []
    definitions = (
        ("cpu-utilization", "basis_points", 5000),
        ("environment-cache-size", "bytes", 10_000),
        ("execution-scratch-size", "bytes", 20_000),
        ("persistent-disk-available", "bytes", 50_000),
        ("processor-temperature", "millidegrees_celsius", 60_000),
        ("ram-working-set", "bytes", 30_000),
        ("result-spool-size", "bytes", 40_000),
    )
    for name, unit, observed in definitions:
        if name == "processor-temperature" and not thermal_available:
            values.append(
                {
                    "diagnostic": "portable temperature telemetry is unavailable on this fixture host",
                    "last": None,
                    "maximum": None,
                    "measurement": name,
                    "minimum": None,
                    "sample_count": 0,
                    "status": "unavailable",
                    "unit": unit,
                }
            )
        else:
            values.append(
                {
                    "diagnostic": None,
                    "last": observed,
                    "maximum": observed + 1,
                    "measurement": name,
                    "minimum": observed - 1,
                    "sample_count": 60,
                    "status": "observed",
                    "unit": unit,
                }
            )
    return values


def build_chain(*, unstable: bool = False) -> tuple[dict[str, object], ...]:
    plan = load_plan(PLAN_PATH)
    checkpoints: list[dict[str, object]] = []
    counters = {field: 0 for field in COUNTER_FIELDS}
    observed = datetime(2026, 8, 24, tzinfo=timezone.utc)
    attempt = opid("execution-attempt", 1)
    session = 1

    def append(phase: str, *, duration_ms: int | None = None, work: int = 0) -> None:
        nonlocal observed, attempt, session, counters
        sequence = len(checkpoints) + 1
        if phase == "recovery":
            attempt = opid("execution-attempt", 2)
            session = 2
        window = None
        if duration_ms is not None:
            window = {
                "completed_work_count": work,
                "duration_ms": duration_ms,
                "measurement_summaries": measurement_summaries(),
                "sampling_overhead_ms": 100,
            }
            counters["completed_work_count"] += work
            counters["sampler_overhead_ms"] += 100
            if phase in {"steady-load", "post-recovery"}:
                counters["stability_duration_ms"] += duration_ms
                counters["stability_window_count"] += 1
                if phase == "post-recovery":
                    counters["post_recovery_duration_ms"] += duration_ms
        if phase == "interruption":
            counters["interruption_count"] += 1
        elif phase == "recovery":
            counters["successful_resume_count"] += 1
        elif phase == "complete":
            counters["logical_completion_count"] += 1
        checkpoint = {
            "attempt_id": attempt,
            "checkpoint_digest_sha256": "0" * 64,
            "checkpoint_id": opid("operating-envelope-checkpoint", sequence),
            "classification": dict(CLASSIFICATION),
            "counters": dict(counters),
            "failure_increments": {field: 0 for field in sorted({
                "containment_failure_count",
                "duplicate_completion_count",
                "integrity_failure_count",
                "resource_floor_breach_count",
            })},
            "logical_execution_id": opid("logical-execution", 1),
            "observed_at": observed.isoformat().replace("+00:00", "Z"),
            "phase": phase,
            "plan_digest_sha256": plan["plan_digest_sha256"],
            "previous_checkpoint_digest_sha256": (
                None if not checkpoints else checkpoints[-1]["checkpoint_digest_sha256"]
            ),
            "qualification_id": opid("operating-envelope", 1),
            "record_type": "checkpoint",
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "sequence": sequence,
            "session_index": session,
            "window": window,
        }
        checkpoints.append(finalize_checkpoint(checkpoint))
        observed += timedelta(hours=1)

    append("baseline", duration_ms=3_600_000, work=3_600)
    for _ in range(24):
        append("steady-load", duration_ms=3_600_000, work=3_600)
    append("interruption")
    append("recovery")
    for index in range(24):
        work = 100 if unstable and index == 23 else 3_600
        append("post-recovery", duration_ms=3_600_000, work=work)
    append("complete")
    return tuple(checkpoints)


class SustainedOperatingEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = load_plan(PLAN_PATH)
        cls.validator = Draft202012Validator(
            json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
            format_checker=FormatChecker(),
        )

    def test_tracked_plan_is_canonical_digest_bound_and_schema_valid(self) -> None:
        validate_plan(self.plan)
        verify_plan_source_bindings(ROOT, self.plan)
        self.assertEqual(PLAN_PATH.read_bytes(), canonical_artifact_bytes(self.plan))
        self.validator.validate(self.plan)
        self.assertEqual(self.plan["minimum_stability_duration_ms"], 48 * 60 * 60 * 1000)
        self.assertEqual(self.plan["minimum_post_recovery_duration_ms"], 12 * 60 * 60 * 1000)

    def test_complete_multi_day_chain_passes_with_one_logical_completion(self) -> None:
        chain = build_chain()
        validated = validate_checkpoint_chain(self.plan, chain)
        for checkpoint in validated:
            self.validator.validate(checkpoint)
        report = build_report(self.plan, validated)
        validate_report(self.plan, chain, report)
        self.validator.validate(report)
        self.assertEqual(report["summary"]["status"], "passed")
        self.assertEqual(report["summary"]["physical_attempt_count"], 2)
        self.assertEqual(report["summary"]["logical_completion_count"], 1)
        thermal = next(
            item for item in report["measurement_coverage"]
            if item["measurement"] == "processor-temperature"
        )
        self.assertEqual(thermal["status"], "unavailable")
        self.assertTrue(thermal["diagnostics"])

    def test_checkpoint_files_load_as_canonical_contiguous_append_only_chain(self) -> None:
        chain = build_chain()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for checkpoint in chain:
                sequence = checkpoint["sequence"]
                (root / f"checkpoint-{sequence:06d}.json").write_bytes(
                    canonical_artifact_bytes(checkpoint)
                )
            self.assertEqual(load_checkpoint_chain(root, self.plan), chain)

            tool = ROOT / "tools" / "control_plane" / "compile_sustained_operating_envelope.py"
            expected_report = canonical_artifact_bytes(build_report(self.plan, chain))
            compiled = subprocess.run(
                [sys.executable, str(tool), "--checkpoint-root", str(root)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr.decode("utf-8"))
            self.assertEqual(compiled.stdout, expected_report)

            report_path = root / "operating-envelope-report.json"
            written = subprocess.run(
                [
                    sys.executable,
                    str(tool),
                    "--checkpoint-root",
                    str(root),
                    "--report",
                    str(report_path),
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(written.returncode, 0, written.stderr.decode("utf-8"))
            self.assertEqual(report_path.read_bytes(), expected_report)
            refused = subprocess.run(
                [
                    sys.executable,
                    str(tool),
                    "--checkpoint-root",
                    str(root),
                    "--report",
                    str(report_path),
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(refused.returncode, 2)
            self.assertIn(b"cannot be overwritten", refused.stderr)
            self.assertEqual(report_path.read_bytes(), expected_report)

            renamed = root / "checkpoint-0000100.json"
            (root / "checkpoint-000010.json").rename(renamed)
            with self.assertRaisesRegex(OperatingEnvelopeError, "filenames"):
                load_checkpoint_chain(root, self.plan)

    def test_predecessor_or_content_substitution_fails_closed(self) -> None:
        chain = list(build_chain())
        substituted = deepcopy(chain[10])
        substituted["window"]["completed_work_count"] += 1
        chain[10] = substituted
        with self.assertRaisesRegex(OperatingEnvelopeError, "digest"):
            validate_checkpoint_chain(self.plan, chain)

        chain = list(build_chain())
        substituted = deepcopy(chain[10])
        substituted["previous_checkpoint_digest_sha256"] = "f" * 64
        chain[10] = finalize_checkpoint(substituted)
        with self.assertRaisesRegex(OperatingEnvelopeError, "predecessor"):
            validate_checkpoint_chain(self.plan, chain)

    def test_implicit_retry_and_duplicate_logical_completion_are_rejected(self) -> None:
        chain = list(build_chain())
        changed_attempt = deepcopy(chain[2])
        changed_attempt["attempt_id"] = opid("execution-attempt", 99)
        chain[2] = finalize_checkpoint(changed_attempt)
        with self.assertRaisesRegex(OperatingEnvelopeError, "only at an explicit recovery"):
            validate_checkpoint_chain(self.plan, chain[:3])

        chain = list(build_chain())
        duplicated = deepcopy(chain[-1])
        duplicated["counters"]["logical_completion_count"] = 2
        chain[-1] = finalize_checkpoint(duplicated)
        with self.assertRaisesRegex(OperatingEnvelopeError, "logical_completion_count"):
            validate_checkpoint_chain(self.plan, chain)

    def test_unknown_required_measurement_is_rejected_but_unknown_thermal_is_preserved(self) -> None:
        chain = list(build_chain())
        changed = deepcopy(chain[1])
        summary = next(
            item for item in changed["window"]["measurement_summaries"]
            if item["measurement"] == "ram-working-set"
        )
        summary.update(
            {"diagnostic": "fixture cannot inspect RAM", "last": None, "maximum": None,
             "minimum": None, "sample_count": 0, "status": "unavailable"}
        )
        chain[1] = finalize_checkpoint(changed)
        with self.assertRaisesRegex(OperatingEnvelopeError, "required measurement"):
            validate_checkpoint_chain(self.plan, chain[:2])

    def test_completed_unstable_throughput_fails_qualification(self) -> None:
        report = build_report(self.plan, build_chain(unstable=True))
        self.validator.validate(report)
        self.assertEqual(report["summary"]["status"], "failed")
        criterion = {item["criterion"]: item["status"] for item in report["criteria"]}
        self.assertEqual(criterion["throughput-stability"], "failed")

    def test_incomplete_chain_reports_pending_without_claiming_success(self) -> None:
        report = build_report(self.plan, build_chain()[:-1])
        self.validator.validate(report)
        self.assertEqual(report["summary"]["status"], "in-progress")
        self.assertEqual(report["summary"]["logical_completion_count"], 0)
        self.assertIn("pending", {item["status"] for item in report["criteria"]})


if __name__ == "__main__":
    unittest.main()
