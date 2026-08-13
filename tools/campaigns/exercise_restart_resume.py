#!/usr/bin/env python3
"""Execute the closed P18 restart/resume interruption qualification."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_scheduler import (
    CHECKPOINT_STATES,
    RecoveryIntegrityError,
    RecoveryJournal,
    build_restart_resume_reference_report,
)
from regex_conformance_schema.identity import NamespaceRegistry, generate_assigned_id
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance


MANIFEST_SHA256 = hashlib.sha256(b"verified immutable recovery qualification manifest").hexdigest()


class PhysicalRunFactory:
    def __init__(self, *fixed: str) -> None:
        self.fixed = list(fixed)
        self.registry = NamespaceRegistry.load(
            ROOT / "registries" / "identity" / "namespaces.v1.json"
        )

    def __call__(self) -> str:
        if self.fixed:
            return self.fixed.pop(0)
        return generate_assigned_id(self.registry, "rcid", "physical-run")


def _outside_repository(path: Path, label: str) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        return resolved
    raise ValueError(f"{label} must remain outside the Git repository")


def _journal(
    path: Path,
    campaign_manifest_id: str,
    logical_execution_id: str,
    session: str,
    factory: PhysicalRunFactory,
) -> RecoveryJournal:
    return RecoveryJournal(
        path,
        campaign_manifest_id=campaign_manifest_id,
        logical_execution_ids=(logical_execution_id,),
        controller_session_id=session,
        physical_run_id_factory=factory,
    )


def _advance(value: RecoveryJournal, physical_run_id: str, target_state: str) -> None:
    current = value.attempts()[-1].latest_state
    for state in CHECKPOINT_STATES[CHECKPOINT_STATES.index(current) + 1 :]:
        if state == "acknowledged":
            value.acknowledge(physical_run_id)
        elif state == "manifest-committed":
            value.checkpoint(
                physical_run_id,
                state,
                {"publication": "read-after-write-verified"},
                manifest_sha256=MANIFEST_SHA256,
            )
        else:
            value.checkpoint(physical_run_id, state, {"state": state})
        if state == target_state:
            return


def _finish(value: RecoveryJournal, physical_run_id: str) -> None:
    latest = value.attempts()[-1].latest_state
    if latest == "acknowledged":
        return
    if latest == "manifest-committed":
        value.acknowledge(physical_run_id)
        return
    _advance(value, physical_run_id, "acknowledged")


def _case_result(
    case_key: str,
    expected_action: str,
    observed_action: str,
    attempts: list[dict[str, Any]],
) -> dict[str, Any]:
    run_ids = [item["physical_run_id"] for item in attempts]
    return {
        "attempt_count": len(attempts),
        "case_key": case_key,
        "committed_attempt_count": sum(item["disposition"] == "committed" for item in attempts),
        "distinct_physical_run_count": len(set(run_ids)),
        "expected_action": expected_action,
        "interrupted_attempt_count": sum(
            item["disposition"] == "interrupted" for item in attempts
        ),
        "observed_action": observed_action,
        "physical_run_ids": sorted(set(run_ids)),
    }


def _write_evidence(root: Path, payload: dict[str, Any]) -> tuple[Path, str]:
    encoded = canonical_bytes(payload) + b"\n"
    digest = hashlib.sha256(encoded).hexdigest()
    destination = root / f"restart-resume-execution-sha256-{digest}.json"
    temporary = root / f".{digest}.tmp"
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    if destination.read_bytes() != encoded:
        raise RuntimeError("restart/resume evidence failed read-after-write verification")
    return destination, digest


def _crash_child(arguments: list[str]) -> int:
    if len(arguments) != 4:
        raise ValueError("crash child requires database, campaign, logical, and physical IDs")
    database, campaign_id, logical_id, physical_id = arguments
    with _journal(
        Path(database),
        campaign_id,
        logical_id,
        "forced-crash-child",
        PhysicalRunFactory(physical_id),
    ) as value:
        decision = value.start_or_resume(logical_id)
        assert decision.physical_run_id == physical_id
        _advance(value, physical_id, "running")
        value.audit()
        os._exit(77)


def exercise(evidence_root: Path) -> dict[str, Any]:
    destination_root = _outside_repository(evidence_root, "evidence directory")
    compiled = load_strict(ROOT / "campaigns" / "compiled" / "small-scale-qualification.v1.json")
    campaign_id = compiled["campaign_manifest_id"]
    logical_id = sorted(
        item["logical_execution_id"] for item in compiled["logical_executions"]
    )[0]
    reference_path = ROOT / "reports" / "small-scale" / "restart-resume-qualification.json"
    reference = load_strict(reference_path)
    expected = build_restart_resume_reference_report()
    if canonical_bytes(reference) != canonical_bytes(expected):
        raise RuntimeError("checked-in restart/resume report differs from executable policy")
    expected_by_key = {item["case_key"]: item for item in reference["cases"]}
    results: list[dict[str, Any]] = []
    restart_count = 0

    with tempfile.TemporaryDirectory(prefix="strling-recovery-") as temporary:
        workspace = Path(temporary)
        for stage in CHECKPOINT_STATES:
            case_key = f"restart-after-{stage}"
            expected_action = expected_by_key[case_key]["expected_action"]
            path = workspace / f"boundary-{stage}.sqlite3"
            factory = PhysicalRunFactory()
            with _journal(path, campaign_id, logical_id, "boundary-before", factory) as before:
                started = before.start_or_resume(logical_id)
                assert started.physical_run_id is not None
                original_run = started.physical_run_id
                if stage != "leased":
                    _advance(before, original_run, stage)
            restart_count += 1
            with _journal(path, campaign_id, logical_id, "boundary-after", factory) as after:
                decision = after.start_or_resume(logical_id)
                if decision.action != expected_action:
                    raise RuntimeError(f"{case_key} recovered as {decision.action}, expected {expected_action}")
                if expected_by_key[case_key]["requires_new_physical_run"]:
                    if decision.physical_run_id == original_run:
                        raise RuntimeError(f"{case_key} reused an interrupted physical run")
                elif decision.physical_run_id != original_run:
                    raise RuntimeError(f"{case_key} replaced a resumable physical run")
                assert decision.physical_run_id is not None
                _finish(after, decision.physical_run_id)
                after.audit()
                attempts = [item.to_dict() for item in after.attempts()]
                if sum(item["disposition"] == "committed" for item in attempts) != 1:
                    raise RuntimeError(f"{case_key} did not finish with exactly one commit")
                results.append(_case_result(case_key, expected_action, decision.action, attempts))

        duplicate_key = "duplicate-active-delivery"
        path = workspace / "duplicate.sqlite3"
        factory = PhysicalRunFactory()
        with _journal(path, campaign_id, logical_id, "duplicate-session", factory) as value:
            first = value.start_or_resume(logical_id)
            assert first.physical_run_id is not None
            _advance(value, first.physical_run_id, "running")
            duplicate = value.start_or_resume(logical_id)
            if duplicate.physical_run_id != first.physical_run_id or len(value.attempts()) != 1:
                raise RuntimeError("duplicate delivery created a second physical attempt")
            _finish(value, first.physical_run_id)
            attempts = [item.to_dict() for item in value.attempts()]
            results.append(
                _case_result(
                    duplicate_key,
                    expected_by_key[duplicate_key]["expected_action"],
                    duplicate.action,
                    attempts,
                )
            )

        repeated_key = "repeated-running-restarts"
        path = workspace / "forced-process-crash.sqlite3"
        initial_run = PhysicalRunFactory()()
        child = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--crash-child",
                str(path),
                campaign_id,
                logical_id,
                initial_run,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        if child.returncode != 77:
            raise RuntimeError(
                f"forced crash child returned {child.returncode}: {child.stderr.decode('utf-8', 'replace')}"
            )
        restart_count += 1
        factory = PhysicalRunFactory()
        for session_number in range(2, 5):
            with _journal(
                path, campaign_id, logical_id, f"forced-restart-{session_number}", factory
            ) as value:
                decision = value.start_or_resume(logical_id)
                if decision.action != "retry" or decision.attempt_number != session_number:
                    raise RuntimeError("forced process restart did not create the expected retry")
                assert decision.physical_run_id is not None
                if session_number < 4:
                    _advance(value, decision.physical_run_id, "running")
                else:
                    _finish(value, decision.physical_run_id)
                    attempts = [item.to_dict() for item in value.attempts()]
                    if [item["disposition"] for item in attempts] != [
                        "interrupted",
                        "interrupted",
                        "interrupted",
                        "committed",
                    ]:
                        raise RuntimeError("repeated restarts lost or rewrote physical attempts")
                    results.append(
                        _case_result(
                            repeated_key,
                            expected_by_key[repeated_key]["expected_action"],
                            decision.action,
                            attempts,
                        )
                    )
            restart_count += 1

        corrupt_key = "corrupt-checkpoint-chain"
        path = workspace / "corrupt.sqlite3"
        factory = PhysicalRunFactory()
        with _journal(path, campaign_id, logical_id, "corrupt-before", factory) as value:
            started = value.start_or_resume(logical_id)
            assert started.physical_run_id is not None
        connection = sqlite3.connect(path)
        connection.execute(
            "UPDATE checkpoints SET checkpoint_sha256 = ? WHERE physical_run_id = ? AND checkpoint_ordinal = 1",
            ("0" * 64, started.physical_run_id),
        )
        connection.commit()
        connection.close()
        restart_count += 1
        observed_action = "continue"
        try:
            _journal(path, campaign_id, logical_id, "corrupt-after", factory)
        except RecoveryIntegrityError:
            observed_action = "quarantine"
        if observed_action != "quarantine":
            raise RuntimeError("corrupt checkpoint chain was not quarantined")
        results.append(
            _case_result(
                corrupt_key,
                expected_by_key[corrupt_key]["expected_action"],
                observed_action,
                [
                    {
                        "disposition": "active",
                        "physical_run_id": started.physical_run_id,
                    }
                ],
            )
        )

        transaction_key = "uncommitted-transaction"
        path = workspace / "uncommitted.sqlite3"
        factory = PhysicalRunFactory()
        with _journal(path, campaign_id, logical_id, "transaction-before", factory) as value:
            started = value.start_or_resume(logical_id)
            assert started.physical_run_id is not None
        raw = sqlite3.connect(path, isolation_level=None)
        raw.execute("BEGIN IMMEDIATE")
        raw.execute(
            "UPDATE attempts SET owner_session_id = 'uncommitted-owner' WHERE physical_run_id = ?",
            (started.physical_run_id,),
        )
        raw.close()
        restart_count += 1
        with _journal(path, campaign_id, logical_id, "transaction-after", factory) as value:
            decision = value.start_or_resume(logical_id)
            if decision.physical_run_id != started.physical_run_id:
                raise RuntimeError("rolled-back transaction replaced the original physical run")
            assert decision.physical_run_id is not None
            _finish(value, decision.physical_run_id)
            attempts = [item.to_dict() for item in value.attempts()]
            results.append(
                _case_result(
                    transaction_key,
                    expected_by_key[transaction_key]["expected_action"],
                    decision.action,
                    attempts,
                )
            )

    results.sort(key=lambda item: item["case_key"])
    if [item["case_key"] for item in results] != sorted(expected_by_key):
        raise RuntimeError("live recovery cases do not exactly match the governed matrix")
    for result in results:
        if result["observed_action"] != result["expected_action"]:
            raise RuntimeError(f"{result['case_key']} did not match its expected recovery action")
        if result["attempt_count"] != result["distinct_physical_run_count"]:
            raise RuntimeError(f"{result['case_key']} reused a physical run identity")

    payload = {
        "campaign_manifest_id": campaign_id,
        "cases": results,
        "classification": reference["classification"],
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "reference_report_sha256": hashlib.sha256(reference_path.read_bytes()).hexdigest(),
        "schema_version": "restart-resume-execution.v1",
        "summary": {
            "case_count": len(results),
            "completed_case_count": sum(
                item["committed_attempt_count"] == 1 for item in results
            ),
            "forced_process_exit_count": 1,
            "quarantined_case_count": sum(item["observed_action"] == "quarantine" for item in results),
            "restart_count": restart_count,
        },
    }
    validate_instance(
        payload,
        load_strict(ROOT / "schemas" / "json" / "restart-resume-execution.schema.json"),
        source="live restart/resume execution evidence",
    )
    evidence_path, evidence_sha256 = _write_evidence(destination_root, payload)
    return {
        **payload["summary"],
        "evidence_path": str(evidence_path),
        "evidence_sha256": evidence_sha256,
    }


def main(arguments: list[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    if values and values[0] == "--crash-child":
        return _crash_child(values[1:])
    if len(values) != 1:
        raise SystemExit("usage: exercise_restart_resume.py EVIDENCE_DIRECTORY")
    summary = exercise(Path(values[0]))
    sys.stdout.buffer.write(canonical_bytes({"ok": True, **summary}) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
