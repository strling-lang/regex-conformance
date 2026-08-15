"""Restartable execution controller for immutable segmented scale campaigns."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any, Protocol
import uuid

from regex_conformance_scale.compiler import (
    reconstruct_request,
    verify_materialized_segments,
    verify_scale_plan,
)
from regex_conformance_scheduler.scale_recovery import ScaleRecoveryLedger
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.identity import NamespaceRegistry, generate_assigned_id
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict
from regex_conformance_schema.schema import validate_instance
from regex_conformance_verifier import ScaleEvidenceStore


class ScaleExecutionError(RuntimeError):
    """Scale execution cannot continue without corrupting its meaning."""


class PlannedInterruption(ScaleExecutionError):
    """The controller stopped at an exact frozen interruption boundary."""

    def __init__(self, event: dict[str, Any], progress: dict[str, Any]) -> None:
        super().__init__(f"planned interruption completed: {event['interruption_key']}")
        self.event = event
        self.progress = progress


class ScaleShardWorker(Protocol):
    def execute_shard(
        self,
        selection_key: str,
        logical_executions: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]: ...

    def force_kill(self, selection_key: str) -> dict[str, Any]: ...


def _stamp() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class ScaleLogicalStore:
    """Verified access to the 100K external logical-execution segments."""

    def __init__(
        self, repository_root: Path, plan: dict[str, Any], segment_root: Path
    ) -> None:
        self.repository_root = repository_root.resolve(strict=True)
        self.plan = plan
        self.segment_root = segment_root.expanduser().resolve(strict=True)
        verify_materialized_segments(self.repository_root, plan, self.segment_root)
        base = load_strict(self.repository_root / plan["base_campaign"]["path"])
        self.base_by_id = {
            item["logical_execution_id"]: item for item in base["logical_executions"]
        }
        self.segment_schema = load_strict(
            self.repository_root
            / "schemas"
            / "json"
            / "logical-execution-segment.schema.json"
        )

    def load(self, shard: dict[str, Any]) -> list[dict[str, Any]]:
        unresolved = self.segment_root / shard["relative_path"]
        try:
            path = unresolved.resolve(strict=True)
            path.relative_to(self.segment_root)
        except (OSError, ValueError) as error:
            raise ScaleExecutionError(
                "logical-execution segment is missing or escapes its root"
            ) from error
        encoded = path.read_bytes()
        if (
            unresolved.absolute() != path
            or len(encoded) != shard["size_bytes"]
            or hashlib.sha256(encoded).hexdigest() != shard["sha256"]
        ):
            raise ScaleExecutionError(
                "logical-execution segment differs from the campaign manifest"
            )
        try:
            payload = loads_strict(encoded.decode("utf-8"))
        except (ConformanceDataError, UnicodeError) as error:
            raise ScaleExecutionError(
                "logical-execution segment is not strict UTF-8 JSON"
            ) from error
        validate_instance(payload, self.segment_schema, source=str(path))
        if canonical_bytes(payload) + b"\n" != encoded:
            raise ScaleExecutionError("logical-execution segment is noncanonical")
        logical_ids = [
            item["logical_execution_id"] for item in payload["logical_executions"]
        ]
        if (
            payload["shard_id"] != shard["shard_id"]
            or payload["selection_key"] != shard["selection_key"]
            or len(logical_ids) != shard["logical_execution_count"]
            or len(logical_ids) != len(set(logical_ids))
            or logical_ids[0] != shard["first_logical_execution_id"]
            or logical_ids[-1] != shard["last_logical_execution_id"]
            or hashlib.sha256(canonical_bytes(logical_ids)).hexdigest()
            != shard["logical_execution_ids_sha256"]
        ):
            raise ScaleExecutionError(
                "logical-execution segment coordinates differ from its shard"
            )
        result: list[dict[str, Any]] = []
        for record in payload["logical_executions"]:
            base = self.base_by_id.get(record["base_logical_execution_id"])
            if base is None:
                raise ScaleExecutionError(
                    "scale logical execution references an unknown base template"
                )
            request = reconstruct_request(self.plan["campaign_id"], record, base)
            result.append({**record, "request": request})
        return result


@dataclass
class ScaleCampaignController:
    repository_root: Path
    plan: dict[str, Any]
    logical_store: ScaleLogicalStore
    ledger: ScaleRecoveryLedger
    evidence: ScaleEvidenceStore
    worker: ScaleShardWorker

    def __post_init__(self) -> None:
        self.repository_root = self.repository_root.resolve(strict=True)
        verify_scale_plan(self.repository_root, self.plan)
        self.registry = NamespaceRegistry.load(
            self.repository_root / "registries" / "identity" / "namespaces.v1.json"
        )
        self.shard_by_id = {item["shard_id"]: item for item in self.plan["shards"]}
        if len(self.shard_by_id) != len(self.plan["shards"]):
            raise ScaleExecutionError("scale plan contains colliding shard identities")

    @staticmethod
    def _attempts(
        registry: NamespaceRegistry,
        logicals: list[dict[str, Any]],
        attempt_number: int,
        *,
        started_at: str,
        ended_at: str,
        infrastructure_failure: dict[str, str] | None,
    ) -> list[dict[str, Any]]:
        outcome = (
            "target-observation"
            if infrastructure_failure is None
            else "infrastructure-failure"
        )
        return [
            {
                "attempt_number": attempt_number,
                "ended_at": ended_at,
                "infrastructure_failure": infrastructure_failure,
                "logical_execution_id": logical["logical_execution_id"],
                "outcome": outcome,
                "physical_run_id": generate_assigned_id(
                    registry, "rcid", "physical-run"
                ),
                "started_at": started_at,
            }
            for logical in logicals
        ]

    def _progress(self) -> dict[str, Any]:
        completed = len(self.ledger.result_shard_ids())
        return {
            "campaign_manifest_id": self.plan["campaign_manifest_id"],
            "committed_result_shards": completed,
            "interruption_count": len(self.ledger.interruptions()),
            "remaining_result_shards": len(self.plan["shards"]) - completed,
            "schema_version": "scale-execution-progress.v1",
        }

    def _verify_recovery(self) -> None:
        self.ledger.verify(self.plan["campaign_manifest_id"])
        self.ledger.recover_active_sessions()
        for committed in self.ledger.segments():
            shard = self.shard_by_id.get(committed.shard_id)
            if shard is None:
                raise ScaleExecutionError(
                    "recovery ledger references a shard outside the campaign"
                )
            self.evidence.verify_segment(
                committed.reference,
                self.plan,
                shard,
                self.logical_store.load(shard),
            )

    def _due_interruption(self) -> dict[str, Any] | None:
        completed = len(self.ledger.result_shard_ids())
        observed = {item["interruption_key"] for item in self.ledger.interruptions()}
        return next(
            (
                item
                for item in self.plan["planned_interruptions"]
                if item["after_committed_shards"] == completed
                and item["key"] not in observed
            ),
            None,
        )

    def _interrupt(
        self, session_id: str, interruption: dict[str, Any]
    ) -> PlannedInterruption:
        if interruption["action"] == "controller-restart":
            event = self.ledger.record_interruption(
                interruption_key=interruption["key"],
                action=interruption["action"],
                after_committed_shards=interruption["after_committed_shards"],
                controller_session_id=session_id,
            )
        else:
            completed = self.ledger.result_shard_ids()
            shard = next(
                item
                for item in self.plan["shards"]
                if item["shard_id"] not in completed
            )
            logicals = self.logical_store.load(shard)
            prior = [
                item
                for item in self.ledger.segments()
                if item.shard_id == shard["shard_id"] and item.segment_kind == "attempt"
            ]
            if prior:
                recovered = self.evidence.verify_segment(
                    prior[-1].reference, self.plan, shard, logicals
                )
                provenance = recovered["provenance"]
                worker_process = provenance.get("worker_process")
                if provenance.get("forced_interruption") == interruption[
                    "key"
                ] and isinstance(worker_process, dict):
                    event = self.ledger.record_interruption(
                        interruption_key=interruption["key"],
                        action=interruption["action"],
                        after_committed_shards=interruption["after_committed_shards"],
                        controller_session_id=session_id,
                        worker_process=worker_process,
                    )
                    self.ledger.end_session(session_id, "forced-interruption")
                    return PlannedInterruption(event, self._progress())
            attempt_number = self.ledger.attempt_number(shard["shard_id"])
            worker_process = self.worker.force_kill(shard["selection_key"])
            started_at = worker_process["started_at"]
            ended_at = worker_process["ended_at"]
            attempts = self._attempts(
                self.registry,
                logicals,
                attempt_number,
                started_at=started_at,
                ended_at=ended_at,
                infrastructure_failure={
                    "code": "forced-worker-process-kill",
                    "message": "qualification deliberately killed the exact shard worker",
                },
            )
            reference = self.evidence.write_result_segment(
                plan=self.plan,
                shard=shard,
                logicals=logicals,
                attempt_number=attempt_number,
                attempts=attempts,
                results=[],
                provenance={
                    "controller_session_id": session_id,
                    "forced_interruption": interruption["key"],
                    "trust_class": worker_process["trust_class"],
                    "worker_process": {
                        "exit_code": worker_process["exit_code"],
                        "forced": True,
                        "selection_key": worker_process["selection_key"],
                    },
                },
                segment_kind="attempt",
            )
            self.ledger.commit_segment(
                shard["shard_id"], "attempt", attempt_number, reference
            )
            event = self.ledger.record_interruption(
                interruption_key=interruption["key"],
                action=interruption["action"],
                after_committed_shards=interruption["after_committed_shards"],
                controller_session_id=session_id,
                worker_process={
                    "exit_code": worker_process["exit_code"],
                    "forced": True,
                    "selection_key": worker_process["selection_key"],
                },
            )
        self.ledger.end_session(session_id, "forced-interruption")
        return PlannedInterruption(event, self._progress())

    def execute(self, trust_class: str) -> tuple[dict[str, Any], dict[str, Any]]:
        self._verify_recovery()
        session_id = str(uuid.uuid4())
        self.ledger.begin_session(session_id)
        session_terminal = False
        try:
            while True:
                interruption = self._due_interruption()
                if interruption is not None:
                    planned = self._interrupt(session_id, interruption)
                    session_terminal = True
                    raise planned
                completed = self.ledger.result_shard_ids()
                shard = next(
                    (
                        item
                        for item in self.plan["shards"]
                        if item["shard_id"] not in completed
                    ),
                    None,
                )
                if shard is None:
                    break
                logicals = self.logical_store.load(shard)
                attempt_number = self.ledger.attempt_number(shard["shard_id"])
                if attempt_number > 3:
                    raise ScaleExecutionError(
                        "scale shard exhausted its frozen physical-attempt limit"
                    )
                started_at = _stamp()
                try:
                    results, provenance = self.worker.execute_shard(
                        shard["selection_key"], logicals
                    )
                except Exception as error:
                    ended_at = _stamp()
                    failure = {
                        "code": "scale-shard-infrastructure-failure",
                        "message": f"{type(error).__name__}: {str(error)[:1900]}",
                    }
                    attempts = self._attempts(
                        self.registry,
                        logicals,
                        attempt_number,
                        started_at=started_at,
                        ended_at=ended_at,
                        infrastructure_failure=failure,
                    )
                    reference = self.evidence.write_result_segment(
                        plan=self.plan,
                        shard=shard,
                        logicals=logicals,
                        attempt_number=attempt_number,
                        attempts=attempts,
                        results=[],
                        provenance={
                            "controller_session_id": session_id,
                            "failure_type": type(error).__name__,
                            "trust_class": trust_class,
                        },
                        segment_kind="attempt",
                    )
                    self.ledger.commit_segment(
                        shard["shard_id"], "attempt", attempt_number, reference
                    )
                    continue
                ended_at = _stamp()
                attempts = self._attempts(
                    self.registry,
                    logicals,
                    attempt_number,
                    started_at=started_at,
                    ended_at=ended_at,
                    infrastructure_failure=None,
                )
                reference = self.evidence.write_result_segment(
                    plan=self.plan,
                    shard=shard,
                    logicals=logicals,
                    attempt_number=attempt_number,
                    attempts=attempts,
                    results=results,
                    provenance={
                        **provenance,
                        "controller_session_id": session_id,
                        "trust_class": trust_class,
                    },
                    segment_kind="result",
                )
                self.ledger.commit_segment(
                    shard["shard_id"], "result", attempt_number, reference
                )
            interruptions = self.ledger.interruptions()
            if len(interruptions) != len(self.plan["planned_interruptions"]):
                raise ScaleExecutionError(
                    "campaign completed shards without every planned interruption"
                )
            manifest = self.evidence.publish_manifest(
                self.plan,
                self.ledger.segments(),
                interruptions,
                self.logical_store.load,
            )
            self.ledger.end_session(session_id, "completed")
            session_terminal = True
            report = {
                "accepted_observation_count": manifest["accepted_observation_count"],
                "attempt_count": manifest["attempt_count"],
                "campaign_manifest_id": self.plan["campaign_manifest_id"],
                "evidence_manifest_id": manifest["evidence_manifest_id"],
                "evidence_manifest_reference": manifest["manifest_reference"],
                "infrastructure_failure_attempt_count": manifest[
                    "infrastructure_failure_attempt_count"
                ],
                "interruption_count": len(interruptions),
                "logical_execution_count": manifest["logical_execution_count"],
                "reconciliation": "exact",
                "result_shard_count": manifest["result_shard_count"],
                "schema_version": "scale-execution-report.v1",
                "session_summary": self.ledger.session_summary(),
                "trust_class": trust_class,
            }
            validate_instance(
                report,
                load_strict(
                    self.repository_root
                    / "schemas"
                    / "json"
                    / "scale-execution-report.schema.json"
                ),
                source="100K scale execution report",
            )
            return manifest, report
        except PlannedInterruption:
            raise
        except Exception:
            if not session_terminal:
                self.ledger.end_session(session_id, "failed")
            raise
