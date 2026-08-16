"""Partition-safe execution and exact reconciliation for the 1M campaign."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
import uuid

from regex_conformance_scale.compiler import reconstruct_request
from regex_conformance_scale.execution import (
    PlannedInterruption,
    ScaleCampaignController,
    ScaleExecutionError,
)
from regex_conformance_scale.million_compiler import (
    verify_materialized_partition,
    verify_partition_plan,
)
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.identity import NamespaceRegistry
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict
from regex_conformance_schema.schema import validate_instance


class DistributedLogicalStore:
    """Verified request reconstruction over one exact master-plan partition."""

    def __init__(
        self,
        repository_root: Path,
        master_plan: dict[str, Any],
        partition_plan: dict[str, Any],
        segment_root: Path,
    ) -> None:
        self.repository_root = repository_root.resolve(strict=True)
        self.master_plan = master_plan
        self.plan = partition_plan
        self.segment_root = segment_root.expanduser().resolve(strict=True)
        verify_materialized_partition(
            self.repository_root, master_plan, partition_plan, self.segment_root
        )
        base = load_strict(self.repository_root / partition_plan["base_campaign"]["path"])
        self.base_by_id = {
            item["logical_execution_id"]: item for item in base["logical_executions"]
        }
        self.schema = load_strict(
            self.repository_root / "schemas/json/logical-execution-segment.schema.json"
        )

    def load(self, shard: dict[str, Any]) -> list[dict[str, Any]]:
        unresolved = self.segment_root / shard["relative_path"]
        try:
            path = unresolved.resolve(strict=True)
            path.relative_to(self.segment_root)
        except (OSError, ValueError) as error:
            raise ScaleExecutionError("partition logical segment is absent") from error
        encoded = path.read_bytes()
        if (
            unresolved.absolute() != path
            or len(encoded) != shard["size_bytes"]
            or hashlib.sha256(encoded).hexdigest() != shard["sha256"]
        ):
            raise ScaleExecutionError("partition logical segment bytes differ")
        try:
            payload = loads_strict(encoded.decode("utf-8"))
        except (ConformanceDataError, UnicodeError) as error:
            raise ScaleExecutionError("partition logical segment is not strict JSON") from error
        validate_instance(payload, self.schema, source=str(path))
        if canonical_bytes(payload) + b"\n" != encoded:
            raise ScaleExecutionError("partition logical segment is not canonical")
        logical_ids = [
            item["logical_execution_id"] for item in payload["logical_executions"]
        ]
        if (
            payload["shard_id"] != shard["shard_id"]
            or payload["selection_key"] != shard["selection_key"]
            or hashlib.sha256(canonical_bytes(logical_ids)).hexdigest()
            != shard["logical_execution_ids_sha256"]
        ):
            raise ScaleExecutionError("partition logical coordinates differ")
        result = []
        for record in payload["logical_executions"]:
            base = self.base_by_id.get(record["base_logical_execution_id"])
            if base is None:
                raise ScaleExecutionError("partition logical base template is absent")
            request = reconstruct_request(self.plan["campaign_id"], record, base)
            result.append({**record, "request": request})
        return result


class DistributedPartitionController(ScaleCampaignController):
    """Use the proven scale state machine with a partition-specific verifier."""

    def __init__(
        self,
        repository_root: Path,
        master_plan: dict[str, Any],
        plan: dict[str, Any],
        logical_store: DistributedLogicalStore,
        ledger: Any,
        evidence: Any,
        worker: Any,
    ) -> None:
        self.repository_root = repository_root
        self.master_plan = master_plan
        self.plan = plan
        self.logical_store = logical_store
        self.ledger = ledger
        self.evidence = evidence
        self.worker = worker
        self.__post_init__()

    def __post_init__(self) -> None:
        self.repository_root = self.repository_root.resolve(strict=True)
        verify_partition_plan(self.repository_root, self.master_plan, self.plan)
        self.registry = NamespaceRegistry.load(
            self.repository_root / "registries/identity/namespaces.v1.json"
        )
        self.shard_by_id = {item["shard_id"]: item for item in self.plan["shards"]}
        if len(self.shard_by_id) != len(self.plan["shards"]):
            raise ScaleExecutionError("partition shard identities collide")

    def execute(self, trust_class: str) -> tuple[dict[str, Any], dict[str, Any]]:
        if trust_class != "trusted_executioner":
            raise ScaleExecutionError("million partitions require trusted execution")
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
                    (item for item in self.plan["shards"] if item["shard_id"] not in completed),
                    None,
                )
                if shard is None:
                    break
                logicals = self.logical_store.load(shard)
                attempt_number = self.ledger.attempt_number(shard["shard_id"])
                if attempt_number > self.plan["attempt_policy"]["maximum_attempts_per_logical_execution"]:
                    raise ScaleExecutionError("partition shard exhausted its attempts")
                from regex_conformance_scale.execution import _stamp

                started_at = _stamp()
                try:
                    results, provenance = self.worker.execute_shard(
                        shard["selection_key"], logicals
                    )
                except Exception as error:
                    ended_at = _stamp()
                    attempts = self._attempts(
                        self.registry,
                        logicals,
                        attempt_number,
                        started_at=started_at,
                        ended_at=ended_at,
                        infrastructure_failure={
                            "code": "million-partition-infrastructure-failure",
                            "message": f"{type(error).__name__}: {str(error)[:1900]}",
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
                        "distributed_parent_campaign_manifest_id": self.plan[
                            "parent_campaign_manifest_id"
                        ],
                        "partition_index": self.plan["partition_index"],
                        "trust_class": trust_class,
                    },
                    segment_kind="result",
                )
                self.ledger.commit_segment(
                    shard["shard_id"], "result", attempt_number, reference
                )
            interruptions = self.ledger.interruptions()
            if len(interruptions) != 3:
                raise ScaleExecutionError("partition interruption history is incomplete")
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
                "parent_campaign_manifest_id": self.plan[
                    "parent_campaign_manifest_id"
                ],
                "partition_count": self.plan["partition_count"],
                "partition_index": self.plan["partition_index"],
                "reconciliation": "exact",
                "result_shard_count": manifest["result_shard_count"],
                "schema_version": "million-scale-partition-execution-report.v1",
                "session_summary": self.ledger.session_summary(),
                "trust_class": trust_class,
            }
            validate_instance(
                report,
                load_strict(
                    self.repository_root
                    / "schemas/json/million-scale-partition-execution-report.schema.json"
                ),
                source="million scale partition execution report",
            )
            return manifest, report
        except PlannedInterruption:
            raise
        except Exception:
            if not session_terminal:
                self.ledger.end_session(session_id, "failed")
            raise
