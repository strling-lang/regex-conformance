"""Verify an exact PCRE2 assignment and reserve its physical runs once."""

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
from typing import Any

from regex_conformance_schema.execution_provenance_v3 import LINEAGE_VERSION
from regex_conformance_schema.identity import NamespaceRegistry, generate_assigned_id
from regex_conformance_schema.jsonio import canonical_bytes, loads_strict
from regex_conformance_schema.pcre2_production_adjudication import production_trace_reference, request_semantics


class Pcre2ExecutionGateError(ValueError):
    """A production assignment or journal failed a fail-closed check."""


def _digest(body: dict) -> str:
    return sha256(canonical_bytes(body)).hexdigest()


def _read_pinned(raw: bytes, field: str, expected: str) -> dict:
    if len(raw) > 4_194_304:
        raise Pcre2ExecutionGateError("assignment input exceeds the byte limit")
    body = loads_strict(raw.decode("utf-8"))
    if not isinstance(body, dict) or canonical_bytes(body) + b"\n" != raw or (
        body.get(field) != expected or _digest({k: v for k, v in body.items() if k != field}) != expected
    ):
        raise Pcre2ExecutionGateError(f"{field} does not match the independently pinned canonical record")
    return body


@dataclass(frozen=True)
class Pcre2ExecutionGate:
    """A local verified assignment. The protected worker owns the independent pins."""

    proposal_bytes: bytes
    admission_sha256: str
    environment_realization_id: str

    @classmethod
    def verify(
        cls, root: Path, proposal_bytes: bytes, admission_bytes: bytes, *,
        expected_proposal: str, expected_admission: str, verified_source: dict,
        verified_worker: dict,
    ) -> "Pcre2ExecutionGate":
        proposal = _read_pinned(proposal_bytes, "proposal_digest_sha256", expected_proposal)
        admission = _read_pinned(admission_bytes, "execution_admission_sha256", expected_admission)
        required_shape = {
            "schema_version": "pcre2-production-campaign-proposal.v1",
            "classification": "offline-proposal-not-execution-authority",
            "execution_authorized": False,
            "production_credit": 0,
        }
        if any(proposal.get(key) != value for key, value in required_shape.items()):
            raise Pcre2ExecutionGateError("execution requires the exact offline proposal version")
        expected_source = {
            "source_sha": proposal["source_sha"], "envelope_sha": proposal["protected_envelope_sha"],
            "local_certification_root": proposal["local_certification_root"],
        }
        if verified_source != expected_source:
            raise Pcre2ExecutionGateError("worker source differs from the protected proposal source")
        required_worker = {
            "trust_class": "trusted_executioner", "os": "Ubuntu 24.04", "architecture": "x86-64",
            "environment_fingerprint_id": proposal["worker"]["scope"]["environment_fingerprint_id"],
            "network_during_execution": False, "process_tree_containment": True,
            "maximum_target_processes": 1, "resource_admission_passed": True,
        }
        if any(verified_worker.get(key) != value for key, value in required_worker.items()):
            raise Pcre2ExecutionGateError("worker trust, realization, resource, or containment attestation differs")
        realization = verified_worker["environment_realization_id"]
        registry = NamespaceRegistry.load(root / "registries/identity/namespaces.v2.json")
        if registry.validate(realization).namespace != "environment-realization":
            raise Pcre2ExecutionGateError("invalid environment realization identity")
        rows = proposal["logical_assignments"]
        logical_ids = [row["logical_execution_id"] for row in rows]
        caps = proposal["execution_caps"]
        exact_caps = {
            "logical_executions": 16, "physical_attempts": 16, "automatic_retries": 0, "automatic_repeats": 0,
            "concurrency": 1, "target_wall_time_total_ms": 16_000, "local_evidence_bytes": 16_777_216,
            "remote_writes": 0,
        }
        if caps != exact_caps or len(logical_ids) != 16 or len(set(logical_ids)) != 16 or (
            len({row["vector_revision_id"] for row in rows}) != 16
            or sum(row["resource_budget"]["wall_time_ms"] for row in rows) != caps["target_wall_time_total_ms"]
        ):
            raise Pcre2ExecutionGateError("proposal differs from the one-run 16-coordinate execution limits")
        for row in rows:
            budget = row["resource_budget"]
            request = row["request_preview"]
            if (
                row["campaign_manifest_id"] != proposal["campaign_manifest_id"]
                or _digest(request) != row["request_preview_sha256"]
                or _digest(request_semantics(request)) != row["request_semantic_sha256"]
                or row["environment_fingerprint_id"] != required_worker["environment_fingerprint_id"]
                or row["operation"] != request["operation"]
                or not 1 <= budget["wall_time_ms"] <= 1_000
                or request["limits"]["wall_time_ms"] != budget["wall_time_ms"]
                or not 1 <= budget["cpu_time_ms"] <= 1_000
                or budget["process_count"] != 1
                or not 1 <= budget["memory_bytes"] <= 268_435_456
                or not 1 <= budget["stdout_bytes"] <= 65_536
                or not 1 <= budget["stderr_bytes"] <= 4_096
            ):
                raise Pcre2ExecutionGateError("an assignment request or hard resource bound differs")
        expected_scope = {
            "schema_version": "pcre2-production-execution-admission.v1",
            "classification": "trusted-execution-admission", "execution_authorized": True,
            "proposal_digest_sha256": expected_proposal,
            "campaign_manifest_id": proposal["campaign_manifest_id"],
            "source": expected_source, "worker_attestation_sha256": _digest(verified_worker),
            "environment_realization_id": realization, "execution_lineage_version": LINEAGE_VERSION,
            "execution_policy_revision_sha256": proposal["execution_policy_revision_sha256"],
            "logical_execution_ids": logical_ids, "caps": caps,
        }
        if any(admission.get(key) != value for key, value in expected_scope.items()):
            raise Pcre2ExecutionGateError("trusted execution admission differs from the frozen expected scope")
        return cls(proposal_bytes, expected_admission, realization)

    def reserve_next(self, root: Path, journal: Path, index: int) -> tuple[dict[str, Any], dict[str, Any]]:
        """Reserve before invocation. A prior reservation is never safe to retry."""
        proposal = loads_strict(self.proposal_bytes.decode("utf-8"))
        rows = proposal["logical_assignments"]
        if not 0 <= index < len(rows) or journal.is_symlink() or not journal.is_dir():
            raise Pcre2ExecutionGateError("invalid campaign journal or coordinate ordinal")
        campaign_key = proposal["campaign_manifest_id"].rsplit(":", 1)[1]
        if journal.name != campaign_key:
            raise Pcre2ExecutionGateError("journal directory differs from the approved campaign identity")
        row = rows[index]
        for prior in range(index):
            _validate_closed(journal, prior, rows[prior]["logical_execution_id"], self.admission_sha256)
        registry = NamespaceRegistry.load(root / "registries/identity/namespaces.v2.json")
        physical_id = generate_assigned_id(registry, "rcid", "physical-run")
        request = {
            **row["request_preview"], "correlation_id": physical_id.rsplit(":", 1)[1],
            "trace_reference": production_trace_reference(physical_id),
        }
        reservation = {
            "schema_version": "pcre2-physical-reservation.v1",
            "execution_admission_sha256": self.admission_sha256,
            "environment_realization_id": self.environment_realization_id,
            "logical_execution_id": row["logical_execution_id"],
            "physical_run_id": physical_id, "request_sha256": _digest(request),
        }
        pending = journal / f"{index:02d}.reserved"
        _write_once(pending, reservation)
        return reservation, request

    def close(self, journal: Path, index: int, capture: dict) -> Path:
        """Commit the backed physical capture after the dispatcher has stopped."""
        proposal = loads_strict(self.proposal_bytes.decode("utf-8"))
        rows = proposal["logical_assignments"]
        if not 0 <= index < len(rows) or journal.is_symlink() or journal.name != proposal["campaign_manifest_id"].rsplit(":", 1)[1]:
            raise Pcre2ExecutionGateError("invalid campaign capture or coordinate ordinal")
        row = rows[index]
        reserved_path = journal / f"{index:02d}.reserved"
        reserved = _read_journal(reserved_path)
        if (
            capture["reservation_sha256"] != _digest(reserved)
            or capture["physical_run_id"] != reserved["physical_run_id"]
            or reserved["logical_execution_id"] != row["logical_execution_id"]
            or reserved["execution_admission_sha256"] != self.admission_sha256
        ):
            raise Pcre2ExecutionGateError("physical capture does not belong to its exact reservation")
        if capture["disposition"] not in {"complete-native-response", "inconclusive-attempt"}:
            raise Pcre2ExecutionGateError("capture has an unknown physical disposition")
        bytes_used = sum(path.stat().st_size for path in journal.iterdir() if path.is_file())
        if bytes_used + len(canonical_bytes(capture)) + 1 > proposal["execution_caps"]["local_evidence_bytes"]:
            raise Pcre2ExecutionGateError("closing capture exceeds approved local evidence capacity")
        path = journal / f"{index:02d}.closed"
        _write_once(path, capture)
        return path


def _read_journal(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise Pcre2ExecutionGateError("a required create-once journal record is missing")
    with path.open("rb") as stream:
        raw = stream.read(16_777_217)
    if len(raw) > 16_777_216:
        raise Pcre2ExecutionGateError("journal record exceeds campaign capacity")
    record = loads_strict(raw.decode("utf-8"))
    if not isinstance(record, dict) or canonical_bytes(record) + b"\n" != raw:
        raise Pcre2ExecutionGateError("journal record differs from its canonical representation")
    return record


def _validate_closed(journal: Path, index: int, logical_id: str, admission_sha256: str) -> None:
    reserved = _read_journal(journal / f"{index:02d}.reserved")
    closed = _read_journal(journal / f"{index:02d}.closed")
    if (
        reserved.get("logical_execution_id") != logical_id or reserved.get("execution_admission_sha256") != admission_sha256
        or closed.get("physical_run_id") != reserved.get("physical_run_id") or closed.get("reservation_sha256") != _digest(reserved)
        or closed.get("disposition") not in {"complete-native-response", "inconclusive-attempt"}
    ):
        raise Pcre2ExecutionGateError("earlier physical capture does not reconcile with its reservation")


def _write_once(path: Path, record: dict) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(canonical_bytes(record) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise Pcre2ExecutionGateError("journal record already exists and cannot be replaced or retried") from error
    if os.name == "posix":
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
