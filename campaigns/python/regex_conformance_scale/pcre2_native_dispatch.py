"""Serial, locally retained native execution for an already admitted PCRE2 assignment."""

from base64 import b64encode
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Callable

from regex_conformance_adapters.jsonio import encode_frame
from regex_conformance_control_plane.containment import ContainedExecutionResult, ExecutionLimits
from regex_conformance_schema.execution_provenance_v3 import parse_native_frame
from regex_conformance_schema.identity import NamespaceRegistry, generate_assigned_id
from regex_conformance_schema.jsonio import canonical_bytes, loads_strict
from regex_conformance_schema.errors import ConformanceDataError

from .pcre2_execution_gate import Pcre2ExecutionGate, _write_once


def _frame_pairs(stdout: bytes) -> tuple[bytes, bytes]:
    if len(stdout) < 8:
        raise ValueError("target returned fewer than two frames")
    split = 4 + int.from_bytes(stdout[:4], "big")
    if split <= 4 or split + 4 >= len(stdout):
        raise ValueError("target handshake is incomplete")
    if split + 4 + int.from_bytes(stdout[split:split + 4], "big") != len(stdout):
        raise ValueError("target result is incomplete or has trailing frames")
    return stdout[:split], stdout[split:]


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _b64(raw: bytes) -> str:
    return b64encode(raw).decode("ascii")


def _validate_native_exchange(root: Path, stdout: bytes, offer: dict, request: dict, facts: dict) -> None:
    handshake_frame, response_frame = _frame_pairs(stdout)
    handshake = parse_native_frame(_b64(handshake_frame), root / "schemas/json/adapter-handshake.schema.json", "handshake")
    response = parse_native_frame(_b64(response_frame), root / "schemas/json/adapter-response.schema.json", "response")
    names = ("adapter_release_manifest_id", "correlation_id", "profile_id", "target_release_id", "trace_reference")
    transcript = {"offer": offer, "result": {key: val for key, val in handshake.items() if key != "transcript_sha256"}}
    if (
        handshake["outcome"] != "accepted" or handshake["adapter_release_manifest_id"] != request["adapter_release_manifest_id"]
        or handshake["correlation_id"] != offer["correlation_id"]
        or handshake["transcript_sha256"] != sha256(canonical_bytes(transcript)).hexdigest()
        or any(request[name] != response[name] for name in names)
        or response["status"] != "completed"
    ):
        raise ValueError("target response does not bind the exact adapter and native request")
    runtime = handshake["runtime_identity"]
    handshake_facts = {row["name"]: row["value"] for row in runtime["facts"]}
    if (
        handshake_facts != facts or len(handshake_facts) != len(runtime["facts"])
        or runtime["profile_id"] != request["profile_id"] or runtime["target_release_id"] != request["target_release_id"]
    ):
        raise ValueError("target handshake differs from the admitted runtime identity")
    observation = response["observation"]
    observed = observation["runtime_identity"]["facts"]
    if (
        observation["operation"] != request["operation"] or {row["name"]: row["value"] for row in observed} != facts
        or len(observed) != len(facts) or any(item["reason"] == "truncated" for item in observation["absences"])
    ):
        raise ValueError("native result contradicts its operation, runtime or response completeness")


def dispatch_serial(
    root: Path, journal: Path, gate: Pcre2ExecutionGate, *, offer: dict, runtime_facts: dict,
    invoke: Callable[[bytes, ExecutionLimits], ContainedExecutionResult],
) -> dict:
    """Dispatch up to the frozen exact population, using an independent hard-limit provider."""
    proposal = loads_strict(gate.proposal_bytes.decode("utf-8"))
    rows = proposal["logical_assignments"]
    caps = proposal["execution_caps"]
    registry = NamespaceRegistry.load(root / "registries/identity/namespaces.v2.json")
    session = {
        "campaign_id": generate_assigned_id(registry, "rcid", "campaign"),
        "campaign_manifest_id": proposal["campaign_manifest_id"],
        "execution_admission_sha256": gate.admission_sha256,
        "environment_realization_id": gate.environment_realization_id,
    }
    _write_once(journal / "dispatch-session.json", session)
    target_wall_total = 0
    physical_attempts = 0
    captures = []
    stop_reason = None
    for index, row in enumerate(rows):
        budget = row["resource_budget"]
        if target_wall_total + budget["wall_time_ms"] > caps["target_wall_time_total_ms"]:
            stop_reason = "aggregate-wall-time-admission"
            break
        bytes_used = sum(path.stat().st_size for path in journal.iterdir() if path.is_file())
        # Reserve encoded output, protocol frames, the journal header and fixed telemetry.
        capture_bound = 2 * (budget["stdout_bytes"] + budget["stderr_bytes"]) + 32_768
        if bytes_used + capture_bound > caps["local_evidence_bytes"]:
            stop_reason = "local-evidence-admission"
            break
        reservation, request = gate.reserve_next(root, journal, index)
        request_frame = encode_frame(request)
        offer_frame = encode_frame(offer)
        limits = ExecutionLimits(
            wall_time_ms=budget["wall_time_ms"], memory_bytes=budget["memory_bytes"],
            stdout_bytes=budget["stdout_bytes"], stderr_bytes=budget["stderr_bytes"], cpu_time_seconds=1,
        )
        started = _utc()
        physical_attempts += 1
        try:
            result = invoke(offer_frame + request_frame, limits)
        except Exception as error:
            # An exception after reserving cannot establish whether the process
            # launched. Its reservation remains permanently unresolved.
            stop_reason = f"uncertain-dispatch-{type(error).__name__}"
            break
        ended = _utc()
        target_wall_total += result.wall_time_ms
        complete = False
        if result.outcome != "completed" or result.exit_code != 0 or result.wall_time_ms > budget["wall_time_ms"]:
            stop_reason = "contained-process-failure"
        elif result.stdout_total_bytes != len(result.stdout) or result.stderr_total_bytes != len(result.stderr):
            stop_reason = "incomplete-process-capture"
        else:
            try:
                _validate_native_exchange(root, result.stdout, offer, request, runtime_facts)
                complete = True
            except (ValueError, ConformanceDataError):
                stop_reason = "malformed-native-exchange"
        report = {
            "schema_version": "pcre2-physical-capture.v1",
            "reservation_sha256": sha256(canonical_bytes(reservation)).hexdigest(),
            "physical_run_id": reservation["physical_run_id"],
            "logical_execution_id": reservation["logical_execution_id"],
            "observation_id": generate_assigned_id(registry, "rcid", "observation") if complete else None,
            "disposition": "complete-native-response" if complete else "inconclusive-attempt",
            "start_time": started, "end_time": ended, "process": result.to_dict(),
            "native_offer_frame": _b64(offer_frame), "native_request_frame": _b64(request_frame),
            "native_stdout": _b64(result.stdout), "native_stderr": _b64(result.stderr),
        }
        path = gate.close(journal, index, report)
        captures.append({"path": path.name, "sha256": sha256(path.read_bytes()).hexdigest()})
        if stop_reason:
            break
    return {
        "schema_version": "pcre2-local-serial-dispatch-report.v1",
        "planned": len(rows), "dispatch_reservations": physical_attempts, "closed_physical_captures": len(captures),
        "withheld": len(rows) - physical_attempts, "target_wall_time_ms": target_wall_total,
        "captures": captures, "stop_reason": stop_reason,
    }
