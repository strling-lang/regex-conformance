"""Read-only scale-evidence reconciliation into an immutable SQLite warehouse."""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any, Iterable

from regex_conformance_campaign.compiler import SCHEMA_FAMILY_ID
from regex_conformance_scale.compiler import verify_scale_plan
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.identity import NamespaceRegistry, build_content_identity
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict
from regex_conformance_schema.profile import IdentityProfile
from regex_conformance_schema.schema import validate_instance


class ScaleWarehouseReconciliationError(RuntimeError):
    """The scale evidence cannot produce an exact analytical projection."""


SCHEMA = (
    "CREATE TABLE campaign (campaign_manifest_id TEXT PRIMARY KEY, evidence_manifest_id TEXT NOT NULL UNIQUE, evidence_root_digest TEXT NOT NULL, manifest_sha256 TEXT NOT NULL, execution_report_sha256 TEXT NOT NULL, recovery_ledger_sha256 TEXT NOT NULL, recovery_chain_tail TEXT NOT NULL, logical_execution_count INTEGER NOT NULL, selected_observation_count INTEGER NOT NULL, physical_attempt_count INTEGER NOT NULL, infrastructure_failure_attempt_count INTEGER NOT NULL)",
    "CREATE TABLE shard (shard_id TEXT PRIMARY KEY, selection_key TEXT NOT NULL, logical_segment_sha256 TEXT NOT NULL UNIQUE, logical_execution_count INTEGER NOT NULL)",
    "CREATE TABLE result_segment (segment_sha256 TEXT PRIMARY KEY, result_segment_id TEXT NOT NULL UNIQUE, shard_id TEXT NOT NULL REFERENCES shard(shard_id), segment_kind TEXT NOT NULL CHECK (segment_kind IN ('attempt','result')), attempt_number INTEGER NOT NULL, logical_execution_count INTEGER NOT NULL, observation_count INTEGER NOT NULL, physical_attempt_count INTEGER NOT NULL, ledger_ordinal INTEGER NOT NULL UNIQUE, ledger_commit_sha256 TEXT NOT NULL UNIQUE, UNIQUE (shard_id,segment_kind,attempt_number))",
    "CREATE UNIQUE INDEX one_result_segment_per_shard ON result_segment(shard_id) WHERE segment_kind='result'",
    "CREATE TABLE logical_execution (logical_execution_id TEXT PRIMARY KEY, shard_id TEXT NOT NULL REFERENCES shard(shard_id), selection_key TEXT NOT NULL, base_logical_execution_id TEXT NOT NULL, planned_repetition INTEGER NOT NULL, profile_id TEXT NOT NULL, target_release_id TEXT NOT NULL, vector_revision_id TEXT NOT NULL, request_template_sha256 TEXT NOT NULL)",
    "CREATE TABLE physical_attempt (physical_run_id TEXT PRIMARY KEY, logical_execution_id TEXT NOT NULL REFERENCES logical_execution(logical_execution_id), segment_sha256 TEXT NOT NULL REFERENCES result_segment(segment_sha256), attempt_number INTEGER NOT NULL, outcome TEXT NOT NULL CHECK (outcome IN ('infrastructure-failure','target-observation')), infrastructure_failure_code TEXT, started_at TEXT NOT NULL, ended_at TEXT NOT NULL, UNIQUE (logical_execution_id,attempt_number))",
    "CREATE TABLE selected_observation (observation_content_id TEXT PRIMARY KEY, observation_id TEXT NOT NULL UNIQUE, logical_execution_id TEXT NOT NULL UNIQUE REFERENCES logical_execution(logical_execution_id), physical_run_id TEXT NOT NULL UNIQUE REFERENCES physical_attempt(physical_run_id), segment_sha256 TEXT NOT NULL REFERENCES result_segment(segment_sha256), result_schema_version TEXT NOT NULL, response_status TEXT NOT NULL, match_state TEXT)",
    "CREATE TABLE interruption (interruption_key TEXT PRIMARY KEY, action TEXT NOT NULL, after_committed_shards INTEGER NOT NULL, controller_session_id TEXT NOT NULL, event_sha256 TEXT NOT NULL UNIQUE, observed_at TEXT NOT NULL, worker_selection_key TEXT)",
)
SCHEMA_SHA256 = hashlib.sha256("\n".join(SCHEMA).encode("utf-8")).hexdigest()


class _ContentIds:
    def __init__(self, repository_root: Path) -> None:
        self.registry = NamespaceRegistry.load(
            repository_root / "registries" / "identity" / "namespaces.v1.json"
        )
        self.profile = IdentityProfile.from_record(
            load_strict(
                repository_root
                / "schemas"
                / "identity-profiles"
                / "campaign-content.v1.json"
            )
        )

    def build(self, namespace: str, kind: str, identity: Any) -> str:
        content_sha256 = hashlib.sha256(canonical_bytes(identity)).hexdigest()
        result = build_content_identity(
            registry=self.registry,
            profile=self.profile,
            namespace=namespace,
            identity_schema_family_id=SCHEMA_FAMILY_ID,
            identity_schema_version="1.0.0",
            identity={"artifact_kind": kind, "content_sha256": content_sha256},
        )
        return str(result["content_id"])


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _commitment(values: Iterable[str]) -> str:
    return _digest(sorted(values))


def _direct_external_directory(repository_root: Path, path: Path, label: str) -> Path:
    unresolved = path.expanduser().absolute()
    if unresolved.is_symlink():
        raise ScaleWarehouseReconciliationError(f"{label} cannot be a link")
    try:
        resolved = unresolved.resolve(strict=True)
    except OSError as error:
        raise ScaleWarehouseReconciliationError(f"{label} is absent") from error
    try:
        resolved.relative_to(repository_root)
    except ValueError:
        pass
    else:
        raise ScaleWarehouseReconciliationError(f"{label} must remain outside Git")
    if unresolved != resolved or not resolved.is_dir():
        raise ScaleWarehouseReconciliationError(f"{label} must be a direct directory")
    return resolved


def _warehouse_directory(repository_root: Path, path: Path) -> Path:
    unresolved = path.expanduser().absolute()
    if unresolved.exists():
        return _direct_external_directory(repository_root, unresolved, "warehouse root")
    parent = unresolved.parent.resolve(strict=True)
    try:
        parent.relative_to(repository_root)
    except ValueError:
        pass
    else:
        raise ScaleWarehouseReconciliationError("warehouse root must remain outside Git")
    if unresolved.parent.absolute() != parent or unresolved.is_symlink():
        raise ScaleWarehouseReconciliationError("warehouse root parent is indirect")
    unresolved.mkdir()
    resolved = unresolved.resolve(strict=True)
    if resolved != unresolved or not resolved.is_dir():
        raise ScaleWarehouseReconciliationError("warehouse root creation was indirect")
    return resolved


def _read_json_file(path: Path, *, canonical: bool = True) -> tuple[dict[str, Any], bytes]:
    unresolved = path.absolute()
    try:
        resolved = unresolved.resolve(strict=True)
        metadata = unresolved.stat()
    except OSError as error:
        raise ScaleWarehouseReconciliationError(f"required input is absent: {path.name}") from error
    if (
        unresolved != resolved
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise ScaleWarehouseReconciliationError(f"input must be a direct non-linked file: {path.name}")
    encoded = resolved.read_bytes()
    try:
        payload = loads_strict(encoded.decode("utf-8"))
    except (ConformanceDataError, UnicodeError) as error:
        raise ScaleWarehouseReconciliationError(f"input is not strict UTF-8 JSON: {path.name}") from error
    if not isinstance(payload, dict):
        raise ScaleWarehouseReconciliationError(f"input is not a JSON object: {path.name}")
    if canonical and canonical_bytes(payload) + b"\n" != encoded:
        raise ScaleWarehouseReconciliationError(f"input is not canonical JSON: {path.name}")
    return payload, encoded


def _read_reference(
    base: Path,
    reference: dict[str, Any],
    category: str,
    schema: dict[str, Any],
) -> dict[str, Any]:
    try:
        digest = reference["sha256"]
        relative = reference["relative_path"]
        size = reference["size_bytes"]
    except (KeyError, TypeError) as error:
        raise ScaleWarehouseReconciliationError("artifact reference is malformed") from error
    expected = f"{category}/sha256/{digest}.json"
    if reference.get("category") != category or relative != expected:
        raise ScaleWarehouseReconciliationError("artifact reference is not content-addressed")
    path = base / Path(relative)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(base)
    except (OSError, ValueError) as error:
        raise ScaleWarehouseReconciliationError("artifact reference escapes or is absent") from error
    payload, encoded = _read_json_file(path)
    if len(encoded) != size or hashlib.sha256(encoded).hexdigest() != digest:
        raise ScaleWarehouseReconciliationError("artifact size or digest differs from its reference")
    validate_instance(payload, schema, source=relative)
    return payload


def _exact_directory_paths(base: Path, references: list[dict[str, Any]], category: str) -> None:
    directory = base / category / "sha256"
    expected = {(base / Path(item["relative_path"])).resolve(strict=True) for item in references}
    try:
        actual = {item.resolve(strict=True) for item in directory.iterdir()}
    except OSError as error:
        raise ScaleWarehouseReconciliationError(
            f"{category} contains an indirect or unreadable entry"
        ) from error
    if actual != expected:
        raise ScaleWarehouseReconciliationError(
            f"{category} contains missing or unmanifested objects"
        )


def _ledger_state(
    ledger_path: Path, campaign_manifest_id: str
) -> dict[str, Any]:
    ledger_metadata = ledger_path.stat()
    if (
        ledger_path.is_symlink()
        or ledger_path.absolute() != ledger_path.resolve(strict=True)
        or not stat.S_ISREG(ledger_metadata.st_mode)
        or ledger_metadata.st_nlink != 1
    ):
        raise ScaleWarehouseReconciliationError("recovery ledger must be a direct non-linked file")
    before_sha256 = _sha256(ledger_path)
    uri = ledger_path.as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ScaleWarehouseReconciliationError("recovery ledger integrity check failed")
        metadata = dict(connection.execute("SELECT key,value FROM metadata"))
        if metadata != {
            "campaign_manifest_id": campaign_manifest_id,
            "schema_version": "scale-recovery-ledger.v1",
        }:
            raise ScaleWarehouseReconciliationError("recovery ledger metadata differs")
        sessions = [dict(row) for row in connection.execute("SELECT * FROM sessions ORDER BY started_at")]
        if any(row["ended_at"] is None or row["outcome"] is None for row in sessions):
            raise ScaleWarehouseReconciliationError("recovery ledger contains an active session")
        session_counts = Counter(row["outcome"] for row in sessions)
        session_summary = {
            "active": 0,
            "completed": session_counts["completed"],
            "failed": session_counts["failed"],
            "forced_interruption": session_counts["forced-interruption"],
            "total": len(sessions),
        }
        previous: str | None = None
        commits: list[dict[str, Any]] = []
        for expected_ordinal, row in enumerate(
            connection.execute("SELECT * FROM segment_commits ORDER BY ordinal"), start=1
        ):
            if row["ordinal"] != expected_ordinal:
                raise ScaleWarehouseReconciliationError("ledger ordinals are not contiguous")
            try:
                encoded = bytes(row["reference_json"])
                reference = loads_strict(encoded.decode("utf-8"))
            except (ConformanceDataError, UnicodeError, TypeError) as error:
                raise ScaleWarehouseReconciliationError("ledger reference is invalid JSON") from error
            if not isinstance(reference, dict) or canonical_bytes(reference) != encoded:
                raise ScaleWarehouseReconciliationError("ledger reference is not canonical")
            body = {
                "attempt_number": row["attempt_number"],
                "committed_at": row["committed_at"],
                "ordinal": row["ordinal"],
                "previous_commit_sha256": previous,
                "reference": reference,
                "schema_version": "scale-segment-commit.v1",
                "segment_kind": row["segment_kind"],
                "shard_id": row["shard_id"],
            }
            if row["previous_commit_sha256"] != previous or row["commit_sha256"] != _digest(body):
                raise ScaleWarehouseReconciliationError("recovery ledger hash chain is corrupt")
            commits.append(
                {
                    "attempt_number": row["attempt_number"],
                    "commit_sha256": row["commit_sha256"],
                    "ordinal": row["ordinal"],
                    "reference": reference,
                    "segment_kind": row["segment_kind"],
                    "shard_id": row["shard_id"],
                }
            )
            previous = row["commit_sha256"]
        interruptions: list[dict[str, Any]] = []
        for row in connection.execute(
            "SELECT * FROM interruptions ORDER BY after_committed_shards,interruption_key"
        ):
            worker: dict[str, Any] | None = None
            if row["worker_process"] is not None:
                encoded = bytes(row["worker_process"])
                worker = loads_strict(encoded.decode("utf-8"))
                if canonical_bytes(worker) != encoded:
                    raise ScaleWarehouseReconciliationError("ledger worker provenance is noncanonical")
            event = {
                "action": row["action"],
                "after_committed_shards": row["after_committed_shards"],
                "controller_session_id": row["controller_session_id"],
                "event_sha256": row["event_sha256"],
                "interruption_key": row["interruption_key"],
                "observed_at": row["observed_at"],
                "schema_version": "scale-interruption-event.v1",
                "worker_process": worker,
            }
            if event["event_sha256"] != _digest(
                {key: value for key, value in event.items() if key != "event_sha256"}
            ):
                raise ScaleWarehouseReconciliationError("ledger interruption digest is corrupt")
            interruptions.append(event)
    finally:
        connection.close()
    after_sha256 = _sha256(ledger_path)
    if before_sha256 != after_sha256:
        raise ScaleWarehouseReconciliationError("read-only recovery ledger changed during reconciliation")
    return {
        "chain_tail": previous,
        "commits": commits,
        "interruptions": interruptions,
        "ledger_sha256": before_sha256,
        "session_summary": session_summary,
        "sessions": sessions,
    }


def _attempt_only_cause(
    selection_key: str, failure_code: str, message: str, provenance: dict[str, Any]
) -> str:
    if (
        selection_key == "mysql-regex"
        and failure_code == "forced-worker-process-kill"
        and provenance.get("forced_interruption") == "worker-kill"
    ):
        return "planned-forced-worker-kill"
    if (
        selection_key == "python-re"
        and failure_code == "scale-shard-infrastructure-failure"
        and "wall-time-limit/-15" in message
        and provenance.get("failure_type") == "RuntimeError"
    ):
        return "isolated-cpython-outer-wall-time-limit-exit-minus-15"
    return "other-infrastructure-failure"


def _response_projection(result: dict[str, Any], logical: dict[str, Any]) -> tuple[str, str, str | None]:
    schema_version = result.get("schema_version")
    if schema_version == "adapter-response.v1":
        if (
            result.get("correlation_id") != logical["logical_execution_id"]
            or result.get("profile_id") != logical["profile_id"]
            or result.get("target_release_id") != logical["target_release_id"]
            or result.get("canonical_authority") is not False
            or result.get("semantic_authority") is not False
        ):
            raise ScaleWarehouseReconciliationError("selected adapter response changed logical identity")
        observation = result.get("observation")
        match_state = observation.get("match_state") if isinstance(observation, dict) else None
        return schema_version, str(result.get("status")), match_state
    if schema_version == "scale-target-timeout.v1":
        if (
            result.get("logical_execution_id") != logical["logical_execution_id"]
            or result.get("profile_id") != logical["profile_id"]
            or result.get("target_release_id") != logical["target_release_id"]
            or result.get("outcome") != "target-timeout"
            or result.get("canonical_authority") is not False
            or result.get("semantic_authority") is not False
        ):
            raise ScaleWarehouseReconciliationError("selected timeout changed logical identity")
        return schema_version, "target-timeout", None
    raise ScaleWarehouseReconciliationError("selected result has an unknown schema")


def _source_digests(repository_root: Path) -> dict[str, str]:
    paths = (
        "campaigns/compiled/100k-qualification.v1.json",
        "reports/scale/100k-execution.json",
        "schemas/json/logical-execution-segment.schema.json",
        "schemas/json/scale-evidence-manifest.schema.json",
        "schemas/json/scale-execution-report.schema.json",
        "schemas/json/scale-result-segment.schema.json",
        "schemas/json/scale-warehouse-reconciliation.schema.json",
        "tools/campaigns/reconcile_100k_warehouse.py",
        "warehouse/python/regex_conformance_warehouse/scale_reconciliation.py",
    )
    return {relative: _sha256(repository_root / relative) for relative in paths}


def _create_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = DELETE")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("PRAGMA user_version = 1")
    for statement in SCHEMA:
        connection.execute(statement)
    return connection


def _database_counts(connection: sqlite3.Connection) -> dict[str, int]:
    return {
        "campaigns": connection.execute("SELECT COUNT(*) FROM campaign").fetchone()[0],
        "interruptions": connection.execute("SELECT COUNT(*) FROM interruption").fetchone()[0],
        "logical_executions": connection.execute("SELECT COUNT(*) FROM logical_execution").fetchone()[0],
        "physical_attempts": connection.execute("SELECT COUNT(*) FROM physical_attempt").fetchone()[0],
        "result_segments": connection.execute("SELECT COUNT(*) FROM result_segment").fetchone()[0],
        "selected_observations": connection.execute("SELECT COUNT(*) FROM selected_observation").fetchone()[0],
        "shards": connection.execute("SELECT COUNT(*) FROM shard").fetchone()[0],
    }


def reconcile_scale_warehouse(
    repository_root: Path,
    campaign_root: Path,
    warehouse_root: Path,
    *,
    plan_path: Path | None = None,
    reuse_existing: bool = False,
    enforce_p19_100k: bool = True,
) -> dict[str, Any]:
    """Reconcile immutable P19 scale inputs and build or verify their warehouse."""

    repository = repository_root.resolve(strict=True)
    campaign = _direct_external_directory(repository, campaign_root, "campaign root")
    evidence_root = _direct_external_directory(repository, campaign / "evidence", "evidence root")
    logical_root = _direct_external_directory(repository, campaign / "logical", "logical root")
    warehouse = _warehouse_directory(repository, warehouse_root)

    selected_plan_path = (
        repository / "campaigns" / "compiled" / "100k-qualification.v1.json"
        if plan_path is None
        else plan_path.resolve(strict=True)
    )
    plan = load_strict(selected_plan_path)
    if enforce_p19_100k:
        validate_instance(
            plan,
            load_strict(repository / "schemas" / "json" / "scale-campaign-plan.schema.json"),
            source="P19 100K plan",
        )
        verify_scale_plan(repository, plan)
    report_path = campaign / "reports" / "scale-execution-report.json"
    execution_report, report_bytes = _read_json_file(report_path)
    if enforce_p19_100k:
        validate_instance(
            execution_report,
            load_strict(repository / "schemas" / "json" / "scale-execution-report.schema.json"),
            source="P19 100K execution report",
        )
    manifest_reference = execution_report.get("evidence_manifest_reference")
    if not isinstance(manifest_reference, dict):
        raise ScaleWarehouseReconciliationError("execution report lacks a manifest reference")
    manifest_schema = load_strict(
        repository / "schemas" / "json" / "scale-evidence-manifest.schema.json"
    )
    manifest = _read_reference(
        evidence_root, manifest_reference, "scale-manifests", manifest_schema
    )
    content_ids = _ContentIds(repository)
    manifest_body = {key: value for key, value in manifest.items() if key != "evidence_manifest_id"}
    if manifest["evidence_manifest_id"] != content_ids.build(
        "evidence-manifest", "scale-evidence-manifest-v1", manifest_body
    ):
        raise ScaleWarehouseReconciliationError("evidence manifest content identity differs")
    if (
        execution_report.get("campaign_manifest_id") != plan.get("campaign_manifest_id")
        or manifest.get("campaign_manifest_id") != plan.get("campaign_manifest_id")
        or execution_report.get("evidence_manifest_id") != manifest.get("evidence_manifest_id")
        or any(
            execution_report.get(report_key) != manifest.get(manifest_key)
            for report_key, manifest_key in (
                ("accepted_observation_count", "accepted_observation_count"),
                ("attempt_count", "attempt_count"),
                ("infrastructure_failure_attempt_count", "infrastructure_failure_attempt_count"),
                ("logical_execution_count", "logical_execution_count"),
                ("result_shard_count", "result_shard_count"),
            )
        )
        or execution_report.get("interruption_count") != len(manifest.get("interruptions", []))
    ):
        raise ScaleWarehouseReconciliationError("execution report and evidence manifest differ")

    ledger_path = campaign / "state" / "scale-recovery.sqlite"
    ledger = _ledger_state(ledger_path, plan["campaign_manifest_id"])
    if ledger["session_summary"] != execution_report.get("session_summary"):
        raise ScaleWarehouseReconciliationError("execution report session projection differs")
    if canonical_bytes(ledger["interruptions"]) != canonical_bytes(manifest["interruptions"]):
        raise ScaleWarehouseReconciliationError("manifest interruptions differ from the ledger")
    planned_interruptions = [
        (item["key"], item["action"], item["after_committed_shards"])
        for item in plan["planned_interruptions"]
    ]
    observed_interruptions = [
        (item["interruption_key"], item["action"], item["after_committed_shards"])
        for item in ledger["interruptions"]
    ]
    if planned_interruptions != observed_interruptions:
        raise ScaleWarehouseReconciliationError("planned interruptions do not match")

    references = manifest["segments"]
    if len(references) != len(ledger["commits"]):
        raise ScaleWarehouseReconciliationError("manifest and ledger segment counts differ")
    ledger_by_sha: dict[str, dict[str, Any]] = {}
    for commit in ledger["commits"]:
        reference = commit["reference"]
        digest = reference.get("sha256")
        if not isinstance(digest, str) or digest in ledger_by_sha:
            raise ScaleWarehouseReconciliationError("ledger segment reference is duplicated")
        if (
            commit["shard_id"] != reference.get("shard_id")
            or commit["segment_kind"] != reference.get("segment_kind")
            or commit["attempt_number"] != reference.get("attempt_number")
        ):
            raise ScaleWarehouseReconciliationError("ledger commit coordinates differ")
        ledger_by_sha[digest] = commit
    if {canonical_bytes(item) for item in references} != {
        canonical_bytes(item["reference"]) for item in ledger["commits"]
    }:
        raise ScaleWarehouseReconciliationError("manifest references differ from the ledger")

    sorted_references = sorted(
        references,
        key=lambda item: (item["shard_id"], item["attempt_number"], item["segment_kind"]),
    )
    root_digest = _digest(
        {
            "interruption_digests": [item["event_sha256"] for item in ledger["interruptions"]],
            "segment_digests": [item["sha256"] for item in sorted_references],
        }
    )
    if root_digest != manifest["root_digest"]:
        raise ScaleWarehouseReconciliationError("evidence root digest differs")
    _exact_directory_paths(evidence_root, references, "scale-result-segments")
    _exact_directory_paths(evidence_root, [manifest_reference], "scale-manifests")
    _exact_directory_paths(logical_root, plan["shards"], "logical-execution-segments")

    build_identity = {
        "campaign_manifest_id": plan["campaign_manifest_id"],
        "evidence_manifest_id": manifest["evidence_manifest_id"],
        "evidence_root_digest": root_digest,
        "logical_execution_ids_sha256": plan["logical_execution_index"]["ordered_ids_sha256"],
        "manifest_sha256": manifest_reference["sha256"],
        "recovery_chain_tail": ledger["chain_tail"],
        "schema_sha256": SCHEMA_SHA256,
    }
    warehouse_build_id = content_ids.build(
        "artifact-set-manifest", "scale-warehouse-build-v1", build_identity
    )
    suffix = warehouse_build_id.rsplit(":", 1)[-1]
    destination = warehouse / f"scale-warehouse-{suffix}.sqlite"
    temporary = warehouse / f".{destination.name}.tmp"
    if destination.exists():
        destination_metadata = destination.stat()
        if (
            destination.is_symlink()
            or destination.absolute() != destination.resolve(strict=True)
            or not stat.S_ISREG(destination_metadata.st_mode)
            or destination_metadata.st_nlink != 1
        ):
            raise ScaleWarehouseReconciliationError(
                "existing warehouse must be a direct non-linked file"
            )
    if destination.exists() and not reuse_existing:
        raise ScaleWarehouseReconciliationError("immutable warehouse already exists; use reuse_existing")
    if temporary.exists():
        raise ScaleWarehouseReconciliationError("partial warehouse build already exists")
    creating = not destination.exists()
    connection = _create_database(temporary) if creating else sqlite3.connect(
        destination.as_uri() + "?mode=ro", uri=True
    )
    connection.execute("PRAGMA foreign_keys = ON")
    if not creating:
        connection.execute("PRAGMA query_only = ON")

    logical_schema = load_strict(
        repository / "schemas" / "json" / "logical-execution-segment.schema.json"
    )
    segment_schema = load_strict(
        repository / "schemas" / "json" / "scale-result-segment.schema.json"
    )
    shard_by_id = {item["shard_id"]: item for item in plan["shards"]}
    if len(shard_by_id) != len(plan["shards"]):
        raise ScaleWarehouseReconciliationError("plan contains duplicate shards")
    references_by_shard: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for reference in references:
        if reference["shard_id"] not in shard_by_id:
            raise ScaleWarehouseReconciliationError("manifest references an unknown shard")
        references_by_shard[reference["shard_id"]].append(reference)

    logical_ids: set[str] = set()
    physical_ids: set[str] = set()
    observation_content_ids: set[str] = set()
    observation_ids: set[str] = set()
    completion_ids: set[str] = set()
    attempts_by_logical: dict[str, list[tuple[int, str]]] = defaultdict(list)
    selection_counts: dict[str, Counter[str]] = defaultdict(Counter)
    result_shards: set[str] = set()
    infrastructure_failures = 0
    attempt_only: list[dict[str, Any]] = []
    try:
        if creating:
            connection.execute(
                "INSERT INTO campaign VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    plan["campaign_manifest_id"],
                    manifest["evidence_manifest_id"],
                    root_digest,
                    manifest_reference["sha256"],
                    hashlib.sha256(report_bytes).hexdigest(),
                    ledger["ledger_sha256"],
                    ledger["chain_tail"],
                    manifest["logical_execution_count"],
                    manifest["accepted_observation_count"],
                    manifest["attempt_count"],
                    manifest["infrastructure_failure_attempt_count"],
                ),
            )
        for shard in sorted(plan["shards"], key=lambda item: item["shard_id"]):
            logical_payload = _read_reference(
                logical_root, shard, "logical-execution-segments", logical_schema
            )
            members = logical_payload["logical_executions"]
            member_ids = [item["logical_execution_id"] for item in members]
            if (
                logical_payload["shard_id"] != shard["shard_id"]
                or logical_payload["selection_key"] != shard["selection_key"]
                or len(member_ids) != shard["logical_execution_count"]
                or len(member_ids) != len(set(member_ids))
                or member_ids[0] != shard["first_logical_execution_id"]
                or member_ids[-1] != shard["last_logical_execution_id"]
                or _digest(member_ids) != shard["logical_execution_ids_sha256"]
                or logical_ids.intersection(member_ids)
            ):
                raise ScaleWarehouseReconciliationError("logical segment differs from its plan commitment")
            logical_ids.update(member_ids)
            logical_by_id = {item["logical_execution_id"]: item for item in members}
            selection_counts[shard["selection_key"]]["logical_executions"] += len(members)
            if creating:
                connection.execute(
                    "INSERT INTO shard VALUES (?,?,?,?)",
                    (shard["shard_id"], shard["selection_key"], shard["sha256"], len(members)),
                )
                connection.executemany(
                    "INSERT INTO logical_execution VALUES (?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            item["logical_execution_id"],
                            shard["shard_id"],
                            item["selection_key"],
                            item["base_logical_execution_id"],
                            item["planned_repetition"],
                            item["profile_id"],
                            item["target_release_id"],
                            item["vector_revision_id"],
                            item["request_template_sha256"],
                        )
                        for item in members
                    ],
                )
            result_reference: dict[str, Any] | None = None
            attempt_payloads: list[tuple[dict[str, Any], dict[str, Any]]] = []
            for reference in sorted(
                references_by_shard[shard["shard_id"]],
                key=lambda item: (item["attempt_number"], item["segment_kind"]),
            ):
                payload = _read_reference(
                    evidence_root, reference, "scale-result-segments", segment_schema
                )
                body = {key: value for key, value in payload.items() if key != "result_segment_id"}
                expected_segment_id = content_ids.build(
                    "result-segment", "scale-result-segment-v1", body
                )
                if (
                    payload["result_segment_id"] != expected_segment_id
                    or reference["result_segment_id"] != expected_segment_id
                    or payload["campaign_manifest_id"] != plan["campaign_manifest_id"]
                    or payload["shard_id"] != shard["shard_id"]
                    or payload["selection_key"] != shard["selection_key"]
                    or payload["logical_execution_ids"] != member_ids
                    or payload["attempt_number"] != reference["attempt_number"]
                    or payload["segment_kind"] != reference["segment_kind"]
                    or len(payload["physical_attempts"]) != reference["attempt_count"]
                    or len(payload["observations"]) != reference["observation_count"]
                ):
                    raise ScaleWarehouseReconciliationError("result segment coordinates or identity differ")
                commit = ledger_by_sha[reference["sha256"]]
                if creating:
                    connection.execute(
                        "INSERT INTO result_segment VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (
                            reference["sha256"],
                            expected_segment_id,
                            shard["shard_id"],
                            reference["segment_kind"],
                            reference["attempt_number"],
                            reference["logical_execution_count"],
                            reference["observation_count"],
                            reference["attempt_count"],
                            commit["ordinal"],
                            commit["commit_sha256"],
                        ),
                    )
                attempt_map = {
                    item["logical_execution_id"]: item for item in payload["physical_attempts"]
                }
                if len(attempt_map) != len(payload["physical_attempts"]) or set(attempt_map) != set(member_ids):
                    raise ScaleWarehouseReconciliationError("segment physical attempts differ from its shard")
                for logical_id in member_ids:
                    attempt = attempt_map[logical_id]
                    physical_id = attempt["physical_run_id"]
                    if physical_id in physical_ids or attempt["attempt_number"] != reference["attempt_number"]:
                        raise ScaleWarehouseReconciliationError("physical attempt identity or ordinal is duplicated")
                    physical_ids.add(physical_id)
                    attempts_by_logical[logical_id].append(
                        (attempt["attempt_number"], attempt["outcome"])
                    )
                    failure = attempt["infrastructure_failure"]
                    failure_code = None if failure is None else failure["code"]
                    if attempt["outcome"] == "infrastructure-failure":
                        infrastructure_failures += 1
                        selection_counts[shard["selection_key"]]["infrastructure_failures"] += 1
                    selection_counts[shard["selection_key"]]["physical_attempts"] += 1
                    if creating:
                        connection.execute(
                            "INSERT INTO physical_attempt VALUES (?,?,?,?,?,?,?,?)",
                            (
                                physical_id,
                                logical_id,
                                reference["sha256"],
                                attempt["attempt_number"],
                                attempt["outcome"],
                                failure_code,
                                attempt["started_at"],
                                attempt["ended_at"],
                            ),
                        )
                observation_map = {
                    item["logical_execution_id"]: item for item in payload["observations"]
                }
                if len(observation_map) != len(payload["observations"]):
                    raise ScaleWarehouseReconciliationError("segment duplicates logical observation credit")
                if reference["segment_kind"] == "result":
                    if result_reference is not None or set(observation_map) != set(member_ids):
                        raise ScaleWarehouseReconciliationError("result shard is duplicated or incomplete")
                    if any(
                        item["outcome"] != "target-observation" or item["infrastructure_failure"] is not None
                        for item in payload["physical_attempts"]
                    ):
                        raise ScaleWarehouseReconciliationError("result segment contains infrastructure failure")
                    result_reference = reference
                    result_shards.add(shard["shard_id"])
                elif observation_map or any(
                    item["outcome"] != "infrastructure-failure" or item["infrastructure_failure"] is None
                    for item in payload["physical_attempts"]
                ):
                    raise ScaleWarehouseReconciliationError("attempt-only segment received logical credit")
                for logical_id, observation in observation_map.items():
                    if (
                        logical_id in completion_ids
                        or observation["campaign_manifest_id"] != plan["campaign_manifest_id"]
                        or observation["physical_run_id"] != attempt_map[logical_id]["physical_run_id"]
                    ):
                        raise ScaleWarehouseReconciliationError("selected observation duplicates or changes identity")
                    observation_body = {
                        key: value for key, value in observation.items() if key != "observation_content_id"
                    }
                    expected_observation_id = content_ids.build(
                        "observation-content", "scale-observation-content-v1", observation_body
                    )
                    if observation["observation_content_id"] != expected_observation_id:
                        raise ScaleWarehouseReconciliationError("selected observation content ID differs")
                    if (
                        expected_observation_id in observation_content_ids
                        or observation["observation_id"] in observation_ids
                    ):
                        raise ScaleWarehouseReconciliationError("selected observation identity is duplicated")
                    schema_version, response_status, match_state = _response_projection(
                        observation["result"], logical_by_id[logical_id]
                    )
                    observation_content_ids.add(expected_observation_id)
                    observation_ids.add(observation["observation_id"])
                    completion_ids.add(logical_id)
                    selection_counts[shard["selection_key"]]["selected_observations"] += 1
                    if creating:
                        connection.execute(
                            "INSERT INTO selected_observation VALUES (?,?,?,?,?,?,?,?)",
                            (
                                expected_observation_id,
                                observation["observation_id"],
                                logical_id,
                                observation["physical_run_id"],
                                reference["sha256"],
                                schema_version,
                                response_status,
                                match_state,
                            ),
                        )
                if reference["segment_kind"] == "attempt":
                    attempt_payloads.append((reference, payload))
            if result_reference is None:
                raise ScaleWarehouseReconciliationError("shard has no selected result segment")
            for reference, payload in attempt_payloads:
                failures = payload["physical_attempts"]
                codes = {item["infrastructure_failure"]["code"] for item in failures}
                messages = {item["infrastructure_failure"]["message"] for item in failures}
                if len(codes) != 1 or len(messages) != 1:
                    raise ScaleWarehouseReconciliationError("attempt-only cause is not uniform")
                failure_code = next(iter(codes))
                message = next(iter(messages))
                attempt_only.append(
                    {
                        "attempt_count": len(failures),
                        "attempt_number": reference["attempt_number"],
                        "cause": _attempt_only_cause(
                            shard["selection_key"], failure_code, message, payload["provenance"]
                        ),
                        "failure_code": failure_code,
                        "failure_message_sha256": hashlib.sha256(message.encode("utf-8")).hexdigest(),
                        "ledger_commit_ordinal": ledger_by_sha[reference["sha256"]]["ordinal"],
                        "logical_execution_count": len(member_ids),
                        "observation_count": 0,
                        "recovery_attempt_number": result_reference["attempt_number"],
                        "recovery_observation_count": result_reference["observation_count"],
                        "recovery_segment_sha256": result_reference["sha256"],
                        "result_segment_id": reference["result_segment_id"],
                        "segment_sha256": reference["sha256"],
                        "selection_key": shard["selection_key"],
                        "shard_id": shard["shard_id"],
                    }
                )

        # The frozen index orders by selection key then logical ID, not by the
        # content-addressed shard schedule.
        ordered_plan_ids = [
            row[0]
            for row in connection.execute(
                "SELECT logical_execution_id FROM logical_execution ORDER BY selection_key,logical_execution_id"
            )
        ]
        if _digest(ordered_plan_ids) != plan["logical_execution_index"]["ordered_ids_sha256"]:
            raise ScaleWarehouseReconciliationError("global logical execution commitment differs")
        for logical_id, attempts in attempts_by_logical.items():
            ordered = sorted(attempts)
            if (
                [item[0] for item in ordered] != list(range(1, len(ordered) + 1))
                or ordered[-1][1] != "target-observation"
                or any(outcome != "infrastructure-failure" for _, outcome in ordered[:-1])
            ):
                raise ScaleWarehouseReconciliationError("retry ordinals or selection history differ")
        if (
            logical_ids != completion_ids
            or set(attempts_by_logical) != logical_ids
            or result_shards != set(shard_by_id)
            or len(logical_ids) != manifest["logical_execution_count"]
            or len(observation_content_ids) != manifest["accepted_observation_count"]
            or len(physical_ids) != manifest["attempt_count"]
            or infrastructure_failures != manifest["infrastructure_failure_attempt_count"]
        ):
            raise ScaleWarehouseReconciliationError("scale denominator or retry accounting differs")

        if creating:
            for event in ledger["interruptions"]:
                worker = event["worker_process"]
                connection.execute(
                    "INSERT INTO interruption VALUES (?,?,?,?,?,?,?)",
                    (
                        event["interruption_key"],
                        event["action"],
                        event["after_committed_shards"],
                        event["controller_session_id"],
                        event["event_sha256"],
                        event["observed_at"],
                        None if worker is None else worker["selection_key"],
                    ),
                )
            connection.commit()
        counts = _database_counts(connection)
        expected_counts = {
            "campaigns": 1,
            "interruptions": len(ledger["interruptions"]),
            "logical_executions": len(logical_ids),
            "physical_attempts": len(physical_ids),
            "result_segments": len(references),
            "selected_observations": len(observation_content_ids),
            "shards": len(plan["shards"]),
        }
        if counts != expected_counts:
            raise ScaleWarehouseReconciliationError("warehouse row counts differ")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ScaleWarehouseReconciliationError("warehouse foreign keys differ")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ScaleWarehouseReconciliationError("warehouse integrity check failed")
        database_commitments = {
            "logical_execution_ids_sha256": _commitment(
                row[0] for row in connection.execute("SELECT logical_execution_id FROM logical_execution")
            ),
            "observation_content_ids_sha256": _commitment(
                row[0] for row in connection.execute("SELECT observation_content_id FROM selected_observation")
            ),
            "physical_run_ids_sha256": _commitment(
                row[0] for row in connection.execute("SELECT physical_run_id FROM physical_attempt")
            ),
            "result_segment_sha256s_sha256": _commitment(
                row[0] for row in connection.execute("SELECT segment_sha256 FROM result_segment")
            ),
        }
        source_commitments = {
            "logical_execution_ids_sha256": _commitment(logical_ids),
            "observation_content_ids_sha256": _commitment(observation_content_ids),
            "physical_run_ids_sha256": _commitment(physical_ids),
            "result_segment_sha256s_sha256": _commitment(item["sha256"] for item in references),
        }
        if database_commitments != source_commitments:
            raise ScaleWarehouseReconciliationError("warehouse row commitments differ from evidence")
    except Exception:
        connection.close()
        if creating:
            temporary.unlink(missing_ok=True)
        raise
    connection.close()
    if creating:
        os.replace(temporary, destination)
    warehouse_sha256 = _sha256(destination)
    verify_connection = sqlite3.connect(destination.as_uri() + "?mode=ro", uri=True)
    try:
        verify_connection.execute("PRAGMA query_only = ON")
        if _database_counts(verify_connection) != expected_counts:
            raise ScaleWarehouseReconciliationError("promoted warehouse read-back differs")
        if verify_connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ScaleWarehouseReconciliationError("promoted warehouse read-back failed")
    finally:
        verify_connection.close()

    selection_summary = [
        {
            "infrastructure_failures": value["infrastructure_failures"],
            "logical_executions": value["logical_executions"],
            "physical_attempts": value["physical_attempts"],
            "selected_observations": value["selected_observations"],
            "selection_key": key,
        }
        for key, value in sorted(selection_counts.items())
    ]
    attempt_only.sort(key=lambda item: item["ledger_commit_ordinal"])
    latest_session = ledger["sessions"][-1]
    if latest_session["outcome"] != "completed":
        raise ScaleWarehouseReconciliationError("latest controller session is not completed")
    if enforce_p19_100k:
        if (
            expected_counts
            != {
                "campaigns": 1,
                "interruptions": 3,
                "logical_executions": 100_000,
                "physical_attempts": 100_500,
                "result_segments": 404,
                "selected_observations": 100_000,
                "shards": 402,
            }
            or execution_report.get("trust_class") != "trusted_executioner"
            or execution_report.get("reconciliation") != "exact"
            or len(attempt_only) != 2
            or {item["cause"] for item in attempt_only}
            != {
                "planned-forced-worker-kill",
                "isolated-cpython-outer-wall-time-limit-exit-minus-15",
            }
            or sum(item["attempt_count"] for item in attempt_only) != 500
        ):
            raise ScaleWarehouseReconciliationError("P19 100K terminal accounting differs")
    reconciliation_identity = {
        "commitments": source_commitments,
        "counts": expected_counts,
        "evidence_manifest_id": manifest["evidence_manifest_id"],
        "recovery_chain_tail": ledger["chain_tail"],
        "warehouse_build_id": warehouse_build_id,
        "warehouse_sha256": warehouse_sha256,
    }
    result = {
        "campaign": {
            "campaign_manifest_id": plan["campaign_manifest_id"],
            "logical_plan_sha256": _sha256(selected_plan_path),
        },
        "classification": {
            "canonical_authority": False,
            "docker_used": False,
            "external_source_evidence_mutated": False,
            "normative_authority": False,
            "operational_reconciliation_only": True,
            "semantic_authority": False,
            "target_execution_performed": False,
        },
        "evidence": {
            "evidence_manifest_id": manifest["evidence_manifest_id"],
            "evidence_manifest_sha256": manifest_reference["sha256"],
            "evidence_manifest_size_bytes": manifest_reference["size_bytes"],
            "evidence_root_digest": root_digest,
            "execution_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        },
        "reconciliation": {
            "attempt_only_segments": attempt_only,
            "commitments": source_commitments,
            "counts": expected_counts,
            "invariants": {
                "all_planned_interruptions_match": True,
                "evidence_and_report_identities_match": True,
                "evidence_objects_are_exactly_manifested": True,
                "infrastructure_failures_are_non_crediting": True,
                "logical_denominator_is_exact": True,
                "no_duplicate_logical_completion": True,
                "observation_content_identities_match": True,
                "recovery_ledger_hash_chain_matches": True,
                "retry_ordinals_are_contiguous": True,
                "warehouse_rows_match_immutable_evidence": True,
            },
            "reconciliation_digest": _digest(reconciliation_identity),
            "selection_summary": selection_summary,
        },
        "recovery": {
            "commit_count": len(ledger["commits"]),
            "completed_session": {
                "ended_at": latest_session["ended_at"],
                "session_id": latest_session["session_id"],
                "started_at": latest_session["started_at"],
            },
            "hash_chain_tail": ledger["chain_tail"],
            "ledger_sha256": ledger["ledger_sha256"],
            "session_summary": ledger["session_summary"],
        },
        "schema_version": "scale-warehouse-reconciliation.v1",
        "source_digests": _source_digests(repository),
        "warehouse": {
            "counts": expected_counts,
            "row_commitments": database_commitments,
            "schema_sha256": SCHEMA_SHA256,
            "warehouse_build_id": warehouse_build_id,
            "warehouse_filename": destination.name,
            "warehouse_sha256": warehouse_sha256,
        },
    }
    validate_instance(
        result,
        load_strict(
            repository / "schemas" / "json" / "scale-warehouse-reconciliation.schema.json"
        ),
        source="P19-T04 scale warehouse reconciliation",
    )
    return result
