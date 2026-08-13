"""Build and reconcile the first derived SQLite warehouse from one evidence manifest."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
from typing import Any

from regex_conformance_campaign.compiler import _content_id
from regex_conformance_schema.jsonio import canonical_bytes


class WarehouseIntegrityError(RuntimeError):
    pass


SCHEMA = (
    "CREATE TABLE campaign (campaign_manifest_id TEXT PRIMARY KEY, evidence_manifest_id TEXT NOT NULL, logical_count INTEGER NOT NULL)",
    "CREATE TABLE logical_execution (logical_execution_id TEXT PRIMARY KEY, selection_key TEXT NOT NULL, vector_revision_id TEXT NOT NULL)",
    "CREATE TABLE observation (observation_content_id TEXT PRIMARY KEY, observation_id TEXT NOT NULL UNIQUE, logical_execution_id TEXT NOT NULL UNIQUE REFERENCES logical_execution(logical_execution_id), physical_run_id TEXT NOT NULL UNIQUE, response_status TEXT NOT NULL, match_state TEXT)",
    "CREATE TABLE result_shard (result_shard_id TEXT PRIMARY KEY, shard_id TEXT NOT NULL UNIQUE, artifact_sha256 TEXT NOT NULL)",
)
SCHEMA_SHA256 = hashlib.sha256("\n".join(SCHEMA).encode()).hexdigest()


def _database_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_warehouse(
    repository_root: Path,
    warehouse_root: Path,
    compiled: dict[str, Any],
    evidence_manifest: dict[str, Any],
    evidence_store: Any,
) -> dict[str, Any]:
    assessment = evidence_store.qualify_manifest(compiled, evidence_manifest)
    if not assessment["analytical_admissible"]:
        finding_codes = ",".join(item["code"] for item in assessment["findings"])
        suffix = f": {finding_codes}" if finding_codes else ""
        raise WarehouseIntegrityError(
            f"evidence disposition {assessment['disposition']} is excluded from the trusted analytical dataset{suffix}"
        )
    if not evidence_manifest.get("complete"):
        raise WarehouseIntegrityError("incomplete evidence cannot produce a qualifying warehouse")
    logicals = compiled["logical_executions"]
    observations = evidence_manifest["observations"]
    if len(logicals) != len(observations):
        raise WarehouseIntegrityError("evidence denominator differs from campaign denominator")
    row_digest = hashlib.sha256(
        canonical_bytes(
            {
                "logical_execution_ids": [item["logical_execution_id"] for item in logicals],
                "observation_content_ids": [item["observation_content_id"] for item in observations],
                "result_shard_ids": [item["result_shard_id"] for item in evidence_manifest["result_shards"]],
            }
        )
    ).hexdigest()
    build_identity = {
        "campaign_manifest_id": compiled["campaign_manifest_id"],
        "evidence_manifest_id": evidence_manifest["evidence_manifest_id"],
        "row_digest": row_digest,
        "schema_sha256": SCHEMA_SHA256,
    }
    warehouse_build_id = _content_id(
        repository_root, "artifact-set-manifest", "warehouse-build-v1", build_identity
    )
    destination_root = warehouse_root.expanduser().resolve(strict=False)
    try:
        destination_root.relative_to(repository_root.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise WarehouseIntegrityError("derived warehouse must remain outside the Git repository")
    destination_root.mkdir(parents=True, exist_ok=True)
    digest_suffix = warehouse_build_id.rsplit(":", 1)[-1]
    destination = destination_root / f"warehouse-{digest_suffix}.sqlite"
    if destination.exists():
        raise WarehouseIntegrityError("warehouse build target already exists; derived builds are immutable")
    temporary = destination_root / f".{destination.name}.tmp"
    if temporary.exists():
        raise WarehouseIntegrityError("partial warehouse build already exists and will not be overwritten")
    connection = sqlite3.connect(temporary)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        for statement in SCHEMA:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO campaign VALUES (?, ?, ?)",
            (compiled["campaign_manifest_id"], evidence_manifest["evidence_manifest_id"], len(logicals)),
        )
        for logical in sorted(logicals, key=lambda item: item["logical_execution_id"]):
            connection.execute(
                "INSERT INTO logical_execution VALUES (?, ?, ?)",
                (logical["logical_execution_id"], logical["selection_key"], logical["vector_revision_id"]),
            )
        for reference in sorted(observations, key=lambda item: item["logical_execution_id"]):
            payload = evidence_store.read_artifact(reference)
            response = payload["response"]
            connection.execute(
                "INSERT INTO observation VALUES (?, ?, ?, ?, ?, ?)",
                (
                    reference["observation_content_id"],
                    reference["observation_id"],
                    reference["logical_execution_id"],
                    payload["physical_run_id"],
                    response["status"],
                    (
                        None
                        if response["observation"] is None
                        else response["observation"]["match_state"]
                    ),
                ),
            )
        for reference in sorted(evidence_manifest["result_shards"], key=lambda item: item["shard_id"]):
            connection.execute(
                "INSERT INTO result_shard VALUES (?, ?, ?)",
                (reference["result_shard_id"], reference["shard_id"], reference["sha256"]),
            )
        connection.commit()
        observed = {
            "campaigns": connection.execute("SELECT COUNT(*) FROM campaign").fetchone()[0],
            "logical_executions": connection.execute("SELECT COUNT(*) FROM logical_execution").fetchone()[0],
            "observations": connection.execute("SELECT COUNT(*) FROM observation").fetchone()[0],
            "result_shards": connection.execute("SELECT COUNT(*) FROM result_shard").fetchone()[0],
        }
        if observed != {
            "campaigns": 1,
            "logical_executions": len(logicals),
            "observations": len(logicals),
            "result_shards": len(evidence_manifest["result_shards"]),
        }:
            raise WarehouseIntegrityError("warehouse row reconciliation failed")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise WarehouseIntegrityError("warehouse referential integrity failed")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise WarehouseIntegrityError("SQLite integrity check failed")
    finally:
        connection.close()
    os.replace(temporary, destination)
    return {
        "schema_version": "warehouse-build.v1",
        "warehouse_build_id": warehouse_build_id,
        "warehouse_sha256": _database_sha256(destination),
        "warehouse_filename": destination.name,
        "schema_sha256": SCHEMA_SHA256,
        "row_digest": row_digest,
        "counts": observed,
    }
