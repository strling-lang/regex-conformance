"""Append-only evidence objects with exact campaign-manifest reconciliation."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from regex_conformance_campaign.compiler import _content_id
from regex_conformance_schema.identity import NamespaceRegistry, generate_assigned_id
from regex_conformance_schema.jsonio import canonical_bytes


class EvidenceIntegrityError(RuntimeError):
    """Evidence conflicts with immutable content or the planned denominator."""


class ImmutableEvidenceStore:
    def __init__(self, repository_root: Path, evidence_root: Path) -> None:
        self.repository_root = repository_root.resolve(strict=True)
        self.evidence_root = evidence_root.expanduser().resolve(strict=False)
        try:
            self.evidence_root.relative_to(self.repository_root)
        except ValueError:
            pass
        else:
            raise EvidenceIntegrityError("raw evidence must remain outside the Git repository")
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        self.registry = NamespaceRegistry.load(
            self.repository_root / "registries" / "identity" / "namespaces.v1.json"
        )

    def _write(self, category: str, payload: dict[str, Any]) -> dict[str, Any]:
        encoded = canonical_bytes(payload) + b"\n"
        digest = hashlib.sha256(encoded).hexdigest()
        directory = self.evidence_root / category / "sha256"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{digest}.json"
        if path.exists():
            if path.read_bytes() != encoded:
                raise EvidenceIntegrityError("content-addressed evidence path contains conflicting bytes")
        else:
            temporary = directory / f".{digest}.tmp"
            with temporary.open("xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        if path.read_bytes() != encoded:
            raise EvidenceIntegrityError("evidence failed read-after-write verification")
        return {
            "category": category,
            "relative_path": path.relative_to(self.evidence_root).as_posix(),
            "sha256": digest,
            "size_bytes": len(encoded),
        }

    def read_artifact(self, reference: dict[str, Any]) -> dict[str, Any]:
        path = (self.evidence_root / reference["relative_path"]).resolve(strict=True)
        path.relative_to(self.evidence_root)
        encoded = path.read_bytes()
        if hashlib.sha256(encoded).hexdigest() != reference["sha256"]:
            raise EvidenceIntegrityError("evidence artifact digest mismatch")
        from regex_conformance_schema.jsonio import loads_strict

        return loads_strict(encoded.decode("utf-8"))

    def verify_manifest(
        self,
        compiled: dict[str, Any],
        evidence_manifest: dict[str, Any],
    ) -> None:
        reference = evidence_manifest.get("manifest_reference")
        if not isinstance(reference, dict):
            raise EvidenceIntegrityError("evidence manifest reference is missing")
        stored_manifest = self.read_artifact(reference)
        supplied_manifest = {
            key: value for key, value in evidence_manifest.items() if key != "manifest_reference"
        }
        if canonical_bytes(stored_manifest) != canonical_bytes(supplied_manifest):
            raise EvidenceIntegrityError("stored and supplied evidence manifests differ")
        if stored_manifest.get("schema_version") != "evidence-manifest.v2":
            raise EvidenceIntegrityError("unsupported evidence manifest schema")
        manifest_body = {
            key: value
            for key, value in stored_manifest.items()
            if key not in {"schema_version", "evidence_manifest_id"}
        }
        expected_manifest_id = _content_id(
            self.repository_root, "evidence-manifest", "evidence-manifest-v2", manifest_body
        )
        if stored_manifest.get("evidence_manifest_id") != expected_manifest_id:
            raise EvidenceIntegrityError("evidence manifest content identity does not match")
        if stored_manifest.get("campaign_manifest_id") != compiled["campaign_manifest_id"]:
            raise EvidenceIntegrityError("evidence manifest references the wrong campaign")

        planned = {item["logical_execution_id"] for item in compiled["logical_executions"]}
        attempt_logicals: set[str] = set()
        physical_logicals: dict[str, str] = {}
        physical_runs: set[str] = set()
        observation_logicals: set[str] = set()
        observation_logical_by_content: dict[str, str] = {}
        observation_contents: set[str] = set()
        artifact_digests: list[str] = []
        for attempt_reference in stored_manifest["attempts"]:
            attempt = self.read_artifact(attempt_reference)
            if (
                attempt.get("logical_execution_id") != attempt_reference.get("logical_execution_id")
                or attempt.get("physical_run_id") != attempt_reference.get("physical_run_id")
                or attempt["logical_execution_id"] not in planned
                or attempt["physical_run_id"] in physical_runs
            ):
                raise EvidenceIntegrityError("attempt reference or identity reconciliation failed")
            attempt_logicals.add(attempt["logical_execution_id"])
            physical_runs.add(attempt["physical_run_id"])
            physical_logicals[attempt["physical_run_id"]] = attempt["logical_execution_id"]
            artifact_digests.append(attempt_reference["sha256"])
        if attempt_logicals != planned:
            raise EvidenceIntegrityError("attempts do not cover the planned logical denominator")

        for observation_reference in stored_manifest["observations"]:
            observation = self.read_artifact(observation_reference)
            logical_id = observation_reference.get("logical_execution_id")
            content_id = observation_reference.get("observation_content_id")
            if (
                observation.get("logical_execution_id") != logical_id
                or observation.get("observation_content_id") != content_id
                or observation.get("observation_id") != observation_reference.get("observation_id")
                or logical_id in observation_logicals
                or content_id in observation_contents
                or observation.get("physical_run_id") not in physical_runs
            ):
                raise EvidenceIntegrityError("observation reference or identity reconciliation failed")
            body = {key: value for key, value in observation.items() if key != "observation_content_id"}
            if content_id != _content_id(
                self.repository_root, "observation-content", "observation-content-v1", body
            ):
                raise EvidenceIntegrityError("observation content identity does not match")
            observation_logicals.add(logical_id)
            observation_contents.add(content_id)
            observation_logical_by_content[content_id] = logical_id
            artifact_digests.append(observation_reference["sha256"])

        planned_by_shard = {
            item["shard_id"]: set(item["logical_execution_ids"]) for item in compiled["shards"]
        }
        shard_ids = set(planned_by_shard)
        observed_shards: set[str] = set()
        sharded_observations: set[str] = set()
        for shard_reference in stored_manifest["result_shards"]:
            shard = self.read_artifact(shard_reference)
            if (
                shard.get("shard_id") != shard_reference.get("shard_id")
                or shard.get("result_shard_id") != shard_reference.get("result_shard_id")
                or shard["shard_id"] not in shard_ids
                or shard["shard_id"] in observed_shards
            ):
                raise EvidenceIntegrityError("result shard reference or completeness failed")
            body = {
                key: value for key, value in shard.items() if key not in {"schema_version", "result_shard_id"}
            }
            if shard["result_shard_id"] != _content_id(
                self.repository_root, "result-shard", "result-shard-v1", body
            ):
                raise EvidenceIntegrityError("result shard content identity does not match")
            try:
                shard_observation_logicals = {
                    observation_logical_by_content[item] for item in shard["observation_content_ids"]
                }
                shard_physical_logicals = {
                    physical_logicals[item] for item in shard["physical_run_ids"]
                }
            except KeyError as error:
                raise EvidenceIntegrityError("result shard references an unknown artifact identity") from error
            planned_logicals = planned_by_shard[shard["shard_id"]]
            if (
                set(shard["planned_logical_execution_ids"]) != planned_logicals
                or shard_physical_logicals != planned_logicals
                or not shard_observation_logicals.issubset(planned_logicals)
                or shard.get("complete") != (shard_observation_logicals == planned_logicals)
            ):
                raise EvidenceIntegrityError("result shard membership does not reconcile its plan")
            observed_shards.add(shard["shard_id"])
            sharded_observations.update(shard["observation_content_ids"])
            artifact_digests.append(shard_reference["sha256"])
        if observed_shards != shard_ids or sharded_observations != observation_contents:
            raise EvidenceIntegrityError("result shards do not reconcile the observation set")
        if hashlib.sha256(canonical_bytes(sorted(artifact_digests))).hexdigest() != stored_manifest["root_digest"]:
            raise EvidenceIntegrityError("evidence root digest does not match its artifacts")
        if (
            stored_manifest["logical_execution_count"] != len(planned)
            or stored_manifest["accepted_observation_count"] != len(observation_contents)
            or stored_manifest["infrastructure_failure_count"] != len(planned - observation_logicals)
            or stored_manifest["complete"] != (observation_logicals == planned)
        ):
            raise EvidenceIntegrityError("evidence manifest counts or completion state do not reconcile")

    def publish(
        self,
        compiled: dict[str, Any],
        attempts_by_shard: list[tuple[dict[str, Any], list[dict[str, Any]]]],
    ) -> dict[str, Any]:
        planned = {item["logical_execution_id"] for item in compiled["logical_executions"]}
        seen: set[str] = set()
        attempt_references: list[dict[str, Any]] = []
        observation_references: list[dict[str, Any]] = []
        result_shard_references: list[dict[str, Any]] = []
        infrastructure_failures = 0
        for shard, attempts in attempts_by_shard:
            shard_observations: list[str] = []
            shard_attempts: list[str] = []
            for attempt in attempts:
                logical_id = attempt["logical_execution_id"]
                if logical_id not in planned or logical_id in seen:
                    raise EvidenceIntegrityError("physical attempt is unplanned or duplicates completion")
                seen.add(logical_id)
                attempt_payload = {
                    "schema_version": "physical-attempt-evidence.v1",
                    "attempt_number": attempt["attempt_number"],
                    "campaign_manifest_id": compiled["campaign_manifest_id"],
                    "infrastructure_failure": attempt.get("infrastructure_failure"),
                    "logical_execution_id": logical_id,
                    "observed_at": attempt["observed_at"],
                    "physical_run_id": attempt["physical_run_id"],
                    "provenance": attempt.get("provenance", {}),
                    "response": attempt.get("response"),
                }
                attempt_reference = self._write("attempts", attempt_payload)
                attempt_reference["physical_run_id"] = attempt["physical_run_id"]
                attempt_reference["logical_execution_id"] = logical_id
                attempt_references.append(attempt_reference)
                shard_attempts.append(attempt["physical_run_id"])
                if attempt.get("infrastructure_failure") is not None:
                    infrastructure_failures += 1
                    continue
                response = attempt["response"]
                if (
                    response.get("correlation_id") != logical_id
                    or response.get("status") != "completed"
                    or not isinstance(response.get("observation"), dict)
                    or response["observation"].get("match_state") != "match"
                    or response.get("canonical_authority")
                    or response.get("semantic_authority")
                ):
                    raise EvidenceIntegrityError("target response is not an accepted probe observation")
                observation_id = generate_assigned_id(self.registry, "rcid", "observation")
                observation_body = {
                    "schema_version": "observation-content.v1",
                    "campaign_manifest_id": compiled["campaign_manifest_id"],
                    "logical_execution_id": logical_id,
                    "observation_id": observation_id,
                    "physical_run_id": attempt["physical_run_id"],
                    "provenance": attempt.get("provenance", {}),
                    "response": response,
                }
                observation_content_id = _content_id(
                    self.repository_root, "observation-content", "observation-content-v1", observation_body
                )
                observation_payload = {
                    **observation_body,
                    "observation_content_id": observation_content_id,
                }
                observation_reference = self._write("observations", observation_payload)
                observation_reference["logical_execution_id"] = logical_id
                observation_reference["observation_content_id"] = observation_content_id
                observation_reference["observation_id"] = observation_id
                observation_references.append(observation_reference)
                shard_observations.append(observation_content_id)
            result_shard_body = {
                "campaign_manifest_id": compiled["campaign_manifest_id"],
                "complete": len(shard_observations) == len(shard["logical_execution_ids"]),
                "observation_content_ids": sorted(shard_observations),
                "physical_run_ids": sorted(shard_attempts),
                "planned_logical_execution_ids": shard["logical_execution_ids"],
                "shard_id": shard["shard_id"],
            }
            result_shard_id = _content_id(
                self.repository_root, "result-shard", "result-shard-v1", result_shard_body
            )
            result_reference = self._write(
                "result-shards",
                {"schema_version": "result-shard.v1", "result_shard_id": result_shard_id, **result_shard_body},
            )
            result_reference["result_shard_id"] = result_shard_id
            result_reference["shard_id"] = shard["shard_id"]
            result_shard_references.append(result_reference)
        if seen != planned:
            raise EvidenceIntegrityError("physical attempts do not cover the planned logical denominator")
        accepted = len(observation_references)
        complete = infrastructure_failures == 0 and accepted == len(planned)
        artifact_digests = sorted(
            item["sha256"]
            for item in [*attempt_references, *observation_references, *result_shard_references]
        )
        root_digest = hashlib.sha256(canonical_bytes(artifact_digests)).hexdigest()
        manifest_body = {
            "accepted_observation_count": accepted,
            "attempts": sorted(attempt_references, key=lambda item: item["logical_execution_id"]),
            "campaign_manifest_id": compiled["campaign_manifest_id"],
            "complete": complete,
            "infrastructure_failure_count": infrastructure_failures,
            "logical_execution_count": len(planned),
            "observations": sorted(observation_references, key=lambda item: item["logical_execution_id"]),
            "result_shards": sorted(result_shard_references, key=lambda item: item["shard_id"]),
            "root_digest": root_digest,
        }
        evidence_manifest_id = _content_id(
            self.repository_root, "evidence-manifest", "evidence-manifest-v2", manifest_body
        )
        payload = {
            "schema_version": "evidence-manifest.v2",
            "evidence_manifest_id": evidence_manifest_id,
            **manifest_body,
        }
        reference = self._write("manifests", payload)
        result = {**payload, "manifest_reference": reference}
        self.verify_manifest(compiled, result)
        return result
