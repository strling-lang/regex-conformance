"""Append-only evidence objects with exact campaign-manifest reconciliation."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from typing import Any

from regex_conformance_campaign.compiler import _content_id
from regex_conformance_schema.identity import NamespaceRegistry, generate_assigned_id
from regex_conformance_schema.jsonio import canonical_bytes

from .diagnostics import EvidenceIntegrityError


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

    def _direct_directory(self, path: Path, category: str) -> None:
        try:
            path.mkdir()
        except FileExistsError:
            pass
        try:
            resolved_directory = path.resolve(strict=True)
            resolved_directory.relative_to(self.evidence_root)
        except (OSError, ValueError) as error:
            raise EvidenceIntegrityError(
                "artifact-directory-invalid",
                "evidence category directory is not contained in the evidence root",
                artifact_category=category,
            ) from error
        if path.absolute() != resolved_directory or not resolved_directory.is_dir():
            raise EvidenceIntegrityError(
                "artifact-directory-indirect",
                "evidence category directories must be direct directories, not links",
                artifact_category=category,
            )

    def _write(self, category: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not category or any(not (part.isalpha() and part.islower()) for part in category.split("-")):
            raise EvidenceIntegrityError("artifact-category-invalid", "evidence category is invalid")
        encoded = canonical_bytes(payload) + b"\n"
        digest = hashlib.sha256(encoded).hexdigest()
        category_directory = self.evidence_root / category
        self._direct_directory(category_directory, category)
        directory = category_directory / "sha256"
        self._direct_directory(directory, category)
        path = directory / f"{digest}.json"
        if path.exists():
            if path.absolute() != path.resolve(strict=True) or not stat.S_ISREG(path.stat().st_mode):
                raise EvidenceIntegrityError(
                    "artifact-path-indirect",
                    "existing content-addressed evidence must be a direct regular file",
                    artifact_category=category,
                    artifact_sha256=digest,
                )
            if path.read_bytes() != encoded:
                raise EvidenceIntegrityError("content-addressed evidence path contains conflicting bytes")
        else:
            temporary = directory / f".{digest}.tmp"
            with temporary.open("xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            if os.name != "nt":
                directory_descriptor = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
        if path.read_bytes() != encoded:
            raise EvidenceIntegrityError("evidence failed read-after-write verification")
        return {
            "category": category,
            "relative_path": path.relative_to(self.evidence_root).as_posix(),
            "sha256": digest,
            "size_bytes": len(encoded),
        }

    def read_artifact(self, reference: dict[str, Any]) -> dict[str, Any]:
        from regex_conformance_schema.errors import ConformanceDataError
        from regex_conformance_schema.jsonio import loads_strict

        try:
            relative = reference["relative_path"]
            expected_digest = reference["sha256"]
            expected_size = reference["size_bytes"]
            category = reference.get("category")
            candidate = self.evidence_root / relative
            path = candidate.resolve(strict=True)
            path.relative_to(self.evidence_root)
        except (KeyError, OSError, TypeError, ValueError) as error:
            raise EvidenceIntegrityError(
                "artifact-path-invalid",
                "evidence reference does not resolve to a contained artifact",
                artifact_category=reference.get("category") if isinstance(reference, dict) else None,
                artifact_sha256=reference.get("sha256") if isinstance(reference, dict) else None,
            ) from error
        if candidate.absolute() != path or not stat.S_ISREG(path.stat().st_mode):
            raise EvidenceIntegrityError(
                "artifact-path-indirect",
                "evidence artifacts must be direct regular files, not links",
                artifact_category=category,
                artifact_sha256=expected_digest,
            )
        encoded = path.read_bytes()
        if len(encoded) != expected_size:
            raise EvidenceIntegrityError(
                "artifact-size-mismatch",
                "evidence artifact size differs from its immutable reference",
                artifact_category=category,
                artifact_sha256=expected_digest,
            )
        if hashlib.sha256(encoded).hexdigest() != expected_digest:
            raise EvidenceIntegrityError(
                "artifact-digest-mismatch",
                "evidence artifact digest differs from its immutable reference",
                artifact_category=category,
                artifact_sha256=expected_digest,
            )
        try:
            payload = loads_strict(encoded.decode("utf-8"))
        except (ConformanceDataError, UnicodeError) as error:
            code = getattr(error, "code", "artifact-json-invalid")
            if code not in {
                "duplicate-json-key", "invalid-json", "invalid-json-number", "invalid-unicode"
            }:
                code = "artifact-json-invalid"
            raise EvidenceIntegrityError(
                code,
                "evidence artifact is not strict UTF-8 JSON",
                artifact_category=category,
                artifact_sha256=expected_digest,
            ) from error
        if not isinstance(payload, dict):
            raise EvidenceIntegrityError(
                "artifact-not-object",
                "evidence artifact top level must be an object",
                artifact_category=category,
                artifact_sha256=expected_digest,
            )
        if canonical_bytes(payload) + b"\n" != encoded:
            raise EvidenceIntegrityError(
                "artifact-not-canonical",
                "evidence artifact bytes are not canonical JSON plus one newline",
                artifact_category=category,
                artifact_sha256=expected_digest,
            )
        return payload

    def verify_manifest(
        self,
        compiled: dict[str, Any],
        evidence_manifest: dict[str, Any],
    ) -> None:
        from .result_verifier import ResultVerifier

        ResultVerifier(self.repository_root, self).verify(compiled, evidence_manifest)

    def qualify_manifest(
        self,
        compiled: dict[str, Any],
        evidence_manifest: dict[str, Any],
    ) -> dict[str, Any]:
        """Persist an immutable admission or quarantine assessment."""

        finding = None
        try:
            self.verify_manifest(compiled, evidence_manifest)
        except EvidenceIntegrityError as error:
            finding = error.as_finding()
        manifest_reference = (
            evidence_manifest.get("manifest_reference")
            if isinstance(evidence_manifest, dict)
            else None
        )
        evidence_manifest_id = (
            evidence_manifest.get("evidence_manifest_id")
            if isinstance(evidence_manifest, dict)
            and isinstance(evidence_manifest.get("evidence_manifest_id"), str)
            else None
        )
        complete = bool(
            finding is None
            and isinstance(evidence_manifest, dict)
            and evidence_manifest.get("complete") is True
        )
        disposition = "quarantined" if finding else ("admitted" if complete else "retained-incomplete")
        body = {
            "assessed_manifest_sha256": (
                manifest_reference.get("sha256")
                if isinstance(manifest_reference, dict)
                and isinstance(manifest_reference.get("sha256"), str)
                else None
            ),
            "analytical_admissible": complete,
            "campaign_manifest_id": compiled["campaign_manifest_id"],
            "certification_admissible": False,
            "classification": {
                "canonical_authority": False,
                "normative_authority": False,
                "operational_qualification_only": True,
                "semantic_authority": False,
            },
            "disposition": disposition,
            "evidence_manifest_id": evidence_manifest_id,
            "findings": [] if finding is None else [finding],
            "integrity_qualification": "failed" if finding else "passed",
            "policy_revision": "result-integrity-v1",
            "summary": {
                "error_count": 0 if finding is None else 1,
                "finding_count": 0 if finding is None else 1,
            },
            "trust_qualification": "not-assessed",
        }
        trust_assessment_id = _content_id(
            self.repository_root, "trust-assessment", "trust-assessment-v1", body
        )
        payload = {
            "schema_version": "trust-assessment.v1",
            "trust_assessment_id": trust_assessment_id,
            **body,
        }
        from regex_conformance_schema.jsonio import load_strict
        from regex_conformance_schema.schema import validate_instance

        validate_instance(
            payload,
            load_strict(
                self.repository_root / "schemas" / "json" / "trust-assessment.schema.json"
            ),
            source="trust assessment",
        )
        assessment_reference = self._write("trust-assessments", payload)
        return {**payload, "assessment_reference": assessment_reference}

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
                from .result_verifier import validate_target_response

                validate_target_response(
                    self.repository_root,
                    response,
                    logical_id,
                )
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
