"""Immutable segmented evidence publication for recoverable scale campaigns."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from typing import Any, Callable, Iterable

from regex_conformance_campaign.compiler import SCHEMA_FAMILY_ID
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.identity import (
    NamespaceRegistry,
    build_content_identity,
    generate_assigned_id,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict
from regex_conformance_schema.profile import IdentityProfile
from regex_conformance_schema.schema import validate_instance

from .diagnostics import EvidenceIntegrityError
from .result_verifier import validate_response_against_plan, validate_target_response


LogicalLoader = Callable[[dict[str, Any]], list[dict[str, Any]]]


def _fail(code: str, message: str) -> EvidenceIntegrityError:
    return EvidenceIntegrityError(code, message)


def _shard_logical_ids(
    shard: dict[str, Any], logicals: list[dict[str, Any]]
) -> list[str]:
    logical_ids = [item["logical_execution_id"] for item in logicals]
    if (
        not logical_ids
        or len(logical_ids) != shard["logical_execution_count"]
        or len(logical_ids) != len(set(logical_ids))
        or logical_ids[0] != shard["first_logical_execution_id"]
        or logical_ids[-1] != shard["last_logical_execution_id"]
        or hashlib.sha256(canonical_bytes(logical_ids)).hexdigest()
        != shard["logical_execution_ids_sha256"]
    ):
        raise _fail(
            "segment-logical-mismatch",
            "materialized logical IDs differ from the compact shard commitment",
        )
    return logical_ids


class ScaleEvidenceStore:
    """Content-addressed shard segments and one atomic scale manifest."""

    def __init__(self, repository_root: Path, evidence_root: Path) -> None:
        self.repository_root = repository_root.resolve(strict=True)
        unresolved = evidence_root.expanduser().absolute()
        if unresolved.is_symlink():
            raise _fail(
                "evidence-root-indirect", "scale evidence root cannot be a link"
            )
        self.evidence_root = unresolved.resolve(strict=False)
        try:
            self.evidence_root.relative_to(self.repository_root)
        except ValueError:
            pass
        else:
            raise _fail(
                "evidence-root-inside-git", "scale evidence must remain outside Git"
            )
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        if unresolved != self.evidence_root or not self.evidence_root.is_dir():
            raise _fail(
                "evidence-root-indirect",
                "scale evidence root must be a direct directory",
            )
        self.registry = NamespaceRegistry.load(
            self.repository_root / "registries" / "identity" / "namespaces.v1.json"
        )
        self.content_profile = IdentityProfile.from_record(
            load_strict(
                self.repository_root
                / "schemas"
                / "identity-profiles"
                / "campaign-content.v1.json"
            )
        )
        self.segment_schema = load_strict(
            self.repository_root
            / "schemas"
            / "json"
            / "scale-result-segment.schema.json"
        )
        self.manifest_schema = load_strict(
            self.repository_root
            / "schemas"
            / "json"
            / "scale-evidence-manifest.schema.json"
        )
        self.timeout_schema = load_strict(
            self.repository_root
            / "schemas"
            / "json"
            / "scale-target-timeout.schema.json"
        )

    def _content_id(self, namespace: str, kind: str, identity: Any) -> str:
        result = build_content_identity(
            registry=self.registry,
            profile=self.content_profile,
            namespace=namespace,
            identity_schema_family_id=SCHEMA_FAMILY_ID,
            identity_schema_version="1.0.0",
            identity={
                "artifact_kind": kind,
                "content_sha256": hashlib.sha256(canonical_bytes(identity)).hexdigest(),
            },
        )
        return str(result["content_id"])

    @staticmethod
    def _result_logical_id(result: dict[str, Any]) -> str:
        schema_version = result.get("schema_version")
        if schema_version == "adapter-response.v1":
            logical_id = result.get("correlation_id")
        elif schema_version == "scale-target-timeout.v1":
            logical_id = result.get("logical_execution_id")
        else:
            raise _fail(
                "segment-result-kind-invalid",
                "scale segment contains an unknown target-result kind",
            )
        if not isinstance(logical_id, str):
            raise _fail(
                "segment-result-identity-invalid",
                "scale target result has no valid logical identity",
            )
        return logical_id

    def _validate_result(
        self,
        result: dict[str, Any],
        logical_id: str,
        logical: dict[str, Any],
    ) -> None:
        if result.get("schema_version") == "adapter-response.v1":
            validate_target_response(
                self.repository_root,
                result,
                logical_id,
            )
            validate_response_against_plan(result, logical)
            return
        validate_instance(result, self.timeout_schema, source="scale target timeout")
        request = logical["request"]
        facts = result["runtime_identity"]["facts"]
        fact_names = [item["name"] for item in facts]
        provider_plan = result["process_execution"]["provider_plan"]
        if (
            logical["selection_key"] != "python-re"
            or request["limits"]["wall_time_ms"] > 1_000
            or result["logical_execution_id"] != logical_id
            or result["adapter_release_manifest_id"]
            != request["adapter_release_manifest_id"]
            or result["profile_id"] != request["profile_id"]
            or result["target_release_id"] != request["target_release_id"]
            or result["trace_reference"] != request["trace_reference"]
            or result["timer"]["wall_time_ms"] != request["limits"]["wall_time_ms"]
            or len(fact_names) != len(set(fact_names))
            or provider_plan.get("provider") != "native"
            or provider_plan.get("process_tree_containment") is not True
            or not {
                "cpu-time",
                "memory",
                "process-tree",
                "stderr",
                "stdout",
                "wall-time",
            }.issubset(set(provider_plan.get("enforced_limits", ())))
            or provider_plan.get("canonical_authority") is not False
            or provider_plan.get("semantic_authority") is not False
        ):
            raise _fail(
                "target-timeout-binding-invalid",
                "target-timeout evidence does not bind the exact contained request",
            )

    def _directory(self, category: str) -> Path:
        parent = self.evidence_root / category
        directory = parent / "sha256"
        for path in (parent, directory):
            try:
                path.mkdir()
            except FileExistsError:
                pass
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(self.evidence_root)
            except (OSError, ValueError) as error:
                raise _fail(
                    "evidence-directory-invalid",
                    "scale evidence directory is absent or escapes its root",
                ) from error
            if path.absolute() != resolved or not resolved.is_dir():
                raise _fail(
                    "evidence-directory-indirect",
                    "scale evidence directories must be direct directories",
                )
        return directory

    def _write(self, category: str, payload: dict[str, Any]) -> dict[str, Any]:
        encoded = canonical_bytes(payload) + b"\n"
        digest = hashlib.sha256(encoded).hexdigest()
        directory = self._directory(category)
        path = directory / f"{digest}.json"
        if path.exists():
            metadata = path.stat()
            if (
                path.absolute() != path.resolve(strict=True)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                raise _fail(
                    "evidence-path-indirect",
                    "existing scale evidence must be a direct non-linked file",
                )
            if path.read_bytes() != encoded:
                raise _fail(
                    "evidence-content-conflict",
                    "content-addressed scale evidence contains conflicting bytes",
                )
        else:
            temporary = directory / f".{digest}.tmp"
            with temporary.open("xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            if os.name != "nt":
                descriptor = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        if path.read_bytes() != encoded:
            raise _fail(
                "evidence-readback-failed",
                "scale evidence failed read-after-write verification",
            )
        return {
            "category": category,
            "relative_path": path.relative_to(self.evidence_root).as_posix(),
            "sha256": digest,
            "size_bytes": len(encoded),
        }

    def read(self, reference: dict[str, Any]) -> dict[str, Any]:
        try:
            category = reference["category"]
            digest = reference["sha256"]
            size = reference["size_bytes"]
            expected_path = f"{category}/sha256/{digest}.json"
            if reference["relative_path"] != expected_path:
                raise ValueError("non-content-addressed reference")
            unresolved = self.evidence_root / expected_path
            resolved = unresolved.resolve(strict=True)
            resolved.relative_to(self.evidence_root)
        except (KeyError, OSError, TypeError, ValueError) as error:
            raise _fail(
                "evidence-reference-invalid",
                "scale evidence reference is absent, malformed, or escaping",
            ) from error
        metadata = unresolved.stat()
        if (
            unresolved.absolute() != resolved
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise _fail(
                "evidence-path-indirect",
                "scale evidence artifacts must be direct non-linked files",
            )
        encoded = resolved.read_bytes()
        if len(encoded) != size:
            raise _fail(
                "evidence-size-mismatch",
                "scale evidence size differs from its reference",
            )
        if hashlib.sha256(encoded).hexdigest() != digest:
            raise _fail(
                "evidence-digest-mismatch",
                "scale evidence digest differs from its reference",
            )
        try:
            payload = loads_strict(encoded.decode("utf-8"))
        except (ConformanceDataError, UnicodeError) as error:
            raise _fail(
                "evidence-json-invalid", "scale evidence is not strict UTF-8 JSON"
            ) from error
        if not isinstance(payload, dict) or canonical_bytes(payload) + b"\n" != encoded:
            raise _fail(
                "evidence-not-canonical",
                "scale evidence must be a canonical JSON object",
            )
        return payload

    def write_result_segment(
        self,
        *,
        plan: dict[str, Any],
        shard: dict[str, Any],
        logicals: list[dict[str, Any]],
        attempt_number: int,
        attempts: list[dict[str, Any]],
        results: list[dict[str, Any]],
        provenance: dict[str, Any],
        segment_kind: str,
    ) -> dict[str, Any]:
        logical_ids = _shard_logical_ids(shard, logicals)
        attempt_by_logical = {item["logical_execution_id"]: item for item in attempts}
        if set(attempt_by_logical) != set(logical_ids) or len(attempts) != len(
            logical_ids
        ):
            raise _fail(
                "segment-attempt-mismatch", "segment attempts do not cover its shard"
            )
        if any(item["attempt_number"] != attempt_number for item in attempts):
            raise _fail(
                "segment-attempt-number-mismatch",
                "physical attempts use another attempt number",
            )
        result_by_logical = {self._result_logical_id(item): item for item in results}
        if len(result_by_logical) != len(results):
            raise _fail(
                "segment-result-duplicate",
                "segment target results contain duplicate credit",
            )
        if segment_kind == "result":
            if set(result_by_logical) != set(logical_ids) or any(
                item["outcome"] != "target-observation"
                or item["infrastructure_failure"] is not None
                for item in attempts
            ):
                raise _fail(
                    "segment-result-incomplete",
                    "result segment must contain one target observation per logical execution",
                )
        elif segment_kind == "attempt":
            if results or any(
                item["outcome"] != "infrastructure-failure"
                or item["infrastructure_failure"] is None
                for item in attempts
            ):
                raise _fail(
                    "segment-attempt-invalid",
                    "attempt-only segment must preserve infrastructure failures only",
                )
        else:
            raise _fail("segment-kind-invalid", "scale result segment kind is invalid")

        observations: list[dict[str, Any]] = []
        logical_by_id = {item["logical_execution_id"]: item for item in logicals}
        for logical_id in logical_ids:
            result = result_by_logical.get(logical_id)
            if result is None:
                continue
            self._validate_result(result, logical_id, logical_by_id[logical_id])
            observation_id = generate_assigned_id(self.registry, "rcid", "observation")
            body = {
                "campaign_manifest_id": plan["campaign_manifest_id"],
                "logical_execution_id": logical_id,
                "observation_id": observation_id,
                "physical_run_id": attempt_by_logical[logical_id]["physical_run_id"],
                "result": result,
            }
            observation_content_id = self._content_id(
                "observation-content",
                "scale-observation-content-v1",
                body,
            )
            observations.append(
                {**body, "observation_content_id": observation_content_id}
            )
        segment_body = {
            "attempt_number": attempt_number,
            "campaign_manifest_id": plan["campaign_manifest_id"],
            "logical_execution_ids": logical_ids,
            "observations": observations,
            "physical_attempts": attempts,
            "provenance": provenance,
            "schema_version": "scale-result-segment.v1",
            "segment_kind": segment_kind,
            "selection_key": shard["selection_key"],
            "shard_id": shard["shard_id"],
        }
        result_segment_id = self._content_id(
            "result-segment",
            "scale-result-segment-v1",
            segment_body,
        )
        payload = {**segment_body, "result_segment_id": result_segment_id}
        validate_instance(payload, self.segment_schema, source="scale result segment")
        reference = self._write("scale-result-segments", payload)
        return {
            **reference,
            "attempt_count": len(attempts),
            "attempt_number": attempt_number,
            "logical_execution_count": len(logical_ids),
            "observation_count": len(observations),
            "result_segment_id": result_segment_id,
            "segment_kind": segment_kind,
            "shard_id": shard["shard_id"],
        }

    def verify_segment(
        self,
        reference: dict[str, Any],
        plan: dict[str, Any],
        shard: dict[str, Any],
        logicals: list[dict[str, Any]],
    ) -> dict[str, Any]:
        logical_ids = _shard_logical_ids(shard, logicals)
        payload = self.read(reference)
        validate_instance(payload, self.segment_schema, source="scale result segment")
        body = {
            key: value for key, value in payload.items() if key != "result_segment_id"
        }
        expected_id = self._content_id(
            "result-segment",
            "scale-result-segment-v1",
            body,
        )
        if (
            payload["result_segment_id"] != expected_id
            or reference["result_segment_id"] != expected_id
            or payload["campaign_manifest_id"] != plan["campaign_manifest_id"]
            or payload["shard_id"] != shard["shard_id"]
            or payload["selection_key"] != shard["selection_key"]
            or payload["logical_execution_ids"] != logical_ids
            or reference["attempt_number"] != payload["attempt_number"]
            or reference["segment_kind"] != payload["segment_kind"]
            or reference["attempt_count"] != len(payload["physical_attempts"])
            or reference["observation_count"] != len(payload["observations"])
            or reference["logical_execution_count"]
            != len(payload["logical_execution_ids"])
        ):
            raise _fail(
                "segment-reconciliation-failed",
                "scale segment identity or manifest coordinates disagree",
            )
        logical_by_id = {item["logical_execution_id"]: item for item in logicals}
        attempt_by_id = {
            item["logical_execution_id"]: item for item in payload["physical_attempts"]
        }
        if set(attempt_by_id) != set(logical_by_id):
            raise _fail(
                "segment-attempt-mismatch",
                "scale segment attempts differ from its shard",
            )
        observation_by_id = {
            item["logical_execution_id"]: item for item in payload["observations"]
        }
        if len(observation_by_id) != len(payload["observations"]):
            raise _fail(
                "segment-observation-duplicate",
                "scale observations duplicate logical credit",
            )
        for logical_id, observation in observation_by_id.items():
            if (
                logical_id not in logical_by_id
                or observation["physical_run_id"]
                != attempt_by_id[logical_id]["physical_run_id"]
            ):
                raise _fail(
                    "segment-observation-mismatch",
                    "scale observation does not bind its physical attempt",
                )
            observation_body = {
                key: value
                for key, value in observation.items()
                if key != "observation_content_id"
            }
            expected_observation_id = self._content_id(
                "observation-content",
                "scale-observation-content-v1",
                observation_body,
            )
            if observation["observation_content_id"] != expected_observation_id:
                raise _fail(
                    "observation-content-id-mismatch",
                    "scale observation content identity differs",
                )
            self._validate_result(
                observation["result"], logical_id, logical_by_id[logical_id]
            )
        if payload["segment_kind"] == "result":
            if set(observation_by_id) != set(logical_by_id) or any(
                item["outcome"] != "target-observation"
                or item["infrastructure_failure"] is not None
                for item in payload["physical_attempts"]
            ):
                raise _fail(
                    "segment-result-incomplete", "scale result segment is incomplete"
                )
        elif observation_by_id or any(
            item["outcome"] != "infrastructure-failure"
            or item["infrastructure_failure"] is None
            for item in payload["physical_attempts"]
        ):
            raise _fail(
                "segment-attempt-invalid", "scale attempt-only segment is inconsistent"
            )
        return payload

    def publish_manifest(
        self,
        plan: dict[str, Any],
        committed_segments: Iterable[Any],
        interruptions: list[dict[str, Any]],
        logical_loader: LogicalLoader,
    ) -> dict[str, Any]:
        references = [item.reference for item in committed_segments]
        manifest = self._manifest(plan, references, interruptions, logical_loader)
        reference = self._write("scale-manifests", manifest)
        result = {**manifest, "manifest_reference": reference}
        self.verify_manifest(plan, result, logical_loader)
        return result

    def _manifest(
        self,
        plan: dict[str, Any],
        references: list[dict[str, Any]],
        interruptions: list[dict[str, Any]],
        logical_loader: LogicalLoader,
    ) -> dict[str, Any]:
        shard_by_id = {item["shard_id"]: item for item in plan["shards"]}
        result_shards: set[str] = set()
        logical_attempts: dict[str, list[tuple[int, str]]] = {}
        selected_logicals: set[str] = set()
        physical_ids: set[str] = set()
        observation_ids: set[str] = set()
        infrastructure_failures = 0
        for reference in references:
            shard = shard_by_id.get(reference.get("shard_id"))
            if shard is None:
                raise _fail(
                    "manifest-shard-unknown",
                    "scale evidence references an unknown shard",
                )
            payload = self.verify_segment(reference, plan, shard, logical_loader(shard))
            if payload["segment_kind"] == "result":
                if shard["shard_id"] in result_shards:
                    raise _fail(
                        "manifest-result-duplicate",
                        "scale manifest duplicates a result shard",
                    )
                result_shards.add(shard["shard_id"])
                selected_logicals.update(payload["logical_execution_ids"])
            for attempt in payload["physical_attempts"]:
                physical_id = attempt["physical_run_id"]
                if physical_id in physical_ids:
                    raise _fail(
                        "manifest-physical-run-duplicate",
                        "scale manifest reuses a physical run identity",
                    )
                physical_ids.add(physical_id)
                logical_attempts.setdefault(attempt["logical_execution_id"], []).append(
                    (attempt["attempt_number"], attempt["outcome"])
                )
                infrastructure_failures += (
                    attempt["outcome"] == "infrastructure-failure"
                )
            for observation in payload["observations"]:
                content_id = observation["observation_content_id"]
                if content_id in observation_ids:
                    raise _fail(
                        "manifest-observation-duplicate",
                        "scale manifest duplicates observation content",
                    )
                observation_ids.add(content_id)
        planned_ids: set[str] = set()
        for shard in plan["shards"]:
            shard_ids = _shard_logical_ids(shard, logical_loader(shard))
            if planned_ids.intersection(shard_ids):
                raise _fail("manifest-logical-duplicate", "scale shards overlap")
            planned_ids.update(shard_ids)
        if result_shards != set(shard_by_id) or selected_logicals != planned_ids:
            raise _fail(
                "manifest-denominator-incomplete",
                "scale result segments do not cover the exact denominator",
            )
        if set(logical_attempts) != planned_ids:
            raise _fail(
                "manifest-attempt-incomplete",
                "scale attempts do not cover the denominator",
            )
        for attempts in logical_attempts.values():
            ordered = sorted(attempts)
            if [item[0] for item in ordered] != list(range(1, len(ordered) + 1)):
                raise _fail(
                    "manifest-attempt-gap", "scale retry ordinals are not contiguous"
                )
            if ordered[-1][1] != "target-observation" or any(
                outcome != "infrastructure-failure" for _, outcome in ordered[:-1]
            ):
                raise _fail(
                    "manifest-attempt-selection-invalid",
                    "scale retry history does not end in one selected target observation",
                )
        expected_interruptions = [
            (item["key"], item["action"], item["after_committed_shards"])
            for item in plan["planned_interruptions"]
        ]
        observed_interruptions = [
            (
                item["interruption_key"],
                item["action"],
                item["after_committed_shards"],
            )
            for item in interruptions
        ]
        if observed_interruptions != expected_interruptions:
            raise _fail(
                "manifest-interruption-mismatch",
                "observed interruptions differ from the frozen plan",
            )
        if any(
            (item["action"] == "worker-process-kill")
            != (item["worker_process"] is not None)
            for item in interruptions
        ):
            raise _fail(
                "manifest-interruption-provenance-invalid",
                "worker kill provenance is absent or attached to another action",
            )
        sorted_references = sorted(
            references,
            key=lambda item: (
                item["shard_id"],
                item["attempt_number"],
                item["segment_kind"],
            ),
        )
        root_digest = hashlib.sha256(
            canonical_bytes(
                {
                    "interruption_digests": [
                        item["event_sha256"] for item in interruptions
                    ],
                    "segment_digests": [item["sha256"] for item in sorted_references],
                }
            )
        ).hexdigest()
        body = {
            "accepted_observation_count": len(observation_ids),
            "attempt_count": len(physical_ids),
            "campaign_manifest_id": plan["campaign_manifest_id"],
            "complete": True,
            "infrastructure_failure_attempt_count": infrastructure_failures,
            "interruptions": interruptions,
            "logical_execution_count": len(planned_ids),
            "result_shard_count": len(result_shards),
            "root_digest": root_digest,
            "schema_version": "scale-evidence-manifest.v1",
            "segments": sorted_references,
        }
        evidence_manifest_id = self._content_id(
            "evidence-manifest",
            "scale-evidence-manifest-v1",
            body,
        )
        payload = {**body, "evidence_manifest_id": evidence_manifest_id}
        validate_instance(
            payload, self.manifest_schema, source="scale evidence manifest"
        )
        return payload

    def verify_manifest(
        self,
        plan: dict[str, Any],
        supplied: dict[str, Any],
        logical_loader: LogicalLoader,
    ) -> None:
        reference = supplied.get("manifest_reference")
        if (
            not isinstance(reference, dict)
            or reference.get("category") != "scale-manifests"
        ):
            raise _fail(
                "manifest-reference-invalid", "scale manifest reference is invalid"
            )
        stored = self.read(reference)
        validate_instance(
            stored, self.manifest_schema, source="scale evidence manifest"
        )
        without_reference = {
            key: value for key, value in supplied.items() if key != "manifest_reference"
        }
        if canonical_bytes(stored) != canonical_bytes(without_reference):
            raise _fail(
                "manifest-substitution", "supplied and stored scale manifests differ"
            )
        expected = self._manifest(
            plan,
            stored["segments"],
            stored["interruptions"],
            logical_loader,
        )
        if canonical_bytes(stored) != canonical_bytes(expected):
            raise _fail(
                "manifest-reconciliation-failed",
                "scale manifest differs from deterministic evidence reconciliation",
            )
