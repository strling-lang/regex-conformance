"""Fail-closed structural, semantic, and reconciliation verification."""

from __future__ import annotations

from datetime import datetime
import hashlib
import re
from typing import Any

from regex_conformance_campaign.compiler import _content_id
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance

from .diagnostics import EvidenceIntegrityError


_HEX = re.compile(r"^[0-9a-f]{64}$")
_REFERENCE_KEYS = {"category", "relative_path", "sha256", "size_bytes"}
_REFERENCE_EXTRAS = {
    "attempts": {"logical_execution_id", "physical_run_id"},
    "manifests": set(),
    "observations": {"logical_execution_id", "observation_content_id", "observation_id"},
    "result-shards": {"result_shard_id", "shard_id"},
}
_SCHEMAS = {
    "attempts": "physical-attempt-evidence.schema.json",
    "manifests": "evidence-manifest.schema.json",
    "observations": "observation-content.schema.json",
    "result-shards": "result-shard.schema.json",
}


def _error(
    code: str,
    message: str,
    *,
    reference: dict[str, Any] | None = None,
    logical_execution_id: str | None = None,
) -> EvidenceIntegrityError:
    return EvidenceIntegrityError(
        code,
        message,
        artifact_category=None if reference is None else reference.get("category"),
        artifact_sha256=None if reference is None else reference.get("sha256"),
        logical_execution_id=logical_execution_id,
    )


def _diagnostics(observation: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    native_error = observation.get("native_error")
    if isinstance(native_error, dict) and isinstance(native_error.get("diagnostic"), dict):
        result.append(native_error["diagnostic"])
    return result


def _walk_captures(observation: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        capture
        for match in observation.get("matches", [])
        if isinstance(match, dict)
        for capture in match.get("captures", [])
        if isinstance(capture, dict)
    ]


def validate_target_response(
    repository_root: Any,
    response: Any,
    logical_execution_id: str,
    *,
    reference: dict[str, Any] | None = None,
) -> None:
    """Validate a terminal adapter response without interpreting its regex meaning."""

    if not isinstance(response, dict):
        raise _error("response-not-object", "target response must be an object", reference=reference)
    try:
        validate_instance(
            response,
            load_strict(repository_root / "schemas" / "json" / "adapter-response.schema.json"),
            source="target response",
        )
    except ConformanceDataError as error:
        raise _error(
            "response-schema-invalid",
            "target response does not satisfy adapter-response.v1",
            reference=reference,
            logical_execution_id=logical_execution_id,
        ) from error
    if response["correlation_id"] != logical_execution_id:
        raise _error(
            "response-correlation-mismatch",
            "target response correlation does not identify its logical execution",
            reference=reference,
            logical_execution_id=logical_execution_id,
        )
    if response["canonical_authority"] or response["semantic_authority"]:
        raise _error(
            "response-authority-claim",
            "empirical target response cannot claim canonical or semantic authority",
            reference=reference,
            logical_execution_id=logical_execution_id,
        )
    observation = response["observation"]
    if observation is None:
        return

    matches = observation["matches"]
    match_state = observation["match_state"]
    if match_state == "match" and not matches:
        raise _error(
            "match-state-without-match",
            "match state requires at least one native-preserving match",
            reference=reference,
            logical_execution_id=logical_execution_id,
        )
    if match_state != "match" and matches:
        raise _error(
            "nonmatch-state-with-matches",
            "only match state may contain match records",
            reference=reference,
            logical_execution_id=logical_execution_id,
        )
    ordinals = [item["ordinal"] for item in matches]
    if ordinals != sorted(ordinals) or len(ordinals) != len(set(ordinals)):
        raise _error(
            "match-ordinal-inconsistent",
            "match ordinals must be unique and increasing",
            reference=reference,
            logical_execution_id=logical_execution_id,
        )
    for match in matches:
        span = match["span"]
        if span["start"] > span["end"]:
            raise _error(
                "span-order-impossible",
                "match span start exceeds end",
                reference=reference,
                logical_execution_id=logical_execution_id,
            )
        indexes = [capture["index"] for capture in match["captures"]]
        if len(indexes) != len(set(indexes)):
            raise _error(
                "capture-index-duplicate",
                "capture indexes must be unique within a match",
                reference=reference,
                logical_execution_id=logical_execution_id,
            )
    for capture in _walk_captures(observation):
        spans = [capture["span"]] if capture["span"] is not None else []
        spans.extend(item["span"] for item in capture["history"])
        if any(span["start"] > span["end"] for span in spans):
            raise _error(
                "span-order-impossible",
                "capture span start exceeds end",
                reference=reference,
                logical_execution_id=logical_execution_id,
            )
    cursor = observation["cursor"]
    if cursor is not None and cursor["next_offset"] < cursor["initial_offset"]:
        raise _error(
            "cursor-regression",
            "next cursor offset precedes the initial offset",
            reference=reference,
            logical_execution_id=logical_execution_id,
        )
    absence_fields = [item["field"] for item in observation["absences"]]
    if len(absence_fields) != len(set(absence_fields)):
        raise _error(
            "absence-field-duplicate",
            "an observation field may have only one absence reason",
            reference=reference,
            logical_execution_id=logical_execution_id,
        )
    outputs = observation["outputs"]
    if outputs["kind"] == "none" and outputs["values"]:
        raise _error(
            "none-output-with-values",
            "none output kind cannot contain values",
            reference=reference,
            logical_execution_id=logical_execution_id,
        )
    for diagnostic in _diagnostics(observation):
        encoded = diagnostic["content"].encode("utf-8")
        if (
            diagnostic["captured_bytes"] != len(encoded)
            or diagnostic["sha256"] != hashlib.sha256(encoded).hexdigest()
            or diagnostic["original_bytes"] < diagnostic["captured_bytes"]
            or diagnostic["truncated"]
            != (diagnostic["original_bytes"] > diagnostic["captured_bytes"])
        ):
            raise _error(
                "diagnostic-integrity-inconsistent",
                "diagnostic length, digest, or truncation metadata is inconsistent",
                reference=reference,
                logical_execution_id=logical_execution_id,
            )


def validate_response_against_plan(
    response: dict[str, Any],
    logical: dict[str, Any],
    *,
    reference: dict[str, Any] | None = None,
) -> None:
    """Reject valid-looking responses that identify a different execution coordinate."""

    request = logical["request"]
    expected = {
        "adapter_release_manifest_id": request["adapter_release_manifest_id"],
        "profile_id": request["profile_id"],
        "target_release_id": request["target_release_id"],
        "trace_reference": request["trace_reference"],
    }
    if any(response.get(key) != value for key, value in expected.items()):
        raise _error(
            "response-plan-mismatch",
            "target response identity does not match the frozen execution coordinate",
            reference=reference,
            logical_execution_id=logical["logical_execution_id"],
        )
    observation = response.get("observation")
    if observation is None:
        return
    materialization = observation["materialization"]
    if (
        observation["operation"] != request["operation"]
        or materialization["pattern_domain"] != request["pattern"]["domain"]
        or materialization["subject_domains"]
        != [item["domain"] for item in request["subjects"]]
    ):
        raise _error(
            "response-plan-mismatch",
            "target response operation or materialization does not match the frozen request",
            reference=reference,
            logical_execution_id=logical["logical_execution_id"],
        )


class ResultVerifier:
    """Verify one supplied and stored evidence manifest against its plan."""

    def __init__(self, repository_root: Any, evidence_store: Any) -> None:
        self.repository_root = repository_root
        self.evidence_store = evidence_store

    def _reference(
        self,
        reference: Any,
        category: str,
        *,
        logical_execution_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(reference, dict):
            raise _error("artifact-reference-invalid", "artifact reference must be an object")
        expected = _REFERENCE_KEYS | _REFERENCE_EXTRAS[category]
        digest = reference.get("sha256")
        if (
            set(reference) != expected
            or reference.get("category") != category
            or not isinstance(digest, str)
            or _HEX.fullmatch(digest) is None
            or not isinstance(reference.get("size_bytes"), int)
            or isinstance(reference.get("size_bytes"), bool)
            or reference["size_bytes"] < 1
            or reference.get("relative_path") != f"{category}/sha256/{digest}.json"
        ):
            raise _error(
                "artifact-reference-invalid",
                "artifact reference is not an exact content-addressed reference",
                reference=reference,
                logical_execution_id=logical_execution_id,
            )
        return reference

    def _artifact(
        self,
        reference: Any,
        category: str,
        *,
        logical_execution_id: str | None = None,
    ) -> dict[str, Any]:
        checked = self._reference(
            reference, category, logical_execution_id=logical_execution_id
        )
        payload = self.evidence_store.read_artifact(checked)
        try:
            validate_instance(
                payload,
                load_strict(
                    self.repository_root / "schemas" / "json" / _SCHEMAS[category]
                ),
                source=category,
            )
        except ConformanceDataError as error:
            raise _error(
                "artifact-schema-invalid",
                f"{category} artifact does not satisfy its frozen schema",
                reference=checked,
                logical_execution_id=logical_execution_id,
            ) from error
        return payload

    def verify(self, compiled: dict[str, Any], evidence_manifest: dict[str, Any]) -> None:
        if not isinstance(evidence_manifest, dict):
            raise _error("manifest-not-object", "supplied evidence manifest must be an object")
        reference = self._reference(evidence_manifest.get("manifest_reference"), "manifests")
        stored_manifest = self._artifact(reference, "manifests")
        supplied_manifest = {
            key: value for key, value in evidence_manifest.items() if key != "manifest_reference"
        }
        try:
            validate_instance(
                supplied_manifest,
                load_strict(
                    self.repository_root / "schemas" / "json" / _SCHEMAS["manifests"]
                ),
                source="supplied manifest",
            )
        except ConformanceDataError as error:
            raise _error(
                "manifest-schema-invalid",
                "supplied evidence manifest does not satisfy its frozen schema",
                reference=reference,
            ) from error
        if canonical_bytes(stored_manifest) != canonical_bytes(supplied_manifest):
            raise _error(
                "manifest-substitution",
                "stored and supplied evidence manifests differ",
                reference=reference,
            )
        manifest_body = {
            key: value
            for key, value in stored_manifest.items()
            if key not in {"schema_version", "evidence_manifest_id"}
        }
        expected_manifest_id = _content_id(
            self.repository_root,
            "evidence-manifest",
            "evidence-manifest-v2",
            manifest_body,
        )
        if stored_manifest["evidence_manifest_id"] != expected_manifest_id:
            raise _error(
                "manifest-identity-mismatch",
                "evidence manifest content identity does not match",
                reference=reference,
            )
        if stored_manifest["campaign_manifest_id"] != compiled["campaign_manifest_id"]:
            raise _error(
                "manifest-campaign-mismatch",
                "evidence manifest references the wrong campaign",
                reference=reference,
            )

        planned_by_logical = {
            item["logical_execution_id"]: item for item in compiled["logical_executions"]
        }
        planned = set(planned_by_logical)
        attempt_logicals: set[str] = set()
        attempt_numbers: set[tuple[str, int]] = set()
        attempts_by_physical: dict[str, dict[str, Any]] = {}
        physical_logicals: dict[str, str] = {}
        infrastructure_failure_count = 0
        artifact_digests: list[str] = []
        for attempt_reference in stored_manifest["attempts"]:
            logical_id = attempt_reference.get("logical_execution_id")
            attempt = self._artifact(
                attempt_reference, "attempts", logical_execution_id=logical_id
            )
            physical_id = attempt["physical_run_id"]
            attempt_key = (logical_id, attempt["attempt_number"])
            if (
                attempt["logical_execution_id"] != logical_id
                or physical_id != attempt_reference.get("physical_run_id")
                or logical_id not in planned
                or physical_id in attempts_by_physical
                or attempt_key in attempt_numbers
                or attempt["campaign_manifest_id"] != compiled["campaign_manifest_id"]
            ):
                raise _error(
                    "attempt-identity-inconsistent",
                    "attempt reference or identity does not reconcile",
                    reference=attempt_reference,
                    logical_execution_id=logical_id,
                )
            try:
                observed_at = datetime.fromisoformat(attempt["observed_at"].replace("Z", "+00:00"))
                if observed_at.tzinfo is None:
                    raise ValueError("timezone is absent")
            except ValueError as error:
                raise _error(
                    "attempt-timestamp-invalid",
                    "attempt timestamp must be an offset-aware ISO 8601 instant",
                    reference=attempt_reference,
                    logical_execution_id=logical_id,
                ) from error
            target = attempt["response"] is not None
            infrastructure = attempt["infrastructure_failure"] is not None
            if target == infrastructure:
                raise _error(
                    "attempt-terminal-ambiguous",
                    "attempt must contain exactly one target response or infrastructure failure",
                    reference=attempt_reference,
                    logical_execution_id=logical_id,
                )
            if target:
                validate_target_response(
                    self.repository_root,
                    attempt["response"],
                    logical_id,
                    reference=attempt_reference,
                )
                validate_response_against_plan(
                    attempt["response"],
                    planned_by_logical[logical_id],
                    reference=attempt_reference,
                )
            else:
                infrastructure_failure_count += 1
            attempt_logicals.add(logical_id)
            attempt_numbers.add(attempt_key)
            attempts_by_physical[physical_id] = attempt
            physical_logicals[physical_id] = logical_id
            artifact_digests.append(attempt_reference["sha256"])
        if attempt_logicals != planned:
            raise _error(
                "attempt-denominator-incomplete",
                "attempts do not cover the planned logical denominator",
                reference=reference,
            )

        observation_logicals: set[str] = set()
        observation_logical_by_content: dict[str, str] = {}
        observation_contents: set[str] = set()
        for observation_reference in stored_manifest["observations"]:
            logical_id = observation_reference.get("logical_execution_id")
            observation = self._artifact(
                observation_reference, "observations", logical_execution_id=logical_id
            )
            content_id = observation_reference.get("observation_content_id")
            physical_id = observation["physical_run_id"]
            attempt = attempts_by_physical.get(physical_id)
            if (
                observation["logical_execution_id"] != logical_id
                or observation["campaign_manifest_id"] != compiled["campaign_manifest_id"]
                or observation["observation_content_id"] != content_id
                or observation["observation_id"] != observation_reference.get("observation_id")
                or logical_id in observation_logicals
                or content_id in observation_contents
                or attempt is None
                or attempt["logical_execution_id"] != logical_id
                or attempt["response"] is None
                or canonical_bytes(attempt["response"])
                != canonical_bytes(observation["response"])
                or canonical_bytes(attempt["provenance"])
                != canonical_bytes(observation["provenance"])
            ):
                raise _error(
                    "observation-reconciliation-inconsistent",
                    "observation identity, attempt, response, or provenance does not reconcile",
                    reference=observation_reference,
                    logical_execution_id=logical_id,
                )
            body = {
                key: value for key, value in observation.items() if key != "observation_content_id"
            }
            if content_id != _content_id(
                self.repository_root,
                "observation-content",
                "observation-content-v1",
                body,
            ):
                raise _error(
                    "observation-identity-mismatch",
                    "observation content identity does not match",
                    reference=observation_reference,
                    logical_execution_id=logical_id,
                )
            validate_target_response(
                self.repository_root,
                observation["response"],
                logical_id,
                reference=observation_reference,
            )
            validate_response_against_plan(
                observation["response"],
                planned_by_logical[logical_id],
                reference=observation_reference,
            )
            observation_logicals.add(logical_id)
            observation_contents.add(content_id)
            observation_logical_by_content[content_id] = logical_id
            artifact_digests.append(observation_reference["sha256"])

        planned_by_shard = {
            item["shard_id"]: set(item["logical_execution_ids"])
            for item in compiled["shards"]
        }
        observed_shards: set[str] = set()
        sharded_observations: set[str] = set()
        for shard_reference in stored_manifest["result_shards"]:
            shard = self._artifact(shard_reference, "result-shards")
            shard_id = shard["shard_id"]
            if (
                shard_id != shard_reference.get("shard_id")
                or shard["result_shard_id"] != shard_reference.get("result_shard_id")
                or shard["campaign_manifest_id"] != compiled["campaign_manifest_id"]
                or shard_id not in planned_by_shard
                or shard_id in observed_shards
            ):
                raise _error(
                    "shard-identity-inconsistent",
                    "result shard reference or identity does not reconcile",
                    reference=shard_reference,
                )
            body = {
                key: value
                for key, value in shard.items()
                if key not in {"schema_version", "result_shard_id"}
            }
            if shard["result_shard_id"] != _content_id(
                self.repository_root, "result-shard", "result-shard-v1", body
            ):
                raise _error(
                    "shard-identity-mismatch",
                    "result shard content identity does not match",
                    reference=shard_reference,
                )
            try:
                shard_observation_logicals = {
                    observation_logical_by_content[item]
                    for item in shard["observation_content_ids"]
                }
                shard_physical_logicals = {
                    physical_logicals[item] for item in shard["physical_run_ids"]
                }
            except KeyError as error:
                raise _error(
                    "shard-artifact-unknown",
                    "result shard references an unknown artifact identity",
                    reference=shard_reference,
                ) from error
            planned_logicals = planned_by_shard[shard_id]
            if (
                set(shard["planned_logical_execution_ids"]) != planned_logicals
                or shard_physical_logicals != planned_logicals
                or not shard_observation_logicals.issubset(planned_logicals)
                or shard["complete"] != (shard_observation_logicals == planned_logicals)
            ):
                raise _error(
                    "shard-membership-inconsistent",
                    "result shard membership does not reconcile its plan",
                    reference=shard_reference,
                )
            observed_shards.add(shard_id)
            sharded_observations.update(shard["observation_content_ids"])
            artifact_digests.append(shard_reference["sha256"])
        if observed_shards != set(planned_by_shard) or sharded_observations != observation_contents:
            raise _error(
                "shard-set-inconsistent",
                "result shards do not reconcile the observation set",
                reference=reference,
            )
        if (
            hashlib.sha256(canonical_bytes(sorted(artifact_digests))).hexdigest()
            != stored_manifest["root_digest"]
        ):
            raise _error(
                "manifest-root-digest-mismatch",
                "evidence root digest does not match its artifacts",
                reference=reference,
            )
        if (
            stored_manifest["logical_execution_count"] != len(planned)
            or stored_manifest["accepted_observation_count"] != len(observation_contents)
            or stored_manifest["infrastructure_failure_count"]
            != infrastructure_failure_count
            or stored_manifest["complete"] != (observation_logicals == planned)
        ):
            raise _error(
                "manifest-count-inconsistent",
                "evidence manifest counts or completion state do not reconcile",
                reference=reference,
            )
