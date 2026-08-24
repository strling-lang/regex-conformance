"""Validation and deterministic indexing for downstream Coverage Shards."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Callable

from .errors import ConformanceDataError
from .jsonio import canonical_bytes, load_strict, loads_strict


ValidateInstance = Callable[..., None]
_CHECKPOINT_NAME = re.compile(r"^coverage-shard-([0-9]{4})\.v1\.json$")


class DownstreamProtocolError(ConformanceDataError):
    """A tracked downstream artifact violates the checkpoint protocol."""

    def __init__(self, message: str, *, path: str = "$") -> None:
        super().__init__("downstream-protocol-invalid", message, path=path)


def _digest(value: Any, excluded_field: str) -> str:
    body = deepcopy(value)
    body.pop(excluded_field, None)
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def _relative_path(root: Path, relative: str) -> Path:
    logical = PurePosixPath(relative)
    if (
        logical.is_absolute()
        or not logical.parts
        or any(part in {"", ".", ".."} for part in logical.parts)
        or "\\" in relative
    ):
        raise DownstreamProtocolError("artifact path is not a safe repository-relative path", path=relative)
    candidate = root.joinpath(*logical.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise DownstreamProtocolError("artifact path is missing or escapes the repository", path=relative) from error
    if candidate.absolute() != resolved or not candidate.is_file():
        raise DownstreamProtocolError("artifact path must resolve directly to a regular file", path=relative)
    return candidate


def _load_json_bytes(root: Path, relative: str, *, canonical: bool) -> tuple[dict[str, Any], bytes]:
    path = _relative_path(root, relative)
    raw = path.read_bytes()
    try:
        value = loads_strict(raw.decode("utf-8"))
    except (ConformanceDataError, UnicodeError) as error:
        raise DownstreamProtocolError("artifact is not strict UTF-8 JSON", path=relative) from error
    if not isinstance(value, dict):
        raise DownstreamProtocolError("artifact root must be a JSON object", path=relative)
    if canonical and raw != canonical_bytes(value) + b"\n":
        raise DownstreamProtocolError("artifact bytes are not canonical JSON plus one newline", path=relative)
    return value, raw


def _assert_file_sha(raw: bytes, expected: str, relative: str) -> None:
    if hashlib.sha256(raw).hexdigest() != expected:
        raise DownstreamProtocolError("artifact SHA-256 differs from its reference", path=relative)


def _collect_strings(value: Any, key: str) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for member_key, member in value.items():
            if member_key == key and isinstance(member, str):
                found.add(member)
            found.update(_collect_strings(member, key))
    elif isinstance(value, list):
        for member in value:
            found.update(_collect_strings(member, key))
    return found


def _profile_release_pairs(value: Any) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    if isinstance(value, dict):
        profile_id = value.get("profile_id")
        if isinstance(profile_id, str):
            for release_id in _collect_strings(value, "release_id"):
                pairs.add((profile_id, release_id))
        for member in value.values():
            pairs.update(_profile_release_pairs(member))
    elif isinstance(value, list):
        for member in value:
            pairs.update(_profile_release_pairs(member))
    return pairs


def _validate_projection_digest(projection: dict[str, Any], relative: str) -> None:
    if projection["projection_digest_sha256"] != _digest(projection, "projection_digest_sha256"):
        raise DownstreamProtocolError("projection content digest differs", path=relative)


def _validate_source_reference(
    root: Path, reference: dict[str, Any]
) -> dict[str, Any]:
    value, raw = _load_json_bytes(root, reference["relative_path"], canonical=False)
    _assert_file_sha(raw, reference["sha256"], reference["relative_path"])
    if reference["artifact_id"] not in _collect_strings(value, "environment_recipe_id") | _collect_strings(value, "recipe_id") | _collect_strings(value, "adapter_release_manifest_id") | _collect_strings(value, "adapter_id"):
        raise DownstreamProtocolError(
            "Lab source reference identity is absent from the referenced artifact",
            path=reference["relative_path"],
        )
    return value


def _validate_lab_projection(
    root: Path,
    projection: dict[str, Any],
    checkpoint: dict[str, Any],
    operations: set[str],
    systems: set[str],
) -> None:
    relative = checkpoint["lab_projection"]["relative_path"]
    _validate_projection_digest(projection, relative)
    expected_id = f"{checkpoint['checkpoint_id']}.lab.v1"
    expected_path = f"downstream/lab/{checkpoint['checkpoint_id']}.v1.json"
    if projection["projection_id"] != expected_id or checkpoint["lab_projection"]["projection_id"] != expected_id:
        raise DownstreamProtocolError("Lab projection identity differs from its Coverage Shard", path=relative)
    if relative != expected_path:
        raise DownstreamProtocolError("Lab projection path differs from its Coverage Shard", path=relative)
    if (
        projection["coverage_shard_id"] != checkpoint["checkpoint_id"]
        or projection["source_revision"] != checkpoint["source_revision"]
        or projection["semantic_snapshot_digest_sha256"]
        != checkpoint["semantic_snapshot"]["semantic_digest_sha256"]
    ):
        raise DownstreamProtocolError("Lab projection source bindings differ from its checkpoint", path=relative)
    coverage_by_profile = {
        item["profile_id"]: item for item in checkpoint["coverage"]["profiles"]
    }
    if len(coverage_by_profile) != len(checkpoint["coverage"]["profiles"]):
        raise DownstreamProtocolError("checkpoint profile identities collide", path=relative)
    projected_by_profile = {item["profile_id"]: item for item in projection["profiles"]}
    if len(projected_by_profile) != len(projection["profiles"]) or set(projected_by_profile) != set(coverage_by_profile):
        raise DownstreamProtocolError("Lab projection must represent every checkpoint profile exactly once", path=relative)
    for profile_id, profile in projected_by_profile.items():
        coverage = coverage_by_profile[profile_id]
        if (
            profile["release_id"] != coverage["release_id"]
            or profile["release_classification"] != coverage["release_classification"]
            or profile["lab_eligibility"]["eligible"] != coverage["lab_eligible"]
            or profile["system_id"] not in systems
        ):
            raise DownstreamProtocolError("Lab profile binding differs from checkpoint coverage", path=relative)
        if coverage["reproducibility_disposition"] == "explicitly-unreproducible":
            if profile["lab_eligibility"]["reason_code"] != "certified-unreproducible":
                raise DownstreamProtocolError("unreproducible Lab profile lacks the matching eligibility reason", path=relative)
        elif profile["lab_eligibility"]["reason_code"] == "certified-unreproducible":
            raise DownstreamProtocolError("reproducible Lab profile claims an unreproducible reason", path=relative)
        if not set(profile["operations"]).issubset(operations):
            raise DownstreamProtocolError("Lab profile references an unknown semantic operation", path=relative)
        for reference in profile["environment_recipe_refs"] + profile["adapter_refs"]:
            source = _validate_source_reference(root, reference)
            targets = _collect_strings(source, "target_profile_id")
            if targets and profile_id not in targets:
                raise DownstreamProtocolError("Lab source reference targets a different profile", path=reference["relative_path"])


def _validate_compatibility_outcome(
    outcome: dict[str, Any],
    *,
    profile_disposition: str,
    manifest_sha256: str,
    relative: str,
) -> None:
    applicable = outcome["applicable_obligation_count"]
    credited = outcome["credited_obligation_count"]
    not_applicable = outcome["governed_not_applicable_obligation_count"]
    state = outcome["coverage_state"]
    result = outcome["outcome"]
    evidence = outcome["evidence_manifest_sha256"]
    coordinate_evidence = outcome["evidence_coordinate_digest_sha256"]
    exclusion = outcome["governed_exclusion_digest_sha256"]
    limitation = outcome["limitation_digest_sha256"]
    if result == "conditional" and outcome["condition"] is None:
        raise DownstreamProtocolError("conditional compatibility requires an explicit condition", path=relative)
    if result != "conditional" and outcome["condition"] is not None:
        raise DownstreamProtocolError("only conditional compatibility may carry a condition", path=relative)
    if state == "certified":
        if (
            result not in {"supported", "unsupported", "conditional"}
            or applicable < 1
            or credited != applicable
            or not_applicable != 0
            or evidence != manifest_sha256
            or coordinate_evidence is None
            or exclusion is not None
            or limitation is not None
            or profile_disposition != "reproducibly-executable"
        ):
            raise DownstreamProtocolError("certified compatibility outcome lacks exact evidence credit", path=relative)
    elif state == "governed-not-applicable":
        if (
            result != "not-applicable"
            or applicable != 0
            or credited != 0
            or not_applicable < 1
            or exclusion is None
            or evidence is not None
            or coordinate_evidence is not None
            or limitation is not None
        ):
            raise DownstreamProtocolError("Not Applicable outcome lacks governed exclusion", path=relative)
    elif state == "certified-unreproducible":
        if (
            result != "unknown"
            or applicable < 1
            or credited != 0
            or not_applicable != 0
            or limitation is None
            or evidence is not None
            or coordinate_evidence is not None
            or exclusion is not None
            or profile_disposition != "explicitly-unreproducible"
        ):
            raise DownstreamProtocolError("Unknown is allowed only for an explicit certified unreproducible limitation", path=relative)
    else:  # pragma: no cover - schema validation rejects this first
        raise DownstreamProtocolError("unknown compatibility coverage state", path=relative)


def _validate_compatibility_projection(
    projection: dict[str, Any],
    checkpoint: dict[str, Any],
    features: set[str],
    operations: set[str],
) -> None:
    relative = checkpoint["compatibility_projection"]["relative_path"]
    _validate_projection_digest(projection, relative)
    expected_id = f"{checkpoint['checkpoint_id']}.compatibility.v1"
    expected_path = f"downstream/compatibility/{checkpoint['checkpoint_id']}.v1.json"
    if projection["projection_id"] != expected_id or checkpoint["compatibility_projection"]["projection_id"] != expected_id:
        raise DownstreamProtocolError("Compatibility projection identity differs from its Coverage Shard", path=relative)
    if relative != expected_path:
        raise DownstreamProtocolError("Compatibility projection path differs from its Coverage Shard", path=relative)
    if (
        projection["coverage_shard_id"] != checkpoint["checkpoint_id"]
        or projection["source_revision"] != checkpoint["source_revision"]
        or projection["semantic_snapshot_digest_sha256"]
        != checkpoint["semantic_snapshot"]["semantic_digest_sha256"]
    ):
        raise DownstreamProtocolError("Compatibility projection source bindings differ from its checkpoint", path=relative)
    coverage_by_profile = {
        item["profile_id"]: item for item in checkpoint["coverage"]["profiles"]
    }
    projected_by_profile = {item["profile_id"]: item for item in projection["profiles"]}
    if len(projected_by_profile) != len(projection["profiles"]) or set(projected_by_profile) != set(coverage_by_profile):
        raise DownstreamProtocolError("Compatibility projection must represent every checkpoint profile exactly once", path=relative)
    for profile_id, profile in projected_by_profile.items():
        coverage = coverage_by_profile[profile_id]
        if (
            profile["release_id"] != coverage["release_id"]
            or profile["release_classification"] != coverage["release_classification"]
            or profile["reproducibility_disposition"] != coverage["reproducibility_disposition"]
            or not coverage["compatibility_published"]
        ):
            raise DownstreamProtocolError("Compatibility profile binding differs from checkpoint coverage", path=relative)
        keys: set[tuple[str, str]] = set()
        totals = {"applicable": 0, "credited": 0, "not_applicable": 0, "non_executable": 0}
        for outcome in profile["outcomes"]:
            key = (outcome["feature_id"], outcome["operation_id"])
            if key in keys:
                raise DownstreamProtocolError("Compatibility feature-operation outcome is duplicated", path=relative)
            keys.add(key)
            if outcome["feature_id"] not in features or outcome["operation_id"] not in operations:
                raise DownstreamProtocolError("Compatibility outcome is outside the frozen semantic snapshot", path=relative)
            _validate_compatibility_outcome(
                outcome,
                profile_disposition=profile["reproducibility_disposition"],
                manifest_sha256=checkpoint["evidence_manifest"]["manifest_sha256"],
                relative=relative,
            )
            totals["applicable"] += outcome["applicable_obligation_count"]
            totals["credited"] += outcome["credited_obligation_count"]
            totals["not_applicable"] += outcome["governed_not_applicable_obligation_count"]
            if outcome["coverage_state"] == "certified-unreproducible":
                totals["non_executable"] += outcome["applicable_obligation_count"]
        expected = {
            "applicable": coverage["planned_applicable_coordinate_count"],
            "credited": coverage["credited_coordinate_count"],
            "not_applicable": coverage["governed_not_applicable_coordinate_count"],
            "non_executable": coverage["governed_non_executable_coordinate_count"],
        }
        if totals != expected:
            raise DownstreamProtocolError("Compatibility outcomes do not reconcile checkpoint coordinates", path=relative)


def _validate_checkpoint(
    root: Path,
    checkpoint: dict[str, Any],
    raw: bytes,
    relative: str,
    expected_sequence: int,
    previous: dict[str, Any] | None,
    schemas: dict[str, dict[str, Any]],
    validate_instance: ValidateInstance,
) -> dict[str, Any]:
    validate_instance(checkpoint, schemas["checkpoint"], source=relative)
    expected_id = f"coverage-shard-{expected_sequence:04d}"
    expected_relative = f"downstream/checkpoints/{expected_id}.v1.json"
    if checkpoint["sequence"] != expected_sequence or checkpoint["checkpoint_id"] != expected_id or relative != expected_relative:
        raise DownstreamProtocolError("checkpoint sequence, identity, and path are not monotonic", path=relative)
    if checkpoint["checkpoint_digest_sha256"] != _digest(checkpoint, "checkpoint_digest_sha256"):
        raise DownstreamProtocolError("checkpoint content digest differs", path=relative)
    if previous is None:
        if checkpoint["previous_checkpoint"] is not None:
            raise DownstreamProtocolError("first checkpoint must have no predecessor", path=relative)
    else:
        expected_previous = {
            "checkpoint_digest_sha256": previous["checkpoint_digest_sha256"],
            "checkpoint_id": previous["checkpoint_id"],
            "relative_path": f"downstream/checkpoints/{previous['checkpoint_id']}.v1.json",
        }
        if checkpoint["previous_checkpoint"] != expected_previous:
            raise DownstreamProtocolError("checkpoint predecessor does not match the sealed chain", path=relative)

    semantic, _ = _load_json_bytes(root, checkpoint["semantic_snapshot"]["relative_path"], canonical=False)
    semantic_digest = checkpoint["semantic_snapshot"]["semantic_digest_sha256"]
    if semantic.get("corpus_digest_sha256") != semantic_digest:
        raise DownstreamProtocolError("checkpoint semantic digest differs from the frozen snapshot", path=relative)
    features = _collect_strings(semantic.get("features", []), "feature_id")
    operations = _collect_strings(semantic.get("operations", []), "operation_id")

    profile_snapshot, profile_snapshot_raw = _load_json_bytes(root, checkpoint["profile_snapshot"]["relative_path"], canonical=False)
    _assert_file_sha(profile_snapshot_raw, checkpoint["profile_snapshot"]["sha256"], checkpoint["profile_snapshot"]["relative_path"])
    known_profile_release_pairs = _profile_release_pairs(profile_snapshot)
    known_systems = _collect_strings(profile_snapshot, "system_id")

    profiles = checkpoint["coverage"]["profiles"]
    profile_keys = [(item["profile_id"], item["release_id"]) for item in profiles]
    if len(profile_keys) != len(set(profile_keys)):
        raise DownstreamProtocolError("checkpoint profile-release coverage is duplicated", path=relative)
    totals = {
        "profile_count": len(profiles),
        "planned_applicable_coordinate_count": 0,
        "credited_coordinate_count": 0,
        "governed_non_executable_coordinate_count": 0,
        "governed_not_applicable_coordinate_count": 0,
        "unexpected_skip_count": 0,
        "lab_eligible_profile_count": 0,
        "compatibility_published_profile_count": 0,
    }
    for profile in profiles:
        if (profile["profile_id"], profile["release_id"]) not in known_profile_release_pairs:
            raise DownstreamProtocolError("checkpoint profile or release is absent from its frozen profile snapshot", path=relative)
        planned = profile["planned_applicable_coordinate_count"]
        credited = profile["credited_coordinate_count"]
        non_executable = profile["governed_non_executable_coordinate_count"]
        if planned != credited + non_executable:
            raise DownstreamProtocolError("planned coordinates do not reconcile credited and governed non-executable coordinates", path=relative)
        if profile["reproducibility_disposition"] == "reproducibly-executable":
            if non_executable != 0 or profile["limitation_digest_sha256"] is not None:
                raise DownstreamProtocolError("executable profile carries an unreproducible disposition", path=relative)
        elif credited != 0 or non_executable != planned or profile["limitation_digest_sha256"] is None or profile["lab_eligible"]:
            raise DownstreamProtocolError("unreproducible profile is not fully and explicitly dispositioned", path=relative)
        totals["planned_applicable_coordinate_count"] += planned
        totals["credited_coordinate_count"] += credited
        totals["governed_non_executable_coordinate_count"] += non_executable
        totals["governed_not_applicable_coordinate_count"] += profile["governed_not_applicable_coordinate_count"]
        totals["lab_eligible_profile_count"] += int(profile["lab_eligible"])
        totals["compatibility_published_profile_count"] += int(profile["compatibility_published"])
    if totals != checkpoint["coverage"]["counts"]:
        raise DownstreamProtocolError("checkpoint aggregate counts do not reconcile profile coverage", path=relative)

    manifest_key_digest = checkpoint["evidence_manifest"]["manifest_object_key"].rsplit("/", 1)[-1][:-5]
    if manifest_key_digest != checkpoint["evidence_manifest"]["manifest_sha256"]:
        raise DownstreamProtocolError("evidence manifest object key is not content-addressed by its SHA-256", path=relative)

    lab, lab_raw = _load_json_bytes(root, checkpoint["lab_projection"]["relative_path"], canonical=True)
    compatibility, compatibility_raw = _load_json_bytes(root, checkpoint["compatibility_projection"]["relative_path"], canonical=True)
    _assert_file_sha(lab_raw, checkpoint["lab_projection"]["sha256"], checkpoint["lab_projection"]["relative_path"])
    _assert_file_sha(compatibility_raw, checkpoint["compatibility_projection"]["sha256"], checkpoint["compatibility_projection"]["relative_path"])
    validate_instance(lab, schemas["lab"], source=checkpoint["lab_projection"]["relative_path"])
    validate_instance(compatibility, schemas["compatibility"], source=checkpoint["compatibility_projection"]["relative_path"])
    _validate_lab_projection(root, lab, checkpoint, operations, known_systems)
    _validate_compatibility_projection(compatibility, checkpoint, features, operations)
    return {
        "checkpoint_digest_sha256": checkpoint["checkpoint_digest_sha256"],
        "checkpoint_id": checkpoint["checkpoint_id"],
        "checkpoint_sha256": hashlib.sha256(raw).hexdigest(),
        "relative_path": relative,
        "sequence": checkpoint["sequence"],
        "source_revision": checkpoint["source_revision"],
    }


def build_checkpoint_index(root: Path, *, validate_instance: ValidateInstance) -> dict[str, Any]:
    """Rebuild the complete monotonic index from immutable checkpoint files."""

    root = root.resolve(strict=True)
    schema_root = root / "schemas" / "json"
    schemas = {
        "checkpoint": load_strict(schema_root / "coverage-shard-checkpoint.schema.json"),
        "compatibility": load_strict(schema_root / "downstream-compatibility-projection.schema.json"),
        "lab": load_strict(schema_root / "downstream-lab-projection.schema.json"),
    }
    checkpoint_root = root / "downstream" / "checkpoints"
    paths = sorted(checkpoint_root.glob("coverage-shard-*.v1.json"))
    entries: list[dict[str, Any]] = []
    previous: dict[str, Any] | None = None
    covered_profiles: set[tuple[str, str]] = set()
    for sequence, path in enumerate(paths, start=1):
        match = _CHECKPOINT_NAME.fullmatch(path.name)
        if match is None or int(match.group(1)) != sequence:
            raise DownstreamProtocolError("checkpoint files must form a contiguous sequence starting at 0001", path=path.as_posix())
        relative = path.relative_to(root).as_posix()
        checkpoint, raw = _load_json_bytes(root, relative, canonical=True)
        shard_profiles = {
            (item["profile_id"], item["release_id"])
            for item in checkpoint.get("coverage", {}).get("profiles", [])
            if isinstance(item, dict) and isinstance(item.get("profile_id"), str) and isinstance(item.get("release_id"), str)
        }
        if covered_profiles.intersection(shard_profiles):
            raise DownstreamProtocolError("a profile-release coordinate appears in more than one Coverage Shard", path=relative)
        entry = _validate_checkpoint(
            root,
            checkpoint,
            raw,
            relative,
            sequence,
            previous,
            schemas,
            validate_instance,
        )
        entries.append(entry)
        covered_profiles.update(shard_profiles)
        previous = checkpoint
    index = {
        "authority": {
            "append_only": True,
            "checkpoint_commit_only_sync_signal": True,
            "consumers_independent": True,
            "execution_shards_are_sync_signals": False,
        },
        "checkpoint_count": len(entries),
        "entries": entries,
        "latest_checkpoint_digest_sha256": None if previous is None else previous["checkpoint_digest_sha256"],
        "latest_checkpoint_id": None if previous is None else previous["checkpoint_id"],
        "schema_version": "coverage-shard-checkpoint-index.v1",
    }
    index["index_digest_sha256"] = _digest(index, "index_digest_sha256")
    return index


def _assert_append_only(previous: dict[str, Any], rebuilt: dict[str, Any]) -> None:
    if previous["checkpoint_count"] > rebuilt["checkpoint_count"]:
        raise DownstreamProtocolError("checkpoint index cannot shrink")
    prefix_length = previous["checkpoint_count"]
    if previous["entries"] != rebuilt["entries"][:prefix_length]:
        raise DownstreamProtocolError("previous checkpoint index entries are immutable")


def write_checkpoint_index(root: Path, *, validate_instance: ValidateInstance) -> dict[str, Any]:
    """Append new checkpoint entries to the tracked index without rewriting history."""

    root = root.resolve(strict=True)
    index_path = root / "downstream" / "checkpoints" / "index.v1.json"
    rebuilt = build_checkpoint_index(root, validate_instance=validate_instance)
    schema = load_strict(root / "schemas" / "json" / "coverage-shard-checkpoint-index.schema.json")
    validate_instance(rebuilt, schema, source="downstream/checkpoints/index.v1.json")
    if index_path.exists():
        previous, _ = _load_json_bytes(root, "downstream/checkpoints/index.v1.json", canonical=True)
        validate_instance(previous, schema, source="downstream/checkpoints/index.v1.json")
        if previous["index_digest_sha256"] != _digest(previous, "index_digest_sha256"):
            raise DownstreamProtocolError("tracked checkpoint index digest differs")
        _assert_append_only(previous, rebuilt)
    encoded = canonical_bytes(rebuilt) + b"\n"
    temporary = index_path.with_suffix(index_path.suffix + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, index_path)
    if index_path.read_bytes() != encoded:
        raise DownstreamProtocolError("checkpoint index failed read-after-write verification")
    return rebuilt


def load_and_validate_downstream_records(
    root: Path, *, validate_instance: ValidateInstance
) -> dict[str, int]:
    """Validate the tracked index against a deterministic full chain rebuild."""

    root = root.resolve(strict=True)
    relative = "downstream/checkpoints/index.v1.json"
    index, raw = _load_json_bytes(root, relative, canonical=True)
    schema = load_strict(root / "schemas" / "json" / "coverage-shard-checkpoint-index.schema.json")
    validate_instance(index, schema, source=relative)
    if index["index_digest_sha256"] != _digest(index, "index_digest_sha256"):
        raise DownstreamProtocolError("checkpoint index content digest differs", path=relative)
    rebuilt = build_checkpoint_index(root, validate_instance=validate_instance)
    if raw != canonical_bytes(rebuilt) + b"\n":
        raise DownstreamProtocolError("checkpoint index differs from deterministic chain reconstruction", path=relative)
    return {
        "coverage_shard_checkpoints": index["checkpoint_count"],
        "downstream_checkpoint_indexes": 1,
    }
