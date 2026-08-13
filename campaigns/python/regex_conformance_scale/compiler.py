"""Compile the 100K qualification into a compact manifest and immutable segments."""

from __future__ import annotations

from collections import Counter
import hashlib
import os
from pathlib import Path
import stat
from typing import Any

from regex_conformance_campaign.compiler import SCHEMA_FAMILY_ID
from regex_conformance_qualification.compiler import (
    REQUIRED_CATEGORIES,
    verify_compiled_qualification,
    verify_coverage_report,
)
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.identity import NamespaceRegistry, build_content_identity
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict
from regex_conformance_schema.profile import IdentityProfile
from regex_conformance_schema.schema import validate_instance


class ScaleCompileError(ValueError):
    """The six-figure campaign inputs do not form a closed deterministic plan."""


class _ContentIds:
    def __init__(self, root: Path) -> None:
        self.registry = NamespaceRegistry.load(
            root / "registries" / "identity" / "namespaces.v1.json"
        )
        self.profile = IdentityProfile.from_record(
            load_strict(
                root / "schemas" / "identity-profiles" / "campaign-content.v1.json"
            )
        )

    def build(self, namespace: str, kind: str, identity: Any) -> str:
        inner = {
            "artifact_kind": kind,
            "content_sha256": _digest(identity),
        }
        result = build_content_identity(
            registry=self.registry,
            profile=self.profile,
            namespace=namespace,
            identity_schema_family_id=SCHEMA_FAMILY_ID,
            identity_schema_version="1.0.0",
            identity=inner,
        )
        return str(result["content_id"])


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_source(root: Path, relative: str) -> Path:
    try:
        path = (root / relative).resolve(strict=True)
        path.relative_to(root)
    except (OSError, ValueError) as error:
        raise ScaleCompileError(
            f"scale source path is unsafe or absent: {relative}"
        ) from error
    if not stat.S_ISREG(path.stat().st_mode):
        raise ScaleCompileError(f"scale source is not a regular file: {relative}")
    return path


def _assert_pinned(root: Path, source: dict[str, Any], label: str) -> Path:
    path = _safe_source(root, source["path"])
    if _file_digest(path) != source["sha256"]:
        raise ScaleCompileError(f"{label} digest differs from the frozen definition")
    return path


def _request_template(request: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in request.items()
        if key not in {"correlation_id", "trace_reference"}
    }


def reconstruct_request(
    campaign_id: str,
    record: dict[str, Any],
    base_logical: dict[str, Any],
) -> dict[str, Any]:
    """Reconstruct an exact adapter request from one compact scale record."""

    if record["base_logical_execution_id"] != base_logical["logical_execution_id"]:
        raise ScaleCompileError("logical record references the wrong base template")
    template = _request_template(base_logical["request"])
    if _digest(template) != record["request_template_sha256"]:
        raise ScaleCompileError(
            "logical record request-template digest does not reconcile"
        )
    logical_id = record["logical_execution_id"]
    return {
        **template,
        "correlation_id": logical_id,
        "trace_reference": f"campaign:{campaign_id}:{logical_id}",
    }


def _source_digests(
    root: Path, definition_path: Path, definition: dict[str, Any]
) -> dict[str, str]:
    paths = {
        definition_path,
        _safe_source(root, definition["base_campaign"]["path"]),
        _safe_source(root, definition["base_coverage"]["path"]),
        _safe_source(root, definition["base_vectors"]["path"]),
        root / "campaigns" / "python" / "regex_conformance_scale" / "compiler.py",
        root
        / "campaigns"
        / "python"
        / "regex_conformance_qualification"
        / "compiler.py",
        root / "registries" / "identity" / "namespaces.v1.json",
        root / "schemas" / "identity-profiles" / "campaign-content.v1.json",
        root / "schemas" / "json" / "adapter-request.schema.json",
        root / "schemas" / "json" / "logical-execution-segment.schema.json",
        root / "schemas" / "json" / "scale-campaign-definition.schema.json",
        root / "schemas" / "json" / "scale-campaign-plan.schema.json",
        root / "schemas" / "json" / "scale-qualification-design-report.schema.json",
        root
        / "schemas"
        / "tooling"
        / "python"
        / "regex_conformance_schema"
        / "campaigns.py",
        root
        / "schemas"
        / "tooling"
        / "python"
        / "regex_conformance_schema"
        / "identity.py",
        root
        / "schemas"
        / "tooling"
        / "python"
        / "regex_conformance_schema"
        / "jsonio.py",
        root
        / "schemas"
        / "tooling"
        / "python"
        / "regex_conformance_schema"
        / "profile.py",
        root / "tools" / "campaigns" / "compile_100k_qualification.py",
    }
    return {
        path.relative_to(root).as_posix(): _file_digest(path) for path in sorted(paths)
    }


def _direct_external_directory(path: Path, external_root: Path) -> None:
    try:
        path.mkdir()
    except FileExistsError:
        pass
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(external_root)
    except (OSError, ValueError) as error:
        raise ScaleCompileError(
            "scale segment directory is invalid or escapes its root"
        ) from error
    if path.absolute() != resolved or not resolved.is_dir():
        raise ScaleCompileError("scale segment directories must be direct directories")


def _external_root(repository_root: Path, requested: Path) -> Path:
    raw = requested.expanduser().absolute()
    candidate = raw.resolve(strict=False)
    try:
        candidate.relative_to(repository_root)
    except ValueError:
        pass
    else:
        raise ScaleCompileError(
            "large logical-execution segments must remain outside Git"
        )
    try:
        candidate.mkdir()
    except FileExistsError:
        pass
    if raw != candidate or not candidate.is_dir():
        raise ScaleCompileError("scale segment root must be a direct directory")
    return candidate


def _write_segment(
    external_root: Path, reference: dict[str, Any], encoded: bytes
) -> None:
    category = external_root / "logical-execution-segments"
    _direct_external_directory(category, external_root)
    directory = category / "sha256"
    _direct_external_directory(directory, external_root)
    path = external_root / reference["relative_path"]
    if path.exists():
        if path.absolute() != path.resolve(strict=True) or not stat.S_ISREG(
            path.stat().st_mode
        ):
            raise ScaleCompileError("existing scale segment path is indirect")
        if path.read_bytes() != encoded:
            raise ScaleCompileError(
                "content-addressed scale segment contains conflicting bytes"
            )
        return
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory_descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    if path.read_bytes() != encoded:
        raise ScaleCompileError("scale segment failed read-after-write verification")


def _compile(root: Path) -> tuple[dict[str, Any], list[tuple[dict[str, Any], bytes]]]:
    root = root.resolve(strict=True)
    definition_path = root / "campaigns" / "definitions" / "100k-qualification.v1.json"
    definition = load_strict(definition_path)
    validate_instance(
        definition,
        load_strict(
            root / "schemas" / "json" / "scale-campaign-definition.schema.json"
        ),
        source=str(definition_path),
    )
    identifiers = _ContentIds(root)
    parsed_definition = identifiers.registry.validate(
        definition["campaign_definition_id"]
    )
    parsed_campaign = identifiers.registry.validate(definition["campaign_id"])
    if (parsed_definition.namespace, parsed_definition.mode) != (
        "campaign-definition",
        "u7",
    ):
        raise ScaleCompileError(
            "scale campaign definition requires an assigned identifier"
        )
    if (parsed_campaign.namespace, parsed_campaign.mode) != ("campaign", "u7"):
        raise ScaleCompileError(
            "scale campaign occurrence requires an assigned identifier"
        )

    base_path = _assert_pinned(root, definition["base_campaign"], "base campaign")
    coverage_path = _assert_pinned(root, definition["base_coverage"], "base coverage")
    vector_path = _assert_pinned(root, definition["base_vectors"], "base vectors")
    base = load_strict(base_path)
    coverage = load_strict(coverage_path)
    verify_compiled_qualification(root, base)
    verify_coverage_report(root, base, coverage)
    if (
        base["campaign_manifest_id"]
        != definition["base_campaign"]["campaign_manifest_id"]
    ):
        raise ScaleCompileError(
            "base campaign identity differs from the frozen definition"
        )

    base_logicals = sorted(
        base["logical_executions"], key=lambda item: item["logical_execution_id"]
    )
    obligations = definition["stress_obligations"]
    if len(base_logicals) < obligations["minimum_base_logical_templates"]:
        raise ScaleCompileError(
            "base campaign lacks the required logical-template diversity"
        )
    selections = sorted({item["selection_key"] for item in base_logicals})
    if len(selections) < obligations["minimum_profile_coordinates"]:
        raise ScaleCompileError("base campaign lacks the required profile diversity")
    required_categories = obligations["required_categories"]
    if (
        required_categories != sorted(required_categories)
        or tuple(required_categories) != REQUIRED_CATEGORIES
    ):
        raise ScaleCompileError(
            "required scale categories differ from the certified P18 obligations"
        )

    vectors = load_strict(vector_path)["vectors"]
    vector_categories: dict[str, list[str]] = {}
    for vector in vectors:
        revision = identifiers.build(
            "vector-revision", "qualification-vector-revision", vector
        )
        vector_categories[revision] = vector["qualification_categories"]
    if any(
        item["vector_revision_id"] not in vector_categories for item in base_logicals
    ):
        raise ScaleCompileError(
            "base logical execution references an unknown vector revision"
        )

    definition_revision_id = identifiers.build(
        "campaign-definition-revision", "scale-campaign-definition-v1", definition
    )
    target = definition["logical_execution_target"]
    quotient, remainder = divmod(target, len(base_logicals))
    records_by_selection: dict[str, list[dict[str, Any]]] = {
        key: [] for key in selections
    }
    base_counts: Counter[str] = Counter()
    profile_counts: Counter[str] = Counter()
    vector_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    for offset, base_logical in enumerate(base_logicals):
        quota = quotient + (1 if offset < remainder else 0)
        base_id = base_logical["logical_execution_id"]
        template_digest = _digest(_request_template(base_logical["request"]))
        for planned_repetition in range(1, quota + 1):
            identity = {
                "base_campaign_manifest_id": base["campaign_manifest_id"],
                "base_logical_execution_id": base_id,
                "campaign_definition_revision_id": definition_revision_id,
                "campaign_id": definition["campaign_id"],
                "planned_repetition": planned_repetition,
                "purpose": "operational-scale-qualification-v1",
                "request_template_sha256": template_digest,
            }
            logical_id = identifiers.build(
                "logical-execution", "scale-logical-execution-v1", identity
            )
            record = {
                "base_logical_execution_id": base_id,
                "logical_execution_id": logical_id,
                "planned_repetition": planned_repetition,
                "profile_id": base_logical["profile_id"],
                "request_template_sha256": template_digest,
                "selection_key": base_logical["selection_key"],
                "target_release_id": base_logical["target_release_id"],
                "vector_revision_id": base_logical["vector_revision_id"],
            }
            records_by_selection[record["selection_key"]].append(record)
            base_counts[base_id] += 1
            profile_counts[record["selection_key"]] += 1
            vector_counts[record["vector_revision_id"]] += 1
            for category in vector_categories[record["vector_revision_id"]]:
                category_counts[category] += 1

    ordered_records: list[dict[str, Any]] = []
    for selection_key in selections:
        records_by_selection[selection_key].sort(
            key=lambda item: item["logical_execution_id"]
        )
        ordered_records.extend(records_by_selection[selection_key])
    logical_ids = [item["logical_execution_id"] for item in ordered_records]
    if len(logical_ids) != target or len(logical_ids) != len(set(logical_ids)):
        raise ScaleCompileError("scale logical denominator is incomplete or colliding")
    if max(base_counts.values()) - min(base_counts.values()) > 1:
        raise ScaleCompileError("balanced repetition quotas differ by more than one")
    if set(category_counts) != set(required_categories) or any(
        category_counts[key] == 0 for key in required_categories
    ):
        raise ScaleCompileError("scale workload does not cover every required category")

    maximum = definition["shard_policy"]["maximum_execution_count"]
    artifacts: list[tuple[dict[str, Any], bytes]] = []
    for selection_key in selections:
        members = records_by_selection[selection_key]
        for offset in range(0, len(members), maximum):
            chunk = members[offset : offset + maximum]
            chunk_ids = [item["logical_execution_id"] for item in chunk]
            shard_body = {
                "algorithm": definition["shard_policy"]["algorithm"],
                "logical_execution_ids": chunk_ids,
                "maximum_execution_count": maximum,
                "selection_key": selection_key,
            }
            shard_id = identifiers.build("shard", "scale-locality-shard-v1", shard_body)
            payload = {
                "logical_executions": chunk,
                "schema_version": "logical-execution-segment.v1",
                "selection_key": selection_key,
                "shard_id": shard_id,
            }
            encoded = canonical_bytes(payload) + b"\n"
            digest = hashlib.sha256(encoded).hexdigest()
            reference = {
                "category": "logical-execution-segments",
                "first_logical_execution_id": chunk_ids[0],
                "last_logical_execution_id": chunk_ids[-1],
                "logical_execution_count": len(chunk_ids),
                "logical_execution_ids_sha256": _digest(chunk_ids),
                "relative_path": f"logical-execution-segments/sha256/{digest}.json",
                "selection_key": selection_key,
                "sha256": digest,
                "shard_id": shard_id,
                "size_bytes": len(encoded),
            }
            artifacts.append((reference, encoded))
    artifacts.sort(key=lambda item: item[0]["shard_id"])
    shard_references = [item[0] for item in artifacts]
    if any(
        interruption["after_committed_shards"] >= len(shard_references)
        for interruption in definition["planned_interruptions"]
    ):
        raise ScaleCompileError("planned interruption falls outside the shard schedule")

    distribution = {
        "base_logical_templates": [
            {"key": key, "logical_execution_count": base_counts[key]}
            for key in sorted(base_counts)
        ],
        "categories": [
            {"key": key, "logical_execution_count": category_counts[key]}
            for key in sorted(category_counts)
        ],
        "profiles": [
            {"key": key, "logical_execution_count": profile_counts[key]}
            for key in sorted(profile_counts)
        ],
        "vectors": [
            {"key": key, "logical_execution_count": vector_counts[key]}
            for key in sorted(vector_counts)
        ],
    }
    denominator = {
        "candidate_count": target,
        "excluded_count": 0,
        "included_count": target,
        "invalid_count": 0,
        "unresolved_count": 0,
    }
    logical_index = {
        "logical_execution_count": target,
        "ordered_ids_sha256": _digest(logical_ids),
        "ordering": definition["expansion_policy"]["logical_order"],
        "segment_count": len(shard_references),
    }
    source_digests = _source_digests(root, definition_path, definition)
    manifest_body = {
        "attempt_policy": definition["attempt_policy"],
        "base_campaign": definition["base_campaign"],
        "campaign_definition_revision_id": definition_revision_id,
        "campaign_id": definition["campaign_id"],
        "classification": definition["classification"],
        "denominator": denominator,
        "expansion_policy": definition["expansion_policy"],
        "logical_execution_index": logical_index,
        "planned_interruptions": definition["planned_interruptions"],
        "segment_authority": "immutable-content-addressed-external-v1",
        "shard_policy": definition["shard_policy"],
        "shards": shard_references,
        "source_digests": source_digests,
        "stress_obligations": definition["stress_obligations"],
        "workload_distribution": distribution,
    }
    manifest_id = identifiers.build(
        "campaign-manifest", "scale-campaign-manifest-v1", manifest_body
    )
    plan = {
        "base_campaign": definition["base_campaign"],
        "campaign_definition_id": definition["campaign_definition_id"],
        "campaign_definition_revision_id": definition_revision_id,
        "campaign_id": definition["campaign_id"],
        "campaign_manifest": {"campaign_manifest_id": manifest_id, **manifest_body},
        "campaign_manifest_id": manifest_id,
        "classification": definition["classification"],
        "denominator": denominator,
        "logical_execution_index": logical_index,
        "planned_interruptions": definition["planned_interruptions"],
        "schema_version": "scale-campaign-plan.v1",
        "shards": shard_references,
        "source_digests": source_digests,
        "workload_distribution": distribution,
    }
    return plan, artifacts


def compile_scale_plan(
    root: Path,
    *,
    segment_root: Path | None = None,
    _verify: bool = True,
) -> dict[str, Any]:
    plan, artifacts = _compile(root)
    if _verify:
        verify_scale_plan(root, plan)
    if segment_root is not None:
        external = _external_root(root.resolve(strict=True), segment_root)
        for reference, encoded in artifacts:
            _write_segment(external, reference, encoded)
        if _verify:
            verify_materialized_segments(root, plan, external)
    return plan


def verify_scale_plan(root: Path, plan: dict[str, Any]) -> None:
    root = root.resolve(strict=True)
    validate_instance(
        plan,
        load_strict(root / "schemas" / "json" / "scale-campaign-plan.schema.json"),
        source="100K scale campaign plan",
    )
    if plan["campaign_manifest_id"] != plan["campaign_manifest"].get(
        "campaign_manifest_id"
    ):
        raise ScaleCompileError("scale campaign manifest identities disagree")
    manifest_body = {
        key: value
        for key, value in plan["campaign_manifest"].items()
        if key != "campaign_manifest_id"
    }
    actual_manifest_id = _ContentIds(root).build(
        "campaign-manifest", "scale-campaign-manifest-v1", manifest_body
    )
    if actual_manifest_id != plan["campaign_manifest_id"]:
        raise ScaleCompileError(
            "scale campaign manifest content identity does not match"
        )
    if plan["campaign_manifest"].get("shards") != plan["shards"]:
        raise ScaleCompileError("scale plan and manifest shard references disagree")
    if sum(item["logical_execution_count"] for item in plan["shards"]) != 100000:
        raise ScaleCompileError("scale shard counts do not reconcile the denominator")
    if len({item["shard_id"] for item in plan["shards"]}) != len(plan["shards"]):
        raise ScaleCompileError("scale shard identities collide")
    for relative, expected_digest in plan["source_digests"].items():
        if _file_digest(_safe_source(root, relative)) != expected_digest:
            raise ScaleCompileError(f"scale source digest changed for {relative}")
    expected, _artifacts = _compile(root)
    if canonical_bytes(plan) != canonical_bytes(expected):
        raise ScaleCompileError("scale campaign differs from deterministic compilation")


def verify_materialized_segments(
    root: Path,
    plan: dict[str, Any],
    segment_root: Path,
) -> None:
    root = root.resolve(strict=True)
    external = _external_root(root, segment_root)
    validate_instance(
        plan,
        load_strict(root / "schemas" / "json" / "scale-campaign-plan.schema.json"),
        source="100K scale campaign plan",
    )
    manifest_body = {
        key: value
        for key, value in plan["campaign_manifest"].items()
        if key != "campaign_manifest_id"
    }
    actual_manifest_id = _ContentIds(root).build(
        "campaign-manifest", "scale-campaign-manifest-v1", manifest_body
    )
    if (
        plan["campaign_manifest_id"]
        != plan["campaign_manifest"].get("campaign_manifest_id")
        or actual_manifest_id != plan["campaign_manifest_id"]
    ):
        raise ScaleCompileError(
            "segment store is being verified against a substituted plan"
        )
    expected_paths: set[Path] = set()
    segment_schema = load_strict(
        root / "schemas" / "json" / "logical-execution-segment.schema.json"
    )
    for reference in plan["shards"]:
        path = external / reference["relative_path"]
        expected_paths.add(path)
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(external)
        except (OSError, ValueError) as error:
            raise ScaleCompileError(
                "scale segment is missing or escapes its root"
            ) from error
        if path.absolute() != resolved or not stat.S_ISREG(path.stat().st_mode):
            raise ScaleCompileError("scale segment must be a direct regular file")
        if path.stat().st_nlink != 1:
            raise ScaleCompileError("scale segment must not be hard-linked")
        encoded = path.read_bytes()
        if len(encoded) != reference["size_bytes"]:
            raise ScaleCompileError("scale segment size differs from its manifest")
        if hashlib.sha256(encoded).hexdigest() != reference["sha256"]:
            raise ScaleCompileError("scale segment digest differs from its manifest")
        try:
            payload = loads_strict(encoded.decode("utf-8"))
        except (ConformanceDataError, UnicodeError) as error:
            raise ScaleCompileError("scale segment is not strict UTF-8 JSON") from error
        validate_instance(payload, segment_schema, source=str(path))
        if canonical_bytes(payload) + b"\n" != encoded:
            raise ScaleCompileError("scale segment is noncanonical")
    directory = external / "logical-execution-segments" / "sha256"
    actual_paths = set(directory.iterdir())
    if actual_paths != expected_paths:
        raise ScaleCompileError(
            "scale segment store contains missing or unmanifested objects"
        )
    expected_plan, _artifacts = _compile(root)
    if canonical_bytes(plan) != canonical_bytes(expected_plan):
        raise ScaleCompileError(
            "segment store is being verified against a substituted plan"
        )


def _design_report(root: Path, plan: dict[str, Any]) -> dict[str, Any]:
    definition = load_strict(
        root / "campaigns" / "definitions" / "100k-qualification.v1.json"
    )
    report = {
        "base_logical_template_count": len(
            plan["workload_distribution"]["base_logical_templates"]
        ),
        "campaign_manifest_id": plan["campaign_manifest_id"],
        "classification": plan["classification"],
        "logical_execution_count": plan["denominator"]["included_count"],
        "maximum_shard_size": definition["shard_policy"]["maximum_execution_count"],
        "planned_interruptions": plan["planned_interruptions"],
        "profile_coordinate_count": len(plan["workload_distribution"]["profiles"]),
        "required_categories": definition["stress_obligations"]["required_categories"],
        "safety_contract": {
            "attempts_append_only": True,
            "infrastructure_failure_excluded": True,
            "large_segments_outside_git": True,
            "logical_physical_identity_separate": True,
            "semantic_authority": False,
        },
        "schema_version": "scale-qualification-design-report.v1",
        "shard_count": len(plan["shards"]),
        "workload_distribution": plan["workload_distribution"],
    }
    validate_instance(
        report,
        load_strict(
            root / "schemas" / "json" / "scale-qualification-design-report.schema.json"
        ),
        source="100K qualification design report",
    )
    return report


def build_design_report(root: Path, plan: dict[str, Any]) -> dict[str, Any]:
    verify_scale_plan(root, plan)
    return _design_report(root, plan)


def verify_design_report(
    root: Path, plan: dict[str, Any], report: dict[str, Any]
) -> None:
    verify_scale_plan(root, plan)
    validate_instance(
        report,
        load_strict(
            root / "schemas" / "json" / "scale-qualification-design-report.schema.json"
        ),
        source="100K qualification design report",
    )
    if canonical_bytes(report) != canonical_bytes(_design_report(root, plan)):
        raise ScaleCompileError(
            "100K design report differs from the frozen campaign plan"
        )
