"""Compile the governed one-million qualification and its hosted partitions."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
from typing import Any, Iterable

from regex_conformance_qualification.compiler import (
    REQUIRED_CATEGORIES,
    verify_compiled_qualification,
    verify_coverage_report,
)
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict
from regex_conformance_schema.schema import validate_instance

from .compiler import (
    _ContentIds,
    _assert_pinned,
    _digest,
    _file_digest,
    _request_template,
    _safe_source,
)


DEFINITION_RELATIVE = "campaigns/million/definitions/million-qualification.v1.json"
PLAN_RELATIVE = "campaigns/million/compiled/million-qualification.v1.json"
LOGICAL_TARGET = 1_000_000


class MillionScaleCompileError(ValueError):
    """The million-scale master or partition plan is not closed."""


@dataclass(frozen=True)
class MillionCompilation:
    plan: dict[str, Any]
    artifacts: tuple[tuple[dict[str, Any], bytes], ...]
    logical_ids_by_shard: dict[str, tuple[str, ...]]


def _source_digests(root: Path, definition: dict[str, Any]) -> dict[str, str]:
    paths = {
        root / ".github/workflows/trusted-million-qualification.yml",
        root / DEFINITION_RELATIVE,
        _safe_source(root, definition["base_campaign"]["path"]),
        _safe_source(root, definition["base_coverage"]["path"]),
        _safe_source(root, definition["base_vectors"]["path"]),
        _safe_source(root, definition["scale_basis"]["path"]),
        root / "campaigns/python/regex_conformance_scale/compiler.py",
        root / "campaigns/python/regex_conformance_scale/million_compiler.py",
        root / "campaigns/python/regex_conformance_scale/distributed_execution.py",
        root / "campaigns/python/regex_conformance_scale/evidence_pack_v2.py",
        root / "campaigns/python/regex_conformance_scale/factorized_evidence.py",
        root / "campaigns/python/regex_conformance_scale/r2_publication.py",
        root / "schemas/json/logical-execution-segment.schema.json",
        root / "schemas/json/attempt-diagnostic-envelope-v2.schema.json",
        root / "schemas/json/evidence-pack-v2-manifest.schema.json",
        root / "schemas/json/million-scale-campaign-definition.schema.json",
        root / "schemas/json/million-scale-campaign-plan.schema.json",
        root / "schemas/json/million-scale-execution-report.schema.json",
        root / "schemas/json/million-scale-partition-plan.schema.json",
        root / "schemas/json/million-scale-partition-execution-report.schema.json",
        root / "schemas/json/million-scale-partition-publication-receipt.schema.json",
        root / "schemas/json/scale-evidence-manifest.schema.json",
        root / "schemas/json/scale-result-segment.schema.json",
        root / "schemas/json/raw-performance-samples-v2.schema.json",
        root / "schemas/identity-profiles/campaign-content.v1.json",
        root / "registries/identity/namespaces.v1.json",
        root / "tools/campaigns/compile_million_qualification.py",
        root / "tools/campaigns/finalize_million_qualification.py",
        root / "tools/campaigns/run_million_partition.py",
        root / "tools/campaigns/publish_million_partition.py",
        root / "tools/campaigns/recover_million_partition.py",
        root / "verifier/python/regex_conformance_verifier/scale_evidence.py",
    }
    missing = sorted(path.relative_to(root).as_posix() for path in paths if not path.is_file())
    if missing:
        raise MillionScaleCompileError(
            "million scale source set is incomplete: " + ",".join(missing)
        )
    return {
        path.relative_to(root).as_posix(): _file_digest(path)
        for path in sorted(paths)
    }


def _compile(root: Path) -> MillionCompilation:
    root = root.resolve(strict=True)
    definition_path = root / DEFINITION_RELATIVE
    definition = load_strict(definition_path)
    validate_instance(
        definition,
        load_strict(root / "schemas/json/million-scale-campaign-definition.schema.json"),
        source=str(definition_path),
    )
    identifiers = _ContentIds(root)
    for value, namespace in (
        (definition["campaign_definition_id"], "campaign-definition"),
        (definition["campaign_id"], "campaign"),
    ):
        parsed = identifiers.registry.validate(value)
        if (parsed.namespace, parsed.mode) != (namespace, "u7"):
            raise MillionScaleCompileError(
                f"million scale {namespace} requires an assigned identifier"
            )

    base_path = _assert_pinned(root, definition["base_campaign"], "base campaign")
    coverage_path = _assert_pinned(root, definition["base_coverage"], "base coverage")
    vector_path = _assert_pinned(root, definition["base_vectors"], "base vectors")
    scale_basis_path = _assert_pinned(
        root, definition["scale_basis"], "100K scale basis"
    )
    base = load_strict(base_path)
    coverage = load_strict(coverage_path)
    scale_basis = load_strict(scale_basis_path)
    verify_compiled_qualification(root, base)
    verify_coverage_report(root, base, coverage)
    if base["campaign_manifest_id"] != definition["base_campaign"]["campaign_manifest_id"]:
        raise MillionScaleCompileError("base campaign identity differs")
    from .compiler import verify_scale_plan

    verify_scale_plan(root, scale_basis)

    base_logicals = sorted(
        base["logical_executions"], key=lambda item: item["logical_execution_id"]
    )
    obligations = definition["stress_obligations"]
    if len(base_logicals) < obligations["minimum_base_logical_templates"]:
        raise MillionScaleCompileError("base campaign lacks logical-template diversity")
    selections = sorted({item["selection_key"] for item in base_logicals})
    if len(selections) < obligations["minimum_profile_coordinates"]:
        raise MillionScaleCompileError("base campaign lacks profile diversity")
    required_categories = obligations["required_categories"]
    if tuple(required_categories) != REQUIRED_CATEGORIES:
        raise MillionScaleCompileError("qualification categories differ")

    vectors = load_strict(vector_path)["vectors"]
    vector_categories: dict[str, list[str]] = {}
    for vector in vectors:
        revision = identifiers.build(
            "vector-revision", "qualification-vector-revision", vector
        )
        vector_categories[revision] = vector["qualification_categories"]
    if any(item["vector_revision_id"] not in vector_categories for item in base_logicals):
        raise MillionScaleCompileError("base logical references an unknown vector")

    definition_revision_id = identifiers.build(
        "campaign-definition-revision", "million-scale-campaign-definition-v1", definition
    )
    target = definition["logical_execution_target"]
    scale_basis_counts = {
        item["key"]: item["logical_execution_count"]
        for item in scale_basis["workload_distribution"]["base_logical_templates"]
    }
    if set(scale_basis_counts) != {
        item["logical_execution_id"] for item in base_logicals
    }:
        raise MillionScaleCompileError("100K scale basis template set differs")
    records_by_selection: dict[str, list[dict[str, Any]]] = {
        key: [] for key in selections
    }
    base_counts: Counter[str] = Counter()
    profile_counts: Counter[str] = Counter()
    vector_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    for base_logical in base_logicals:
        base_id = base_logical["logical_execution_id"]
        quota = scale_basis_counts[base_id] * 10
        template_digest = _digest(_request_template(base_logical["request"]))
        for repetition in range(1, int(quota) + 1):
            identity = {
                "base_campaign_manifest_id": base["campaign_manifest_id"],
                "base_logical_execution_id": base_id,
                "campaign_definition_revision_id": definition_revision_id,
                "campaign_id": definition["campaign_id"],
                "planned_repetition": repetition,
                "purpose": "operational-million-qualification-v1",
                "request_template_sha256": template_digest,
            }
            logical_id = identifiers.build(
                "logical-execution", "scale-logical-execution-v1", identity
            )
            record = {
                "base_logical_execution_id": base_id,
                "logical_execution_id": logical_id,
                "planned_repetition": repetition,
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
    if len(logical_ids) != target or len(set(logical_ids)) != target:
        raise MillionScaleCompileError("million logical denominator collides")
    if any(
        base_counts[key] != scale_basis_counts[key] * 10
        for key in scale_basis_counts
    ):
        raise MillionScaleCompileError("tenfold 100K repetition quota differs")
    if set(category_counts) != set(required_categories):
        raise MillionScaleCompileError("million workload category coverage differs")

    maximum = definition["shard_policy"]["maximum_execution_count"]
    artifact_rows: list[tuple[dict[str, Any], bytes, tuple[str, ...]]] = []
    for selection_key in selections:
        members = records_by_selection[selection_key]
        for offset in range(0, len(members), maximum):
            chunk = members[offset : offset + maximum]
            chunk_ids = tuple(item["logical_execution_id"] for item in chunk)
            shard_body = {
                "algorithm": definition["shard_policy"]["algorithm"],
                "logical_execution_ids": list(chunk_ids),
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
                "logical_execution_ids_sha256": _digest(list(chunk_ids)),
                "relative_path": f"logical-execution-segments/sha256/{digest}.json",
                "selection_key": selection_key,
                "sha256": digest,
                "shard_id": shard_id,
                "size_bytes": len(encoded),
            }
            artifact_rows.append((reference, encoded, chunk_ids))
    artifact_rows.sort(key=lambda item: item[0]["shard_id"])
    references = [item[0] for item in artifact_rows]
    partition_policy = definition["partition_policy"]
    maximum_partition_shards = (
        len(references) + partition_policy["partition_count"] - 1
    ) // partition_policy["partition_count"]
    if maximum_partition_shards > partition_policy["maximum_partition_shards"]:
        raise MillionScaleCompileError("partition shard ceiling is insufficient")

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
        "segment_count": len(references),
    }
    source_digests = _source_digests(root, definition)
    manifest_body = {
        "attempt_policy": definition["attempt_policy"],
        "base_campaign": definition["base_campaign"],
        "campaign_definition_revision_id": definition_revision_id,
        "campaign_id": definition["campaign_id"],
        "classification": definition["classification"],
        "denominator": denominator,
        "expansion_policy": definition["expansion_policy"],
        "logical_execution_index": logical_index,
        "partition_policy": partition_policy,
        "scale_basis": definition["scale_basis"],
        "segment_authority": "immutable-content-addressed-external-v1",
        "shard_policy": definition["shard_policy"],
        "shards": references,
        "source_digests": source_digests,
        "stress_obligations": obligations,
        "workload_distribution": distribution,
    }
    manifest_id = identifiers.build(
        "campaign-manifest", "million-scale-campaign-manifest-v1", manifest_body
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
        "partition_policy": partition_policy,
        "schema_version": "million-scale-campaign-plan.v1",
        "shards": references,
        "source_digests": source_digests,
        "workload_distribution": distribution,
    }
    return MillionCompilation(
        plan=plan,
        artifacts=tuple((item[0], item[1]) for item in artifact_rows),
        logical_ids_by_shard={item[0]["shard_id"]: item[2] for item in artifact_rows},
    )


def compile_million_scale_plan(root: Path) -> MillionCompilation:
    compiled = _compile(root)
    verify_million_scale_plan(root, compiled.plan, deterministic=False)
    return compiled


def verify_million_scale_plan(
    root: Path, plan: dict[str, Any], *, deterministic: bool = True
) -> None:
    root = root.resolve(strict=True)
    validate_instance(
        plan,
        load_strict(root / "schemas/json/million-scale-campaign-plan.schema.json"),
        source="million scale campaign plan",
    )
    if plan["campaign_manifest_id"] != plan["campaign_manifest"].get("campaign_manifest_id"):
        raise MillionScaleCompileError("million campaign manifest identities disagree")
    body = {
        key: value
        for key, value in plan["campaign_manifest"].items()
        if key != "campaign_manifest_id"
    }
    expected_id = _ContentIds(root).build(
        "campaign-manifest", "million-scale-campaign-manifest-v1", body
    )
    if expected_id != plan["campaign_manifest_id"]:
        raise MillionScaleCompileError("million campaign manifest digest differs")
    if plan["campaign_manifest"].get("shards") != plan["shards"]:
        raise MillionScaleCompileError("million master shard set differs")
    if sum(item["logical_execution_count"] for item in plan["shards"]) != LOGICAL_TARGET:
        raise MillionScaleCompileError("million shard denominator differs")
    if len({item["shard_id"] for item in plan["shards"]}) != len(plan["shards"]):
        raise MillionScaleCompileError("million shard identity collides")
    for relative, expected in plan["source_digests"].items():
        if _file_digest(_safe_source(root, relative)) != expected:
            raise MillionScaleCompileError(f"million source digest changed: {relative}")
    if deterministic and canonical_bytes(plan) != canonical_bytes(_compile(root).plan):
        raise MillionScaleCompileError("million plan differs from deterministic compilation")


def _partition_ranges(length: int, count: int) -> list[tuple[int, int]]:
    quotient, remainder = divmod(length, count)
    result = []
    start = 0
    for index in range(count):
        size = quotient + (index < remainder)
        result.append((start, start + int(size)))
        start += int(size)
    if start != length or any(a == b for a, b in result):
        raise MillionScaleCompileError("partition ranges do not close")
    return result


def build_partition_plans(
    root: Path, compiled: MillionCompilation
) -> tuple[dict[str, Any], ...]:
    root = root.resolve(strict=True)
    master = compiled.plan
    verify_million_scale_plan(root, master, deterministic=False)
    definition = load_strict(root / DEFINITION_RELATIVE)
    identifiers = _ContentIds(root)
    count = definition["partition_policy"]["partition_count"]
    result: list[dict[str, Any]] = []
    all_shard_ids: list[str] = []
    all_logical_ids: set[str] = set()
    for index, (start, end) in enumerate(_partition_ranges(len(master["shards"]), count)):
        shards = master["shards"][start:end]
        logical_ids = [
            logical_id
            for shard in shards
            for logical_id in compiled.logical_ids_by_shard[shard["shard_id"]]
        ]
        local_count = len(logical_ids)
        boundaries = []
        for item in definition["planned_interruptions"]:
            committed = max(
                1,
                min(
                    len(shards) - 1,
                    (len(shards) * item["partition_fraction_basis_points"]) // 10_000,
                ),
            )
            boundaries.append(
                {
                    "action": item["action"],
                    "after_committed_shards": committed,
                    "key": item["key"],
                }
            )
        if len({item["after_committed_shards"] for item in boundaries}) != 3:
            raise MillionScaleCompileError("partition interruption boundaries collide")
        denominator = {
            "candidate_count": local_count,
            "excluded_count": 0,
            "included_count": local_count,
            "invalid_count": 0,
            "unresolved_count": 0,
        }
        logical_index = {
            "logical_execution_count": local_count,
            "ordered_ids_sha256": _digest(logical_ids),
            "ordering": "master-shard-ordinal-v1",
            "segment_count": len(shards),
        }
        manifest_body = {
            "attempt_policy": master["campaign_manifest"]["attempt_policy"],
            "base_campaign": master["base_campaign"],
            "campaign_definition_revision_id": master[
                "campaign_definition_revision_id"
            ],
            "campaign_id": master["campaign_id"],
            "classification": master["classification"],
            "denominator": denominator,
            "logical_execution_index": logical_index,
            "parent_campaign_manifest_id": master["campaign_manifest_id"],
            "partition_count": count,
            "partition_index": index,
            "planned_interruptions": boundaries,
            "shards": shards,
            "source_digests": master["source_digests"],
        }
        manifest_id = identifiers.build(
            "campaign-manifest", "million-scale-partition-manifest-v1", manifest_body
        )
        partition = {
            **manifest_body,
            "campaign_manifest": {"campaign_manifest_id": manifest_id, **manifest_body},
            "campaign_manifest_id": manifest_id,
            "schema_version": "million-scale-partition-plan.v1",
        }
        verify_partition_plan(root, master, partition, compiled.logical_ids_by_shard)
        result.append(partition)
        all_shard_ids.extend(item["shard_id"] for item in shards)
        overlap = all_logical_ids.intersection(logical_ids)
        if overlap:
            raise MillionScaleCompileError("partition logical denominator overlaps")
        all_logical_ids.update(logical_ids)
    if all_shard_ids != [item["shard_id"] for item in master["shards"]]:
        raise MillionScaleCompileError("partition shards do not reconstruct the master")
    if len(all_logical_ids) != LOGICAL_TARGET:
        raise MillionScaleCompileError("partition logical union differs from one million")
    return tuple(result)


def verify_partition_plan(
    root: Path,
    master: dict[str, Any],
    partition: dict[str, Any],
    logical_ids_by_shard: dict[str, tuple[str, ...]] | None = None,
) -> None:
    root = root.resolve(strict=True)
    validate_instance(
        partition,
        load_strict(root / "schemas/json/million-scale-partition-plan.schema.json"),
        source="million scale partition plan",
    )
    if partition["parent_campaign_manifest_id"] != master["campaign_manifest_id"]:
        raise MillionScaleCompileError("partition parent manifest differs")
    if partition["campaign_manifest_id"] != partition["campaign_manifest"].get("campaign_manifest_id"):
        raise MillionScaleCompileError("partition manifest identities disagree")
    body = {
        key: value
        for key, value in partition["campaign_manifest"].items()
        if key != "campaign_manifest_id"
    }
    if any(partition.get(key) != value for key, value in body.items()):
        raise MillionScaleCompileError("partition manifest projection differs")
    expected = _ContentIds(root).build(
        "campaign-manifest", "million-scale-partition-manifest-v1", body
    )
    if expected != partition["campaign_manifest_id"]:
        raise MillionScaleCompileError("partition manifest digest differs")
    definition = load_strict(root / DEFINITION_RELATIVE)
    partition_count = definition["partition_policy"]["partition_count"]
    index = partition["partition_index"]
    if (
        master["partition_policy"] != definition["partition_policy"]
        or partition["partition_count"] != partition_count
        or index not in range(partition_count)
    ):
        raise MillionScaleCompileError("partition coordinate policy differs")
    start, end = _partition_ranges(len(master["shards"]), partition_count)[index]
    expected_shards = master["shards"][start:end]
    if partition["shards"] != expected_shards:
        raise MillionScaleCompileError("partition contains a substituted shard slice")
    logical_count = sum(item["logical_execution_count"] for item in partition["shards"])
    expected_denominator = {
        "candidate_count": logical_count,
        "excluded_count": 0,
        "included_count": logical_count,
        "invalid_count": 0,
        "unresolved_count": 0,
    }
    expected_interruptions = []
    for item in definition["planned_interruptions"]:
        committed = max(
            1,
            min(
                len(expected_shards) - 1,
                (len(expected_shards) * item["partition_fraction_basis_points"])
                // 10_000,
            ),
        )
        expected_interruptions.append(
            {
                "action": item["action"],
                "after_committed_shards": committed,
                "key": item["key"],
            }
        )
    expected_projection = {
        "attempt_policy": master["campaign_manifest"]["attempt_policy"],
        "base_campaign": master["base_campaign"],
        "campaign_definition_revision_id": master["campaign_definition_revision_id"],
        "campaign_id": master["campaign_id"],
        "classification": master["classification"],
        "denominator": expected_denominator,
        "parent_campaign_manifest_id": master["campaign_manifest_id"],
        "partition_count": partition_count,
        "partition_index": index,
        "planned_interruptions": expected_interruptions,
        "shards": expected_shards,
        "source_digests": master["source_digests"],
    }
    if any(partition.get(key) != value for key, value in expected_projection.items()):
        raise MillionScaleCompileError("partition deterministic projection differs")
    if partition["logical_execution_index"] != {
        **partition["logical_execution_index"],
        "logical_execution_count": logical_count,
        "ordering": "master-shard-ordinal-v1",
        "segment_count": len(expected_shards),
    }:
        raise MillionScaleCompileError("partition logical index projection differs")
    if logical_count != partition["denominator"]["included_count"]:
        raise MillionScaleCompileError("partition denominator differs")
    if logical_ids_by_shard is not None:
        logical_ids = [
            logical_id
            for shard in partition["shards"]
            for logical_id in logical_ids_by_shard[shard["shard_id"]]
        ]
        if _digest(logical_ids) != partition["logical_execution_index"]["ordered_ids_sha256"]:
            raise MillionScaleCompileError("partition logical index digest differs")


def _write_direct(path: Path, encoded: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != encoded:
            raise MillionScaleCompileError("existing materialized segment conflicts")
        return
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != encoded:
        raise MillionScaleCompileError("materialized segment read-back differs")


def materialize_partition_inputs(
    root: Path,
    compiled: MillionCompilation,
    partition_root: Path,
    partition_indexes: Iterable[int] | None = None,
) -> tuple[dict[str, Any], ...]:
    root = root.resolve(strict=True)
    external = partition_root.expanduser().resolve(strict=False)
    try:
        external.relative_to(root)
    except ValueError:
        pass
    else:
        raise MillionScaleCompileError("partition inputs must remain outside Git")
    external.mkdir(parents=True, exist_ok=True)
    partitions = build_partition_plans(root, compiled)
    if partition_indexes is None:
        selected = partitions
    else:
        indexes = tuple(partition_indexes)
        if (
            len(indexes) != len(set(indexes))
            or any(index not in range(len(partitions)) for index in indexes)
        ):
            raise MillionScaleCompileError("materialized partition selection is invalid")
        selected = tuple(partitions[index] for index in indexes)
    artifact_by_shard = {
        reference["shard_id"]: (reference, encoded)
        for reference, encoded in compiled.artifacts
    }
    for partition in selected:
        directory = external / f"partition-{partition['partition_index']:03d}"
        _write_direct(directory / "partition-plan.json", canonical_bytes(partition) + b"\n")
        for shard in partition["shards"]:
            reference, encoded = artifact_by_shard[shard["shard_id"]]
            if reference != shard:
                raise MillionScaleCompileError("partition artifact reference differs")
            _write_direct(directory / "logical" / shard["relative_path"], encoded)
        verify_materialized_partition(root, compiled.plan, partition, directory / "logical")
    return selected


def verify_materialized_partition(
    root: Path,
    master: dict[str, Any],
    partition: dict[str, Any],
    segment_root: Path,
) -> None:
    root = root.resolve(strict=True)
    external = segment_root.expanduser().resolve(strict=True)
    verify_partition_plan(root, master, partition)
    schema = load_strict(root / "schemas/json/logical-execution-segment.schema.json")
    expected: set[Path] = set()
    logical_ids: list[str] = []
    for reference in partition["shards"]:
        unresolved = external / reference["relative_path"]
        path = unresolved.resolve(strict=True)
        try:
            path.relative_to(external)
        except ValueError as error:
            raise MillionScaleCompileError("partition segment escapes its root") from error
        if unresolved.absolute() != path or not stat.S_ISREG(path.stat().st_mode):
            raise MillionScaleCompileError("partition segment is not direct")
        encoded = path.read_bytes()
        if len(encoded) != reference["size_bytes"] or hashlib.sha256(encoded).hexdigest() != reference["sha256"]:
            raise MillionScaleCompileError("partition segment bytes differ")
        try:
            payload = loads_strict(encoded.decode("utf-8"))
        except (ConformanceDataError, UnicodeError) as error:
            raise MillionScaleCompileError("partition segment is not strict JSON") from error
        validate_instance(payload, schema, source=str(path))
        if canonical_bytes(payload) + b"\n" != encoded:
            raise MillionScaleCompileError("partition segment is not canonical")
        ids = [item["logical_execution_id"] for item in payload["logical_executions"]]
        if (
            payload["shard_id"] != reference["shard_id"]
            or payload["selection_key"] != reference["selection_key"]
            or _digest(ids) != reference["logical_execution_ids_sha256"]
        ):
            raise MillionScaleCompileError("partition segment commitment differs")
        logical_ids.extend(ids)
        expected.add(path)
    directory = external / "logical-execution-segments/sha256"
    if set(directory.iterdir()) != expected:
        raise MillionScaleCompileError("partition segment set is not exact")
    if _digest(logical_ids) != partition["logical_execution_index"]["ordered_ids_sha256"]:
        raise MillionScaleCompileError("materialized partition logical digest differs")
