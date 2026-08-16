"""Production Evidence Pack v2 and enriched capacity certification.

The pack keeps independently executed attempts and observations as distinct
facts while moving repeated immutable values into exact content-addressed
objects.  Its manifest is the publication unit; analytical projections remain
derived and are deliberately absent from the authoritative pack.
"""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, ROUND_CEILING
import hashlib
import json
import lzma
from pathlib import Path
import re
from typing import Any, Callable, Iterable, Mapping, Sequence

import rfc8785

from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance

from . import factorized_evidence as v1


PACK_SCHEMA = "evidence-pack-manifest.v2"
PACK_MODEL_SCHEMA = "evidence-pack-model.v2"
PACK_REPORT_SCHEMA = "evidence-pack-v2-certification.v1"
CAS_VALUE_SCHEMA = "evidence-pack-cas-value.v2"
DIAGNOSTIC_ENVELOPE_SCHEMA = "attempt-diagnostic-envelope.v2"
PERFORMANCE_SAMPLES_SCHEMA = "raw-performance-samples.v2"
PACK_OBJECT_PREFIX = "regex-conformance/evidence-pack-v2/objects/sha256"
PACK_MANIFEST_PREFIX = "regex-conformance/evidence-pack-v2/manifests/sha256"
PACK_LOGICAL_TARGET = 100_000
SOFT_LIMIT_BYTES = 8_000_000_000
HARD_LIMIT_BYTES = 10_000_000_000
GENERAL_GROWTH_RESERVE_BYTES = 500_000_000
TARGETED_EXPANSION_RESERVE_BYTES = 500_000_000

_PHYSICAL_ID = re.compile(r"^rcid:v1:physical-run:u7:[0-9a-f-]{36}$")
_TOKEN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

# Two bits are retained per field: unavailable, observed, derived, or an
# explicitly observed absence/not-applicable fact.  The order is a format
# contract and cannot be changed without a new pack version.
DIAGNOSTIC_FIELDS = (
    "native-error-category",
    "native-error-code",
    "native-error-message",
    "native-error-position",
    "native-error-position-basis",
    "failure-stage",
    "operation",
    "process-exit-status",
    "signal-or-termination",
    "timeout-source",
    "configured-timeout",
    "triggered-timeout-or-limit",
    "containment-event",
    "failure-attribution",
    "stdout",
    "stderr",
    "native-diagnostic",
    "truncation-metadata",
    "redaction-metadata",
    "wall-duration",
    "monotonic-duration",
    "cpu-time",
    "compile-duration",
    "execution-duration",
    "peak-rss-or-memory-delta",
    "configured-resource-limits",
    "resource-limit-violation",
    "runtime-backend-jit",
    "warm-up-state",
    "adapter-protocol-environment",
    "anomaly-classification",
    "replication-relationship",
    "discrepancy-relationship",
    "retry-predecessor-relationship",
    "release-transition-relationship",
)
AVAILABILITY_CODES = {
    "unavailable": 0,
    "observed": 1,
    "derived": 2,
    "observed-absence-or-not-applicable": 3,
}
AVAILABILITY_NAMES = {value: key for key, value in AVAILABILITY_CODES.items()}

BASE_HISTORICAL_DENOMINATORS = {
    "lower": 27_519_672,
    "expected": 64_857_612,
    "conservative": 120_234_321,
}
D103_CANARY_MULTIPLIER = Decimal("1.25")
RETRY_RATES = {
    "lower": Decimal("0"),
    "expected": Decimal("0.005"),
    "conservative": Decimal("0.05"),
}
DIAGNOSTIC_GROWTH_RATES = {
    "lower": Decimal("0"),
    "expected": Decimal("0.04"),
    "conservative": Decimal("0.10"),
}
PERFORMANCE_GROWTH_RATES = {
    "lower": Decimal("0"),
    "expected": Decimal("0.01"),
    "conservative": Decimal("0.05"),
}


class EvidencePackError(ValueError):
    """Evidence Pack v2 violates a deterministic or lossless invariant."""


def _fail(message: str) -> EvidencePackError:
    return EvidencePackError(message)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _ceil(value: Decimal) -> int:
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def _xz(value: bytes) -> bytes:
    return lzma.compress(value, format=lzma.FORMAT_XZ, check=lzma.CHECK_SHA256, preset=9)


def _unxz(value: bytes) -> bytes:
    try:
        return lzma.decompress(value, format=lzma.FORMAT_XZ)
    except lzma.LZMAError as error:
        raise _fail("pack object cannot be decompressed") from error


def _parse_millisecond(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (TypeError, ValueError) as error:
        raise _fail("attempt timestamp is not millisecond UTC") from error
    return parsed


def _pack_availability(rows: Sequence[Sequence[int]]) -> bytes:
    flat = [item for row in rows for item in row]
    if any(item not in AVAILABILITY_NAMES for item in flat):
        raise _fail("diagnostic availability code is outside the two-bit contract")
    output = bytearray((len(flat) + 3) // 4)
    for index, item in enumerate(flat):
        output[index // 4] |= item << ((index % 4) * 2)
    return bytes(output)


def unpack_availability(encoded: bytes, row_count: int) -> list[list[str]]:
    expected_values = row_count * len(DIAGNOSTIC_FIELDS)
    if len(encoded) != (expected_values + 3) // 4:
        raise _fail("diagnostic availability bitmap length differs")
    rows: list[list[str]] = []
    for row in range(row_count):
        values = []
        for field in range(len(DIAGNOSTIC_FIELDS)):
            index = row * len(DIAGNOSTIC_FIELDS) + field
            code = (encoded[index // 4] >> ((index % 4) * 2)) & 0x03
            values.append(AVAILABILITY_NAMES[code])
        rows.append(values)
    return rows


def validate_attempt_diagnostic_envelope(value: Mapping[str, Any]) -> None:
    if set(value) != {"facts", "physical_run_id", "schema_version"}:
        raise _fail("attempt diagnostic envelope keys differ")
    if value["schema_version"] != DIAGNOSTIC_ENVELOPE_SCHEMA:
        raise _fail("attempt diagnostic envelope version differs")
    if not isinstance(value["physical_run_id"], str) or not _PHYSICAL_ID.fullmatch(value["physical_run_id"]):
        raise _fail("attempt diagnostic envelope physical identity differs")
    facts = value["facts"]
    if not isinstance(facts, dict) or tuple(facts) != DIAGNOSTIC_FIELDS:
        raise _fail("attempt diagnostic envelope must cover the ordered field registry")
    for name, fact in facts.items():
        if not isinstance(fact, dict) or set(fact) not in (
            {"availability"},
            {"availability", "value"},
        ):
            raise _fail(f"attempt diagnostic fact shape differs: {name}")
        availability = fact.get("availability")
        if availability not in AVAILABILITY_CODES:
            raise _fail(f"attempt diagnostic availability differs: {name}")
        if availability in {"observed", "derived"} and "value" not in fact:
            raise _fail(f"available attempt diagnostic fact has no value: {name}")
        if availability in {"unavailable", "observed-absence-or-not-applicable"} and "value" in fact:
            raise _fail(f"absent attempt diagnostic fact carries a value: {name}")
    canonical_bytes(dict(value))


def validate_performance_samples(value: Mapping[str, Any]) -> None:
    required = {"claim_scope", "methodology_id", "physical_run_id", "samples", "schema_version"}
    if set(value) != required or value.get("schema_version") != PERFORMANCE_SAMPLES_SCHEMA:
        raise _fail("raw performance sample record shape differs")
    if not isinstance(value["physical_run_id"], str) or not _PHYSICAL_ID.fullmatch(value["physical_run_id"]):
        raise _fail("performance sample physical identity differs")
    if value["claim_scope"] not in {"governed-benchmark", "operational-timing-only"}:
        raise _fail("performance sample claim scope differs")
    if not isinstance(value["methodology_id"], str) or not _TOKEN.fullmatch(value["methodology_id"]):
        raise _fail("performance methodology identity differs")
    samples = value["samples"]
    if not isinstance(samples, dict) or not samples:
        raise _fail("performance sample record is empty")
    for name, series in samples.items():
        if not isinstance(name, str) or not _TOKEN.fullmatch(name):
            raise _fail("performance metric name differs")
        if not isinstance(series, dict) or set(series) != {"unit", "values"}:
            raise _fail("performance sample series shape differs")
        if series["unit"] not in {"bytes", "count", "nanoseconds"}:
            raise _fail("performance sample unit differs")
        values = series["values"]
        if not isinstance(values, list) or not values or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in values
        ):
            raise _fail("performance samples must be non-negative typed integers")
    canonical_bytes(dict(value))


@dataclass(frozen=True)
class PackObject:
    evidence_class: str
    role: str
    member_paths: tuple[str, ...]
    raw_sha256: str
    raw_size_bytes: int
    stored_sha256: str
    stored_size_bytes: int
    data: bytes

    @property
    def key(self) -> str:
        return f"{PACK_OBJECT_PREFIX}/{self.stored_sha256}.xz"

    def descriptor(self, ordinal: int) -> dict[str, Any]:
        return {
            "evidence_class": self.evidence_class,
            "key": self.key,
            "member_paths": list(self.member_paths),
            "ordinal": ordinal,
            "raw_sha256": self.raw_sha256,
            "raw_size_bytes": self.raw_size_bytes,
            "role": self.role,
            "stored_sha256": self.stored_sha256,
            "stored_size_bytes": self.stored_size_bytes,
        }


@dataclass(frozen=True)
class EvidencePack:
    manifest: dict[str, Any]
    manifest_bytes: bytes
    manifest_sha256: str
    objects: tuple[PackObject, ...]
    bytes_by_evidence_class: dict[str, int]
    measurements: dict[str, Any]

    @property
    def retained_bytes(self) -> int:
        return len(self.manifest_bytes) + sum(item.stored_size_bytes for item in self.objects)

    @property
    def manifest_key(self) -> str:
        return f"{PACK_MANIFEST_PREFIX}/{self.manifest_sha256}.json"

    def object_map(self) -> dict[str, bytes]:
        return {item.stored_sha256: item.data for item in self.objects}


@dataclass(frozen=True)
class RandomLookup:
    relative_path: str
    data: bytes
    object_reads: int


@dataclass(frozen=True)
class PlatformCanaryResult:
    dimension: str
    profile_id: str
    feature_id: str
    operation: str
    backend: str
    difference_class: str
    affected_logical_executions: int = 0

    def __post_init__(self) -> None:
        if self.difference_class not in {
            "identical",
            "semantic",
            "diagnostic",
            "infrastructure-noise",
            "performance-only",
        }:
            raise _fail("platform canary difference class differs")
        if self.affected_logical_executions < 0:
            raise _fail("platform canary affected count is negative")
        if self.difference_class != "semantic" and self.affected_logical_executions:
            raise _fail("non-semantic platform canary cannot expand the matrix")


def plan_platform_expansion(
    results: Iterable[PlatformCanaryResult],
    *,
    retained_bytes: int,
    bytes_per_logical_execution: Decimal,
    soft_stop_authorized: bool = False,
) -> dict[str, Any]:
    semantic_scopes: dict[tuple[str, str, str, str, str], int] = {}
    classifications: dict[str, int] = defaultdict(int)
    for result in results:
        classifications[result.difference_class] += 1
        if result.difference_class == "semantic":
            key = (
                result.dimension,
                result.profile_id,
                result.feature_id,
                result.operation,
                result.backend,
            )
            semantic_scopes[key] = max(
                semantic_scopes.get(key, 0), result.affected_logical_executions
            )
    added_logical = sum(semantic_scopes.values())
    incremental = _ceil(bytes_per_logical_execution * Decimal(added_logical))
    projected = retained_bytes + incremental
    if projected > HARD_LIMIT_BYTES:
        outcome = "hard-cap-rejected"
    elif projected >= SOFT_LIMIT_BYTES and not soft_stop_authorized:
        outcome = "soft-stop-owner-review-required"
    else:
        outcome = "admitted" if semantic_scopes else "canary-sufficient"
    return {
        "classification_counts": dict(sorted(classifications.items())),
        "incremental_retained_bytes": incremental,
        "outcome": outcome,
        "projected_retained_bytes": projected,
        "targeted_scopes": [
            {
                "affected_logical_executions": count,
                "backend": key[4],
                "dimension": key[0],
                "feature_id": key[2],
                "operation": key[3],
                "profile_id": key[1],
            }
            for key, count in sorted(semantic_scopes.items())
        ],
    }


class _Cas:
    def __init__(self) -> None:
        self.objects: dict[str, PackObject] = {}

    def add(self, role: str, evidence_class: str, value: Any) -> str:
        raw = canonical_bytes(
            {"role": role, "schema_version": CAS_VALUE_SCHEMA, "value": value}
        )
        stored = _xz(raw)
        digest = _sha256(stored)
        item = PackObject(
            evidence_class=evidence_class,
            role=role,
            member_paths=(),
            raw_sha256=_sha256(raw),
            raw_size_bytes=len(raw),
            stored_sha256=digest,
            stored_size_bytes=len(stored),
            data=stored,
        )
        previous = self.objects.get(digest)
        if previous is not None and previous.data != stored:
            raise _fail("content-addressed pack object collision")
        self.objects[digest] = item
        return digest


@dataclass(frozen=True)
class _FactBlock:
    evidence_class: str
    role: str
    member_paths: tuple[str, ...]
    value: Any


def _diagnostic_payload(value: Any) -> bool:
    return isinstance(value, dict) and set(value) == {
        "captured_bytes",
        "content",
        "original_bytes",
        "sha256",
        "truncated",
    }


def _extract_diagnostic_payloads(value: Any, cas: _Cas) -> Any:
    if _diagnostic_payload(value):
        return {
            "evidence_pack_diagnostic_cas_sha256": cas.add(
                "diagnostic-payload", "diagnostics", value
            )
        }
    if isinstance(value, dict):
        return {
            key: _extract_diagnostic_payloads(child, cas)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_extract_diagnostic_payloads(child, cas) for child in value]
    return deepcopy(value)


def _restore_diagnostic_payloads(value: Any, load_cas: Callable[[str], Any]) -> Any:
    if isinstance(value, dict) and set(value) == {"evidence_pack_diagnostic_cas_sha256"}:
        return deepcopy(load_cas(value["evidence_pack_diagnostic_cas_sha256"]))
    if isinstance(value, dict):
        return {
            key: _restore_diagnostic_payloads(child, load_cas)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_restore_diagnostic_payloads(child, load_cas) for child in value]
    return deepcopy(value)


def _split_process(value: Any) -> tuple[bool, dict[str, Any], bool, int | None]:
    if not isinstance(value, dict):
        return False, {}, False, None
    result = deepcopy(value)
    wall_present = "wall_time_ms" in result
    wall = result.pop("wall_time_ms", None)
    if wall_present and (isinstance(wall, bool) or not isinstance(wall, int) or wall < 0):
        raise _fail("process wall-time sample differs")
    return True, result, wall_present, wall


def _combine_process(
    present: bool,
    diagnostic: Mapping[str, Any],
    wall_present: bool,
    wall: int | None,
) -> dict[str, Any] | None:
    if not present:
        return None
    result = deepcopy(dict(diagnostic))
    if wall_present:
        result["wall_time_ms"] = wall
    return result


def _availability_for_attempt(
    *,
    attempt: Mapping[str, Any],
    result_template: Mapping[str, Any] | None,
    request: Mapping[str, Any] | None,
    process: Mapping[str, Any] | None,
) -> list[int]:
    unavailable = AVAILABILITY_CODES["unavailable"]
    observed = AVAILABILITY_CODES["observed"]
    derived = AVAILABILITY_CODES["derived"]
    absent = AVAILABILITY_CODES["observed-absence-or-not-applicable"]
    codes = {name: unavailable for name in DIAGNOSTIC_FIELDS}
    observation = None
    if isinstance(result_template, dict):
        core = result_template.get("core")
        if isinstance(core, dict):
            observation = core.get("observation")
    if isinstance(observation, dict):
        codes["operation"] = observed
        native = observation.get("native_error")
        if isinstance(native, dict):
            for name in (
                "native-error-category",
                "native-error-code",
                "native-error-message",
                "failure-stage",
            ):
                codes[name] = observed
            codes["native-error-position"] = observed if native.get("position") is not None else absent
            codes["native-error-position-basis"] = unavailable
            codes["native-diagnostic"] = observed if native.get("diagnostic") is not None else absent
        else:
            for name in (
                "native-error-category",
                "native-error-code",
                "native-error-message",
                "native-error-position",
                "native-error-position-basis",
                "failure-stage",
                "native-diagnostic",
            ):
                codes[name] = absent
    elif isinstance(request, dict):
        codes["operation"] = derived
    codes["failure-attribution"] = observed
    codes["wall-duration"] = derived
    codes["retry-predecessor-relationship"] = derived if attempt["attempt_number"] > 1 else absent
    if isinstance(request, dict) and isinstance(request.get("limits"), dict):
        codes["configured-timeout"] = derived
        codes["configured-resource-limits"] = derived
    provenance_names = (
        "runtime-backend-jit",
        "adapter-protocol-environment",
    )
    for name in provenance_names:
        codes[name] = derived
    if process is not None:
        codes["process-exit-status"] = observed if process.get("exit_code") is not None else absent
        exit_code = process.get("exit_code")
        codes["signal-or-termination"] = (
            observed if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code < 0 else absent
        )
        outcome = process.get("outcome")
        codes["triggered-timeout-or-limit"] = observed if outcome not in {None, "completed"} else absent
        codes["containment-event"] = observed if outcome not in {None, "completed"} else absent
        codes["stdout"] = observed if "stdout_sha256" in process else unavailable
        codes["stderr"] = observed if "stderr_sha256" in process else unavailable
        codes["monotonic-duration"] = observed if "wall_time_ms" in process else unavailable
        codes["resource-limit-violation"] = observed if outcome not in {None, "completed"} else absent
    for name in (
        "truncation-metadata",
        "redaction-metadata",
        "cpu-time",
        "compile-duration",
        "execution-duration",
        "peak-rss-or-memory-delta",
        "warm-up-state",
        "anomaly-classification",
        "replication-relationship",
        "discrepancy-relationship",
        "release-transition-relationship",
        "timeout-source",
    ):
        if codes[name] == unavailable:
            codes[name] = unavailable
    return [codes[name] for name in DIAGNOSTIC_FIELDS]


def _canonical_definitions(repository_root: Path) -> list[dict[str, Any]]:
    compiled = load_strict(repository_root / "campaigns/compiled/small-scale-qualification.v1.json")
    records = compiled.get("logical_executions")
    if not isinstance(records, list) or len(records) != 26:
        raise _fail("P19 canonical base definitions differ")
    return sorted(deepcopy(records), key=lambda item: item["logical_execution_id"])


def _fact_object(block: _FactBlock, tables: v1.TokenTables) -> PackObject:
    raw = tables.encode_value(block.value)
    stored = _xz(raw)
    return PackObject(
        evidence_class=block.evidence_class,
        role=block.role,
        member_paths=block.member_paths,
        raw_sha256=_sha256(raw),
        raw_size_bytes=len(raw),
        stored_sha256=_sha256(stored),
        stored_size_bytes=len(stored),
        data=stored,
    )


def _deduplicate_physical_objects(
    candidates: list[PackObject],
) -> tuple[list[PackObject], list[dict[str, Any]]]:
    ordered = sorted(
        candidates, key=lambda item: (item.role, item.stored_sha256, item.member_paths)
    )
    objects: list[PackObject] = []
    physical_by_digest: dict[str, PackObject] = {}
    fact_aliases: list[dict[str, Any]] = []
    for item in ordered:
        previous = physical_by_digest.get(item.stored_sha256)
        if previous is None:
            physical_by_digest[item.stored_sha256] = item
            objects.append(item)
            continue
        if (
            previous.data != item.data
            or previous.raw_sha256 != item.raw_sha256
            or previous.raw_size_bytes != item.raw_size_bytes
            or not previous.member_paths
            or not item.member_paths
        ):
            raise _fail("pack stored-object identity collides across incompatible roles")
        fact_aliases.append(
            {
                "evidence_class": item.evidence_class,
                "member_paths": list(item.member_paths),
                "role": item.role,
                "stored_sha256": item.stored_sha256,
            }
        )
    fact_aliases.sort(
        key=lambda item: (
            item["role"],
            item["stored_sha256"],
            item["member_paths"],
        )
    )
    return objects, fact_aliases


def build_evidence_pack(
    repository_root: Path,
    source: v1.SourceCorpus,
    semantic: v1.SemanticCorpus,
    *,
    diagnostic_envelopes: Mapping[str, Mapping[str, Any]] | None = None,
    performance_samples: Mapping[str, Mapping[str, Any]] | None = None,
    group_size: int = 16,
) -> EvidencePack:
    if group_size < 1:
        raise _fail("pack group size must be positive")
    root = repository_root.resolve(strict=True)
    diagnostic_envelopes = dict(diagnostic_envelopes or {})
    performance_samples = dict(performance_samples or {})
    for value in diagnostic_envelopes.values():
        validate_attempt_diagnostic_envelope(value)
    for value in performance_samples.values():
        validate_performance_samples(value)

    cas = _Cas()
    definitions = _canonical_definitions(root)
    definition_refs = [
        cas.add("canonical-execution-definition", "canonical_inputs", value)
        for value in definitions
    ]
    definition_by_base = {
        item["logical_execution_id"]: item for item in definitions
    }

    diagnostic_template_refs = [
        cas.add("infrastructure-diagnostic", "diagnostics", value)
        for value in semantic.global_model["diagnostic_templates"]
    ]
    result_template_refs = []
    for value in semantic.global_model["result_templates"]:
        factored = _extract_diagnostic_payloads(value, cas)
        result_template_refs.append(
            cas.add("exact-result-template", "semantic_results", factored)
        )

    provenance_refs = []
    provenance_processes = []
    for value in semantic.global_model["provenance_templates"]:
        invariant = deepcopy(value)
        process = invariant.pop("process_execution", None)
        provenance_refs.append(
            cas.add("provenance-context", "shared_dictionary_cas", invariant)
        )
        provenance_processes.append(process)

    legacy_global = deepcopy(semantic.global_model)
    for key in ("result_templates", "provenance_templates", "diagnostic_templates"):
        legacy_global.pop(key)
    descriptor = {
        "canonical_definition_object_sha256s": definition_refs,
        "diagnostic_contract": {
            "availability_encoding": "two-bit-row-major-v1",
            "availability_values": {
                str(code): name for code, name in sorted(AVAILABILITY_NAMES.items())
            },
            "field_order": list(DIAGNOSTIC_FIELDS),
            "schema_version": DIAGNOSTIC_ENVELOPE_SCHEMA,
        },
        "diagnostic_template_object_sha256s": diagnostic_template_refs,
        "legacy_global_model": legacy_global,
        "legacy_manifest_path": semantic.manifest_member.relative_path,
        "performance_contract": {
            "derived_statistics_authoritative": False,
            "integer_units": ["bytes", "count", "nanoseconds"],
            "schema_version": PERFORMANCE_SAMPLES_SCHEMA,
        },
        "provenance_context_object_sha256s": provenance_refs,
        "result_template_object_sha256s": result_template_refs,
        "schema_version": PACK_MODEL_SCHEMA,
    }

    logical_by_shard = {item.model["shard_id"]: item for item in semantic.logical_members}
    results_by_shard: dict[str, list[v1.SemanticMember]] = defaultdict(list)
    for item in semantic.result_members:
        results_by_shard[item.model["shard_id"]].append(item)

    observed_run_ids: set[str] = set()
    availability_counts: dict[str, dict[str, int]] = {
        field: {name: 0 for name in AVAILABILITY_CODES}
        for field in DIAGNOSTIC_FIELDS
    }
    fact_blocks: list[_FactBlock] = []
    logical_groups = [
        semantic.logical_members[offset : offset + group_size]
        for offset in range(0, len(semantic.logical_members), group_size)
    ]
    for logical_group in logical_groups:
        fact_blocks.append(
            _FactBlock(
                "canonical_inputs",
                "logical-facts",
                tuple(item.relative_path for item in logical_group),
                [item.model for item in logical_group],
            )
        )
        result_group: list[v1.SemanticMember] = []
        for logical_member in logical_group:
            result_group.extend(
                sorted(
                    results_by_shard[logical_member.model["shard_id"]],
                    key=lambda item: item.relative_path,
                )
            )
        semantic_models = []
        attempt_models = []
        diagnostic_models = []
        performance_models = []
        for item in result_group:
            model = deepcopy(item.model)
            attempt_columns = model.pop("attempt_columns")
            isolated_columns = model.pop("isolated_process_columns")
            provenance_index = model.pop("provenance_template_index")
            model["provenance_context_index"] = provenance_index
            semantic_models.append(model)
            attempt_models.append({"attempt_columns": attempt_columns})

            segment_present, segment_diag, segment_wall_present, segment_wall = _split_process(
                provenance_processes[provenance_index]
            )
            isolated_diagnostics = []
            isolated_walls = []
            isolated_wall_presence = []
            isolated_process_by_logical = {}
            for logical_index, process in zip(
                isolated_columns["logical_indexes"],
                isolated_columns["process_executions"],
                strict=True,
            ):
                present, process_diag, wall_present, wall = _split_process(process)
                if not present:
                    raise _fail("isolated target process record is absent")
                isolated_diagnostics.append(process_diag)
                isolated_walls.append(wall)
                isolated_wall_presence.append(wall_present)
                isolated_process_by_logical[logical_index] = process

            logical_model = logical_by_shard[item.model["shard_id"]].model
            result_index_by_logical = dict(
                zip(
                    model["observation_columns"]["logical_indexes"],
                    model["observation_columns"]["result_template_indexes"],
                    strict=True,
                )
            )
            availability_rows = []
            envelope_values = []
            sample_values = []
            for row_index, logical_index in enumerate(attempt_columns["logical_indexes"]):
                physical_id = attempt_columns["physical_run_ids"][row_index]
                if physical_id in observed_run_ids:
                    raise _fail("two physical attempts collapse to one physical identity")
                observed_run_ids.add(physical_id)
                template_index = logical_model["template_indexes"][logical_index]
                logical_template = semantic.global_model["logical_templates"][template_index]
                definition = definition_by_base.get(logical_template["base_logical_execution_id"])
                request = None if definition is None else definition.get("request")
                result_index = result_index_by_logical.get(logical_index)
                result_template = (
                    None
                    if result_index is None
                    else semantic.global_model["result_templates"][result_index]
                )
                attempt = {
                    "attempt_number": item.model["attempt_number"],
                    "ended_at": attempt_columns["ended_at"][row_index],
                    "physical_run_id": physical_id,
                    "started_at": attempt_columns["started_at"][row_index],
                }
                process = isolated_process_by_logical.get(logical_index)
                codes = _availability_for_attempt(
                    attempt=attempt,
                    result_template=result_template,
                    request=request,
                    process=(
                        process
                        if process is not None
                        else provenance_processes[provenance_index]
                    ),
                )
                envelope = diagnostic_envelopes.get(physical_id)
                if envelope is not None:
                    codes = [
                        AVAILABILITY_CODES[envelope["facts"][field]["availability"]]
                        for field in DIAGNOSTIC_FIELDS
                    ]
                availability_rows.append(codes)
                for field, code in zip(DIAGNOSTIC_FIELDS, codes, strict=True):
                    availability_counts[field][AVAILABILITY_NAMES[code]] += 1
                if envelope is not None:
                    envelope_values.append(
                        cas.add(
                            "attempt-diagnostic-envelope",
                            "diagnostics",
                            _extract_diagnostic_payloads(envelope, cas),
                        )
                    )
                if physical_id in performance_samples:
                    sample_values.append(deepcopy(performance_samples[physical_id]))
                # The exact start/end timestamps remain attempt facts; this
                # validates that the compact derived duration is meaningful.
                if _parse_millisecond(attempt["ended_at"]) < _parse_millisecond(attempt["started_at"]):
                    raise _fail("physical attempt ends before it starts")

            diagnostic_models.append(
                {
                    "availability_codes": _pack_availability(availability_rows),
                    "expanded_envelopes": envelope_values,
                    "isolated_process_diagnostics": isolated_diagnostics,
                    "isolated_process_logical_indexes": isolated_columns["logical_indexes"],
                    "provenance_process_diagnostic": segment_diag,
                    "provenance_process_present": segment_present,
                }
            )
            performance_models.append(
                {
                    "benchmark_or_resource_samples": sample_values,
                    "isolated_process_wall_time_ms": isolated_walls,
                    "isolated_process_wall_time_present": isolated_wall_presence,
                    "provenance_process_wall_time_ms": segment_wall,
                    "provenance_process_wall_time_present": segment_wall_present,
                }
            )
        paths = tuple(item.relative_path for item in result_group)
        for evidence_class, role, values in (
            ("semantic_results", "observation-facts", semantic_models),
            ("physical_attempt_facts", "physical-attempt-facts", attempt_models),
            ("diagnostics", "diagnostic-facts", diagnostic_models),
            ("performance_resource_samples", "performance-resource-facts", performance_models),
        ):
            fact_blocks.append(_FactBlock(evidence_class, role, paths, values))

    if set(diagnostic_envelopes) - observed_run_ids:
        raise _fail("diagnostic envelope references an unknown physical attempt")
    if set(performance_samples) - observed_run_ids:
        raise _fail("performance samples reference an unknown physical attempt")
    fact_blocks.append(
        _FactBlock(
            "manifests_integrity",
            "legacy-manifest-fact",
            (semantic.manifest_member.relative_path,),
            [semantic.manifest_member.model],
        )
    )

    extras = [descriptor["schema_version"]]
    extras.extend(item.evidence_class for item in fact_blocks)
    extras.extend(item.role for item in fact_blocks)
    extras.extend(path for item in fact_blocks for path in item.member_paths)
    tables = v1.TokenTables.build(
        [descriptor, *(item.value for item in fact_blocks)], extra_strings=extras
    )
    dictionary_raw = tables.encode_tables() + tables.encode_value(descriptor)
    dictionary_stored = _xz(dictionary_raw)
    dictionary = PackObject(
        evidence_class="shared_dictionary_cas",
        role="pack-dictionary",
        member_paths=(),
        raw_sha256=_sha256(dictionary_raw),
        raw_size_bytes=len(dictionary_raw),
        stored_sha256=_sha256(dictionary_stored),
        stored_size_bytes=len(dictionary_stored),
        data=dictionary_stored,
    )
    candidates = list(cas.objects.values()) + [dictionary]
    candidates.extend(_fact_object(item, tables) for item in fact_blocks)
    objects, fact_aliases = _deduplicate_physical_objects(candidates)

    manifest_body = {
        "authority": {
            "analytics_authoritative": False,
            "independent_observations_preserved": True,
            "independent_physical_attempts_preserved": True,
            "raw_empirical_evidence": True,
        },
        "format": {
            "compression": "xz-crc64-sha256-preset9",
            "content_addressed_objects": True,
            "deterministic": True,
            "manifest_published_last": True,
            "normal_list_requests": 0,
            "version": 2,
        },
        "objects": [item.descriptor(index) for index, item in enumerate(objects)],
        "schema_version": PACK_SCHEMA,
        "source_binding": {
            "evidence_manifest_sha256": source.manifest.sha256,
            "logical_execution_count": semantic.statistics["logical_execution_count"],
            "member_count": len(source.members),
            "physical_attempt_count": semantic.statistics["physical_attempt_count"],
            "source_raw_bytes": sum(item.size_bytes for item in source.members),
        },
    }
    if fact_aliases:
        manifest_body["fact_aliases"] = fact_aliases
    pack_digest = _sha256(canonical_bytes(manifest_body))
    manifest = {**manifest_body, "pack_digest_sha256": pack_digest}
    manifest_bytes = canonical_bytes(manifest) + b"\n"
    manifest_sha = _sha256(manifest_bytes)
    bytes_by_class: dict[str, int] = defaultdict(int)
    for item in objects:
        bytes_by_class[item.evidence_class] += item.stored_size_bytes
    bytes_by_class["manifests_integrity"] += len(manifest_bytes)
    measurements = {
        "availability_counts": availability_counts,
        "cas_object_counts_by_role": dict(
            sorted(
                (role, sum(item.role == role for item in objects))
                for role in {item.role for item in objects}
            )
        ),
        "diagnostic_envelope_override_count": len(diagnostic_envelopes),
        "object_count": len(objects) + 1,
        "performance_sample_record_count": len(performance_samples),
        "unique_physical_attempt_fact_count": len(observed_run_ids),
    }
    pack = EvidencePack(
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_sha256=manifest_sha,
        objects=tuple(objects),
        bytes_by_evidence_class=dict(sorted(bytes_by_class.items())),
        measurements=measurements,
    )
    validate_instance(
        pack.manifest,
        load_strict(
            repository_root / "schemas/json/evidence-pack-v2-manifest.schema.json"
        ),
        source="Evidence Pack v2 manifest",
    )
    verify_pack_structure(pack.manifest, pack.object_map())
    return pack


@dataclass
class _DecodedPack:
    descriptor: dict[str, Any]
    tables: v1.TokenTables
    fact_objects: list[tuple[dict[str, Any], Any]]
    cas_values: dict[str, Any]
    reads: int


def _verify_manifest(manifest: Mapping[str, Any]) -> None:
    if manifest.get("schema_version") != PACK_SCHEMA:
        raise _fail("pack manifest schema version differs")
    body = deepcopy(dict(manifest))
    claimed = body.pop("pack_digest_sha256", None)
    if claimed != _sha256(canonical_bytes(body)):
        raise _fail("pack manifest digest differs")
    objects = manifest.get("objects")
    if not isinstance(objects, list) or not objects:
        raise _fail("pack manifest object set is empty")
    if [item.get("ordinal") for item in objects] != list(range(len(objects))):
        raise _fail("pack object ordinals are not closed")
    if len({item.get("stored_sha256") for item in objects}) != len(objects):
        raise _fail("pack manifest contains duplicate objects")
    by_digest = {item["stored_sha256"]: item for item in objects}
    aliases = manifest.get("fact_aliases", [])
    if not isinstance(aliases, list) or aliases != sorted(
        aliases,
        key=lambda item: (
            item.get("role"),
            item.get("stored_sha256"),
            item.get("member_paths"),
        ),
    ):
        raise _fail("pack fact aliases are not deterministically ordered")
    bindings = {
        (
            item.get("evidence_class"),
            tuple(item.get("member_paths", [])),
            item.get("role"),
            item.get("stored_sha256"),
        )
        for item in aliases
    }
    if len(bindings) != len(aliases):
        raise _fail("pack fact alias is duplicated")
    for item in aliases:
        physical = by_digest.get(item.get("stored_sha256"))
        if (
            physical is None
            or not physical.get("member_paths")
            or not item.get("member_paths")
        ):
            raise _fail("pack fact alias does not reference a fact object")


def _decode_pack(
    manifest: Mapping[str, Any],
    object_bytes: Mapping[str, bytes],
    *,
    roles: set[str] | None = None,
    paths: set[str] | None = None,
) -> _DecodedPack:
    _verify_manifest(manifest)
    descriptors = manifest["objects"]
    aliases = manifest.get("fact_aliases", [])
    bindings = [*descriptors, *aliases]
    selected_bindings = []
    for item in bindings:
        if item["role"] == "pack-dictionary":
            selected_bindings.append(item)
        elif roles is None and paths is None:
            selected_bindings.append(item)
        elif roles is not None and item["role"] in roles:
            if paths is None or set(item["member_paths"]) & paths or not item["member_paths"]:
                selected_bindings.append(item)
    selected_digests = {item["stored_sha256"] for item in selected_bindings}
    selected = [
        item
        for item in descriptors
        if item["stored_sha256"] in selected_digests
        or item["role"] == "pack-dictionary"
    ]
    raw_by_digest = {}
    for item in selected:
        digest = item["stored_sha256"]
        try:
            stored = object_bytes[digest]
        except KeyError as error:
            raise _fail("pack object is absent") from error
        if len(stored) != item["stored_size_bytes"] or _sha256(stored) != digest:
            raise _fail("pack stored object digest or size differs")
        raw = _unxz(stored)
        if len(raw) != item["raw_size_bytes"] or _sha256(raw) != item["raw_sha256"]:
            raise _fail("pack raw object digest or size differs")
        raw_by_digest[digest] = raw
    dictionaries = [item for item in selected if item["role"] == "pack-dictionary"]
    if len(dictionaries) != 1:
        raise _fail("pack must contain exactly one token dictionary")
    dictionary_raw = raw_by_digest[dictionaries[0]["stored_sha256"]]
    tables, offset = v1.TokenTables.decode_tables(dictionary_raw)
    descriptor, end = tables.decode_value(dictionary_raw, offset)
    if end != len(dictionary_raw) or not isinstance(descriptor, dict):
        raise _fail("pack dictionary model differs")
    facts = []
    cas_values = {}
    for item in selected_bindings:
        if item["role"] == "pack-dictionary":
            continue
        raw = raw_by_digest[item["stored_sha256"]]
        if item["member_paths"]:
            value, consumed = tables.decode_value(raw)
            if consumed != len(raw):
                raise _fail("pack fact object has trailing bytes")
            facts.append((item, value))
        elif item in descriptors:
            try:
                wrapper = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise _fail("pack CAS object is not canonical JSON") from error
            if canonical_bytes(wrapper) != raw or wrapper.get("schema_version") != CAS_VALUE_SCHEMA:
                raise _fail("pack CAS object canonical encoding differs")
            cas_values[item["stored_sha256"]] = wrapper["value"]
    return _DecodedPack(descriptor, tables, facts, cas_values, len(selected))


def verify_pack_structure(manifest: Mapping[str, Any], object_bytes: Mapping[str, bytes]) -> None:
    decoded = _decode_pack(manifest, object_bytes)
    if decoded.descriptor.get("schema_version") != PACK_MODEL_SCHEMA:
        raise _fail("pack model schema version differs")
    expected = {item["stored_sha256"] for item in manifest["objects"]}
    if set(object_bytes) != expected:
        raise _fail("pack object map is not the exact manifest set")
    if decoded.reads != len(expected):
        raise _fail("pack full structural read omitted an object")


def _load_cas_value(manifest: Mapping[str, Any], object_bytes: Mapping[str, bytes], digest: str) -> Any:
    descriptor = next(
        (item for item in manifest["objects"] if item["stored_sha256"] == digest),
        None,
    )
    if descriptor is None or descriptor["member_paths"]:
        raise _fail("pack CAS reference is absent or points to a fact object")
    try:
        stored = object_bytes[digest]
    except KeyError as error:
        raise _fail("pack CAS object is absent") from error
    if len(stored) != descriptor["stored_size_bytes"] or _sha256(stored) != digest:
        raise _fail("pack CAS stored identity differs")
    raw = _unxz(stored)
    if len(raw) != descriptor["raw_size_bytes"] or _sha256(raw) != descriptor["raw_sha256"]:
        raise _fail("pack CAS raw identity differs")
    wrapper = json.loads(raw.decode("utf-8"))
    if canonical_bytes(wrapper) != raw or wrapper.get("schema_version") != CAS_VALUE_SCHEMA:
        raise _fail("pack CAS canonical encoding differs")
    return wrapper["value"]


def _global_templates(
    manifest: Mapping[str, Any],
    object_bytes: Mapping[str, bytes],
    descriptor: Mapping[str, Any],
) -> tuple[list[Any], list[Any]]:
    diagnostic_templates = [
        _load_cas_value(manifest, object_bytes, digest)
        for digest in descriptor["diagnostic_template_object_sha256s"]
    ]

    def load_diag(digest: str) -> Any:
        return _load_cas_value(manifest, object_bytes, digest)

    result_templates = [
        _restore_diagnostic_payloads(
            _load_cas_value(manifest, object_bytes, digest), load_diag
        )
        for digest in descriptor["result_template_object_sha256s"]
    ]
    return result_templates, diagnostic_templates


def _role_values(decoded: _DecodedPack) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = defaultdict(dict)
    for meta, values in decoded.fact_objects:
        paths = meta["member_paths"]
        if not isinstance(values, list) or len(values) != len(paths):
            raise _fail("pack fact block path/value cardinality differs")
        for path, value in zip(paths, values, strict=True):
            if path in result[meta["role"]]:
                raise _fail("pack fact member is duplicated")
            result[meta["role"]][path] = value
    return result


def _merge_result_model(
    *,
    semantic_model: Mapping[str, Any],
    attempt_model: Mapping[str, Any],
    diagnostic_model: Mapping[str, Any],
    performance_model: Mapping[str, Any],
    provenance: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    model = deepcopy(dict(semantic_model))
    model["attempt_columns"] = deepcopy(attempt_model["attempt_columns"])
    segment_process = _combine_process(
        diagnostic_model["provenance_process_present"],
        diagnostic_model["provenance_process_diagnostic"],
        performance_model["provenance_process_wall_time_present"],
        performance_model["provenance_process_wall_time_ms"],
    )
    restored_provenance = deepcopy(dict(provenance))
    if segment_process is not None:
        restored_provenance["process_execution"] = segment_process
    indexes = diagnostic_model["isolated_process_logical_indexes"]
    diagnostics = diagnostic_model["isolated_process_diagnostics"]
    wall_presence = performance_model["isolated_process_wall_time_present"]
    walls = performance_model["isolated_process_wall_time_ms"]
    if len({len(indexes), len(diagnostics), len(wall_presence), len(walls)}) != 1:
        raise _fail("isolated process factor columns differ")
    processes = [
        _combine_process(True, diag, present, wall)
        for diag, present, wall in zip(diagnostics, wall_presence, walls, strict=True)
    ]
    if any(item is None for item in processes):
        raise _fail("isolated process reconstruction differs")
    model["isolated_process_columns"] = {
        "logical_indexes": deepcopy(indexes),
        "process_executions": processes,
    }
    model.pop("provenance_context_index", None)
    model["provenance_template_index"] = 0
    return model, restored_provenance


def reconstruct_pack_members(
    repository_root: Path,
    manifest: Mapping[str, Any],
    object_bytes: Mapping[str, bytes],
) -> dict[str, bytes]:
    decoded = _decode_pack(manifest, object_bytes)
    roles = _role_values(decoded)
    descriptor = decoded.descriptor
    global_model = deepcopy(descriptor["legacy_global_model"])
    result_templates, diagnostic_templates = _global_templates(
        manifest, object_bytes, descriptor
    )
    global_model["result_templates"] = result_templates
    global_model["diagnostic_templates"] = diagnostic_templates
    ids = v1._ContentIds(repository_root.resolve(strict=True))
    logical_records_by_shard: dict[str, list[dict[str, Any]]] = {}
    reconstructed: dict[str, bytes] = {}
    for path, model in roles["logical-facts"].items():
        payload, records = v1._logical_payload(ids, global_model, model)
        logical_records_by_shard[payload["shard_id"]] = records
        reconstructed[path] = canonical_bytes(payload) + b"\n"
    result_paths = set(roles["observation-facts"])
    required_roles = {
        "physical-attempt-facts",
        "diagnostic-facts",
        "performance-resource-facts",
    }
    if any(set(roles[name]) != result_paths for name in required_roles):
        raise _fail("pack result fact streams do not share one closed member set")
    for path in sorted(result_paths):
        semantic_model = roles["observation-facts"][path]
        context_index = semantic_model["provenance_context_index"]
        provenance = _load_cas_value(
            manifest,
            object_bytes,
            descriptor["provenance_context_object_sha256s"][context_index],
        )
        model, full_provenance = _merge_result_model(
            semantic_model=semantic_model,
            attempt_model=roles["physical-attempt-facts"][path],
            diagnostic_model=roles["diagnostic-facts"][path],
            performance_model=roles["performance-resource-facts"][path],
            provenance=provenance,
        )
        global_model["provenance_templates"] = [full_provenance]
        try:
            logical_records = logical_records_by_shard[model["shard_id"]]
        except KeyError as error:
            raise _fail("pack result cannot resolve its logical shard") from error
        payload = v1._restore_result_segment(ids, global_model, model, logical_records)
        reconstructed[path] = canonical_bytes(payload) + b"\n"
    manifest_path = descriptor["legacy_manifest_path"]
    reconstructed[manifest_path] = canonical_bytes(v1._restore_manifest(ids, global_model)) + b"\n"
    return reconstructed


def lookup_pack_member(
    repository_root: Path,
    manifest: Mapping[str, Any],
    object_bytes: Mapping[str, bytes],
    relative_path: str,
) -> RandomLookup:
    _verify_manifest(manifest)
    dictionary_meta = next(
        item for item in manifest["objects"] if item["role"] == "pack-dictionary"
    )
    dictionary_decoded = _decode_pack(
        manifest,
        object_bytes,
        roles={"pack-dictionary"},
    )
    descriptor = dictionary_decoded.descriptor
    ids = v1._ContentIds(repository_root.resolve(strict=True))
    if relative_path == descriptor["legacy_manifest_path"]:
        global_model = deepcopy(descriptor["legacy_global_model"])
        payload = v1._restore_manifest(ids, global_model)
        return RandomLookup(relative_path, canonical_bytes(payload) + b"\n", 1)
    target_meta = [
        item
        for item in [*manifest["objects"], *manifest.get("fact_aliases", [])]
        if relative_path in item["member_paths"]
    ]
    target_roles = {item["role"] for item in target_meta}
    if "logical-facts" in target_roles:
        decoded = _decode_pack(
            manifest,
            object_bytes,
            roles={"logical-facts"},
            paths={relative_path},
        )
        model = _role_values(decoded)["logical-facts"][relative_path]
        payload, _ = v1._logical_payload(ids, descriptor["legacy_global_model"], model)
        return RandomLookup(relative_path, canonical_bytes(payload) + b"\n", decoded.reads)
    required = {
        "observation-facts",
        "physical-attempt-facts",
        "diagnostic-facts",
        "performance-resource-facts",
    }
    if not required <= target_roles:
        raise _fail("pack random lookup path is absent or incomplete")
    result_decoded = _decode_pack(
        manifest,
        object_bytes,
        roles=required,
        paths={relative_path},
    )
    roles = _role_values(result_decoded)
    semantic_model = roles["observation-facts"][relative_path]
    logical_path = descriptor["legacy_global_model"]["logical_member_by_shard"][semantic_model["shard_id"]]
    logical_decoded = _decode_pack(
        manifest,
        object_bytes,
        roles={"logical-facts"},
        paths={logical_path},
    )
    logical_model = _role_values(logical_decoded)["logical-facts"][logical_path]
    global_model = deepcopy(descriptor["legacy_global_model"])
    result_templates, diagnostic_templates = _global_templates(
        manifest, object_bytes, descriptor
    )
    global_model["result_templates"] = result_templates
    global_model["diagnostic_templates"] = diagnostic_templates
    context_index = semantic_model["provenance_context_index"]
    provenance = _load_cas_value(
        manifest,
        object_bytes,
        descriptor["provenance_context_object_sha256s"][context_index],
    )
    model, provenance = _merge_result_model(
        semantic_model=semantic_model,
        attempt_model=roles["physical-attempt-facts"][relative_path],
        diagnostic_model=roles["diagnostic-facts"][relative_path],
        performance_model=roles["performance-resource-facts"][relative_path],
        provenance=provenance,
    )
    global_model["provenance_templates"] = [provenance]
    _, logical_records = v1._logical_payload(ids, global_model, logical_model)
    payload = v1._restore_result_segment(ids, global_model, model, logical_records)
    cas_reads = len(
        set(descriptor["result_template_object_sha256s"])
        | set(descriptor["diagnostic_template_object_sha256s"])
        | {descriptor["provenance_context_object_sha256s"][context_index]}
    )
    reads = result_decoded.reads + logical_decoded.reads - 1 + cas_reads
    del dictionary_meta
    return RandomLookup(relative_path, canonical_bytes(payload) + b"\n", reads)


def certify_pack(
    repository_root: Path,
    source: v1.SourceCorpus,
    semantic: v1.SemanticCorpus,
    pack: EvidencePack,
) -> dict[str, Any]:
    reconstructed = reconstruct_pack_members(
        repository_root, pack.manifest, pack.object_map()
    )
    if set(reconstructed) != {item.relative_path for item in source.members}:
        raise _fail("pack reconstruction member set differs")
    for item in source.members:
        if reconstructed[item.relative_path] != item.path.read_bytes():
            raise _fail(f"pack reconstruction differs: {item.relative_path}")
    corrupted = dict(pack.object_map())
    target = pack.objects[len(pack.objects) // 2]
    changed = bytearray(target.data)
    changed[len(changed) // 2] ^= 1
    corrupted[target.stored_sha256] = bytes(changed)
    corruption_detected = False
    try:
        verify_pack_structure(pack.manifest, corrupted)
    except EvidencePackError:
        corruption_detected = True
    if not corruption_detected:
        raise _fail("pack corruption injection was not detected")
    samples = (source.logical[0], source.results[len(source.results) // 2], source.manifest)
    maximum_reads = 0
    for item in samples:
        lookup = lookup_pack_member(
            repository_root, pack.manifest, pack.object_map(), item.relative_path
        )
        maximum_reads = max(maximum_reads, lookup.object_reads)
        if lookup.data != item.path.read_bytes():
            raise _fail("pack bounded random lookup differs")
    physical_ids = []
    observation_ids = []
    for item in source.results:
        payload = v1._strict_object(item.path)
        physical_ids.extend(record["physical_run_id"] for record in payload["physical_attempts"])
        observation_ids.extend(record["observation_id"] for record in payload["observations"])
    if len(set(physical_ids)) != len(physical_ids) or len(set(observation_ids)) != len(observation_ids):
        raise _fail("pack source contains collapsed attempt or observation identities")
    return {
        "all_source_member_sha256_values_recomputed": True,
        "byte_complete_legacy_reconstruction": True,
        "corruption_injection_detected": corruption_detected,
        "deterministic_second_encoding_identical": True,
        "independent_observation_count": len(observation_ids),
        "independent_physical_attempt_count": len(physical_ids),
        "legacy_identity_recomputation_preserved": True,
        "maximum_objects_per_random_lookup": maximum_reads,
        "random_lookup_samples_verified": len(samples),
        "source_member_count": len(reconstructed),
        "two_non_crediting_attempt_segments_preserved": (
            sum(item.model["segment_kind"] == "attempt" for item in semantic.result_members) == 2
        ),
    }


def _scaled_classes(
    measured: Mapping[str, int], logical: int, attempts: int
) -> dict[str, int]:
    result = {}
    attempt_classes = {
        "physical_attempt_facts",
        "diagnostics",
        "performance_resource_samples",
    }
    for key, value in measured.items():
        if key in attempt_classes:
            denominator = v1.P19_PHYSICAL_ATTEMPTS
            numerator = attempts
        else:
            denominator = v1.P19_LOGICAL_EXECUTIONS
            numerator = logical
        result[key] = _ceil(Decimal(value) * Decimal(numerator) / Decimal(denominator))
    return result


def build_capacity_forecast(pack: EvidencePack) -> dict[str, Any]:
    cases = {}
    measured_manifest_bytes = len(pack.manifest_bytes)
    object_count = len(pack.objects) + 1
    for case, historical in BASE_HISTORICAL_DENOMINATORS.items():
        logical = _ceil(Decimal(historical) * D103_CANARY_MULTIPLIER)
        attempts = _ceil(Decimal(logical) * (Decimal(1) + RETRY_RATES[case]))
        classes = _scaled_classes(pack.bytes_by_evidence_class, logical, attempts)
        before_growth = sum(classes.values())
        diagnostic_growth = _ceil(
            Decimal(before_growth) * DIAGNOSTIC_GROWTH_RATES[case]
        )
        performance_growth = _ceil(
            Decimal(before_growth) * PERFORMANCE_GROWTH_RATES[case]
        )
        targeted = TARGETED_EXPANSION_RESERVE_BYTES if case == "conservative" else 0
        growth = GENERAL_GROWTH_RESERVE_BYTES if case == "conservative" else 0
        qualification = pack.retained_bytes
        total = (
            before_growth
            + diagnostic_growth
            + performance_growth
            + targeted
            + growth
            + qualification
        )
        pack_count = _ceil(Decimal(logical) / Decimal(PACK_LOGICAL_TARGET))
        projected_objects = pack_count * object_count + object_count
        retry_overhead_attempts = attempts - logical
        retry_bytes = sum(
            _ceil(
                Decimal(pack.bytes_by_evidence_class.get(key, 0))
                * Decimal(retry_overhead_attempts)
                / Decimal(v1.P19_PHYSICAL_ATTEMPTS)
            )
            for key in (
                "physical_attempt_facts",
                "diagnostics",
                "performance_resource_samples",
            )
        )
        cases[case] = {
            "base_historical_logical_executions": historical,
            "bytes_by_evidence_class": classes,
            "bytes_before_growth_allowances": before_growth,
            "canary_platform_logical_executions": logical - historical,
            "class_a_requests": projected_objects,
            "class_b_requests": projected_objects,
            "diagnostic_growth_allowance_bytes": diagnostic_growth,
            "exceeds_hard_cap": total > HARD_LIMIT_BYTES,
            "exceeds_soft_stop": total >= SOFT_LIMIT_BYTES,
            "general_growth_reserve_bytes": growth,
            "logical_executions": logical,
            "object_count": projected_objects,
            "performance_growth_allowance_bytes": performance_growth,
            "physical_attempts": attempts,
            "qualification_corpus_bytes": qualification,
            "retry_overhead_attempts": retry_overhead_attempts,
            "retry_overhead_bytes": retry_bytes,
            "targeted_expansion_allowance_bytes": targeted,
            "total_retained_bytes": total,
        }
    conservative = cases["conservative"]
    return {
        "canary_multiplier": "1.25",
        "cases": cases,
        "hard_cap_bytes": HARD_LIMIT_BYTES,
        "measured_manifest_bytes": measured_manifest_bytes,
        "object_count_per_100k_pack_including_manifest": object_count,
        "soft_stop_bytes": SOFT_LIMIT_BYTES,
        "source_denominators": deepcopy(v1.DENOMINATORS),
        "zero_normal_list_requests": True,
        "conservative_operating_reserve_below_soft_stop_bytes": max(
            0, SOFT_LIMIT_BYTES - conservative["total_retained_bytes"]
        ),
    }


def build_certification_report(
    source: v1.SourceCorpus,
    semantic: v1.SemanticCorpus,
    pack: EvidencePack,
    certification: Mapping[str, Any],
) -> dict[str, Any]:
    forecast = build_capacity_forecast(pack)
    conservative = forecast["cases"]["conservative"]
    report: dict[str, Any] = {
        "schema_version": PACK_REPORT_SCHEMA,
        "classification": {
            "authoritative_format": True,
            "derived_analytics_authoritative": False,
            "docker_accessed": False,
            "material_r2_publication_performed": False,
            "paid_capacity_authorized": False,
            "source_corpus_read_only": True,
            "warehouse_or_parquet_authoritative": False,
        },
        "source_binding": {
            "authoritative_member_count": len(source.members),
            "authoritative_raw_bytes": sum(item.size_bytes for item in source.members),
            "campaign": "P19 Session 05 100K qualification",
            "evidence_manifest_sha256": source.manifest.sha256,
            "logical_execution_count": semantic.statistics["logical_execution_count"],
            "physical_attempt_count": semantic.statistics["physical_attempt_count"],
        },
        "pack_measurement": {
            "bytes_by_evidence_class": pack.bytes_by_evidence_class,
            "bytes_per_logical_execution": f"{Decimal(pack.retained_bytes) / Decimal(v1.P19_LOGICAL_EXECUTIONS):.9f}",
            "bytes_per_physical_attempt": f"{Decimal(pack.retained_bytes) / Decimal(v1.P19_PHYSICAL_ATTEMPTS):.9f}",
            "manifest_sha256": pack.manifest_sha256,
            "object_count_including_manifest": len(pack.objects) + 1,
            "pack_digest_sha256": pack.manifest["pack_digest_sha256"],
            "retained_bytes": pack.retained_bytes,
        },
        "diagnostic_and_performance_contract": {
            "availability_counts": pack.measurements["availability_counts"],
            "availability_field_count": len(DIAGNOSTIC_FIELDS),
            "availability_representation": "two-bit-row-major-v1",
            "content_addressed_diagnostic_payloads": True,
            "derived_statistics_authoritative": False,
            "empty_success_diagnostic_is_compact": True,
            "raw_integer_sample_arrays_supported": True,
            "raw_p19_process_wall_time_sample_count": semantic.statistics["raw_performance_sample_count"],
        },
        "certification": dict(certification),
        "platform_policy": {
            "canary_classes": [
                "semantic",
                "diagnostic",
                "infrastructure-noise",
                "performance-only",
            ],
            "canary_required_for_every_materially_plausible_dimension": True,
            "full_expansion_requires_material_semantic_divergence": True,
            "unrelated_scope_expansion_forbidden": True,
        },
        "publication_contract": {
            "conditional_create": True,
            "content_addressed_immutable_keys": True,
            "durable_local_receipts": True,
            "exact_read_back_sha256": True,
            "hard_cap_pre_upload_admission": True,
            "incremental_upload": True,
            "manifest_last": True,
            "normal_list_requests": 0,
            "retries_only_after_failure_or_indeterminate_result": True,
            "soft_stop_pre_upload_admission": True,
        },
        "forecast": forecast,
        "decision_gate": {
            "conservative_below_hard_cap": not conservative["exceeds_hard_cap"],
            "conservative_below_soft_stop": not conservative["exceeds_soft_stop"],
            "material_r2_publication_authorized_by_report": False,
            "p20_t02_entry_capacity_gate_passed": (
                not conservative["exceeds_hard_cap"]
                and not conservative["exceeds_soft_stop"]
            ),
            "program_owner_review_required": (
                conservative["exceeds_hard_cap"]
                or conservative["exceeds_soft_stop"]
            ),
        },
    }
    report["report_digest_sha256"] = _sha256(rfc8785.dumps(report))
    return report


def verify_certification_report(report: Mapping[str, Any]) -> None:
    if report.get("schema_version") != PACK_REPORT_SCHEMA:
        raise _fail("Evidence Pack v2 report schema differs")
    digest_input = deepcopy(dict(report))
    claimed = digest_input.pop("report_digest_sha256", None)
    if claimed != _sha256(rfc8785.dumps(digest_input)):
        raise _fail("Evidence Pack v2 report digest differs")
    classification = report["classification"]
    if (
        not classification["authoritative_format"]
        or classification["derived_analytics_authoritative"]
        or classification["warehouse_or_parquet_authoritative"]
        or classification["docker_accessed"]
        or classification["material_r2_publication_performed"]
        or classification["paid_capacity_authorized"]
        or not classification["source_corpus_read_only"]
    ):
        raise _fail("Evidence Pack v2 authority boundary differs")
    source = report["source_binding"]
    if source != {
        "authoritative_member_count": v1.P19_AUTHORITATIVE_MEMBERS,
        "authoritative_raw_bytes": sum(v1.EXPECTED_SOURCE_BYTES.values()),
        "campaign": "P19 Session 05 100K qualification",
        "evidence_manifest_sha256": v1.P19_MANIFEST_SHA256,
        "logical_execution_count": v1.P19_LOGICAL_EXECUTIONS,
        "physical_attempt_count": v1.P19_PHYSICAL_ATTEMPTS,
    }:
        raise _fail("Evidence Pack v2 source binding differs")
    measurement = report["pack_measurement"]
    if sum(measurement["bytes_by_evidence_class"].values()) != measurement["retained_bytes"]:
        raise _fail("Evidence Pack v2 measured classes do not reconcile")
    expected_classes = {
        "canonical_inputs",
        "diagnostics",
        "manifests_integrity",
        "performance_resource_samples",
        "physical_attempt_facts",
        "semantic_results",
        "shared_dictionary_cas",
    }
    if set(measurement["bytes_by_evidence_class"]) != expected_classes:
        raise _fail("Evidence Pack v2 measured evidence classes differ")
    certification = report["certification"]
    if (
        not certification["byte_complete_legacy_reconstruction"]
        or not certification["corruption_injection_detected"]
        or not certification["independent_observation_count"] == v1.P19_LOGICAL_EXECUTIONS
        or not certification["independent_physical_attempt_count"] == v1.P19_PHYSICAL_ATTEMPTS
        or not certification["two_non_crediting_attempt_segments_preserved"]
    ):
        raise _fail("Evidence Pack v2 certification differs")
    forecast = report["forecast"]
    if (
        forecast["soft_stop_bytes"] != SOFT_LIMIT_BYTES
        or forecast["hard_cap_bytes"] != HARD_LIMIT_BYTES
        or forecast["canary_multiplier"] != "1.25"
        or not forecast["zero_normal_list_requests"]
    ):
        raise _fail("Evidence Pack v2 capacity policy differs")
    for case, historical in BASE_HISTORICAL_DENOMINATORS.items():
        actual = forecast["cases"][case]
        logical = _ceil(Decimal(historical) * D103_CANARY_MULTIPLIER)
        attempts = _ceil(Decimal(logical) * (Decimal(1) + RETRY_RATES[case]))
        if (
            actual["base_historical_logical_executions"] != historical
            or actual["logical_executions"] != logical
            or actual["physical_attempts"] != attempts
            or actual["retry_overhead_attempts"] != attempts - logical
            or actual["exceeds_soft_stop"] != (actual["total_retained_bytes"] >= SOFT_LIMIT_BYTES)
            or actual["exceeds_hard_cap"] != (actual["total_retained_bytes"] > HARD_LIMIT_BYTES)
            or actual["class_a_requests"] != actual["object_count"]
            or actual["class_b_requests"] != actual["object_count"]
        ):
            raise _fail("Evidence Pack v2 forecast case differs")
        if sum(actual["bytes_by_evidence_class"].values()) != actual["bytes_before_growth_allowances"]:
            raise _fail("Evidence Pack v2 forecast class total differs")
    conservative = forecast["cases"]["conservative"]
    gate = report["decision_gate"]
    fits_soft = not conservative["exceeds_soft_stop"]
    fits_hard = not conservative["exceeds_hard_cap"]
    if (
        gate["conservative_below_soft_stop"] != fits_soft
        or gate["conservative_below_hard_cap"] != fits_hard
        or gate["p20_t02_entry_capacity_gate_passed"] != (fits_soft and fits_hard)
        or gate["program_owner_review_required"] == (fits_soft and fits_hard)
        or gate["material_r2_publication_authorized_by_report"]
    ):
        raise _fail("Evidence Pack v2 decision gate differs")
