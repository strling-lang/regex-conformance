"""Compact, deterministic Evidence Pack v3 production representation.

The format keeps semantic observations, physical attempts, diagnostics,
performance samples, and provenance as independent facts.  It removes two
non-empirical features of the previous container contract for future packs:
randomly assigned observation/attempt labels and the byte identity of the old
container layout.  Stable identities are derived from immutable execution
coordinates, while content-addressed blocks and the root manifest provide the
new integrity boundary.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_CEILING
import hashlib
import json
import lzma
import math
from pathlib import Path
import re
import uuid
from typing import Any, Iterable, Mapping, Sequence

import rfc8785

from regex_conformance_schema.jsonio import canonical_bytes

from .factorized_evidence import TokenTables


PACK_SCHEMA = "evidence-pack-manifest.v3"
REPORT_SCHEMA = "evidence-pack-v3-capacity-certification.v1"
PACK_OBJECT_PREFIX = "regex-conformance/evidence-pack-v3/objects/sha256"
PACK_MANIFEST_PREFIX = "regex-conformance/evidence-pack-v3/manifests/sha256"
SOFT_LIMIT_BYTES = 8_000_000_000
HARD_LIMIT_BYTES = 10_000_000_000

EVIDENCE_CLASSES = (
    "canonical_inputs",
    "diagnostics",
    "manifests_integrity",
    "performance_resource_samples",
    "physical_attempt_facts",
    "profile_environment_release_provenance",
    "semantic_results",
    "shared_dictionary_cas",
)
ATTEMPT_SCALED_CLASSES = frozenset(
    {"diagnostics", "performance_resource_samples", "physical_attempt_facts"}
)
AUTHORIZED_OMISSIONS = (
    "legacy-random-observation-uuidv7-labels",
    "legacy-random-physical-attempt-uuidv7-labels",
    "legacy-v2-container-path-and-object-identities",
)

_RCID_HASH = re.compile(r"^(rcid:v1:[^:]+:h:[^:]+:)([0-9a-f]{64})$")
_RCID_UUID = re.compile(
    r"^(rcid:v1:[^:]+:u:[^:]+:)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)
_RCID_U7 = re.compile(
    r"^(rcid:v1:[^:]+:u7:)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_MILLISECOND = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
_ASSIGNED_IDENTITY_KEYS = frozenset(
    {"observation_id", "observation_ids", "physical_run_id", "physical_run_ids"}
)


class EvidencePackV3Error(ValueError):
    """Evidence Pack v3 violates its deterministic retained-fact contract."""


def _fail(message: str) -> EvidencePackV3Error:
    return EvidencePackV3Error(message)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _xz(value: bytes) -> bytes:
    return lzma.compress(
        value, format=lzma.FORMAT_XZ, check=lzma.CHECK_SHA256, preset=9
    )


def _unxz(value: bytes) -> bytes:
    try:
        return lzma.decompress(value, format=lzma.FORMAT_XZ)
    except lzma.LZMAError as error:
        raise _fail("pack block cannot be decompressed") from error


def _ceil(value: Decimal) -> int:
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def _uvarint(value: int) -> bytes:
    if value < 0:
        raise _fail("unsigned varint cannot encode a negative value")
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _read_uvarint(data: memoryview, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if offset >= len(data) or shift >= 70:
            raise _fail("invalid unsigned varint")
        item = data[offset]
        offset += 1
        value |= (item & 0x7F) << shift
        if not item & 0x80:
            return value, offset
        shift += 7


def _svarint(value: int) -> bytes:
    return _uvarint((value << 1) ^ (value >> 63))


def _read_svarint(data: memoryview, offset: int) -> tuple[int, int]:
    value, offset = _read_uvarint(data, offset)
    return (value >> 1) ^ -(value & 1), offset


def _pack_bytes(value: bytes) -> bytes:
    return _uvarint(len(value)) + value


def _read_bytes(data: memoryview, offset: int) -> tuple[bytes, int]:
    length, offset = _read_uvarint(data, offset)
    end = offset + length
    if end > len(data):
        raise _fail("truncated length-delimited value")
    return bytes(data[offset:end]), end


def _uuid7_parts(value: str) -> tuple[int, int]:
    integer = uuid.UUID(value).int
    timestamp = integer >> 80
    random_a = (integer >> 64) & 0xFFF
    random_b = integer & ((1 << 62) - 1)
    return timestamp, (random_a << 62) | random_b


def _uuid7_from_parts(timestamp: int, random_value: int) -> str:
    integer = (
        (timestamp << 80)
        | (0x7 << 76)
        | ((random_value >> 62) << 64)
        | (0b10 << 62)
        | (random_value & ((1 << 62) - 1))
    )
    return str(uuid.UUID(int=integer))


def _pack_74(values: Sequence[int]) -> bytes:
    output = bytearray()
    accumulator = available = 0
    for value in values:
        if not 0 <= value < 1 << 74:
            raise _fail("UUID random value exceeds 74 bits")
        accumulator |= value << available
        available += 74
        while available >= 8:
            output.append(accumulator & 0xFF)
            accumulator >>= 8
            available -= 8
    if available:
        output.append(accumulator & 0xFF)
    return bytes(output)


def _unpack_74(encoded: bytes, count: int) -> list[int]:
    if len(encoded) != (count * 74 + 7) // 8:
        raise _fail("packed UUID random stream length differs")
    values: list[int] = []
    accumulator = available = offset = 0
    for _ in range(count):
        while available < 74:
            accumulator |= encoded[offset] << available
            available += 8
            offset += 1
        values.append(accumulator & ((1 << 74) - 1))
        accumulator >>= 74
        available -= 74
    return values


def encode_token_tables(tables: TokenTables) -> bytes:
    """Encode token tables with exact UUIDv7 bit packing."""

    output = bytearray(b"TBL3")
    output += _uvarint(len(tables.prefixes))
    for value in tables.prefixes:
        output += _pack_bytes(value.encode("utf-8"))
    output += _uvarint(len(tables.strings))
    index = 0
    while index < len(tables.strings):
        value = tables.strings[index]
        u7 = _RCID_U7.fullmatch(value)
        if u7:
            prefix = u7.group(1)
            group: list[str] = []
            while index < len(tables.strings):
                match = _RCID_U7.fullmatch(tables.strings[index])
                if not match or match.group(1) != prefix:
                    break
                group.append(match.group(2))
                index += 1
            parts = [_uuid7_parts(item) for item in group]
            timestamps = [item[0] for item in parts]
            if timestamps != sorted(timestamps):
                raise _fail("sorted UUIDv7 strings are not timestamp ordered")
            output.append(6)
            output += _pack_bytes(prefix.encode("utf-8"))
            output += _uvarint(len(group))
            output += _uvarint(timestamps[0])
            for previous, current in zip(timestamps, timestamps[1:]):
                output += _uvarint(current - previous)
            output += _pack_bytes(_pack_74([item[1] for item in parts]))
            continue
        hash_match = _RCID_HASH.fullmatch(value)
        uuid_match = _RCID_UUID.fullmatch(value)
        if hash_match:
            output.append(1)
            output += _uvarint(tables.prefix_indexes[hash_match.group(1)])
            output += bytes.fromhex(hash_match.group(2))
        elif uuid_match:
            output.append(2)
            output += _uvarint(tables.prefix_indexes[uuid_match.group(1)])
            output += bytes.fromhex(uuid_match.group(2).replace("-", ""))
        elif _HEX64.fullmatch(value):
            output.append(3)
            output += bytes.fromhex(value)
        elif _UUID.fullmatch(value):
            output.append(4)
            output += bytes.fromhex(value.replace("-", ""))
        elif _MILLISECOND.fullmatch(value):
            output.append(5)
            instant = datetime.fromisoformat(value[:-1] + "+00:00")
            output += _svarint(int(instant.timestamp() * 1000))
        else:
            output.append(0)
            output += _pack_bytes(value.encode("utf-8"))
        index += 1
    output += _uvarint(len(tables.shapes))
    for shape in tables.shapes:
        output += _uvarint(len(shape))
        for key in shape:
            output += _uvarint(tables.string_indexes[key])
    return bytes(output)


def decode_token_tables(encoded: bytes) -> tuple[TokenTables, int]:
    data = memoryview(encoded)
    if bytes(data[:4]) != b"TBL3":
        raise _fail("token table magic differs")
    offset = 4
    prefix_count, offset = _read_uvarint(data, offset)
    prefixes: list[str] = []
    for _ in range(prefix_count):
        raw, offset = _read_bytes(data, offset)
        prefixes.append(raw.decode("utf-8"))
    string_count, offset = _read_uvarint(data, offset)
    strings: list[str] = []
    while len(strings) < string_count:
        if offset >= len(data):
            raise _fail("truncated token table")
        kind = data[offset]
        offset += 1
        if kind == 0:
            raw, offset = _read_bytes(data, offset)
            strings.append(raw.decode("utf-8"))
        elif kind in (1, 2):
            prefix_index, offset = _read_uvarint(data, offset)
            if prefix_index >= len(prefixes):
                raise _fail("token prefix index is out of range")
            length = 32 if kind == 1 else 16
            end = offset + length
            if end > len(data):
                raise _fail("truncated typed identity")
            suffix = bytes(data[offset:end]).hex()
            offset = end
            if kind == 2:
                suffix = f"{suffix[:8]}-{suffix[8:12]}-{suffix[12:16]}-{suffix[16:20]}-{suffix[20:]}"
            strings.append(prefixes[prefix_index] + suffix)
        elif kind == 3:
            end = offset + 32
            if end > len(data):
                raise _fail("truncated digest")
            strings.append(bytes(data[offset:end]).hex())
            offset = end
        elif kind == 4:
            end = offset + 16
            if end > len(data):
                raise _fail("truncated UUID")
            raw = bytes(data[offset:end]).hex()
            offset = end
            strings.append(
                f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}"
            )
        elif kind == 5:
            milliseconds, offset = _read_svarint(data, offset)
            seconds, remainder = divmod(milliseconds, 1000)
            value = datetime.fromtimestamp(seconds, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S"
            )
            strings.append(value + f".{remainder:03d}Z")
        elif kind == 6:
            prefix_raw, offset = _read_bytes(data, offset)
            prefix = prefix_raw.decode("utf-8")
            count, offset = _read_uvarint(data, offset)
            if not count or len(strings) + count > string_count:
                raise _fail("UUIDv7 token group count differs")
            first, offset = _read_uvarint(data, offset)
            timestamps = [first]
            for _ in range(count - 1):
                delta, offset = _read_uvarint(data, offset)
                timestamps.append(timestamps[-1] + delta)
            packed, offset = _read_bytes(data, offset)
            randoms = _unpack_74(packed, count)
            strings.extend(
                prefix + _uuid7_from_parts(timestamp, random_value)
                for timestamp, random_value in zip(timestamps, randoms, strict=True)
            )
        else:
            raise _fail("unknown typed string kind")
    shape_count, offset = _read_uvarint(data, offset)
    shapes: list[tuple[str, ...]] = []
    for _ in range(shape_count):
        length, offset = _read_uvarint(data, offset)
        shape: list[str] = []
        for _ in range(length):
            key_index, offset = _read_uvarint(data, offset)
            if key_index >= len(strings):
                raise _fail("shape key index is out of range")
            shape.append(strings[key_index])
        shapes.append(tuple(shape))
    ordered_strings = tuple(strings)
    ordered_prefixes = tuple(prefixes)
    ordered_shapes = tuple(shapes)
    return (
        TokenTables(
            strings=ordered_strings,
            string_indexes={value: index for index, value in enumerate(ordered_strings)},
            prefixes=ordered_prefixes,
            prefix_indexes={value: index for index, value in enumerate(ordered_prefixes)},
            shapes=ordered_shapes,
            shape_indexes={value: index for index, value in enumerate(ordered_shapes)},
        ),
        offset,
    )


def encode_value(value: Any) -> bytes:
    tables = TokenTables.build([value])
    return encode_token_tables(tables) + tables.encode_value(value)


def decode_value(encoded: bytes) -> Any:
    tables, offset = decode_token_tables(encoded)
    value, end = tables.decode_value(encoded, offset)
    if end != len(encoded):
        raise _fail("encoded value has trailing bytes")
    return value


def _coordinate_identity(namespace: str, constituents: Mapping[str, Any]) -> str:
    digest = _sha256(canonical_bytes(dict(constituents)))
    return f"rcid:v1:{namespace}:h:jcs-sha256-v1:{digest}"


def derive_observation_identity(
    campaign_manifest_sha256: str,
    partition: int,
    shard: int,
    logical_index: int,
) -> str:
    return _coordinate_identity(
        "observation",
        {
            "campaign_manifest_sha256": campaign_manifest_sha256,
            "logical_index": logical_index,
            "partition": partition,
            "schema_version": "observation-coordinate.v1",
            "shard": shard,
        },
    )


def derive_physical_attempt_identity(
    campaign_manifest_sha256: str,
    partition: int,
    shard: int,
    logical_index: int,
    attempt_number: int,
) -> str:
    if attempt_number < 1:
        raise _fail("attempt number must be positive")
    return _coordinate_identity(
        "physical-run",
        {
            "attempt_number": attempt_number,
            "campaign_manifest_sha256": campaign_manifest_sha256,
            "logical_index": logical_index,
            "partition": partition,
            "schema_version": "physical-attempt-coordinate.v1",
            "shard": shard,
        },
    )


def strip_legacy_assigned_identities(value: Any) -> tuple[Any, dict[str, int]]:
    """Remove only authorized assigned labels; preserve every surrounding fact."""

    counts = {"observation_uuidv7_labels": 0, "physical_attempt_uuidv7_labels": 0}

    def visit(item: Any, key: str | None = None) -> Any:
        if key in _ASSIGNED_IDENTITY_KEYS:
            values = item if isinstance(item, list) else [item]
            for value in values:
                if not isinstance(value, str):
                    raise _fail("assigned identity field is not a string")
                if value.startswith("rcid:v1:observation:u7:"):
                    counts["observation_uuidv7_labels"] += 1
                elif value.startswith("rcid:v1:physical-run:u7:"):
                    counts["physical_attempt_uuidv7_labels"] += 1
                else:
                    raise _fail("identity omission attempted on a non-legacy identity")
            return {"derived_identity": "execution-coordinate-sha256-v1"}
        if isinstance(item, dict):
            return {name: visit(child, name) for name, child in item.items()}
        if isinstance(item, list):
            return [visit(child) for child in item]
        if isinstance(item, str):
            if item.startswith("rcid:v1:observation:u7:"):
                counts["observation_uuidv7_labels"] += 1
                return {"derived_identity": "observation-coordinate-sha256-v1"}
            if item.startswith("rcid:v1:physical-run:u7:"):
                counts["physical_attempt_uuidv7_labels"] += 1
                return {"derived_identity": "physical-attempt-coordinate-sha256-v1"}
        return deepcopy(item)

    return visit(value), counts


def _strip_assigned_identities(
    value: Any,
    counts: Counter[str],
    cas_indexes: Mapping[str, int] | None = None,
) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if key in _ASSIGNED_IDENTITY_KEYS:
                values = child if isinstance(child, list) else [child]
                for identity in values:
                    if not isinstance(identity, str):
                        raise _fail("assigned identity field is not a string")
                    if identity.startswith("rcid:v1:observation:u7:"):
                        counts["observation_uuidv7_labels"] += 1
                    elif identity.startswith("rcid:v1:physical-run:u7:"):
                        counts["physical_attempt_uuidv7_labels"] += 1
                    else:
                        raise _fail("identity omission attempted on a non-legacy identity")
                continue
            result[key] = _strip_assigned_identities(child, counts, cas_indexes)
        return result
    if isinstance(value, list):
        return [_strip_assigned_identities(item, counts, cas_indexes) for item in value]
    if isinstance(value, str):
        if value.startswith("rcid:v1:physical-run:u7:"):
            counts["physical_attempt_uuidv7_labels"] += 1
            return {"derived_identity": "physical-attempt-coordinate-sha256-v1"}
        if value.startswith("rcid:v1:observation:u7:"):
            counts["observation_uuidv7_labels"] += 1
            return {"derived_identity": "observation-coordinate-sha256-v1"}
        if cas_indexes is not None and value in cas_indexes:
            return {"cas_index": cas_indexes[value]}
    return deepcopy(value)


def _compact_partition_descriptor(
    descriptor: Mapping[str, Any],
    cas_indexes: Mapping[str, int],
    removed: Counter[str],
) -> dict[str, Any]:
    legacy = descriptor["legacy_global_model"]
    source_manifest = legacy["manifest"]
    return {
        "canonical_definition_cas_indexes": [
            cas_indexes[value]
            for value in descriptor["canonical_definition_object_sha256s"]
        ],
        "diagnostic_contract": deepcopy(descriptor["diagnostic_contract"]),
        "diagnostic_template_cas_indexes": [
            cas_indexes[value]
            for value in descriptor["diagnostic_template_object_sha256s"]
        ],
        "identity_context": deepcopy(legacy["identity_context"]),
        "interruptions": _strip_assigned_identities(
            source_manifest["interruptions"], removed, cas_indexes
        ),
        "logical_templates": _strip_assigned_identities(
            legacy["logical_templates"], removed, cas_indexes
        ),
        "performance_contract": deepcopy(descriptor["performance_contract"]),
        "provenance_context_cas_indexes": [
            cas_indexes[value]
            for value in descriptor["provenance_context_object_sha256s"]
        ],
        "result_template_cas_indexes": [
            cas_indexes[value]
            for value in descriptor["result_template_object_sha256s"]
        ],
        "source_binding": {
            "logical_member_count": legacy["source_binding"]["logical_member_count"],
            "raw_result_member_count": legacy["source_binding"]["raw_result_member_count"],
        },
    }


@dataclass(frozen=True)
class RetainedBlock:
    evidence_class: str
    role: str
    lookup_group: int
    value: Any

    def __post_init__(self) -> None:
        if self.evidence_class not in EVIDENCE_CLASSES:
            raise _fail("unknown evidence class")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", self.role):
            raise _fail("block role is not a durable token")
        if self.lookup_group < 0:
            raise _fail("lookup group is negative")


@dataclass(frozen=True)
class EvidencePackV3:
    manifest: dict[str, Any]
    manifest_bytes: bytes
    manifest_sha256: str
    objects: dict[str, bytes]

    @property
    def retained_bytes(self) -> int:
        return len(self.manifest_bytes) + sum(map(len, self.objects.values()))

    @property
    def manifest_key(self) -> str:
        return f"{PACK_MANIFEST_PREFIX}/{self.manifest_sha256}.json"


def _validate_counts(counts: Mapping[str, Any]) -> None:
    if set(counts) != {"logical_executions", "observations", "physical_attempts"}:
        raise _fail("pack counts differ")
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in counts.values()):
        raise _fail("pack counts must be positive integers")
    if counts["observations"] != counts["logical_executions"]:
        raise _fail("every credited logical execution must retain one observation fact")
    if counts["physical_attempts"] < counts["logical_executions"]:
        raise _fail("physical attempt count cannot be below logical executions")


def build_evidence_pack(
    blocks: Iterable[RetainedBlock],
    *,
    campaign_manifest_sha256: str,
    counts: Mapping[str, int],
    canonical_input_derivation: str,
) -> EvidencePackV3:
    if not _HEX64.fullmatch(campaign_manifest_sha256):
        raise _fail("campaign manifest identity differs")
    _validate_counts(counts)
    ordered = sorted(
        blocks,
        key=lambda item: (item.evidence_class, item.role, item.lookup_group),
    )
    if not ordered:
        raise _fail("pack contains no retained evidence blocks")
    coordinates = [(item.evidence_class, item.role, item.lookup_group) for item in ordered]
    if len(coordinates) != len(set(coordinates)):
        raise _fail("pack block coordinate is duplicated")
    objects: dict[str, bytes] = {}
    descriptors: list[dict[str, Any]] = []
    for ordinal, block in enumerate(ordered):
        raw = encode_value(block.value)
        stored = _xz(raw)
        digest = _sha256(stored)
        previous = objects.setdefault(digest, stored)
        if previous != stored:
            raise _fail("content-addressed block collision")
        descriptors.append(
            {
                "evidence_class": block.evidence_class,
                "key": f"{PACK_OBJECT_PREFIX}/{digest}.xz",
                "lookup_group": block.lookup_group,
                "ordinal": ordinal,
                "raw_sha256": _sha256(raw),
                "raw_size_bytes": len(raw),
                "role": block.role,
                "stored_sha256": digest,
                "stored_size_bytes": len(stored),
            }
        )
    body = {
        "authority": {
            "analytics_authoritative": False,
            "independent_observations_preserved": True,
            "independent_physical_attempts_preserved": True,
            "raw_empirical_evidence": True,
            "retained_fact_contract": "semantic-diagnostic-performance-provenance-complete.v1",
        },
        "blocks": descriptors,
        "counts": dict(counts),
        "derivations": {
            "canonical_logical_inputs": canonical_input_derivation,
            "observation_identity": "sha256(campaign-manifest,partition,shard,logical-index)",
            "physical_attempt_identity": "sha256(campaign-manifest,partition,shard,logical-index,attempt-number)",
        },
        "format": {
            "compression": "xz-sha256-preset9",
            "content_addressed_objects": True,
            "deterministic": True,
            "maximum_object_reads_per_lookup": 3,
            "normal_list_requests": 0,
            "token_tables": "typed-token-table-v3",
            "version": 3,
        },
        "omitted_information": list(AUTHORIZED_OMISSIONS),
        "schema_version": PACK_SCHEMA,
        "source_binding": {"campaign_manifest_sha256": campaign_manifest_sha256},
    }
    body["pack_digest_sha256"] = _sha256(canonical_bytes(body))
    manifest_bytes = canonical_bytes(body) + b"\n"
    return EvidencePackV3(
        manifest=body,
        manifest_bytes=manifest_bytes,
        manifest_sha256=_sha256(manifest_bytes),
        objects=objects,
    )


def transcode_v2_staging(
    repository_root: Path,
    staging_root: Path,
    *,
    campaign_manifest_sha256: str,
    partitions_per_lookup_group: int = 4,
) -> tuple[EvidencePackV3, dict[str, Any]]:
    """Read-only migration of completed v2 partitions into the v3 contract."""

    if partitions_per_lookup_group < 1:
        raise _fail("partitions per lookup group must be positive")
    from .evidence_pack_v2 import _decode_pack
    from .million_compiler import compile_million_scale_plan

    compiled = compile_million_scale_plan(repository_root)
    compiled_logical_by_path = {
        "logical/" + reference["relative_path"]: json.loads(encoded)
        for reference, encoded in compiled.artifacts
    }

    manifests = sorted((staging_root / "manifests" / "sha256").glob("*.json"))
    if not manifests:
        raise _fail("v2 staging contains no manifests")
    decoded_packs: list[tuple[dict[str, Any], dict[str, Any], Any]] = []
    cas_pool: dict[tuple[str, str, bytes], Any] = {}
    source_bytes = sum(path.stat().st_size for path in manifests)
    unique_stored: set[str] = set()
    for manifest_path in manifests:
        manifest = json.loads(manifest_path.read_bytes())
        descriptors = {item["stored_sha256"]: item for item in manifest["objects"]}
        object_map: dict[str, bytes] = {}
        for digest in descriptors:
            path = staging_root / "objects" / "sha256" / f"{digest}.xz"
            stored = path.read_bytes()
            if _sha256(stored) != digest:
                raise _fail("v2 source object identity differs")
            object_map[digest] = stored
            if digest not in unique_stored:
                unique_stored.add(digest)
                source_bytes += len(stored)
        decoded = _decode_pack(manifest, object_map)
        for digest, value in decoded.cas_values.items():
            metadata = descriptors[digest]
            key = (
                metadata["evidence_class"],
                metadata["role"],
                canonical_bytes(value),
            )
            cas_pool.setdefault(key, deepcopy(value))
        decoded_packs.append((manifest, descriptors, decoded))

    ordered_cas = sorted(cas_pool, key=lambda item: (item[0], item[1], item[2]))
    global_cas = [
        {
            "evidence_class": key[0],
            "role": key[1],
            "value": cas_pool[key],
        }
        for key in ordered_cas
    ]
    cas_index = {key: index for index, key in enumerate(ordered_cas)}
    partitions: list[dict[str, Any]] = []
    removed: Counter[str] = Counter()
    retained_fact_counts: Counter[str] = Counter()
    logical_count = physical_count = observation_count = 0
    verified_logical_segments = 0
    for ordinal, (manifest, descriptors, decoded) in enumerate(decoded_packs):
        local_cas_indexes: dict[str, int] = {}
        for digest, value in decoded.cas_values.items():
            metadata = descriptors[digest]
            key = (
                metadata["evidence_class"],
                metadata["role"],
                canonical_bytes(value),
            )
            local_cas_indexes[digest] = cas_index[key]
        roles: dict[str, list[Any]] = defaultdict(list)
        for metadata, values in decoded.fact_objects:
            role = metadata["role"]
            if role == "legacy-manifest-fact":
                removed["legacy_v2_manifest_facts"] += 1
                continue
            transformed = _strip_assigned_identities(
                values, removed, local_cas_indexes
            )
            rows = transformed if isinstance(transformed, list) else [transformed]
            if role == "logical-facts":
                template_keys = (
                    "base_logical_execution_id",
                    "profile_id",
                    "request_template_sha256",
                    "selection_key",
                    "target_release_id",
                    "vector_revision_id",
                )
                logical_templates = decoded.descriptor["legacy_global_model"][
                    "logical_templates"
                ]
                template_indexes = {
                    canonical_bytes(value): index
                    for index, value in enumerate(logical_templates)
                }
                if len(metadata["member_paths"]) != len(values):
                    raise _fail("logical fact member binding count differs")
                for member_path, fact in zip(
                    metadata["member_paths"], values, strict=True
                ):
                    try:
                        payload = compiled_logical_by_path[member_path]
                    except KeyError as error:
                        raise _fail("logical fact has no compiled source segment") from error
                    expected_fact = {
                        "planned_repetitions": [
                            record["planned_repetition"]
                            for record in payload["logical_executions"]
                        ],
                        "schema_version": payload["schema_version"],
                        "selection_key": payload["selection_key"],
                        "shard_id": payload["shard_id"],
                        "template_indexes": [
                            template_indexes[
                                canonical_bytes(
                                    {key: record[key] for key in template_keys}
                                )
                            ]
                            for record in payload["logical_executions"]
                        ],
                    }
                    if fact != expected_fact:
                        raise _fail("compiled canonical logical fact differs")
                    verified_logical_segments += 1
                logical_count += sum(len(row["template_indexes"]) for row in rows)
                removed["physically_stored_logical_fact_segments"] += len(rows)
                continue
            roles[role].extend(rows)
            retained_fact_counts[role] += len(rows)
        for fact in roles["physical-attempt-facts"]:
            physical_count += len(fact["attempt_columns"]["logical_indexes"])
        for fact in roles["observation-facts"]:
            observation_count += len(fact["observation_columns"]["logical_indexes"])
        partitions.append(
            {
                "descriptor": _compact_partition_descriptor(
                    decoded.descriptor, local_cas_indexes, removed
                ),
                "ordinal": ordinal,
                "roles": dict(sorted(roles.items())),
            }
        )

    blocks: list[RetainedBlock] = [
        RetainedBlock(
            "canonical_inputs",
            "derivation-contract",
            0,
            {
                "identity_derivation": {
                    "observation": "sha256(campaign-manifest,partition,shard,logical-index)",
                    "physical_attempt": "sha256(campaign-manifest,partition,shard,logical-index,attempt-number)",
                },
                "logical_input_derivation": {
                    "method": "content-bound-campaign-definition-and-versioned-compiler-v1",
                    "reconstruction_count": logical_count,
                },
                "schema_version": "evidence-pack-v3-global-model.v1",
            },
        )
    ]
    cas_by_class: dict[str, list[Any]] = defaultdict(list)
    for item in global_cas:
        cas_by_class[item["evidence_class"]].append(item)
    for evidence_class, values in sorted(cas_by_class.items()):
        blocks.append(
            RetainedBlock(
                evidence_class,
                f"global-cas-{evidence_class.replace('_', '-')}",
                0,
                values,
            )
        )
    class_for_role = {
        "diagnostic-facts": "diagnostics",
        "observation-facts": "semantic_results",
        "performance-resource-facts": "performance_resource_samples",
        "physical-attempt-facts": "physical_attempt_facts",
    }
    for offset in range(0, len(partitions), partitions_per_lookup_group):
        group_number = offset // partitions_per_lookup_group
        group = partitions[offset : offset + partitions_per_lookup_group]
        blocks.append(
            RetainedBlock(
                "profile_environment_release_provenance",
                "partition-descriptors",
                group_number,
                [
                    {"descriptor": item["descriptor"], "ordinal": item["ordinal"]}
                    for item in group
                ],
            )
        )
        for role, evidence_class in class_for_role.items():
            blocks.append(
                RetainedBlock(
                    evidence_class,
                    role,
                    group_number,
                    [
                        {
                            "facts": item["roles"].get(role, []),
                            "ordinal": item["ordinal"],
                        }
                        for item in group
                    ],
                )
            )
    counts = {
        "logical_executions": logical_count,
        "observations": observation_count,
        "physical_attempts": physical_count,
    }
    pack = build_evidence_pack(
        blocks,
        campaign_manifest_sha256=campaign_manifest_sha256,
        counts=counts,
        canonical_input_derivation="content-bound-campaign-definition-and-versioned-compiler-v1",
    )
    repeated = build_evidence_pack(
        blocks,
        campaign_manifest_sha256=campaign_manifest_sha256,
        counts=counts,
        canonical_input_derivation="content-bound-campaign-definition-and-versioned-compiler-v1",
    )
    if repeated.manifest_bytes != pack.manifest_bytes or repeated.objects != pack.objects:
        raise _fail("v3 staging migration is not deterministic")
    reconstructed = decode_evidence_pack(pack.manifest, pack.objects)
    if reconstructed != sorted(
        blocks, key=lambda item: (item.evidence_class, item.role, item.lookup_group)
    ):
        raise _fail("v3 retained-fact reconstruction differs")
    damaged = dict(pack.objects)
    target_digest = sorted(damaged)[len(damaged) // 2]
    target = bytearray(damaged[target_digest])
    target[len(target) // 2] ^= 1
    damaged[target_digest] = bytes(target)
    corruption_detected = False
    try:
        decode_evidence_pack(pack.manifest, damaged)
    except EvidencePackV3Error:
        corruption_detected = True
    if not corruption_detected:
        raise _fail("v3 corruption injection was not detected")
    bytes_by_class: Counter[str] = Counter()
    for item in pack.manifest["blocks"]:
        bytes_by_class[item["evidence_class"]] += item["stored_size_bytes"]
    bytes_by_class["manifests_integrity"] += len(pack.manifest_bytes)
    measurement = {
        "bytes_by_evidence_class": {
            name: bytes_by_class[name] for name in EVIDENCE_CLASSES
        },
        "corruption_detected": True,
        "deterministic_second_encoding_identical": True,
        "logical_executions": logical_count,
        "manifest_sha256": pack.manifest_sha256,
        "maximum_compressed_block_bytes": max(map(len, pack.objects.values())),
        "maximum_object_reads_per_lookup": 3,
        "object_count_including_manifest": len(pack.objects) + 1,
        "observations": observation_count,
        "pack_digest_sha256": pack.manifest["pack_digest_sha256"],
        "physical_attempts": physical_count,
        "removed_legacy_information": dict(sorted(removed.items())),
        "retained_bytes": pack.retained_bytes,
        "retained_fact_counts": dict(sorted(retained_fact_counts.items())),
        "source_v2_bytes": source_bytes,
        "verified_canonical_logical_segments": verified_logical_segments,
    }
    return pack, measurement


def decode_evidence_pack(
    manifest: Mapping[str, Any], object_bytes: Mapping[str, bytes]
) -> list[RetainedBlock]:
    body = deepcopy(dict(manifest))
    claimed_digest = body.pop("pack_digest_sha256", None)
    if claimed_digest != _sha256(canonical_bytes(body)):
        raise _fail("pack digest differs")
    if body.get("schema_version") != PACK_SCHEMA:
        raise _fail("pack schema version differs")
    if tuple(body.get("omitted_information", ())) != AUTHORIZED_OMISSIONS:
        raise _fail("pack omission contract differs")
    _validate_counts(body.get("counts", {}))
    descriptors = body.get("blocks")
    if not isinstance(descriptors, list) or not descriptors:
        raise _fail("pack block descriptors differ")
    required = {item["stored_sha256"] for item in descriptors}
    if set(object_bytes) != required:
        raise _fail("pack object set differs")
    result: list[RetainedBlock] = []
    for ordinal, item in enumerate(descriptors):
        if item.get("ordinal") != ordinal:
            raise _fail("pack block ordinal differs")
        stored = object_bytes[item["stored_sha256"]]
        if len(stored) != item["stored_size_bytes"] or _sha256(stored) != item["stored_sha256"]:
            raise _fail("stored block identity differs")
        raw = _unxz(stored)
        if len(raw) != item["raw_size_bytes"] or _sha256(raw) != item["raw_sha256"]:
            raise _fail("raw block identity differs")
        result.append(
            RetainedBlock(
                evidence_class=item["evidence_class"],
                role=item["role"],
                lookup_group=item["lookup_group"],
                value=decode_value(raw),
            )
        )
    return result


def lookup_block(
    manifest: Mapping[str, Any],
    object_bytes: Mapping[str, bytes],
    *,
    role: str,
    lookup_group: int,
) -> tuple[Any, int]:
    matches = [
        item
        for item in manifest.get("blocks", [])
        if item.get("role") == role and item.get("lookup_group") == lookup_group
    ]
    if len(matches) != 1:
        raise _fail("lookup coordinate does not identify exactly one block")
    item = matches[0]
    stored = object_bytes.get(item["stored_sha256"])
    if stored is None or _sha256(stored) != item["stored_sha256"]:
        raise _fail("lookup block identity differs")
    raw = _unxz(stored)
    if _sha256(raw) != item["raw_sha256"]:
        raise _fail("lookup raw identity differs")
    return decode_value(raw), 2


def _scaled_classes(
    measurement: Mapping[str, int],
    *,
    logical_executions: int,
    physical_attempts: int,
    measured_logical_executions: int,
    measured_physical_attempts: int,
) -> dict[str, int]:
    return {
        name: _ceil(
            Decimal(value)
            * Decimal(
                physical_attempts if name in ATTEMPT_SCALED_CLASSES else logical_executions
            )
            / Decimal(
                measured_physical_attempts
                if name in ATTEMPT_SCALED_CLASSES
                else measured_logical_executions
            )
        )
        for name, value in measurement.items()
    }


def build_capacity_forecast(
    measured_bytes_by_class: Mapping[str, int],
    cases: Mapping[str, Mapping[str, int]],
    *,
    measured_logical_executions: int,
    measured_physical_attempts: int,
    qualification_corpus_bytes: int,
) -> dict[str, Any]:
    if set(measured_bytes_by_class) != set(EVIDENCE_CLASSES):
        raise _fail("measured evidence classes differ")
    result: dict[str, Any] = {}
    for name in ("lower", "expected", "conservative"):
        case = cases[name]
        classes = _scaled_classes(
            measured_bytes_by_class,
            logical_executions=case["logical_executions"],
            physical_attempts=case["physical_attempts"],
            measured_logical_executions=measured_logical_executions,
            measured_physical_attempts=measured_physical_attempts,
        )
        base = sum(classes.values())
        diagnostic_rate = Decimal({"lower": "0", "expected": "0.04", "conservative": "0.10"}[name])
        performance_rate = Decimal({"lower": "0", "expected": "0.01", "conservative": "0.05"}[name])
        diagnostic_allowance = _ceil(Decimal(base) * diagnostic_rate)
        performance_allowance = _ceil(Decimal(base) * performance_rate)
        fixed_reserve = 1_000_000_000 if name == "conservative" else 0
        total = base + diagnostic_allowance + performance_allowance + fixed_reserve + qualification_corpus_bytes
        object_count = case.get(
            "object_count", math.ceil(case["logical_executions"] / 11_620)
        )
        result[name] = {
            "bytes_by_evidence_class": classes,
            "bytes_before_growth_allowances": base,
            "class_a_requests": object_count,
            "class_b_requests": object_count,
            "diagnostic_growth_allowance_bytes": diagnostic_allowance,
            "fixed_targeted_and_general_reserve_bytes": fixed_reserve,
            "hard_cap_delta_bytes": HARD_LIMIT_BYTES - total,
            "logical_executions": case["logical_executions"],
            "normal_list_requests": 0,
            "object_count": object_count,
            "performance_growth_allowance_bytes": performance_allowance,
            "physical_attempts": case["physical_attempts"],
            "qualification_corpus_bytes": qualification_corpus_bytes,
            "soft_stop_delta_bytes": SOFT_LIMIT_BYTES - total,
            "total_retained_bytes": total,
        }
    return result


def verify_capacity_forecast(
    measured_bytes_by_class: Mapping[str, int],
    cases: Mapping[str, Mapping[str, int]],
    forecast: Mapping[str, Any],
    *,
    measured_logical_executions: int,
    measured_physical_attempts: int,
    qualification_corpus_bytes: int,
) -> None:
    expected = build_capacity_forecast(
        measured_bytes_by_class,
        cases,
        measured_logical_executions=measured_logical_executions,
        measured_physical_attempts=measured_physical_attempts,
        qualification_corpus_bytes=qualification_corpus_bytes,
    )
    if dict(forecast) != expected:
        raise _fail("capacity forecast does not recompute from measured evidence")
    if expected["conservative"]["total_retained_bytes"] > SOFT_LIMIT_BYTES:
        raise _fail("conservative retained program exceeds the operational soft stop")
    if expected["conservative"]["total_retained_bytes"] > HARD_LIMIT_BYTES:
        raise _fail("conservative retained program exceeds the absolute hard cap")


def report_digest(report: Mapping[str, Any]) -> str:
    value = deepcopy(dict(report))
    value.pop("report_digest_sha256", None)
    return _sha256(rfc8785.dumps(value))


def verify_certification_report(report: Mapping[str, Any]) -> None:
    if report.get("schema_version") != REPORT_SCHEMA:
        raise _fail("certification report schema differs")
    if report.get("report_digest_sha256") != report_digest(report):
        raise _fail("certification report digest differs")
    measurement = report["future_contract_measurement"]
    if sum(measurement["bytes_by_evidence_class"].values()) != measurement["retained_bytes"]:
        raise _fail("future-contract byte attribution does not close")
    cases = report["declared_cutoff_denominators"]
    verify_capacity_forecast(
        measurement["bytes_by_evidence_class"],
        cases,
        report["final_forecast"]["cases"],
        measured_logical_executions=measurement["logical_executions"],
        measured_physical_attempts=measurement["physical_attempts"],
        qualification_corpus_bytes=report["final_forecast"]["qualification_corpus_bytes"],
    )
    accounting = report["three_stage_accounting"]
    if accounting["starting_combined_conservative_bytes"] - accounting["lossless_redesigned_conservative_bytes"] != accounting["lossless_structural_savings_bytes"]:
        raise _fail("lossless savings accounting differs")
    if accounting["lossless_redesigned_conservative_bytes"] - accounting["final_conservative_bytes"] != accounting["deliberate_information_removal_savings_bytes"]:
        raise _fail("retention-change savings accounting differs")
    if accounting["starting_combined_conservative_bytes"] - accounting["final_conservative_bytes"] != accounting["total_savings_bytes"]:
        raise _fail("total savings accounting differs")
    if tuple(report["retention_contract_change"]["no_longer_retained"]) != AUTHORIZED_OMISSIONS:
        raise _fail("certification omission list differs")
