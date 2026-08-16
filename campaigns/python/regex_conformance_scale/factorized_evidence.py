"""Deterministic, lossless factorization of immutable scale evidence.

The archive is an experimental P20-T01B measurement format.  It never changes
the authority of the canonical JSON members: decoding reconstructs those exact
bytes, including their content-addressed paths.
"""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_CEILING
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path
import re
import stat
import tarfile
from typing import Any, Iterable, Iterator, Sequence

import rfc8785

from regex_conformance_campaign.compiler import SCHEMA_FAMILY_ID
from regex_conformance_schema.identity import NamespaceRegistry, build_content_identity
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.profile import IdentityProfile


class FactorizedEvidenceError(ValueError):
    """The source corpus or factorized archive violates its lossless contract."""


ARCHIVE_MAGIC = b"RCFREP1\n"
ARCHIVE_SCHEMA = "factorized-raw-evidence-archive.v1"
MODEL_SCHEMA = "factorized-raw-evidence-model.v1"
REPORT_SCHEMA = "factorized-evidence-forecast.v1"
P19_LOGICAL_EXECUTIONS = 100_000
P19_PHYSICAL_ATTEMPTS = 100_500
P19_LOGICAL_MEMBERS = 402
P19_RESULT_MEMBERS = 404
P19_MANIFEST_MEMBERS = 1
P19_AUTHORITATIVE_MEMBERS = 807
P19_MANIFEST_SHA256 = "a2d8d1c460d7822bc2212df41d41842e02202961caad7bc17ca1b68204ae07fa"
EXPECTED_SOURCE_BYTES = {
    "canonical_logical_input": 69_698_118,
    "raw_result_and_attempt": 316_912_761,
    "minimal_manifest_integrity": 244_518,
}
EXPECTED_INDEPENDENT_GZIP9_BYTES = {
    "canonical_logical_input": 5_588_247,
    "raw_result_and_attempt": 26_282_967,
    "minimal_manifest_integrity": 54_787,
}
EXPECTED_TAR_GZIP9_BYTES = 31_742_126
DENOMINATORS = {
    "lower": {"logical_executions": 34_399_590, "physical_attempts": 34_399_590},
    "expected": {"logical_executions": 129_715_224, "physical_attempts": 130_363_801},
    "conservative": {"logical_executions": 360_702_963, "physical_attempts": 378_738_112},
}
SOFT_LIMIT_BYTES = 8_000_000_000
HARD_LIMIT_BYTES = 10_000_000_000
EXPECTED_DIAGNOSTICS_RESERVE = Decimal("0.05")
CONSERVATIVE_DIAGNOSTICS_RESERVE = Decimal("0.15")
CONSERVATIVE_FIXED_RESERVE_BYTES = 1_000_000_000

_RCID_HASH = re.compile(r"^(rcid:v1:[a-z0-9]+(?:-[a-z0-9]+)*:h:jcs-sha256-v1:)([0-9a-f]{64})$")
_RCID_UUID = re.compile(r"^(rcid:v1:[a-z0-9]+(?:-[a-z0-9]+)*:u7:)([0-9a-f-]{36})$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_MILLISECOND_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def _fail(message: str) -> FactorizedEvidenceError:
    return FactorizedEvidenceError(message)


def _ceil(value: Decimal) -> int:
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_object(path: Path) -> dict[str, Any]:
    value = load_strict(path)
    if not isinstance(value, dict):
        raise _fail(f"evidence member is not an object: {path}")
    encoded = canonical_bytes(value) + b"\n"
    if encoded != path.read_bytes():
        raise _fail(f"evidence member is not exact canonical JSON: {path}")
    return value


def _direct_file(path: Path, root: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise _fail(f"evidence path is absent or escapes its root: {path}") from error
    metadata = resolved.stat()
    if resolved != path.absolute() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise _fail(f"evidence path is not a direct regular file: {path}")
    return resolved


def _content_path_digest(path: Path) -> str:
    claimed = path.stem
    actual = _sha256(path.read_bytes())
    if claimed != actual:
        raise _fail(f"content-addressed member digest differs: {path}")
    return actual


@dataclass(frozen=True)
class SourceMember:
    path: Path
    relative_path: str
    evidence_class: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class SourceCorpus:
    root: Path
    logical: tuple[SourceMember, ...]
    results: tuple[SourceMember, ...]
    manifest: SourceMember

    @property
    def members(self) -> tuple[SourceMember, ...]:
        return self.logical + self.results + (self.manifest,)


def discover_scale_corpus(
    campaign_root: Path, *, enforce_certified_p19: bool = False
) -> SourceCorpus:
    root = campaign_root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise _fail("P19 corpus root is not a directory")
    logical_dir = root / "logical" / "logical-execution-segments" / "sha256"
    result_dir = root / "evidence" / "scale-result-segments" / "sha256"
    manifest_dir = root / "evidence" / "scale-manifests" / "sha256"
    logical_paths = sorted(logical_dir.glob("*.json"))
    result_paths = sorted(result_dir.glob("*.json"))
    manifest_paths = sorted(manifest_dir.glob("*.json"))
    if not logical_paths or not result_paths or len(manifest_paths) != 1:
        raise _fail("P19 corpus does not contain one closed logical/result/manifest set")

    def member(path: Path, evidence_class: str) -> SourceMember:
        direct = _direct_file(path, root)
        digest = _content_path_digest(direct)
        return SourceMember(
            path=direct,
            relative_path=direct.relative_to(root).as_posix(),
            evidence_class=evidence_class,
            sha256=digest,
            size_bytes=direct.stat().st_size,
        )

    corpus = SourceCorpus(
        root=root,
        logical=tuple(member(path, "canonical_logical_input") for path in logical_paths),
        results=tuple(member(path, "raw_result_and_attempt") for path in result_paths),
        manifest=member(manifest_paths[0], "minimal_manifest_integrity"),
    )
    if enforce_certified_p19:
        if (
            len(corpus.logical) != P19_LOGICAL_MEMBERS
            or len(corpus.results) != P19_RESULT_MEMBERS
            or len(corpus.members) != P19_AUTHORITATIVE_MEMBERS
            or corpus.manifest.sha256 != P19_MANIFEST_SHA256
        ):
            raise _fail("source corpus is not the certified P19 Session 05 member set")
        totals: dict[str, int] = defaultdict(int)
        for item in corpus.members:
            totals[item.evidence_class] += item.size_bytes
        if dict(totals) != EXPECTED_SOURCE_BYTES:
            raise _fail("certified P19 source byte totals differ")
    return corpus


def discover_p19_corpus(
    campaign_root: Path, *, enforce_certified_p19: bool = True
) -> SourceCorpus:
    """Compatibility entrypoint for the frozen P19 certification corpus."""

    return discover_scale_corpus(
        campaign_root, enforce_certified_p19=enforce_certified_p19
    )


def _uvarint(value: int) -> bytes:
    if value < 0:
        raise _fail("unsigned varint cannot encode a negative value")
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _read_uvarint(data: memoryview, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if offset >= len(data) or shift > 63:
            raise _fail("invalid or truncated varint")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, offset
        shift += 7


def _svarint(value: int) -> bytes:
    return _uvarint(value * 2 if value >= 0 else (-value * 2) - 1)


def _read_svarint(data: memoryview, offset: int) -> tuple[int, int]:
    raw, offset = _read_uvarint(data, offset)
    return (raw // 2 if raw % 2 == 0 else -(raw // 2) - 1), offset


def _pack_bytes(value: bytes) -> bytes:
    return _uvarint(len(value)) + value


def _read_bytes(data: memoryview, offset: int) -> tuple[bytes, int]:
    length, offset = _read_uvarint(data, offset)
    end = offset + length
    if end > len(data):
        raise _fail("truncated length-delimited value")
    return bytes(data[offset:end]), end


def _walk(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, dict):
        for key in sorted(value, key=lambda item: item.encode("utf-8")):
            yield from _walk(key)
            yield from _walk(value[key])
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


@dataclass(frozen=True)
class TokenTables:
    strings: tuple[str, ...]
    string_indexes: dict[str, int]
    prefixes: tuple[str, ...]
    prefix_indexes: dict[str, int]
    shapes: tuple[tuple[str, ...], ...]
    shape_indexes: dict[tuple[str, ...], int]

    @classmethod
    def build(cls, values: Iterable[Any], *, extra_strings: Iterable[str] = ()) -> "TokenTables":
        strings = set(extra_strings)
        shapes: set[tuple[str, ...]] = set()
        for value in values:
            for item in _walk(value):
                if isinstance(item, str):
                    strings.add(item)
                elif isinstance(item, dict):
                    shapes.add(tuple(sorted(item, key=lambda key: key.encode("utf-8"))))
        ordered_strings = tuple(sorted(strings, key=lambda item: item.encode("utf-8")))
        indexes = {value: index for index, value in enumerate(ordered_strings)}
        prefixes = set()
        for value in ordered_strings:
            match = _RCID_HASH.fullmatch(value) or _RCID_UUID.fullmatch(value)
            if match:
                prefixes.add(match.group(1))
        ordered_prefixes = tuple(sorted(prefixes, key=lambda item: item.encode("utf-8")))
        prefix_indexes = {value: index for index, value in enumerate(ordered_prefixes)}
        ordered_shapes = tuple(sorted(shapes, key=lambda shape: tuple(indexes[key] for key in shape)))
        return cls(
            strings=ordered_strings,
            string_indexes=indexes,
            prefixes=ordered_prefixes,
            prefix_indexes=prefix_indexes,
            shapes=ordered_shapes,
            shape_indexes={value: index for index, value in enumerate(ordered_shapes)},
        )

    def encode_tables(self) -> bytes:
        output = bytearray(b"TBL1")
        output += _uvarint(len(self.prefixes))
        for value in self.prefixes:
            output += _pack_bytes(value.encode("utf-8"))
        output += _uvarint(len(self.strings))
        for value in self.strings:
            hash_match = _RCID_HASH.fullmatch(value)
            uuid_match = _RCID_UUID.fullmatch(value)
            if hash_match:
                output.append(1)
                output += _uvarint(self.prefix_indexes[hash_match.group(1)])
                output += bytes.fromhex(hash_match.group(2))
            elif uuid_match:
                output.append(2)
                output += _uvarint(self.prefix_indexes[uuid_match.group(1)])
                output += bytes.fromhex(uuid_match.group(2).replace("-", ""))
            elif _HEX64.fullmatch(value):
                output.append(3)
                output += bytes.fromhex(value)
            elif _UUID.fullmatch(value):
                output.append(4)
                output += bytes.fromhex(value.replace("-", ""))
            elif _MILLISECOND_UTC.fullmatch(value):
                output.append(5)
                instant = datetime.fromisoformat(value[:-1] + "+00:00")
                milliseconds = int(instant.timestamp() * 1000)
                output += _svarint(milliseconds)
            else:
                output.append(0)
                output += _pack_bytes(value.encode("utf-8"))
        output += _uvarint(len(self.shapes))
        for shape in self.shapes:
            output += _uvarint(len(shape))
            for key in shape:
                output += _uvarint(self.string_indexes[key])
        return bytes(output)

    @classmethod
    def decode_tables(cls, encoded: bytes) -> tuple["TokenTables", int]:
        data = memoryview(encoded)
        if bytes(data[:4]) != b"TBL1":
            raise _fail("token table magic differs")
        offset = 4
        prefix_count, offset = _read_uvarint(data, offset)
        prefixes: list[str] = []
        for _ in range(prefix_count):
            raw, offset = _read_bytes(data, offset)
            prefixes.append(raw.decode("utf-8"))
        string_count, offset = _read_uvarint(data, offset)
        strings: list[str] = []
        for _ in range(string_count):
            if offset >= len(data):
                raise _fail("truncated token table")
            kind = data[offset]
            offset += 1
            if kind == 0:
                raw, offset = _read_bytes(data, offset)
                value = raw.decode("utf-8")
            elif kind in (1, 2):
                prefix_index, offset = _read_uvarint(data, offset)
                if prefix_index >= len(prefixes):
                    raise _fail("token prefix index is out of range")
                length = 32 if kind == 1 else 16
                end = offset + length
                if end > len(data):
                    raise _fail("truncated typed identity")
                raw = bytes(data[offset:end])
                offset = end
                suffix = raw.hex()
                if kind == 2:
                    suffix = f"{suffix[:8]}-{suffix[8:12]}-{suffix[12:16]}-{suffix[16:20]}-{suffix[20:]}"
                value = prefixes[prefix_index] + suffix
            elif kind == 3:
                end = offset + 32
                if end > len(data):
                    raise _fail("truncated digest")
                value = bytes(data[offset:end]).hex()
                offset = end
            elif kind == 4:
                end = offset + 16
                if end > len(data):
                    raise _fail("truncated UUID")
                raw = bytes(data[offset:end]).hex()
                offset = end
                value = f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}"
            elif kind == 5:
                milliseconds, offset = _read_svarint(data, offset)
                seconds, remainder = divmod(milliseconds, 1000)
                value = datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
                value += f".{remainder:03d}Z"
            else:
                raise _fail("unknown typed string kind")
            strings.append(value)
        shape_count, offset = _read_uvarint(data, offset)
        shapes: list[tuple[str, ...]] = []
        for _ in range(shape_count):
            length, offset = _read_uvarint(data, offset)
            shape: list[str] = []
            for _ in range(length):
                index, offset = _read_uvarint(data, offset)
                if index >= len(strings):
                    raise _fail("shape key index is out of range")
                shape.append(strings[index])
            shapes.append(tuple(shape))
        ordered_strings = tuple(strings)
        ordered_prefixes = tuple(prefixes)
        ordered_shapes = tuple(shapes)
        return (
            cls(
                strings=ordered_strings,
                string_indexes={value: index for index, value in enumerate(ordered_strings)},
                prefixes=ordered_prefixes,
                prefix_indexes={value: index for index, value in enumerate(ordered_prefixes)},
                shapes=ordered_shapes,
                shape_indexes={value: index for index, value in enumerate(ordered_shapes)},
            ),
            offset,
        )

    def encode_value(self, value: Any) -> bytes:
        output = bytearray()

        def visit(item: Any) -> None:
            if item is None:
                output.append(0)
            elif item is False:
                output.append(1)
            elif item is True:
                output.append(2)
            elif isinstance(item, int) and not isinstance(item, bool):
                output.append(3)
                output.extend(_svarint(item))
            elif isinstance(item, float):
                raise _fail("floating-point values are not permitted in the factorized model")
            elif isinstance(item, str):
                output.append(4)
                try:
                    output.extend(_uvarint(self.string_indexes[item]))
                except KeyError as error:
                    raise _fail("value references an absent token") from error
            elif isinstance(item, bytes):
                output.append(7)
                output.extend(_pack_bytes(item))
            elif isinstance(item, list):
                output.append(5)
                output.extend(_uvarint(len(item)))
                for child in item:
                    visit(child)
            elif isinstance(item, dict):
                output.append(6)
                shape = tuple(sorted(item, key=lambda key: key.encode("utf-8")))
                try:
                    output.extend(_uvarint(self.shape_indexes[shape]))
                except KeyError as error:
                    raise _fail("object references an absent shape") from error
                for key in shape:
                    visit(item[key])
            else:
                raise _fail(f"unsupported factorized value type: {type(item).__name__}")

        visit(value)
        return bytes(output)

    def decode_value(self, encoded: bytes, offset: int = 0) -> tuple[Any, int]:
        data = memoryview(encoded)

        def visit(position: int) -> tuple[Any, int]:
            if position >= len(data):
                raise _fail("truncated factorized value")
            tag = data[position]
            position += 1
            if tag == 0:
                return None, position
            if tag == 1:
                return False, position
            if tag == 2:
                return True, position
            if tag == 3:
                return _read_svarint(data, position)
            if tag == 4:
                index, position = _read_uvarint(data, position)
                if index >= len(self.strings):
                    raise _fail("string index is out of range")
                return self.strings[index], position
            if tag == 5:
                length, position = _read_uvarint(data, position)
                result = []
                for _ in range(length):
                    value, position = visit(position)
                    result.append(value)
                return result, position
            if tag == 6:
                index, position = _read_uvarint(data, position)
                if index >= len(self.shapes):
                    raise _fail("shape index is out of range")
                result = {}
                for key in self.shapes[index]:
                    value, position = visit(position)
                    result[key] = value
                return result, position
            if tag == 7:
                return _read_bytes(data, position)
            raise _fail("unknown factorized value tag")

        return visit(offset)


class _ContentIds:
    def __init__(self, repository_root: Path) -> None:
        self.registry = NamespaceRegistry.load(repository_root / "registries/identity/namespaces.v1.json")
        self.profile = IdentityProfile.from_record(
            load_strict(repository_root / "schemas/identity-profiles/campaign-content.v1.json")
        )

    def build(self, namespace: str, kind: str, identity: Any) -> str:
        inner = {
            "artifact_kind": kind,
            "content_sha256": _sha256(canonical_bytes(identity)),
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


class _Interner:
    def __init__(self) -> None:
        self._values: dict[str, tuple[bytes, Any]] = {}

    def add(self, value: Any) -> str:
        encoded = canonical_bytes(value)
        key = _sha256(encoded)
        previous = self._values.get(key)
        if previous is not None and previous[0] != encoded:
            raise _fail("template digest collision")
        self._values[key] = (encoded, deepcopy(value))
        return key

    def finalize(self) -> tuple[list[Any], dict[str, int]]:
        keys = sorted(self._values)
        return [self._values[key][1] for key in keys], {key: index for index, key in enumerate(keys)}

    def __len__(self) -> int:
        return len(self._values)


def _logical_identity_context(
    repository_root: Path, plan: dict[str, Any] | None = None
) -> dict[str, str]:
    compiled = (
        load_strict(
            repository_root / "campaigns/compiled/100k-qualification.v1.json"
        )
        if plan is None
        else plan
    )
    purpose = (
        "operational-million-qualification-v1"
        if compiled.get("schema_version") == "million-scale-partition-plan.v1"
        else "operational-scale-qualification-v1"
    )
    return {
        "base_campaign_manifest_id": compiled["base_campaign"]["campaign_manifest_id"],
        "campaign_definition_revision_id": compiled["campaign_definition_revision_id"],
        "campaign_id": compiled["campaign_id"],
        "campaign_manifest_id": compiled["campaign_manifest"]["campaign_manifest_id"],
        "purpose": purpose,
    }


def _derive_logical_id(ids: _ContentIds, context: dict[str, str], template: dict[str, Any], repetition: int) -> str:
    identity = {
        "base_campaign_manifest_id": context["base_campaign_manifest_id"],
        "base_logical_execution_id": template["base_logical_execution_id"],
        "campaign_definition_revision_id": context["campaign_definition_revision_id"],
        "campaign_id": context["campaign_id"],
        "planned_repetition": repetition,
        "purpose": context["purpose"],
        "request_template_sha256": template["request_template_sha256"],
    }
    return ids.build("logical-execution", "scale-logical-execution-v1", identity)


def _logical_template(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: record[key]
        for key in (
            "base_logical_execution_id",
            "profile_id",
            "request_template_sha256",
            "selection_key",
            "target_release_id",
            "vector_revision_id",
        )
    }


def _factor_result(
    result: dict[str, Any],
    *,
    logical: dict[str, Any],
    campaign_id: str,
    adapter_release_manifest_id: str,
    process_execution: dict[str, Any],
) -> dict[str, Any]:
    core = deepcopy(result)
    logical_id = logical["logical_execution_id"]
    candidates = {
        "logical_execution_id": logical_id,
        "correlation_id": logical_id,
        "adapter_release_manifest_id": adapter_release_manifest_id,
        "profile_id": logical["profile_id"],
        "target_release_id": logical["target_release_id"],
        "trace_reference": f"campaign:{campaign_id}:{logical_id}",
        "process_execution": process_execution,
    }
    derived_fields: list[str] = []
    for key, expected in candidates.items():
        if key in core and core[key] == expected:
            del core[key]
            derived_fields.append(key)
    if not ({"logical_execution_id", "correlation_id"} & set(derived_fields)):
        raise _fail("result logical identity cannot be derived")
    return {"core": core, "derived_fields": sorted(derived_fields)}


def _restore_result(
    template: dict[str, Any],
    *,
    logical: dict[str, Any],
    campaign_id: str,
    adapter_release_manifest_id: str,
    process_execution: dict[str, Any],
) -> dict[str, Any]:
    result = deepcopy(template["core"])
    logical_id = logical["logical_execution_id"]
    values = {
        "logical_execution_id": logical_id,
        "correlation_id": logical_id,
        "adapter_release_manifest_id": adapter_release_manifest_id,
        "profile_id": logical["profile_id"],
        "target_release_id": logical["target_release_id"],
        "trace_reference": f"campaign:{campaign_id}:{logical_id}",
        "process_execution": deepcopy(process_execution),
    }
    for key in template["derived_fields"]:
        result[key] = values[key]
    return result


@dataclass(frozen=True)
class SemanticMember:
    relative_path: str
    evidence_class: str
    model: dict[str, Any]


@dataclass(frozen=True)
class SemanticCorpus:
    global_model: dict[str, Any]
    logical_members: tuple[SemanticMember, ...]
    result_members: tuple[SemanticMember, ...]
    manifest_member: SemanticMember
    statistics: dict[str, Any]


def build_semantic_corpus(
    repository_root: Path,
    source: SourceCorpus,
    *,
    plan: dict[str, Any] | None = None,
) -> SemanticCorpus:
    root = repository_root.resolve(strict=True)
    context = _logical_identity_context(root, plan)
    ids = _ContentIds(root)
    logical_templates = _Interner()
    result_templates = _Interner()
    provenance_templates = _Interner()
    diagnostic_templates = _Interner()
    logical_members: list[SemanticMember] = []
    logical_by_shard: dict[str, list[dict[str, Any]]] = {}
    logical_member_by_shard: dict[str, str] = {}
    derived_logical_count = 0

    for member in source.logical:
        payload = _strict_object(member.path)
        if payload.get("schema_version") != "logical-execution-segment.v1":
            raise _fail("logical evidence schema version differs")
        records = payload["logical_executions"]
        template_keys: list[str] = []
        repetitions: list[int] = []
        for record in records:
            template = _logical_template(record)
            derived = _derive_logical_id(ids, context, template, record["planned_repetition"])
            if derived != record["logical_execution_id"]:
                raise _fail("logical execution identity cannot be recomputed")
            derived_logical_count += 1
            template_keys.append(logical_templates.add(template))
            repetitions.append(record["planned_repetition"])
        shard_id = payload["shard_id"]
        if shard_id in logical_by_shard:
            raise _fail("duplicate logical shard")
        logical_by_shard[shard_id] = records
        logical_member_by_shard[shard_id] = member.relative_path
        logical_members.append(
            SemanticMember(
                relative_path=member.relative_path,
                evidence_class=member.evidence_class,
                model={
                    "schema_version": payload["schema_version"],
                    "selection_key": payload["selection_key"],
                    "shard_id": shard_id,
                    "template_keys": template_keys,
                    "planned_repetitions": repetitions,
                },
            )
        )

    manifest = _strict_object(source.manifest.path)
    if manifest.get("schema_version") != "scale-evidence-manifest.v1":
        raise _fail("scale evidence manifest schema version differs")
    catalog_by_path = {
        "evidence/" + item["relative_path"]: item for item in manifest["segments"]
    }
    if set(catalog_by_path) != {member.relative_path for member in source.results}:
        raise _fail("manifest result member set differs from the immutable corpus")

    result_members: list[SemanticMember] = []
    observation_template_references = 0
    provenance_template_references = 0
    physical_attempt_count = 0
    observation_count = 0
    infrastructure_attempt_count = 0
    stdout_digests: set[str] = set()
    performance_sample_count = 0
    result_template_selection_keys: dict[str, set[str]] = defaultdict(set)
    result_template_release_ids: dict[str, set[str]] = defaultdict(set)

    for member in source.results:
        payload = _strict_object(member.path)
        if payload.get("schema_version") != "scale-result-segment.v1":
            raise _fail("result evidence schema version differs")
        reference = catalog_by_path[member.relative_path]
        if reference["sha256"] != member.sha256 or reference["size_bytes"] != member.size_bytes:
            raise _fail("manifest result member bytes differ")
        shard_id = payload["shard_id"]
        try:
            logical_records = logical_by_shard[shard_id]
        except KeyError as error:
            raise _fail("result segment references an unknown logical shard") from error
        logical_ids = [record["logical_execution_id"] for record in logical_records]
        logical_indexes = {value: index for index, value in enumerate(logical_ids)}
        segment_indexes = [logical_indexes[value] for value in payload["logical_execution_ids"]]
        if [logical_ids[index] for index in segment_indexes] != payload["logical_execution_ids"]:
            raise _fail("result logical index projection differs")

        provenance = deepcopy(payload["provenance"])
        isolated_present = "isolated_target_processes" in provenance
        isolated = provenance.pop("isolated_target_processes", [])
        segment_process = provenance.get("process_execution")
        if isinstance(segment_process, dict):
            if isinstance(segment_process.get("stdout_sha256"), str):
                stdout_digests.add(segment_process["stdout_sha256"])
            if isinstance(segment_process.get("wall_time_ms"), int):
                performance_sample_count += 1
        isolated_indexes: list[int] = []
        isolated_records: list[dict[str, Any]] = []
        isolated_by_logical: dict[str, dict[str, Any]] = {}
        for item in isolated:
            logical_id = item["logical_execution_id"]
            if logical_id in isolated_by_logical:
                raise _fail("duplicate isolated process record")
            process = item["process_execution"]
            isolated_by_logical[logical_id] = process
            isolated_indexes.append(logical_indexes[logical_id])
            isolated_records.append(process)
            if isinstance(process.get("stdout_sha256"), str):
                stdout_digests.add(process["stdout_sha256"])
            if isinstance(process.get("wall_time_ms"), int):
                performance_sample_count += 1
        provenance_key = provenance_templates.add(provenance)
        provenance_template_references += 1

        attempts = payload["physical_attempts"]
        attempt_columns = {
            "logical_indexes": [],
            "physical_run_ids": [],
            "started_at": [],
            "ended_at": [],
            "infrastructure_failure_template_keys": [],
        }
        attempts_by_logical: dict[str, dict[str, Any]] = {}
        for attempt in attempts:
            logical_id = attempt["logical_execution_id"]
            expected_outcome = (
                "infrastructure-failure"
                if attempt["infrastructure_failure"] is not None
                else "target-observation"
            )
            if attempt["attempt_number"] != payload["attempt_number"] or attempt["outcome"] != expected_outcome:
                raise _fail("attempt columns cannot derive the ordinal or outcome")
            if logical_id in attempts_by_logical:
                raise _fail("duplicate physical attempt for a logical execution in one segment")
            attempts_by_logical[logical_id] = attempt
            attempt_columns["logical_indexes"].append(logical_indexes[logical_id])
            attempt_columns["physical_run_ids"].append(attempt["physical_run_id"])
            attempt_columns["started_at"].append(attempt["started_at"])
            attempt_columns["ended_at"].append(attempt["ended_at"])
            failure = attempt["infrastructure_failure"]
            attempt_columns["infrastructure_failure_template_keys"].append(
                None if failure is None else diagnostic_templates.add(failure)
            )
            physical_attempt_count += 1
            if failure is not None:
                infrastructure_attempt_count += 1

        observation_columns = {
            "logical_indexes": [],
            "observation_ids": [],
            "result_template_keys": [],
        }
        for observation in payload["observations"]:
            logical_id = observation["logical_execution_id"]
            attempt = attempts_by_logical[logical_id]
            if (
                observation["campaign_manifest_id"] != payload["campaign_manifest_id"]
                or observation["physical_run_id"] != attempt["physical_run_id"]
            ):
                raise _fail("observation cannot derive its segment or physical attempt binding")
            process_execution = isolated_by_logical.get(logical_id, {})
            logical = logical_records[logical_indexes[logical_id]]
            factored_result = _factor_result(
                observation["result"],
                logical=logical,
                campaign_id=context["campaign_id"],
                adapter_release_manifest_id=payload["provenance"]["adapter_release_manifest_id"],
                process_execution=process_execution,
            )
            result_key = result_templates.add(factored_result)
            result_template_selection_keys[result_key].add(payload["selection_key"])
            result_template_release_ids[result_key].add(logical["target_release_id"])
            body = {
                key: value
                for key, value in observation.items()
                if key != "observation_content_id"
            }
            expected_content_id = ids.build(
                "observation-content", "scale-observation-content-v1", body
            )
            if expected_content_id != observation["observation_content_id"]:
                raise _fail("observation content identity cannot be recomputed")
            observation_columns["logical_indexes"].append(logical_indexes[logical_id])
            observation_columns["observation_ids"].append(observation["observation_id"])
            observation_columns["result_template_keys"].append(result_key)
            observation_template_references += 1
            observation_count += 1

        segment_body = {key: value for key, value in payload.items() if key != "result_segment_id"}
        expected_segment_id = ids.build("result-segment", "scale-result-segment-v1", segment_body)
        if expected_segment_id != payload["result_segment_id"] or expected_segment_id != reference["result_segment_id"]:
            raise _fail("result segment identity cannot be recomputed")

        result_members.append(
            SemanticMember(
                relative_path=member.relative_path,
                evidence_class=member.evidence_class,
                model={
                    "attempt_number": payload["attempt_number"],
                    "campaign_manifest_id": payload["campaign_manifest_id"],
                    "logical_indexes": segment_indexes,
                    "observation_columns": observation_columns,
                    "attempt_columns": attempt_columns,
                    "provenance_template_key": provenance_key,
                    "isolated_target_processes_present": isolated_present,
                    "isolated_process_columns": {
                        "logical_indexes": isolated_indexes,
                        "process_executions": isolated_records,
                    },
                    "schema_version": payload["schema_version"],
                    "segment_kind": payload["segment_kind"],
                    "selection_key": payload["selection_key"],
                    "shard_id": shard_id,
                },
            )
        )

    logical_table, logical_indexes = logical_templates.finalize()
    result_table, result_indexes = result_templates.finalize()
    provenance_table, provenance_indexes = provenance_templates.finalize()
    diagnostic_table, diagnostic_indexes = diagnostic_templates.finalize()

    def finalize_member(item: SemanticMember) -> SemanticMember:
        model = deepcopy(item.model)
        if item.evidence_class == "canonical_logical_input":
            model["template_indexes"] = [logical_indexes[key] for key in model.pop("template_keys")]
        elif item.evidence_class == "raw_result_and_attempt":
            provenance_key = model.pop("provenance_template_key")
            model["provenance_template_index"] = provenance_indexes.get(provenance_key)
            if model["provenance_template_index"] is None:
                raise _fail("provenance template index is absent")
            columns = model["observation_columns"]
            columns["result_template_indexes"] = [
                result_indexes[key] for key in columns.pop("result_template_keys")
            ]
            attempts = model["attempt_columns"]
            attempts["infrastructure_failure_template_indexes"] = [
                None if key is None else diagnostic_indexes[key]
                for key in attempts.pop("infrastructure_failure_template_keys")
            ]
        return SemanticMember(item.relative_path, item.evidence_class, model)

    finalized_logical = tuple(finalize_member(item) for item in logical_members)
    finalized_results = tuple(finalize_member(item) for item in result_members)

    catalog = {
        "attempt_counts": [],
        "attempt_numbers": [],
        "logical_execution_counts": [],
        "observation_counts": [],
        "result_segment_ids": [],
        "segment_kinds": [],
        "sha256s": [],
        "shard_ids": [],
        "size_bytes": [],
    }
    for reference in manifest["segments"]:
        for key, target in (
            ("attempt_count", "attempt_counts"),
            ("attempt_number", "attempt_numbers"),
            ("logical_execution_count", "logical_execution_counts"),
            ("observation_count", "observation_counts"),
            ("result_segment_id", "result_segment_ids"),
            ("segment_kind", "segment_kinds"),
            ("sha256", "sha256s"),
            ("shard_id", "shard_ids"),
            ("size_bytes", "size_bytes"),
        ):
            catalog[target].append(reference[key])

    global_model = {
        "schema_version": MODEL_SCHEMA,
        "archive_schema_version": ARCHIVE_SCHEMA,
        "identity_context": context,
        "logical_templates": logical_table,
        "result_templates": result_table,
        "provenance_templates": provenance_table,
        "diagnostic_templates": diagnostic_table,
        "manifest": {
            "campaign_manifest_id": manifest["campaign_manifest_id"],
            "interruptions": manifest["interruptions"],
            "segment_catalog": catalog,
            "schema_version": manifest["schema_version"],
        },
        "logical_member_by_shard": dict(sorted(logical_member_by_shard.items())),
        "source_binding": {
            "evidence_manifest_sha256": source.manifest.sha256,
            "logical_member_count": len(source.logical),
            "manifest_member_count": 1,
            "raw_result_member_count": len(source.results),
        },
    }
    manifest_member = SemanticMember(
        source.manifest.relative_path,
        source.manifest.evidence_class,
        {"derive_from_segment_catalog": True},
    )

    cross_profile_shared = sum(
        1 for key in result_templates._values if len(result_template_selection_keys[key]) > 1
    )
    cross_release_shared = sum(
        1 for key in result_templates._values if len(result_template_release_ids[key]) > 1
    )
    statistics = {
        "logical_execution_count": derived_logical_count,
        "physical_attempt_count": physical_attempt_count,
        "observation_count": observation_count,
        "infrastructure_failure_attempt_count": infrastructure_attempt_count,
        "logical_template_count": len(logical_table),
        "logical_template_references": derived_logical_count,
        "result_template_count": len(result_table),
        "result_template_references": observation_template_references,
        "provenance_template_count": len(provenance_table),
        "provenance_template_references": provenance_template_references,
        "cross_profile_shared_result_templates": cross_profile_shared,
        "cross_release_shared_result_templates": cross_release_shared,
        "independently_executed_release_count": len(
            {record["target_release_id"] for records in logical_by_shard.values() for record in records}
        ),
        "content_addressed_diagnostic_value_count": len(diagnostic_table),
        "stdout_digest_count": len(stdout_digests),
        "raw_performance_sample_count": performance_sample_count,
        "derived_identity_counts": {
            "logical_execution_id": derived_logical_count,
            "observation_content_id": observation_count,
            "result_segment_id": len(finalized_results),
            "evidence_manifest_id": 1,
            "member_sha256_and_path": len(source.members),
        },
    }
    if enforce := (len(source.members) == P19_AUTHORITATIVE_MEMBERS):
        if (
            statistics["logical_execution_count"] != P19_LOGICAL_EXECUTIONS
            or statistics["physical_attempt_count"] != P19_PHYSICAL_ATTEMPTS
            or statistics["observation_count"] != P19_LOGICAL_EXECUTIONS
            or statistics["infrastructure_failure_attempt_count"] != 500
        ):
            raise _fail("factorized counts differ from certified P19 evidence")
    del enforce
    return SemanticCorpus(
        global_model=global_model,
        logical_members=finalized_logical,
        result_members=finalized_results,
        manifest_member=manifest_member,
        statistics=statistics,
    )


@dataclass(frozen=True)
class ArchiveBlock:
    evidence_class: str
    member_paths: tuple[str, ...]
    value: Any


@dataclass(frozen=True)
class EncodedArchive:
    data: bytes
    sha256: str
    bytes_by_class: dict[str, int]
    uncompressed_bytes_by_class: dict[str, int]
    global_uncompressed_bytes: int
    global_compressed_bytes: int
    block_count: int
    dictionary_statistics: dict[str, int]


def _xz(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_SHA256, preset=9)


def _group_members(members: Sequence[SemanticMember], group_size: int) -> list[ArchiveBlock]:
    result = []
    for offset in range(0, len(members), group_size):
        group = members[offset : offset + group_size]
        result.append(
            ArchiveBlock(
                evidence_class=group[0].evidence_class,
                member_paths=tuple(item.relative_path for item in group),
                value=[item.model for item in group],
            )
        )
    return result


def semantic_archive_blocks(semantic: SemanticCorpus, *, group_size: int = 16) -> list[ArchiveBlock]:
    if group_size < 1:
        raise _fail("archive group size must be positive")
    blocks = _group_members(semantic.logical_members, group_size)
    results_by_shard: dict[str, list[SemanticMember]] = defaultdict(list)
    for item in semantic.result_members:
        results_by_shard[item.model["shard_id"]].append(item)
    logical_groups = [semantic.logical_members[offset : offset + group_size] for offset in range(0, len(semantic.logical_members), group_size)]
    for group in logical_groups:
        result_group: list[SemanticMember] = []
        for logical in group:
            result_group.extend(sorted(results_by_shard[logical.model["shard_id"]], key=lambda item: item.relative_path))
        blocks.append(
            ArchiveBlock(
                evidence_class="raw_result_and_attempt",
                member_paths=tuple(item.relative_path for item in result_group),
                value=[item.model for item in result_group],
            )
        )
    blocks.append(
        ArchiveBlock(
            evidence_class=semantic.manifest_member.evidence_class,
            member_paths=(semantic.manifest_member.relative_path,),
            value=[semantic.manifest_member.model],
        )
    )
    return blocks


def encode_semantic_archive(semantic: SemanticCorpus, *, group_size: int = 16) -> EncodedArchive:
    blocks = semantic_archive_blocks(semantic, group_size=group_size)
    extras = [item.evidence_class for item in blocks]
    extras.extend(path for item in blocks for path in item.member_paths)
    tables = TokenTables.build(
        [semantic.global_model, *(item.value for item in blocks)],
        extra_strings=extras,
    )
    global_raw = tables.encode_tables() + tables.encode_value(semantic.global_model)
    global_compressed = _xz(global_raw)
    block_payloads: list[tuple[ArchiveBlock, bytes, bytes]] = []
    for block in blocks:
        raw = tables.encode_value(block.value)
        block_payloads.append((block, raw, _xz(raw)))

    prefix = bytearray(ARCHIVE_MAGIC)
    prefix += _uvarint(len(global_raw))
    prefix += _uvarint(len(global_compressed))
    prefix += hashlib.sha256(global_raw).digest()
    prefix += hashlib.sha256(global_compressed).digest()
    prefix += global_compressed
    prefix += _uvarint(len(block_payloads))

    metadata_by_class: dict[str, int] = defaultdict(int)
    payload_by_class: dict[str, int] = defaultdict(int)
    raw_by_class: dict[str, int] = defaultdict(int)
    metadata = bytearray()
    for block, raw, compressed in block_payloads:
        start = len(metadata)
        metadata += _uvarint(tables.string_indexes[block.evidence_class])
        metadata += _uvarint(len(block.member_paths))
        for path in block.member_paths:
            metadata += _uvarint(tables.string_indexes[path])
        metadata += _uvarint(len(raw))
        metadata += _uvarint(len(compressed))
        metadata += hashlib.sha256(raw).digest()
        metadata += hashlib.sha256(compressed).digest()
        metadata_by_class[block.evidence_class] += len(metadata) - start
        payload_by_class[block.evidence_class] += len(compressed)
        raw_by_class[block.evidence_class] += len(raw)

    body = bytes(prefix + metadata) + b"".join(item[2] for item in block_payloads)
    data = body + hashlib.sha256(body).digest()
    bytes_by_class = {
        key: metadata_by_class[key] + payload_by_class[key]
        for key in sorted(payload_by_class)
    }
    allocated = sum(bytes_by_class.values())
    bytes_by_class["shared_dictionaries_and_index"] = len(data) - allocated
    uncompressed_by_class = dict(sorted(raw_by_class.items()))
    uncompressed_by_class["shared_dictionaries_and_index"] = len(global_raw) + len(prefix) + len(metadata) + 32
    if sum(bytes_by_class.values()) != len(data):
        raise _fail("archive class allocation does not reconcile")
    return EncodedArchive(
        data=data,
        sha256=_sha256(data),
        bytes_by_class=bytes_by_class,
        uncompressed_bytes_by_class=uncompressed_by_class,
        global_uncompressed_bytes=len(global_raw),
        global_compressed_bytes=len(global_compressed),
        block_count=len(blocks),
        dictionary_statistics={
            "string_count": len(tables.strings),
            "typed_rcid_prefix_count": len(tables.prefixes),
            "object_shape_count": len(tables.shapes),
        },
    )


@dataclass(frozen=True)
class DecodedBlock:
    evidence_class: str
    member_paths: tuple[str, ...]
    value: Any


@dataclass(frozen=True)
class DecodedArchive:
    global_model: dict[str, Any]
    blocks: tuple[DecodedBlock, ...]
    sha256: str


@dataclass(frozen=True)
class _BlockMeta:
    evidence_class: str
    member_paths: tuple[str, ...]
    raw_length: int
    compressed_length: int
    raw_sha256: bytes
    compressed_sha256: bytes
    payload_offset: int


@dataclass(frozen=True)
class _ArchiveIndex:
    body: bytes
    tables: TokenTables
    global_model: dict[str, Any]
    blocks: tuple[_BlockMeta, ...]
    sha256: str


def _read_archive_index(encoded: bytes) -> _ArchiveIndex:
    if len(encoded) < len(ARCHIVE_MAGIC) + 32 or not encoded.startswith(ARCHIVE_MAGIC):
        raise _fail("archive magic differs")
    body = encoded[:-32]
    if hashlib.sha256(body).digest() != encoded[-32:]:
        raise _fail("archive root digest differs")
    data = memoryview(body)
    offset = len(ARCHIVE_MAGIC)
    global_raw_length, offset = _read_uvarint(data, offset)
    global_compressed_length, offset = _read_uvarint(data, offset)
    if offset + 64 + global_compressed_length > len(data):
        raise _fail("archive global section is truncated")
    global_raw_sha = bytes(data[offset : offset + 32])
    global_compressed_sha = bytes(data[offset + 32 : offset + 64])
    offset += 64
    global_compressed = bytes(data[offset : offset + global_compressed_length])
    offset += global_compressed_length
    if hashlib.sha256(global_compressed).digest() != global_compressed_sha:
        raise _fail("archive global compressed digest differs")
    try:
        global_raw = lzma.decompress(global_compressed, format=lzma.FORMAT_XZ)
    except lzma.LZMAError as error:
        raise _fail("archive global section cannot be decompressed") from error
    if len(global_raw) != global_raw_length or hashlib.sha256(global_raw).digest() != global_raw_sha:
        raise _fail("archive global raw digest differs")
    tables, global_offset = TokenTables.decode_tables(global_raw)
    global_model, end = tables.decode_value(global_raw, global_offset)
    if end != len(global_raw) or not isinstance(global_model, dict):
        raise _fail("archive global model has trailing bytes or wrong type")
    block_count, offset = _read_uvarint(data, offset)
    provisional = []
    for _ in range(block_count):
        class_index, offset = _read_uvarint(data, offset)
        member_count, offset = _read_uvarint(data, offset)
        paths = []
        for _ in range(member_count):
            path_index, offset = _read_uvarint(data, offset)
            if path_index >= len(tables.strings):
                raise _fail("archive member path index is out of range")
            paths.append(tables.strings[path_index])
        raw_length, offset = _read_uvarint(data, offset)
        compressed_length, offset = _read_uvarint(data, offset)
        if class_index >= len(tables.strings) or offset + 64 > len(data):
            raise _fail("archive block metadata is invalid")
        raw_sha = bytes(data[offset : offset + 32])
        compressed_sha = bytes(data[offset + 32 : offset + 64])
        offset += 64
        provisional.append((tables.strings[class_index], tuple(paths), raw_length, compressed_length, raw_sha, compressed_sha))
    metas = []
    payload_offset = offset
    for evidence_class, paths, raw_length, compressed_length, raw_sha, compressed_sha in provisional:
        end = payload_offset + compressed_length
        if end > len(data):
            raise _fail("archive block payload is truncated")
        metas.append(
            _BlockMeta(
                evidence_class,
                paths,
                raw_length,
                compressed_length,
                raw_sha,
                compressed_sha,
                payload_offset,
            )
        )
        payload_offset = end
    if payload_offset != len(data):
        raise _fail("archive contains trailing payload bytes")
    return _ArchiveIndex(bytes(body), tables, global_model, tuple(metas), _sha256(encoded))


def _decode_block(index: _ArchiveIndex, meta: _BlockMeta) -> DecodedBlock:
    start = meta.payload_offset
    end = start + meta.compressed_length
    compressed = index.body[start:end]
    if hashlib.sha256(compressed).digest() != meta.compressed_sha256:
        raise _fail("archive block compressed digest differs")
    try:
        raw = lzma.decompress(compressed, format=lzma.FORMAT_XZ)
    except lzma.LZMAError as error:
        raise _fail("archive block cannot be decompressed") from error
    if len(raw) != meta.raw_length or hashlib.sha256(raw).digest() != meta.raw_sha256:
        raise _fail("archive block raw digest differs")
    value, consumed = index.tables.decode_value(raw)
    if consumed != len(raw) or not isinstance(value, list) or len(value) != len(meta.member_paths):
        raise _fail("archive block member model differs")
    return DecodedBlock(meta.evidence_class, meta.member_paths, value)


def decode_semantic_archive(encoded: bytes) -> DecodedArchive:
    index = _read_archive_index(encoded)
    blocks = []
    for meta in index.blocks:
        blocks.append(_decode_block(index, meta))
    return DecodedArchive(index.global_model, tuple(blocks), index.sha256)


def _logical_payload(
    ids: _ContentIds,
    global_model: dict[str, Any],
    model: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    templates = global_model["logical_templates"]
    context = global_model["identity_context"]
    indexes = model["template_indexes"]
    repetitions = model["planned_repetitions"]
    if len(indexes) != len(repetitions):
        raise _fail("logical factor columns differ in length")
    records = []
    for index, repetition in zip(indexes, repetitions, strict=True):
        template = templates[index]
        records.append(
            {
                "base_logical_execution_id": template["base_logical_execution_id"],
                "logical_execution_id": _derive_logical_id(ids, context, template, repetition),
                "planned_repetition": repetition,
                "profile_id": template["profile_id"],
                "request_template_sha256": template["request_template_sha256"],
                "selection_key": template["selection_key"],
                "target_release_id": template["target_release_id"],
                "vector_revision_id": template["vector_revision_id"],
            }
        )
    payload = {
        "logical_executions": records,
        "schema_version": model["schema_version"],
        "selection_key": model["selection_key"],
        "shard_id": model["shard_id"],
    }
    return payload, records


def _restore_result_segment(
    ids: _ContentIds,
    global_model: dict[str, Any],
    model: dict[str, Any],
    logical_records: list[dict[str, Any]],
) -> dict[str, Any]:
    context = global_model["identity_context"]
    logical_ids = [record["logical_execution_id"] for record in logical_records]
    segment_logical_ids = [logical_ids[index] for index in model["logical_indexes"]]
    attempt_columns = model["attempt_columns"]
    attempt_lengths = {len(value) for value in attempt_columns.values()}
    if len(attempt_lengths) != 1:
        raise _fail("attempt factor columns differ in length")
    attempts = []
    attempts_by_logical: dict[str, dict[str, Any]] = {}
    for values in zip(
        attempt_columns["logical_indexes"],
        attempt_columns["physical_run_ids"],
        attempt_columns["started_at"],
        attempt_columns["ended_at"],
        attempt_columns["infrastructure_failure_template_indexes"],
        strict=True,
    ):
        logical_index, physical_id, started, ended, failure_index = values
        failure = (
            None
            if failure_index is None
            else deepcopy(global_model["diagnostic_templates"][failure_index])
        )
        logical_id = logical_ids[logical_index]
        attempt = {
            "attempt_number": model["attempt_number"],
            "ended_at": ended,
            "infrastructure_failure": failure,
            "logical_execution_id": logical_id,
            "outcome": "infrastructure-failure" if failure is not None else "target-observation",
            "physical_run_id": physical_id,
            "started_at": started,
        }
        attempts.append(attempt)
        attempts_by_logical[logical_id] = attempt

    provenance = deepcopy(global_model["provenance_templates"][model["provenance_template_index"]])
    isolated_columns = model["isolated_process_columns"]
    if len(isolated_columns["logical_indexes"]) != len(isolated_columns["process_executions"]):
        raise _fail("isolated process columns differ in length")
    isolated = []
    process_by_logical: dict[str, dict[str, Any]] = {}
    for logical_index, process in zip(
        isolated_columns["logical_indexes"], isolated_columns["process_executions"], strict=True
    ):
        logical_id = logical_ids[logical_index]
        isolated.append({"logical_execution_id": logical_id, "process_execution": process})
        process_by_logical[logical_id] = process
    if model["isolated_target_processes_present"]:
        provenance["isolated_target_processes"] = isolated

    observation_columns = model["observation_columns"]
    observation_lengths = {len(value) for value in observation_columns.values()}
    if len(observation_lengths) != 1:
        raise _fail("observation factor columns differ in length")
    observations = []
    for logical_index, observation_id, template_index in zip(
        observation_columns["logical_indexes"],
        observation_columns["observation_ids"],
        observation_columns["result_template_indexes"],
        strict=True,
    ):
        logical = logical_records[logical_index]
        logical_id = logical["logical_execution_id"]
        attempt = attempts_by_logical[logical_id]
        result = _restore_result(
            global_model["result_templates"][template_index],
            logical=logical,
            campaign_id=context["campaign_id"],
            adapter_release_manifest_id=provenance["adapter_release_manifest_id"],
            process_execution=process_by_logical.get(logical_id, {}),
        )
        body = {
            "campaign_manifest_id": model["campaign_manifest_id"],
            "logical_execution_id": logical_id,
            "observation_id": observation_id,
            "physical_run_id": attempt["physical_run_id"],
            "result": result,
        }
        content_id = ids.build("observation-content", "scale-observation-content-v1", body)
        observations.append({**body, "observation_content_id": content_id})

    body = {
        "attempt_number": model["attempt_number"],
        "campaign_manifest_id": model["campaign_manifest_id"],
        "logical_execution_ids": segment_logical_ids,
        "observations": observations,
        "physical_attempts": attempts,
        "provenance": provenance,
        "schema_version": model["schema_version"],
        "segment_kind": model["segment_kind"],
        "selection_key": model["selection_key"],
        "shard_id": model["shard_id"],
    }
    segment_id = ids.build("result-segment", "scale-result-segment-v1", body)
    return {**body, "result_segment_id": segment_id}


def _catalog_references(global_model: dict[str, Any]) -> list[dict[str, Any]]:
    catalog = global_model["manifest"]["segment_catalog"]
    lengths = {len(value) for value in catalog.values()}
    if len(lengths) != 1:
        raise _fail("manifest catalog columns differ in length")
    result = []
    for values in zip(
        catalog["attempt_counts"],
        catalog["attempt_numbers"],
        catalog["logical_execution_counts"],
        catalog["observation_counts"],
        catalog["result_segment_ids"],
        catalog["segment_kinds"],
        catalog["sha256s"],
        catalog["shard_ids"],
        catalog["size_bytes"],
        strict=True,
    ):
        attempt_count, attempt_number, logical_count, observation_count, segment_id, kind, digest, shard_id, size = values
        result.append(
            {
                "attempt_count": attempt_count,
                "attempt_number": attempt_number,
                "category": "scale-result-segments",
                "logical_execution_count": logical_count,
                "observation_count": observation_count,
                "relative_path": f"scale-result-segments/sha256/{digest}.json",
                "result_segment_id": segment_id,
                "segment_kind": kind,
                "sha256": digest,
                "shard_id": shard_id,
                "size_bytes": size,
            }
        )
    return result


def _restore_manifest(ids: _ContentIds, global_model: dict[str, Any]) -> dict[str, Any]:
    blueprint = global_model["manifest"]
    references = _catalog_references(global_model)
    root_digest = _sha256(
        canonical_bytes(
            {
                "interruption_digests": [item["event_sha256"] for item in blueprint["interruptions"]],
                "segment_digests": [item["sha256"] for item in references],
            }
        )
    )
    body = {
        "accepted_observation_count": sum(item["observation_count"] for item in references),
        "attempt_count": sum(item["attempt_count"] for item in references),
        "campaign_manifest_id": blueprint["campaign_manifest_id"],
        "complete": True,
        "infrastructure_failure_attempt_count": sum(
            item["attempt_count"] for item in references if item["segment_kind"] == "attempt"
        ),
        "interruptions": blueprint["interruptions"],
        "logical_execution_count": sum(
            item["logical_execution_count"] for item in references if item["segment_kind"] == "result"
        ),
        "result_shard_count": sum(item["segment_kind"] == "result" for item in references),
        "root_digest": root_digest,
        "schema_version": blueprint["schema_version"],
        "segments": references,
    }
    manifest_id = ids.build("evidence-manifest", "scale-evidence-manifest-v1", body)
    return {**body, "evidence_manifest_id": manifest_id}


def reconstruct_archive_members(repository_root: Path, decoded: DecodedArchive) -> dict[str, bytes]:
    ids = _ContentIds(repository_root.resolve(strict=True))
    logical_by_shard: dict[str, list[dict[str, Any]]] = {}
    result_payloads: dict[str, dict[str, Any]] = {}
    reconstructed: dict[str, bytes] = {}
    manifest_paths: list[str] = []
    pending_results: list[tuple[str, dict[str, Any]]] = []
    for block in decoded.blocks:
        for path, model in zip(block.member_paths, block.value, strict=True):
            if block.evidence_class == "canonical_logical_input":
                payload, records = _logical_payload(ids, decoded.global_model, model)
                logical_by_shard[payload["shard_id"]] = records
                reconstructed[path] = canonical_bytes(payload) + b"\n"
            elif block.evidence_class == "raw_result_and_attempt":
                pending_results.append((path, model))
            elif block.evidence_class == "minimal_manifest_integrity":
                manifest_paths.append(path)
            else:
                raise _fail("archive block evidence class is unknown")
    for path, model in pending_results:
        try:
            logical_records = logical_by_shard[model["shard_id"]]
        except KeyError as error:
            raise _fail("result block cannot resolve its logical shard") from error
        payload = _restore_result_segment(ids, decoded.global_model, model, logical_records)
        encoded = canonical_bytes(payload) + b"\n"
        reconstructed[path] = encoded
        result_payloads[path] = payload
    catalog = {"evidence/" + item["relative_path"]: item for item in _catalog_references(decoded.global_model)}
    if set(catalog) != set(result_payloads):
        raise _fail("archive result catalog differs from reconstructed result members")
    for path, payload in result_payloads.items():
        encoded = reconstructed[path]
        reference = catalog[path]
        if (
            _sha256(encoded) != reference["sha256"]
            or len(encoded) != reference["size_bytes"]
            or payload["result_segment_id"] != reference["result_segment_id"]
        ):
            raise _fail(
                "reconstructed result member differs from its compact catalog: "
                f"{path}; sha={_sha256(encoded)} expected={reference['sha256']}; "
                f"bytes={len(encoded)} expected_bytes={reference['size_bytes']}; "
                f"id={payload['result_segment_id']} expected_id={reference['result_segment_id']}"
            )
    if len(manifest_paths) != 1:
        raise _fail("archive must identify exactly one evidence manifest member")
    manifest = _restore_manifest(ids, decoded.global_model)
    reconstructed[manifest_paths[0]] = canonical_bytes(manifest) + b"\n"
    return reconstructed


@dataclass(frozen=True)
class RandomLookupResult:
    relative_path: str
    data: bytes
    payload_blocks_decompressed: int


def lookup_archive_member(
    repository_root: Path,
    encoded: bytes,
    relative_path: str,
) -> RandomLookupResult:
    """Reconstruct one member after inflating at most its result and logical blocks."""

    index = _read_archive_index(encoded)
    metas = [meta for meta in index.blocks if relative_path in meta.member_paths]
    if len(metas) != 1:
        raise _fail("random lookup path is absent or ambiguous")
    target_meta = metas[0]
    target_block = _decode_block(index, target_meta)
    target_position = target_block.member_paths.index(relative_path)
    model = target_block.value[target_position]
    ids = _ContentIds(repository_root.resolve(strict=True))
    block_count = 1
    if target_block.evidence_class == "canonical_logical_input":
        payload, _ = _logical_payload(ids, index.global_model, model)
    elif target_block.evidence_class == "minimal_manifest_integrity":
        payload = _restore_manifest(ids, index.global_model)
    elif target_block.evidence_class == "raw_result_and_attempt":
        shard_id = model["shard_id"]
        try:
            logical_path = index.global_model["logical_member_by_shard"][shard_id]
        except KeyError as error:
            raise _fail("random result lookup has no logical-member index") from error
        logical_metas = [meta for meta in index.blocks if logical_path in meta.member_paths]
        if len(logical_metas) != 1:
            raise _fail("random result lookup logical path is absent or ambiguous")
        logical_block = _decode_block(index, logical_metas[0])
        block_count += 1
        logical_position = logical_block.member_paths.index(logical_path)
        _, logical_records = _logical_payload(
            ids,
            index.global_model,
            logical_block.value[logical_position],
        )
        payload = _restore_result_segment(ids, index.global_model, model, logical_records)
    else:
        raise _fail("random lookup evidence class is unknown")
    data = canonical_bytes(payload) + b"\n"
    claimed = Path(relative_path).stem
    if _HEX64.fullmatch(claimed) and _sha256(data) != claimed:
        raise _fail("random lookup content-addressed path differs")
    return RandomLookupResult(relative_path, data, block_count)


def certify_reconstruction(repository_root: Path, source: SourceCorpus, encoded: bytes) -> dict[str, Any]:
    decoded = decode_semantic_archive(encoded)
    reconstructed = reconstruct_archive_members(repository_root, decoded)
    expected_paths = {item.relative_path for item in source.members}
    if set(reconstructed) != expected_paths:
        raise _fail("reconstructed member set differs from the source corpus")
    for member in source.members:
        value = reconstructed[member.relative_path]
        if value != member.path.read_bytes() or _sha256(value) != member.sha256:
            raise _fail(f"reconstructed member differs byte-for-byte: {member.relative_path}")
    corrupted = bytearray(encoded)
    corrupted[len(corrupted) // 2] ^= 1
    corruption_detected = False
    try:
        decode_semantic_archive(bytes(corrupted))
    except FactorizedEvidenceError:
        corruption_detected = True
    if not corruption_detected:
        raise _fail("archive corruption injection was not detected")
    source_members = [source.logical[0], source.results[len(source.results) // 2], source.manifest]
    maximum_blocks = 0
    for member in source_members:
        lookup = lookup_archive_member(repository_root, encoded, member.relative_path)
        maximum_blocks = max(maximum_blocks, lookup.payload_blocks_decompressed)
        if lookup.data != member.path.read_bytes():
            raise _fail("indexed random member lookup differs")
    return {
        "archive_root_sha256_verified": decoded.sha256 == _sha256(encoded),
        "byte_complete_reconstruction_verified": True,
        "content_addressed_member_paths_verified": True,
        "corruption_injection_detected": corruption_detected,
        "member_count": len(reconstructed),
        "maximum_payload_blocks_per_random_lookup": maximum_blocks,
        "random_lookup_samples_verified": len(source_members),
    }


def _tar_bytes(source: SourceCorpus, compression: str) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        directories = sorted(
            {
                parent.as_posix()
                for member in source.members
                for parent in Path(member.relative_path).parents
                if parent.as_posix() != "."
            }
        )
        ordered: list[tuple[str, SourceMember | None]] = [
            (path + "/", None) for path in directories
        ] + [(member.relative_path, member) for member in source.members]
        for relative_path, member in sorted(ordered, key=lambda item: item[0]):
            if member is None:
                info = tarfile.TarInfo(relative_path)
                info.type = tarfile.DIRTYPE
                info.size = 0
                info.mtime = 0
                info.mode = 0o755
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                archive.addfile(info)
                continue
            data = member.path.read_bytes()
            info = tarfile.TarInfo(relative_path)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    raw = output.getvalue()
    if compression == "gzip9":
        return gzip.compress(raw, compresslevel=9, mtime=0)
    if compression == "xz9":
        return _xz(raw)
    raise _fail("unknown deterministic tar compression")


def measure_source_representations(source: SourceCorpus) -> dict[str, Any]:
    raw_by_class: dict[str, int] = defaultdict(int)
    gzip_by_class: dict[str, int] = defaultdict(int)
    for member in source.members:
        data = member.path.read_bytes()
        raw_by_class[member.evidence_class] += len(data)
        gzip_by_class[member.evidence_class] += len(gzip.compress(data, compresslevel=9, mtime=0))
    raw_total = sum(raw_by_class.values())
    gzip_total = sum(gzip_by_class.values())
    if len(source.members) == P19_AUTHORITATIVE_MEMBERS:
        if dict(raw_by_class) != EXPECTED_SOURCE_BYTES or dict(gzip_by_class) != EXPECTED_INDEPENDENT_GZIP9_BYTES:
            raise _fail("source raw or independent gzip measurement differs from P20-T01A")
    tar_gzip = _tar_bytes(source, "gzip9")
    tar_xz = _tar_bytes(source, "xz9")
    return {
        "canonical_json_members": {
            "retained_bytes": raw_total,
            "bytes_per_logical_execution": f"{Decimal(raw_total) / Decimal(P19_LOGICAL_EXECUTIONS):.9f}",
            "bytes_by_evidence_class": dict(sorted(raw_by_class.items())),
            "member_count": len(source.members),
            "lossless": True,
        },
        "independent_gzip9_members": {
            "retained_bytes": gzip_total,
            "bytes_per_logical_execution": f"{Decimal(gzip_total) / Decimal(P19_LOGICAL_EXECUTIONS):.9f}",
            "bytes_by_evidence_class": dict(sorted(gzip_by_class.items())),
            "member_count": len(source.members),
            "lossless": True,
        },
        "deterministic_tar_gzip9": {
            "retained_bytes": len(tar_gzip),
            "bytes_per_logical_execution": f"{Decimal(len(tar_gzip)) / Decimal(P19_LOGICAL_EXECUTIONS):.9f}",
            "archive_sha256": _sha256(tar_gzip),
            "member_count": len(source.members),
            "lossless": True,
        },
        "p20_t01a_certified_tar_gzip9": {
            "retained_bytes": EXPECTED_TAR_GZIP9_BYTES,
            "bytes_per_logical_execution": f"{Decimal(EXPECTED_TAR_GZIP9_BYTES) / Decimal(P19_LOGICAL_EXECUTIONS):.9f}",
            "member_count": len(source.members),
            "lossless": True,
            "measurement_status": "previously certified exact baseline",
        },
        "deterministic_tar_xz9": {
            "retained_bytes": len(tar_xz),
            "bytes_per_logical_execution": f"{Decimal(len(tar_xz)) / Decimal(P19_LOGICAL_EXECUTIONS):.9f}",
            "archive_sha256": _sha256(tar_xz),
            "member_count": len(source.members),
            "lossless": True,
        },
    }


def _project_factorized_classes(measured: dict[str, int], logical: int, attempts: int) -> dict[str, int]:
    result = {}
    for key, value in measured.items():
        denominator = P19_PHYSICAL_ATTEMPTS if key == "raw_result_and_attempt" else P19_LOGICAL_EXECUTIONS
        numerator = attempts if key == "raw_result_and_attempt" else logical
        result[key] = _ceil(Decimal(value) * Decimal(numerator) / Decimal(denominator))
    return result


def measure_lossy_performance_upper_bound(
    semantic: SemanticCorpus,
    certified_archive: EncodedArchive,
) -> dict[str, Any]:
    """Measure a non-authoritative upper bound for deleting process wall-time facts."""

    removed = 0

    def visit(value: Any) -> None:
        nonlocal removed
        if isinstance(value, dict):
            if (
                "wall_time_ms" in value
                and "provider_plan" in value
                and "stdout_sha256" in value
                and "stderr_sha256" in value
            ):
                del value["wall_time_ms"]
                removed += 1
            for child in list(value.values()):
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    global_model = deepcopy(semantic.global_model)
    logical_members = deepcopy(semantic.logical_members)
    result_members = deepcopy(semantic.result_members)
    manifest_member = deepcopy(semantic.manifest_member)
    visit(global_model)
    for item in logical_members + result_members + (manifest_member,):
        visit(item.model)
    lossy = SemanticCorpus(
        global_model=global_model,
        logical_members=logical_members,
        result_members=result_members,
        manifest_member=manifest_member,
        statistics=semantic.statistics,
    )
    encoded = encode_semantic_archive(lossy)
    savings = {
        key: certified_archive.bytes_by_class.get(key, 0) - encoded.bytes_by_class.get(key, 0)
        for key in sorted(set(certified_archive.bytes_by_class) | set(encoded.bytes_by_class))
    }
    return {
        "removed_process_wall_time_fact_count": removed,
        "p19_archive_bytes_after_loss": len(encoded.data),
        "p19_archive_bytes_saved": len(certified_archive.data) - len(encoded.data),
        "bytes_saved_by_evidence_class": savings,
        "authoritative_representation": False,
        "reconstruction_possible": False,
        "measurement_role": "storage-savings upper bound only",
    }


def _scenario_total(
    measured_classes: dict[str, int],
    *,
    logical: int,
    attempts: int,
    diagnostics_rate: Decimal,
    fixed_reserve: int,
    qualification_archive_bytes: int,
) -> dict[str, Any]:
    classes = _project_factorized_classes(measured_classes, logical, attempts)
    before = sum(classes.values())
    diagnostics = _ceil(Decimal(before) * diagnostics_rate)
    total = before + diagnostics + fixed_reserve + qualification_archive_bytes
    return {
        "logical_executions": logical,
        "physical_attempts": attempts,
        "bytes_by_evidence_class_before_reserves": classes,
        "bytes_before_reserves": before,
        "diagnostics_reserve_bytes": diagnostics,
        "fixed_reserve_bytes": fixed_reserve,
        "separate_p19_qualification_archive_bytes": qualification_archive_bytes,
        "total_retained_bytes": total,
        "fits_hard_cap": total <= HARD_LIMIT_BYTES,
    }


def _attempts_at_five_percent(logical: int) -> int:
    return _ceil(Decimal(logical) * Decimal("1.05"))


def _maximum_basis_points_that_fit(build: Any) -> tuple[int, dict[str, Any]]:
    low = 0
    high = 10_000
    best = build(0)
    while low <= high:
        middle = (low + high) // 2
        scenario = build(middle)
        if scenario["fits_hard_cap"]:
            best = scenario
            low = middle + 1
        else:
            high = middle - 1
    return high, best


def build_trimming_review(
    measured_classes: dict[str, int],
    qualification_archive_bytes: int,
    conservative_baseline: dict[str, Any],
    performance_upper_bound: dict[str, Any],
) -> dict[str, Any]:
    base_total = conservative_baseline["total_retained_bytes"]

    def standard(logical: int, attempts: int, classes: dict[str, int] | None = None) -> dict[str, Any]:
        return _scenario_total(
            classes or measured_classes,
            logical=logical,
            attempts=attempts,
            diagnostics_rate=CONSERVATIVE_DIAGNOSTICS_RESERVE,
            fixed_reserve=CONSERVATIVE_FIXED_RESERVE_BYTES,
            qualification_archive_bytes=qualification_archive_bytes,
        )

    historical_upper = 120_234_321
    current_upper = 12_013_759
    historical_increment = historical_upper - current_upper
    platform_canary_logical = _ceil(Decimal(historical_upper) * Decimal("1.25"))
    platform_canary = standard(platform_canary_logical, _attempts_at_five_percent(platform_canary_logical))

    def historical_retention(basis_points: int) -> dict[str, Any]:
        retained_increment = _ceil(
            Decimal(historical_increment) * Decimal(basis_points) / Decimal(10_000)
        )
        logical = 3 * (current_upper + retained_increment)
        return standard(logical, _attempts_at_five_percent(logical))

    historical_bps, historical_break_even = _maximum_basis_points_that_fit(historical_retention)

    conservative_logical = DENOMINATORS["conservative"]["logical_executions"]

    def repetition_retention(basis_points: int) -> dict[str, Any]:
        logical = _ceil(Decimal(conservative_logical) * Decimal(basis_points) / Decimal(10_000))
        return standard(logical, _attempts_at_five_percent(logical))

    repetition_bps, repetition_break_even = _maximum_basis_points_that_fit(repetition_retention)

    diagnostics_only = _scenario_total(
        measured_classes,
        logical=conservative_logical,
        attempts=DENOMINATORS["conservative"]["physical_attempts"],
        diagnostics_rate=Decimal(0),
        fixed_reserve=CONSERVATIVE_FIXED_RESERVE_BYTES,
        qualification_archive_bytes=qualification_archive_bytes,
    )

    reduced_classes = {
        key: measured_classes[key] - performance_upper_bound["bytes_saved_by_evidence_class"].get(key, 0)
        for key in measured_classes
    }
    no_process_wall_times = standard(
        conservative_logical,
        DENOMINATORS["conservative"]["physical_attempts"],
        reduced_classes,
    )

    without_manifest = dict(measured_classes)
    without_manifest["minimal_manifest_integrity"] = 0
    manifest_upper_bound = standard(
        conservative_logical,
        DENOMINATORS["conservative"]["physical_attempts"],
        without_manifest,
    )

    options = [
        {
            "key": "transition-directed-historical-testing-break-even",
            "scenario": historical_break_even,
            "storage_savings_bytes": base_total - historical_break_even["total_retained_bytes"],
            "maximum_historical_full_vector_increment_retained_basis_points": historical_bps,
            "minimum_historical_full_vector_increment_removed_basis_points": 10_000 - historical_bps,
            "exact_capability_lost": "Historical versions outside the selected transition-directed probes would no longer have full-vector reference observations; unchanged behavior away from selected transitions would remain unmeasured.",
            "measurement_basis": "Hold the conservative 3.00 platform multiplier and current-version full vectors; solve the maximum fraction of the historical full-vector increment that can remain under 10 GB. This is a capacity break-even, not proof that a scientifically valid transition set exists.",
            "owner_review_rationale": "Smallest targeted break-even among the demonstrated fitting choices; it preferentially reduces historical coverage multiplication but requires a separately justified transition set.",
        },
        {
            "key": "platform-canary-triggered-expansion",
            "scenario": platform_canary,
            "storage_savings_bytes": base_total - platform_canary["total_retained_bytes"],
            "exact_capability_lost": "Conservative certification would no longer contain the full three-times platform/architecture matrix; non-canary coordinates would exist only after a trigger and could lack reference results.",
            "measurement_basis": "Replace the established conservative 3.00 multiplier with the already established 1.25 lower/canary multiplier while retaining full historical vectors.",
            "owner_review_rationale": "Largest storage relief, but it replaces a complete conservative platform/architecture reference matrix and therefore sacrifices broader reference capability than the targeted historical break-even.",
        },
        {
            "key": "uniform-benchmark-repetition-break-even",
            "scenario": repetition_break_even,
            "storage_savings_bytes": base_total - repetition_break_even["total_retained_bytes"],
            "maximum_uniform_execution_retention_basis_points": repetition_bps,
            "minimum_uniform_execution_reduction_basis_points": 10_000 - repetition_bps,
            "exact_capability_lost": "Fewer independent performance/conformance repetitions would reduce precision and rare-event detection; applying this envelope to non-benchmark obligations would also remove coverage and is not authorized.",
            "measurement_basis": "Mathematical break-even if an equivalent fraction of all conservative executions were removable. The P20-T01A denominator does not separately expose benchmark-only repetitions, so this is an upper envelope requiring a future classified denominator before use.",
            "owner_review_rationale": "Fits with near-minimal savings, but is ranked behind targeted historical reduction because the current denominator cannot isolate benchmark repetitions from core coverage.",
        },
        {
            "key": "routine-diagnostics-reserve-to-anomaly-only",
            "scenario": diagnostics_only,
            "storage_savings_bytes": base_total - diagnostics_only["total_retained_bytes"],
            "exact_capability_lost": "The 15% conservative diagnostic reserve would disappear; unexpected routine diagnostics could hit the hard cap or be unavailable unless a separate anomaly path succeeds.",
            "measurement_basis": "Remove only the established 15% conservative diagnostic reserve; retain existing P19 diagnostics and the 1 GB fixed reserve.",
            "owner_review_rationale": "Preserves existing facts but does not fit alone and removes the planned operational margin for unexpected diagnostics.",
        },
        {
            "key": "remove-all-process-wall-time-samples-upper-bound",
            "scenario": no_process_wall_times,
            "storage_savings_bytes": base_total - no_process_wall_times["total_retained_bytes"],
            "p19_measurement": performance_upper_bound,
            "exact_capability_lost": "Exact per-process wall-time measurements would not be reconstructible, eliminating raw latency distributions and weakening historical performance comparison. Historical-only savings would be smaller than this full-corpus upper bound.",
            "measurement_basis": "Actual re-encoding after deleting every process wall_time_ms fact from the P19 semantic model; intentionally non-reconstructible and used only as an upper bound.",
            "owner_review_rationale": "Removes core raw performance facts yet closes less than two percent of the capacity gap.",
        },
        {
            "key": "remove-minimal-manifest-integrity-upper-bound",
            "scenario": manifest_upper_bound,
            "storage_savings_bytes": base_total - manifest_upper_bound["total_retained_bytes"],
            "exact_capability_lost": "Manifest-level closed-set reconciliation and root commitment would be lost; this is prohibited by the evidence contract and is shown only to demonstrate low marginal storage value.",
            "measurement_basis": "Set the measured minimal-manifest class to zero while retaining other classes; shared index bytes remain.",
            "owner_review_rationale": "Prohibited integrity loss for negligible savings; it cannot resolve the capacity gap.",
        },
        {
            "key": "derive-logical-inputs-from-immutable-definitions",
            "scenario": standard(
                conservative_logical,
                DENOMINATORS["conservative"]["physical_attempts"],
            ),
            "storage_savings_bytes": 0,
            "exact_capability_lost": "None: the strongest lossless representation already stores 26 canonical logical templates once and deterministically derives all 100,000 logical identities. Further deletion has no demonstrated lossless saving.",
            "measurement_basis": "Already realized in the certified lossless archive.",
            "owner_review_rationale": "No additional lossless reduction exists; retained only to document that this requested optimization has already been exhausted.",
        },
    ]
    savings_order = {
        option["key"]: rank
        for rank, option in enumerate(
            sorted(options, key=lambda item: item["storage_savings_bytes"], reverse=True),
            1,
        )
    }
    for rank, option in enumerate(options, 1):
        option["owner_review_rank"] = rank
        option["storage_savings_rank"] = savings_order[option["key"]]
        option["requires_program_owner_approval"] = True
        option["implemented"] = False
    return {
        "required": True,
        "reason": "The strongest certified lossless expected case fits, but the conservative retained corpus exceeds the 10 GB hard cap.",
        "baseline_conservative_total_retained_bytes": base_total,
        "bytes_that_must_be_removed_for_hard_cap": base_total - HARD_LIMIT_BYTES,
        "options_ranked_by_storage_and_scientific_tradeoff": options,
        "authority_boundary": "No option changes C1-C7, D101, universe breadth, feature/engine/language/surface coverage, historical semantics, performance requirements, or evidence-retention semantics without a new Program Owner decision.",
        "p20_t02_must_remain_planned": True,
    }


def build_factorized_forecast(
    repository_root: Path,
    source: SourceCorpus,
    source_measurements: dict[str, Any],
    semantic: SemanticCorpus,
    archive: EncodedArchive,
    certification: dict[str, Any],
    performance_upper_bound: dict[str, Any],
) -> dict[str, Any]:
    measured_classes = archive.bytes_by_class
    projections: dict[str, Any] = {}
    for case, counts in DENOMINATORS.items():
        classes = _project_factorized_classes(
            measured_classes,
            counts["logical_executions"],
            counts["physical_attempts"],
        )
        before_reserves = sum(classes.values())
        diagnostics = 0
        fixed = 0
        if case == "expected":
            diagnostics = _ceil(Decimal(before_reserves) * EXPECTED_DIAGNOSTICS_RESERVE)
        elif case == "conservative":
            diagnostics = _ceil(Decimal(before_reserves) * CONSERVATIVE_DIAGNOSTICS_RESERVE)
            fixed = CONSERVATIVE_FIXED_RESERVE_BYTES
        production = before_reserves + diagnostics + fixed
        retained = production + len(archive.data)
        projections[case] = {
            **counts,
            "production_bytes_by_evidence_class_before_reserves": classes,
            "production_bytes_before_reserves": before_reserves,
            "required_diagnostics_reserve_bytes": diagnostics,
            "fixed_reserve_bytes": fixed,
            "production_retained_bytes": production,
            "separate_p19_qualification_archive_bytes": len(archive.data),
            "total_retained_bytes": retained,
            "soft_limit_remaining_bytes": max(0, SOFT_LIMIT_BYTES - retained),
            "hard_limit_remaining_bytes": max(0, HARD_LIMIT_BYTES - retained),
            "exceeds_soft_limit": retained > SOFT_LIMIT_BYTES,
            "exceeds_hard_limit": retained > HARD_LIMIT_BYTES,
        }

    strongest_fits = (
        not projections["expected"]["exceeds_hard_limit"]
        and not projections["conservative"]["exceeds_hard_limit"]
    )
    trimming_review = None
    if not strongest_fits:
        trimming_review = build_trimming_review(
            measured_classes,
            len(archive.data),
            projections["conservative"],
            performance_upper_bound,
        )
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "classification": {
            "authoritative_raw_evidence_changed": False,
            "derived_analytics_are_authoritative": False,
            "docker_accessed": False,
            "material_r2_publication_performed": False,
            "source_corpus_read_only": True,
            "storage_limits_changed": False,
        },
        "source_binding": {
            "campaign": "P19 Session 05 100K qualification",
            "evidence_manifest_sha256": source.manifest.sha256,
            "authoritative_member_count": len(source.members),
            "authoritative_raw_bytes": sum(item.size_bytes for item in source.members),
            "logical_execution_count": semantic.statistics["logical_execution_count"],
            "physical_attempt_count": semantic.statistics["physical_attempt_count"],
        },
        "representations": {
            **source_measurements,
            "factorized_deterministic_binary_xz9": {
                "retained_bytes": len(archive.data),
                "bytes_per_logical_execution": f"{Decimal(len(archive.data)) / Decimal(P19_LOGICAL_EXECUTIONS):.9f}",
                "bytes_by_evidence_class": archive.bytes_by_class,
                "uncompressed_binary_bytes_by_evidence_class": archive.uncompressed_bytes_by_class,
                "archive_sha256": archive.sha256,
                "block_count": archive.block_count,
                "global_uncompressed_bytes": archive.global_uncompressed_bytes,
                "global_compressed_bytes": archive.global_compressed_bytes,
                "dictionary_statistics": archive.dictionary_statistics,
                "lossless": True,
                "random_lookup_indexed": True,
            },
        },
        "factoring_measurements": semantic.statistics,
        "certification": certification,
        "forecast": {
            "denominators_unchanged": True,
            "soft_limit_bytes": SOFT_LIMIT_BYTES,
            "hard_limit_bytes": HARD_LIMIT_BYTES,
            "cases": projections,
        },
        "decision_gate": {
            "strongest_lossless_representation": "factorized_deterministic_binary_xz9",
            "strongest_lossless_fits_expected_and_conservative_below_hard_cap": strongest_fits,
            "p20_t01a_capacity_blocker_resolved": strongest_fits,
            "p20_t02_must_remain_planned": not strongest_fits,
            "material_r2_publication_authorized": False,
            "paid_capacity_authorized": False,
            "second_stage_trimming_review_required": not strongest_fits,
        },
        "second_stage_trimming_review": trimming_review,
    }
    digest_input = deepcopy(report)
    report["report_digest_sha256"] = _sha256(rfc8785.dumps(digest_input))
    return report


def verify_factorized_forecast(report: dict[str, Any]) -> None:
    if report.get("schema_version") != REPORT_SCHEMA:
        raise _fail("factorized forecast schema version differs")
    digest_input = deepcopy(report)
    claimed = digest_input.pop("report_digest_sha256", None)
    if claimed != _sha256(rfc8785.dumps(digest_input)):
        raise _fail("factorized forecast digest differs")
    classification = report["classification"]
    if (
        classification["authoritative_raw_evidence_changed"]
        or classification["derived_analytics_are_authoritative"]
        or classification["docker_accessed"]
        or classification["material_r2_publication_performed"]
        or classification["storage_limits_changed"]
        or not classification["source_corpus_read_only"]
    ):
        raise _fail("factorized forecast authority boundary differs")
    if report["forecast"]["soft_limit_bytes"] != SOFT_LIMIT_BYTES or report["forecast"]["hard_limit_bytes"] != HARD_LIMIT_BYTES:
        raise _fail("factorized forecast storage limits differ")
    source = report["source_binding"]
    if source != {
        "campaign": "P19 Session 05 100K qualification",
        "evidence_manifest_sha256": P19_MANIFEST_SHA256,
        "authoritative_member_count": P19_AUTHORITATIVE_MEMBERS,
        "authoritative_raw_bytes": sum(EXPECTED_SOURCE_BYTES.values()),
        "logical_execution_count": P19_LOGICAL_EXECUTIONS,
        "physical_attempt_count": P19_PHYSICAL_ATTEMPTS,
    }:
        raise _fail("factorized forecast source binding differs")
    representations = report["representations"]
    if (
        representations["canonical_json_members"]["retained_bytes"]
        != sum(EXPECTED_SOURCE_BYTES.values())
        or representations["independent_gzip9_members"]["retained_bytes"]
        != sum(EXPECTED_INDEPENDENT_GZIP9_BYTES.values())
        or representations["p20_t01a_certified_tar_gzip9"]["retained_bytes"]
        != EXPECTED_TAR_GZIP9_BYTES
    ):
        raise _fail("factorized forecast P19 representation baseline differs")
    strongest = representations["factorized_deterministic_binary_xz9"]
    measured_classes = strongest["bytes_by_evidence_class"]
    if (
        not strongest["lossless"]
        or sum(measured_classes.values()) != strongest["retained_bytes"]
        or not strongest["random_lookup_indexed"]
    ):
        raise _fail("factorized strongest representation does not reconcile")
    for case, expected in DENOMINATORS.items():
        actual = report["forecast"]["cases"][case]
        if actual["logical_executions"] != expected["logical_executions"] or actual["physical_attempts"] != expected["physical_attempts"]:
            raise _fail("factorized forecast denominator differs")
        expected_classes = _project_factorized_classes(
            measured_classes,
            expected["logical_executions"],
            expected["physical_attempts"],
        )
        before_reserves = sum(expected_classes.values())
        diagnostics = 0
        fixed = 0
        if case == "expected":
            diagnostics = _ceil(Decimal(before_reserves) * EXPECTED_DIAGNOSTICS_RESERVE)
        elif case == "conservative":
            diagnostics = _ceil(Decimal(before_reserves) * CONSERVATIVE_DIAGNOSTICS_RESERVE)
            fixed = CONSERVATIVE_FIXED_RESERVE_BYTES
        production = before_reserves + diagnostics + fixed
        retained = production + strongest["retained_bytes"]
        if actual != {
            **expected,
            "production_bytes_by_evidence_class_before_reserves": expected_classes,
            "production_bytes_before_reserves": before_reserves,
            "required_diagnostics_reserve_bytes": diagnostics,
            "fixed_reserve_bytes": fixed,
            "production_retained_bytes": production,
            "separate_p19_qualification_archive_bytes": strongest["retained_bytes"],
            "total_retained_bytes": retained,
            "soft_limit_remaining_bytes": max(0, SOFT_LIMIT_BYTES - retained),
            "hard_limit_remaining_bytes": max(0, HARD_LIMIT_BYTES - retained),
            "exceeds_soft_limit": retained > SOFT_LIMIT_BYTES,
            "exceeds_hard_limit": retained > HARD_LIMIT_BYTES,
        }:
            raise _fail("factorized retained total does not reconcile")
    gate = report["decision_gate"]
    if gate["material_r2_publication_authorized"] or gate["paid_capacity_authorized"]:
        raise _fail("factorized forecast grants unapproved authority")
    fits = not report["forecast"]["cases"]["expected"]["exceeds_hard_limit"] and not report["forecast"]["cases"]["conservative"]["exceeds_hard_limit"]
    if (
        gate["strongest_lossless_fits_expected_and_conservative_below_hard_cap"] != fits
        or gate["p20_t01a_capacity_blocker_resolved"] != fits
        or gate["p20_t02_must_remain_planned"] == fits
        or gate["second_stage_trimming_review_required"] == fits
    ):
        raise _fail("factorized decision gate differs from forecast")
    review = report["second_stage_trimming_review"]
    if not fits:
        if (
            not isinstance(review, dict)
            or not review["required"]
            or not review["p20_t02_must_remain_planned"]
        ):
            raise _fail("mandatory second-stage trimming review is absent or grants authority")
        options = review["options_ranked_by_storage_and_scientific_tradeoff"]
        expected_option_keys = {
            "transition-directed-historical-testing-break-even",
            "platform-canary-triggered-expansion",
            "uniform-benchmark-repetition-break-even",
            "routine-diagnostics-reserve-to-anomaly-only",
            "remove-all-process-wall-time-samples-upper-bound",
            "remove-minimal-manifest-integrity-upper-bound",
            "derive-logical-inputs-from-immutable-definitions",
        }
        if (
            review["baseline_conservative_total_retained_bytes"]
            != report["forecast"]["cases"]["conservative"]["total_retained_bytes"]
            or review["bytes_that_must_be_removed_for_hard_cap"]
            != review["baseline_conservative_total_retained_bytes"] - HARD_LIMIT_BYTES
            or {item["key"] for item in options} != expected_option_keys
            or any(
                item["implemented"] or not item["requires_program_owner_approval"]
                for item in options
            )
            or any(
                item["storage_savings_bytes"]
                != review["baseline_conservative_total_retained_bytes"]
                - item["scenario"]["total_retained_bytes"]
                or item["scenario"]["fits_hard_cap"]
                != (item["scenario"]["total_retained_bytes"] <= HARD_LIMIT_BYTES)
                for item in options
            )
        ):
            raise _fail("trimming option accounting or authority differs")
        if [item["owner_review_rank"] for item in options] != list(range(1, len(options) + 1)):
            raise _fail("trimming owner-review ranks are not closed and ordered")
        savings_order = sorted(
            options,
            key=lambda item: item["storage_savings_bytes"],
            reverse=True,
        )
        if [item["storage_savings_rank"] for item in savings_order] != list(
            range(1, len(options) + 1)
        ):
            raise _fail("trimming storage-savings ranks are not closed and ordered")
    elif review is not None:
        raise _fail("trimming review must be absent when lossless storage fits")
