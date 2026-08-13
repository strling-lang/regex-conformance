"""Immutable provider-neutral cache, cleanup, and transfer records."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

SAFE_INTEGER_MAX = 9_007_199_254_740_991
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
RCID_PATTERN = re.compile(
    r"^rcid:v1:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:"
    r"(?:u7:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    r"|h:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:[0-9a-f]{64})$"
)
OPID_PATTERN = re.compile(
    r"^opid:v1:(?:cache-cleanup|transfer):u7:"
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
CACHE_KINDS = frozenset(
    {"artifact", "environment", "toolchain", "provider-cache", "analysis-cache", "protected-spool"}
)
RETENTION_CLASSES = frozenset(
    {"reacquirable", "expensive-reconstruction", "rare-fragile", "registry-authority", "protected-spool"}
)
VERIFICATION_STATES = frozenset({"verified", "provisional", "missing", "mismatch", "unsafe"})
REALITY_STATES = frozenset({"verified", "missing", "mismatch", "unsafe", "provider-error"})


def _require_token(name: str, value: str) -> None:
    if TOKEN_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase canonical token")


def _require_sha256(name: str, value: str | None) -> None:
    if value is not None and SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _require_safe_integer(name: str, value: int | None, *, positive: bool = False) -> None:
    if value is None:
        return
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= SAFE_INTEGER_MAX:
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(f"{name} must be a {qualifier} safe integer")


def _require_signed_safe_integer(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not -SAFE_INTEGER_MAX <= value <= SAFE_INTEGER_MAX:
        raise ValueError(f"{name} must be a signed safe integer")


def _require_timestamp(value: str | None) -> None:
    if value is None:
        return
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"invalid RFC 3339 timestamp: {value!r}") from error
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")


def _require_unique(name: str, values: tuple[str, ...]) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{name} must not contain duplicates")


def _require_relative_path(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("cache paths must be normalized root-relative POSIX paths")


@dataclass(frozen=True)
class CacheEntry:
    cache_key: str
    kind: str
    content_id: str | None
    sha256: str
    relative_path: str
    size_bytes: int
    reclaimable_bytes: int
    accounting_basis: str
    provider_name: str
    retention_class: str
    pinned: bool
    active_leases: tuple[str, ...]
    future_dependencies: tuple[str, ...]
    dependencies: tuple[str, ...]
    last_used_at: str
    reacquisition_time_seconds: int
    reacquisition_cost_microunits: int
    reconstruction_difficulty: int
    upstream_fragility: int
    verification_status: str
    verified_at: str | None
    observed_at: str
    source: str
    staleness_seconds: int
    registry_authority: bool = False

    def __post_init__(self) -> None:
        _require_token("cache key", self.cache_key)
        if self.kind not in CACHE_KINDS:
            raise ValueError(f"invalid cache kind: {self.kind}")
        if self.content_id is not None and RCID_PATTERN.fullmatch(self.content_id) is None:
            raise ValueError("cache content ID must be a canonical rcid")
        _require_sha256("cache digest", self.sha256)
        _require_relative_path(self.relative_path)
        for name in (
            "size_bytes",
            "reclaimable_bytes",
            "reacquisition_time_seconds",
            "reacquisition_cost_microunits",
            "staleness_seconds",
        ):
            _require_safe_integer(name, getattr(self, name))
        if self.accounting_basis not in {"logical", "allocated"}:
            raise ValueError("cache accounting basis must be logical or allocated")
        _require_token("cache provider name", self.provider_name)
        if self.retention_class not in RETENTION_CLASSES:
            raise ValueError(f"invalid cache retention class: {self.retention_class}")
        if not isinstance(self.pinned, bool) or not isinstance(self.registry_authority, bool):
            raise ValueError("cache pin and authority flags must be boolean")
        if self.registry_authority:
            raise ValueError("local cache entries can never claim registry authority")
        for group_name, values in (
            ("active leases", self.active_leases),
            ("future dependencies", self.future_dependencies),
            ("cache dependencies", self.dependencies),
        ):
            _require_unique(group_name, values)
            for value in values:
                _require_token(group_name, value)
        if self.cache_key in self.dependencies:
            raise ValueError("cache entries cannot depend on themselves")
        _require_timestamp(self.last_used_at)
        _require_safe_integer("reconstruction difficulty", self.reconstruction_difficulty)
        _require_safe_integer("upstream fragility", self.upstream_fragility)
        if not 0 <= self.reconstruction_difficulty <= 100:
            raise ValueError("reconstruction difficulty must be between 0 and 100")
        if not 0 <= self.upstream_fragility <= 100:
            raise ValueError("upstream fragility must be between 0 and 100")
        if self.verification_status not in VERIFICATION_STATES:
            raise ValueError(f"invalid cache verification state: {self.verification_status}")
        _require_timestamp(self.verified_at)
        _require_timestamp(self.observed_at)
        if self.verification_status == "verified" and self.verified_at is None:
            raise ValueError("verified cache entries require a verification timestamp")
        if self.verification_status != "verified" and self.verified_at is not None:
            raise ValueError("non-verified cache entries cannot claim a verification timestamp")
        observed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        if datetime.fromisoformat(self.last_used_at.replace("Z", "+00:00")) > observed:
            raise ValueError("cache last-use time cannot follow its observation")
        if self.verified_at is not None and datetime.fromisoformat(
            self.verified_at.replace("Z", "+00:00")
        ) > observed:
            raise ValueError("cache verification time cannot follow its observation")
        if not self.source:
            raise ValueError("cache inventory source is required")

    @property
    def hard_protection_reasons(self) -> tuple[str, ...]:
        reasons: list[str] = []
        if self.pinned:
            reasons.append("pinned")
        if self.active_leases:
            reasons.append("active-lease")
        if self.future_dependencies:
            reasons.append("future-dependency")
        if self.kind == "protected-spool" or self.retention_class == "protected-spool":
            reasons.append("protected-spool")
        if self.retention_class == "registry-authority":
            reasons.append("registry-authority")
        if self.retention_class == "rare-fragile":
            reasons.append("rare-fragile")
        if self.verification_status != "verified":
            reasons.append("not-verified")
        return tuple(reasons)

    def to_dict(self) -> dict[str, Any]:
        return {
            "accounting_basis": self.accounting_basis,
            "active_leases": sorted(self.active_leases),
            "cache_key": self.cache_key,
            "content_id": self.content_id,
            "dependencies": sorted(self.dependencies),
            "future_dependencies": sorted(self.future_dependencies),
            "kind": self.kind,
            "last_used_at": self.last_used_at,
            "observed_at": self.observed_at,
            "pinned": self.pinned,
            "provider_name": self.provider_name,
            "reacquisition_cost_microunits": self.reacquisition_cost_microunits,
            "reacquisition_time_seconds": self.reacquisition_time_seconds,
            "reclaimable_bytes": self.reclaimable_bytes,
            "reconstruction_difficulty": self.reconstruction_difficulty,
            "registry_authority": self.registry_authority,
            "relative_path": self.relative_path,
            "retention_class": self.retention_class,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "source": self.source,
            "staleness_seconds": self.staleness_seconds,
            "upstream_fragility": self.upstream_fragility,
            "verification_status": self.verification_status,
            "verified_at": self.verified_at,
        }


@dataclass(frozen=True)
class CacheInventory:
    observed_at: str
    inventory_digest: str
    entries: tuple[CacheEntry, ...]
    schema_version: str = "cache-inventory.v1"
    canonical_authority: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != "cache-inventory.v1":
            raise ValueError("unsupported cache inventory schema version")
        _require_timestamp(self.observed_at)
        _require_sha256("cache inventory digest", self.inventory_digest)
        _require_unique("cache keys", tuple(item.cache_key for item in self.entries))
        _require_unique("cache paths", tuple(item.relative_path for item in self.entries))
        inventory_time = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        if any(
            datetime.fromisoformat(item.observed_at.replace("Z", "+00:00")) > inventory_time
            for item in self.entries
        ):
            raise ValueError("cache entry observations cannot follow the inventory observation")
        if not isinstance(self.canonical_authority, bool) or self.canonical_authority:
            raise ValueError("cache inventory is operational and non-canonical")

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_authority": self.canonical_authority,
            "entries": [item.to_dict() for item in sorted(self.entries, key=lambda item: item.cache_key)],
            "inventory_digest": self.inventory_digest,
            "observed_at": self.observed_at,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class CacheReality:
    cache_key: str
    status: str
    actual_sha256: str | None
    actual_size_bytes: int | None
    actual_reclaimable_bytes: int | None
    accounting_basis: str | None
    observed_at: str
    source: str
    diagnostic: str | None = None

    def __post_init__(self) -> None:
        _require_token("cache reality key", self.cache_key)
        if self.status not in REALITY_STATES:
            raise ValueError(f"invalid cache reality state: {self.status}")
        _require_sha256("actual cache digest", self.actual_sha256)
        _require_safe_integer("actual cache size", self.actual_size_bytes)
        _require_safe_integer("actual reclaimable bytes", self.actual_reclaimable_bytes)
        if self.accounting_basis not in {None, "logical", "allocated"}:
            raise ValueError("invalid cache reality accounting basis")
        _require_timestamp(self.observed_at)
        if not self.source:
            raise ValueError("cache reality source is required")
        values = (self.actual_sha256, self.actual_size_bytes, self.actual_reclaimable_bytes, self.accounting_basis)
        if self.status == "verified" and any(value is None for value in values):
            raise ValueError("verified cache reality requires digest, sizes, and accounting basis")
        if self.status != "verified" and not self.diagnostic:
            raise ValueError("unverified cache reality requires a diagnostic")

    def to_dict(self) -> dict[str, Any]:
        return {
            "accounting_basis": self.accounting_basis,
            "actual_reclaimable_bytes": self.actual_reclaimable_bytes,
            "actual_sha256": self.actual_sha256,
            "actual_size_bytes": self.actual_size_bytes,
            "cache_key": self.cache_key,
            "diagnostic": self.diagnostic,
            "observed_at": self.observed_at,
            "source": self.source,
            "status": self.status,
        }


@dataclass(frozen=True)
class CacheReconciliation:
    inventory_digest: str
    observed_at: str
    observations: tuple[CacheReality, ...]

    def __post_init__(self) -> None:
        _require_sha256("reconciled inventory digest", self.inventory_digest)
        _require_timestamp(self.observed_at)
        _require_unique("reconciled cache keys", tuple(item.cache_key for item in self.observations))
        reconciliation_time = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        if any(
            datetime.fromisoformat(item.observed_at.replace("Z", "+00:00")) > reconciliation_time
            for item in self.observations
        ):
            raise ValueError("cache reality observations cannot follow their reconciliation")

    def to_dict(self) -> dict[str, Any]:
        return {
            "inventory_digest": self.inventory_digest,
            "observations": [
                item.to_dict() for item in sorted(self.observations, key=lambda item: item.cache_key)
            ],
            "observed_at": self.observed_at,
        }


@dataclass(frozen=True)
class EvictionPolicy:
    bytes_weight: int
    age_weight: int
    reacquisition_time_penalty: int
    reacquisition_cost_penalty: int
    reconstruction_penalty: int
    fragility_penalty: int
    expensive_reconstruction_penalty: int
    maximum_inventory_age_seconds: int

    def __post_init__(self) -> None:
        for name in (
            "bytes_weight",
            "age_weight",
            "reacquisition_time_penalty",
            "reacquisition_cost_penalty",
            "reconstruction_penalty",
            "fragility_penalty",
            "expensive_reconstruction_penalty",
            "maximum_inventory_age_seconds",
        ):
            _require_safe_integer(name, getattr(self, name), positive=True)

    def to_dict(self) -> dict[str, int]:
        return {
            "age_weight": self.age_weight,
            "bytes_weight": self.bytes_weight,
            "expensive_reconstruction_penalty": self.expensive_reconstruction_penalty,
            "fragility_penalty": self.fragility_penalty,
            "maximum_inventory_age_seconds": self.maximum_inventory_age_seconds,
            "reacquisition_cost_penalty": self.reacquisition_cost_penalty,
            "reacquisition_time_penalty": self.reacquisition_time_penalty,
            "reconstruction_penalty": self.reconstruction_penalty,
        }


@dataclass(frozen=True)
class EvictionCandidate:
    cache_key: str
    score: int
    expected_reclaim_bytes: int
    rank: int

    def __post_init__(self) -> None:
        _require_token("eviction candidate key", self.cache_key)
        _require_signed_safe_integer("eviction score", self.score)
        _require_safe_integer("expected reclaim bytes", self.expected_reclaim_bytes, positive=True)
        _require_safe_integer("eviction rank", self.rank, positive=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cache_key": self.cache_key,
            "expected_reclaim_bytes": self.expected_reclaim_bytes,
            "rank": self.rank,
            "score": self.score,
        }


@dataclass(frozen=True)
class EvictionExclusion:
    cache_key: str
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_token("excluded cache key", self.cache_key)
        if not self.reasons:
            raise ValueError("cache exclusions require reasons")
        _require_unique("cache exclusion reasons", self.reasons)
        for value in self.reasons:
            _require_token("cache exclusion reason", value)

    def to_dict(self) -> dict[str, Any]:
        return {"cache_key": self.cache_key, "reasons": sorted(self.reasons)}


@dataclass(frozen=True)
class CleanupPlan:
    cleanup_id: str
    inventory_digest: str
    created_at: str
    target_reclaim_bytes: int
    expected_reclaim_bytes: int
    outcome: str
    policy: EvictionPolicy
    selected: tuple[EvictionCandidate, ...]
    exclusions: tuple[EvictionExclusion, ...]
    mutation_permitted: bool = False

    def __post_init__(self) -> None:
        if OPID_PATTERN.fullmatch(self.cleanup_id) is None or ":cache-cleanup:" not in self.cleanup_id:
            raise ValueError("cleanup ID must be an operational cache-cleanup UUIDv7")
        _require_sha256("cleanup inventory digest", self.inventory_digest)
        _require_timestamp(self.created_at)
        _require_safe_integer("target reclaim bytes", self.target_reclaim_bytes, positive=True)
        _require_safe_integer("expected reclaim bytes", self.expected_reclaim_bytes)
        if self.outcome not in {"ready", "refused"}:
            raise ValueError("cleanup plan outcome must be ready or refused")
        _require_unique("selected cache keys", tuple(item.cache_key for item in self.selected))
        _require_unique("excluded cache keys", tuple(item.cache_key for item in self.exclusions))
        if {item.cache_key for item in self.selected} & {item.cache_key for item in self.exclusions}:
            raise ValueError("cache entries cannot be selected and excluded")
        if tuple(item.rank for item in self.selected) != tuple(range(1, len(self.selected) + 1)):
            raise ValueError("selected cache candidates require contiguous ranks")
        if self.expected_reclaim_bytes != sum(item.expected_reclaim_bytes for item in self.selected):
            raise ValueError("cleanup expected bytes must equal selected candidate bytes")
        if self.outcome == "ready" and self.expected_reclaim_bytes < self.target_reclaim_bytes:
            raise ValueError("ready cleanup plans must meet their reclaim target")
        if self.outcome == "refused" and self.expected_reclaim_bytes >= self.target_reclaim_bytes:
            raise ValueError("refused cleanup plans cannot already meet their target")
        if not isinstance(self.mutation_permitted, bool) or self.mutation_permitted:
            raise ValueError("cleanup planning must be non-mutating")

    def to_dict(self) -> dict[str, Any]:
        return {
            "cleanup_id": self.cleanup_id,
            "created_at": self.created_at,
            "exclusions": [item.to_dict() for item in sorted(self.exclusions, key=lambda item: item.cache_key)],
            "expected_reclaim_bytes": self.expected_reclaim_bytes,
            "inventory_digest": self.inventory_digest,
            "mutation_permitted": self.mutation_permitted,
            "outcome": self.outcome,
            "policy": self.policy.to_dict(),
            "selected": [item.to_dict() for item in self.selected],
            "target_reclaim_bytes": self.target_reclaim_bytes,
        }


@dataclass(frozen=True)
class CleanupMutation:
    cache_key: str
    expected_reclaim_bytes: int
    actual_reclaim_bytes: int
    outcome: str
    code: str
    detail: str

    def __post_init__(self) -> None:
        _require_token("cleanup mutation key", self.cache_key)
        _require_safe_integer("expected mutation bytes", self.expected_reclaim_bytes)
        _require_safe_integer("actual mutation bytes", self.actual_reclaim_bytes)
        if self.outcome not in {"deleted", "skipped", "failed"}:
            raise ValueError("invalid cleanup mutation outcome")
        _require_token("cleanup mutation code", self.code)
        if not self.detail:
            raise ValueError("cleanup mutations require detail")
        if self.outcome != "deleted" and self.actual_reclaim_bytes != 0:
            raise ValueError("only verified deletion may report actual reclaimed bytes")

    def to_dict(self) -> dict[str, Any]:
        return {
            "actual_reclaim_bytes": self.actual_reclaim_bytes,
            "cache_key": self.cache_key,
            "code": self.code,
            "detail": self.detail,
            "expected_reclaim_bytes": self.expected_reclaim_bytes,
            "outcome": self.outcome,
        }


@dataclass(frozen=True)
class CleanupReport:
    plan: CleanupPlan
    state: str
    started_at: str
    completed_at: str
    actual_reclaim_bytes: int
    mutations: tuple[CleanupMutation, ...]
    registry_authority_mutated: bool = False
    schema_version: str = "cache-cleanup.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "cache-cleanup.v1":
            raise ValueError("unsupported cache cleanup schema version")
        if self.state not in {"completed", "partial", "refused", "cancelled"}:
            raise ValueError("invalid cleanup report state")
        _require_timestamp(self.started_at)
        _require_timestamp(self.completed_at)
        if datetime.fromisoformat(self.completed_at.replace("Z", "+00:00")) < datetime.fromisoformat(
            self.started_at.replace("Z", "+00:00")
        ):
            raise ValueError("cleanup reports cannot complete before they start")
        _require_safe_integer("actual cleanup bytes", self.actual_reclaim_bytes)
        _require_unique("cleanup mutation keys", tuple(item.cache_key for item in self.mutations))
        if self.actual_reclaim_bytes != sum(item.actual_reclaim_bytes for item in self.mutations):
            raise ValueError("cleanup actual bytes must reconcile with mutations")
        selected_keys = tuple(item.cache_key for item in self.plan.selected)
        mutation_keys = tuple(item.cache_key for item in self.mutations)
        if mutation_keys != selected_keys[: len(mutation_keys)]:
            raise ValueError("cleanup mutations must be an ordered prefix of selected candidates")
        for mutation, candidate in zip(self.mutations, self.plan.selected):
            if mutation.expected_reclaim_bytes != candidate.expected_reclaim_bytes:
                raise ValueError("cleanup mutation expectations must match the immutable plan")
        if self.state == "refused" and (self.plan.outcome != "refused" or self.mutations):
            raise ValueError("refused reports require a refused non-mutating plan")
        if self.state in {"partial", "cancelled"} and not self.mutations:
            raise ValueError("partial and cancelled cleanup reports require an attempted candidate")
        if self.state == "cancelled" and (
            self.mutations[-1].outcome != "skipped" or self.mutations[-1].code != "cancelled"
        ):
            raise ValueError("cancelled cleanup reports require a final cancelled skip")
        if self.state == "completed" and any(item.outcome != "deleted" for item in self.mutations):
            raise ValueError("completed cleanup reports require every selected deletion to succeed")
        if self.state == "completed" and mutation_keys != selected_keys:
            raise ValueError("completed cleanup reports require every selected candidate")
        if self.state == "completed" and self.actual_reclaim_bytes != self.plan.expected_reclaim_bytes:
            raise ValueError("completed cleanup reports must reconcile every expected byte")
        if not isinstance(self.registry_authority_mutated, bool) or self.registry_authority_mutated:
            raise ValueError("local cleanup can never mutate registry authority")

    def to_dict(self) -> dict[str, Any]:
        return {
            "actual_reclaim_bytes": self.actual_reclaim_bytes,
            "completed_at": self.completed_at,
            "mutations": [item.to_dict() for item in self.mutations],
            "plan": self.plan.to_dict(),
            "registry_authority_mutated": self.registry_authority_mutated,
            "schema_version": self.schema_version,
            "started_at": self.started_at,
            "state": self.state,
        }


@dataclass(frozen=True)
class TransferRequirement:
    transfer_id: str
    operation: str
    locator: str
    expected_sha256: str
    expected_size_bytes: int
    relative_path: str
    cache_key: str | None

    def __post_init__(self) -> None:
        if OPID_PATTERN.fullmatch(self.transfer_id) is None or ":transfer:" not in self.transfer_id:
            raise ValueError("transfer ID must be an operational transfer UUIDv7")
        if self.operation not in {"acquire", "download", "upload"}:
            raise ValueError("invalid transfer operation")
        if not self.locator or any(character in self.locator for character in ("\r", "\n", "\x00")):
            raise ValueError("transfer locator must be a non-empty single-line value")
        if re.search(r"://[^/?#]*@", self.locator) or re.search(
            r"[?&](?:access[_-]?token|api[_-]?key|credential|password|secret|token)=",
            self.locator,
            flags=re.IGNORECASE,
        ):
            raise ValueError("transfer locators cannot embed credentials or secret query parameters")
        _require_sha256("transfer digest", self.expected_sha256)
        _require_safe_integer("transfer size", self.expected_size_bytes)
        _require_relative_path(self.relative_path)
        if self.cache_key is not None:
            _require_token("transfer cache key", self.cache_key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cache_key": self.cache_key,
            "expected_sha256": self.expected_sha256,
            "expected_size_bytes": self.expected_size_bytes,
            "locator": self.locator,
            "operation": self.operation,
            "relative_path": self.relative_path,
            "transfer_id": self.transfer_id,
        }


@dataclass(frozen=True)
class TransferAttempt:
    sequence: int
    started_at: str
    completed_at: str
    offset_start: int
    offset_end: int
    outcome: str
    code: str
    detail: str

    def __post_init__(self) -> None:
        _require_safe_integer("transfer attempt sequence", self.sequence, positive=True)
        _require_timestamp(self.started_at)
        _require_timestamp(self.completed_at)
        if datetime.fromisoformat(self.completed_at.replace("Z", "+00:00")) < datetime.fromisoformat(
            self.started_at.replace("Z", "+00:00")
        ):
            raise ValueError("transfer attempts cannot complete before they start")
        _require_safe_integer("transfer offset start", self.offset_start)
        _require_safe_integer("transfer offset end", self.offset_end)
        if self.offset_end < self.offset_start:
            raise ValueError("transfer attempts cannot move checkpoints backward")
        if self.outcome not in {"interrupted", "failed", "completed"}:
            raise ValueError("invalid transfer attempt outcome")
        _require_token("transfer attempt code", self.code)
        if not self.detail:
            raise ValueError("transfer attempts require detail")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "completed_at": self.completed_at,
            "detail": self.detail,
            "offset_end": self.offset_end,
            "offset_start": self.offset_start,
            "outcome": self.outcome,
            "sequence": self.sequence,
            "started_at": self.started_at,
        }


@dataclass(frozen=True)
class TransferRecord:
    requirement: TransferRequirement
    state: str
    bytes_completed: int
    checkpoint_sha256: str
    attempts: tuple[TransferAttempt, ...]
    verified_sha256: str | None
    verified_size_bytes: int | None
    resumable: bool = True
    schema_version: str = "transfer-record.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "transfer-record.v1":
            raise ValueError("unsupported transfer record schema version")
        if self.state not in {"planned", "interrupted", "failed", "completed"}:
            raise ValueError("invalid transfer state")
        _require_safe_integer("transfer checkpoint bytes", self.bytes_completed)
        _require_sha256("transfer checkpoint digest", self.checkpoint_sha256)
        _require_unique("transfer attempt sequences", tuple(str(item.sequence) for item in self.attempts))
        if tuple(item.sequence for item in self.attempts) != tuple(range(1, len(self.attempts) + 1)):
            raise ValueError("transfer attempts require contiguous sequence numbers")
        if self.attempts and self.bytes_completed != self.attempts[-1].offset_end:
            raise ValueError("transfer checkpoint must equal the last physical attempt offset")
        expected_offset = 0
        for attempt in self.attempts:
            if attempt.offset_start != expected_offset:
                raise ValueError("transfer attempts must form a contiguous checkpoint history")
            expected_offset = attempt.offset_end
        if self.bytes_completed > self.requirement.expected_size_bytes:
            raise ValueError("transfer checkpoint cannot exceed expected size")
        _require_sha256("verified transfer digest", self.verified_sha256)
        _require_safe_integer("verified transfer size", self.verified_size_bytes)
        if self.state == "planned":
            if self.bytes_completed or self.attempts:
                raise ValueError("planned transfers cannot contain physical attempts")
            if self.checkpoint_sha256 != EMPTY_SHA256:
                raise ValueError("planned transfers require the empty-byte checkpoint digest")
        if self.state == "completed":
            if not self.attempts or self.attempts[-1].outcome != "completed":
                raise ValueError("completed transfer requires a completed physical attempt")
            if self.verified_sha256 != self.requirement.expected_sha256:
                raise ValueError("completed transfer digest must match the immutable requirement")
            if self.verified_size_bytes != self.requirement.expected_size_bytes:
                raise ValueError("completed transfer size must match the immutable requirement")
            if self.bytes_completed != self.requirement.expected_size_bytes:
                raise ValueError("completed transfer checkpoint must reach the expected size")
            if self.checkpoint_sha256 != self.requirement.expected_sha256:
                raise ValueError("completed transfer checkpoint must match the expected digest")
        else:
            if self.state in {"interrupted", "failed"}:
                if not self.attempts or self.attempts[-1].outcome != self.state:
                    raise ValueError("incomplete transfer state must match its latest physical attempt")
            if self.verified_sha256 is not None or self.verified_size_bytes is not None:
                raise ValueError("incomplete transfers cannot claim final verification")
        if not isinstance(self.resumable, bool):
            raise ValueError("transfer resumability must be boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempts": [item.to_dict() for item in self.attempts],
            "bytes_completed": self.bytes_completed,
            "checkpoint_sha256": self.checkpoint_sha256,
            "requirement": self.requirement.to_dict(),
            "resumable": self.resumable,
            "schema_version": self.schema_version,
            "state": self.state,
            "verified_sha256": self.verified_sha256,
            "verified_size_bytes": self.verified_size_bytes,
        }
