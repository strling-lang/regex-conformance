"""Project-aware cache reconciliation, safe cleanup, and resumable transfers."""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import stat
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Protocol

import rfc8785

from .cache_models import (
    OPID_PATTERN,
    SAFE_INTEGER_MAX,
    TOKEN_PATTERN,
    CacheEntry,
    CacheInventory,
    CacheReality,
    CacheReconciliation,
    CleanupMutation,
    CleanupPlan,
    CleanupReport,
    EvictionCandidate,
    EvictionExclusion,
    EvictionPolicy,
    TransferAttempt,
    TransferRecord,
    TransferRequirement,
)


class Clock(Protocol):
    def now(self) -> datetime: ...


class OperationIdGenerator(Protocol):
    def new_cleanup_id(self) -> str: ...

    def new_transfer_id(self) -> str: ...


class Cancellation(Protocol):
    def cancelled(self) -> bool: ...


class CacheProvider(Protocol):
    def inspect(self, entry: CacheEntry) -> CacheReality: ...

    def delete_verified(self, entry: CacheEntry, cleanup_id: str) -> "DeletionResult": ...


class ChunkSource(Protocol):
    def read(self, locator: str, offset: int, limit: int) -> bytes: ...


class UtcClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class NeverCancel:
    def cancelled(self) -> bool:
        return False


class Uuid7OperationIds:
    @staticmethod
    def _new(namespace: str) -> str:
        stamp = int(time.time() * 1000)
        if not 0 <= stamp < 2**48:
            raise ValueError("UUIDv7 timestamp must fit in 48 bits")
        integer = (
            (stamp << 80)
            | (0x7 << 76)
            | (secrets.randbits(12) << 64)
            | (0b10 << 62)
            | secrets.randbits(62)
        )
        return f"opid:v1:{namespace}:u7:{uuid.UUID(int=integer)}"

    def new_cleanup_id(self) -> str:
        return self._new("cache-cleanup")

    def new_transfer_id(self) -> str:
        return self._new("transfer")


class TransferIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True)
class DeletionResult:
    succeeded: bool
    actual_reclaim_bytes: int
    code: str
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.succeeded, bool):
            raise ValueError("deletion success must be boolean")
        if isinstance(self.actual_reclaim_bytes, bool) or not 0 <= self.actual_reclaim_bytes <= SAFE_INTEGER_MAX:
            raise ValueError("actual deleted bytes must be a non-negative safe integer")
        if not self.succeeded and self.actual_reclaim_bytes:
            raise ValueError("failed deletion cannot report reclaimed bytes")
        if TOKEN_PATTERN.fullmatch(self.code) is None or not self.detail:
            raise ValueError("deletion results require a code and detail")


def _now(clock: Clock) -> datetime:
    value = clock.now()
    if value.tzinfo is None:
        raise ValueError("cache manager clock must be timezone-aware")
    return value.astimezone(timezone.utc)


def _rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _inventory_payload(observed_at: str, entries: tuple[CacheEntry, ...]) -> dict[str, object]:
    return {
        "canonical_authority": False,
        "entries": [item.to_dict() for item in sorted(entries, key=lambda item: item.cache_key)],
        "observed_at": observed_at,
        "schema_version": "cache-inventory.v1",
    }


def inventory_digest(observed_at: str, entries: tuple[CacheEntry, ...]) -> str:
    try:
        canonical = rfc8785.dumps(_inventory_payload(observed_at, entries))
    except (rfc8785.CanonicalizationError, UnicodeError, TypeError, ValueError) as error:
        raise ValueError("cache inventory is not RFC 8785 canonicalizable") from error
    return _sha256_bytes(canonical)


def _safe_score(value: int) -> int:
    if not -SAFE_INTEGER_MAX <= value <= SAFE_INTEGER_MAX:
        raise OverflowError("eviction score exceeds the signed safe-integer domain")
    return value


class CacheManager:
    def __init__(
        self,
        *,
        clock: Clock | None = None,
        id_generator: OperationIdGenerator | None = None,
    ) -> None:
        self._clock = clock or UtcClock()
        self._ids = id_generator or Uuid7OperationIds()

    def inventory(self, entries: tuple[CacheEntry, ...], *, observed_at: str | None = None) -> CacheInventory:
        stamp = observed_at or _rfc3339(_now(self._clock))
        return CacheInventory(stamp, inventory_digest(stamp, entries), entries)

    @staticmethod
    def _verify_inventory(inventory: CacheInventory) -> None:
        expected = inventory_digest(inventory.observed_at, inventory.entries)
        if not secrets.compare_digest(expected, inventory.inventory_digest):
            raise ValueError("cache inventory digest does not match its canonical contents")

    def reconcile(self, inventory: CacheInventory, provider: CacheProvider) -> CacheReconciliation:
        self._verify_inventory(inventory)
        observations: list[CacheReality] = []
        for entry in sorted(inventory.entries, key=lambda item: item.cache_key):
            try:
                reality = provider.inspect(entry)
            except Exception as error:
                reality = CacheReality(
                    entry.cache_key,
                    "provider-error",
                    None,
                    None,
                    None,
                    None,
                    _rfc3339(_now(self._clock)),
                    entry.provider_name,
                    f"provider inspection failed with {type(error).__name__}",
                )
            if reality.cache_key != entry.cache_key:
                raise ValueError("cache provider returned reality for a different cache key")
            if reality.source != entry.provider_name:
                raise ValueError("cache provider returned reality under a different provider identity")
            observations.append(reality)
        return CacheReconciliation(
            inventory.inventory_digest,
            _rfc3339(_now(self._clock)),
            tuple(observations),
        )

    def plan_cleanup(
        self,
        inventory: CacheInventory,
        reconciliation: CacheReconciliation,
        target_reclaim_bytes: int,
        policy: EvictionPolicy,
    ) -> CleanupPlan:
        self._verify_inventory(inventory)
        if reconciliation.inventory_digest != inventory.inventory_digest:
            raise ValueError("cache reconciliation belongs to a different inventory")
        if target_reclaim_bytes < 1 or target_reclaim_bytes > SAFE_INTEGER_MAX:
            raise ValueError("cleanup target must be a positive safe integer")
        entries = {item.cache_key: item for item in inventory.entries}
        observations = {item.cache_key: item for item in reconciliation.observations}
        if set(observations) != set(entries):
            raise ValueError("cache reconciliation must inspect every and only inventory entry")
        now = _now(self._clock)
        reverse_dependencies: dict[str, set[str]] = {key: set() for key in entries}
        for dependent in inventory.entries:
            for dependency in dependent.dependencies:
                if dependency not in entries:
                    raise ValueError(f"cache dependency {dependency!r} is absent from inventory")
                reverse_dependencies[dependency].add(dependent.cache_key)

        candidates: list[tuple[int, CacheEntry]] = []
        exclusions: list[EvictionExclusion] = []
        for entry in sorted(inventory.entries, key=lambda item: item.cache_key):
            reality = observations[entry.cache_key]
            reasons = list(entry.hard_protection_reasons)
            if reverse_dependencies[entry.cache_key]:
                reasons.append("dependency-protected")
            entry_age = (now - _parse_timestamp(entry.observed_at)).total_seconds()
            reality_age = (now - _parse_timestamp(reality.observed_at)).total_seconds()
            if entry_age < 0 or reality_age < 0:
                reasons.append("observation-in-future")
            if (
                entry_age > policy.maximum_inventory_age_seconds
                or reality_age > policy.maximum_inventory_age_seconds
                or entry.staleness_seconds > policy.maximum_inventory_age_seconds
            ):
                reasons.append("inventory-stale")
            if reality.status != "verified":
                reasons.append(f"reconciliation-{reality.status}")
            elif (
                reality.actual_sha256 != entry.sha256
                or reality.actual_size_bytes != entry.size_bytes
                or reality.actual_reclaimable_bytes != entry.reclaimable_bytes
                or reality.accounting_basis != entry.accounting_basis
            ):
                reasons.append("reconciliation-mismatch")
            if entry.reclaimable_bytes == 0:
                reasons.append("no-reclaimable-space")
            if _parse_timestamp(entry.last_used_at) > now:
                reasons.append("last-use-in-future")
            if reasons:
                exclusions.append(EvictionExclusion(entry.cache_key, tuple(sorted(set(reasons)))))
                continue
            last_use_age_hours = max(0, int((now - _parse_timestamp(entry.last_used_at)).total_seconds()) // 3600)
            score = (
                (entry.reclaimable_bytes // 1024) * policy.bytes_weight
                + last_use_age_hours * policy.age_weight
                - (entry.reacquisition_time_seconds // 60) * policy.reacquisition_time_penalty
                - (entry.reacquisition_cost_microunits // 1000) * policy.reacquisition_cost_penalty
                - entry.reconstruction_difficulty * policy.reconstruction_penalty
                - entry.upstream_fragility * policy.fragility_penalty
                - (
                    policy.expensive_reconstruction_penalty
                    if entry.retention_class == "expensive-reconstruction"
                    else 0
                )
            )
            try:
                candidates.append((_safe_score(score), entry))
            except OverflowError:
                exclusions.append(EvictionExclusion(entry.cache_key, ("score-overflow",)))

        candidates.sort(key=lambda item: (-item[0], -item[1].reclaimable_bytes, item[1].cache_key))
        selected: list[EvictionCandidate] = []
        total = 0
        for score, entry in candidates:
            if total >= target_reclaim_bytes:
                break
            total += entry.reclaimable_bytes
            if total > SAFE_INTEGER_MAX:
                raise OverflowError("cleanup reclaim plan exceeds the safe-integer domain")
            selected.append(EvictionCandidate(entry.cache_key, score, entry.reclaimable_bytes, len(selected) + 1))
        return CleanupPlan(
            cleanup_id=self._ids.new_cleanup_id(),
            inventory_digest=inventory.inventory_digest,
            created_at=_rfc3339(now),
            target_reclaim_bytes=target_reclaim_bytes,
            expected_reclaim_bytes=total,
            outcome="ready" if total >= target_reclaim_bytes else "refused",
            policy=policy,
            selected=tuple(selected),
            exclusions=tuple(exclusions),
        )

    def execute_cleanup(
        self,
        plan: CleanupPlan,
        inventory: CacheInventory,
        provider: CacheProvider,
        cancellation: Cancellation | None = None,
    ) -> CleanupReport:
        self._verify_inventory(inventory)
        if plan.inventory_digest != inventory.inventory_digest:
            raise ValueError("cleanup plan belongs to a different cache inventory")
        start = _rfc3339(_now(self._clock))
        execution_now = _now(self._clock)
        plan_age = (execution_now - _parse_timestamp(plan.created_at)).total_seconds()
        inventory_age = (execution_now - _parse_timestamp(inventory.observed_at)).total_seconds()
        if plan_age < 0 or inventory_age < 0:
            raise ValueError("cleanup plan and inventory timestamps cannot be in the future")
        if (
            plan_age > plan.policy.maximum_inventory_age_seconds
            or inventory_age > plan.policy.maximum_inventory_age_seconds
        ):
            raise ValueError("cleanup plan or inventory is stale; fresh reconciliation is required")
        if plan.outcome == "refused":
            return CleanupReport(plan, "refused", start, _rfc3339(_now(self._clock)), 0, ())
        cancellation = cancellation or NeverCancel()
        entries = {item.cache_key: item for item in inventory.entries}
        selected_keys = tuple(item.cache_key for item in plan.selected)
        if any(key not in entries for key in selected_keys):
            raise ValueError("cleanup plan selects an entry absent from inventory")
        protected_dependencies = {dependency for item in inventory.entries for dependency in item.dependencies}
        mutations: list[CleanupMutation] = []
        state = "completed"
        for candidate in plan.selected:
            entry = entries[candidate.cache_key]
            if candidate.expected_reclaim_bytes != entry.reclaimable_bytes:
                raise ValueError("cleanup candidate expectation diverges from inventory")
            if cancellation.cancelled():
                mutations.append(
                    CleanupMutation(entry.cache_key, candidate.expected_reclaim_bytes, 0, "skipped", "cancelled", "cleanup cancelled before mutation")
                )
                state = "cancelled"
                break
            reasons = list(entry.hard_protection_reasons)
            if entry.cache_key in protected_dependencies:
                reasons.append("dependency-protected")
            if reasons:
                mutations.append(
                    CleanupMutation(
                        entry.cache_key,
                        candidate.expected_reclaim_bytes,
                        0,
                        "failed",
                        "protection-changed",
                        f"entry became protected: {', '.join(sorted(set(reasons)))}",
                    )
                )
                state = "partial"
                continue
            try:
                reality = provider.inspect(entry)
            except Exception as error:
                mutations.append(
                    CleanupMutation(
                        entry.cache_key,
                        candidate.expected_reclaim_bytes,
                        0,
                        "failed",
                        "provider-inspection-error",
                        f"cache provider inspection raised {type(error).__name__}",
                    )
                )
                state = "partial"
                continue
            reality_age = (execution_now - _parse_timestamp(reality.observed_at)).total_seconds()
            if (
                reality.cache_key != entry.cache_key
                or reality.source != entry.provider_name
                or reality_age < 0
                or reality_age > plan.policy.maximum_inventory_age_seconds
                or reality.status != "verified"
                or reality.actual_sha256 != entry.sha256
                or reality.actual_size_bytes != entry.size_bytes
                or reality.actual_reclaimable_bytes != entry.reclaimable_bytes
                or reality.accounting_basis != entry.accounting_basis
            ):
                mutations.append(
                    CleanupMutation(
                        entry.cache_key,
                        candidate.expected_reclaim_bytes,
                        0,
                        "failed",
                        "reconciliation-changed",
                        "provider reality changed after cleanup planning; no deletion attempted",
                    )
                )
                state = "partial"
                continue
            try:
                result = provider.delete_verified(entry, plan.cleanup_id)
            except Exception as error:
                result = DeletionResult(
                    False,
                    0,
                    "provider-delete-error",
                    f"cache provider deletion raised {type(error).__name__}",
                )
            result_code = result.code
            result_detail = result.detail
            if result.succeeded and result.actual_reclaim_bytes != candidate.expected_reclaim_bytes:
                result_code = "reclaim-diverged"
                result_detail = (
                    f"provider deleted the entry but reclaimed {result.actual_reclaim_bytes} bytes "
                    f"instead of the planned {candidate.expected_reclaim_bytes}"
                )
                state = "partial"
            mutations.append(
                CleanupMutation(
                    entry.cache_key,
                    candidate.expected_reclaim_bytes,
                    result.actual_reclaim_bytes,
                    "deleted" if result.succeeded else "failed",
                    result_code,
                    result_detail,
                )
            )
            if not result.succeeded:
                state = "partial"
        if len(mutations) < len(plan.selected) and state != "cancelled":
            state = "partial"
        actual = sum(item.actual_reclaim_bytes for item in mutations)
        if actual > SAFE_INTEGER_MAX:
            raise OverflowError("actual cleanup reconciliation exceeds the safe-integer domain")
        return CleanupReport(
            plan,
            state,
            start,
            _rfc3339(_now(self._clock)),
            actual,
            tuple(mutations),
        )


class FilesystemCacheProvider:
    """A root-confined cache provider that re-verifies bytes before unlink."""

    def __init__(self, root: Path, *, clock: Clock | None = None) -> None:
        root.mkdir(parents=True, exist_ok=True)
        self._root = root.resolve(strict=True)
        self._clock = clock or UtcClock()

    @staticmethod
    def _allocated_bytes(metadata: os.stat_result) -> tuple[int, str]:
        blocks = getattr(metadata, "st_blocks", None)
        if blocks is not None:
            value = blocks * 512
            if value <= SAFE_INTEGER_MAX:
                return value, "allocated"
        return metadata.st_size, "logical"

    def _path(self, relative_path: str) -> Path:
        parts = PurePosixPath(relative_path).parts
        path = self._root.joinpath(*parts)
        current = self._root
        for part in parts[:-1]:
            current = current / part
            if current.exists() and current.is_symlink():
                raise ValueError("cache path contains a symlinked directory")
        try:
            resolved_parent = path.parent.resolve(strict=True)
        except FileNotFoundError:
            resolved_parent = path.parent.resolve(strict=False)
        if resolved_parent != self._root and self._root not in resolved_parent.parents:
            raise ValueError("cache path escapes the configured root")
        return path

    def _inspect_file(self, entry: CacheEntry) -> tuple[CacheReality, tuple[int, int] | None]:
        observed_at = _rfc3339(_now(self._clock))
        try:
            path = self._path(entry.relative_path)
            metadata = path.lstat()
        except FileNotFoundError:
            return (
                CacheReality(entry.cache_key, "missing", None, None, None, None, observed_at, entry.provider_name, "cache path is missing"),
                None,
            )
        except OSError as error:
            return (
                CacheReality(
                    entry.cache_key,
                    "unsafe",
                    None,
                    None,
                    None,
                    None,
                    observed_at,
                    entry.provider_name,
                    f"cache path inspection failed with errno {error.errno}",
                ),
                None,
            )
        except ValueError as error:
            return (
                CacheReality(entry.cache_key, "unsafe", None, None, None, None, observed_at, entry.provider_name, str(error)),
                None,
            )
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return (
                CacheReality(entry.cache_key, "unsafe", None, None, None, None, observed_at, entry.provider_name, "cache path is not a regular non-symlink file"),
                None,
            )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                digest = hashlib.sha256()
                while True:
                    block = os.read(descriptor, 1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
                after = path.lstat()
            finally:
                os.close(descriptor)
        except OSError as error:
            return (
                CacheReality(
                    entry.cache_key,
                    "unsafe",
                    None,
                    None,
                    None,
                    None,
                    observed_at,
                    entry.provider_name,
                    f"cache read failed with errno {error.errno}",
                ),
                None,
            )
        identity = (opened.st_dev, opened.st_ino)
        if identity != (metadata.st_dev, metadata.st_ino) or identity != (after.st_dev, after.st_ino):
            return (
                CacheReality(entry.cache_key, "unsafe", None, None, None, None, observed_at, entry.provider_name, "cache path changed identity during verification"),
                None,
            )
        if opened.st_nlink != 1 or after.st_nlink != 1:
            return (
                CacheReality(
                    entry.cache_key,
                    "unsafe",
                    None,
                    None,
                    None,
                    None,
                    observed_at,
                    entry.provider_name,
                    "cache path has multiple hard links; reclaimed space is not safely attributable",
                ),
                None,
            )
        reclaimable, basis = self._allocated_bytes(opened)
        status = "verified"
        diagnostic = None
        if (
            digest.hexdigest() != entry.sha256
            or opened.st_size != entry.size_bytes
            or reclaimable != entry.reclaimable_bytes
            or basis != entry.accounting_basis
        ):
            status = "mismatch"
            diagnostic = "cache bytes or realized-size accounting differ from inventory"
        return (
            CacheReality(
                entry.cache_key,
                status,
                digest.hexdigest(),
                opened.st_size,
                reclaimable,
                basis,
                observed_at,
                entry.provider_name,
                diagnostic,
            ),
            identity,
        )

    def inspect(self, entry: CacheEntry) -> CacheReality:
        return self._inspect_file(entry)[0]

    def delete_verified(self, entry: CacheEntry, cleanup_id: str) -> DeletionResult:
        if OPID_PATTERN.fullmatch(cleanup_id) is None or ":cache-cleanup:" not in cleanup_id:
            return DeletionResult(False, 0, "cleanup-id-invalid", "provider requires a cache-cleanup transaction ID")
        reality, identity = self._inspect_file(entry)
        if reality.status != "verified" or identity is None:
            return DeletionResult(False, 0, "verification-failed", reality.diagnostic or reality.status)
        path = self._path(entry.relative_path)
        try:
            free_before = shutil.disk_usage(path.parent).free
        except OSError:
            free_before = None
        try:
            immediate = path.lstat()
            if (immediate.st_dev, immediate.st_ino) != identity or not stat.S_ISREG(immediate.st_mode):
                return DeletionResult(False, 0, "identity-changed", "cache identity changed immediately before unlink")
            path.unlink()
        except OSError as error:
            return DeletionResult(False, 0, "unlink-failed", f"cache unlink failed with errno {error.errno}")
        if path.exists() or path.is_symlink():
            return DeletionResult(False, 0, "unlink-unverified", "cache path still exists after unlink")
        try:
            free_after = shutil.disk_usage(path.parent).free
        except OSError:
            free_after = None
        expected = reality.actual_reclaimable_bytes or 0
        if free_before is None or free_after is None:
            return DeletionResult(
                True,
                0,
                "deleted-unreconciled",
                "verified cache entry was unlinked but filesystem free space could not be observed",
            )
        actual = min(expected, max(0, free_after - free_before))
        return DeletionResult(
            True,
            actual,
            "deleted",
            "verified cache entry unlinked; actual bytes use bounded filesystem free-space delta",
        )


class TransferManager:
    """Preserve physical attempts and byte checkpoints for exact transfers."""

    EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

    def __init__(
        self,
        root: Path,
        *,
        clock: Clock | None = None,
        id_generator: OperationIdGenerator | None = None,
    ) -> None:
        root.mkdir(parents=True, exist_ok=True)
        self._root = root.resolve(strict=True)
        self._clock = clock or UtcClock()
        self._ids = id_generator or Uuid7OperationIds()

    def plan(
        self,
        *,
        operation: str,
        locator: str,
        expected_sha256: str,
        expected_size_bytes: int,
        relative_path: str,
        cache_key: str | None = None,
    ) -> TransferRecord:
        requirement = TransferRequirement(
            self._ids.new_transfer_id(),
            operation,
            locator,
            expected_sha256,
            expected_size_bytes,
            relative_path,
            cache_key,
        )
        return TransferRecord(requirement, "planned", 0, self.EMPTY_SHA256, (), None, None)

    def record_external_attempt(
        self,
        record: TransferRecord,
        *,
        bytes_completed: int,
        checkpoint_sha256: str,
        outcome: str,
        code: str,
        detail: str,
    ) -> TransferRecord:
        if record.state == "completed":
            raise ValueError("completed transfers are immutable")
        if bytes_completed < record.bytes_completed or bytes_completed > record.requirement.expected_size_bytes:
            raise ValueError("transfer progress must be monotonic and bounded")
        start = _rfc3339(_now(self._clock))
        attempt = TransferAttempt(
            len(record.attempts) + 1,
            start,
            _rfc3339(_now(self._clock)),
            record.bytes_completed,
            bytes_completed,
            outcome,
            code,
            detail,
        )
        completed = outcome == "completed"
        if completed and bytes_completed != record.requirement.expected_size_bytes:
            raise ValueError("completed attempts must reach the expected byte count")
        if completed and not secrets.compare_digest(
            checkpoint_sha256, record.requirement.expected_sha256
        ):
            raise ValueError("completed attempts must prove the immutable expected digest")
        return TransferRecord(
            record.requirement,
            "completed" if completed else outcome,
            bytes_completed,
            checkpoint_sha256,
            (*record.attempts, attempt),
            record.requirement.expected_sha256 if completed else None,
            record.requirement.expected_size_bytes if completed else None,
            record.resumable,
        )

    def _destination(self, requirement: TransferRequirement, *, partial: bool) -> Path:
        path = self._root.joinpath(*PurePosixPath(requirement.relative_path).parts)
        root = self._root
        parent = path.parent.resolve(strict=False)
        if parent != root and root not in parent.parents:
            raise TransferIntegrityError("transfer path escapes the configured root")
        current = root
        for part in PurePosixPath(requirement.relative_path).parts[:-1]:
            current = current / part
            if current.exists() and current.is_symlink():
                raise TransferIntegrityError("transfer path contains a symlinked directory")
        parent.mkdir(parents=True, exist_ok=True)
        return path.with_name(path.name + ".part") if partial else path

    @staticmethod
    def _hash_path(path: Path) -> tuple[int, str, tuple[int, int]]:
        try:
            before = path.lstat()
        except OSError as error:
            raise TransferIntegrityError(
                f"transfer checkpoint cannot be inspected (errno {error.errno})"
            ) from error
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise TransferIntegrityError("transfer checkpoint is not a regular non-symlink file")
        digest = hashlib.sha256()
        size = 0
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                size += len(block)
                digest.update(block)
            after = path.lstat()
        finally:
            os.close(descriptor)
        identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISREG(opened.st_mode)
            or identity != (before.st_dev, before.st_ino)
            or identity != (after.st_dev, after.st_ino)
        ):
            raise TransferIntegrityError("transfer checkpoint changed identity during verification")
        return size, digest.hexdigest(), identity

    def resume_download(
        self,
        record: TransferRecord,
        source: ChunkSource,
        *,
        chunk_size: int = 1024 * 1024,
        maximum_chunks: int | None = None,
        cancellation: Cancellation | None = None,
    ) -> TransferRecord:
        if record.requirement.operation not in {"acquire", "download"}:
            raise ValueError("local resumable download only supports acquire/download requirements")
        if record.state in {"completed", "failed"}:
            raise ValueError("completed or failed transfers cannot be resumed")
        if chunk_size < 1 or chunk_size > 64 * 1024 * 1024:
            raise ValueError("transfer chunk size must be between 1 and 64 MiB")
        if maximum_chunks is not None and maximum_chunks < 1:
            raise ValueError("maximum chunks must be positive when supplied")
        cancellation = cancellation or NeverCancel()
        partial = self._destination(record.requirement, partial=True)
        final = self._destination(record.requirement, partial=False)
        if final.exists() or final.is_symlink():
            raise TransferIntegrityError("transfer destination already exists")
        if record.bytes_completed == 0:
            if partial.exists() or partial.is_symlink():
                raise TransferIntegrityError("unexpected partial transfer exists for a new plan")
        else:
            size, digest, checkpoint_identity = self._hash_path(partial)
            if size != record.bytes_completed or not secrets.compare_digest(digest, record.checkpoint_sha256):
                raise TransferIntegrityError("partial transfer does not match its durable checkpoint")
        if record.bytes_completed == 0:
            checkpoint_identity = None
        started = _rfc3339(_now(self._clock))
        offset = record.bytes_completed
        chunks = 0
        outcome = "interrupted"
        code = "chunk-budget-reached"
        detail = "transfer paused at the configured chunk budget"
        try:
            flags = os.O_WRONLY | getattr(os, "O_BINARY", 0)
            flags |= os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) if offset else os.O_CREAT | os.O_EXCL
            descriptor = os.open(partial, flags, 0o600)
            with os.fdopen(descriptor, "ab") as destination:
                opened = os.fstat(destination.fileno())
                if not stat.S_ISREG(opened.st_mode):
                    raise TransferIntegrityError("transfer destination is not a regular file")
                if checkpoint_identity is not None and (opened.st_dev, opened.st_ino) != checkpoint_identity:
                    raise TransferIntegrityError("partial transfer changed identity before resume")
                while offset < record.requirement.expected_size_bytes:
                    if cancellation.cancelled():
                        code = "cancelled"
                        detail = "transfer cancelled at a durable checkpoint"
                        break
                    if maximum_chunks is not None and chunks >= maximum_chunks:
                        break
                    request = min(chunk_size, record.requirement.expected_size_bytes - offset)
                    block = source.read(record.requirement.locator, offset, request)
                    if not isinstance(block, bytes) or not block or len(block) > request:
                        raise TransferIntegrityError("transfer source returned an invalid or premature chunk")
                    destination.write(block)
                    destination.flush()
                    os.fsync(destination.fileno())
                    offset += len(block)
                    chunks += 1
                if offset == record.requirement.expected_size_bytes:
                    outcome = "completed"
                    code = "verified"
                    detail = "transfer reached expected size and digest"
        except Exception as error:
            outcome = "interrupted"
            code = "source-or-write-failed"
            detail = f"transfer source or local write raised {type(error).__name__}"
        if offset == 0 and not partial.exists() and not partial.is_symlink():
            size, checkpoint, publication_identity = 0, self.EMPTY_SHA256, None
        else:
            size, checkpoint, publication_identity = self._hash_path(partial)
        if size != offset:
            raise TransferIntegrityError("physical partial size diverged from transfer checkpoint")
        if outcome == "completed":
            if not secrets.compare_digest(checkpoint, record.requirement.expected_sha256):
                outcome = "failed"
                code = "digest-mismatch"
                detail = "completed transfer bytes do not match the immutable digest"
            else:
                try:
                    os.link(partial, final, follow_symlinks=False)
                    published = final.lstat()
                    current_partial = partial.lstat()
                    if (
                        not stat.S_ISREG(published.st_mode)
                        or publication_identity is None
                        or (published.st_dev, published.st_ino) != publication_identity
                        or (current_partial.st_dev, current_partial.st_ino) != publication_identity
                    ):
                        outcome = "failed"
                        code = "publication-identity-mismatch"
                        detail = "filesystem identity changed during atomic transfer publication"
                    else:
                        try:
                            partial.unlink()
                        except OSError:
                            code = "verified-partial-retained"
                            detail = "transfer published exactly; verified partial cleanup is still required"
                except FileExistsError:
                    outcome = "failed"
                    code = "publication-destination-race"
                    detail = "transfer destination appeared before atomic publication"
                except OSError as error:
                    outcome = "failed"
                    code = "publication-failed"
                    detail = f"atomic transfer publication failed with errno {error.errno}"
        attempt = TransferAttempt(
            len(record.attempts) + 1,
            started,
            _rfc3339(_now(self._clock)),
            record.bytes_completed,
            offset,
            outcome,
            code,
            detail,
        )
        return TransferRecord(
            record.requirement,
            outcome,
            offset,
            checkpoint,
            (*record.attempts, attempt),
            record.requirement.expected_sha256 if outcome == "completed" else None,
            record.requirement.expected_size_bytes if outcome == "completed" else None,
            record.resumable,
        )
