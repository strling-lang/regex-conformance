"""Deterministic P19 cache and disk-pressure qualification scenarios."""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

import rfc8785

from .cache_manager import CacheManager, DeletionResult
from .cache_models import CacheEntry, CacheReality, EvictionPolicy
from .models import (
    Capability,
    DoctorReport,
    MachineIdentity,
    ProviderCapability,
    ResourcePool,
    SafetyConfigurationView,
    TrustObservation,
)
from .resource_models import (
    ActiveResourceUsage,
    AdmissionContext,
    AdmissionPolicy,
    ConfidenceMargin,
    PoolSafetyReserve,
    ResourceEstimate,
)
from .resource_planner import ResourcePlanner


OBSERVED_AT = "2026-08-14T22:00:00Z"
VALID_UNTIL = "2026-08-14T22:05:00Z"
NOW = "2026-08-14T22:00:30+00:00"
EVIDENCE_SENTINEL = b"immutable committed evidence sentinel"


class _FixedClock:
    def now(self) -> datetime:
        return datetime.fromisoformat(NOW)


class _FixedOperationIds:
    def __init__(self) -> None:
        self._cleanup_sequence = 1

    def new_cleanup_id(self) -> str:
        value = (
            "opid:v1:cache-cleanup:u7:"
            f"019fff29-c7c4-7422-a341-9ae9af10{self._cleanup_sequence:04x}"
        )
        self._cleanup_sequence += 1
        return value

    def new_transfer_id(self) -> str:
        raise AssertionError("the disk-pressure qualification does not create transfers")


class _FixedReservationIds:
    def __init__(self) -> None:
        self._sequence = 1

    def new_resource_reservation_id(self) -> str:
        value = (
            "opid:v1:resource-reservation:u7:"
            f"019fff29-c7c4-7422-a341-9ae9af11{self._sequence:04x}"
        )
        self._sequence += 1
        return value


class _CancelAfter:
    def __init__(self, allowed_candidates: int) -> None:
        self._allowed_candidates = allowed_candidates
        self._calls = 0

    def cancelled(self) -> bool:
        self._calls += 1
        return self._calls > self._allowed_candidates


class _SimulatedCacheProvider:
    """Deterministic provider reality with an out-of-cache evidence sentinel."""

    def __init__(
        self,
        entries: tuple[CacheEntry, ...],
        *,
        failures: set[str] | None = None,
        overrides: dict[str, CacheReality] | None = None,
    ) -> None:
        self.entries = {entry.cache_key: entry for entry in entries}
        self.failures = failures or set()
        self.overrides = overrides or {}
        self.deleted: list[str] = []
        self.evidence_sentinel = EVIDENCE_SENTINEL

    def inspect(self, entry: CacheEntry) -> CacheReality:
        if entry.cache_key in self.overrides:
            return self.overrides[entry.cache_key]
        current = self.entries.get(entry.cache_key)
        if current is None:
            return CacheReality(
                entry.cache_key,
                "missing",
                None,
                None,
                None,
                None,
                OBSERVED_AT,
                entry.provider_name,
                "fixture entry is absent",
            )
        return CacheReality(
            current.cache_key,
            "verified",
            current.sha256,
            current.size_bytes,
            current.reclaimable_bytes,
            current.accounting_basis,
            OBSERVED_AT,
            current.provider_name,
        )

    def delete_verified(self, entry: CacheEntry, cleanup_id: str) -> DeletionResult:
        del cleanup_id
        if entry.cache_key in self.failures:
            return DeletionResult(False, 0, "seeded-delete-failure", "fixture refused deletion")
        if entry.cache_key not in self.entries:
            return DeletionResult(False, 0, "fixture-missing", "fixture entry is already absent")
        del self.entries[entry.cache_key]
        self.deleted.append(entry.cache_key)
        return DeletionResult(
            True,
            entry.reclaimable_bytes,
            "deleted",
            "fixture reconciled the exact reclaimable bytes",
        )


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _cache_entry(cache_key: str, **changes: Any) -> CacheEntry:
    digest = _digest(cache_key.encode("utf-8"))
    values: dict[str, Any] = {
        "cache_key": cache_key,
        "kind": "environment",
        "content_id": f"rcid:v1:artifact-revision:h:jcs-sha256-v1:{digest}",
        "sha256": digest,
        "relative_path": f"objects/{cache_key}.bin",
        "size_bytes": 4096,
        "reclaimable_bytes": 4096,
        "accounting_basis": "logical",
        "provider_name": "fixture-cache",
        "retention_class": "reacquirable",
        "pinned": False,
        "active_leases": (),
        "future_dependencies": (),
        "dependencies": (),
        "last_used_at": "2026-08-14T20:00:00Z",
        "reacquisition_time_seconds": 10,
        "reacquisition_cost_microunits": 0,
        "reconstruction_difficulty": 1,
        "upstream_fragility": 1,
        "verification_status": "verified",
        "verified_at": OBSERVED_AT,
        "observed_at": OBSERVED_AT,
        "source": "p19-t03-deterministic-fixture",
        "staleness_seconds": 0,
    }
    values.update(changes)
    return CacheEntry(**values)


def _eviction_policy() -> EvictionPolicy:
    return EvictionPolicy(
        bytes_weight=100,
        age_weight=10,
        reacquisition_time_penalty=5,
        reacquisition_cost_penalty=3,
        reconstruction_penalty=20,
        fragility_penalty=30,
        expensive_reconstruction_penalty=10_000,
        maximum_inventory_age_seconds=300,
    )


def _cache_manager() -> CacheManager:
    return CacheManager(clock=_FixedClock(), id_generator=_FixedOperationIds())


def _admission_policy() -> AdmissionPolicy:
    return AdmissionPolicy(
        confidence_margins=(
            ConfidenceMargin("known", 0),
            ConfidenceMargin("measured", 1_000),
            ConfidenceMargin("estimated", 5_000),
            ConfidenceMargin("bounded", 2_500),
        ),
        pool_reserves=(
            PoolSafetyReserve("environment_cache", 100, 0),
            PoolSafetyReserve("build_scratch", 50, 0),
            PoolSafetyReserve("execution_scratch", 100, 0),
            PoolSafetyReserve("result_spool", 100, 0),
            PoolSafetyReserve("ram", 500, 0),
        ),
        max_concurrency=4,
        inventory_max_age_seconds=60,
    )


def _resource_planner() -> ResourcePlanner:
    return ResourcePlanner(
        _admission_policy(),
        clock=_FixedClock(),
        id_generator=_FixedReservationIds(),
    )


def _machine_inventory(
    *,
    disk_available: int = 5_000,
    disk_capacity: int = 10_000,
    ram_available: int | None = 6_000,
) -> DoctorReport:
    disk_kinds = (
        "persistent_disk",
        "environment_cache",
        "build_scratch",
        "execution_scratch",
        "result_spool",
    )
    resources: list[ResourcePool] = [
        ResourcePool(
            kind=kind,
            unit="bytes",
            status="observed",
            capacity=disk_capacity,
            used=disk_capacity - disk_available,
            reserved=0,
            available=disk_available,
            source="p19-t03-fixture-disk",
            accuracy="exact",
            visibility="process",
            observed_at=OBSERVED_AT,
            staleness_seconds=0,
            configured_path=f"/fixture/{kind}",
            observed_path=f"/fixture/{kind}",
            backing_store="device:p19-t03-shared-disk",
        )
        for kind in disk_kinds
    ]
    if ram_available is None:
        resources.append(
            ResourcePool(
                kind="ram",
                unit="bytes",
                status="unknown",
                capacity=None,
                used=None,
                reserved=0,
                available=None,
                source="p19-t03-fixture-memory",
                accuracy="unknown",
                visibility="process",
                observed_at=OBSERVED_AT,
                staleness_seconds=0,
                diagnostic="seeded unknown RAM capacity",
            )
        )
    else:
        resources.append(
            ResourcePool(
                kind="ram",
                unit="bytes",
                status="observed",
                capacity=8_000,
                used=8_000 - ram_available,
                reserved=0,
                available=ram_available,
                source="p19-t03-fixture-memory",
                accuracy="exact",
                visibility="process",
                observed_at=OBSERVED_AT,
                staleness_seconds=0,
            )
        )
    resources.extend(
        (
            ResourcePool(
                kind="swap",
                unit="bytes",
                status="unknown",
                capacity=None,
                used=None,
                reserved=0,
                available=None,
                source="p19-t03-fixture-memory",
                accuracy="unknown",
                visibility="process",
                observed_at=OBSERVED_AT,
                staleness_seconds=0,
                diagnostic="swap is outside this fixture plan",
            ),
            ResourcePool(
                kind="cpu",
                unit="logical_cpu",
                status="partial",
                capacity=8,
                used=None,
                reserved=0,
                available=None,
                source="p19-t03-fixture-affinity",
                accuracy="bounded",
                visibility="process",
                observed_at=OBSERVED_AT,
                staleness_seconds=0,
                diagnostic="CPU is outside this fixture plan",
            ),
        )
    )
    return DoctorReport(
        status="healthy",
        observed_at=OBSERVED_AT,
        valid_until=VALID_UNTIL,
        machine=MachineIdentity(
            "linux", "P19 deterministic fixture", "1", "x86_64", "x86_64", "CPython", "3.12"
        ),
        trust=TrustObservation("development", "p19-t03-fixture", True),
        resources=tuple(resources),
        providers=(
            ProviderCapability(
                "native-runtime",
                "available",
                ("native-host",),
                "p19-t03-fixture-provider",
                OBSERVED_AT,
            ),
        ),
        capabilities=(
            Capability(
                "process-tree-termination",
                "supported",
                "p19-t03-fixture-capability",
                OBSERVED_AT,
                True,
            ),
        ),
        safety_configuration=SafetyConfigurationView(
            True,
            False,
            300,
            {kind: f"/fixture/{kind}" for kind in disk_kinds},
        ),
        diagnostics=(),
    )


def _case(
    case_key: str,
    requirement: str,
    checks: tuple[tuple[str, bool, str], ...],
    metrics: tuple[tuple[str, int | str, str], ...] = (),
) -> dict[str, Any]:
    failed = [name for name, passed, _ in checks if not passed]
    if failed:
        raise AssertionError(f"P19-T03 case {case_key!r} failed: {', '.join(failed)}")
    return {
        "case_key": case_key,
        "checks": [
            {"check_key": name, "detail": detail, "passed": passed}
            for name, passed, detail in checks
        ],
        "metrics": [
            {"metric_key": name, "unit": unit, "value": value}
            for name, value, unit in metrics
        ],
        "mode": "deterministic-simulation",
        "requirement": requirement,
        "status": "passed",
    }


def _weighted_and_protected_case() -> dict[str, Any]:
    entries = (
        _cache_entry("modern-large", size_bytes=6000, reclaimable_bytes=6000),
        _cache_entry(
            "old-expensive",
            size_bytes=6000,
            reclaimable_bytes=6000,
            retention_class="expensive-reconstruction",
            last_used_at="2026-07-01T00:00:00Z",
            reacquisition_time_seconds=10_000,
            reacquisition_cost_microunits=500_000,
            reconstruction_difficulty=90,
            upstream_fragility=90,
        ),
        _cache_entry("pinned", pinned=True),
        _cache_entry("leased", active_leases=("lease-one",)),
        _cache_entry("future-required", future_dependencies=("campaign-next",)),
        _cache_entry("protected-spool", kind="protected-spool", retention_class="protected-spool"),
        _cache_entry("rare-fragile", retention_class="rare-fragile"),
        _cache_entry("dependency"),
        _cache_entry("dependent", dependencies=("dependency",), pinned=True),
    )
    service = _cache_manager()
    inventory = service.inventory(entries, observed_at=OBSERVED_AT)
    provider = _SimulatedCacheProvider(entries)
    plan = service.plan_cleanup(
        inventory,
        service.reconcile(inventory, provider),
        6000,
        _eviction_policy(),
    )
    exclusions = {item.cache_key: set(item.reasons) for item in plan.exclusions}
    reverse_service = _cache_manager()
    reverse_inventory = reverse_service.inventory(tuple(reversed(entries)), observed_at=OBSERVED_AT)
    reverse_plan = reverse_service.plan_cleanup(
        reverse_inventory,
        reverse_service.reconcile(
            reverse_inventory,
            _SimulatedCacheProvider(tuple(reversed(entries))),
        ),
        6000,
        _eviction_policy(),
    )
    protected = {
        "pinned": "pinned",
        "leased": "active-lease",
        "future-required": "future-dependency",
        "protected-spool": "protected-spool",
        "rare-fragile": "rare-fragile",
        "dependency": "dependency-protected",
    }
    return _case(
        "weighted-project-aware-selection",
        "Weighted eviction is deterministic and protects pinned, leased, dependency-required, spool, and fragile assets.",
        (
            (
                "weighted-not-raw-lru",
                [item.cache_key for item in plan.selected] == ["modern-large"],
                "the cheap modern asset is selected ahead of the older expensive asset",
            ),
            (
                "hard-protections",
                all(reason in exclusions.get(key, set()) for key, reason in protected.items()),
                "every hard-protected class has its exact exclusion reason",
            ),
            (
                "permutation-stable",
                inventory.inventory_digest == reverse_inventory.inventory_digest
                and plan.to_dict() == reverse_plan.to_dict(),
                "input order does not change the inventory digest or cleanup plan",
            ),
            (
                "planning-non-mutating",
                not plan.mutation_permitted and not provider.deleted,
                "planning selects candidates without deleting anything",
            ),
        ),
        (
            ("selected-reclaim-bytes", plan.expected_reclaim_bytes, "bytes"),
            ("protected-entry-count", len(protected), "entries"),
        ),
    )


def _safe_refusal_case() -> dict[str, Any]:
    entries = (
        _cache_entry("only-pinned", pinned=True),
        _cache_entry("only-spool", kind="protected-spool", retention_class="protected-spool"),
    )
    service = _cache_manager()
    inventory = service.inventory(entries, observed_at=OBSERVED_AT)
    provider = _SimulatedCacheProvider(entries)
    plan = service.plan_cleanup(
        inventory,
        service.reconcile(inventory, provider),
        1,
        _eviction_policy(),
    )
    report = service.execute_cleanup(plan, inventory, provider)
    return _case(
        "safe-refusal-when-margin-cannot-be-restored",
        "Acquisition remains refused when governed reclamation cannot restore the required margin.",
        (
            ("plan-refused", plan.outcome == "refused", "protected entries cannot satisfy the target"),
            ("execution-refused", report.state == "refused", "a refused plan remains non-mutating"),
            ("nothing-deleted", not provider.deleted, "no protected entry is deleted"),
            ("no-credit-for-unreclaimed-space", report.actual_reclaim_bytes == 0, "zero bytes are credited"),
        ),
        (
            ("cleanup-report-count", 1, "count"),
            ("refused-cleanup-count", 1, "count"),
            ("protected-exclusion-count", 2, "entries"),
            ("executed-plan-expected-reclaim", report.plan.expected_reclaim_bytes, "bytes"),
            ("executed-plan-actual-reclaim", report.actual_reclaim_bytes, "bytes"),
        ),
    )


def _provider_divergence_case() -> dict[str, Any]:
    candidate = _cache_entry("provider-diverged")
    mismatch = CacheReality(
        candidate.cache_key,
        "mismatch",
        "f" * 64,
        candidate.size_bytes,
        candidate.reclaimable_bytes,
        candidate.accounting_basis,
        OBSERVED_AT,
        candidate.provider_name,
        "seeded provider reality divergence",
    )
    service = _cache_manager()
    inventory = service.inventory((candidate,), observed_at=OBSERVED_AT)
    provider = _SimulatedCacheProvider((candidate,), overrides={candidate.cache_key: mismatch})
    plan = service.plan_cleanup(
        inventory,
        service.reconcile(inventory, provider),
        candidate.reclaimable_bytes,
        _eviction_policy(),
    )
    reasons = {reason for exclusion in plan.exclusions for reason in exclusion.reasons}
    return _case(
        "provider-reality-divergence",
        "Provider reality that differs from cached inventory fails closed before deletion.",
        (
            ("plan-refused", plan.outcome == "refused", "no verified candidate can meet the target"),
            (
                "divergence-explicit",
                "reconciliation-mismatch" in reasons,
                "the mismatch is retained as a typed exclusion",
            ),
            ("nothing-deleted", not provider.deleted, "provider divergence prevents mutation"),
        ),
        (("provider-divergence-exclusion-count", 1, "count"),),
    )


def _partial_cleanup_recovery_case() -> dict[str, Any]:
    first = _cache_entry("partial-first")
    second = _cache_entry("partial-second")
    entries = (first, second)
    service = _cache_manager()
    inventory = service.inventory(entries, observed_at=OBSERVED_AT)
    provider = _SimulatedCacheProvider(entries, failures={second.cache_key})
    plan = service.plan_cleanup(
        inventory,
        service.reconcile(inventory, provider),
        8192,
        _eviction_policy(),
    )
    report = service.execute_cleanup(plan, inventory, provider)

    remaining = (second,)
    recovery_service = _cache_manager()
    recovery_inventory = recovery_service.inventory(remaining, observed_at=OBSERVED_AT)
    recovery_provider = _SimulatedCacheProvider(remaining)
    recovery_plan = recovery_service.plan_cleanup(
        recovery_inventory,
        recovery_service.reconcile(recovery_inventory, recovery_provider),
        4096,
        _eviction_policy(),
    )
    recovery_report = recovery_service.execute_cleanup(
        recovery_plan,
        recovery_inventory,
        recovery_provider,
    )
    return _case(
        "partial-cleanup-reconciliation-and-recovery",
        "Partial cleanup preserves exact accounting and can resume from a fresh inventory without duplicate deletion.",
        (
            ("partial-explicit", report.state == "partial", "one seeded provider failure remains explicit"),
            (
                "partial-accounting",
                report.actual_reclaim_bytes == 4096 and report.plan.expected_reclaim_bytes == 8192,
                "expected and actual reclaimed bytes are not conflated",
            ),
            (
                "input-inventory-immutable",
                inventory.inventory_digest
                == service.inventory(tuple(reversed(entries)), observed_at=OBSERVED_AT).inventory_digest,
                "partial mutation does not rewrite the original inventory record",
            ),
            (
                "fresh-recovery-completes",
                recovery_report.state == "completed" and recovery_report.actual_reclaim_bytes == 4096,
                "fresh provider reconciliation safely completes the remaining work",
            ),
            (
                "no-duplicate-deletion",
                provider.deleted == [first.cache_key] and recovery_provider.deleted == [second.cache_key],
                "each cache entry is deleted at most once",
            ),
        ),
        (
            ("initial-expected-reclaim", report.plan.expected_reclaim_bytes, "bytes"),
            ("initial-actual-reclaim", report.actual_reclaim_bytes, "bytes"),
            ("recovery-actual-reclaim", recovery_report.actual_reclaim_bytes, "bytes"),
            ("cleanup-report-count", 2, "count"),
            ("completed-cleanup-count", 1, "count"),
            ("partial-cleanup-count", 1, "count"),
            ("successful-deletion-count", 2, "count"),
            ("failed-deletion-count", 1, "count"),
            (
                "executed-plan-expected-reclaim",
                report.plan.expected_reclaim_bytes + recovery_report.plan.expected_reclaim_bytes,
                "bytes",
            ),
            (
                "executed-plan-actual-reclaim",
                report.actual_reclaim_bytes + recovery_report.actual_reclaim_bytes,
                "bytes",
            ),
        ),
    )


def _interrupted_cleanup_recovery_case() -> dict[str, Any]:
    first = _cache_entry("interrupt-first")
    second = _cache_entry("interrupt-second")
    entries = (first, second)
    service = _cache_manager()
    inventory = service.inventory(entries, observed_at=OBSERVED_AT)
    provider = _SimulatedCacheProvider(entries)
    plan = service.plan_cleanup(
        inventory,
        service.reconcile(inventory, provider),
        8192,
        _eviction_policy(),
    )
    interrupted = service.execute_cleanup(plan, inventory, provider, _CancelAfter(1))

    remaining = (second,)
    recovery_service = _cache_manager()
    recovery_inventory = recovery_service.inventory(remaining, observed_at=OBSERVED_AT)
    recovery_provider = _SimulatedCacheProvider(remaining)
    recovery_plan = recovery_service.plan_cleanup(
        recovery_inventory,
        recovery_service.reconcile(recovery_inventory, recovery_provider),
        4096,
        _eviction_policy(),
    )
    recovered = recovery_service.execute_cleanup(
        recovery_plan,
        recovery_inventory,
        recovery_provider,
    )
    return _case(
        "interrupted-cleanup-reconciliation-and-recovery",
        "Interrupted cleanup records its boundary and resumes safely from fresh provider reality.",
        (
            (
                "interruption-explicit",
                interrupted.state == "cancelled"
                and interrupted.mutations[-1].code == "cancelled",
                "the unattempted candidate is retained as a cancelled skip",
            ),
            (
                "interruption-accounted",
                interrupted.actual_reclaim_bytes == 4096,
                "only the completed deletion receives reclaimed-byte credit",
            ),
            (
                "resume-completes",
                recovered.state == "completed" and recovered.actual_reclaim_bytes == 4096,
                "the remaining candidate completes after fresh reconciliation",
            ),
            (
                "no-duplicate-deletion",
                provider.deleted == [first.cache_key] and recovery_provider.deleted == [second.cache_key],
                "resume does not repeat the completed deletion",
            ),
        ),
        (
            ("cleanup-report-count", 2, "count"),
            ("completed-cleanup-count", 1, "count"),
            ("cancelled-cleanup-count", 1, "count"),
            ("successful-deletion-count", 2, "count"),
            ("cancelled-candidate-count", 1, "count"),
            (
                "executed-plan-expected-reclaim",
                interrupted.plan.expected_reclaim_bytes + recovered.plan.expected_reclaim_bytes,
                "bytes",
            ),
            (
                "executed-plan-actual-reclaim",
                interrupted.actual_reclaim_bytes + recovered.actual_reclaim_bytes,
                "bytes",
            ),
        ),
    )


def _reclaimable_accounting_case() -> dict[str, Any]:
    entry = _cache_entry(
        "allocated-accounting",
        size_bytes=10_000,
        reclaimable_bytes=4096,
        accounting_basis="allocated",
    )
    service = _cache_manager()
    inventory = service.inventory((entry,), observed_at=OBSERVED_AT)
    provider = _SimulatedCacheProvider((entry,))
    plan = service.plan_cleanup(
        inventory,
        service.reconcile(inventory, provider),
        4096,
        _eviction_policy(),
    )
    report = service.execute_cleanup(plan, inventory, provider)
    return _case(
        "logical-versus-reclaimable-accounting",
        "Cleanup decisions and credit use provider-reconciled reclaimable bytes rather than logical size.",
        (
            (
                "reclaimable-basis-used",
                plan.expected_reclaim_bytes == 4096 and report.actual_reclaim_bytes == 4096,
                "the allocated reclaimable size drives planning and credit",
            ),
            (
                "logical-size-not-overcredited",
                report.actual_reclaim_bytes != entry.size_bytes,
                "the 10,000-byte logical size is not claimed as reclaimed space",
            ),
        ),
        (
            ("logical-size", entry.size_bytes, "bytes"),
            ("reclaimable-size", entry.reclaimable_bytes, "bytes"),
            ("cleanup-report-count", 1, "count"),
            ("completed-cleanup-count", 1, "count"),
            ("successful-deletion-count", 1, "count"),
            ("executed-plan-expected-reclaim", report.plan.expected_reclaim_bytes, "bytes"),
            ("executed-plan-actual-reclaim", report.actual_reclaim_bytes, "bytes"),
        ),
    )


def _disk_pressure_admission_case() -> dict[str, Any]:
    planner = _resource_planner()
    plan = planner.workload_plan(
        operation_kind="campaign",
        operation_id=(
            "rcid:v1:campaign-manifest:h:jcs-sha256-v1:"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        estimates=(
            ResourceEstimate("environment-acquisition", "environment_cache", "bytes", 1000, 1000, "known", "fixture"),
            ResourceEstimate("execution-working-set", "execution_scratch", "bytes", 500, 500, "known", "fixture"),
            ResourceEstimate("protected-spool-growth", "result_spool", "bytes", 500, 500, "known", "fixture"),
        ),
        required_capabilities=("process-tree-termination",),
        requested_concurrency=2,
    )
    preflight = planner.preflight(plan, _machine_inventory(disk_available=5000))
    pressure = planner.dynamic_admit(plan, _machine_inventory(disk_available=1800))
    recovery = planner.dynamic_admit(plan, _machine_inventory(disk_available=5000))
    pressure_store = pressure.backing_store_evaluations[0]
    recovery_store = recovery.backing_store_evaluations[0]
    return _case(
        "pressure-between-preflight-and-dynamic-admission",
        "New disk pressure after preflight causes backpressure, preserves the shared-store floor, and admits only after relief.",
        (
            ("preflight-admitted", preflight.outcome == "admitted", "initial capacity satisfies the plan"),
            (
                "pressure-backpressures",
                pressure.outcome == "backpressure" and pressure_store.status == "fail",
                "shared cache, scratch, and spool demand is not double-counted",
            ),
            (
                "no-unsafe-reservation",
                not pressure.mutation_permitted and pressure_store.post_admission_available == 0,
                "failed admission creates no reservation or negative free-space claim",
            ),
            (
                "recovery-admitted",
                recovery.outcome == "admitted"
                and recovery_store.post_admission_available >= 0
                and recovery_store.post_admission_available
                == recovery_store.observed_available
                - recovery_store.required
                - recovery_store.safety_reserve,
                "work resumes only after the protected margin is restored",
            ),
        ),
        (
            ("pressure-available", pressure_store.observed_available, "bytes"),
            ("aggregate-required", pressure_store.required, "bytes"),
            ("safety-reserve", pressure_store.safety_reserve, "bytes"),
            ("recovery-post-admission", recovery_store.post_admission_available, "bytes"),
        ),
    )


def _forecast_confidence_case() -> dict[str, Any]:
    planner = _resource_planner()
    estimated_plan = planner.workload_plan(
        operation_kind="environment",
        operation_id="opid:v1:environment:u7:019fff29-c7c4-7422-a341-9ae9af120001",
        estimates=(
            ResourceEstimate(
                "low-confidence-cache-growth",
                "environment_cache",
                "bytes",
                1000,
                1200,
                "estimated",
                "bounded-sample",
            ),
        ),
    )
    estimated = planner.dynamic_admit(
        estimated_plan,
        _machine_inventory(disk_available=2000),
    )
    evaluation = estimated.resource_evaluations[0]

    ram_plan = planner.workload_plan(
        operation_kind="shard",
        operation_id=(
            "rcid:v1:shard:h:jcs-sha256-v1:"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ),
        estimates=(
            ResourceEstimate("worker-ram", "ram", "bytes", 500, 500, "known", "fixture"),
        ),
    )
    unknown = planner.dynamic_admit(ram_plan, _machine_inventory(ram_available=None))
    refreshed = planner.dynamic_admit(ram_plan, _machine_inventory(ram_available=6000))
    return _case(
        "forecast-confidence-and-unknown-capacity",
        "Low-confidence forecasts receive conservative margin; unknown capacity drains until fresh telemetry is available.",
        (
            (
                "confidence-margin-applied",
                evaluation.upper_bound == 1200
                and evaluation.margin == 600
                and evaluation.required == 1800,
                "the 50% estimated-confidence margin is applied to the upper bound",
            ),
            (
                "protected-floor-retained",
                estimated.outcome == "admitted" and evaluation.post_admission_available == 100,
                "admission retains the configured cache floor",
            ),
            (
                "unknown-drains",
                unknown.outcome == "drain"
                and any(item.code == "resource-capacity-unknown" for item in unknown.issues),
                "unknown RAM is never treated as zero demand or available capacity",
            ),
            (
                "fresh-telemetry-recovers",
                refreshed.outcome == "admitted",
                "the same work becomes admissible after an exact fresh inventory",
            ),
        ),
    )


def _competing_active_usage_case() -> dict[str, Any]:
    planner = _resource_planner()
    plan = planner.workload_plan(
        operation_kind="shard",
        operation_id=(
            "rcid:v1:shard:h:jcs-sha256-v1:"
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        ),
        estimates=(
            ResourceEstimate("new-shard-scratch", "execution_scratch", "bytes", 1000, 1000, "known", "fixture"),
        ),
    )
    competing = planner.dynamic_admit(
        plan,
        _machine_inventory(disk_available=2000),
        AdmissionContext(
            active_concurrency=1,
            active_usage=(ActiveResourceUsage("execution_scratch", "bytes", 901),),
        ),
    )
    relieved = planner.dynamic_admit(
        plan,
        _machine_inventory(disk_available=2000),
        AdmissionContext(),
    )
    return _case(
        "competing-active-resource-usage",
        "Active work consumes its reservation before new work is dynamically admitted.",
        (
            (
                "active-usage-backpressures",
                competing.outcome == "backpressure",
                "the one-byte safety shortfall pauses the new shard",
            ),
            (
                "active-work-not-evicted",
                any(item.active_usage == 901 for item in competing.resource_evaluations),
                "active usage is retained in the admission accounting",
            ),
            (
                "capacity-relief-recovers",
                relieved.outcome == "admitted",
                "new work resumes when the competing reservation is released",
            ),
        ),
    )


def _evidence_protection_case() -> dict[str, Any]:
    evictable = _cache_entry("ordinary-cache")
    spool = _cache_entry(
        "result-spool",
        kind="protected-spool",
        retention_class="protected-spool",
    )
    entries = (evictable, spool)
    service = _cache_manager()
    inventory = service.inventory(entries, observed_at=OBSERVED_AT)
    provider = _SimulatedCacheProvider(entries)
    evidence_before = _digest(provider.evidence_sentinel)
    plan = service.plan_cleanup(
        inventory,
        service.reconcile(inventory, provider),
        evictable.reclaimable_bytes,
        _eviction_policy(),
    )
    report = service.execute_cleanup(plan, inventory, provider)
    evidence_after = _digest(provider.evidence_sentinel)
    excluded = {item.cache_key for item in plan.exclusions}
    return _case(
        "protected-spool-and-committed-evidence",
        "Cache eviction cannot select protected spool data or mutate committed evidence authority.",
        (
            (
                "protected-spool-excluded",
                spool.cache_key in excluded and spool.cache_key not in provider.deleted,
                "the protected spool remains outside the deletion set",
            ),
            (
                "committed-evidence-available",
                evidence_before == evidence_after,
                "the out-of-cache immutable evidence sentinel remains byte-identical",
            ),
            (
                "authority-not-mutated",
                report.state == "completed" and not report.registry_authority_mutated,
                "cleanup remains non-canonical and cannot rewrite evidence authority",
            ),
        ),
        (
            ("cleanup-report-count", 1, "count"),
            ("completed-cleanup-count", 1, "count"),
            ("successful-deletion-count", 1, "count"),
            ("protected-exclusion-count", 1, "entries"),
            ("executed-plan-expected-reclaim", report.plan.expected_reclaim_bytes, "bytes"),
            ("executed-plan-actual-reclaim", report.actual_reclaim_bytes, "bytes"),
        ),
    )


def _cache_churn(cases: list[dict[str, Any]]) -> dict[str, int]:
    totals = {
        "cancelled_candidate_count": 0,
        "cancelled_cleanup_count": 0,
        "cleanup_report_count": 0,
        "completed_cleanup_count": 0,
        "executed_plan_actual_reclaim_bytes": 0,
        "executed_plan_expected_reclaim_bytes": 0,
        "failed_deletion_count": 0,
        "partial_cleanup_count": 0,
        "protected_exclusion_count": 0,
        "provider_divergence_exclusion_count": 0,
        "refused_cleanup_count": 0,
        "successful_deletion_count": 0,
    }
    metric_to_total = {
        "cancelled-candidate-count": "cancelled_candidate_count",
        "cancelled-cleanup-count": "cancelled_cleanup_count",
        "cleanup-report-count": "cleanup_report_count",
        "completed-cleanup-count": "completed_cleanup_count",
        "executed-plan-actual-reclaim": "executed_plan_actual_reclaim_bytes",
        "executed-plan-expected-reclaim": "executed_plan_expected_reclaim_bytes",
        "failed-deletion-count": "failed_deletion_count",
        "partial-cleanup-count": "partial_cleanup_count",
        "protected-exclusion-count": "protected_exclusion_count",
        "provider-divergence-exclusion-count": "provider_divergence_exclusion_count",
        "refused-cleanup-count": "refused_cleanup_count",
        "successful-deletion-count": "successful_deletion_count",
    }
    for case in cases:
        for metric in case["metrics"]:
            total_key = metric_to_total.get(metric["metric_key"])
            if total_key is not None:
                value = metric["value"]
                if isinstance(value, bool) or not isinstance(value, int):
                    raise AssertionError(f"churn metric {metric['metric_key']!r} is not an integer")
                totals[total_key] += value
    expected = {
        "cancelled_candidate_count": 1,
        "cancelled_cleanup_count": 1,
        "cleanup_report_count": 7,
        "completed_cleanup_count": 4,
        "executed_plan_actual_reclaim_bytes": 24_576,
        "executed_plan_expected_reclaim_bytes": 32_768,
        "failed_deletion_count": 1,
        "partial_cleanup_count": 1,
        "protected_exclusion_count": 3,
        "provider_divergence_exclusion_count": 1,
        "refused_cleanup_count": 1,
        "successful_deletion_count": 6,
    }
    if totals != expected:
        raise AssertionError(f"unexpected aggregate cache churn metrics: {totals!r}")
    return totals


def _source_bindings(root: Path) -> list[dict[str, str]]:
    paths = (
        "control-plane/python/regex_conformance_control_plane/cache_manager.py",
        "control-plane/python/regex_conformance_control_plane/cache_models.py",
        "control-plane/python/regex_conformance_control_plane/disk_pressure_qualification.py",
        "control-plane/python/regex_conformance_control_plane/resource_models.py",
        "control-plane/python/regex_conformance_control_plane/resource_planner.py",
        "schemas/json/cache-disk-pressure-qualification.schema.json",
        "schemas/json/cache-operations.schema.json",
        "schemas/json/resource-admission.schema.json",
        "tools/control_plane/compile_cache_disk_pressure_qualification.py",
    )
    return [
        {"path": path, "sha256": _digest((root / path).read_bytes())}
        for path in paths
    ]


def build_cache_disk_pressure_reference_report(root: Path) -> dict[str, Any]:
    """Recompute the complete deterministic P19-T03 qualification report."""

    cases = [
        _weighted_and_protected_case(),
        _safe_refusal_case(),
        _provider_divergence_case(),
        _partial_cleanup_recovery_case(),
        _interrupted_cleanup_recovery_case(),
        _reclaimable_accounting_case(),
        _disk_pressure_admission_case(),
        _forecast_confidence_case(),
        _competing_active_usage_case(),
        _evidence_protection_case(),
    ]
    cases.sort(key=lambda item: item["case_key"])
    case_keys = {str(item["case_key"]) for item in cases}
    invariants = [
        {
            "case_keys": ["pressure-between-preflight-and-dynamic-admission"],
            "description": "Protected free-space margins are never knowingly exhausted.",
            "invariant_key": "protected-free-space-margin",
            "status": "passed",
        },
        {
            "case_keys": ["protected-spool-and-committed-evidence"],
            "description": "Committed evidence remains available and protected spool data is never evicted.",
            "invariant_key": "evidence-and-spool-protection",
            "status": "passed",
        },
        {
            "case_keys": ["weighted-project-aware-selection"],
            "description": "Active, pinned, dependency-required, expensive, and fragile assets receive governed protection.",
            "invariant_key": "project-aware-protection",
            "status": "passed",
        },
        {
            "case_keys": ["weighted-project-aware-selection"],
            "description": "Safe reclamation is deterministic and is not raw LRU.",
            "invariant_key": "deterministic-weighted-reclamation",
            "status": "passed",
        },
        {
            "case_keys": [
                "logical-versus-reclaimable-accounting",
                "partial-cleanup-reconciliation-and-recovery",
            ],
            "description": "Expected and actual reclaimed bytes remain explicit and use the provider accounting basis.",
            "invariant_key": "reclaimed-byte-reconciliation",
            "status": "passed",
        },
        {
            "case_keys": ["safe-refusal-when-margin-cannot-be-restored"],
            "description": "Work is refused without mutation when safe reclamation cannot restore the floor.",
            "invariant_key": "safe-refusal",
            "status": "passed",
        },
        {
            "case_keys": [
                "pressure-between-preflight-and-dynamic-admission",
                "forecast-confidence-and-unknown-capacity",
                "competing-active-resource-usage",
            ],
            "description": "Backpressure or drain pauses unsafe work and fresh safe capacity permits recovery.",
            "invariant_key": "pause-drain-and-recovery",
            "status": "passed",
        },
        {
            "case_keys": [
                "partial-cleanup-reconciliation-and-recovery",
                "interrupted-cleanup-reconciliation-and-recovery",
            ],
            "description": "Partial and interrupted cleanup preserve accounting and resume without duplicate mutation.",
            "invariant_key": "cleanup-restart-safety",
            "status": "passed",
        },
        {
            "case_keys": ["provider-reality-divergence"],
            "description": "Provider reality is rechecked and stale cached inventory fails closed.",
            "invariant_key": "provider-reality-reconciliation",
            "status": "passed",
        },
    ]
    if any(not set(item["case_keys"]) <= case_keys for item in invariants):
        raise AssertionError("qualification invariant references an unknown case")
    body: dict[str, Any] = {
        "cache_churn": _cache_churn(cases),
        "cases": cases,
        "classification": {
            "canonical_authority": False,
            "docker_used": False,
            "external_evidence_mutated": False,
            "normative_authority": False,
            "operational_qualification_only": True,
            "simulated_disk_pressure": True,
            "target_behavior": False,
        },
        "decisions": [
            {"decision_id": "D024", "contract": "predictive preflight and dynamic admission"},
            {"decision_id": "D026", "contract": "transactional verified environment lifecycle"},
            {"decision_id": "D030", "contract": "project-aware weighted cache eviction"},
            {"decision_id": "D081", "contract": "one authoritative durable home per artifact class"},
            {"decision_id": "D085", "contract": "fresh typed inventories and independent reservations"},
            {"decision_id": "D089", "contract": "dynamic re-admission and atomic resource safety"},
        ],
        "invariants": sorted(invariants, key=lambda item: item["invariant_key"]),
        "schema_version": "cache-disk-pressure-qualification.v1",
        "source_bindings": _source_bindings(root),
        "summary": {
            "case_count": len(cases),
            "failed_case_count": 0,
            "invariant_count": len(invariants),
            "passed_case_count": len(cases),
            "qualification_outcome": "passed",
        },
    }
    body["qualification_digest_sha256"] = _digest(rfc8785.dumps(body))
    return body
