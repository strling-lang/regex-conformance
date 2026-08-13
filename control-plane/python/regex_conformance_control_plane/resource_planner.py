"""Conservative preflight and dynamic admission for typed machine resources."""

from __future__ import annotations

import secrets
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Protocol

from .environment_models import AdmissionDecision, EnvironmentLifecycleRecord
from .models import DoctorReport, ResourcePool
from .resource_models import (
    SAFE_INTEGER_MAX,
    ActiveResourceUsage,
    AdmissionContext,
    AdmissionIssue,
    AdmissionPolicy,
    BackingStoreEvaluation,
    ResourceAdmissionReport,
    ResourceEstimate,
    ResourceEvaluation,
    TransferForecast,
    WorkloadResourcePlan,
)


class Clock(Protocol):
    def now(self) -> datetime: ...


class ReservationIdGenerator(Protocol):
    def new_resource_reservation_id(self) -> str: ...


class UtcClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class Uuid7ReservationIdGenerator:
    def new_resource_reservation_id(self) -> str:
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
        return f"opid:v1:resource-reservation:u7:{uuid.UUID(int=integer)}"


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _rfc3339(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("clock values must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _ceil_basis_points(amount: int, basis_points: int) -> int:
    result = (amount * basis_points + 9_999) // 10_000
    if result > SAFE_INTEGER_MAX:
        raise OverflowError("basis-point calculation exceeds the safe-integer domain")
    return result


def _safe_sum(values: list[int]) -> int:
    result = sum(values)
    if result > SAFE_INTEGER_MAX:
        raise OverflowError("resource aggregation exceeds the safe-integer domain")
    return result


def _observation_problem(
    now: datetime,
    observed_at: str,
    reported_staleness_seconds: int,
    maximum_age_seconds: int,
) -> str | None:
    actual_age = (now - _parse_timestamp(observed_at)).total_seconds()
    if actual_age < 0:
        return "future"
    if actual_age > maximum_age_seconds or reported_staleness_seconds > maximum_age_seconds:
        return "stale"
    return None


class ResourcePlanner:
    """Produce non-mutating plans and fail-closed admission reports."""

    def __init__(
        self,
        policy: AdmissionPolicy,
        *,
        clock: Clock | None = None,
        id_generator: ReservationIdGenerator | None = None,
    ) -> None:
        self._policy = policy
        self._clock = clock or UtcClock()
        self._ids = id_generator or Uuid7ReservationIdGenerator()

    def workload_plan(
        self,
        *,
        operation_kind: str,
        operation_id: str,
        estimates: tuple[ResourceEstimate, ...],
        transfers: tuple[TransferForecast, ...] = (),
        provider_name: str | None = None,
        provider_strategy: str | None = None,
        required_capabilities: tuple[str, ...] = (),
        eligible_trust_classes: tuple[str, ...] = ("development", "trusted_executioner"),
        requested_concurrency: int = 1,
    ) -> WorkloadResourcePlan:
        return WorkloadResourcePlan(
            operation_kind=operation_kind,
            operation_id=operation_id,
            estimates=estimates,
            transfers=transfers,
            provider_name=provider_name,
            provider_strategy=provider_strategy,
            required_capabilities=required_capabilities,
            eligible_trust_classes=eligible_trust_classes,
            requested_concurrency=requested_concurrency,
        )

    def environment_plan(
        self,
        record: EnvironmentLifecycleRecord,
        *,
        machine_provider_name: str,
        estimate_confidence: str = "estimated",
        supplemental_estimates: tuple[ResourceEstimate, ...] = (),
        required_capabilities: tuple[str, ...] = (),
        eligible_trust_classes: tuple[str, ...] = ("development", "trusted_executioner"),
    ) -> WorkloadResourcePlan:
        if record.state != "planned" or record.plan is None:
            raise ValueError("environment resource planning requires a planned provider transaction")
        provider_plan = record.plan
        estimates = (
            ResourceEstimate(
                "environment-download-cache",
                "environment_cache",
                "bytes",
                provider_plan.expected_download_bytes,
                provider_plan.expected_download_bytes,
                estimate_confidence,
                "provider-plan",
            ),
            ResourceEstimate(
                "environment-expanded-cache",
                "environment_cache",
                "bytes",
                provider_plan.expected_expanded_bytes,
                provider_plan.expected_expanded_bytes,
                estimate_confidence,
                "provider-plan",
            ),
            ResourceEstimate(
                "environment-build-scratch",
                "build_scratch",
                "bytes",
                provider_plan.expected_scratch_bytes,
                provider_plan.expected_scratch_bytes,
                estimate_confidence,
                "provider-plan",
            ),
            *supplemental_estimates,
        )
        transfers = (
            TransferForecast(
                "environment-acquisition",
                "download",
                provider_plan.expected_download_bytes,
                provider_plan.expected_download_bytes,
                estimate_confidence,
                "provider-plan",
            ),
        )
        return self.workload_plan(
            operation_kind="environment",
            operation_id=record.transaction_id,
            estimates=estimates,
            transfers=transfers,
            provider_name=machine_provider_name,
            provider_strategy=record.recipe.strategy,
            required_capabilities=required_capabilities,
            eligible_trust_classes=eligible_trust_classes,
        )

    def preflight(
        self,
        plan: WorkloadResourcePlan,
        inventory: DoctorReport,
        context: AdmissionContext | None = None,
    ) -> ResourceAdmissionReport:
        return self._evaluate(plan, inventory, context or AdmissionContext(), "preflight")

    def dynamic_admit(
        self,
        plan: WorkloadResourcePlan,
        inventory: DoctorReport,
        context: AdmissionContext | None = None,
    ) -> ResourceAdmissionReport:
        return self._evaluate(plan, inventory, context or AdmissionContext(), "dynamic")

    def environment_decision(
        self,
        record: EnvironmentLifecycleRecord,
        report: ResourceAdmissionReport,
    ) -> AdmissionDecision:
        if record.state != "planned":
            raise ValueError("resource admission can only bind a planned environment")
        if report.stage != "preflight" or report.plan.operation_kind != "environment":
            raise ValueError("environment admission requires an environment preflight report")
        if report.policy != self._policy:
            raise ValueError("environment admission requires this planner's exact admission policy")
        if report.plan.operation_id != record.transaction_id:
            raise ValueError("resource preflight belongs to a different environment transaction")
        admitted = report.outcome == "admitted"
        if report.outcome not in {"admitted", "rejected"}:
            raise ValueError("environment preflight outcome cannot be applied as an admission decision")
        if admitted:
            reason = "resource preflight admitted all typed pools, shared stores, capabilities, and concurrency"
        else:
            reason = "; ".join(f"{item.code}: {item.message}" for item in report.issues)
        return AdmissionDecision(admitted, report.reservation_id, reason)

    def _evaluate(
        self,
        plan: WorkloadResourcePlan,
        inventory: DoctorReport,
        context: AdmissionContext,
        stage: str,
    ) -> ResourceAdmissionReport:
        now = self._clock.now()
        if now.tzinfo is None:
            raise ValueError("resource planner clock must be timezone-aware")
        now = now.astimezone(timezone.utc)
        issues: list[AdmissionIssue] = []
        self._evaluate_inventory(now, inventory, issues)
        self._evaluate_trust(plan, inventory, issues)
        self._evaluate_provider(plan, inventory, now, issues)
        self._evaluate_capabilities(plan, inventory, now, issues)
        self._evaluate_concurrency(plan, inventory, context, now, issues)

        pool_map = self._pool_map(inventory, issues)
        active_usage = {item.pool_kind: item for item in context.active_usage}
        grouped: dict[str, list[ResourceEstimate]] = defaultdict(list)
        for estimate in plan.estimates:
            grouped[estimate.pool_kind].append(estimate)
        evaluations = tuple(
            self._evaluate_pool(pool_kind, grouped[pool_kind], pool_map.get(pool_kind), active_usage, now, issues)
            for pool_kind in sorted(grouped)
        )
        backing_evaluations = self._evaluate_backing_stores(
            evaluations,
            pool_map,
            active_usage,
            issues,
        )

        if not issues:
            outcome = "admitted"
        elif stage == "preflight":
            outcome = "rejected"
        elif any(not item.recoverable for item in issues):
            outcome = "drain"
        else:
            outcome = "backpressure"
        return ResourceAdmissionReport(
            reservation_id=self._ids.new_resource_reservation_id(),
            stage=stage,
            outcome=outcome,
            observed_at=_rfc3339(now),
            inventory_observed_at=inventory.observed_at,
            plan=plan,
            policy=self._policy,
            context=context,
            resource_evaluations=evaluations,
            backing_store_evaluations=backing_evaluations,
            issues=tuple(issues),
        )

    def _evaluate_inventory(
        self,
        now: datetime,
        inventory: DoctorReport,
        issues: list[AdmissionIssue],
    ) -> None:
        observed_at = _parse_timestamp(inventory.observed_at)
        valid_until = _parse_timestamp(inventory.valid_until)
        age_seconds = (now - observed_at).total_seconds()
        if age_seconds < 0:
            issues.append(
                AdmissionIssue(
                    "inventory-observed-in-future",
                    "inventory",
                    "machine inventory observation time is later than the admission clock",
                    "Synchronize clocks and refresh the machine inventory before admitting work.",
                    False,
                )
            )
        if now > valid_until or age_seconds > self._policy.inventory_max_age_seconds:
            issues.append(
                AdmissionIssue(
                    "inventory-stale",
                    "inventory",
                    "machine inventory is outside the configured admission freshness window",
                    "Refresh machine inspection and repeat resource admission.",
                    False,
                )
            )
        if inventory.status == "unsupported":
            issues.append(
                AdmissionIssue(
                    "inventory-unsupported",
                    "inventory",
                    "machine doctor reports an unsupported execution host",
                    "Resolve machine-doctor error diagnostics before admitting work.",
                    False,
                )
            )

    @staticmethod
    def _evaluate_trust(
        plan: WorkloadResourcePlan,
        inventory: DoctorReport,
        issues: list[AdmissionIssue],
    ) -> None:
        if inventory.trust.trust_class not in plan.eligible_trust_classes:
            issues.append(
                AdmissionIssue(
                    "trust-class-ineligible",
                    "trust",
                    f"machine trust class {inventory.trust.trust_class!r} is not eligible for this workload",
                    "Use a machine with an explicitly eligible trust class or change the governed workload policy.",
                    False,
                )
            )
        if not inventory.trust.configured:
            issues.append(
                AdmissionIssue(
                    "trust-class-unconfigured",
                    "trust",
                    "machine trust class was not explicitly configured",
                    "Configure the governed trust class before admitting work.",
                    False,
                )
            )

    def _evaluate_provider(
        self,
        plan: WorkloadResourcePlan,
        inventory: DoctorReport,
        now: datetime,
        issues: list[AdmissionIssue],
    ) -> None:
        if plan.provider_name is None:
            return
        candidates = [item for item in inventory.providers if item.name == plan.provider_name]
        if len(candidates) != 1:
            issues.append(
                AdmissionIssue(
                    "provider-inventory-ambiguous",
                    "provider",
                    f"machine inventory does not contain exactly one provider named {plan.provider_name!r}",
                    "Refresh provider discovery and remove missing or duplicate provider identities.",
                    False,
                )
            )
            return
        provider = candidates[0]
        observation_problem = _observation_problem(
            now,
            provider.observed_at,
            provider.staleness_seconds,
            self._policy.inventory_max_age_seconds,
        )
        if observation_problem is not None:
            issues.append(
                AdmissionIssue(
                    f"provider-inventory-{observation_problem}",
                    "provider",
                    f"provider {provider.name!r} has a {observation_problem} observation",
                    "Refresh provider discovery before admitting work.",
                    False,
                )
            )
        if provider.accuracy != "exact":
            issues.append(
                AdmissionIssue(
                    "provider-availability-ambiguous",
                    "provider",
                    f"provider {provider.name!r} availability is not exact",
                    "Complete exact provider identity and health verification before admission.",
                    False,
                )
            )
        if provider.availability != "available":
            issues.append(
                AdmissionIssue(
                    "provider-not-verified-available",
                    "provider",
                    f"provider {provider.name!r} is {provider.availability!r}, not verified available",
                    "Complete provider identity and health verification or choose a verified provider.",
                    False,
                )
            )
        if plan.provider_strategy not in provider.strategies:
            issues.append(
                AdmissionIssue(
                    "provider-strategy-unavailable",
                    "provider",
                    f"provider {provider.name!r} does not advertise strategy {plan.provider_strategy!r}",
                    "Choose a provider that explicitly advertises the planned environment strategy.",
                    False,
                )
            )

    def _evaluate_capabilities(
        self,
        plan: WorkloadResourcePlan,
        inventory: DoctorReport,
        now: datetime,
        issues: list[AdmissionIssue],
    ) -> None:
        names = [item.name for item in inventory.capabilities]
        if len(names) != len(set(names)):
            issues.append(
                AdmissionIssue(
                    "capability-inventory-ambiguous",
                    "capability",
                    "machine inventory contains duplicate capability identities",
                    "Refresh discovery with one authoritative observation per capability.",
                    False,
                )
            )
            return
        capabilities = {item.name: item for item in inventory.capabilities}
        for name in sorted(plan.required_capabilities):
            capability = capabilities.get(name)
            if capability is None or capability.status != "supported":
                status = "absent" if capability is None else capability.status
                issues.append(
                    AdmissionIssue(
                        "required-capability-unavailable",
                        "capability",
                        f"required machine capability {name!r} is {status}",
                        "Use a machine where discovery proves this capability is supported.",
                        False,
                    )
                )
            elif capability.accuracy != "exact":
                issues.append(
                    AdmissionIssue(
                        "required-capability-ambiguous",
                        "capability",
                        f"required capability {name!r} is not known exactly",
                        "Refresh discovery with exact support evidence before admitting work.",
                        False,
                    )
                )
            else:
                observation_problem = _observation_problem(
                    now,
                    capability.observed_at,
                    capability.staleness_seconds,
                    self._policy.inventory_max_age_seconds,
                )
                if observation_problem is None:
                    continue
                issues.append(
                    AdmissionIssue(
                        f"capability-inventory-{observation_problem}",
                        "capability",
                        f"required capability {name!r} has a {observation_problem} observation",
                        "Refresh machine capability discovery before admitting work.",
                        False,
                    )
                )

    def _evaluate_concurrency(
        self,
        plan: WorkloadResourcePlan,
        inventory: DoctorReport,
        context: AdmissionContext,
        now: datetime,
        issues: list[AdmissionIssue],
    ) -> None:
        try:
            requested_total = _safe_sum([context.active_concurrency, plan.requested_concurrency])
        except OverflowError:
            issues.append(
                AdmissionIssue(
                    "concurrency-plan-overflow",
                    "plan",
                    "active and requested concurrency exceed the safe-integer domain",
                    "Wait for active work to finish and submit a bounded concurrency request.",
                    False,
                    pool_kind="cpu",
                )
            )
            return
        if requested_total > self._policy.max_concurrency:
            issues.append(
                AdmissionIssue(
                    "concurrency-limit-reached",
                    "concurrency",
                    f"requested concurrency {requested_total} exceeds configured maximum {self._policy.max_concurrency}",
                    "Wait for active work to finish or reduce requested concurrency.",
                    True,
                    pool_kind="cpu",
                    required=requested_total,
                    available=max(0, self._policy.max_concurrency - context.active_concurrency),
                )
            )
        cpu = next((item for item in inventory.resources if item.kind == "cpu"), None)
        if cpu is None or cpu.capacity is None:
            issues.append(
                AdmissionIssue(
                    "cpu-capacity-unknown",
                    "concurrency",
                    "logical CPU visibility is unknown and cannot bound concurrency",
                    "Refresh inventory with a supported logical CPU visibility probe.",
                    False,
                    pool_kind="cpu",
                    required=requested_total,
                )
            )
        elif _observation_problem(
            now,
            cpu.observed_at,
            cpu.staleness_seconds,
            self._policy.inventory_max_age_seconds,
        ) is not None:
            issues.append(
                AdmissionIssue(
                    "cpu-inventory-stale",
                    "concurrency",
                    "logical CPU capacity observation is stale or in the future",
                    "Refresh machine resource discovery before admitting work.",
                    False,
                    pool_kind="cpu",
                    required=requested_total,
                )
            )
        elif requested_total > cpu.capacity:
            issues.append(
                AdmissionIssue(
                    "cpu-capacity-exceeded",
                    "concurrency",
                    f"requested concurrency {requested_total} exceeds visible CPU capacity {cpu.capacity}",
                    "Wait for active work to finish or reduce requested concurrency.",
                    True,
                    pool_kind="cpu",
                    required=requested_total,
                    available=max(0, cpu.capacity - context.active_concurrency),
                )
            )

    @staticmethod
    def _pool_map(inventory: DoctorReport, issues: list[AdmissionIssue]) -> dict[str, ResourcePool]:
        names = [item.kind for item in inventory.resources]
        if len(names) != len(set(names)):
            issues.append(
                AdmissionIssue(
                    "resource-pool-inventory-ambiguous",
                    "inventory",
                    "machine inventory contains duplicate typed resource pools",
                    "Refresh discovery with one authoritative observation per typed pool.",
                    False,
                )
            )
        result: dict[str, ResourcePool] = {}
        for resource in inventory.resources:
            result.setdefault(resource.kind, resource)
        return result

    def _evaluate_pool(
        self,
        pool_kind: str,
        estimates: list[ResourceEstimate],
        pool: ResourcePool | None,
        active_usage: dict[str, ActiveResourceUsage],
        now: datetime,
        issues: list[AdmissionIssue],
    ) -> ResourceEvaluation:
        names = tuple(sorted(item.name for item in estimates))
        unit = estimates[0].unit
        active = active_usage.get(pool_kind)
        active_amount = 0 if active is None else active.amount
        unknown = [item for item in estimates if item.confidence == "unknown"]
        if unknown:
            issues.append(
                AdmissionIssue(
                    "resource-estimate-unknown",
                    "plan",
                    f"resource demand for {pool_kind!r} is unknown",
                    "Provide a governed conservative bound before admitting this work.",
                    False,
                    pool_kind=pool_kind,
                )
            )
        if any(item.unit != unit for item in estimates):
            issues.append(
                AdmissionIssue(
                    "resource-estimate-unit-conflict",
                    "plan",
                    f"resource estimates for {pool_kind!r} use conflicting units",
                    "Normalize all estimates for one typed pool to its registered unit.",
                    False,
                    pool_kind=pool_kind,
                )
            )
            unknown = estimates
        if active is not None and active.unit != unit:
            issues.append(
                AdmissionIssue(
                    "active-resource-unit-conflict",
                    "plan",
                    f"active reservation for {pool_kind!r} uses a conflicting unit",
                    "Reconcile active reservation accounting before admitting more work.",
                    False,
                    pool_kind=pool_kind,
                )
            )
        expected: int | None = None
        upper_bound: int | None = None
        margin: int | None = None
        required: int | None = None
        if not unknown:
            try:
                expected = _safe_sum([item.expected or 0 for item in estimates])
                upper_bound = _safe_sum([item.upper_bound or 0 for item in estimates])
                margin = _safe_sum(
                    [
                        _ceil_basis_points(item.upper_bound or 0, self._policy.margin_basis_points(item.confidence))
                        for item in estimates
                    ]
                )
                required = _safe_sum([upper_bound, margin])
            except OverflowError:
                issues.append(
                    AdmissionIssue(
                        "resource-plan-overflow",
                        "plan",
                        f"aggregated resource demand for {pool_kind!r} exceeds the safe-integer domain",
                        "Split the work into smaller governed plans before admission.",
                        False,
                        pool_kind=pool_kind,
                    )
                )
        if pool is None:
            issues.append(
                AdmissionIssue(
                    "resource-pool-missing",
                    "inventory",
                    f"required typed resource pool {pool_kind!r} is missing",
                    "Refresh machine discovery with the complete typed resource inventory.",
                    False,
                    pool_kind=pool_kind,
                    required=required,
                )
            )
            return ResourceEvaluation(
                pool_kind,
                unit,
                names,
                expected,
                upper_bound,
                margin,
                required,
                None,
                "unknown",
                "missing",
                None,
                active_amount,
                None,
                None,
                "unknown",
            )
        if pool.unit != unit:
            issues.append(
                AdmissionIssue(
                    "resource-pool-unit-mismatch",
                    "inventory",
                    f"pool {pool_kind!r} reports {pool.unit!r}, but the plan requires {unit!r}",
                    "Correct the typed inventory or resource plan before admission.",
                    False,
                    pool_kind=pool_kind,
                    required=required,
                    available=pool.available,
                )
            )
        observation_problem = _observation_problem(
            now,
            pool.observed_at,
            pool.staleness_seconds,
            self._policy.inventory_max_age_seconds,
        )
        if observation_problem is not None:
            issues.append(
                AdmissionIssue(
                    f"resource-pool-{observation_problem}",
                    "inventory",
                    f"resource pool {pool_kind!r} has a {observation_problem} observation",
                    "Refresh machine resource discovery before admitting work.",
                    False,
                    pool_kind=pool_kind,
                    required=required,
                    available=pool.available,
                )
            )
        reserve: int | None = None
        if pool.capacity is not None:
            reserve_policy = self._policy.reserve(pool_kind)
            reserve = max(
                reserve_policy.minimum_units,
                _ceil_basis_points(pool.capacity, reserve_policy.capacity_basis_points),
            )
        if pool.available is None or pool.accuracy in {"unknown", "bounded"}:
            issues.append(
                AdmissionIssue(
                    "resource-capacity-unknown",
                    "resource",
                    f"admissible available capacity for {pool_kind!r} is not known",
                    "Refresh inventory with exact or estimated available capacity, or choose another machine.",
                    False,
                    pool_kind=pool_kind,
                    required=required,
                )
            )
        usable = None
        if pool.available is not None and reserve is not None:
            usable = max(0, pool.available - reserve - active_amount)
        passed = (
            required is not None
            and usable is not None
            and pool.unit == unit
            and observation_problem is None
            and required <= usable
        )
        if required is not None and usable is not None and required > usable:
            issues.append(
                AdmissionIssue(
                    "resource-capacity-insufficient",
                    "resource",
                    f"pool {pool_kind!r} has {usable} admissible units but requires {required}",
                    "Wait for active work, reclaim governed cache where allowed, reduce work, or choose a larger pool.",
                    True,
                    pool_kind=pool_kind,
                    required=required,
                    available=usable,
                )
            )
        status = "pass" if passed else "unknown" if required is None or usable is None else "fail"
        post = usable - required if passed and usable is not None and required is not None else None
        return ResourceEvaluation(
            pool_kind,
            unit,
            names,
            expected,
            upper_bound,
            margin,
            required,
            pool.available,
            pool.accuracy,
            pool.source,
            reserve,
            active_amount,
            post,
            pool.backing_store,
            status,
        )

    def _evaluate_backing_stores(
        self,
        evaluations: tuple[ResourceEvaluation, ...],
        pool_map: dict[str, ResourcePool],
        active_usage: dict[str, ActiveResourceUsage],
        issues: list[AdmissionIssue],
    ) -> tuple[BackingStoreEvaluation, ...]:
        disk_evaluations = [item for item in evaluations if item.unit == "bytes" and item.pool_kind not in {"ram", "swap"}]
        if len(disk_evaluations) > 1 and any(item.backing_store is None for item in disk_evaluations):
            issues.append(
                AdmissionIssue(
                    "backing-store-identity-unknown",
                    "inventory",
                    "multiple disk pools are demanded but at least one physical backing-store identity is unknown",
                    "Refresh filesystem discovery so shared capacity cannot be double counted.",
                    False,
                )
            )
        demanded = {item.pool_kind: item for item in disk_evaluations}
        stores: dict[str, list[ResourcePool]] = defaultdict(list)
        for pool in pool_map.values():
            if pool.unit == "bytes" and pool.kind not in {"ram", "swap"} and pool.backing_store:
                stores[pool.backing_store].append(pool)
        results: list[BackingStoreEvaluation] = []
        for backing_store, pools in sorted(stores.items()):
            if len(pools) < 2 or not any(pool.kind in demanded for pool in pools):
                continue
            if any(pool.available is None for pool in pools):
                issues.append(
                    AdmissionIssue(
                        "backing-store-capacity-unknown",
                        "resource",
                        f"shared backing store {backing_store!r} has an unobservable logical pool",
                        "Refresh all logical pools on the shared store before admission.",
                        False,
                    )
                )
                continue
            try:
                required = _safe_sum(
                    [demanded[pool.kind].required or 0 for pool in pools if pool.kind in demanded]
                )
                active = _safe_sum(
                    [active_usage[pool.kind].amount for pool in pools if pool.kind in active_usage]
                )
                reserves = []
                for pool in pools:
                    reserve_policy = self._policy.reserve(pool.kind)
                    reserves.append(
                        max(
                            reserve_policy.minimum_units,
                            _ceil_basis_points(pool.capacity or 0, reserve_policy.capacity_basis_points),
                        )
                    )
                reserve = max(reserves, default=0)
                available = min(pool.available or 0 for pool in pools)
                total = _safe_sum([required, active, reserve])
                admitted = total <= available
                post = available - total if admitted else 0
            except OverflowError:
                issues.append(
                    AdmissionIssue(
                        "backing-store-plan-overflow",
                        "plan",
                        f"aggregate demand on shared store {backing_store!r} exceeds safe-integer bounds",
                        "Split the work into smaller governed plans before admission.",
                        False,
                    )
                )
                continue
            if not admitted:
                issues.append(
                    AdmissionIssue(
                        "backing-store-capacity-insufficient",
                        "resource",
                        f"shared store {backing_store!r} would be overcommitted by its logical pools",
                        "Reduce aggregate disk demand, wait for active reservations, reclaim safe cache, or choose another store.",
                        True,
                        required=total,
                        available=available,
                    )
                )
            results.append(
                BackingStoreEvaluation(
                    backing_store=backing_store,
                    pool_kinds=tuple(sorted(pool.kind for pool in pools)),
                    required=required,
                    observed_available=available,
                    safety_reserve=reserve,
                    active_usage=active,
                    post_admission_available=post,
                    status="pass" if admitted else "fail",
                )
            )
        return tuple(results)
