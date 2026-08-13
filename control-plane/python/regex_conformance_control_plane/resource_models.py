"""Immutable predictive resource plans and admission reports."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

RESOURCE_ADMISSION_SCHEMA_VERSION = "resource-admission.v1"
SAFE_INTEGER_MAX = 9_007_199_254_740_991
TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
IDENTITY_PATTERN = re.compile(
    r"^(?:opid|rcid):v1:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:"
    r"(?:u7:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    r"|h:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:[0-9a-f]{64})$"
)
RESOURCE_RESERVATION_ID_PATTERN = re.compile(
    r"^opid:v1:resource-reservation:u7:"
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
ENVIRONMENT_ID_PATTERN = re.compile(
    r"^opid:v1:environment:u7:"
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
CONFIDENCE_CLASSES = frozenset({"known", "measured", "estimated", "bounded", "unknown"})
MARGIN_CONFIDENCE_CLASSES = frozenset(CONFIDENCE_CLASSES - {"unknown"})
RESOURCE_POOL_KINDS = frozenset(
    {
        "persistent_disk",
        "environment_cache",
        "build_scratch",
        "execution_scratch",
        "result_spool",
        "ram",
        "swap",
        "cpu",
    }
)
RESOURCE_UNITS = frozenset({"bytes", "logical_cpu"})
OPERATION_KINDS = frozenset({"environment", "campaign", "shard"})
ADMISSION_STAGES = frozenset({"preflight", "dynamic"})
ADMISSION_OUTCOMES = frozenset({"admitted", "rejected", "backpressure", "drain"})
EVALUATION_STATES = frozenset({"pass", "fail", "unknown"})
ISSUE_CATEGORIES = frozenset(
    {"inventory", "provider", "capability", "trust", "resource", "concurrency", "plan"}
)
TRUST_CLASSES = frozenset({"unknown", "development", "trusted_executioner", "untrusted_public"})


def _require_token(name: str, value: str) -> None:
    if TOKEN_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase canonical token")


def _require_nonnegative_safe_integer(name: str, value: int | None) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= SAFE_INTEGER_MAX:
        raise ValueError(f"{name} must be a non-negative safe integer or unknown")


def _require_timestamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"invalid RFC 3339 timestamp: {value!r}") from error
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")


def _require_unique(name: str, values: tuple[str, ...]) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{name} must not contain duplicate identities")


def _validate_forecast(
    *,
    confidence: str,
    expected: int | None,
    upper_bound: int | None,
    diagnostic: str | None,
) -> None:
    if confidence not in CONFIDENCE_CLASSES:
        raise ValueError(f"invalid resource confidence: {confidence}")
    _require_nonnegative_safe_integer("expected resource amount", expected)
    _require_nonnegative_safe_integer("resource upper bound", upper_bound)
    if confidence == "unknown":
        if expected is not None or upper_bound is not None or not diagnostic:
            raise ValueError("unknown forecasts require null amounts and a diagnostic")
        return
    if upper_bound is None:
        raise ValueError(f"{confidence} forecasts require a conservative upper bound")
    if confidence in {"known", "measured", "estimated"} and expected is None:
        raise ValueError(f"{confidence} forecasts require an expected amount")
    if expected is not None and upper_bound < expected:
        raise ValueError("resource upper bound cannot be below the expected amount")
    if confidence == "known" and upper_bound != expected:
        raise ValueError("known forecasts require equal expected and upper-bound amounts")


@dataclass(frozen=True)
class ResourceEstimate:
    name: str
    pool_kind: str
    unit: str
    expected: int | None
    upper_bound: int | None
    confidence: str
    source: str
    diagnostic: str | None = None

    def __post_init__(self) -> None:
        _require_token("resource estimate name", self.name)
        if self.pool_kind not in RESOURCE_POOL_KINDS:
            raise ValueError(f"unknown typed resource pool: {self.pool_kind}")
        if self.unit not in RESOURCE_UNITS:
            raise ValueError(f"invalid resource unit: {self.unit}")
        if self.pool_kind == "cpu" and self.unit != "logical_cpu":
            raise ValueError("CPU estimates must use logical_cpu units")
        if self.pool_kind != "cpu" and self.unit != "bytes":
            raise ValueError("non-CPU estimates must use byte units")
        if not self.source:
            raise ValueError("resource estimate source is required")
        _validate_forecast(
            confidence=self.confidence,
            expected=self.expected,
            upper_bound=self.upper_bound,
            diagnostic=self.diagnostic,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": self.confidence,
            "diagnostic": self.diagnostic,
            "expected": self.expected,
            "name": self.name,
            "pool_kind": self.pool_kind,
            "source": self.source,
            "unit": self.unit,
            "upper_bound": self.upper_bound,
        }


@dataclass(frozen=True)
class TransferForecast:
    name: str
    direction: str
    expected_bytes: int | None
    upper_bound_bytes: int | None
    confidence: str
    source: str
    diagnostic: str | None = None

    def __post_init__(self) -> None:
        _require_token("transfer forecast name", self.name)
        if self.direction not in {"download", "upload", "internal"}:
            raise ValueError(f"invalid transfer direction: {self.direction}")
        if not self.source:
            raise ValueError("transfer forecast source is required")
        _validate_forecast(
            confidence=self.confidence,
            expected=self.expected_bytes,
            upper_bound=self.upper_bound_bytes,
            diagnostic=self.diagnostic,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": self.confidence,
            "diagnostic": self.diagnostic,
            "direction": self.direction,
            "expected_bytes": self.expected_bytes,
            "name": self.name,
            "source": self.source,
            "upper_bound_bytes": self.upper_bound_bytes,
        }


@dataclass(frozen=True)
class WorkloadResourcePlan:
    operation_kind: str
    operation_id: str
    estimates: tuple[ResourceEstimate, ...]
    transfers: tuple[TransferForecast, ...]
    provider_name: str | None
    provider_strategy: str | None
    required_capabilities: tuple[str, ...]
    eligible_trust_classes: tuple[str, ...]
    requested_concurrency: int
    mutation_permitted: bool = False

    def __post_init__(self) -> None:
        if self.operation_kind not in OPERATION_KINDS:
            raise ValueError(f"invalid resource-plan operation kind: {self.operation_kind}")
        if IDENTITY_PATTERN.fullmatch(self.operation_id) is None:
            raise ValueError("resource-plan operation ID must be a canonical rcid/opid identity")
        if self.operation_kind == "environment" and ENVIRONMENT_ID_PATTERN.fullmatch(self.operation_id) is None:
            raise ValueError("environment resource plans must bind an operational environment UUIDv7")
        if not self.estimates:
            raise ValueError("resource plans require at least one typed estimate")
        _require_unique("resource estimate names", tuple(item.name for item in self.estimates))
        _require_unique("transfer forecast names", tuple(item.name for item in self.transfers))
        _require_unique("required capabilities", self.required_capabilities)
        _require_unique("eligible trust classes", self.eligible_trust_classes)
        for value in self.required_capabilities:
            _require_token("required machine capability", value)
        if not self.eligible_trust_classes or any(value not in TRUST_CLASSES for value in self.eligible_trust_classes):
            raise ValueError("resource plans require registered eligible trust classes")
        if (self.provider_name is None) != (self.provider_strategy is None):
            raise ValueError("provider name and strategy must be supplied together")
        if self.provider_name is not None:
            _require_token("machine provider name", self.provider_name)
            _require_token("machine provider strategy", self.provider_strategy or "")
        _require_nonnegative_safe_integer("requested concurrency", self.requested_concurrency)
        if self.requested_concurrency < 1:
            raise ValueError("requested concurrency must be at least one")
        if not isinstance(self.mutation_permitted, bool) or self.mutation_permitted:
            raise ValueError("resource plans must be explicitly non-mutating")

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible_trust_classes": sorted(self.eligible_trust_classes),
            "estimates": [item.to_dict() for item in sorted(self.estimates, key=lambda item: item.name)],
            "mutation_permitted": self.mutation_permitted,
            "operation_id": self.operation_id,
            "operation_kind": self.operation_kind,
            "provider_name": self.provider_name,
            "provider_strategy": self.provider_strategy,
            "requested_concurrency": self.requested_concurrency,
            "required_capabilities": sorted(self.required_capabilities),
            "transfers": [item.to_dict() for item in sorted(self.transfers, key=lambda item: item.name)],
        }


@dataclass(frozen=True)
class ConfidenceMargin:
    confidence: str
    basis_points: int

    def __post_init__(self) -> None:
        if self.confidence not in MARGIN_CONFIDENCE_CLASSES:
            raise ValueError("margin confidence must be known, measured, estimated, or bounded")
        _require_nonnegative_safe_integer("confidence margin basis points", self.basis_points)
        if self.basis_points > 100_000:
            raise ValueError("confidence margin cannot exceed 1000 percent")

    def to_dict(self) -> dict[str, Any]:
        return {"basis_points": self.basis_points, "confidence": self.confidence}


@dataclass(frozen=True)
class PoolSafetyReserve:
    pool_kind: str
    minimum_units: int
    capacity_basis_points: int

    def __post_init__(self) -> None:
        if self.pool_kind not in RESOURCE_POOL_KINDS:
            raise ValueError(f"unknown reserve pool: {self.pool_kind}")
        _require_nonnegative_safe_integer("minimum reserve", self.minimum_units)
        _require_nonnegative_safe_integer("reserve basis points", self.capacity_basis_points)
        if self.capacity_basis_points > 10_000:
            raise ValueError("capacity reserve cannot exceed 100 percent")

    def to_dict(self) -> dict[str, Any]:
        return {
            "capacity_basis_points": self.capacity_basis_points,
            "minimum_units": self.minimum_units,
            "pool_kind": self.pool_kind,
        }


@dataclass(frozen=True)
class AdmissionPolicy:
    confidence_margins: tuple[ConfidenceMargin, ...]
    pool_reserves: tuple[PoolSafetyReserve, ...]
    max_concurrency: int
    inventory_max_age_seconds: int

    def __post_init__(self) -> None:
        confidence_names = tuple(item.confidence for item in self.confidence_margins)
        if set(confidence_names) != MARGIN_CONFIDENCE_CLASSES or len(confidence_names) != len(
            MARGIN_CONFIDENCE_CLASSES
        ):
            raise ValueError("admission policy must define each non-unknown confidence margin exactly once")
        _require_unique("pool reserve policies", tuple(item.pool_kind for item in self.pool_reserves))
        _require_nonnegative_safe_integer("maximum concurrency", self.max_concurrency)
        _require_nonnegative_safe_integer("inventory maximum age", self.inventory_max_age_seconds)
        if self.max_concurrency < 1 or self.inventory_max_age_seconds < 1:
            raise ValueError("concurrency and inventory maximum age must be positive")

    def margin_basis_points(self, confidence: str) -> int:
        return next(item.basis_points for item in self.confidence_margins if item.confidence == confidence)

    def reserve(self, pool_kind: str) -> PoolSafetyReserve:
        return next(
            (item for item in self.pool_reserves if item.pool_kind == pool_kind),
            PoolSafetyReserve(pool_kind, 0, 0),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence_margins": [
                item.to_dict() for item in sorted(self.confidence_margins, key=lambda item: item.confidence)
            ],
            "inventory_max_age_seconds": self.inventory_max_age_seconds,
            "max_concurrency": self.max_concurrency,
            "pool_reserves": [item.to_dict() for item in sorted(self.pool_reserves, key=lambda item: item.pool_kind)],
        }


@dataclass(frozen=True)
class ActiveResourceUsage:
    pool_kind: str
    unit: str
    amount: int

    def __post_init__(self) -> None:
        if self.pool_kind not in RESOURCE_POOL_KINDS:
            raise ValueError(f"unknown active resource pool: {self.pool_kind}")
        if self.unit not in RESOURCE_UNITS:
            raise ValueError(f"invalid active-resource unit: {self.unit}")
        if self.pool_kind == "cpu" and self.unit != "logical_cpu":
            raise ValueError("active CPU usage must use logical_cpu units")
        if self.pool_kind != "cpu" and self.unit != "bytes":
            raise ValueError("active non-CPU usage must use byte units")
        _require_nonnegative_safe_integer("active resource amount", self.amount)

    def to_dict(self) -> dict[str, Any]:
        return {"amount": self.amount, "pool_kind": self.pool_kind, "unit": self.unit}


@dataclass(frozen=True)
class AdmissionContext:
    active_concurrency: int = 0
    active_usage: tuple[ActiveResourceUsage, ...] = ()

    def __post_init__(self) -> None:
        _require_nonnegative_safe_integer("active concurrency", self.active_concurrency)
        _require_unique("active resource pools", tuple(item.pool_kind for item in self.active_usage))

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_concurrency": self.active_concurrency,
            "active_usage": [item.to_dict() for item in sorted(self.active_usage, key=lambda item: item.pool_kind)],
        }


@dataclass(frozen=True)
class AdmissionIssue:
    code: str
    category: str
    message: str
    remediation: str
    recoverable: bool
    pool_kind: str | None = None
    required: int | None = None
    available: int | None = None

    def __post_init__(self) -> None:
        _require_token("admission issue code", self.code)
        if self.category not in ISSUE_CATEGORIES:
            raise ValueError(f"invalid admission issue category: {self.category}")
        if not self.message or not self.remediation:
            raise ValueError("admission issues require a message and remediation")
        if not isinstance(self.recoverable, bool):
            raise ValueError("admission issue recoverability must be boolean")
        if self.pool_kind is not None and self.pool_kind not in RESOURCE_POOL_KINDS:
            raise ValueError(f"unknown issue resource pool: {self.pool_kind}")
        _require_nonnegative_safe_integer("issue required amount", self.required)
        _require_nonnegative_safe_integer("issue available amount", self.available)

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "pool_kind": self.pool_kind,
            "recoverable": self.recoverable,
            "remediation": self.remediation,
            "required": self.required,
        }


@dataclass(frozen=True)
class ResourceEvaluation:
    pool_kind: str
    unit: str
    estimate_names: tuple[str, ...]
    expected: int | None
    upper_bound: int | None
    margin: int | None
    required: int | None
    observed_available: int | None
    inventory_accuracy: str
    inventory_source: str
    safety_reserve: int | None
    active_usage: int
    post_admission_available: int | None
    backing_store: str | None
    status: str

    def __post_init__(self) -> None:
        if self.pool_kind not in RESOURCE_POOL_KINDS or self.unit not in RESOURCE_UNITS:
            raise ValueError("resource evaluation must name a typed pool and unit")
        if self.pool_kind == "cpu" and self.unit != "logical_cpu":
            raise ValueError("CPU evaluations must use logical_cpu units")
        if self.pool_kind != "cpu" and self.unit != "bytes":
            raise ValueError("non-CPU evaluations must use byte units")
        if self.inventory_accuracy not in {"exact", "bounded", "estimated", "unknown"}:
            raise ValueError("resource evaluation must preserve registered inventory accuracy")
        if not self.inventory_source:
            raise ValueError("resource evaluation must preserve inventory provenance")
        if not self.estimate_names:
            raise ValueError("resource evaluation requires estimate identities")
        _require_unique("resource evaluation estimates", self.estimate_names)
        for value in self.estimate_names:
            _require_token("resource evaluation estimate name", value)
        for name in (
            "expected",
            "upper_bound",
            "margin",
            "required",
            "observed_available",
            "safety_reserve",
            "active_usage",
            "post_admission_available",
        ):
            _require_nonnegative_safe_integer(name, getattr(self, name))
        if self.status not in EVALUATION_STATES:
            raise ValueError(f"invalid resource evaluation state: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_usage": self.active_usage,
            "backing_store": self.backing_store,
            "estimate_names": sorted(self.estimate_names),
            "expected": self.expected,
            "inventory_accuracy": self.inventory_accuracy,
            "inventory_source": self.inventory_source,
            "margin": self.margin,
            "observed_available": self.observed_available,
            "pool_kind": self.pool_kind,
            "post_admission_available": self.post_admission_available,
            "required": self.required,
            "safety_reserve": self.safety_reserve,
            "status": self.status,
            "unit": self.unit,
            "upper_bound": self.upper_bound,
        }


@dataclass(frozen=True)
class BackingStoreEvaluation:
    backing_store: str
    pool_kinds: tuple[str, ...]
    required: int
    observed_available: int
    safety_reserve: int
    active_usage: int
    post_admission_available: int
    status: str

    def __post_init__(self) -> None:
        if not self.backing_store or len(self.pool_kinds) < 2:
            raise ValueError("backing-store evaluations require an identity and at least two logical pools")
        _require_unique("backing-store pool kinds", self.pool_kinds)
        disk_pools = RESOURCE_POOL_KINDS - {"ram", "swap", "cpu"}
        if any(value not in disk_pools for value in self.pool_kinds):
            raise ValueError("backing-store evaluations may contain only disk-backed pools")
        for name in ("required", "observed_available", "safety_reserve", "active_usage", "post_admission_available"):
            _require_nonnegative_safe_integer(name, getattr(self, name))
        if self.status not in {"pass", "fail"}:
            raise ValueError("backing-store evaluation status must be pass or fail")

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_usage": self.active_usage,
            "backing_store": self.backing_store,
            "observed_available": self.observed_available,
            "pool_kinds": sorted(self.pool_kinds),
            "post_admission_available": self.post_admission_available,
            "required": self.required,
            "safety_reserve": self.safety_reserve,
            "status": self.status,
        }


@dataclass(frozen=True)
class ResourceAdmissionReport:
    reservation_id: str
    stage: str
    outcome: str
    observed_at: str
    inventory_observed_at: str
    plan: WorkloadResourcePlan
    policy: AdmissionPolicy
    context: AdmissionContext
    resource_evaluations: tuple[ResourceEvaluation, ...]
    backing_store_evaluations: tuple[BackingStoreEvaluation, ...]
    issues: tuple[AdmissionIssue, ...]
    mutation_permitted: bool = False
    schema_version: str = RESOURCE_ADMISSION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if RESOURCE_RESERVATION_ID_PATTERN.fullmatch(self.reservation_id) is None:
            raise ValueError("reservation ID must be an operational resource-reservation UUIDv7")
        if self.stage not in ADMISSION_STAGES or self.outcome not in ADMISSION_OUTCOMES:
            raise ValueError("invalid admission stage or outcome")
        _require_timestamp(self.observed_at)
        _require_timestamp(self.inventory_observed_at)
        _require_unique("resource evaluation pools", tuple(item.pool_kind for item in self.resource_evaluations))
        _require_unique(
            "backing-store evaluations", tuple(item.backing_store for item in self.backing_store_evaluations)
        )
        if self.outcome == "admitted" and self.issues:
            raise ValueError("admitted resource reports cannot retain blocking issues")
        if self.outcome != "admitted" and not self.issues:
            raise ValueError("non-admitted resource reports require explicit issues")
        if self.stage == "preflight" and self.outcome not in {"admitted", "rejected"}:
            raise ValueError("preflight outcomes must be admitted or rejected")
        if self.stage == "dynamic" and self.outcome == "rejected":
            raise ValueError("dynamic admission uses backpressure or drain instead of rejected")
        if self.outcome == "backpressure" and any(not item.recoverable for item in self.issues):
            raise ValueError("backpressure reports may contain only recoverable issues")
        if self.outcome == "drain" and not any(not item.recoverable for item in self.issues):
            raise ValueError("drain reports require at least one non-recoverable issue")
        planned_pools = {item.pool_kind for item in self.plan.estimates}
        evaluated_pools = {item.pool_kind for item in self.resource_evaluations}
        if planned_pools != evaluated_pools:
            raise ValueError("resource reports must evaluate every and only planned typed pool")
        if self.outcome == "admitted":
            if any(item.status != "pass" for item in self.resource_evaluations):
                raise ValueError("admitted reports require every typed resource evaluation to pass")
            if any(item.status != "pass" for item in self.backing_store_evaluations):
                raise ValueError("admitted reports require every shared backing-store evaluation to pass")
        if not isinstance(self.mutation_permitted, bool) or self.mutation_permitted:
            raise ValueError("admission reports must be explicitly non-mutating")

    def to_dict(self) -> dict[str, Any]:
        return {
            "backing_store_evaluations": [
                item.to_dict()
                for item in sorted(self.backing_store_evaluations, key=lambda item: item.backing_store)
            ],
            "context": self.context.to_dict(),
            "inventory_observed_at": self.inventory_observed_at,
            "issues": [item.to_dict() for item in self.issues],
            "mutation_permitted": self.mutation_permitted,
            "observed_at": self.observed_at,
            "outcome": self.outcome,
            "plan": self.plan.to_dict(),
            "policy": self.policy.to_dict(),
            "reservation_id": self.reservation_id,
            "resource_evaluations": [
                item.to_dict() for item in sorted(self.resource_evaluations, key=lambda item: item.pool_kind)
            ],
            "schema_version": self.schema_version,
            "stage": self.stage,
        }
