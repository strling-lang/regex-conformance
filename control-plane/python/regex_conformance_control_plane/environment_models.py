"""Immutable provider-neutral environment lifecycle records."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

ENVIRONMENT_LIFECYCLE_SCHEMA_VERSION = "environment-lifecycle.v1"
TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SAFE_INTEGER_MAX = 9_007_199_254_740_991
RCID_PATTERN = re.compile(
    r"^rcid:v1:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:"
    r"(?:u7:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    r"|h:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:[0-9a-f]{64})$"
)
OPERATIONAL_ENVIRONMENT_ID_PATTERN = re.compile(
    r"^opid:v1:environment:u7:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
CAPABILITY_STATES = frozenset({"supported", "unsupported", "unknown"})
LIFECYCLE_STATES = frozenset(
    {
        "planned",
        "admitted",
        "acquiring",
        "verifying_artifacts",
        "artifacts_verified",
        "constructing",
        "constructed",
        "verifying_runtime",
        "runtime_verified",
        "verifying_smoke",
        "smoke_verified",
        "fingerprinting",
        "ready",
        "releasing",
        "released",
        "cancelled",
        "rejected",
        "failed",
        "cleanup_required",
        "release_failed",
    }
)
FAILURE_CLASSES = frozenset({"admission", "cancelled", "input", "provider", "verification"})


def _require_token(name: str, value: str) -> None:
    if TOKEN_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase canonical token")


def _require_sha256(name: str, value: str) -> None:
    if SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _require_rcid(name: str, value: str) -> None:
    if RCID_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a canonical rcid:v1 identifier")


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


def _require_nonnegative_safe_integer(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= SAFE_INTEGER_MAX:
        raise ValueError(f"{name} must be a non-negative safe integer")


@dataclass(frozen=True)
class NamedValue:
    name: str
    value: str

    def __post_init__(self) -> None:
        _require_token("fact name", self.name)
        if not isinstance(self.value, str) or not self.value:
            raise ValueError("fact value must be a non-empty string")

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "value": self.value}


@dataclass(frozen=True)
class ArtifactRequirement:
    name: str
    sha256: str
    size_bytes: int
    media_type: str
    locators: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_token("artifact name", self.name)
        _require_sha256("artifact sha256", self.sha256)
        _require_token("artifact media type", self.media_type)
        _require_nonnegative_safe_integer("artifact size", self.size_bytes)
        if not self.locators or any(not isinstance(value, str) or not value for value in self.locators):
            raise ValueError("artifact locators must contain non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "locators": list(self.locators),
            "media_type": self.media_type,
            "name": self.name,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class EnvironmentRecipe:
    recipe_revision_id: str
    target_profile_id: str
    target_release_id: str
    strategy: str
    artifacts: tuple[ArtifactRequirement, ...]
    expected_runtime_facts: tuple[NamedValue, ...]
    expected_configuration: tuple[NamedValue, ...]
    required_capabilities: tuple[str, ...]
    smoke_probe_ids: tuple[str, ...]
    isolation_policy_digest: str
    network_policy: str

    def __post_init__(self) -> None:
        for name, value in (
            ("recipe revision", self.recipe_revision_id),
            ("target profile", self.target_profile_id),
            ("target release", self.target_release_id),
        ):
            _require_rcid(name, value)
        _require_token("environment strategy", self.strategy)
        _require_sha256("isolation policy digest", self.isolation_policy_digest)
        _require_token("network policy", self.network_policy)
        artifact_names = tuple(item.name for item in self.artifacts)
        fact_names = tuple(item.name for item in self.expected_runtime_facts)
        configuration_names = tuple(item.name for item in self.expected_configuration)
        _require_unique("artifact requirements", artifact_names)
        _require_unique("expected runtime facts", fact_names)
        _require_unique("expected configuration", configuration_names)
        _require_unique("required capabilities", self.required_capabilities)
        _require_unique("smoke probes", self.smoke_probe_ids)
        if not self.artifacts or not self.expected_runtime_facts or not self.smoke_probe_ids:
            raise ValueError("environment recipes require artifacts, runtime facts, and smoke probes")
        for value in (*self.required_capabilities, *self.smoke_probe_ids):
            _require_token("recipe capability or probe", value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifacts": [item.to_dict() for item in sorted(self.artifacts, key=lambda item: item.name)],
            "expected_configuration": [
                item.to_dict() for item in sorted(self.expected_configuration, key=lambda item: item.name)
            ],
            "expected_runtime_facts": [
                item.to_dict() for item in sorted(self.expected_runtime_facts, key=lambda item: item.name)
            ],
            "isolation_policy_digest": self.isolation_policy_digest,
            "network_policy": self.network_policy,
            "recipe_revision_id": self.recipe_revision_id,
            "required_capabilities": sorted(self.required_capabilities),
            "smoke_probe_ids": sorted(self.smoke_probe_ids),
            "strategy": self.strategy,
            "target_profile_id": self.target_profile_id,
            "target_release_id": self.target_release_id,
        }


@dataclass(frozen=True)
class ProviderCapability:
    name: str
    status: str
    diagnostic: str | None = None

    def __post_init__(self) -> None:
        _require_token("provider capability", self.name)
        if self.status not in CAPABILITY_STATES:
            raise ValueError(f"invalid provider capability status: {self.status}")
        if self.status != "supported" and not self.diagnostic:
            raise ValueError("unsupported or unknown provider capabilities require a diagnostic")

    def to_dict(self) -> dict[str, Any]:
        return {"diagnostic": self.diagnostic, "name": self.name, "status": self.status}


@dataclass(frozen=True)
class ProviderDescriptor:
    name: str
    strategy: str
    implementation_digest: str
    capabilities: tuple[ProviderCapability, ...]

    def __post_init__(self) -> None:
        _require_token("provider name", self.name)
        _require_token("provider strategy", self.strategy)
        _require_sha256("provider implementation digest", self.implementation_digest)
        _require_unique("provider capabilities", tuple(item.name for item in self.capabilities))
        if not self.capabilities:
            raise ValueError("provider descriptor requires explicit capabilities")

    def capability(self, name: str) -> ProviderCapability | None:
        return next((item for item in self.capabilities if item.name == name), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capabilities": [item.to_dict() for item in sorted(self.capabilities, key=lambda item: item.name)],
            "implementation_digest": self.implementation_digest,
            "name": self.name,
            "strategy": self.strategy,
        }


@dataclass(frozen=True)
class ProviderPlan:
    provider_name: str
    plan_token: str
    expected_download_bytes: int
    expected_expanded_bytes: int
    expected_scratch_bytes: int
    diagnostics: tuple[str, ...] = ()
    mutation_permitted: bool = False

    def __post_init__(self) -> None:
        _require_token("provider name", self.provider_name)
        if not self.plan_token:
            raise ValueError("provider plan token is required")
        for name in ("expected_download_bytes", "expected_expanded_bytes", "expected_scratch_bytes"):
            _require_nonnegative_safe_integer(name, getattr(self, name))
        if not isinstance(self.mutation_permitted, bool):
            raise ValueError("mutation_permitted must be a boolean")
        if self.mutation_permitted:
            raise ValueError("environment planning must not permit mutation")

    def to_dict(self) -> dict[str, Any]:
        return {
            "diagnostics": list(self.diagnostics),
            "expected_download_bytes": self.expected_download_bytes,
            "expected_expanded_bytes": self.expected_expanded_bytes,
            "expected_scratch_bytes": self.expected_scratch_bytes,
            "mutation_permitted": self.mutation_permitted,
            "plan_token": self.plan_token,
            "provider_name": self.provider_name,
        }


@dataclass(frozen=True)
class AdmissionDecision:
    admitted: bool
    decision_id: str
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.admitted, bool):
            raise ValueError("admission decision must be boolean")
        if not self.decision_id or not self.reason:
            raise ValueError("admission decision ID and reason are required")

    def to_dict(self) -> dict[str, Any]:
        return {"admitted": self.admitted, "decision_id": self.decision_id, "reason": self.reason}


@dataclass(frozen=True)
class ArtifactObservation:
    name: str
    path: str

    def __post_init__(self) -> None:
        _require_token("observed artifact name", self.name)
        if not self.path:
            raise ValueError("observed artifact path is required")


@dataclass(frozen=True)
class ProviderAcquisition:
    handle: str
    artifacts: tuple[ArtifactObservation, ...]

    def __post_init__(self) -> None:
        if not self.handle:
            raise ValueError("provider acquisition handle is required")
        _require_unique("observed artifacts", tuple(item.name for item in self.artifacts))


@dataclass(frozen=True)
class VerifiedArtifact:
    name: str
    sha256: str
    size_bytes: int
    media_type: str

    def __post_init__(self) -> None:
        _require_token("verified artifact name", self.name)
        _require_sha256("verified artifact digest", self.sha256)
        _require_token("verified artifact media type", self.media_type)
        _require_nonnegative_safe_integer("verified artifact size", self.size_bytes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "media_type": self.media_type,
            "name": self.name,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class RuntimeIdentity:
    strategy: str
    provider_implementation_digest: str
    facts: tuple[NamedValue, ...]
    relevant_configuration: tuple[NamedValue, ...]
    isolation_policy_digest: str
    network_policy: str

    def __post_init__(self) -> None:
        _require_token("runtime strategy", self.strategy)
        _require_sha256("runtime provider implementation digest", self.provider_implementation_digest)
        _require_sha256("runtime isolation policy digest", self.isolation_policy_digest)
        _require_token("runtime network policy", self.network_policy)
        _require_unique("runtime facts", tuple(item.name for item in self.facts))
        _require_unique("runtime configuration", tuple(item.name for item in self.relevant_configuration))
        if not self.facts:
            raise ValueError("runtime identity requires behaviorally relevant facts")

    def to_dict(self) -> dict[str, Any]:
        return {
            "facts": [item.to_dict() for item in sorted(self.facts, key=lambda item: item.name)],
            "isolation_policy_digest": self.isolation_policy_digest,
            "network_policy": self.network_policy,
            "provider_implementation_digest": self.provider_implementation_digest,
            "relevant_configuration": [
                item.to_dict() for item in sorted(self.relevant_configuration, key=lambda item: item.name)
            ],
            "strategy": self.strategy,
        }


@dataclass(frozen=True)
class SmokeObservation:
    probe_id: str
    passed: bool
    diagnostic: str | None = None

    def __post_init__(self) -> None:
        _require_token("smoke probe ID", self.probe_id)
        if not isinstance(self.passed, bool):
            raise ValueError("smoke probe result must be boolean")
        if not self.passed and not self.diagnostic:
            raise ValueError("failed smoke probes require a diagnostic")

    def to_dict(self) -> dict[str, Any]:
        return {"diagnostic": self.diagnostic, "passed": self.passed, "probe_id": self.probe_id}


@dataclass(frozen=True)
class ProviderOutcome:
    succeeded: bool
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.succeeded, bool):
            raise ValueError("provider outcome must be boolean")
        if not self.succeeded and not self.diagnostics:
            raise ValueError("failed provider outcomes require diagnostics")

    def to_dict(self) -> dict[str, Any]:
        return {"diagnostics": list(self.diagnostics), "succeeded": self.succeeded}


@dataclass(frozen=True)
class ProviderDiagnosis:
    status: str
    diagnostics: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in {"healthy", "degraded", "unavailable", "unknown"}:
            raise ValueError("invalid provider diagnosis status")

    def to_dict(self) -> dict[str, Any]:
        return {"diagnostics": list(self.diagnostics), "status": self.status}


@dataclass(frozen=True)
class EnvironmentDiagnosis:
    transaction_id: str
    state: str
    provider_name: str
    provider_status: str
    diagnostics: tuple[str, ...]
    failure_code: str | None

    def __post_init__(self) -> None:
        if OPERATIONAL_ENVIRONMENT_ID_PATTERN.fullmatch(self.transaction_id) is None:
            raise ValueError("diagnosis transaction ID must be an operational environment UUIDv7")
        if self.state not in LIFECYCLE_STATES:
            raise ValueError("diagnosis state is invalid")
        _require_token("diagnosis provider", self.provider_name)
        if self.provider_status not in {"healthy", "degraded", "unavailable", "unknown"}:
            raise ValueError("diagnosis provider status is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "diagnostics": list(self.diagnostics),
            "failure_code": self.failure_code,
            "provider_name": self.provider_name,
            "provider_status": self.provider_status,
            "state": self.state,
            "transaction_id": self.transaction_id,
        }


@dataclass(frozen=True)
class LifecycleFailure:
    classification: str
    code: str
    message: str
    cleanup_required: bool = False

    def __post_init__(self) -> None:
        if self.classification not in FAILURE_CLASSES:
            raise ValueError(f"invalid lifecycle failure class: {self.classification}")
        _require_token("failure code", self.code)
        if not isinstance(self.cleanup_required, bool):
            raise ValueError("cleanup_required must be a boolean")
        if not self.message:
            raise ValueError("failure message is required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "cleanup_required": self.cleanup_required,
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True)
class LifecycleTransition:
    sequence: int
    from_state: str | None
    to_state: str
    observed_at: str
    detail: str

    def __post_init__(self) -> None:
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 1:
            raise ValueError("transition sequence starts at one")
        if self.from_state is not None and self.from_state not in LIFECYCLE_STATES:
            raise ValueError(f"invalid source lifecycle state: {self.from_state}")
        if self.to_state not in LIFECYCLE_STATES:
            raise ValueError(f"invalid target lifecycle state: {self.to_state}")
        _require_timestamp(self.observed_at)
        if not self.detail:
            raise ValueError("transition detail is required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "detail": self.detail,
            "from_state": self.from_state,
            "observed_at": self.observed_at,
            "sequence": self.sequence,
            "to_state": self.to_state,
        }


@dataclass(frozen=True)
class EnvironmentLifecycleRecord:
    transaction_id: str
    state: str
    recipe: EnvironmentRecipe
    provider: ProviderDescriptor
    plan: ProviderPlan | None
    admission: AdmissionDecision | None
    provider_handle: str | None
    verified_artifacts: tuple[VerifiedArtifact, ...]
    runtime_identity: RuntimeIdentity | None
    smoke_observations: tuple[SmokeObservation, ...]
    verification_digest: str | None
    environment_fingerprint_id: str | None
    transitions: tuple[LifecycleTransition, ...]
    failure: LifecycleFailure | None = None
    rollback: ProviderOutcome | None = None
    diagnostics: tuple[str, ...] = ()
    schema_version: str = ENVIRONMENT_LIFECYCLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if OPERATIONAL_ENVIRONMENT_ID_PATTERN.fullmatch(self.transaction_id) is None:
            raise ValueError("transaction ID must be an operational environment UUIDv7")
        if self.state not in LIFECYCLE_STATES:
            raise ValueError(f"invalid lifecycle state: {self.state}")
        _require_unique("verified artifacts", tuple(item.name for item in self.verified_artifacts))
        _require_unique("smoke observations", tuple(item.probe_id for item in self.smoke_observations))
        if self.verification_digest is not None:
            _require_sha256("verification digest", self.verification_digest)
        if self.environment_fingerprint_id is not None:
            _require_rcid("environment fingerprint", self.environment_fingerprint_id)
            if ":environment-fingerprint:h:" not in self.environment_fingerprint_id:
                raise ValueError("environment fingerprint must use the environment-fingerprint hash namespace")
        if self.state == "ready":
            if any(
                value is None
                for value in (
                    self.provider_handle,
                    self.runtime_identity,
                    self.verification_digest,
                    self.environment_fingerprint_id,
                )
            ) or self.failure is not None:
                raise ValueError("Ready requires verified runtime, fingerprint, handle, and no failure")
            if self.plan is None or self.admission is None or not self.admission.admitted:
                raise ValueError("Ready requires an admitted provider plan")
            if not self.verified_artifacts or not self.smoke_observations:
                raise ValueError("Ready requires verified artifacts and smoke observations")
            if any(not item.passed for item in self.smoke_observations):
                raise ValueError("Ready cannot contain a failed smoke observation")
            if self.rollback is not None:
                raise ValueError("Ready cannot follow a rollback")
        if self.state in {"rejected", "failed", "cleanup_required", "release_failed"} and self.failure is None:
            raise ValueError(f"{self.state} requires an explicit failure")
        if self.state == "cancelled" and self.failure is None:
            raise ValueError("cancelled requires an explicit failure")
        if self.state in {"cleanup_required", "release_failed"} and not self.failure.cleanup_required:
            raise ValueError(f"{self.state} requires cleanup_required failure evidence")
        sequences = tuple(item.sequence for item in self.transitions)
        if sequences != tuple(range(1, len(sequences) + 1)):
            raise ValueError("transition sequence must be contiguous and ordered")
        if self.transitions and self.transitions[-1].to_state != self.state:
            raise ValueError("last transition must match current lifecycle state")

    def to_dict(self) -> dict[str, Any]:
        return {
            "admission": None if self.admission is None else self.admission.to_dict(),
            "diagnostics": list(self.diagnostics),
            "environment_fingerprint_id": self.environment_fingerprint_id,
            "failure": None if self.failure is None else self.failure.to_dict(),
            "plan": None if self.plan is None else self.plan.to_dict(),
            "provider": self.provider.to_dict(),
            "provider_handle": self.provider_handle,
            "recipe": self.recipe.to_dict(),
            "rollback": None if self.rollback is None else self.rollback.to_dict(),
            "runtime_identity": None if self.runtime_identity is None else self.runtime_identity.to_dict(),
            "schema_version": self.schema_version,
            "smoke_observations": [
                item.to_dict() for item in sorted(self.smoke_observations, key=lambda item: item.probe_id)
            ],
            "state": self.state,
            "transaction_id": self.transaction_id,
            "transitions": [item.to_dict() for item in self.transitions],
            "verification_digest": self.verification_digest,
            "verified_artifacts": [
                item.to_dict() for item in sorted(self.verified_artifacts, key=lambda item: item.name)
            ],
        }
