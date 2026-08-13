"""Transactional provider-neutral environment orchestration."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import time
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .event_models import EventDraft, EventPublisher
from .environment_fingerprint import EnvironmentFingerprinter
from .environment_models import (
    AdmissionDecision,
    ArtifactObservation,
    ArtifactRequirement,
    EnvironmentDiagnosis,
    EnvironmentLifecycleRecord,
    EnvironmentRecipe,
    LifecycleFailure,
    LifecycleTransition,
    NamedValue,
    ProviderDescriptor,
    ProviderOutcome,
    RuntimeIdentity,
    SmokeObservation,
    VerifiedArtifact,
)
from .environment_providers import EnvironmentProvider, ProviderOperationError, ProviderRegistry

BASE_READY_CAPABILITIES = frozenset(
    {
        "acquisition",
        "artifact-digest-visibility",
        "construction",
        "diagnostics",
        "rollback",
        "runtime-identity",
        "safe-release",
        "smoke-verification",
    }
)
MUTATED_STATES = frozenset(
    {
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
        "release_failed",
        "cleanup_required",
    }
)


class Clock(Protocol):
    def now(self) -> datetime: ...


class IdGenerator(Protocol):
    def new_environment_transaction_id(self) -> str: ...


class UtcClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class Uuid7EnvironmentIdGenerator:
    def new_environment_transaction_id(self) -> str:
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
        return f"opid:v1:environment:u7:{uuid.UUID(int=integer)}"


class InvalidLifecycleTransition(ValueError):
    pass


class LifecycleVerificationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _rfc3339(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("clock values must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class EnvironmentManager:
    def __init__(
        self,
        providers: ProviderRegistry,
        *,
        clock: Clock | None = None,
        id_generator: IdGenerator | None = None,
        fingerprinter: EnvironmentFingerprinter | None = None,
        event_publisher: EventPublisher | None = None,
    ) -> None:
        self._providers = providers
        self._clock = clock or UtcClock()
        self._ids = id_generator or Uuid7EnvironmentIdGenerator()
        self._fingerprinter = fingerprinter or EnvironmentFingerprinter()
        self._event_publisher = event_publisher

    def plan(self, recipe: EnvironmentRecipe, provider_name: str) -> EnvironmentLifecycleRecord:
        provider = self._providers.get(provider_name)
        transaction_id = self._ids.new_environment_transaction_id()
        descriptor = provider.descriptor
        incompatibility = self._provider_incompatibility(recipe, descriptor)
        if incompatibility is not None:
            failure = LifecycleFailure("input", "provider-capability-mismatch", incompatibility)
            return self._initial_record(transaction_id, recipe, descriptor, "rejected", failure=failure)
        try:
            plan = provider.plan(recipe)
            if plan.provider_name != descriptor.name:
                raise LifecycleVerificationError(
                    "provider-plan-identity-mismatch",
                    "provider plan names a different provider implementation",
                )
            if plan.mutation_permitted:
                raise LifecycleVerificationError(
                    "provider-plan-permits-mutation",
                    "provider plan incorrectly permits mutation",
                )
        except LifecycleVerificationError as error:
            failure = LifecycleFailure("verification", error.code, error.message)
            return self._initial_record(transaction_id, recipe, descriptor, "rejected", failure=failure)
        except ProviderOperationError as error:
            failure = LifecycleFailure("provider", error.code, error.message)
            return self._initial_record(
                transaction_id,
                recipe,
                descriptor,
                "failed",
                failure=failure,
                diagnostics=error.diagnostics,
            )
        except Exception as error:  # provider boundary: untyped failures remain operational
            failure = LifecycleFailure("provider", "provider-plan-failed", str(error) or type(error).__name__)
            return self._initial_record(transaction_id, recipe, descriptor, "failed", failure=failure)
        record = self._initial_record(transaction_id, recipe, descriptor, "planned")
        return replace(record, plan=plan, diagnostics=plan.diagnostics)

    def admit(
        self,
        record: EnvironmentLifecycleRecord,
        decision: AdmissionDecision,
    ) -> EnvironmentLifecycleRecord:
        self._require_state(record, {"planned"}, "admit")
        if not decision.admitted:
            failure = LifecycleFailure("admission", "admission-denied", decision.reason)
            return self._transition(replace(record, admission=decision, failure=failure), "rejected", decision.reason)
        return self._transition(replace(record, admission=decision), "admitted", decision.reason)

    def realize(self, record: EnvironmentLifecycleRecord) -> EnvironmentLifecycleRecord:
        self._require_state(record, {"admitted"}, "realize")
        if record.plan is None or record.admission is None or not record.admission.admitted:
            raise InvalidLifecycleTransition("realization requires an admitted provider plan")
        provider = self._providers.get(record.provider.name)
        current = self._transition(record, "acquiring", "provider acquisition started")
        handle: str | None = None
        try:
            acquisition = provider.acquire(record.recipe, record.plan, record.transaction_id)
            handle = acquisition.handle
            current = replace(current, provider_handle=handle)
            current = self._transition(current, "verifying_artifacts", "independent artifact verification started")
            verified = self._verify_artifacts(record.recipe.artifacts, acquisition.artifacts)
            current = replace(current, verified_artifacts=verified)
            current = self._transition(current, "artifacts_verified", "all acquired artifact bytes match the recipe")
            current = self._transition(current, "constructing", "provider construction started")
            handle = provider.construct(record.recipe, acquisition, record.transaction_id)
            if not handle:
                raise LifecycleVerificationError("empty-provider-handle", "provider construction returned an empty handle")
            current = replace(current, provider_handle=handle)
            current = self._transition(current, "constructed", "provider construction completed")
            current = self._transition(current, "verifying_runtime", "runtime identity inspection started")
            runtime = provider.inspect_runtime(record.recipe, handle, record.transaction_id)
            self._verify_runtime(record.recipe, record.provider, runtime)
            current = replace(current, runtime_identity=runtime)
            current = self._transition(current, "runtime_verified", "runtime identity matches recipe requirements")
            current = self._transition(current, "verifying_smoke", "identity smoke verification started")
            smoke = provider.smoke_verify(record.recipe, handle, record.transaction_id)
            self._verify_smoke(record.recipe, smoke)
            current = replace(current, smoke_observations=smoke)
            current = self._transition(current, "smoke_verified", "all required non-conformance smoke probes passed")
            current = self._transition(current, "fingerprinting", "verified realized fingerprint derivation started")
            try:
                fingerprint = self._fingerprinter.fingerprint(
                    recipe=record.recipe,
                    provider=record.provider,
                    artifacts=verified,
                    runtime=runtime,
                    smoke=smoke,
                )
            except ValueError as error:
                raise LifecycleVerificationError(
                    "fingerprint-canonicalization-failed",
                    str(error) or "verified environment fingerprint could not be canonicalized",
                ) from error
            current = replace(
                current,
                verification_digest=fingerprint.verification_digest,
                environment_fingerprint_id=fingerprint.environment_fingerprint_id,
            )
            return self._transition(current, "ready", "artifact, runtime, smoke, and fingerprint verification passed")
        except Exception as error:
            return self._fail_with_rollback(current, provider, error, handle)

    def cancel(self, record: EnvironmentLifecycleRecord, reason: str) -> EnvironmentLifecycleRecord:
        if not reason:
            raise ValueError("cancellation reason is required")
        if record.state in {"planned", "admitted"}:
            failure = LifecycleFailure("cancelled", "operation-cancelled", reason)
            return self._transition(replace(record, failure=failure), "cancelled", reason)
        if record.state not in MUTATED_STATES:
            raise InvalidLifecycleTransition(f"cannot cancel environment from {record.state}")
        provider = self._providers.get(record.provider.name)
        failure = LifecycleFailure("cancelled", "operation-cancelled", reason)
        return self._rollback(record, provider, record.provider_handle, failure, cancelled=True)

    def release(self, record: EnvironmentLifecycleRecord) -> EnvironmentLifecycleRecord:
        self._require_state(record, {"ready"}, "release")
        provider = self._providers.get(record.provider.name)
        current = self._transition(record, "releasing", "provider release started")
        try:
            outcome = provider.release(record.provider_handle or "", record.transaction_id)
        except ProviderOperationError as error:
            outcome = ProviderOutcome(False, (error.message, *error.diagnostics))
        except Exception as error:
            outcome = ProviderOutcome(False, (str(error) or type(error).__name__,))
        if not outcome.succeeded:
            failure = LifecycleFailure(
                "provider",
                "provider-release-failed",
                "; ".join(outcome.diagnostics),
                cleanup_required=True,
            )
            return self._transition(
                replace(current, failure=failure, diagnostics=current.diagnostics + outcome.diagnostics),
                "release_failed",
                "provider could not prove safe release",
            )
        return self._transition(
            replace(current, diagnostics=current.diagnostics + outcome.diagnostics),
            "released",
            "provider release completed",
        )

    def diagnose(self, record: EnvironmentLifecycleRecord) -> EnvironmentDiagnosis:
        provider = self._providers.get(record.provider.name)
        try:
            diagnosis = provider.diagnose(record.provider_handle, record.transaction_id)
        except Exception as error:
            diagnosis_status = "unknown"
            provider_diagnostics = (f"provider diagnosis failed: {str(error) or type(error).__name__}",)
        else:
            diagnosis_status = diagnosis.status
            provider_diagnostics = diagnosis.diagnostics
        failure_diagnostics = () if record.failure is None else (f"{record.failure.code}: {record.failure.message}",)
        return EnvironmentDiagnosis(
            transaction_id=record.transaction_id,
            state=record.state,
            provider_name=record.provider.name,
            provider_status=diagnosis_status,
            diagnostics=tuple((*record.diagnostics, *failure_diagnostics, *provider_diagnostics)),
            failure_code=None if record.failure is None else record.failure.code,
        )

    def _provider_incompatibility(self, recipe: EnvironmentRecipe, provider: ProviderDescriptor) -> str | None:
        if provider.strategy != recipe.strategy:
            return f"provider strategy {provider.strategy!r} does not realize recipe strategy {recipe.strategy!r}"
        required = BASE_READY_CAPABILITIES | set(recipe.required_capabilities)
        failures: list[str] = []
        for name in sorted(required):
            capability = provider.capability(name)
            if capability is None:
                failures.append(f"{name}=absent")
            elif capability.status != "supported":
                failures.append(f"{name}={capability.status}")
        if failures:
            return "provider cannot satisfy required capabilities: " + ", ".join(failures)
        return None

    def _verify_artifacts(
        self,
        requirements: tuple[ArtifactRequirement, ...],
        observations: tuple[ArtifactObservation, ...],
    ) -> tuple[VerifiedArtifact, ...]:
        expected = {item.name: item for item in requirements}
        observed = {item.name: item for item in observations}
        if len(observed) != len(observations):
            raise LifecycleVerificationError("artifact-identity-collision", "provider returned duplicate artifact names")
        missing = sorted(set(expected) - set(observed))
        unexpected = sorted(set(observed) - set(expected))
        if missing or unexpected:
            raise LifecycleVerificationError(
                "artifact-set-mismatch",
                f"artifact set mismatch; missing={missing!r}, unexpected={unexpected!r}",
            )
        verified: list[VerifiedArtifact] = []
        for name in sorted(expected):
            requirement = expected[name]
            path = Path(observed[name].path)
            actual_digest, size = self._hash_regular_artifact(name, path, requirement.size_bytes)
            if size != requirement.size_bytes or actual_digest != requirement.sha256:
                raise LifecycleVerificationError(
                    "artifact-identity-mismatch",
                    f"artifact {name!r} does not match its pinned size and digest",
                )
            verified.append(VerifiedArtifact(name, actual_digest, size, requirement.media_type))
        return tuple(verified)

    @staticmethod
    def _hash_regular_artifact(name: str, path: Path, expected_size: int) -> tuple[str, int]:
        descriptor: int | None = None
        try:
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode):
                raise LifecycleVerificationError(
                    "artifact-path-unsafe",
                    f"artifact {name!r} is not a regular non-symlink file",
                )
            flags = os.O_RDONLY
            flags |= getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise LifecycleVerificationError(
                    "artifact-path-unsafe",
                    f"artifact {name!r} changed identity during verification",
                )
            if opened.st_size != expected_size:
                return hashlib.sha256().hexdigest(), opened.st_size
            digest = hashlib.sha256()
            size = 0
            with os.fdopen(descriptor, "rb", closefd=True) as stream:
                descriptor = None
                while chunk := stream.read(1024 * 1024):
                    size += len(chunk)
                    if size > expected_size:
                        break
                    digest.update(chunk)
            return digest.hexdigest(), size
        except LifecycleVerificationError:
            raise
        except OSError as error:
            raise LifecycleVerificationError(
                "artifact-read-failed",
                f"artifact {name!r} could not be read: {error}",
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _verify_runtime(
        self,
        recipe: EnvironmentRecipe,
        provider: ProviderDescriptor,
        runtime: RuntimeIdentity,
    ) -> None:
        if runtime.strategy != recipe.strategy or runtime.strategy != provider.strategy:
            raise LifecycleVerificationError("runtime-strategy-mismatch", "realized runtime strategy is not the planned strategy")
        if runtime.provider_implementation_digest != provider.implementation_digest:
            raise LifecycleVerificationError(
                "provider-implementation-mismatch",
                "runtime inspection does not bind the selected provider implementation",
            )
        if runtime.isolation_policy_digest != recipe.isolation_policy_digest:
            raise LifecycleVerificationError("isolation-policy-mismatch", "realized isolation policy differs from the recipe")
        if runtime.network_policy != recipe.network_policy:
            raise LifecycleVerificationError("network-policy-mismatch", "realized network policy differs from the recipe")
        self._verify_named_values("runtime", recipe.expected_runtime_facts, runtime.facts)
        self._verify_named_values("configuration", recipe.expected_configuration, runtime.relevant_configuration)

    def _verify_named_values(
        self,
        label: str,
        expected_values: tuple[NamedValue, ...],
        actual_values: tuple[NamedValue, ...],
    ) -> None:
        expected = {item.name: item.value for item in expected_values}
        actual = {item.name: item.value for item in actual_values}
        if len(actual) != len(actual_values):
            raise LifecycleVerificationError(f"{label}-identity-collision", f"duplicate {label} fact names")
        missing = sorted(set(expected) - set(actual))
        mismatched = sorted(name for name in expected if name in actual and expected[name] != actual[name])
        if missing or mismatched:
            raise LifecycleVerificationError(
                f"{label}-identity-mismatch",
                f"{label} identity mismatch; missing={missing!r}, mismatched={mismatched!r}",
            )

    def _verify_smoke(
        self,
        recipe: EnvironmentRecipe,
        observations: tuple[SmokeObservation, ...],
    ) -> None:
        actual = {item.probe_id: item for item in observations}
        if len(actual) != len(observations):
            raise LifecycleVerificationError("smoke-identity-collision", "duplicate smoke probe IDs")
        missing = sorted(set(recipe.smoke_probe_ids) - set(actual))
        failed = sorted(name for name in recipe.smoke_probe_ids if name in actual and not actual[name].passed)
        if missing or failed:
            raise LifecycleVerificationError(
                "smoke-verification-failed",
                f"required smoke verification failed; missing={missing!r}, failed={failed!r}",
            )

    def _fail_with_rollback(
        self,
        record: EnvironmentLifecycleRecord,
        provider: EnvironmentProvider,
        error: Exception,
        handle: str | None,
    ) -> EnvironmentLifecycleRecord:
        if isinstance(error, LifecycleVerificationError):
            failure = LifecycleFailure("verification", error.code, error.message)
        elif isinstance(error, ProviderOperationError):
            failure = LifecycleFailure("provider", error.code, error.message)
            handle = error.cleanup_handle or handle
            record = replace(record, diagnostics=record.diagnostics + error.diagnostics)
        else:
            failure = LifecycleFailure(
                "provider",
                "provider-operation-failed",
                str(error) or type(error).__name__,
            )
        return self._rollback(record, provider, handle, failure)

    def _rollback(
        self,
        record: EnvironmentLifecycleRecord,
        provider: EnvironmentProvider,
        handle: str | None,
        failure: LifecycleFailure,
        *,
        cancelled: bool = False,
    ) -> EnvironmentLifecycleRecord:
        try:
            outcome = provider.rollback(handle, record.transaction_id)
        except ProviderOperationError as error:
            outcome = ProviderOutcome(False, (error.message, *error.diagnostics))
        except Exception as error:
            outcome = ProviderOutcome(False, (str(error) or type(error).__name__,))
        if not outcome.succeeded:
            failure = replace(failure, cleanup_required=True)
            target = "cleanup_required"
            detail = "rollback could not prove cleanup; reconciliation is required"
        else:
            target = "cancelled" if cancelled else "failed"
            detail = "provider rollback completed after cancellation" if cancelled else "provider rollback completed after failure"
        return self._transition(
            replace(
                record,
                provider_handle=handle or record.provider_handle,
                failure=failure,
                rollback=outcome,
                diagnostics=record.diagnostics + outcome.diagnostics,
            ),
            target,
            detail,
        )

    def _initial_record(
        self,
        transaction_id: str,
        recipe: EnvironmentRecipe,
        provider: ProviderDescriptor,
        state: str,
        *,
        failure: LifecycleFailure | None = None,
        diagnostics: tuple[str, ...] = (),
    ) -> EnvironmentLifecycleRecord:
        transition = LifecycleTransition(1, None, state, _rfc3339(self._clock.now()), f"environment {state}")
        record = EnvironmentLifecycleRecord(
            transaction_id=transaction_id,
            state=state,
            recipe=recipe,
            provider=provider,
            plan=None,
            admission=None,
            provider_handle=None,
            verified_artifacts=(),
            runtime_identity=None,
            smoke_observations=(),
            verification_digest=None,
            environment_fingerprint_id=None,
            transitions=(transition,),
            failure=failure,
            diagnostics=diagnostics,
        )
        self._emit_transition(record, transition)
        return record

    def _transition(
        self,
        record: EnvironmentLifecycleRecord,
        state: str,
        detail: str,
    ) -> EnvironmentLifecycleRecord:
        transition = LifecycleTransition(
            len(record.transitions) + 1,
            record.state,
            state,
            _rfc3339(self._clock.now()),
            detail,
        )
        updated = replace(record, state=state, transitions=record.transitions + (transition,))
        self._emit_transition(updated, transition)
        return updated

    def _emit_transition(
        self,
        record: EnvironmentLifecycleRecord,
        transition: LifecycleTransition,
    ) -> None:
        if self._event_publisher is None:
            return
        terminal_status = {
            "cancelled": "cancelled",
            "cleanup_required": "failed",
            "failed": "failed",
            "rejected": "refused",
            "release_failed": "failed",
            "released": "completed",
        }.get(record.state)
        self._event_publisher.publish(
            EventDraft(
                stream_id=record.transaction_id,
                operation_kind="environment-lifecycle",
                event_type="lifecycle",
                phase=record.state,
                status=terminal_status or "running",
                message=f"environment lifecycle entered {record.state}",
                attributes={
                    "from_state": transition.from_state,
                    "provider_name": record.provider.name,
                    "recipe_revision_id": record.recipe.recipe_revision_id,
                    "to_state": transition.to_state,
                    "transition_sequence": transition.sequence,
                },
                terminal=terminal_status is not None,
            )
        )

    @staticmethod
    def _require_state(record: EnvironmentLifecycleRecord, allowed: set[str], operation: str) -> None:
        if record.state not in allowed:
            raise InvalidLifecycleTransition(f"cannot {operation} environment from {record.state}")
