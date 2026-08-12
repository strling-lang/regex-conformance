"""Capability-negotiated provider interfaces for environment realization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .environment_models import (
    EnvironmentRecipe,
    ProviderAcquisition,
    ProviderDescriptor,
    ProviderDiagnosis,
    ProviderOutcome,
    ProviderPlan,
    RuntimeIdentity,
    SmokeObservation,
    TOKEN_PATTERN,
)


class EnvironmentProvider(Protocol):
    @property
    def descriptor(self) -> ProviderDescriptor: ...

    def plan(self, recipe: EnvironmentRecipe) -> ProviderPlan: ...

    def acquire(self, recipe: EnvironmentRecipe, plan: ProviderPlan, transaction_id: str) -> ProviderAcquisition: ...

    def construct(self, recipe: EnvironmentRecipe, acquisition: ProviderAcquisition, transaction_id: str) -> str: ...

    def inspect_runtime(self, recipe: EnvironmentRecipe, handle: str, transaction_id: str) -> RuntimeIdentity: ...

    def smoke_verify(
        self,
        recipe: EnvironmentRecipe,
        handle: str,
        transaction_id: str,
    ) -> tuple[SmokeObservation, ...]: ...

    def release(self, handle: str, transaction_id: str) -> ProviderOutcome: ...

    def rollback(self, handle: str | None, transaction_id: str) -> ProviderOutcome: ...

    def diagnose(self, handle: str | None, transaction_id: str) -> ProviderDiagnosis: ...


@dataclass(frozen=True)
class ProviderOperationError(Exception):
    """A provider failure with an optional handle for safe reconciliation."""

    code: str
    message: str
    cleanup_handle: str | None = None
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if TOKEN_PATTERN.fullmatch(self.code) is None:
            raise ValueError("provider error code must be a lowercase canonical token")
        if not self.message:
            raise ValueError("provider errors require a code and message")

    def __str__(self) -> str:
        return self.message


class ProviderRegistry:
    def __init__(self, providers: tuple[EnvironmentProvider, ...]) -> None:
        names = tuple(provider.descriptor.name for provider in providers)
        if len(names) != len(set(names)):
            raise ValueError("provider registry contains duplicate provider names")
        self._providers = {provider.descriptor.name: provider for provider in providers}

    def get(self, name: str) -> EnvironmentProvider:
        try:
            return self._providers[name]
        except KeyError as error:
            raise ValueError(f"environment provider {name!r} is not registered") from error

    def descriptors(self) -> tuple[ProviderDescriptor, ...]:
        return tuple(sorted((provider.descriptor for provider in self._providers.values()), key=lambda item: item.name))
