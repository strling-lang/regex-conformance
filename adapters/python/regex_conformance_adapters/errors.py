"""Typed adapter protocol and target-boundary errors."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AdapterError(Exception):
    code: str
    message: str
    layer: str = "protocol"
    kind: str = "request-validation"

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass
class UnsupportedRequest(AdapterError):
    layer: str = "materialization"
    kind: str = "unsupported"


@dataclass(frozen=True)
class TargetError:
    error_class: str
    code: int | str | None
    message: str
    phase: str
    position: int | None = None
    diagnostic: bytes | None = None


@dataclass
class BackendFailure(AdapterError):
    layer: str = "invocation"
    kind: str = "adapter-invocation"
