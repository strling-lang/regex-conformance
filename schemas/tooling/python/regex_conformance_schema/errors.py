"""Stable, machine-readable errors emitted by the bootstrap toolchain."""

from __future__ import annotations


class ConformanceDataError(ValueError):
    """A fail-closed validation error with a stable public code."""

    def __init__(self, code: str, message: str, *, path: str = "$") -> None:
        super().__init__(f"{code} at {path}: {message}")
        self.code = code
        self.message = message
        self.path = path


def fail(code: str, message: str, path: str = "$") -> None:
    raise ConformanceDataError(code, message, path=path)
