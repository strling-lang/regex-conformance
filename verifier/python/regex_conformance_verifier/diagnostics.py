"""Stable, non-sensitive diagnostics for immutable evidence qualification."""

from __future__ import annotations

from typing import Any


class EvidenceIntegrityError(RuntimeError):
    """A fail-closed evidence finding with a stable machine-readable code."""

    def __init__(
        self,
        code: str,
        message: str | None = None,
        *,
        artifact_category: str | None = None,
        artifact_sha256: str | None = None,
        logical_execution_id: str | None = None,
    ) -> None:
        # Preserve the old one-argument construction contract for publication
        # errors while all verifier findings use explicit stable codes.
        if message is None:
            message = code
            code = "evidence-integrity-failed"
        self.code = code
        self.message = message
        self.artifact_category = artifact_category
        self.artifact_sha256 = artifact_sha256
        self.logical_execution_id = logical_execution_id
        super().__init__(f"{code}: {message}")

    def as_finding(self) -> dict[str, Any]:
        return {
            "artifact_category": self.artifact_category,
            "artifact_sha256": self.artifact_sha256,
            "code": self.code,
            "logical_execution_id": self.logical_execution_id,
            "message": self.message[:512],
            "severity": "error",
        }
