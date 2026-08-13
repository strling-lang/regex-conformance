"""Stable non-canonical command documents shared by CLI and automation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

from .state_models import StateModelError, TOKEN_PATTERN, canonical_object, parse_canonical_object


EXIT_CODES = {"succeeded": 0, "rejected": 2, "failed": 3, "unavailable": 4}
ACTIONS = frozenset({"execute", "inspect", "plan", "verify"})
ISSUE_CATEGORIES = frozenset({"admission", "input", "integrity", "runtime", "unavailable"})


class CommandModelError(ValueError):
    """A command result violates the public automation contract."""


def _text(value: str, label: str, *, maximum: int = 1024) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum or any(not c.isprintable() for c in value):
        raise CommandModelError(f"{label} must be bounded non-empty single-line text")


def _command(value: str) -> None:
    _text(value, "command", maximum=128)
    if any(TOKEN_PATTERN.fullmatch(part) is None for part in value.split(" ")):
        raise CommandModelError("command must contain lowercase canonical tokens")


@dataclass(frozen=True)
class CommandIssue:
    code: str
    category: str
    message: str
    remediation: str | None = None

    def __post_init__(self) -> None:
        _text(self.code, "command issue code", maximum=128)
        if TOKEN_PATTERN.fullmatch(self.code) is None:
            raise CommandModelError("command issue code must be a lowercase canonical token")
        if self.category not in ISSUE_CATEGORIES:
            raise CommandModelError("command issue category is unsupported")
        _text(self.message, "command issue message")
        if self.remediation is not None:
            _text(self.remediation, "command issue remediation")

    def to_dict(self) -> dict[str, str | None]:
        return {
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class CommandDocument:
    command: str
    action: str
    outcome: str
    dry_run: bool
    changed: bool
    payload_json: str
    payload_sha256: str
    issues: tuple[CommandIssue, ...] = ()
    canonical_authority: bool = False
    schema_version: str = "control-plane-command.v1"

    def __post_init__(self) -> None:
        _command(self.command)
        if self.action not in ACTIONS:
            raise CommandModelError("command action is unsupported")
        if self.outcome not in EXIT_CODES:
            raise CommandModelError("command outcome is unsupported")
        if not isinstance(self.dry_run, bool) or not isinstance(self.changed, bool):
            raise CommandModelError("command dry-run/changed flags must be boolean")
        if self.dry_run and self.changed:
            raise CommandModelError("a dry-run command cannot report mutation")
        if self.changed and self.action != "execute":
            raise CommandModelError("only execution actions can report mutation")
        if self.outcome == "succeeded" and self.issues:
            raise CommandModelError("successful commands cannot contain issues")
        if self.outcome != "succeeded" and not self.issues:
            raise CommandModelError("non-successful commands require an issue")
        try:
            payload = parse_canonical_object(self.payload_json)
        except StateModelError as error:
            raise CommandModelError("command payload must be canonical secret-safe JSON") from error
        if len(self.payload_json.encode("utf-8")) > 1024 * 1024:
            raise CommandModelError("command payload exceeds the 1 MiB interface limit")
        digest = hashlib.sha256(self.payload_json.encode("utf-8")).hexdigest()
        if digest != self.payload_sha256:
            raise CommandModelError("command payload digest does not match")
        del payload
        if self.canonical_authority is not False:
            raise CommandModelError("control-plane commands cannot claim canonical authority")
        if self.schema_version != "control-plane-command.v1":
            raise CommandModelError("unsupported command document schema")

    @classmethod
    def build(
        cls,
        *,
        command: str,
        action: str,
        outcome: str = "succeeded",
        dry_run: bool,
        changed: bool,
        payload: Mapping[str, Any] | None = None,
        issues: tuple[CommandIssue, ...] = (),
    ) -> "CommandDocument":
        payload_json, payload_sha256 = canonical_object(payload or {})
        return cls(command, action, outcome, dry_run, changed, payload_json, payload_sha256, issues)

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.outcome]

    @property
    def payload(self) -> dict[str, Any]:
        return parse_canonical_object(self.payload_json)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "canonical_authority": False,
            "changed": self.changed,
            "command": self.command,
            "dry_run": self.dry_run,
            "exit_code": self.exit_code,
            "issues": [item.to_dict() for item in self.issues],
            "outcome": self.outcome,
            "payload": self.payload,
            "payload_sha256": self.payload_sha256,
            "schema_version": self.schema_version,
        }


def render_command_json(document: CommandDocument, *, compact: bool = False) -> str:
    return json.dumps(
        document.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
        separators=(",", ":") if compact else None,
        indent=None if compact else 2,
    ) + "\n"


def render_command_human(document: CommandDocument) -> str:
    lines = [
        f"Command: {document.command}",
        f"Action: {document.action}{' (dry run)' if document.dry_run else ''}",
        f"Outcome: {document.outcome}",
        f"Changed: {'yes' if document.changed else 'no'}",
        f"Payload SHA-256: {document.payload_sha256}",
    ]
    payload = document.payload
    if payload:
        lines.append("Payload:")
        for key in sorted(payload):
            value = payload[key]
            summary = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"))
            if len(summary) > 240:
                summary = summary[:237] + "..."
            lines.append(f"  - {key}: {summary}")
    if document.issues:
        lines.append("Issues:")
        for issue in document.issues:
            lines.append(f"  - [{issue.category}] {issue.code}: {issue.message}")
            if issue.remediation:
                lines.append(f"    remediation: {issue.remediation}")
    return "\n".join(lines) + "\n"
