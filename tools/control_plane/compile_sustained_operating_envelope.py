#!/usr/bin/env python3
"""Validate external envelope checkpoints and deterministically compile a report."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "control-plane" / "python"
if str(CONTROL_PLANE) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE))

from regex_conformance_control_plane.operating_envelope import (  # noqa: E402
    OperatingEnvelopeError,
    build_report,
    canonical_artifact_bytes,
    load_checkpoint_chain,
    load_plan,
    verify_plan_source_bindings,
)


DEFAULT_PLAN = ROOT / "control-plane" / "qualification" / "sustained-operating-envelope.v1.json"


def _outside_repository(path: Path, label: str, *, must_exist: bool) -> Path:
    unresolved = path.expanduser().absolute()
    for current in (unresolved, *unresolved.parents):
        if current.exists() and (
            current.is_symlink() or bool(getattr(current, "is_junction", lambda: False)())
        ):
            raise OperatingEnvelopeError(f"{label} must not traverse a symlink or junction")
    candidate = unresolved.resolve(strict=must_exist)
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError:
        return candidate
    raise OperatingEnvelopeError(f"{label} must remain outside the repository")


def _write_new(path: Path, payload: bytes) -> None:
    destination = _outside_repository(path, "operating-envelope report", must_exist=False)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.is_symlink():
        raise OperatingEnvelopeError("operating-envelope report must not be link-backed")
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except FileExistsError as error:
        raise OperatingEnvelopeError("operating-envelope reports are immutable and cannot be overwritten") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compile a non-canonical report from external append-only operating-envelope checkpoints."
    )
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--checkpoint-root", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args(argv)
    try:
        plan = load_plan(arguments.plan)
        verify_plan_source_bindings(ROOT, plan)
        checkpoint_root = _outside_repository(
            arguments.checkpoint_root, "operating-envelope checkpoint root", must_exist=True
        )
        checkpoints = load_checkpoint_chain(checkpoint_root, plan)
        payload = canonical_artifact_bytes(build_report(plan, checkpoints))
        if arguments.report is not None:
            _write_new(arguments.report, payload)
        sys.stdout.buffer.write(payload)
        return 0
    except (OSError, OperatingEnvelopeError, ValueError) as error:
        parser.exit(2, f"operating-envelope validation failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
