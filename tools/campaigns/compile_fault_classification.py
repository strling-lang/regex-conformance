#!/usr/bin/env python3
"""Materialize the deterministic P18 deliberate-fault reference report."""

from __future__ import annotations

import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "control-plane" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_control_plane.fault_attribution import build_reference_report
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance


def main() -> int:
    report = build_reference_report()
    validate_instance(
        report,
        load_strict(ROOT / "schemas" / "json" / "fault-classification-report.schema.json"),
        source="compiled fault classification report",
    )
    destination = ROOT / "reports" / "small-scale" / "fault-classification.json"
    encoded = canonical_bytes(report) + b"\n"
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    if destination.read_bytes() != encoded:
        raise RuntimeError("fault classification report failed read-after-write verification")
    if canonical_bytes(build_reference_report()) + b"\n" != encoded:
        raise RuntimeError("fault classification is not deterministic")
    sys.stdout.buffer.write(
        canonical_bytes({"ok": True, **report["summary"]}) + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
