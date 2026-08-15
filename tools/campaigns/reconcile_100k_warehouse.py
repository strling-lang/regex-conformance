#!/usr/bin/env python3
"""Reconcile the completed P19 100K evidence into a derived warehouse."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
    ROOT / "warehouse" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_schema.jsonio import canonical_bytes
from regex_conformance_warehouse import reconcile_scale_warehouse


def _write_report(path: Path, report: dict) -> None:
    destination = path.expanduser().resolve(strict=False)
    reports_root = (ROOT / "reports").resolve(strict=True)
    try:
        destination.relative_to(reports_root)
    except ValueError as error:
        raise RuntimeError("compact reconciliation report must remain under reports/") from error
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_bytes(report) + b"\n"
    temporary = destination.with_name(f".{destination.name}.tmp")
    if temporary.exists():
        raise RuntimeError("partial compact report already exists")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    if destination.read_bytes() != encoded:
        raise RuntimeError("compact report read-after-write verification failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--warehouse-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reuse-existing", action="store_true")
    arguments = parser.parse_args()
    report = reconcile_scale_warehouse(
        ROOT,
        arguments.campaign_root,
        arguments.warehouse_root,
        reuse_existing=arguments.reuse_existing,
    )
    _write_report(arguments.output, report)
    sys.stdout.buffer.write(canonical_bytes({"ok": True, **report}) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
