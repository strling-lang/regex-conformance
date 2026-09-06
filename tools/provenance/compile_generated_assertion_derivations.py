#!/usr/bin/env python3
"""Build or verify the generated-assertion derivation inventory."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(SCHEMA_TOOLING) not in sys.path:
    sys.path.insert(0, str(SCHEMA_TOOLING))

from regex_conformance_schema.derivation import (  # noqa: E402
    CATALOG_PATH,
    SCHEMA_PATH,
    build_catalog,
    verify_catalog,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict  # noqa: E402
from regex_conformance_schema.schema import validate_instance  # noqa: E402


def _write(path: Path, payload: dict[str, object]) -> None:
    encoded = canonical_bytes(payload) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != encoded:
        raise RuntimeError(f"read-after-write verification failed for {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the tracked inventory")
    arguments = parser.parse_args()
    built = build_catalog(ROOT)
    validate_instance(built, load_strict(ROOT / SCHEMA_PATH), source=SCHEMA_PATH.as_posix())
    destination = ROOT / CATALOG_PATH
    if arguments.check:
        verify_catalog(ROOT)
    else:
        _write(destination, built)
        verify_catalog(ROOT)
        if canonical_bytes(build_catalog(ROOT)) + b"\n" != destination.read_bytes():
            raise RuntimeError("second inventory build is not deterministic")
    summary = built["coverage_summary"]
    print(
        f"artifacts={summary['inventoried_artifacts']} "
        f"groups={summary['assertion_groups']} "
        f"assertions={summary['assertion_occurrences']} "
        f"ambiguous={summary['previously_ambiguous_occurrences']} "
        f"count_contracts={summary['count_contracts']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
