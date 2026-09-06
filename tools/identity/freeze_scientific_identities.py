#!/usr/bin/env python3
"""Allocate once or verify the permanent scientific-identity catalog."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(SCHEMA_TOOLING) not in sys.path:
    sys.path.insert(0, str(SCHEMA_TOOLING))

from regex_conformance_schema.jsonio import load_strict  # noqa: E402
from regex_conformance_schema.schema import validate_instance  # noqa: E402
from regex_conformance_schema.scientific_identity import (  # noqa: E402
    CATALOG_PATH,
    initialize_catalog,
    verify_catalog,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--initialize",
        action="store_true",
        help="allocate bindings only for current entities that have no binding",
    )
    mode.add_argument("--check", action="store_true", help="perform read-only verification")
    parser.add_argument("--effective-date", default="2026-09-06")
    arguments = parser.parse_args()
    if arguments.initialize:
        catalog = initialize_catalog(ROOT, effective_date=arguments.effective_date)
    else:
        catalog = load_strict(ROOT / CATALOG_PATH)
    validate_instance(
        load_strict(ROOT / "registries" / "identity" / "namespaces.v2.json"),
        load_strict(ROOT / "schemas" / "json" / "namespace-registry.schema.json"),
        source="registries/identity/namespaces.v2.json",
    )
    validate_instance(
        catalog,
        load_strict(ROOT / "schemas" / "json" / "scientific-identity-catalog.schema.json"),
        source=CATALOG_PATH.as_posix(),
    )
    counts = verify_catalog(ROOT, catalog)
    print(json.dumps({"ok": True, **counts}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
