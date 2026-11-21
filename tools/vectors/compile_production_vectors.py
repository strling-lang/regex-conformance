#!/usr/bin/env python3
"""Compile or verify a deterministic candidate production-vector manifest."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "schemas" / "tooling" / "python"))

from regex_conformance_schema.errors import fail  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes, loads_strict  # noqa: E402
from regex_conformance_schema.production_vectors import (  # noqa: E402
    compile_vector_manifest,
    load_vector_compiler_inputs,
)


MAX_FAMILY_FILES = 4096
MAX_FAMILY_FILE_BYTES = 1024 * 1024
MAX_FAMILY_INPUT_BYTES = 32 * 1024 * 1024


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("families", nargs="+", type=Path, help="candidate family definition files")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--output", type=Path, help="write a new canonical manifest")
    output.add_argument("--check", type=Path, help="verify an existing manifest byte for byte")
    args = parser.parse_args()

    if len(args.families) > MAX_FAMILY_FILES:
        fail("vector-family-file-count", "too many family definitions for one manifest")
    families = []
    input_bytes = 0
    for path in args.families:
        with path.open("rb") as stream:
            raw = stream.read(MAX_FAMILY_FILE_BYTES + 1)
        input_bytes += len(raw)
        if len(raw) > MAX_FAMILY_FILE_BYTES or input_bytes > MAX_FAMILY_INPUT_BYTES:
            fail("vector-family-file-size", "family definitions exceed the input byte limit", str(path))
        families.append(loads_strict(raw.decode("utf-8")))
    manifest = compile_vector_manifest(load_vector_compiler_inputs(ROOT), families)
    encoded = canonical_bytes(manifest) + b"\n"
    if args.output is not None:
        with args.output.open("xb") as stream:
            stream.write(encoded)
    if args.check is not None:
        with args.check.open("rb") as stream:
            if stream.read(len(encoded) + 1) != encoded:
                fail("vector-manifest-drift", "manifest differs from fresh expansion", str(args.check))
    print(canonical_bytes({"manifest_digest_sha256": manifest["manifest_digest_sha256"], **manifest["counts"]}).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
