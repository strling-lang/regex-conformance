#!/usr/bin/env python3
"""Build an execution-ineligible design from a pinned candidate vector manifest."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "schemas/tooling/python"))

from regex_conformance_schema.errors import fail  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict  # noqa: E402
from regex_conformance_schema.production_campaign_design import build_production_campaign_design  # noqa: E402
from regex_conformance_schema.production_vectors import load_vector_compiler_inputs  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--expected-digest", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--output", type=Path)
    mode.add_argument("--check", type=Path)
    args = parser.parse_args()
    maximum = 32 * 1024 * 1024
    with args.manifest.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        fail("campaign-design-input-size", "candidate manifest exceeds the verification limit")
    manifest = loads_strict(raw.decode("utf-8"))
    if canonical_bytes(manifest) + b"\n" != raw:
        fail("campaign-design-input-bytes", "candidate manifest is not canonical")
    families = [load_strict(path) for path in sorted((ROOT / "vectors/families").glob("*.json"))]
    result = build_production_campaign_design(
        ROOT, load_vector_compiler_inputs(ROOT), manifest, families,
        expected_manifest_digest=args.expected_digest,
    )
    encoded = canonical_bytes(result) + b"\n"
    if args.output is not None:
        with args.output.open("xb") as stream:
            stream.write(encoded)
    if args.check is not None:
        with args.check.open("rb") as stream:
            if stream.read(len(encoded) + 1) != encoded:
                fail("campaign-design-drift", "design differs from fresh compilation")
    if args.output is None and args.check is None:
        print(encoded.decode("utf-8"), end="")
    else:
        print(canonical_bytes({
            key: result[key] for key in ("design_digest_sha256", "execution_ready", "candidate_selection_count")
        }).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
