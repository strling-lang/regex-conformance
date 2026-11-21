#!/usr/bin/env python3
"""Replay retained native qualification and compile a non-executable comparison plan."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "schemas/tooling/python"))

from regex_conformance_schema.errors import fail  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes, loads_strict  # noqa: E402
from regex_conformance_schema.pcre2_campaign_handoff import build_handoff  # noqa: E402
from regex_conformance_schema.pcre2_production_adjudication import compile_comparison_plan  # noqa: E402
from regex_conformance_schema.pcre2_qualified_applicability import compile_qualified_applicability  # noqa: E402


def read(path: Path, limit: int = 4_194_304) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        fail("pcre2-readiness-input-size", "input exceeds the bounded offline reader", str(path))
    return raw


def read_json(path: Path) -> dict:
    raw = read(path)
    parsed = loads_strict(raw.decode("utf-8"))
    if raw != canonical_bytes(parsed) + b"\n":
        fail("pcre2-readiness-input-canonical", "input is not stored in canonical bytes", str(path))
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "oracle-review", "preflight", "qualification"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    for name in ("expected-manifest", "expected-review", "expected-preflight", "expected-qualification", "protected-head"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    manifest, review, preflight = (read_json(path) for path in (args.manifest, args.oracle_review, args.preflight))
    qualification = read(args.qualification, 2_097_152)
    applicability = compile_qualified_applicability(
        ROOT, manifest, review, qualification, expected_manifest_digest=args.expected_manifest,
        expected_review_digest=args.expected_review, expected_qualification_sha256=args.expected_qualification,
        protected_head=args.protected_head,
    )
    handoff = build_handoff(ROOT, review, expected_review_digest=args.expected_review)
    plan = compile_comparison_plan(
        handoff, applicability, preflight, handoff_digest=handoff["handoff_digest_sha256"],
        applicability_digest=applicability["report_digest_sha256"], preflight_digest=args.expected_preflight,
    )
    encoded = canonical_bytes({"qualified_applicability": applicability, "comparison_plan": plan}) + b"\n"
    if args.output:
        with args.output.open("xb") as stream:
            stream.write(encoded)
    else:
        sys.stdout.buffer.write(encoded)


if __name__ == "__main__":
    main()
