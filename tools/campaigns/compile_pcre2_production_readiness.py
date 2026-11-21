#!/usr/bin/env python3
"""Replay retained native qualification and compile a non-executable comparison plan."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "schemas/tooling/python"))

from regex_conformance_schema.errors import fail  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes, loads_strict  # noqa: E402
from regex_conformance_schema.pcre2_campaign_handoff import build_handoff  # noqa: E402
from regex_conformance_schema.pcre2_production_adjudication import compile_comparison_plan  # noqa: E402
from regex_conformance_schema.pcre2_production_proposal import compile_proposal  # noqa: E402
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
    parser.add_argument("--historical-plan", action="store_true", help="replay the predecessor comparison version")
    parser.add_argument("--production-source")
    parser.add_argument("--production-envelope")
    parser.add_argument("--certification-root")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    delivery = (args.production_source, args.production_envelope, args.certification_root)
    if any(delivery) and (not all(delivery) or args.historical_plan):
        parser.error("a successor proposal requires the exact source, envelope and certification root together")
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
        successor_root=None if args.historical_plan else ROOT,
    )
    result = {"qualified_applicability": applicability, "comparison_plan": plan}
    if all(delivery):
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        if head != args.production_envelope:
            fail("pcre2-proposal-unverified-envelope", "the exact certification envelope must be checked out")
        sys.path.insert(0, str(ROOT / "tools/ci"))
        from local_certification import MANIFEST_PATH, verify_manifest

        verified = verify_manifest(
            ROOT, MANIFEST_PATH, expected_envelope_sha=head, expected_root=args.certification_root, require_envelope=True,
        )
        if verified["certified_source_sha"] != args.production_source:
            fail("pcre2-proposal-unverified-source", "certificate binds a different source")
        result["campaign_proposal"] = compile_proposal(
            ROOT, plan, applicability, preflight, source_sha=args.production_source,
            envelope_sha=args.production_envelope, certification_root=args.certification_root,
        )
    encoded = canonical_bytes(result) + b"\n"
    if args.output:
        with args.output.open("xb") as stream:
            stream.write(encoded)
    else:
        sys.stdout.buffer.write(encoded)


if __name__ == "__main__":
    main()
