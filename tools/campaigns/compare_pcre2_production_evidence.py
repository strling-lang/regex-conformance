#!/usr/bin/env python3
"""Compare exact local PCRE2 observations after independent evidence admission."""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "schemas/tooling/python"))

from regex_conformance_schema.jsonio import canonical_bytes, loads_strict
from regex_conformance_schema.pcre2_production_adjudication import compare_production_lineage


def _canonical_input(path: Path) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(16_777_217)
    if len(raw) > 16_777_216:
        raise ValueError("input exceeds the bounded reader")
    record = loads_strict(raw.decode("utf-8"))
    if raw != canonical_bytes(record) + b"\n":
        raise ValueError("input is not the exact canonical record")
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("readiness", "reconciled-lineage", "admission", "output"):
        parser.add_argument(f"--{key}", type=Path, required=True)
    for key in ("expected-proposal", "expected-plan", "expected-admission"):
        parser.add_argument(f"--{key}", required=True)
    args = parser.parse_args()
    readiness = _canonical_input(args.readiness)
    evidence = _canonical_input(args.reconciled_lineage)
    if evidence["lineage"] is None:
        raise ValueError("no independently verifiable physical attempt lineage is available")
    trace = compare_production_lineage(
        ROOT, readiness["comparison_plan"], evidence["lineage"], _canonical_input(args.admission),
        expected_plan_digest=args.expected_plan, expected_admission_digest=args.expected_admission,
        native_evidence=evidence["native_receipts"], proposal=readiness["campaign_proposal"],
        expected_proposal_digest=args.expected_proposal,
    )
    with args.output.open("xb") as stream:
        stream.write(canonical_bytes(trace) + b"\n")


if __name__ == "__main__":
    main()
