#!/usr/bin/env python3
"""Materialize, verify, or evaluate the versioned C1-C7 certification contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from regex_conformance_schema.certification import (  # noqa: E402
    CONTRACT_PATH,
    evaluate,
    materialize_repository_certification,
    verify_repository_certification,
)
from regex_conformance_schema.jsonio import load_strict  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify all tracked certification artifacts")
    parser.add_argument("--input", help="evaluate one certification-input-set JSON without writing")
    arguments = parser.parse_args()
    if arguments.input:
        report = evaluate(ROOT, load_strict(ROOT / CONTRACT_PATH), load_strict(Path(arguments.input)))
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0
    result = verify_repository_certification(ROOT) if arguments.check else materialize_repository_certification(ROOT)
    print(" ".join(f"{key}={result[key]}" for key in sorted(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
