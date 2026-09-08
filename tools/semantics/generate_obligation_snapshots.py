#!/usr/bin/env python3
"""Allocate, materialize, verify, or explain semantic denominator snapshots.

This command materializes definitions only.  It does not author vectors,
realize profiles, execute targets, or compute a profile-expanded denominator.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from regex_conformance_schema.obligation_snapshots import (  # noqa: E402
    allocate_identities,
    explain,
    finalize_authority,
    materialize_core,
    verify_current,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--allocate-identities", action="store_true", help="persist reviewed identity allocations, then materialize the successor snapshots")
    mode.add_argument("--finalize-authority", action="store_true", help="advance the denominator authority index after certification inputs exist")
    mode.add_argument("--check", action="store_true", help="verify tracked snapshots, identities, report, and authority against a deterministic rebuild")
    mode.add_argument("--explain", metavar="IDENTIFIER", help="print the derivation trace for one obligation or requirement ID/key")
    arguments = parser.parse_args()
    if arguments.allocate_identities:
        allocated = allocate_identities(ROOT)
        result = {**allocated, **materialize_core(ROOT)}
    elif arguments.finalize_authority:
        result = finalize_authority(ROOT)
    elif arguments.check:
        result = verify_current(ROOT)
    elif arguments.explain:
        print(json.dumps(explain(ROOT, arguments.explain), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    else:
        result = materialize_core(ROOT)
    print(" ".join(f"{key}={result[key]}" for key in sorted(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
