#!/usr/bin/env python3
"""Perform bounded independent verification of a local authoritative certificate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from local_certification import MANIFEST_PATH, LocalCertificationError, verify_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--expected-envelope-sha")
    parser.add_argument("--expected-root")
    parser.add_argument("--without-envelope", action="store_true", help="fixture-only structural verification")
    args = parser.parse_args()
    try:
        result = verify_manifest(args.root.resolve(), args.manifest, expected_envelope_sha=args.expected_envelope_sha, expected_root=args.expected_root, require_envelope=not args.without_envelope)
        print(json.dumps(result, indent=2, sort_keys=True))
    except (OSError, KeyError, ValueError, LocalCertificationError) as error:
        print(f"hosted integrity verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
