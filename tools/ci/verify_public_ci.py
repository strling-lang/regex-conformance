#!/usr/bin/env python3
"""Verify the public CI boundary and emit stable structured output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from public_ci_policy import evaluate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    arguments = parser.parse_args()
    violations = evaluate(Path(arguments.root).resolve())
    payload = {
        "ok": not violations,
        "violations": [item.__dict__ for item in violations],
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0 if not violations else 2)


if __name__ == "__main__":
    main()
