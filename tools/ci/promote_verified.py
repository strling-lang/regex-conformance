#!/usr/bin/env python3
"""Promote one caller-verified codex/* commit through local main by fast-forward."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from promotion_policy import PromotionPolicyError, build_plan, promote


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--root", type=Path, default=Path.cwd(), help="repository root")
    value.add_argument("--verified-sha", required=True, help="full commit SHA that passed task verification")
    value.add_argument("--source", help="checked-out codex/* source branch; defaults to current branch")
    value.add_argument("--target", default="main", help="target branch (default: main)")
    value.add_argument("--remote", default="origin", help="Git remote (default: origin)")
    value.add_argument("--dry-run", action="store_true", help="verify and print the promotion plan without mutating Git")
    return value


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        plan = build_plan(
            arguments.root.resolve(),
            verified_sha=arguments.verified_sha,
            source_branch=arguments.source,
            target_branch=arguments.target,
            remote=arguments.remote,
        )
        if not arguments.dry_run:
            promote(arguments.root.resolve(), plan)
        print(plan.as_json(promoted=not arguments.dry_run))
    except (OSError, ValueError, PromotionPolicyError) as error:
        print(f"promotion rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
