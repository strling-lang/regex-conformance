#!/usr/bin/env python3
"""Run expensive authoritative checks locally and write the certification manifest."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from local_certification import MANIFEST_PATH, LocalCertificationError, build_manifest, require_clean_source, run_local_suite, write_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        source_sha = require_clean_source(root)
        results = run_local_suite(root)
        if require_clean_source(root) != source_sha:
            raise LocalCertificationError("source changed while local certification ran")
        manifest = build_manifest(root, source_sha, results)
        write_manifest(root, args.manifest, manifest)
        print(json.dumps({"result": "PASS", "certified_source_sha": source_sha, "manifest": str(args.manifest), "local_certification_root": manifest["local_certification_root"]}, indent=2, sort_keys=True))
    except (OSError, subprocess.SubprocessError, LocalCertificationError) as error:
        print(f"local certification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
