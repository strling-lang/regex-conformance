#!/usr/bin/env python3
"""Run one post-vertical-slice qualification adapter over bounded frames."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = ROOT / "adapters" / "python"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from regex_conformance_adapters.errors import AdapterError
from regex_conformance_adapters.pcre2_dfa import Pcre2DfaBackend
from regex_conformance_adapters.qualification_manifest import load_qualification_manifest
from regex_conformance_adapters.server import AdapterServer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="strling-regex-qualification-adapter")
    parser.add_argument("--selection-key", required=True, choices=("pcre2-dfa",))
    parser.add_argument("--runtime-binding", required=True)
    arguments = parser.parse_args(argv)
    try:
        package = load_qualification_manifest(ROOT, arguments.selection_key)
        backend = Pcre2DfaBackend(package, Path(arguments.runtime_binding))
        return AdapterServer(backend).serve(sys.stdin.buffer, sys.stdout.buffer)
    except (AdapterError, OSError, ValueError) as error:
        code = error.code if isinstance(error, AdapterError) else "adapter-startup-failed"
        message = error.message if isinstance(error, AdapterError) else type(error).__name__
        print(json.dumps({"error": {"code": code, "message": message}, "ok": False}, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
