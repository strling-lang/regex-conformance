#!/usr/bin/env python3
"""Run one pinned adapter over bounded framed stdin/stdout."""

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
from regex_conformance_adapters.manifest import load_manifest
from regex_conformance_adapters.mysql_regex import DockerSqlExecutor, MysqlRegexBackend
from regex_conformance_adapters.pcre2 import Pcre2Backend
from regex_conformance_adapters.python_re import PythonReBackend
from regex_conformance_adapters.server import AdapterServer


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="strling-regex-adapter")
    value.add_argument("--selection-key", required=True, choices=("mysql-regex", "pcre2-ordinary", "python-re"))
    value.add_argument("--runtime-binding")
    return value


def backend(selection_key: str, runtime_binding: str | None):
    manifest = load_manifest(ROOT, selection_key)
    if selection_key == "python-re":
        if runtime_binding is not None:
            raise AdapterError("runtime-binding-unexpected", "CPython adapter runs inside its bound runtime")
        return PythonReBackend(manifest)
    if runtime_binding is None:
        raise AdapterError("runtime-binding-missing", f"{selection_key} requires an exact realized runtime binding")
    if selection_key == "pcre2-ordinary":
        return Pcre2Backend(manifest, Path(runtime_binding))
    return MysqlRegexBackend(manifest, DockerSqlExecutor(runtime_binding))


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        implementation = backend(arguments.selection_key, arguments.runtime_binding)
        return AdapterServer(implementation).serve(sys.stdin.buffer, sys.stdout.buffer)
    except AdapterError as error:
        payload = {"error": {"code": error.code, "message": error.message}, "ok": False}
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
