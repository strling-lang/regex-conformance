"""Command-line interface for schema, fixture, and identity operations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .errors import ConformanceDataError
from .fixtures import materialize_manifest, verify_manifest
from .identity import NamespaceRegistry, build_content_identity, generate_assigned_id
from .jsonio import canonical_bytes, load_strict
from .profile import IdentityProfile
from .schema import validate_file, validate_repository


def _root(value: str | None) -> Path:
    return Path(value).resolve() if value else Path(__file__).resolve().parents[4]


def _emit(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="regex-conformance-schema")
    top.add_argument("--root", help="repository root (normally auto-detected)")
    commands = top.add_subparsers(dest="command", required=True)
    commands.add_parser("validate-repository")
    verify = commands.add_parser("verify-fixtures")
    verify.add_argument("manifest", nargs="?", default="tests/fixtures/identity/manifest.json")
    materialize = commands.add_parser("materialize-fixtures")
    materialize.add_argument("manifest", nargs="?", default="tests/fixtures/identity/manifest.json")
    validate = commands.add_parser("validate")
    validate.add_argument("record")
    validate.add_argument("schema")
    canonicalize = commands.add_parser("canonicalize")
    canonicalize.add_argument("record")
    content = commands.add_parser("content-id")
    content.add_argument("--profile", required=True)
    content.add_argument("--namespace", required=True)
    content.add_argument("--schema-family-id", required=True)
    content.add_argument("--schema-version", required=True)
    content.add_argument("record")
    identifier = commands.add_parser("validate-id")
    identifier.add_argument("identifier")
    generate = commands.add_parser("generate-id")
    generate.add_argument("scheme", choices=["rcid", "opid"])
    generate.add_argument("namespace")
    return top


def run(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    root = _root(arguments.root)
    registry_path = root / "registries" / "identity" / "namespaces.v1.json"
    try:
        if arguments.command == "validate-repository":
            _emit({"ok": True, **validate_repository(root)})
        elif arguments.command == "verify-fixtures":
            _emit({"ok": True, **verify_manifest(root, root / arguments.manifest)})
        elif arguments.command == "materialize-fixtures":
            _emit({"ok": True, **materialize_manifest(root, root / arguments.manifest)})
        elif arguments.command == "validate":
            validate_file(root / arguments.record, root / arguments.schema)
            _emit({"ok": True})
        elif arguments.command == "canonicalize":
            sys.stdout.buffer.write(canonical_bytes(load_strict(root / arguments.record)) + b"\n")
        elif arguments.command == "content-id":
            profile = IdentityProfile.from_record(load_strict(root / arguments.profile))
            result = build_content_identity(
                registry=NamespaceRegistry.load(registry_path),
                profile=profile,
                namespace=arguments.namespace,
                identity_schema_family_id=arguments.schema_family_id,
                identity_schema_version=arguments.schema_version,
                identity=load_strict(root / arguments.record),
            )
            _emit({key: value.hex() if isinstance(value, bytes) else value for key, value in result.items()})
        elif arguments.command == "validate-id":
            parsed = NamespaceRegistry.load(registry_path).validate(arguments.identifier)
            _emit({"ok": True, **parsed.__dict__})
        elif arguments.command == "generate-id":
            _emit({"identifier": generate_assigned_id(NamespaceRegistry.load(registry_path), arguments.scheme, arguments.namespace)})
        return 0
    except (ConformanceDataError, OSError, KeyError) as error:
        if isinstance(error, ConformanceDataError):
            payload = {"ok": False, "error": {"code": error.code, "message": error.message, "path": error.path}}
        else:
            payload = {"ok": False, "error": {"code": "io-or-record-error", "message": str(error), "path": "$"}}
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2


def main() -> None:
    raise SystemExit(run())
