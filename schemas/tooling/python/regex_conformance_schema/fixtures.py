"""Cross-language materialization and verification of identity fixtures."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from .errors import ConformanceDataError, fail
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, dump_pretty, load_strict
from .profile import IdentityProfile


def _profile(root: Path, name: str) -> IdentityProfile:
    return IdentityProfile.from_record(load_strict(root / "schemas" / "identity-profiles" / name))


def _oracle(root: Path, value: Any) -> dict[str, Any]:
    source = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    command = ["node", str(root / "schemas" / "tooling" / "node" / "jcs_oracle.mjs")]
    try:
        completed = subprocess.run(
            command,
            input=source,
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        )
    except FileNotFoundError as error:
        raise ConformanceDataError("oracle-unavailable", "Node.js was not found") from error
    except subprocess.TimeoutExpired as error:
        raise ConformanceDataError("oracle-timeout", "Node.js oracle exceeded 10 seconds") from error
    except subprocess.CalledProcessError as error:
        raise ConformanceDataError("oracle-failed", error.stderr.strip() or "Node.js oracle failed") from error
    return json.loads(completed.stdout)


def _canonical_result(root: Path, value: Any) -> dict[str, Any]:
    encoded = canonical_bytes(value)
    python = {
        "canonical_utf8_hex": encoded.hex(),
        "canonical_byte_length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }
    node = _oracle(root, value)
    if python != node:
        fail("oracle-disagreement", f"Python and Node canonicalization disagree: {python!r} != {node!r}")
    return python


def _content_result(root: Path, registry: NamespaceRegistry, case: dict[str, Any]) -> dict[str, Any]:
    result = build_content_identity(
        registry=registry,
        profile=_profile(root, case["profile"]),
        namespace=case["namespace"],
        identity_schema_family_id=case["identity_schema_family_id"],
        identity_schema_version=case["identity_schema_version"],
        identity=case["identity"],
    )
    node = _oracle(root, result["envelope"])
    python = {
        "canonical_utf8_hex": result["canonical_utf8"].hex(),
        "canonical_byte_length": result["canonical_byte_length"],
        "sha256": result["sha256"],
    }
    if python != node:
        fail("oracle-disagreement", f"Python and Node content envelopes disagree: {python!r} != {node!r}")
    return {
        "projection": result["projection"],
        **python,
        "content_id": result["content_id"],
    }


def materialize_manifest(root: Path, manifest_path: Path) -> dict[str, int]:
    manifest = load_strict(manifest_path)
    registry = NamespaceRegistry.load(root / "registries" / "identity" / "namespaces.v1.json")
    counts = {"jcs": 0, "content-id": 0, "projection-error": 0}
    for case in manifest["cases"]:
        counts[case["kind"]] += 1
        if case["kind"] == "jcs":
            case["expected"] = _canonical_result(root, case["input"])
        elif case["kind"] == "content-id":
            case["expected"] = _content_result(root, registry, case)
    manifest_path.write_text(dump_pretty(manifest), encoding="utf-8", newline="\n")
    return counts


def verify_manifest(root: Path, manifest_path: Path) -> dict[str, int]:
    manifest = load_strict(manifest_path)
    registry = NamespaceRegistry.load(root / "registries" / "identity" / "namespaces.v1.json")
    results: dict[str, dict[str, Any]] = {}
    counts = {"jcs": 0, "content-id": 0, "projection-error": 0, "assertions": 0}
    for case in manifest["cases"]:
        case_id = case["case_id"]
        if case_id in results:
            fail("duplicate-fixture-id", f"duplicate fixture case {case_id!r}")
        counts[case["kind"]] += 1
        if case["kind"] == "jcs":
            actual = _canonical_result(root, case["input"])
            if actual != case["expected"]:
                fail("fixture-mismatch", f"fixture {case_id!r} does not match its expected canonical result")
            results[case_id] = actual
        elif case["kind"] == "content-id":
            actual = _content_result(root, registry, case)
            if actual != case["expected"]:
                fail("fixture-mismatch", f"fixture {case_id!r} does not match its expected content result")
            results[case_id] = actual
        else:
            try:
                _profile(root, case["profile"]).project(case["identity"])
            except ConformanceDataError as error:
                if error.code != case["error_code"]:
                    fail("wrong-fixture-error", f"fixture {case_id!r} produced {error.code!r}, expected {case['error_code']!r}")
            else:
                fail("missing-fixture-error", f"fixture {case_id!r} unexpectedly projected successfully")
            results[case_id] = {"error_code": case["error_code"]}

    for assertion in manifest["assertions"]:
        counts["assertions"] += 1
        cases = [results[case_id] for case_id in assertion["cases"]]
        field = "content_id" if assertion["kind"].endswith("id") else "canonical_utf8_hex"
        values = [case[field] for case in cases]
        equal_expected = assertion["kind"].startswith("equal")
        passed = len(set(values)) == 1 if equal_expected else len(set(values)) == len(values)
        if not passed:
            fail("fixture-assertion-failed", f"{assertion['kind']} failed for {assertion['cases']!r}")
    return counts
