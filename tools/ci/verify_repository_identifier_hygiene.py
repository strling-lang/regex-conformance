#!/usr/bin/env python3
"""Keep external planning codes out of durable human-authored repository text."""

from __future__ import annotations

import ast
import hashlib
import io
import re
import subprocess
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path


TRACKER_CODE = re.compile(
    r"\b(?:P[0-9]{2}[A-Z]?(?:-[TGM][0-9]{2}[A-Z]?)?|[DQR][0-9]{3})\b"
)
DOCUMENT_SUFFIXES = {".md", ".rst", ".adoc"}
HASH_COMMENT_SUFFIXES = {".cfg", ".ini", ".ps1", ".sh", ".toml", ".yaml", ".yml"}
SLASH_COMMENT_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp", ".js", ".jsx", ".mjs", ".ts", ".tsx"}

# These exact source bytes are inputs to historical, identity-bound generated
# artifacts. A changed file loses the exception automatically; removing its old
# docstring wording during a separately governed regeneration also removes the
# need for an exception.
IDENTITY_BOUND_SOURCE_SHA256 = {
    "adapters/python/regex_conformance_adapters/__init__.py": "4e86ae623ce844160e65da3fe8285856ff61c872d74887d38ad5d7df381b8537",
    "adapters/python/regex_conformance_adapters/qualification_manifest.py": "a2165fcb3db8f3fc8044ea5336f89ed6efe65fc900b5fd59e5d764468793189b",
    "campaigns/python/regex_conformance_qualification/__init__.py": "fe66b9df84ff71beef260dfec27ae434f79467d8614425c91310b88091d78ccb",
    "campaigns/python/regex_conformance_qualification/compiler.py": "fc8542ad88906e2002d379c0046a645a5a85b44fcec6694b80d4dfb460d17ebd",
    "campaigns/python/regex_conformance_scale/capacity_plan.py": "648fb231e4c15cffcfbfe3812c6106926e9d5dce6159a83c9d3642805a0028d2",
    "campaigns/python/regex_conformance_scale/factorized_evidence.py": "64d219d9ab5d6e941028cc4de71da6b40a928df56b7314e025f29ec238e09ef0",
    "campaigns/python/regex_conformance_scale/universe_forecast.py": "86dc4f4fb726d4650c104899d529ad716b599802850c319ae4063c4c31850791",
    "control-plane/python/regex_conformance_control_plane/certified_environments.py": "937e48a84b9c49c788c89764cfa9375f4a61dd3668286bbc068e0e2d8e77fa6e",
    "control-plane/python/regex_conformance_control_plane/disk_pressure_qualification.py": "ca91eec37cc196f786b6ef9a393f8a24264408386356c0d8feb41380e2924b0d",
    "scheduler/python/regex_conformance_scheduler/recovery.py": "0ce629ef099eb5c5507fa0861131e9c62e05a6574e0f204dcd7e1176571391f3",
    "schemas/tooling/python/regex_conformance_schema/qualification.py": "0d2f06b639c4372f31c4fab9d091aa38e5542a83e631406a1422375398d6de82",
    "schemas/tooling/python/regex_conformance_schema/selection.py": "70222e47786fd8b30f282952baa79bdf39e7d95613c04f5258ae1f4b16704195",
    "tools/adapters/certify_minimal.py": "18b6c884bb7121ce7de6f25606fa1122dc97d072e187a663d4e85100dac5dfb1",
    "tools/campaigns/compile_evidence_pack_v2.py": "f0519e7f0c4a446cf7c0f2aecc6971969b7f972a34e2d1252b40525bbf05d87c",
    "tools/campaigns/compile_factorized_evidence_forecast.py": "f4a30320b799b5d7f2287fbb69269e56a1814fc5e2090eb3ddb3b7db77beb97d",
    "tools/campaigns/compile_fault_classification.py": "d1d5ca74f6b65a35f286800cbd1138dff8444d792dc8abab65d0d2ef0b65cef3",
    "tools/campaigns/compile_full_known_universe_forecast.py": "25d92b1bce833360ccdbc43975bfc49384e09cd22f40dcfe1a8d4de930b7afd6",
    "tools/campaigns/compile_million_scale_capacity_plan.py": "6456af35eaf26db1cc0b8c4637c997a7f7bb80d95405b394b1dd733b29b59dd8",
    "tools/campaigns/compile_small_scale.py": "35bc93cf735ebf3112433a15c827fa98d493030ffc1f79cd9addbfc3a6441c54",
    "tools/campaigns/exercise_faults.py": "6486dcb412cb054b7cbc2d08a0e6528f47396e3c857dc56ffd7a136c772381c4",
    "tools/campaigns/exercise_restart_resume.py": "d66bab4710edc7b3c258015cd82757a7a380e19090d35b3a2b8d1bb974ba5520",
    "tools/campaigns/reconcile_100k_warehouse.py": "a86b2ecd75c39d23db4e137199a52f1b799b3b2aa8ed156850796e7db9c35c4a",
    "tools/control_plane/compile_cache_disk_pressure_qualification.py": "68eb5f49d1f9d29e6da704545cad65467bb376f1bcfe432c482a1929d73f0aa5",
    "tools/environments/certify_minimal.py": "8839d5189acf4d342b88e4955496e0c4a5c70bb808832962e2963f917c735776",
    "warehouse/python/regex_conformance_warehouse/scale_reconciliation.py": "4df39313af444900369994147d8db703162ceb4e1203869961c996593966baf8",
}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    code: str
    surface: str


def _tracked_files(root: Path) -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [root / item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]


def _matches(path: str, line: int, text: str, surface: str) -> list[Finding]:
    return [Finding(path, line, match.group(0), surface) for match in TRACKER_CODE.finditer(text)]


def _python_findings(relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        if token.type == tokenize.COMMENT:
            findings.extend(_matches(relative, token.start[0], token.string, "comment"))

    tree = ast.parse(text, filename=relative)
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            findings.extend(_matches(relative, first.lineno, first.value.value, "docstring"))
    return findings


def _hash_comment_findings(relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        marker = line.find("#")
        if marker >= 0:
            findings.extend(_matches(relative, line_number, line[marker:], "comment"))
    return findings


def _slash_comment_findings(relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    in_block = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        comment = ""
        if in_block:
            comment = line
            if "*/" in line:
                in_block = False
        elif "/*" in line:
            comment = line.split("/*", 1)[1]
            in_block = "*/" not in comment
        elif "//" in line:
            comment = line.split("//", 1)[1]
        if comment:
            findings.extend(_matches(relative, line_number, comment, "comment"))
    return findings


def scan(root: Path) -> tuple[int, list[Finding], list[Finding]]:
    violations: list[Finding] = []
    identity_bound: list[Finding] = []
    scanned = 0
    for path in _tracked_files(root):
        relative = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        if suffix not in DOCUMENT_SUFFIXES | HASH_COMMENT_SUFFIXES | SLASH_COMMENT_SUFFIXES | {".py"} and path.name != ".gitattributes":
            continue
        scanned += 1
        text = path.read_text(encoding="utf-8")
        if suffix in DOCUMENT_SUFFIXES:
            findings = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                findings.extend(_matches(relative, line_number, line, "documentation"))
        elif suffix == ".py":
            findings = _python_findings(relative, text)
        elif suffix in SLASH_COMMENT_SUFFIXES:
            findings = _slash_comment_findings(relative, text)
        else:
            findings = _hash_comment_findings(relative, text)

        expected_hash = IDENTITY_BOUND_SOURCE_SHA256.get(relative)
        if findings and expected_hash == hashlib.sha256(path.read_bytes()).hexdigest():
            identity_bound.extend(findings)
        else:
            violations.extend(findings)
    return scanned, violations, identity_bound


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    scanned, violations, identity_bound = scan(root)
    for finding in violations:
        print(f"{finding.path}:{finding.line}: {finding.surface}: {finding.code}", file=sys.stderr)
    print(
        "repository identifier hygiene "
        f"scanned={scanned} violations={len(violations)} "
        f"identity_bound_exceptions={len(identity_bound)}"
    )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
