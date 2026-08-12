from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from regex_conformance_schema.identity import NamespaceRegistry
from regex_conformance_schema.jsonio import load_strict
from regex_conformance_schema.profile import IdentityProfile


def registry() -> NamespaceRegistry:
    return NamespaceRegistry.load(ROOT / "registries" / "identity" / "namespaces.v1.json")


def profile(name: str) -> IdentityProfile:
    return IdentityProfile.from_record(load_strict(ROOT / "schemas" / "identity-profiles" / name))
