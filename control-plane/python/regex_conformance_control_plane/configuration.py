"""Read-only machine-doctor configuration with no implicit trust inference."""

from __future__ import annotations

import os
import platform
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

TRUST_CLASSES = frozenset({"unknown", "development", "trusted_executioner", "untrusted_public"})
POOL_KINDS = (
    "persistent_disk",
    "environment_cache",
    "build_scratch",
    "execution_scratch",
    "result_spool",
)
POOL_ENVIRONMENT = {
    "persistent_disk": "STRLING_REGEX_PERSISTENT_PATH",
    "environment_cache": "STRLING_REGEX_CACHE_PATH",
    "build_scratch": "STRLING_REGEX_BUILD_SCRATCH_PATH",
    "execution_scratch": "STRLING_REGEX_EXECUTION_SCRATCH_PATH",
    "result_spool": "STRLING_REGEX_SPOOL_PATH",
}


def _default_bases(environment: Mapping[str, str], system: str) -> tuple[Path, Path]:
    home = Path(environment.get("USERPROFILE") or environment.get("HOME") or str(Path.home()))
    normalized = system.casefold()
    if normalized == "windows":
        state = Path(environment.get("LOCALAPPDATA", home / "AppData" / "Local")) / "STRling" / "RegexConformance"
        cache = state / "Cache"
    elif normalized == "darwin":
        state = home / "Library" / "Application Support" / "STRling" / "RegexConformance"
        cache = home / "Library" / "Caches" / "STRling" / "RegexConformance"
    else:
        state = Path(environment.get("XDG_STATE_HOME", home / ".local" / "state")) / "strling-regex-conformance"
        cache = Path(environment.get("XDG_CACHE_HOME", home / ".cache")) / "strling-regex-conformance"
    return state, cache


def default_pool_paths(environment: Mapping[str, str], system: str) -> dict[str, Path]:
    state, cache = _default_bases(environment, system)
    scratch = Path(environment.get("TMPDIR") or environment.get("TEMP") or tempfile.gettempdir()) / "strling-regex-conformance"
    return {
        "persistent_disk": state,
        "environment_cache": cache,
        "build_scratch": scratch / "build",
        "execution_scratch": scratch / "execution",
        "result_spool": state / "spool",
    }


@dataclass(frozen=True)
class DoctorConfiguration:
    trust_class: str
    trust_source: str
    inventory_max_age_seconds: int
    pool_paths: tuple[tuple[str, Path], ...]

    def __post_init__(self) -> None:
        if self.inventory_max_age_seconds <= 0:
            raise ValueError("inventory max age must be a positive number of seconds")
        kinds = [kind for kind, _ in self.pool_paths]
        if sorted(kinds) != sorted(POOL_KINDS) or len(set(kinds)) != len(POOL_KINDS):
            raise ValueError("configuration must define each typed disk pool exactly once")

    @property
    def trust_is_valid(self) -> bool:
        return self.trust_class in TRUST_CLASSES

    def paths(self) -> dict[str, Path]:
        return dict(self.pool_paths)

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
        *,
        trust_override: str | None = None,
        pool_overrides: Mapping[str, Path] | None = None,
        inventory_max_age_seconds: int = 300,
        system: str | None = None,
    ) -> "DoctorConfiguration":
        values = dict(os.environ if environment is None else environment)
        selected_system = system or platform.system()
        paths = default_pool_paths(values, selected_system)
        for kind, variable in POOL_ENVIRONMENT.items():
            if values.get(variable):
                paths[kind] = Path(values[variable])
        for kind, path in (pool_overrides or {}).items():
            if kind not in POOL_KINDS:
                raise ValueError(f"unknown pool kind: {kind}")
            paths[kind] = Path(path)
        if trust_override is not None:
            trust_class = trust_override
            trust_source = "command-line"
        elif values.get("STRLING_REGEX_TRUST_CLASS"):
            trust_class = values["STRLING_REGEX_TRUST_CLASS"]
            trust_source = "environment"
        else:
            trust_class = "unknown"
            trust_source = "default"
        return cls(
            trust_class=trust_class,
            trust_source=trust_source,
            inventory_max_age_seconds=inventory_max_age_seconds,
            pool_paths=tuple(sorted(paths.items())),
        )
