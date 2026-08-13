"""Backend contract and response assembly without conformance judgment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .errors import AdapterError, TargetError, UnsupportedRequest
from .manifest import AdapterManifest
from .model import Datum, ExecuteRequest, absence, diagnostic_record


@dataclass(frozen=True)
class RuntimeIdentity:
    facts: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        names = tuple(name for name, _ in self.facts)
        if not self.facts or names != tuple(sorted(names)) or len(names) != len(set(names)):
            raise ValueError("runtime identity facts must be non-empty, unique, and sorted")

    def to_record(self) -> dict[str, Any]:
        return {"facts": [{"name": name, "value": value} for name, value in self.facts]}


class AdapterBackend(Protocol):
    manifest: AdapterManifest

    def runtime_identity(self) -> RuntimeIdentity: ...

    def execute(self, request: ExecuteRequest) -> dict[str, Any]: ...


class ThinBackend:
    """Shared exact-binding checks; target semantics stay in concrete backends."""

    supported_operations: frozenset[str] = frozenset()
    supported_options: frozenset[str] = frozenset()
    supported_environment_inputs: frozenset[str] = frozenset()
    supported_domains: frozenset[str] = frozenset()

    def __init__(self, manifest: AdapterManifest) -> None:
        self.manifest = manifest

    def validate_request(self, request: ExecuteRequest) -> None:
        if request.adapter_release_manifest_id != self.manifest.manifest_id:
            raise AdapterError("adapter-binding-mismatch", "request names a different adapter release manifest")
        if request.profile_id != self.manifest.profile_id or request.target_release_id != self.manifest.target_release_id:
            raise AdapterError("target-binding-mismatch", "request profile/release differs from the certified adapter binding")
        if request.operation not in self.supported_operations:
            raise UnsupportedRequest("operation-unsupported", f"target surface does not expose {request.operation!r}")
        if len(request.subjects) != 1:
            raise UnsupportedRequest("subject-arity-unsupported", "minimal adapter operations require exactly one subject")
        domains = {request.pattern.domain, *(item.domain for item in request.subjects)}
        if request.replacement is not None:
            domains.add(request.replacement.domain)
        unsupported_domains = sorted(domains - self.supported_domains)
        if unsupported_domains:
            raise UnsupportedRequest(
                "datum-domain-unsupported", f"target profile does not expose data domains {unsupported_domains!r}"
            )
        option_names = {name for name, _ in request.options}
        unknown_options = sorted(option_names - self.supported_options)
        if unknown_options:
            raise UnsupportedRequest("option-unsupported", f"target surface does not expose options {unknown_options!r}")
        environment_names = {name for name, _ in request.environment_inputs}
        unknown_environment = sorted(environment_names - self.supported_environment_inputs)
        if unknown_environment:
            raise UnsupportedRequest(
                "environment-input-unsupported",
                f"target surface does not expose environment inputs {unknown_environment!r}",
            )
        if request.start_offset > self.native_length(request.subjects[0]):
            raise AdapterError(
                "start-offset-out-of-range",
                "start offset exceeds the subject in the target's native index basis",
                "materialization",
                "request-validation",
            )

    @staticmethod
    def native_length(datum: Datum) -> int:
        if isinstance(datum.value, (bytes, str, tuple)):
            return len(datum.value)
        raise AssertionError("unsupported materialized datum")

    def base_observation(self, request: ExecuteRequest) -> dict[str, Any]:
        return {
            "absences": [],
            "compile_status": "not-requested",
            "cursor": None,
            "execution_status": "not-requested",
            "materialization": {
                "pattern_domain": request.pattern.domain,
                "subject_domains": [item.domain for item in request.subjects],
            },
            "match_state": "not-requested",
            "matches": [],
            "native_error": None,
            "operation": {"name": request.operation, "version": "1.0.0"},
            "outputs": {"kind": "none", "values": []},
            "runtime_identity": self.runtime_identity().to_record(),
        }

    def target_error_observation(self, request: ExecuteRequest, error: TargetError) -> dict[str, Any]:
        observation = self.base_observation(request)
        diagnostic = None
        if error.diagnostic is not None:
            diagnostic = diagnostic_record(error.diagnostic, request.maximum_diagnostic_bytes)
            if diagnostic["truncated"]:
                observation["absences"].append(absence("native-error.diagnostic-tail", "truncated"))
        observation["native_error"] = {
            "class": error.error_class,
            "code": error.code,
            "diagnostic": diagnostic,
            "message": error.message[:4096] or error.error_class,
            "phase": error.phase,
            "position": error.position,
        }
        if error.phase == "compile":
            observation["compile_status"] = "rejected"
            observation["execution_status"] = "not-requested"
            observation["match_state"] = "not-applicable"
            observation["absences"].extend(
                [
                    absence("matches", "prior-layer-failure"),
                    absence("outputs", "prior-layer-failure"),
                ]
            )
        else:
            observation["compile_status"] = "accepted"
            observation["execution_status"] = "rejected"
            observation["match_state"] = "not-applicable"
            observation["absences"].extend(
                [absence("matches", "prior-layer-failure"), absence("outputs", "prior-layer-failure")]
            )
        observation["absences"] = sorted(observation["absences"], key=lambda item: (item["field"], item["reason"]))
        return observation
