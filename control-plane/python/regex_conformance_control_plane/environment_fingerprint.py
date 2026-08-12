"""JCS-derived verified environment fingerprints."""

from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterable

import rfc8785

from .environment_models import (
    EnvironmentRecipe,
    ProviderDescriptor,
    RuntimeIdentity,
    SmokeObservation,
    VerifiedArtifact,
)

CONTENT_DOMAIN = "strling.regex-conformance.content-id"
VERIFICATION_DOMAIN = "strling.regex-conformance.environment-verification"
HASH_POLICY = "jcs-sha256-v1"
ENVIRONMENT_FINGERPRINT_SCHEMA_FAMILY_ID = (
    "rcid:v1:schema-family:u7:019ff82c-9517-76fb-a67d-c461e9145384"
)
ENVIRONMENT_FINGERPRINT_SCHEMA_VERSION = "1.0.0"


def _canonical_bytes(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, UnicodeError, TypeError, ValueError) as error:
        raise ValueError(f"environment fingerprint canonicalization failed: {error}") from error


def _canonical_set(values: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    keyed = {_canonical_bytes(value): value for value in values}
    return [keyed[key] for key in sorted(keyed)]


def _normalized_values(values: Iterable[Any]) -> list[dict[str, str]]:
    return _canonical_set(
        {"name": item.name, "value": unicodedata.normalize("NFC", item.value)}
        for item in values
    )


@dataclass(frozen=True)
class FingerprintResult:
    environment_fingerprint_id: str
    verification_digest: str
    identity: dict[str, Any]
    canonical_utf8: bytes


class EnvironmentFingerprinter:
    """Derive a scientific fingerprint only from verified realized facts."""

    def fingerprint(
        self,
        *,
        recipe: EnvironmentRecipe,
        provider: ProviderDescriptor,
        artifacts: tuple[VerifiedArtifact, ...],
        runtime: RuntimeIdentity,
        smoke: tuple[SmokeObservation, ...],
    ) -> FingerprintResult:
        verification = {
            "artifacts": _canonical_set(
                {
                    "digest": item.sha256,
                    "media_type": item.media_type,
                    "name": item.name,
                    "size_bytes": item.size_bytes,
                }
                for item in artifacts
            ),
            "runtime_facts": _normalized_values(runtime.facts),
            "smoke": _canonical_set(
                {
                    "diagnostic": None if item.diagnostic is None else unicodedata.normalize("NFC", item.diagnostic),
                    "passed": item.passed,
                    "probe_id": item.probe_id,
                }
                for item in smoke
            ),
        }
        verification_bytes = _canonical_bytes({"domain": VERIFICATION_DOMAIN, "verification": verification})
        verification_digest = hashlib.sha256(verification_bytes).hexdigest()
        identity = {
            "artifacts": verification["artifacts"],
            "isolation_policy_digest": runtime.isolation_policy_digest,
            "network_policy": runtime.network_policy,
            "provider_capabilities": _canonical_set(
                {"name": item.name, "status": item.status} for item in provider.capabilities
            ),
            "provider_implementation_digest": runtime.provider_implementation_digest,
            "provider_name": provider.name,
            "provider_strategy": runtime.strategy,
            "recipe_revision": recipe.recipe_revision_id,
            "relevant_configuration": _normalized_values(runtime.relevant_configuration),
            "runtime_facts": verification["runtime_facts"],
            "target_profile": recipe.target_profile_id,
            "target_release": recipe.target_release_id,
            "verification_digest": verification_digest,
        }
        envelope = {
            "domain": CONTENT_DOMAIN,
            "hash_policy": HASH_POLICY,
            "identity": identity,
            "identity_schema_family_id": ENVIRONMENT_FINGERPRINT_SCHEMA_FAMILY_ID,
            "identity_schema_version": ENVIRONMENT_FINGERPRINT_SCHEMA_VERSION,
            "namespace": "environment-fingerprint",
        }
        canonical = _canonical_bytes(envelope)
        digest = hashlib.sha256(canonical).hexdigest()
        return FingerprintResult(
            environment_fingerprint_id=f"rcid:v1:environment-fingerprint:h:{HASH_POLICY}:{digest}",
            verification_digest=verification_digest,
            identity=identity,
            canonical_utf8=canonical,
        )
