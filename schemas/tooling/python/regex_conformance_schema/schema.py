"""JSON Schema validation for repository-owned records."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jsonschema import ValidationError, validators

from .adapters import load_and_validate_adapter_records
from .campaigns import load_and_validate_campaign_records
from .evidence import load_and_validate_evidence_records
from .errors import ConformanceDataError
from .environments import load_and_validate_environment_records
from .faults import load_and_validate_fault_records
from .jsonio import load_strict
from .qualification import load_and_validate_qualification_records
from .recovery import load_and_validate_recovery_records
from .selection import validate_vertical_slice_selection


def validate_instance(instance: Any, schema: dict[str, Any], *, source: str = "record") -> None:
    validator_class = validators.validator_for(schema)
    try:
        validator_class.check_schema(schema)
    except Exception as error:
        raise ConformanceDataError("invalid-schema", str(error), path=source) from error
    errors = sorted(validator_class(schema).iter_errors(instance), key=lambda item: list(item.absolute_path))
    if errors:
        error: ValidationError = errors[0]
        suffix = "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in error.absolute_path)
        raise ConformanceDataError("schema-validation-failed", error.message, path=f"{source}{suffix}")


def validate_file(record_path: Path | str, schema_path: Path | str) -> None:
    record_source = Path(record_path)
    schema_source = Path(schema_path)
    validate_instance(load_strict(record_source), load_strict(schema_source), source=str(record_source))


def validate_repository(root: Path) -> dict[str, int]:
    schemas = root / "schemas" / "json"
    profile_schema = load_strict(schemas / "identity-profile.schema.json")
    registry_schema = load_strict(schemas / "namespace-registry.schema.json")
    fixture_schema = load_strict(schemas / "canonical-fixture-manifest.schema.json")
    selection_schema = load_strict(schemas / "vertical-slice-selection.schema.json")

    for source in sorted(schemas.glob("*.schema.json")):
        schema = load_strict(source)
        validators.validator_for(schema).check_schema(schema)

    profiles = sorted((root / "schemas" / "identity-profiles").glob("*.json"))
    for source in profiles:
        validate_instance(load_strict(source), profile_schema, source=str(source))

    validate_instance(
        load_strict(root / "registries" / "identity" / "namespaces.v1.json"),
        registry_schema,
        source="registries/identity/namespaces.v1.json",
    )
    manifests = sorted((root / "tests" / "fixtures" / "identity").glob("manifest*.json"))
    for source in manifests:
        validate_instance(load_strict(source), fixture_schema, source=str(source))
    selections = sorted((root / "registries" / "profiles").glob("vertical-slice-archetypes*.json"))
    for source in selections:
        record = load_strict(source)
        validate_instance(record, selection_schema, source=str(source))
        validate_vertical_slice_selection(record, source=str(source))
    environment_counts = load_and_validate_environment_records(root, validate_instance=validate_instance)
    adapter_counts = load_and_validate_adapter_records(root, validate_instance=validate_instance)
    qualification_counts = load_and_validate_qualification_records(
        root, validate_instance=validate_instance
    )
    campaign_counts = load_and_validate_campaign_records(root, validate_instance=validate_instance)
    fault_counts = load_and_validate_fault_records(root, validate_instance=validate_instance)
    recovery_counts = load_and_validate_recovery_records(root, validate_instance=validate_instance)
    evidence_counts = load_and_validate_evidence_records(
        root, validate_instance=validate_instance
    )
    return {
        "schemas": len(list(schemas.glob("*.schema.json"))),
        "profiles": len(profiles),
        "manifests": len(manifests),
        "vertical_slice_selections": len(selections),
        **environment_counts,
        **adapter_counts,
        **qualification_counts,
        **campaign_counts,
        **fault_counts,
        **recovery_counts,
        **evidence_counts,
    }
