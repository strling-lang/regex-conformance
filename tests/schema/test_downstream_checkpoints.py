from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest

from support import ROOT
from regex_conformance_schema.downstream import (
    DownstreamProtocolError,
    build_checkpoint_index,
    load_and_validate_downstream_records,
    write_checkpoint_index,
)
from regex_conformance_schema.jsonio import canonical_bytes
from regex_conformance_schema.schema import validate_instance


SCHEMAS = (
    "coverage-shard-checkpoint-index.schema.json",
    "coverage-shard-checkpoint.schema.json",
    "downstream-compatibility-projection.schema.json",
    "downstream-lab-projection.schema.json",
)
SEMANTIC_DIGEST = "1" * 64
MANIFEST_DIGEST = "e" * 64
SOURCE_REVISION = "a" * 40


def _rcid(kind: str, digit: str) -> str:
    return f"rcid:v1:{kind}:h:jcs-sha256-v1:{digit * 64}"


def _digest(value: dict[str, object], field: str) -> str:
    body = deepcopy(value)
    body.pop(field, None)
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def _write(path: Path, value: dict[str, object]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_bytes(value) + b"\n"
    path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


def _seed(root: Path) -> None:
    schema_root = root / "schemas" / "json"
    schema_root.mkdir(parents=True)
    for name in SCHEMAS:
        shutil.copy2(ROOT / "schemas" / "json" / name, schema_root / name)
    _write(
        root
        / "semantic-corpus"
        / "snapshots"
        / "regex-semantic-features.v1.json",
        {
            "corpus_digest_sha256": SEMANTIC_DIGEST,
            "features": [{"feature_id": "feature.literal"}],
            "operations": [{"operation_id": "operation.test"}],
        },
    )
    (root / "downstream" / "checkpoints").mkdir(parents=True)


@contextmanager
def _temporary_root():
    parent = ROOT / ".conformance-state" / "downstream-checkpoint-tests"
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        yield Path(directory).resolve()


def _seal_checkpoint(
    root: Path,
    sequence: int,
    *,
    previous: dict[str, object] | None = None,
    compatibility_state: str = "certified",
    outcome: str = "supported",
    checkpoint_credited: int = 1,
    outcome_credited: int = 1,
    evidence_trace: bool = True,
) -> dict[str, object]:
    digit = str(sequence)
    shard_id = f"coverage-shard-{sequence:04d}"
    profile_id = _rcid("profile", digit)
    release_id = _rcid("release", digit)
    system_id = _rcid("system", digit)
    recipe_id = _rcid("environment-recipe", digit)
    adapter_id = _rcid("adapter-release-manifest", digit)
    profile_snapshot_path = (
        root / "registries" / "profiles" / f"profile-snapshot-{sequence:04d}.json"
    )
    profile_snapshot_sha = _write(
        profile_snapshot_path,
        {
            "profiles": [
                {
                    "nodes": [{"release_id": release_id}],
                    "profile_id": profile_id,
                }
            ],
            "systems": [{"system_id": system_id}],
        },
    )
    recipe_path = root / "environments" / f"recipe-{sequence:04d}.json"
    adapter_path = root / "adapters" / f"adapter-{sequence:04d}.json"
    recipe_sha = _write(
        recipe_path,
        {
            "environment_recipe_id": recipe_id,
            "target_profile_id": profile_id,
        },
    )
    adapter_sha = _write(
        adapter_path, {"adapter_release_manifest_id": adapter_id}
    )
    unreproducible = compatibility_state == "certified-unreproducible"
    lab = {
        "classification": {
            "derived_from_certified_evidence": True,
            "manually_authored_compatibility_truth": False,
            "primary_evidence": False,
            "website_authority": False,
        },
        "coverage_shard_id": shard_id,
        "profiles": [
            {
                "adapter_refs": []
                if unreproducible
                else [
                    {
                        "artifact_id": adapter_id,
                        "relative_path": f"adapters/adapter-{sequence:04d}.json",
                        "sha256": adapter_sha,
                    }
                ],
                "display_name": f"Synthetic profile {sequence}",
                "environment_recipe_refs": []
                if unreproducible
                else [
                    {
                        "artifact_id": recipe_id,
                        "relative_path": f"environments/recipe-{sequence:04d}.json",
                        "sha256": recipe_sha,
                    }
                ],
                "lab_eligibility": {
                    "eligible": not unreproducible,
                    "reason_code": "eligible"
                    if not unreproducible
                    else "certified-unreproducible",
                    **(
                        {}
                        if not unreproducible
                        else {"explanation": "Exact runtime cannot be reproduced."}
                    ),
                },
                "limitations": []
                if not unreproducible
                else ["Exact runtime cannot be reproduced."],
                "operations": ["operation.test"],
                "options": [],
                "profile_id": profile_id,
                "release_classification": "current",
                "release_id": release_id,
                "system_id": system_id,
            }
        ],
        "projection_id": f"{shard_id}.lab.v1",
        "schema_version": "downstream-lab-projection.v1",
        "semantic_snapshot_digest_sha256": SEMANTIC_DIGEST,
        "source_revision": SOURCE_REVISION,
    }
    lab["projection_digest_sha256"] = _digest(lab, "projection_digest_sha256")
    lab_sha = _write(
        root / "downstream" / "lab" / f"{shard_id}.v1.json", lab
    )

    if compatibility_state == "certified":
        applicable = 1
        not_applicable = 0
        limitation_digest = None
        exclusion_digest = None
    elif compatibility_state == "governed-not-applicable":
        applicable = 0
        not_applicable = 1
        limitation_digest = None
        exclusion_digest = "7" * 64
    else:
        applicable = 1
        not_applicable = 0
        limitation_digest = "6" * 64
        exclusion_digest = None
    compatibility = {
        "classification": {
            "derived_from_certified_evidence": True,
            "manually_authored_compatibility_truth": False,
            "primary_evidence": False,
            "website_authority": False,
        },
        "coverage_shard_id": shard_id,
        "profiles": [
            {
                "outcomes": [
                    {
                        "applicable_obligation_count": applicable,
                        "condition": None,
                        "coordinate_set_digest_sha256": "8" * 64,
                        "coverage_state": compatibility_state,
                        "credited_obligation_count": outcome_credited,
                        "evidence_coordinate_digest_sha256": "9" * 64
                        if evidence_trace
                        else None,
                        "evidence_manifest_sha256": MANIFEST_DIGEST
                        if evidence_trace
                        else None,
                        "feature_id": "feature.literal",
                        "governed_exclusion_digest_sha256": exclusion_digest,
                        "governed_not_applicable_obligation_count": not_applicable,
                        "limitation_digest_sha256": limitation_digest,
                        "operation_id": "operation.test",
                        "outcome": outcome,
                    }
                ],
                "profile_id": profile_id,
                "release_classification": "current",
                "release_id": release_id,
                "reproducibility_disposition": "explicitly-unreproducible"
                if unreproducible
                else "reproducibly-executable",
            }
        ],
        "projection_id": f"{shard_id}.compatibility.v1",
        "schema_version": "downstream-compatibility-projection.v1",
        "semantic_snapshot_digest_sha256": SEMANTIC_DIGEST,
        "source_revision": SOURCE_REVISION,
    }
    compatibility["projection_digest_sha256"] = _digest(
        compatibility, "projection_digest_sha256"
    )
    compatibility_sha = _write(
        root / "downstream" / "compatibility" / f"{shard_id}.v1.json",
        compatibility,
    )

    non_executable = applicable if unreproducible else 0
    planned = checkpoint_credited + non_executable
    profile_coverage = {
        "compatibility_published": True,
        "credited_coordinate_count": checkpoint_credited,
        "governed_non_executable_coordinate_count": non_executable,
        "governed_not_applicable_coordinate_count": not_applicable,
        "lab_eligible": not unreproducible,
        "limitation_digest_sha256": limitation_digest,
        "planned_applicable_coordinate_count": planned,
        "profile_id": profile_id,
        "release_classification": "current",
        "release_id": release_id,
        "reproducibility_disposition": "explicitly-unreproducible"
        if unreproducible
        else "reproducibly-executable",
        "unexpected_skip_count": 0,
    }
    checkpoint = {
        "certification": {
            "capacity_admission_pass": True,
            "certification_digest_sha256": "c" * 64,
            "completeness_conjunction_pass": True,
            "downstream_publication_gate_pass": True,
            "evidence_reconciliation_pass": True,
        },
        "checkpoint_id": shard_id,
        "compatibility_projection": {
            "projection_id": f"{shard_id}.compatibility.v1",
            "relative_path": f"downstream/compatibility/{shard_id}.v1.json",
            "sha256": compatibility_sha,
        },
        "coverage": {
            "counts": {
                "compatibility_published_profile_count": 1,
                "credited_coordinate_count": checkpoint_credited,
                "governed_non_executable_coordinate_count": non_executable,
                "governed_not_applicable_coordinate_count": not_applicable,
                "lab_eligible_profile_count": int(not unreproducible),
                "planned_applicable_coordinate_count": planned,
                "profile_count": 1,
                "unexpected_skip_count": 0,
            },
            "profiles": [profile_coverage],
        },
        "evidence_manifest": {
            "manifest_object_key": f"regex-conformance/evidence-pack-v3/manifests/{MANIFEST_DIGEST}.json",
            "manifest_sha256": MANIFEST_DIGEST,
            "pack_digest_sha256": "d" * 64,
            "readback_verified": True,
            "schema_version": "evidence-pack-manifest.v3",
            "size_bytes": 123,
        },
        "lab_projection": {
            "projection_id": f"{shard_id}.lab.v1",
            "relative_path": f"downstream/lab/{shard_id}.v1.json",
            "sha256": lab_sha,
        },
        "previous_checkpoint": None
        if previous is None
        else {
            "checkpoint_digest_sha256": previous["checkpoint_digest_sha256"],
            "checkpoint_id": previous["checkpoint_id"],
            "relative_path": f"downstream/checkpoints/{previous['checkpoint_id']}.v1.json",
        },
        "profile_snapshot": {
            "relative_path": f"registries/profiles/profile-snapshot-{sequence:04d}.json",
            "sha256": profile_snapshot_sha,
        },
        "schema_version": "coverage-shard-checkpoint.v1",
        "semantic_snapshot": {
            "relative_path": "semantic-corpus/snapshots/regex-semantic-features.v1.json",
            "semantic_digest_sha256": SEMANTIC_DIGEST,
        },
        "sequence": sequence,
        "source_revision": SOURCE_REVISION,
    }
    checkpoint["checkpoint_digest_sha256"] = _digest(
        checkpoint, "checkpoint_digest_sha256"
    )
    _write(
        root / "downstream" / "checkpoints" / f"{shard_id}.v1.json",
        checkpoint,
    )
    return checkpoint


class DownstreamCheckpointTests(unittest.TestCase):
    def test_repository_empty_index_is_deterministic(self) -> None:
        counts = load_and_validate_downstream_records(
            ROOT, validate_instance=validate_instance
        )
        self.assertEqual(
            counts,
            {
                "coverage_shard_checkpoints": 0,
                "downstream_checkpoint_indexes": 1,
            },
        )

    def test_two_checkpoint_chain_appends_without_rewriting_prefix(self) -> None:
        with _temporary_root() as root:
            _seed(root)
            first = _seal_checkpoint(root, 1)
            initial = write_checkpoint_index(root, validate_instance=validate_instance)
            self.assertEqual(initial["checkpoint_count"], 1)
            _seal_checkpoint(root, 2, previous=first)
            extended = write_checkpoint_index(root, validate_instance=validate_instance)
            self.assertEqual(extended["checkpoint_count"], 2)
            self.assertEqual(extended["entries"][:1], initial["entries"])
            self.assertEqual(
                build_checkpoint_index(root, validate_instance=validate_instance),
                extended,
            )
            load_and_validate_downstream_records(
                root, validate_instance=validate_instance
            )

    def test_unsupported_without_certified_evidence_is_rejected(self) -> None:
        with _temporary_root() as root:
            _seed(root)
            _seal_checkpoint(
                root,
                1,
                outcome="unsupported",
                evidence_trace=False,
            )
            with self.assertRaisesRegex(
                DownstreamProtocolError, "lacks exact evidence credit"
            ):
                build_checkpoint_index(root, validate_instance=validate_instance)

    def test_unknown_requires_explicit_unreproducible_disposition(self) -> None:
        with _temporary_root() as root:
            _seed(root)
            _seal_checkpoint(
                root,
                1,
                outcome="unknown",
            )
            with self.assertRaisesRegex(
                DownstreamProtocolError, "lacks exact evidence credit"
            ):
                build_checkpoint_index(root, validate_instance=validate_instance)
        with _temporary_root() as root:
            _seed(root)
            _seal_checkpoint(
                root,
                1,
                compatibility_state="certified-unreproducible",
                outcome="unknown",
                checkpoint_credited=0,
                outcome_credited=0,
                evidence_trace=False,
            )
            index = build_checkpoint_index(
                root, validate_instance=validate_instance
            )
            self.assertEqual(index["checkpoint_count"], 1)

    def test_not_applicable_requires_governed_exclusion(self) -> None:
        with _temporary_root() as root:
            _seed(root)
            _seal_checkpoint(
                root,
                1,
                compatibility_state="governed-not-applicable",
                outcome="not-applicable",
                checkpoint_credited=0,
                outcome_credited=0,
                evidence_trace=False,
            )
            index = build_checkpoint_index(
                root, validate_instance=validate_instance
            )
            self.assertEqual(index["checkpoint_count"], 1)

    def test_compatibility_counts_must_reconcile_checkpoint(self) -> None:
        with _temporary_root() as root:
            _seed(root)
            _seal_checkpoint(
                root,
                1,
                checkpoint_credited=2,
                outcome_credited=1,
            )
            with self.assertRaisesRegex(
                DownstreamProtocolError,
                "do not reconcile checkpoint coordinates",
            ):
                build_checkpoint_index(root, validate_instance=validate_instance)

    def test_checkpoint_sequence_gap_is_rejected(self) -> None:
        with _temporary_root() as root:
            _seed(root)
            _seal_checkpoint(root, 2)
            with self.assertRaisesRegex(
                DownstreamProtocolError, "contiguous sequence"
            ):
                build_checkpoint_index(root, validate_instance=validate_instance)


if __name__ == "__main__":
    unittest.main()
