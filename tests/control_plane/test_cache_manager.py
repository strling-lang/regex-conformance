from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "control-plane" / "python"
if str(CONTROL_PLANE) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE))

from regex_conformance_control_plane.cache_manager import (
    CacheManager,
    DeletionResult,
    FilesystemCacheProvider,
    TransferIntegrityError,
    TransferManager,
)
from regex_conformance_control_plane.cache_models import (
    CacheEntry,
    CacheReality,
    CleanupPlan,
    EvictionCandidate,
    EvictionPolicy,
)
from regex_conformance_control_plane.controller import ControlPlaneController, ControlPlaneServices

FIXTURE = ROOT / "tests" / "control_plane" / "fixtures" / "cache_operations.json"
SCHEMA = ROOT / "schemas" / "json" / "cache-operations.schema.json"
NOW = "2026-08-12T23:00:30+00:00"
OBSERVED = "2026-08-12T23:00:00Z"
SHA_A = "a" * 64
CONTENT_ID = f"rcid:v1:artifact-revision:h:jcs-sha256-v1:{SHA_A}"


class FixedClock:
    def now(self) -> datetime:
        return datetime.fromisoformat(NOW)


class FixedIds:
    def __init__(self) -> None:
        self.cleanup_sequence = 1
        self.transfer_sequence = 1

    def new_cleanup_id(self) -> str:
        value = f"opid:v1:cache-cleanup:u7:019ff82c-9517-76fb-a67d-c461e916{self.cleanup_sequence:04x}"
        self.cleanup_sequence += 1
        return value

    def new_transfer_id(self) -> str:
        value = f"opid:v1:transfer:u7:019ff82c-9517-76fb-a67d-c461e917{self.transfer_sequence:04x}"
        self.transfer_sequence += 1
        return value


class NullDoctor:
    def inspect(self, configuration: object) -> object:
        raise AssertionError("machine inspection is not used by cache tests")


class StaticProvider:
    def __init__(self, entries: tuple[CacheEntry, ...], *, failures: set[str] | None = None) -> None:
        self.entries = {entry.cache_key: entry for entry in entries}
        self.failures = failures or set()
        self.deleted: list[str] = []
        self.overrides: dict[str, CacheReality] = {}

    def inspect(self, entry: CacheEntry) -> CacheReality:
        if entry.cache_key in self.overrides:
            return self.overrides[entry.cache_key]
        current = self.entries[entry.cache_key]
        return CacheReality(
            current.cache_key,
            "verified",
            current.sha256,
            current.size_bytes,
            current.reclaimable_bytes,
            current.accounting_basis,
            OBSERVED,
            current.provider_name,
        )

    def delete_verified(self, entry: CacheEntry, cleanup_id: str) -> DeletionResult:
        if entry.cache_key in self.failures:
            return DeletionResult(False, 0, "fixture-failure", "fixture refused deletion")
        self.deleted.append(entry.cache_key)
        return DeletionResult(True, entry.reclaimable_bytes, "deleted", "fixture deleted entry")


class BytesSource:
    def __init__(self, value: bytes, *, fail_offsets: set[int] | None = None) -> None:
        self.value = value
        self.fail_offsets = fail_offsets or set()

    def read(self, locator: str, offset: int, limit: int) -> bytes:
        if offset in self.fail_offsets:
            raise OSError("seeded interrupted source")
        return self.value[offset : offset + limit]


class CancelImmediately:
    def cancelled(self) -> bool:
        return True


def entry(cache_key: str, **changes: object) -> CacheEntry:
    values: dict[str, object] = {
        "cache_key": cache_key,
        "kind": "artifact",
        "content_id": CONTENT_ID,
        "sha256": SHA_A,
        "relative_path": f"objects/{cache_key}.bin",
        "size_bytes": 4096,
        "reclaimable_bytes": 4096,
        "accounting_basis": "logical",
        "provider_name": "fixture-cache",
        "retention_class": "reacquirable",
        "pinned": False,
        "active_leases": (),
        "future_dependencies": (),
        "dependencies": (),
        "last_used_at": "2026-08-01T00:00:00Z",
        "reacquisition_time_seconds": 10,
        "reacquisition_cost_microunits": 0,
        "reconstruction_difficulty": 1,
        "upstream_fragility": 1,
        "verification_status": "verified",
        "verified_at": OBSERVED,
        "observed_at": OBSERVED,
        "source": "fixture inventory",
        "staleness_seconds": 0,
    }
    values.update(changes)
    return CacheEntry(**values)


def policy() -> EvictionPolicy:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))["policy"]
    return EvictionPolicy(**value)


def manager() -> CacheManager:
    return CacheManager(clock=FixedClock(), id_generator=FixedIds())


class CacheInventoryAndPlanningTests(unittest.TestCase):
    def test_inventory_digest_and_serialization_are_permutation_stable(self) -> None:
        first = entry("first-cache", active_leases=("lease-b", "lease-a"))
        second = entry("second-cache")
        one = manager().inventory((first, second), observed_at=OBSERVED)
        two = manager().inventory((second, first), observed_at=OBSERVED)
        self.assertEqual(one.inventory_digest, two.inventory_digest)
        self.assertEqual(one.to_dict(), two.to_dict())
        self.assertEqual(one.to_dict()["entries"][0]["active_leases"], ["lease-a", "lease-b"])

    def test_weighted_plan_protects_leases_dependencies_pins_spools_and_rare_entries(self) -> None:
        entries = (
            entry("modern-cache", reclaimable_bytes=6000, size_bytes=6000),
            entry(
                "expensive-cache",
                reclaimable_bytes=6000,
                size_bytes=6000,
                retention_class="expensive-reconstruction",
                reacquisition_time_seconds=10000,
                reacquisition_cost_microunits=500000,
                reconstruction_difficulty=90,
                upstream_fragility=90,
            ),
            entry("pinned-cache", pinned=True),
            entry("active-cache", active_leases=("lease-one",)),
            entry("future-cache", future_dependencies=("campaign-one",)),
            entry("spool-cache", kind="protected-spool", retention_class="protected-spool"),
            entry("rare-cache", retention_class="rare-fragile"),
            entry("dependency-cache"),
            entry("dependent-cache", dependencies=("dependency-cache",), pinned=True),
        )
        service = manager()
        inventory = service.inventory(entries, observed_at=OBSERVED)
        provider = StaticProvider(entries)
        plan = service.plan_cleanup(inventory, service.reconcile(inventory, provider), 10000, policy())
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual([item.cache_key for item in plan.selected], fixture["expected_weighted_order"])
        exclusions = {item.cache_key: item.reasons for item in plan.exclusions}
        for cache_key, reason in fixture["expected_protected_reasons"].items():
            self.assertIn(reason, exclusions[cache_key])
        self.assertFalse(plan.mutation_permitted)
        self.assertEqual(provider.deleted, [])
        reversed_service = manager()
        reversed_entries = tuple(reversed(entries))
        reversed_inventory = reversed_service.inventory(reversed_entries, observed_at=OBSERVED)
        reversed_plan = reversed_service.plan_cleanup(
            reversed_inventory,
            reversed_service.reconcile(reversed_inventory, StaticProvider(reversed_entries)),
            10000,
            policy(),
        )
        self.assertEqual(plan.to_dict(), reversed_plan.to_dict())

    def test_insufficient_safe_space_is_refused_without_deletion(self) -> None:
        entries = (entry("only-cache", reclaimable_bytes=100, size_bytes=100),)
        service = manager()
        inventory = service.inventory(entries, observed_at=OBSERVED)
        provider = StaticProvider(entries)
        plan = service.plan_cleanup(inventory, service.reconcile(inventory, provider), 101, policy())
        self.assertEqual(plan.outcome, "refused")
        report = service.execute_cleanup(plan, inventory, provider)
        self.assertEqual(report.state, "refused")
        self.assertEqual(report.actual_reclaim_bytes, 0)
        self.assertEqual(provider.deleted, [])

    def test_stale_mismatch_provider_error_and_future_last_use_fail_closed(self) -> None:
        entries = (
            entry(
                "stale-cache",
                observed_at="2026-08-12T22:00:00Z",
                verified_at="2026-08-12T22:00:00Z",
            ),
            entry("mismatch-cache"),
            entry("error-cache"),
        )
        with self.assertRaisesRegex(ValueError, "last-use"):
            entry("future-cache", last_used_at="2026-08-13T00:00:00Z")
        service = manager()
        inventory = service.inventory(entries, observed_at=OBSERVED)
        provider = StaticProvider(entries)
        provider.overrides["mismatch-cache"] = CacheReality(
            "mismatch-cache", "mismatch", "b" * 64, 4096, 4096, "logical", OBSERVED,
            "fixture-cache", "seeded digest mismatch"
        )

        class ErrorProvider(StaticProvider):
            def inspect(self, item: CacheEntry) -> CacheReality:
                if item.cache_key == "error-cache":
                    raise OSError("seeded provider failure")
                return super().inspect(item)

        provider = ErrorProvider(entries)
        provider.overrides["mismatch-cache"] = CacheReality(
            "mismatch-cache", "mismatch", "b" * 64, 4096, 4096, "logical", OBSERVED,
            "fixture-cache", "seeded digest mismatch"
        )
        plan = service.plan_cleanup(inventory, service.reconcile(inventory, provider), 1, policy())
        exclusions = {item.cache_key: item.reasons for item in plan.exclusions}
        self.assertIn("inventory-stale", exclusions["stale-cache"])
        self.assertIn("reconciliation-mismatch", exclusions["mismatch-cache"])
        self.assertIn("reconciliation-provider-error", exclusions["error-cache"])

    def test_tampered_inventory_and_cleanup_candidate_are_rejected(self) -> None:
        original = entry("safe-cache")
        service = manager()
        inventory = service.inventory((original,), observed_at=OBSERVED)
        forged_inventory = replace(inventory, entries=(replace(original, sha256="b" * 64),))
        with self.assertRaisesRegex(ValueError, "digest"):
            service.reconcile(forged_inventory, StaticProvider((original,)))
        reconciliation = service.reconcile(inventory, StaticProvider((original,)))
        plan = service.plan_cleanup(inventory, reconciliation, 1, policy())
        forged_plan = replace(
            plan,
            selected=(replace(plan.selected[0], expected_reclaim_bytes=1),),
            expected_reclaim_bytes=1,
        )
        with self.assertRaisesRegex(ValueError, "expectation"):
            service.execute_cleanup(forged_plan, inventory, StaticProvider((original,)))

    def test_provider_identity_and_stale_execution_plan_fail_closed(self) -> None:
        cached = entry("identity-cache")
        service = manager()
        inventory = service.inventory((cached,), observed_at=OBSERVED)
        provider = StaticProvider((cached,))
        provider.overrides[cached.cache_key] = replace(
            provider.inspect(cached),
            source="other-provider",
        )
        with self.assertRaisesRegex(ValueError, "provider identity"):
            service.reconcile(inventory, provider)
        provider = StaticProvider((cached,))
        plan = service.plan_cleanup(inventory, service.reconcile(inventory, provider), 1, policy())
        stale = replace(plan, created_at="2026-08-12T22:00:00Z")
        with self.assertRaisesRegex(ValueError, "stale"):
            service.execute_cleanup(stale, inventory, provider)


class SafeCleanupTests(unittest.TestCase):
    def test_filesystem_cleanup_reconciles_allocated_bytes_and_deletes_only_verified_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "objects" / "payload.bin"
            path.parent.mkdir()
            payload = b"verified payload"
            path.write_bytes(payload)
            metadata = path.stat()
            blocks = getattr(metadata, "st_blocks", None)
            reclaimable = blocks * 512 if blocks is not None else len(payload)
            basis = "allocated" if blocks is not None else "logical"
            cached = entry(
                "payload-cache",
                sha256=hashlib.sha256(payload).hexdigest(),
                relative_path="objects/payload.bin",
                size_bytes=len(payload),
                reclaimable_bytes=reclaimable,
                accounting_basis=basis,
            )
            service = manager()
            inventory = service.inventory((cached,), observed_at=OBSERVED)
            provider = FilesystemCacheProvider(root, clock=FixedClock())
            plan = service.plan_cleanup(inventory, service.reconcile(inventory, provider), 1, policy())
            report = service.execute_cleanup(plan, inventory, provider)
            self.assertIn(report.state, {"completed", "partial"})
            self.assertLessEqual(report.actual_reclaim_bytes, reclaimable)
            self.assertFalse(path.exists())
            self.assertFalse(report.registry_authority_mutated)

    def test_reconciliation_change_partial_failure_and_cancellation_preserve_safety(self) -> None:
        entries = (entry("first-cache"), entry("second-cache"))
        service = manager()
        inventory = service.inventory(entries, observed_at=OBSERVED)
        provider = StaticProvider(entries)
        plan = service.plan_cleanup(inventory, service.reconcile(inventory, provider), 8000, policy())
        provider.overrides[plan.selected[0].cache_key] = CacheReality(
            plan.selected[0].cache_key,
            "mismatch",
            "b" * 64,
            4096,
            4096,
            "logical",
            OBSERVED,
            "fixture-cache",
            "seeded post-plan substitution",
        )
        report = service.execute_cleanup(plan, inventory, provider)
        self.assertEqual(report.state, "partial")
        self.assertEqual(report.mutations[0].code, "reconciliation-changed")
        self.assertNotIn(plan.selected[0].cache_key, provider.deleted)
        cancelled = service.execute_cleanup(plan, inventory, StaticProvider(entries), CancelImmediately())
        self.assertEqual(cancelled.state, "cancelled")
        self.assertEqual(cancelled.mutations[0].outcome, "skipped")

        class InspectionFailureProvider(StaticProvider):
            def inspect(self, item: CacheEntry) -> CacheReality:
                raise OSError("seeded secret-bearing provider diagnostic")

        inspection_failure = service.execute_cleanup(
            plan,
            inventory,
            InspectionFailureProvider(entries),
        )
        self.assertEqual(inspection_failure.state, "partial")
        self.assertEqual(inspection_failure.mutations[0].code, "provider-inspection-error")
        self.assertNotIn("secret-bearing", inspection_failure.mutations[0].detail)

    def test_actual_reclamation_divergence_remains_explicit_partial_state(self) -> None:
        cached = entry("divergent-cache")

        class DivergentProvider(StaticProvider):
            def delete_verified(self, item: CacheEntry, cleanup_id: str) -> DeletionResult:
                return DeletionResult(True, 1, "deleted", "fixture deleted with divergent accounting")

        service = manager()
        inventory = service.inventory((cached,), observed_at=OBSERVED)
        provider = DivergentProvider((cached,))
        plan = service.plan_cleanup(inventory, service.reconcile(inventory, provider), 1, policy())
        report = service.execute_cleanup(plan, inventory, provider)
        self.assertEqual(report.state, "partial")
        self.assertEqual(report.actual_reclaim_bytes, 1)
        self.assertEqual(report.mutations[0].code, "reclaim-diverged")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support is required")
    def test_symlink_and_path_traversal_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "normalized"):
            entry("escape-cache", relative_path="../outside.bin")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.bin"
            target.write_bytes(b"target")
            link = root / "linked.bin"
            try:
                link.symlink_to(target)
            except OSError as error:
                if os.name == "nt" and getattr(error, "winerror", None) == 1314:
                    self.skipTest("Windows symlink privilege is not available")
                raise
            cached = entry(
                "linked-cache",
                relative_path="linked.bin",
                sha256=hashlib.sha256(b"target").hexdigest(),
                size_bytes=6,
                reclaimable_bytes=6,
            )
            reality = FilesystemCacheProvider(root, clock=FixedClock()).inspect(cached)
            self.assertEqual(reality.status, "unsafe")
            self.assertTrue(target.exists())

    def test_multiply_linked_file_is_not_treated_as_reclaimable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original.bin"
            linked = root / "linked.bin"
            original.write_bytes(b"shared")
            os.link(original, linked)
            cached = entry(
                "linked-cache",
                relative_path="linked.bin",
                sha256=hashlib.sha256(b"shared").hexdigest(),
                size_bytes=6,
                reclaimable_bytes=6,
            )
            provider = FilesystemCacheProvider(root, clock=FixedClock())
            reality = provider.inspect(cached)
            self.assertEqual(reality.status, "unsafe")
            self.assertIn("multiple hard links", reality.diagnostic or "")
            self.assertTrue(original.exists())
            self.assertTrue(linked.exists())


class TransferTests(unittest.TestCase):
    def test_interrupted_download_resumes_with_distinct_attempts_and_exact_publication(self) -> None:
        payload = b"abcdefgh"
        with tempfile.TemporaryDirectory() as directory:
            service = TransferManager(Path(directory), clock=FixedClock(), id_generator=FixedIds())
            record = service.plan(
                operation="download",
                locator="fixture://payload",
                expected_sha256=hashlib.sha256(payload).hexdigest(),
                expected_size_bytes=len(payload),
                relative_path="objects/payload.bin",
                cache_key="payload-cache",
            )
            interrupted = service.resume_download(record, BytesSource(payload), chunk_size=4, maximum_chunks=1)
            self.assertEqual(interrupted.state, "interrupted")
            self.assertEqual(interrupted.bytes_completed, 4)
            completed = service.resume_download(interrupted, BytesSource(payload), chunk_size=4)
            self.assertEqual(completed.state, "completed")
            self.assertEqual([item.outcome for item in completed.attempts], ["interrupted", "completed"])
            self.assertEqual((Path(directory) / "objects" / "payload.bin").read_bytes(), payload)
            self.assertFalse((Path(directory) / "objects" / "payload.bin.part").exists())

    def test_corrupted_checkpoint_and_final_digest_mismatch_never_publish(self) -> None:
        payload = b"abcdefgh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = TransferManager(root, clock=FixedClock(), id_generator=FixedIds())
            record = service.plan(
                operation="acquire",
                locator="fixture://payload",
                expected_sha256=hashlib.sha256(payload).hexdigest(),
                expected_size_bytes=len(payload),
                relative_path="payload.bin",
            )
            interrupted = service.resume_download(record, BytesSource(payload), chunk_size=4, maximum_chunks=1)
            (root / "payload.bin.part").write_bytes(b"evil")
            with self.assertRaisesRegex(TransferIntegrityError, "checkpoint"):
                service.resume_download(interrupted, BytesSource(payload), chunk_size=4)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = TransferManager(root, clock=FixedClock(), id_generator=FixedIds())
            record = service.plan(
                operation="download",
                locator="fixture://payload",
                expected_sha256="0" * 64,
                expected_size_bytes=len(payload),
                relative_path="bad.bin",
            )
            failed = service.resume_download(record, BytesSource(payload), chunk_size=8)
            self.assertEqual(failed.state, "failed")
            self.assertEqual(failed.attempts[-1].code, "digest-mismatch")
            self.assertFalse((root / "bad.bin").exists())
            self.assertTrue((root / "bad.bin.part").exists())

    def test_external_upload_attempts_are_append_only_and_completion_requires_exact_digest(self) -> None:
        payload = b"upload"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            service = TransferManager(Path(directory), clock=FixedClock(), id_generator=FixedIds())
            record = service.plan(
                operation="upload",
                locator="fixture://remote",
                expected_sha256=digest,
                expected_size_bytes=len(payload),
                relative_path="upload.bin",
            )
            interrupted = service.record_external_attempt(
                record,
                bytes_completed=2,
                checkpoint_sha256=hashlib.sha256(payload[:2]).hexdigest(),
                outcome="interrupted",
                code="connection-lost",
                detail="seeded connection loss",
            )
            with self.assertRaisesRegex(ValueError, "digest"):
                service.record_external_attempt(
                    interrupted,
                    bytes_completed=len(payload),
                    checkpoint_sha256="0" * 64,
                    outcome="completed",
                    code="verified",
                    detail="forged remote completion",
                )
            completed = service.record_external_attempt(
                interrupted,
                bytes_completed=len(payload),
                checkpoint_sha256=digest,
                outcome="completed",
                code="verified",
                detail="remote digest and size verified",
            )
            self.assertEqual(len(completed.attempts), 2)
            self.assertEqual(completed.verified_sha256, digest)
            forged_attempt = replace(completed.attempts[1], offset_start=0)
            with self.assertRaisesRegex(ValueError, "contiguous checkpoint"):
                replace(completed, attempts=(completed.attempts[0], forged_attempt))
            with self.assertRaisesRegex(ValueError, "final verification"):
                replace(
                    interrupted,
                    verified_sha256=digest,
                    verified_size_bytes=len(payload),
                )

    def test_locator_credentials_are_rejected_before_transfer_state_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = TransferManager(Path(directory), clock=FixedClock(), id_generator=FixedIds())
            for locator in (
                "https://user:password@example.test/artifact",
                "https://example.test/artifact?access_token=secret",
            ):
                with self.subTest(locator=locator), self.assertRaisesRegex(ValueError, "credentials"):
                    service.plan(
                        operation="download",
                        locator=locator,
                        expected_sha256=SHA_A,
                        expected_size_bytes=1,
                        relative_path="secret-free.bin",
                    )

    def test_zero_byte_transfer_publishes_exact_empty_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = TransferManager(root, clock=FixedClock(), id_generator=FixedIds())
            record = service.plan(
                operation="download",
                locator="fixture://empty",
                expected_sha256=hashlib.sha256(b"").hexdigest(),
                expected_size_bytes=0,
                relative_path="empty.bin",
            )
            completed = service.resume_download(record, BytesSource(b""))
            self.assertEqual(completed.state, "completed")
            self.assertEqual((root / "empty.bin").read_bytes(), b"")

    def test_pre_checkpoint_open_failure_is_retained_as_an_interrupted_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = TransferManager(Path(directory), clock=FixedClock(), id_generator=FixedIds())
            record = service.plan(
                operation="download",
                locator="fixture://permission-failure",
                expected_sha256=hashlib.sha256(b"x").hexdigest(),
                expected_size_bytes=1,
                relative_path="blocked.bin",
            )
            with patch(
                "regex_conformance_control_plane.cache_manager.os.open",
                side_effect=PermissionError("seeded secret path"),
            ):
                interrupted = service.resume_download(record, BytesSource(b"x"))
            self.assertEqual(interrupted.state, "interrupted")
            self.assertEqual(interrupted.bytes_completed, 0)
            self.assertEqual(interrupted.attempts[-1].code, "source-or-write-failed")
            self.assertNotIn("secret path", interrupted.attempts[-1].detail)

    def test_publication_race_is_preserved_as_failed_attempt_without_overwrite(self) -> None:
        payload = b"expected"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            class RacingSource(BytesSource):
                def read(self, locator: str, offset: int, limit: int) -> bytes:
                    (root / "final.bin").write_bytes(b"attacker")
                    return super().read(locator, offset, limit)

            service = TransferManager(root, clock=FixedClock(), id_generator=FixedIds())
            record = service.plan(
                operation="download",
                locator="fixture://race",
                expected_sha256=hashlib.sha256(payload).hexdigest(),
                expected_size_bytes=len(payload),
                relative_path="final.bin",
            )
            failed = service.resume_download(record, RacingSource(payload), chunk_size=len(payload))
            self.assertEqual(failed.state, "failed")
            self.assertEqual(failed.attempts[-1].code, "publication-destination-race")
            self.assertEqual((root / "final.bin").read_bytes(), b"attacker")
            self.assertEqual((root / "final.bin.part").read_bytes(), payload)


class SchemaAndControllerTests(unittest.TestCase):
    def test_wire_schema_accepts_records_and_rejects_authority_or_mutation_forgery(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        cached = entry("schema-cache")
        service = manager()
        inventory = service.inventory((cached,), observed_at=OBSERVED)
        provider = StaticProvider((cached,))
        plan = service.plan_cleanup(inventory, service.reconcile(inventory, provider), 1, policy())
        report = service.execute_cleanup(plan, inventory, provider)
        with tempfile.TemporaryDirectory() as directory:
            transfers = TransferManager(Path(directory), clock=FixedClock(), id_generator=FixedIds())
            transfer = transfers.plan(
                operation="download",
                locator="fixture://schema",
                expected_sha256=hashlib.sha256(b"x").hexdigest(),
                expected_size_bytes=1,
                relative_path="x.bin",
            )
            for value in (inventory.to_dict(), report.to_dict(), transfer.to_dict()):
                self.assertEqual(list(validator.iter_errors(value)), [])
        forged_inventory = inventory.to_dict()
        forged_inventory["canonical_authority"] = True
        self.assertTrue(list(validator.iter_errors(forged_inventory)))
        forged_report = report.to_dict()
        forged_report["registry_authority_mutated"] = True
        self.assertTrue(list(validator.iter_errors(forged_report)))
        with tempfile.TemporaryDirectory() as directory:
            transfers = TransferManager(Path(directory), clock=FixedClock(), id_generator=FixedIds())
            forged_transfer = transfers.plan(
                operation="download",
                locator="fixture://safe",
                expected_sha256=SHA_A,
                expected_size_bytes=1,
                relative_path="safe.bin",
            ).to_dict()
        forged_transfer["requirement"]["locator"] = "https://user:password@example.test/file"
        self.assertTrue(list(validator.iter_errors(forged_transfer)))
        forged_checkpoint = transfer.to_dict()
        forged_checkpoint["checkpoint_sha256"] = "a" * 64
        self.assertTrue(list(validator.iter_errors(forged_checkpoint)))

    def test_controller_exposes_cache_and_transfer_services_and_refuses_missing_services(self) -> None:
        cached = entry("controller-cache")
        cache_service = manager()
        with tempfile.TemporaryDirectory() as directory:
            transfer_service = TransferManager(Path(directory), clock=FixedClock(), id_generator=FixedIds())
            controller = ControlPlaneController(
                ControlPlaneServices(
                    NullDoctor(),
                    cache_manager=cache_service,
                    transfer_manager=transfer_service,
                )
            )
            inventory = controller.inventory_cache((cached,), observed_at=OBSERVED)
            reconciliation = controller.reconcile_cache(inventory, StaticProvider((cached,)))
            cleanup = controller.plan_cache_cleanup(inventory, reconciliation, 1, policy())
            self.assertEqual(cleanup.outcome, "ready")
            transfer = controller.plan_transfer(
                operation="download",
                locator="fixture://controller",
                expected_sha256=SHA_A,
                expected_size_bytes=1,
                relative_path="controller.bin",
            )
            self.assertEqual(transfer.state, "planned")
        missing = ControlPlaneController(ControlPlaneServices(NullDoctor()))
        with self.assertRaisesRegex(RuntimeError, "cache manager"):
            missing.inventory_cache((cached,), observed_at=OBSERVED)
        with self.assertRaisesRegex(RuntimeError, "transfer manager"):
            missing.plan_transfer(
                operation="download",
                locator="fixture://missing",
                expected_sha256=SHA_A,
                expected_size_bytes=1,
                relative_path="missing.bin",
            )


if __name__ == "__main__":
    unittest.main()
