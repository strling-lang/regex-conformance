from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    sys.path.insert(0, str(source))

from regex_conformance_scale.r2_publication import (  # noqa: E402
    CapacityAdmissionError,
    EvidencePackPublisher,
    GetResult,
    PublicationError,
    PublicationItem,
    PublicationReceiptLedger,
    PutResult,
    R2Configuration,
    R2TransportError,
    publication_items_from_evidence_pack,
)


def item(data: bytes, *, manifest: bool = False) -> PublicationItem:
    digest = hashlib.sha256(data).hexdigest()
    suffix = "json" if manifest else "xz"
    return PublicationItem(
        key=f"regex-conformance/evidence-pack-v2/{'manifests' if manifest else 'objects'}/sha256/{digest}.{suffix}",
        data=data,
        evidence_class="manifests_integrity" if manifest else "diagnostics",
        manifest=manifest,
    )


class FakeTransport:
    def __init__(self, objects: dict[str, bytes] | None = None) -> None:
        self.objects = {} if objects is None else objects
        self.calls: list[tuple[str, str]] = []
        self.indeterminate_once = False
        self.corrupt_reads = False

    def put_if_absent(self, key: str, data: bytes, *, content_type: str) -> PutResult:
        self.calls.append(("put", key))
        if self.indeterminate_once:
            self.indeterminate_once = False
            self.objects.setdefault(key, data)
            raise R2TransportError("injected-indeterminate", indeterminate=True)
        created = key not in self.objects
        self.objects.setdefault(key, data)
        return PutResult(created, hashlib.md5(data, usedforsecurity=False).hexdigest())

    def get_exact(self, key: str) -> GetResult:
        self.calls.append(("get", key))
        data = self.objects[key]
        if self.corrupt_reads:
            data += b"corruption"
        return GetResult(data, None)


class PublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temporary.cleanup)

    def ledger(self, name: str = "receipts.sqlite") -> PublicationReceiptLedger:
        ledger = PublicationReceiptLedger(Path(self.temporary.name) / name)
        self.addCleanup(ledger.close)
        return ledger

    def test_create_verify_manifest_last_and_idempotent_receipt_skip(self) -> None:
        objects = [item(b"object"), item(b'{"manifest":true}\n', manifest=True)]
        transport = FakeTransport()
        ledger = self.ledger()
        first = EvidencePackPublisher(transport, ledger).publish(objects)
        self.assertEqual(first["created_objects"], 2)
        self.assertEqual(first["class_a_requests"], 2)
        self.assertEqual(first["class_b_requests"], 2)
        self.assertEqual(first["list_requests"], 0)
        self.assertEqual(
            sum(first["retained_bytes_by_evidence_class"].values()),
            first["retained_bytes"],
        )
        self.assertEqual([call[1] for call in transport.calls if call[0] == "put"], [value.key for value in objects])
        calls = list(transport.calls)
        second = EvidencePackPublisher(transport, ledger).publish(objects)
        self.assertEqual(second["skipped_verified_receipts"], 2)
        self.assertEqual(transport.calls, calls)

    def test_zero_list_recovery_uses_exact_put_and_get(self) -> None:
        objects = [item(b"object"), item(b"manifest", manifest=True)]
        shared: dict[str, bytes] = {}
        EvidencePackPublisher(FakeTransport(shared), self.ledger("first.sqlite")).publish(objects)
        recovery_transport = FakeTransport(shared)
        report = EvidencePackPublisher(
            recovery_transport, self.ledger("recovery.sqlite")
        ).publish(objects)
        self.assertEqual(report["recovered_existing_objects"], 2)
        self.assertEqual(report["list_requests"], 0)
        self.assertEqual([call[0] for call in recovery_transport.calls], ["put", "get", "put", "get"])

    def test_indeterminate_put_is_retried_then_recovered(self) -> None:
        transport = FakeTransport()
        transport.indeterminate_once = True
        objects = [item(b"object"), item(b"manifest", manifest=True)]
        report = EvidencePackPublisher(transport, self.ledger()).publish(objects)
        self.assertEqual(report["created_objects"], 1)
        self.assertEqual(report["recovered_existing_objects"], 1)
        self.assertEqual(report["class_a_requests"], 3)
        self.assertEqual(report["class_b_requests"], 2)

    def test_integrity_failure_does_not_create_receipt(self) -> None:
        transport = FakeTransport()
        transport.corrupt_reads = True
        ledger = self.ledger()
        with self.assertRaisesRegex(PublicationError, "readback-integrity"):
            EvidencePackPublisher(transport, ledger).publish(
                [item(b"object"), item(b"manifest", manifest=True)]
            )
        self.assertEqual(ledger.receipt_count, 0)

    def test_capacity_is_rejected_before_any_request(self) -> None:
        transport = FakeTransport()
        objects = [item(b"12345"), item(b"manifest", manifest=True)]
        with self.assertRaises(CapacityAdmissionError):
            EvidencePackPublisher(
                transport, self.ledger(), soft_stop_bytes=10, hard_cap_bytes=20
            ).publish(objects)
        self.assertEqual(transport.calls, [])

    def test_configuration_checks_exact_interface_without_disclosing_values(self) -> None:
        environment = {
            "STRLING_R2_ACCOUNT_ID": "a" * 32,
            "STRLING_R2_BUCKET_NAME": "regex-conformance",
            "STRLING_R2_ENDPOINT": f"https://{'a' * 32}.r2.cloudflarestorage.com",
            "STRLING_R2_REGION": "auto",
            "STRLING_R2_ACCESS_KEY_ID": "sensitive-access",
            "STRLING_R2_SECRET_ACCESS_KEY": "sensitive-secret",
        }
        configuration = R2Configuration.from_environment(environment)
        self.assertEqual(configuration.region, "auto")
        invalid = dict(environment)
        invalid["STRLING_R2_ENDPOINT"] = "http://wrong.invalid"
        with self.assertRaises(PublicationError) as captured:
            R2Configuration.from_environment(invalid)
        self.assertNotIn("sensitive", str(captured.exception))

    def test_certified_pack_projects_to_manifest_last_plan(self) -> None:
        object_data = b"object"
        manifest_data = b"manifest"
        object_digest = hashlib.sha256(object_data).hexdigest()
        manifest_digest = hashlib.sha256(manifest_data).hexdigest()
        pack = SimpleNamespace(
            objects=(
                SimpleNamespace(
                    key=f"regex-conformance/evidence-pack-v2/objects/sha256/{object_digest}.xz",
                    data=object_data,
                    evidence_class="diagnostics",
                ),
            ),
            manifest_key=f"regex-conformance/evidence-pack-v2/manifests/sha256/{manifest_digest}.json",
            manifest_bytes=manifest_data,
        )
        plan = publication_items_from_evidence_pack(pack)
        self.assertEqual(len(plan), 2)
        self.assertFalse(plan[0].manifest)
        self.assertTrue(plan[1].manifest)


if __name__ == "__main__":
    unittest.main()
