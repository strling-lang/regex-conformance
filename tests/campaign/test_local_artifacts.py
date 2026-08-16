from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns/python",
    ROOT / "matrix/python",
    ROOT / "scheduler/python",
    ROOT / "schemas/tooling/python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_scale.local_artifacts import (
    LocalArtifactError,
    read_staged_object,
    stage_publication_items,
)
from regex_conformance_scale.r2_publication import PublicationItem


_RUNNER_SPEC = importlib.util.spec_from_file_location(
    "million_local_campaign_runner", ROOT / "tools/campaigns/run_million_local_campaign.py"
)
if _RUNNER_SPEC is None or _RUNNER_SPEC.loader is None:
    raise RuntimeError("cannot load local campaign runner")
runner_module = importlib.util.module_from_spec(_RUNNER_SPEC)
_RUNNER_SPEC.loader.exec_module(runner_module)


def _object(data: bytes, evidence_class: str = "semantic_results") -> PublicationItem:
    import hashlib

    digest = hashlib.sha256(data).hexdigest()
    return PublicationItem(
        key=f"regex-conformance/evidence-pack-v2/objects/sha256/{digest}.xz",
        data=data,
        evidence_class=evidence_class,
    )


def _manifest(data: bytes) -> PublicationItem:
    import hashlib

    digest = hashlib.sha256(data).hexdigest()
    return PublicationItem(
        key=f"regex-conformance/evidence-pack-v2/manifests/sha256/{digest}.json",
        data=data,
        evidence_class="manifests_integrity",
        manifest=True,
    )


class LocalArtifactTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux mode contract")
    def test_private_state_directory_requires_exact_posix_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_root = runner_module._private_directory(Path(temporary) / "state")
            self.assertEqual(state_root.stat().st_mode & 0o777, 0o700)

    def test_stages_exact_bytes_and_reuses_identical_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "staging"
            items = [_object(b"object"), _manifest(b"{}\n")]
            first = stage_publication_items(root, items)
            second = stage_publication_items(root, items)
            self.assertEqual(first.created_objects, 2)
            self.assertEqual(first.reused_objects, 0)
            self.assertEqual(second.created_objects, 0)
            self.assertEqual(second.reused_objects, 2)
            self.assertEqual(first.descriptors_sha256, second.descriptors_sha256)
            for item in items:
                self.assertEqual(read_staged_object(root, item.key), item.data)

    def test_rejects_conflicting_existing_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "staging"
            items = [_object(b"object"), _manifest(b"{}\n")]
            stage_publication_items(root, items)
            target = root.joinpath(*items[0].key.split("/"))
            target.write_bytes(b"changed")
            with self.assertRaisesRegex(LocalArtifactError, "conflicts"):
                stage_publication_items(root, items)

    def test_requires_manifest_last(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(LocalArtifactError, "end with one manifest"):
                stage_publication_items(
                    Path(temporary), [_manifest(b"{}\n"), _object(b"object")]
                )

    def test_concurrent_deduplicated_staging_preserves_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "staging"
            items = [_object(b"shared-object"), _manifest(b"{}\n")]
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(
                    pool.map(lambda _: stage_publication_items(root, items), range(32))
                )
            self.assertEqual(sum(result.created_objects for result in results), 2)
            self.assertEqual(sum(result.reused_objects for result in results), 62)
            for item in items:
                self.assertEqual(read_staged_object(root, item.key), item.data)

    def test_readback_recovers_an_internal_crash_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "staging"
            items = [_object(b"object"), _manifest(b"{}\n")]
            stage_publication_items(root, items)
            target = root.joinpath(*items[0].key.split("/"))
            alias = target.with_name(f".{target.name}.tmp-999999-dead")
            os.link(target, alias)
            self.assertEqual(read_staged_object(root, items[0].key), items[0].data)
            self.assertFalse(alias.exists())


if __name__ == "__main__":
    unittest.main()
