from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "control_plane" / "stage_sustained_operating_envelope_input.py"
SPEC = importlib.util.spec_from_file_location("stage_sustained_input", TOOL)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SustainedInputStagingTests(unittest.TestCase):
    def test_mount_resolution_uses_longest_matching_mount(self) -> None:
        lines = (
            "29 1 8:1 / / rw - ext4 /dev/sda rw",
            "30 29 0:44 / /mnt/c rw - 9p C:\\134 rw",
            "31 29 0:45 / /native\\040data rw - xfs /dev/sdb rw",
        )
        self.assertEqual(MODULE.filesystem_type(Path("/mnt/c/input"), lines), "9p")
        self.assertEqual(MODULE.filesystem_type(Path("/native data/input"), lines), "xfs")
        self.assertEqual(MODULE.filesystem_type(Path("/root/input"), lines), "ext4")

    def test_tree_identity_matches_canonical_relative_file_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nested").mkdir()
            (root / "a.txt").write_bytes(b"alpha")
            (root / "nested" / "b.txt").write_bytes(b"beta")
            entries = [
                {
                    "path": "a.txt",
                    "sha256": hashlib.sha256(b"alpha").hexdigest(),
                    "size_bytes": 5,
                },
                {
                    "path": "nested/b.txt",
                    "sha256": hashlib.sha256(b"beta").hexdigest(),
                    "size_bytes": 4,
                },
            ]
            expected = hashlib.sha256(MODULE.canonical_json({"entries": entries})).hexdigest()
            self.assertEqual(
                MODULE.tree_identity(root),
                {"file_count": 2, "sha256": expected, "size_bytes": 9},
            )

    def test_staging_is_digest_identical_read_only_and_no_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "nested").mkdir()
            (source / "value.json").write_bytes(b"{\"value\":1}\n")
            (source / "nested" / "blob.bin").write_bytes(bytes(range(64)))
            destination = root / "destination"

            source_identity, destination_identity = MODULE.stage_tree(source, destination)

            self.assertEqual(source_identity, destination_identity)
            self.assertEqual(MODULE.tree_identity(destination), source_identity)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o500)
            self.assertEqual((destination / "value.json").stat().st_mode & 0o777, 0o400)
            with self.assertRaisesRegex(MODULE.StagingError, "already exists"):
                MODULE.stage_tree(source, destination)


if __name__ == "__main__":
    unittest.main()
