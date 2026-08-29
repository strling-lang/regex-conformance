#!/usr/bin/env python3
"""Stage an immutable sustained-envelope input tree on native Linux storage."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "control-plane" / "python"
if str(CONTROL_PLANE) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE))

from regex_conformance_control_plane.state_models import canonical_json  # noqa: E402


NATIVE_PERSISTENT_FILESYSTEMS = frozenset(
    {"btrfs", "ext2", "ext3", "ext4", "f2fs", "xfs", "zfs"}
)
TREE_DIGEST_ALGORITHM = "canonical-relative-file-sha256-v1"
_MOUNT_ESCAPE = re.compile(r"\\([0-7]{3})")


class StagingError(ValueError):
    """Raised when native immutable staging cannot be proved safe."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _git_revision() -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain"),
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if status.returncode != 0 or status.stdout:
        raise StagingError("input staging requires a clean source worktree")
    revision = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    value = revision.stdout.decode("ascii", "strict").strip()
    if revision.returncode != 0 or len(value) != 40:
        raise StagingError("input staging cannot resolve the exact source revision")
    return value


def _is_link(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def _reject_linked_ancestors(path: Path, label: str) -> None:
    candidate = path.expanduser().absolute()
    for current in (candidate, *candidate.parents):
        if current.exists() and _is_link(current):
            raise StagingError(f"{label} must not traverse a symlink or junction")


def _external(path: Path, label: str, *, must_exist: bool) -> Path:
    _reject_linked_ancestors(path, label)
    candidate = path.expanduser().absolute().resolve(strict=must_exist)
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError:
        return candidate
    raise StagingError(f"{label} must remain outside the repository")


def _decode_mount_path(value: str) -> str:
    return _MOUNT_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def filesystem_type(path: Path, mountinfo_lines: Iterable[str] | None = None) -> str:
    """Return the filesystem type for the longest matching Linux mount point."""
    candidate = path.expanduser().absolute().resolve(strict=False)
    lines = (
        Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
        if mountinfo_lines is None
        else mountinfo_lines
    )
    matches: list[tuple[int, str]] = []
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
            mount_point = Path(_decode_mount_path(fields[4]))
            file_system = fields[separator + 1]
        except (IndexError, ValueError):
            continue
        try:
            candidate.relative_to(mount_point)
        except ValueError:
            continue
        matches.append((len(mount_point.parts), file_system))
    if not matches:
        raise StagingError(f"cannot determine filesystem type for {candidate}")
    return max(matches)[1]


def require_native_persistent_filesystem(path: Path, label: str) -> str:
    file_system = filesystem_type(path)
    if file_system not in NATIVE_PERSISTENT_FILESYSTEMS:
        raise StagingError(
            f"{label} must use native persistent Linux storage; observed {file_system}"
        )
    return file_system


def _file_digest(path: Path) -> tuple[str, int]:
    if _is_link(path) or not path.is_file():
        raise StagingError(f"input must be a regular non-link file: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def tree_identity(path: Path) -> dict[str, Any]:
    if _is_link(path) or not path.is_dir():
        raise StagingError(f"input must be a non-link directory: {path}")
    entries: list[dict[str, object]] = []
    total = 0
    for child in sorted(path.rglob("*")):
        if _is_link(child):
            raise StagingError(f"input tree contains a link: {child}")
        if child.is_dir():
            continue
        digest, size = _file_digest(child)
        entries.append(
            {
                "path": child.relative_to(path).as_posix(),
                "sha256": digest,
                "size_bytes": size,
            }
        )
        total += size
    if not entries:
        raise StagingError("input directory cannot be empty")
    return {
        "file_count": len(entries),
        "sha256": hashlib.sha256(canonical_json({"entries": entries})).hexdigest(),
        "size_bytes": total,
    }


def _copy_tree(source: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for child in sorted(source.rglob("*")):
        if _is_link(child):
            raise StagingError(f"input tree contains a link: {child}")
        relative = child.relative_to(source)
        target = destination / relative
        if child.is_dir():
            target.mkdir(mode=0o700)
            continue
        if not child.is_file():
            raise StagingError(f"input contains an unsupported node: {child}")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with child.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
            output_stream.flush()
            os.fsync(output_stream.fileno())


def _make_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        os.chmod(path, 0o500 if path.is_dir() else 0o400)
    os.chmod(root, 0o500)


def _remove_temporary(root: Path) -> None:
    if not root.exists():
        return
    os.chmod(root, 0o700)
    for path in root.rglob("*"):
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    shutil.rmtree(root)


def stage_tree(source: Path, destination: Path) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    source_identity = tree_identity(source)
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    if destination.exists() or _is_link(destination):
        raise StagingError(f"staged input destination already exists: {destination}")
    if temporary.exists():
        raise StagingError(f"temporary staging path already exists: {temporary}")
    destination_identity: Mapping[str, Any]
    try:
        _copy_tree(source, temporary)
        destination_identity = tree_identity(temporary)
        if destination_identity != source_identity:
            raise StagingError("staged input identity differs from the source input")
        _make_read_only(temporary)
        if destination.exists() or _is_link(destination):
            raise StagingError(f"staged input destination raced with another writer: {destination}")
        temporary.rename(destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        _remove_temporary(temporary)
    return source_identity, destination_identity


def _write_new(path: Path, document: Mapping[str, Any]) -> None:
    payload = canonical_json(document)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Digest-verify and stage sustained input on native Linux storage."
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--yes", action="store_true")
    arguments = parser.parse_args(argv)
    if not arguments.execute or not arguments.yes:
        parser.error("input staging requires both --execute and --yes")
    try:
        if sys.platform != "linux":
            raise StagingError("sustained input staging requires a native Linux host")
        source = _external(arguments.source, "source input", must_exist=True)
        destination = _external(arguments.destination, "staged input", must_exist=False)
        receipt = _external(arguments.receipt, "staging receipt", must_exist=False)
        if receipt.exists() or _is_link(receipt):
            raise StagingError(f"immutable staging receipt already exists: {receipt}")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        receipt.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination_file_system = require_native_persistent_filesystem(
            destination.parent, "staged input"
        )
        source_file_system = filesystem_type(source)
        source_revision = _git_revision()
        source_identity, destination_identity = stage_tree(source, destination)
        document = {
            "created_at": _now(),
            "destination": str(destination),
            "destination_file_system": destination_file_system,
            "destination_identity": dict(destination_identity),
            "record_type": "sustained-input-staging-receipt",
            "schema_version": "sustained-input-staging-receipt.v1",
            "source": str(source),
            "source_file_system": source_file_system,
            "source_identity": dict(source_identity),
            "source_revision": source_revision,
            "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "tree_digest_algorithm": TREE_DIGEST_ALGORITHM,
        }
        _write_new(receipt, document)
        print(canonical_json(document).decode("utf-8"))
        return 0
    except (OSError, StagingError, ValueError) as error:
        print(f"sustained input staging failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
