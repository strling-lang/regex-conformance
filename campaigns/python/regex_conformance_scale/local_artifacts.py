"""Immutable local staging for certified Evidence Pack v2 publication items."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
import time
from typing import Sequence

from .r2_publication import PublicationError, PublicationItem


class LocalArtifactError(RuntimeError):
    """A local publication artifact is absent, unsafe, or identity-inconsistent."""


@dataclass(frozen=True)
class LocalStagingResult:
    created_objects: int
    reused_objects: int
    verified_objects: int
    retained_bytes: int
    descriptors_sha256: str


def _root(path: Path) -> Path:
    unresolved = path.expanduser().absolute()
    unresolved.mkdir(parents=True, exist_ok=True)
    resolved = unresolved.resolve(strict=True)
    if unresolved != resolved or unresolved.is_symlink() or not resolved.is_dir():
        raise LocalArtifactError("local staging root must be a direct directory")
    return resolved


def _destination(root: Path, key: str) -> Path:
    parts = PurePosixPath(key).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise LocalArtifactError("local artifact key is unsafe")
    destination = root.joinpath(*parts)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.parent.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as error:
        raise LocalArtifactError("local artifact path escapes its staging root") from error
    return destination


def _read_direct(path: Path, root: Path) -> bytes:
    unresolved = path.absolute()
    for attempt in range(201):
        try:
            resolved = unresolved.resolve(strict=True)
            resolved.relative_to(root)
            details = resolved.stat()
        except (OSError, ValueError) as error:
            raise LocalArtifactError("staged object is absent or escapes its root") from error
        if (
            unresolved != resolved
            or unresolved.is_symlink()
            or not stat.S_ISREG(details.st_mode)
        ):
            raise LocalArtifactError("staged object must be a direct regular file")
        if getattr(details, "st_nlink", 1) == 1:
            return resolved.read_bytes()
        for candidate in resolved.parent.glob(f".{resolved.name}.tmp-*"):
            try:
                candidate_details = candidate.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if (
                stat.S_ISREG(candidate_details.st_mode)
                and candidate_details.st_dev == details.st_dev
                and candidate_details.st_ino == details.st_ino
            ):
                candidate.unlink(missing_ok=True)
        if attempt == 200:
            break
        time.sleep(0.01)
    raise LocalArtifactError("staged object retains an unexpected hard-link alias")


def _write_once(path: Path, data: bytes, root: Path) -> bool:
    if path.exists() or path.is_symlink():
        if _read_direct(path, root) != data:
            raise LocalArtifactError("staged object conflicts with immutable content")
        return False
    temporary = path.with_name(
        f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    )
    linked = False
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
            created = True
            linked = True
        except FileExistsError:
            created = False
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    if linked and not path.exists():
        raise LocalArtifactError("staged object link disappeared")
    if _read_direct(path, root) != data:
        raise LocalArtifactError("staged object read-back differs")
    return created


def _descriptor(item: PublicationItem) -> dict[str, object]:
    return {
        "evidence_class": item.evidence_class,
        "key": item.key,
        "manifest": item.manifest,
        "sha256": item.sha256,
        "size_bytes": len(item.data),
    }


def descriptors_sha256(items: Sequence[PublicationItem]) -> str:
    from regex_conformance_schema.jsonio import canonical_bytes

    return hashlib.sha256(
        canonical_bytes([_descriptor(item) for item in items])
    ).hexdigest()


def stage_publication_items(
    staging_root: Path, items: Sequence[PublicationItem]
) -> LocalStagingResult:
    """Write a manifest-last pack plan to a direct local content-addressed tree."""

    if not items or sum(item.manifest for item in items) != 1 or not items[-1].manifest:
        raise LocalArtifactError("local staging plan must end with one manifest")
    if len({item.key for item in items}) != len(items):
        raise LocalArtifactError("local staging plan contains duplicate keys")
    root = _root(staging_root)
    created = reused = 0
    retained = 0
    for item in items:
        try:
            item.validate()
        except PublicationError as error:
            raise LocalArtifactError(str(error)) from error
        destination = _destination(root, item.key)
        was_created = _write_once(destination, item.data, root)
        created += int(was_created)
        reused += int(not was_created)
        retained += len(item.data)
    return LocalStagingResult(
        created_objects=created,
        reused_objects=reused,
        verified_objects=len(items),
        retained_bytes=retained,
        descriptors_sha256=descriptors_sha256(items),
    )


def read_staged_object(staging_root: Path, key: str) -> bytes:
    root = _root(staging_root)
    return _read_direct(_destination(root, key), root)
