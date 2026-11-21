#!/usr/bin/env python3
"""Run one separately admitted PCRE2 assignment on its protected Linux worker."""

from argparse import ArgumentParser
from hashlib import sha256
import os
from pathlib import Path
import platform
import runpy
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
for location in ("campaigns", "matrix", "scheduler", "control-plane", "adapters"):
    sys.path.insert(0, str(ROOT / location / "python"))
sys.path.insert(0, str(ROOT / "schemas/tooling/python"))
sys.path.insert(0, str(ROOT / "tools/ci"))

from local_certification import MANIFEST_PATH, verify_manifest
from regex_conformance_control_plane.containment import ContainedProcessSupervisor
from regex_conformance_schema.jsonio import canonical_bytes, loads_strict
from regex_conformance_scale.pcre2_execution_gate import Pcre2ExecutionGate, _write_once
from regex_conformance_scale.pcre2_local_reconciliation import reconcile_local
from regex_conformance_scale.pcre2_native_dispatch import dispatch_serial


def _read_operator_file(path: Path) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError("operator inputs must be root-owned regular files without worker write access")
    with path.open("rb") as stream:
        value = stream.read(4_194_305)
    if len(value) > 4_194_304:
        raise ValueError("operator input exceeds its byte limit")
    return value


def _isolated_worker() -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() == 0:
        raise ValueError("assignment requires an unprivileged Ubuntu 24.04 x86-64 worker")
    release = platform.freedesktop_os_release()
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
        raise ValueError("worker operating system differs")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    devices = {path.name for path in Path("/sys/class/net").iterdir()}
    if status["NoNewPrivs"].strip() != "1" or int(status["CapEff"], 16) or devices - {"lo"}:
        raise ValueError("worker must run without ambient privilege on an isolated network namespace")


def _cgroup(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to("/sys/fs/cgroup") or (resolved / "pids.max").read_text().strip() != "1":
        raise ValueError("a dedicated one-process cgroup controlled by the operator is required")
    return resolved


def _git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True, timeout=10).strip()


def _enter_cgroup(argv: list[str]) -> None:
    _isolated_worker()
    if len(argv) != 2:
        raise ValueError("target arguments differ from the PCRE2 invocation")
    group = _cgroup(Path(argv[0]))
    library = Path(argv[1]).resolve(strict=True)
    if (group / "pids.current").read_text().strip() != "0":
        raise ValueError("target cgroup is occupied")
    (group / "cgroup.procs").write_text(str(os.getpid()), encoding="ascii")
    os.execv(sys.executable, (
        sys.executable, "-BI", str(ROOT / "adapters/python/run.py"), "--selection-key", "pcre2-ordinary",
        "--runtime-binding", str(library),
    ))


def _retain_local_reconciliation(journal: Path, gate: Pcre2ExecutionGate) -> None:
    closure, pack = reconcile_local(ROOT, journal, gate)
    proposal = loads_strict(gate.proposal_bytes.decode("utf-8"))
    cap = proposal["execution_caps"]["local_evidence_bytes"]
    records = {journal / "reconciled-lineage.json": canonical_bytes(closure) + b"\n"}
    if pack:
        directory = journal / "compact-evidence"
        records.update({directory / f"{digest}.xz": data for digest, data in sorted(pack.objects.items())})
        records[directory / "pack-manifest.json"] = pack.manifest_bytes
    current = sum(path.stat().st_size for path in journal.rglob("*") if path.is_file())
    added = sum(len(data) for path, data in records.items() if not path.exists())
    if current + added > cap:
        raise ValueError("local closure would exceed the admitted evidence ceiling")
    for path, data in records.items():
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError("local evidence destinations must not be symbolic links")
        path.parent.mkdir(mode=0o700, exist_ok=True)
        if path.exists():
            with path.open("rb") as stream:
                if stream.read(len(data) + 1) != data:
                    raise ValueError("previously retained evidence differs from recovery")
            continue
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())


def main() -> None:
    if sys.argv[1:2] == ["--enter-target-cgroup"]:
        _enter_cgroup(sys.argv[2:])
        return
    parser = ArgumentParser(description=__doc__)
    for field in ("readiness", "admission", "attestation", "journal"):
        parser.add_argument(f"--{field}", type=Path, required=True)
    parser.add_argument("--runtime-library", type=Path)
    parser.add_argument("--reconcile-only", action="store_true")
    for field in ("expected-proposal", "expected-admission", "protected-head", "certification-root"):
        parser.add_argument(f"--{field}", required=True)
    args = parser.parse_args()
    _isolated_worker()
    if _git("rev-parse", "HEAD", "refs/heads/main", "refs/remotes/origin/main").splitlines() != [args.protected_head] * 3 or (
        _git("status", "--porcelain=v1", "--untracked-files=all")
    ):
        raise ValueError("worker has not pulled the exact clean protected envelope")
    if not _git("ls-files", "--error-unmatch", str(Path(__file__).relative_to(ROOT))):
        raise ValueError("dispatch implementation is unavailable from protected source")
    verified = verify_manifest(
        ROOT, MANIFEST_PATH, expected_envelope_sha=args.protected_head,
        expected_root=args.certification_root, require_envelope=True,
    )
    source = {
        "source_sha": verified["certified_source_sha"], "envelope_sha": args.protected_head,
        "local_certification_root": args.certification_root,
    }
    readiness_bytes = _read_operator_file(args.readiness)
    readiness = loads_strict(readiness_bytes.decode("utf-8"))
    if canonical_bytes(readiness) + b"\n" != readiness_bytes:
        raise ValueError("worker readiness bytes are not canonical")
    proposal = readiness["campaign_proposal"]
    worker = loads_strict(_read_operator_file(args.attestation).decode("utf-8"))
    gate = Pcre2ExecutionGate.verify(
        ROOT, canonical_bytes(proposal) + b"\n", _read_operator_file(args.admission),
        expected_proposal=args.expected_proposal, expected_admission=args.expected_admission,
        verified_source=source, verified_worker=worker,
    )
    if worker["worker_uid"] != os.geteuid():
        raise ValueError("current worker uid differs from its admission")
    parent = args.journal.parent.resolve(strict=True)
    if parent.is_relative_to(ROOT) or parent.stat().st_uid != os.geteuid() or parent.stat().st_mode & 0o077:
        raise ValueError("evidence parent must be private, worker-owned and outside the repository")
    journal = parent / args.journal.name
    if journal.name != proposal["campaign_manifest_id"].rsplit(":", 1)[1]:
        raise ValueError("journal path must bind the exact campaign manifest identity")
    if args.reconcile_only:
        if journal.is_symlink() or not journal.is_dir():
            raise ValueError("reconciliation requires the existing external campaign journal")
        _retain_local_reconciliation(journal, gate)
        return
    if args.runtime_library is None:
        parser.error("dispatch needs the exact admitted runtime library")
    group = _cgroup(Path(worker["target_cgroup"]))
    library = args.runtime_library.resolve(strict=True)
    facts = {
        row["name"]: row["value"] for row in proposal["worker"]["scope"]["runtime_identity"]["facts"]
        if row["name"] in {"engine-version", "library-sha256", "runtime-kind"}
    }
    if not library.is_file() or str(library) != worker["runtime_library"] or library.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("target library path or size differs")
    if sha256(library.read_bytes()).hexdigest() != facts["library-sha256"]:
        raise ValueError("target library differs from the verified profile")
    journal.mkdir(mode=0o700, exist_ok=False)
    package = runpy.run_path(str(ROOT / "tools/adapters/certify_minimal.py"))
    offer = package["_offer"](package["load_manifest"](ROOT, "pcre2-ordinary"))
    supervisor = ContainedProcessSupervisor(maximum_concurrency=1)
    environment = {
        "HOME": str(parent), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
        "LD_LIBRARY_PATH": str(library.parent), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
    }
    command = (sys.executable, "-BI", str(Path(__file__).resolve()), "--enter-target-cgroup", str(group), str(library))

    def invoke(payload, limits):
        return supervisor.run(command, limits=limits, cwd=ROOT, environment=environment, stdin=payload)

    result = dispatch_serial(ROOT, journal, gate, offer=offer, runtime_facts=facts, invoke=invoke)
    _write_once(journal / "dispatch-report.json", result)
    _retain_local_reconciliation(journal, gate)
    print(canonical_bytes(result).decode())


if __name__ == "__main__":
    main()
