#!/usr/bin/env python3
"""Qualify only the protected PCRE2 ordinary profile from a signed local archive."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import os
from pathlib import Path
import platform
import runpy
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace

minimal = SimpleNamespace(**runpy.run_path(str(Path(__file__).with_name("certify_minimal.py"))))

from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.pcre2_qualification import SELECTION, SIGNER, build_plan, verify_responses
from regex_conformance_schema.schema import validate_instance


ROOT = minimal.ROOT


def _git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True, timeout=10).strip()


def _require_protected_worker(expected_head: str) -> None:
    values = _git("rev-parse", "HEAD", "refs/heads/main", "refs/remotes/origin/main").splitlines()
    if values != [expected_head] * 3 or _git("status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("qualification requires clean source at the exact protected main revision")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("qualification requires Ubuntu 24.04 x86-64")
    release = platform.freedesktop_os_release()
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
        raise ValueError("qualification requires Ubuntu 24.04 x86-64")


class OfflineRelease:
    """Feed only already verified release bytes into the existing provider."""

    def __init__(self, plan: dict, archive: Path, signature: Path, keyring: Path) -> None:
        paths = {"pcre2-source": archive, "pcre2-signature": signature}
        self.artifacts = {}
        for entry in plan["source_artifacts"]:
            path = paths[entry["name"]]
            with path.open("rb") as stream:
                raw = stream.read(entry["size_bytes"] + 1)
            if len(raw) != entry["size_bytes"] or sha256(raw).hexdigest() != entry["sha256"]:
                raise ValueError(f"release input differs from recipe size or digest: {entry['name']}")
            self.artifacts[entry["name"]] = raw
        if keyring.stat().st_size > 1_048_576:
            raise ValueError("OpenPGP keyring exceeds the verification limit")
        # Verify private copies of the two exact byte strings acquired above.
        with TemporaryDirectory(prefix="pcre2-release-verification-") as directory:
            temporary = Path(directory)
            for key, raw in self.artifacts.items():
                (temporary / key).write_bytes(raw)
            with keyring.open("rb") as stream:
                keyring_bytes = stream.read(1_048_577)
            if len(keyring_bytes) > 1_048_576:
                raise ValueError("OpenPGP keyring exceeds the verification limit")
            (temporary / "publisher.gpg").write_bytes(keyring_bytes)
            verification = subprocess.run(
                (
                    "/usr/bin/gpgv", "--homedir", directory, "--keyring", "publisher.gpg", "--status-fd", "1",
                    str(temporary / "pcre2-signature"), str(temporary / "pcre2-source"),
                ),
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": directory},
                capture_output=True, text=True, timeout=10, check=False,
            )
        valid = [
            line.split() for line in verification.stdout.splitlines()
            if line.startswith("[GNUPG:] VALIDSIG ")
        ]
        if verification.returncode or len(valid) != 1 or valid[0][-1] != SIGNER:
            raise ValueError("detached signature does not verify against the pinned primary publisher")
        self.signature_status = " ".join(valid[0])

    def fetch(self, requirement, destination: Path) -> None:
        with destination.open("xb") as stream:
            stream.write(self.artifacts[requirement.name])


def _run_capability_probes(plan: dict, ready, package) -> tuple[list[dict], dict, list[dict]]:
    command, environment, _ = minimal._adapter_command(SELECTION, ready)
    request_frames = [minimal._offer(package), *(case["request"] for case in plan["probes"])]
    payload = b"".join(minimal.encode_frame(frame) for frame in request_frames)
    response_schema = load_strict(ROOT / "schemas/json/adapter-response.schema.json")
    supervisor = minimal.ContainedProcessSupervisor(maximum_concurrency=1)
    execution, attempts = minimal._run_adapter_process_attempts(
        SELECTION,
        lambda: supervisor.run(command, limits=minimal._adapter_process_limits(SELECTION), cwd=ROOT, environment=environment, stdin=payload),
        lambda process: minimal._completed_invocation_failure_code(process, response_schema),
    )
    handshake, *responses = minimal._decode_frames(execution.stdout)
    validate_instance(handshake, load_strict(ROOT / "schemas/json/adapter-handshake.schema.json"))
    runtime = handshake["runtime_identity"]
    facts = {item["name"]: item["value"] for item in runtime["facts"]}
    if (
        handshake["outcome"] != "accepted"
        or handshake["adapter_release_manifest_id"] != package.manifest_id
        or runtime["profile_id"] != package.profile_id or runtime["target_release_id"] != package.target_release_id
        or set(handshake["capabilities"]) != set(package.capabilities)
        or any(facts.get(name) != value for name, value in package.runtime_constraints)
    ):
        raise RuntimeError("qualification handshake does not bind the exact runtime and adapter")
    return responses, handshake, attempts


def qualify(plan: dict, state_root: Path, evidence_dir: Path, release: OfflineRelease, head: str) -> dict:
    definitions = tuple(item for item in minimal.load_certified_recipes(ROOT) if item.selection_key == SELECTION)
    (definition,) = definitions
    (provider,) = minimal.build_certified_providers(definitions, state_root, fetcher=release)
    package = minimal.load_manifest(ROOT, SELECTION)
    manager = minimal.EnvironmentManager(minimal.ProviderRegistry((provider,)))
    planner = minimal.ResourcePlanner(minimal.environment_certification._policy())
    doctor = minimal.MachineDoctor(minimal.StandardLibraryMachineDiscovery(), minimal.UtcClock())
    trust = "trusted_executioner"
    configuration = minimal.environment_certification._doctor_configuration(state_root, trust)
    planned = manager.plan(definition.lifecycle, provider.descriptor.name)
    if planned.state != "planned":
        raise RuntimeError(f"PCRE2 environment planning failed: {planned.failure}")
    inventory = minimal._health_checked_inventory(doctor.inspect(configuration), provider)
    memory = definition.limits.memory_bytes
    supplemental = (minimal.ResourceEstimate(
        "environment-memory-ceiling", "ram", "bytes", memory, memory, "bounded", "isolation-policy",
    ),)
    resource_plan = planner.environment_plan(
        planned, machine_provider_name=provider.machine_provider_name, estimate_confidence="bounded",
        supplemental_estimates=supplemental, eligible_trust_classes=(trust,),
    )
    admission = planner.preflight(resource_plan, inventory)
    admitted = manager.admit(planned, planner.environment_decision(planned, admission))
    if admitted.state != "admitted":
        raise RuntimeError(f"PCRE2 resource admission refused: {[item.code for item in admission.issues]}")
    ready = manager.realize(admitted)
    if ready.state != "ready":
        raise RuntimeError(f"PCRE2 environment did not reach Ready: {manager.diagnose(ready).to_dict()}")
    try:
        smoke = minimal._invoke_adapter(SELECTION, ready, package)
        responses, handshake, attempts = _run_capability_probes(plan, ready, package)
        if smoke["handshake"]["runtime_identity"] != handshake["runtime_identity"]:
            raise RuntimeError("smoke and capability probes used different realized runtimes")
        assertions = verify_responses(ROOT, plan, responses, handshake["runtime_identity"]["facts"])
    finally:
        released = manager.release(ready)
    if released.state != "released":
        raise RuntimeError(f"PCRE2 environment release failed: {released.failure}")
    _require_protected_worker(head)
    body = {
        "schema_version": "pcre2-bounded-capability-qualification.v1", "classification": "qualification-only",
        "source_head": head, "observed_at": datetime.now(timezone.utc).isoformat(), "trust_class": trust,
        "plan_digest_sha256": plan["plan_digest_sha256"], "source_signature_status": release.signature_status,
        "profile_id": package.profile_id, "release_id": package.target_release_id, "adapter_manifest_id": package.manifest_id,
        "environment": ready.to_dict(), "release_state": released.state,
        "inventory_sha256": sha256(canonical_bytes(inventory.to_dict())).hexdigest(),
        "admission_sha256": sha256(canonical_bytes(admission.to_dict())).hexdigest(),
        "smoke": smoke, "capability_responses": responses, "capability_process_attempts": attempts,
        "capability_handshake": handshake, "capability_assertions": assertions,
        "production_logical_executions": 0, "certified_requirement_count": 0,
    }
    encoded = canonical_bytes(body) + b"\n"
    digest = sha256(encoded).hexdigest()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    path = evidence_dir / f"pcre2-capability-qualification-sha256-{digest}.json"
    with path.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    return {
        "evidence_file": path.name, "evidence_sha256": digest,
        "qualified_assertions": sum(row["state"] == "verified-in-qualification" for row in assertions),
        "qualification_only": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--expected-plan")
    parser.add_argument("--protected-head")
    for name in ("archive", "signature", "keyring", "state-root", "evidence-dir"):
        parser.add_argument(f"--{name}", type=Path)
    args = parser.parse_args()
    plan = build_plan(ROOT)
    if not args.execute:
        sys.stdout.buffer.write(canonical_bytes(plan) + b"\n")
        return
    values = (args.protected_head, args.archive, args.signature, args.keyring, args.state_root, args.evidence_dir)
    if not all(values) or args.expected_plan != plan["plan_digest_sha256"]:
        parser.error("execute requires the exact protected revision, plan digest, release inputs and external roots")
    _require_protected_worker(args.protected_head)
    state_root = minimal._outside_repository(args.state_root, "state root")
    evidence_dir = minimal._outside_repository(args.evidence_dir, "evidence directory")
    archive = OfflineRelease(plan, args.archive, args.signature, args.keyring)
    with minimal._exclusive_lock(state_root):
        result = qualify(plan, state_root, evidence_dir, archive, args.protected_head)
    sys.stdout.buffer.write(canonical_bytes(result) + b"\n")


if __name__ == "__main__":
    main()
