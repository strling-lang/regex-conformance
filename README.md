# STRling Regex Conformance

STRling Regex Conformance is a versioned, reproducible empirical verification
system for the global regular-expression ecosystem. It executes exact
conformance vectors against exact, reproducible regex profiles and preserves
the resulting observations with enough provenance for independent verification
and rerun.

The project is intentionally broader than a compatibility table and narrower
than a normative regex specification. It measures what a precisely identified
runtime did under controlled conditions; it does not turn an observation into
a standards guarantee.

## Program status

This section describes the latest committed repository certification state.
Revalidate it whenever a certification or campaign boundary changes; live
planning and approval status remains in the canonical program hub.

Repository bootstrap and the portable Control Plane foundation are certified.
The architectural vertical slice is active. Its exact PCRE2, CPython, and
MySQL release/profile coordinates and minimal reproducible environments are
certified. Environment smoke observations establish executable identity only;
no repository observation is a conformance result yet, and no production
evidence campaign is authorized merely by this certification.

Program planning, dependencies, decisions, risks, and certification gates are
maintained in the canonical [STRling Regex Conformance Program][program-hub].
The controlling constitutional text is the [Regex Conformance Foundation
Specification][foundation].

## Authority boundaries

Each durable fact class has one primary home:

- The STRling Regex Knowledge Program owns canonical researched knowledge,
  terminology, feature ontology, and normative primary-source evidence.
- This repository owns lightweight machine-operational definitions and source,
  including registries, profiles, vectors, applicability, environment recipes,
  campaign definitions, schemas, and compact generated reports.
- Immutable evidence infrastructure owns published observations, physical
  attempts, provenance, environment fingerprints, diagnostics, and certified
  evidence objects. Corrections preserve prior observations and add explicit
  invalidation, supersession, or replacement metadata.
- Derived warehouse data is a regenerable analytical projection and never
  outranks immutable evidence.
- Local Control Plane state is recoverable operational state and is not
  canonical scientific evidence.
- Notion owns the development program: work status, dependencies, decisions,
  risks, assumptions, and certification gates.

Normative expectations, empirical probes, physical attempts, observations,
derived findings, and inferences remain distinct. Infrastructure failure is
never silently reported as regex non-conformance.

## Governing principles

- Stable public releases are the primary completion denominator.
- Unreproducible historical releases remain represented instead of
  disappearing from coverage accounting.
- Applicability rules prevent meaningless Cartesian-product expansion.
- Execution profiles are behaviorally relevant component graphs, not just
  engine labels.
- Logical executions remain distinct from retryable physical attempts.
- Native index units are preserved in observations.
- Published evidence is immutable and independently traceable.
- Trusted self-hosted execution never runs arbitrary public fork or pull-request
  code.
- Certification gates pass through evidence, never declaration.

## Repository layout

The repository uses a language-neutral module scaffold so canonical definitions,
runtime orchestration, verification, and analytical projections retain explicit
boundaries before implementation-language choices are made. See the
[repository layout and architecture traceability map](docs/architecture/repository-layout.md).
Each module contains a local README defining what may and may not live there.

Large runtime artifacts, realized environments, raw observations, physical-run
records, diagnostics, execution spools, and warehouse datasets remain outside
Git. Compact definitions, schemas, manifests, reports, hashes, and source belong
here only when the architecture assigns them to repository authority.

## Bootstrap schema and identity checks

The schema foundation uses an exact dependency lock, a Python validator/content
ID implementation, and an independent dependency-free Node.js JCS oracle:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python schemas/tooling/python/run.py validate-repository
.venv/bin/python schemas/tooling/python/run.py verify-fixtures
.venv/bin/python -m unittest discover -s tests/schema -v
```

Node.js 18 or newer is required for the independent canonical-byte oracle. These
bootstrap tooling choices do not select the later Control Plane implementation
language or packaging strategy.

## Control Plane command surface

The Control Plane includes a read-only machine doctor. It reports typed
resource pools, provider visibility, process capabilities, explicit trust, and
actionable diagnostics without creating environments, cache entries, spools, or
local state:

```sh
python control-plane/python/run.py doctor --trust-class development
python control-plane/python/run.py machine inspect --format json --trust-class development
```

Machine JSON conforms to `machine-inventory.v1`; every other non-event command
conforms to `control-plane-command.v1`. Unknown values remain null, trust is
never inferred, mutating environment acquisition requires `--execute --yes`,
and the CLI delegates to reusable controller services. See [the Control Plane
module](control-plane/README.md) for its command groups, stable exit codes,
dry-run contract, service-injection boundary, configuration, and validation
details.

## Minimal certified environments

A Linux worker with CMake, a C compiler, and Docker can independently realize,
verify, fingerprint, and release all three vertical-slice environments:

```sh
python tools/environments/certify_minimal.py \
  --state-root /var/tmp/strling-regex-state \
  --evidence-dir /var/tmp/strling-regex-evidence \
  --trust-class development \
  --compact-report reports/vertical-slice/minimal-environment-certification.json
```

The state root and raw content-addressed evidence directory must remain outside
Git. The compact report records their digest, the exact repository `HEAD`, and
whether certification ran from a clean worktree. See the [minimal certified
environment architecture](docs/architecture/minimal-certified-environments.md)
for provenance, containment, commands, trust boundaries, and known limits.

## Minimal thin adapters

The protocol-compliant vertical-slice adapter packages exercise PCRE2's shared C ABI,
CPython's native `re` API, and MySQL's contained SQL regex surface without
performing conformance judgment:

```sh
.venv/bin/python -m unittest discover -s tests/adapters -v
.venv/bin/python tools/adapters/certify_minimal.py \
  --state-root /var/tmp/strling-regex-adapter-state \
  --evidence-dir /var/tmp/strling-regex-adapter-evidence \
  --trust-class development \
  --compact-report reports/vertical-slice/minimal-adapter-certification.json
```

Raw evidence and realized state remain outside Git. The compact report binds the
exact protocol, adapter source, recipe, realized environment, transcript,
response, and process-execution digests. See the [minimal thin adapter
architecture](docs/architecture/minimal-thin-adapters.md).

## Public validation and promotion

Every external pull request and `main` push runs the public-validation check on
a disposable GitHub-hosted Ubuntu worker with read-only repository permission.
The workflow has no trusted evidence credentials, publication permission,
self-hosted runner label, or cross-zone artifact output. Its action revisions
and Linux dependency wheels are SHA-256 pinned.

Program work is fully verified and committed on a local `codex/**` branch, then
promoted without a pull request or server-administration dependency. Record the
exact commit that passed task verification; the authorized tool checks that
identity, fetches `origin/main`, fast-forwards local `main`, pushes normally,
fetches again, and proves local and remote main identify the same commit:

    VERIFIED_SHA=$(git rev-parse HEAD)
    python tools/ci/promote_verified.py --verified-sha "$VERIFIED_SHA" --dry-run
    python tools/ci/promote_verified.py --verified-sha "$VERIFIED_SHA"

Run the same gate locally after installing requirements.lock:

    python tools/ci/verify_public_ci.py --root .
    python -m unittest discover -s tests/ci -v

The machine-readable promotion/public-CI state and operator verification
procedure are documented in the [repository delivery policy][protection]. No
GitHub ruleset or legacy branch protection is required solely for this delivery
path. If GitHub rejects a normal `main` push because a real rule exists, stop
and report that specific restriction.

See [GOVERNANCE.md](GOVERNANCE.md) for authority and change control,
[CONTRIBUTING.md](CONTRIBUTING.md) for contribution requirements, and
[SECURITY.md](SECURITY.md) for private vulnerability reporting and execution
trust boundaries. Organization-wide community participation follows the
[Code of Conduct](https://github.com/strling-lang/.github/blob/main/CODE_OF_CONDUCT.md),
and the shared [support guide](https://github.com/strling-lang/.github/blob/main/SUPPORT.md)
routes questions that belong elsewhere in the STRling ecosystem.

## License

Repository source and documentation are available under the
[Apache License 2.0](LICENSE). Copyright 2026 STRling Team.
Licensing for empirical datasets, third-party runtime artifacts, and derived
public evidence is governed separately by artifact class and is not implied by
the repository source license.

[program-hub]: https://app.notion.com/p/3ba7d9406475810db8eec9b5c449ffb7?pvs=204
[foundation]: https://app.notion.com/p/3ba7d94064758154bf88ddfc16566b33?pvs=204
[protection]: docs/governance/repository-protection-policy.md
