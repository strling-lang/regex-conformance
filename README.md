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

The project is in repository bootstrap. No observation in this repository is a
certified conformance result yet, and no production evidence campaign has been
authorized merely by the existence of this repository.

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

See [GOVERNANCE.md](GOVERNANCE.md) for authority and change control,
[CONTRIBUTING.md](CONTRIBUTING.md) for contribution requirements, and
[SECURITY.md](SECURITY.md) for private vulnerability reporting and execution
trust boundaries.

## License

Repository source and documentation are available under the [MIT License](LICENSE).
Licensing for empirical datasets, third-party runtime artifacts, and derived
public evidence is governed separately by artifact class and is not implied by
the repository source license.

[program-hub]: https://app.notion.com/p/3ba7d9406475810db8eec9b5c449ffb7?pvs=204
[foundation]: https://app.notion.com/p/3ba7d94064758154bf88ddfc16566b33?pvs=204
