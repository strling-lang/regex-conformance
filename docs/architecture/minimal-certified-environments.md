# Minimal Certified Environments

The P17 architectural vertical slice has three executable coordinates. Each
coordinate binds an exact stable release, component-graph profile, immutable
environment recipe revision, and a realized environment fingerprint. The
selection is intentionally small and architecturally diverse; it is not a
claim of ecosystem coverage.

| Selection | Root surface | Stable release | Strategy |
| --- | --- | --- | --- |
| `pcre2-ordinary` | PCRE2 ordinary matching API | PCRE2 10.47 | native source build |
| `python-re` | Python standard-library `re` API | CPython 3.14.6 | prebuilt native runtime |
| `mysql-regex` | MySQL regular-expression SQL surface | MySQL 8.4.10 | OCI service |

Canonical graph and release IDs live in
`registries/profiles/vertical-slice-coordinates.v1.json`. Recipe IDs are stable
assigned identities; recipe revision IDs are derived from canonical recipe
bytes. Realized fingerprints are derived only after independent artifact,
runtime, configuration, isolation, and smoke verification.

## Acquisition and provenance

The PCRE2 recipe pins the upstream 10.47 source archive and detached signature
by exact size and SHA-256. Its build is deliberately classified
`bounded-host-toolchain`, not hermetic: certification records the admitted CMake
and compiler realization, verifies the requested 8-bit/JIT/Unicode build
facets, requires the loadable shared-library public ABI needed by the thin
adapter, and hashes that exact installed library. A different admitted toolchain
may therefore produce a different legitimate environment fingerprint.

The CPython recipe pins the official GitHub Actions Ubuntu 24.04 x64 archive by
exact size and SHA-256. The provider safely extracts the archive and executes
the packaged `python3.14` directly. It never executes the archive's `setup.sh`.
Certification checks CPython, platform, Unicode database, cache-tag, and SOABI
facts before exercising ordinary `re` behavior.

The MySQL recipe pins the official OCI index, linux/amd64 manifest, config, and
every layer digest. Docker pulls the child manifest by digest, never by tag.
The container runs with no network, two CPUs, a 1 GiB memory/swap ceiling, a
256-process ceiling, bounded output/time, and an isolated temporary filesystem.
The graph binds MySQL 8.4.10 to ICU 77.1 using the corresponding MySQL source
provenance. The runtime verifier confirms the exact MySQL image/config/platform,
container limits, the daemon-pinned global regex time limit, and SQL behavior.
Adapters validate requests against that certified global value and never mutate
shared server behavior. The verifier does not claim independent binary-level
introspection of the embedded ICU build.

Artifact downloads use an exact HTTPS host allowlist and a bounded redirect
chain. Interrupted transfers, size/hash substitution, unsafe archives, mutable
OCI tags, runtime identity drift, failed smoke probes, and containment drift all
fail before `Ready`. Provider errors remain infrastructure diagnostics and never
become regex observations.

## Certification procedure

Run from a Linux worker with CMake, a C compiler, and Docker. Operational state
and raw evidence must be outside the repository:

```sh
python tools/environments/certify_minimal.py \
  --state-root /var/tmp/strling-regex-state \
  --evidence-dir /var/tmp/strling-regex-evidence \
  --trust-class development \
  --compact-report reports/vertical-slice/minimal-environment-certification.json
python schemas/tooling/python/run.py validate \
  reports/vertical-slice/minimal-environment-certification.json \
  schemas/json/minimal-environment-certification.schema.json
```

The harness obtains a nonblocking owner-only lock for the selected state root,
so two certifications cannot race the same operational directory. Each runtime
must progress through admission, acquisition, construction, artifact/runtime
verification, smoke verification, fingerprinting, `Ready`, and release. A
successful exit also leaves no realized transaction under the state root.

The raw certificate is RFC 8785 canonical JSON named by its SHA-256 digest. It
records the exact repository `HEAD` and whether the worktree was clean. The
compact Git report points to that raw digest but is not itself raw evidence.
Raw evidence, downloads, builds, images, containers, and local Control Plane
state remain outside Git.

The public-validation workflow repeats certification on a disposable
GitHub-hosted Ubuntu 24.04 worker after `main` source validation. It uses the
`untrusted_public` trust class, read-only permission, no secrets, and no
artifact handoff. Its evidence proves reproducibility on that worker only; it
is not production observation evidence or publication authority.

## Scientific boundary

These smoke observations certify environment identity and the availability of
the selected API paths. They are not normative expectations and are not a
conformance campaign. P17 adapters and the first compiled campaign create the
first logical executions separately. Retryable physical attempts, immutable
observations, and public evidence enter only under their later task contracts.
