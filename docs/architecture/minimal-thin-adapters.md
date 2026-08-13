# Minimal Thin Adapters

The P17 adapter layer is a provider-neutral invocation boundary, not a source of
regex semantics or conformance judgment. Each adapter accepts the governed v1
protocol, validates exact release/profile/environment bindings, invokes one
native target surface, and serializes the target's observable result. Every
handshake and response states that canonical and semantic authority are false.

## Governed protocol and packages

`protocol/adapter-protocol.v1.json` content-addresses protocol 1.0, its bounded
uint32 big-endian JSON framing, and the handshake, request, and response schema
digests. Frames reject duplicate keys, floats and non-finite values, unsafe
integers, invalid Unicode, excessive nesting or collection sizes, truncated
lengths, and payloads over 1 MiB. Capability negotiation fails closed when the
major/minor range, schema set, required capabilities, or resource limits do not
intersect.

Each `adapters/manifests/*.v1.json` record binds one assigned adapter and release
ID to the exact protocol revision, target profile/release, entrypoint, runtime
constraints, source-file hashes, and aggregate source digest. The loader checks
those hashes and the manifest content ID before importing target behavior.
Source paths must be sorted regular Python files inside the repository and may
not traverse symbolic links.

## Archetype implementations

- `pcre2-ordinary` invokes the exact PCRE2 10.47 shared C ABI. It preserves
  byte offsets and native error codes, and contains match enumeration within
  explicit result and output limits.
- `python-re` invokes CPython 3.14.6 `re`. It preserves Unicode-scalar indices,
  native exceptions, captures, split output, and replacement output exposed by
  that API.
- `mysql-regex` sends hex-materialized utf8mb4 values through the MySQL client
  to the exact contained MySQL 8.4.10 service. It preserves MySQL character
  positions and SQL error codes. The dedicated daemon pins the certified global
  `regexp_time_limit` to 1000 ms; the adapter verifies that runtime identity and
  accepts only the same explicit request binding. It never changes global or
  session server behavior.

Unsupported operations, domains, options, callbacks, captures, or environment
inputs return typed `unsupported` responses. Native compile or execution
rejections remain target observations. Client launch, service connection,
containment, framing, and adapter failures remain infrastructure failures and
cannot become regex non-conformance.

## Independent certification

Run the complete deterministic compliance suite first:

```sh
python -m unittest discover -s tests/adapters -v
python schemas/tooling/python/run.py validate-repository
```

On Linux with CMake, a C compiler, and Docker, certify all adapters against the
exact P17 environments:

```sh
python tools/adapters/certify_minimal.py \
  --state-root /var/tmp/strling-regex-adapter-state \
  --evidence-dir /var/tmp/strling-regex-adapter-evidence \
  --trust-class development \
  --compact-report reports/vertical-slice/minimal-adapter-certification.json
```

The state and raw evidence roots must remain outside Git. The harness performs
machine inspection, provider health checking, forecast/admission, exact runtime
realization, manifest verification, framed handshake, positive matching, native
compile rejection, unsupported-callback execution, response-schema validation,
bounded process supervision, environment release, and empty-state checks. It
writes immutable RFC 8785 evidence under its SHA-256 filename and a compact Git
report that binds the protocol, package, recipe, environment fingerprint,
verification, provider, transcript, response, and process-execution digests.

Public `main` pushes repeat the adapter unit suite and exact certification on a
disposable, read-only, secretless hosted worker. No raw evidence is uploaded or
passed between jobs, and no public workflow can enter the trusted Executioner
domain.

## Deliberate limits

These three packages cover the minimal architectural archetypes only. They do
not yet claim ecosystem, historical, platform, operation, or option completeness.
They contain no matrix construction, applicability, normative expectations,
pass/fail verdicts, scheduling, retries, evidence qualification, or publication
authority. Those remain Control Plane and later-program responsibilities.
