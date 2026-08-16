# Adapters

Thin runtime-specific protocol implementations and their governed package
manifests live here. The current archetypes invoke PCRE2 10.47 through its shared
C ABI, CPython 3.14.6 through `re`, and MySQL 8.4.10 through its contained SQL
surface.

`python/run.py` loads and self-verifies the exact package manifest before
starting a framed session. Backends validate explicit target bindings, translate
typed data into the native API, preserve native indices/errors/outputs, and
report unsupported target surfaces. They do not construct matrices, infer
applicability, acquire environments, schedule attempts, compare expectations,
qualify evidence, or issue conformance verdicts.

Run `python -m unittest discover -s tests/adapters -v` for deterministic
compliance checks. Run `tools/adapters/certify_minimal.py` for exact-runtime
certification; its state and raw evidence directories must be outside Git. See
[the architecture and reproduction procedure](../docs/architecture/minimal-thin-adapters.md).

Adapters added after the architectural vertical slice use isolated qualification
manifests and entrypoints. The
first such adapter binds PCRE2's public DFA API, preserves alternative native
octet spans, and reports unavailable subgroup capture data explicitly.
