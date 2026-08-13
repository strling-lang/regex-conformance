# Environments

Reproducible environment recipes, provider contracts, acquisition policies, and
verification definitions live here. Realized instances, images, binaries,
downloaded toolchains, and cache state remain outside Git.

- `recipes/` — immutable reconstructible environment definitions
- `policies/` — strategy, platform, acquisition, and verification policy

The first executable recipe set covers PCRE2 10.47 from source, the official
CPython 3.14.6 Ubuntu archive, and the official MySQL 8.4.10 linux/amd64 OCI
image. Acquisition is immutable, runtime networking is disabled, realization
is independently checked, and raw certification state remains outside Git.
See the [minimal certified environment architecture](../docs/architecture/minimal-certified-environments.md)
for exact provenance, containment, certification, and limitation details.

`qualification-recipes/` contains post-P17 additions. Its PCRE2 DFA recipe
reuses the pinned 10.47 source artifact while independently binding the DFA
profile and requiring an exported `pcre2_dfa_match_8` smoke probe.
