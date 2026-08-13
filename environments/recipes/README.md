# Environment Recipes

Pinned, reconstructible recipe graphs and artifact references belong here.
Recipe identity is distinct from every realized environment instance.

The vertical-slice recipes are:

- `pcre2-10.47-linux-x86-64.v1.json` — bounded host-toolchain source build;
- `cpython-3.14.6-linux-24.04-x64.v1.json` — safely extracted prebuilt runtime;
- `mysql-8.4.10-linux-amd64.v1.json` — digest-selected OCI service.

Every record binds exact release/profile IDs, content-derived recipe revision,
artifact sizes and SHA-256 digests, construction bounds, runtime facts,
configuration, isolation policy, provider capabilities, and smoke probes.
