# Schemas

Versioned schemas, identity projections, canonicalization declarations, and
cross-language reference fixtures live here. Certified artifacts name exact
schema revisions; mutable `latest` aliases are not certification inputs.

Schema validation and canonicalization tooling is introduced by its separate
bootstrap contract.

## Bootstrap toolchain

- `json/` contains Draft 2020-12 structural schemas.
- `identity-profiles/` contains typed, immutable projection contracts used by
  certified fixtures.
- `tooling/python/` contains validation, projection, identity, collision, and
  fixture tooling.
- `tooling/node/` contains the independent dependency-free JCS oracle.

Run all schema and fixture checks from the repository root:

```sh
.venv/bin/python schemas/tooling/python/run.py validate-repository
.venv/bin/python schemas/tooling/python/run.py verify-fixtures
```
