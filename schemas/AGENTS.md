# Schema agent guidance

`schemas/` owns machine contracts for repository definitions, identity,
operational records, evidence, reports, and validation. Read [README.md](README.md)
and the schema-family documentation before editing. A schema validates shape
and cross-field invariants; it does not create normative regex expectations.

Keep schema, semantic validator, fixtures, identity manifest, and consuming
compiler/test changes coupled. Materialize tracked identity fixtures only with
`python schemas/tooling/python/run.py materialize-fixtures`; never hand-edit a
derived fixture. Verify with `validate-repository`, `verify-fixtures`, and the
smallest focused test under `tests/schema` before broader suites. Review
compatibility and durable-identity consequences before changing an accepted
schema.
