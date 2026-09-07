# Provenance contracts

`generated-assertion-derivations.v1.json` is the canonical companion inventory
for assertion-like values in generated scientific, audit, forecast,
qualification, reconciliation, campaign, and certification artifacts. It
binds shared stable derivation handles and their content-derived revisions to
artifact selectors, rather than duplicating metadata in every generated row.

The inventory does not elevate a generated artifact's authority or alter the
scientific identities inside it. Its contract, evidence-strength rules, known
legacy ambiguities, and reproduction command are documented in
[`../../docs/architecture/generated-assertion-derivations.md`](../../docs/architecture/generated-assertion-derivations.md).

`execution-provenance-policy.v1.json` is the digest-bound prospective policy
for terminality, retry/reset causality, repeat measurement, anti-laundering,
and population-explicit reporting. Its schemas, deterministic reference
lineages, and compatibility rules are documented in
[`../../docs/architecture/execution-provenance.md`](../../docs/architecture/execution-provenance.md).
