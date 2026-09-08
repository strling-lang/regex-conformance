# Obligation derivations

This directory owns versioned, machine-readable rules that translate the
current frozen semantic authority into prospective obligation decisions.

`regex-obligation-derivation-rules-2026-09-08.v1.json` is design authority for
the derivation method. It is not an obligation ledger and does not advance the
denominator. `obligation-derivation-identities-2026-09-08.v1.json` records the
one-time typed allocations used by the contract and its reports.

The rules are total over the frozen feature/facet universe, contain no generic
fallback, and bind operation, variant, modifier, manifestation, and interaction
conditions through scientific identities. See
[`../../docs/architecture/explainable-obligation-derivation.md`](../../docs/architecture/explainable-obligation-derivation.md)
for the contract and authority boundary.

Do not hand-edit generated JSON. Use:

```sh
python tools/semantics/define_obligation_derivation.py
python tools/semantics/define_obligation_derivation.py --check
```
