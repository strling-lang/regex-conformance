# Warehouse

Regenerable warehouse schemas, transforms, partition/compaction declarations,
and query source live here. Raw evidence remains authoritative and large
analytical data is never committed to Git.

Warehouse construction requires a fresh immutable integrity assessment with
`analytical_admissible=true`. Quarantined or incomplete evidence fails before any
derived database is promoted; integrity admission does not imply trusted execution
or certification qualification.

The P19 scale warehouse is a separate, immutable derived projection of the
certified 100K evidence. `reconcile_100k_warehouse.py` opens the recovery ledger
read-only, independently recomputes plan, segment, observation, manifest,
retry, and interruption commitments, and then proves the SQLite row set matches
the immutable sources. See
`docs/campaigns/100k-warehouse-reconciliation.md`.
