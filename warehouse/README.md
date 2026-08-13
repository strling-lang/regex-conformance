# Warehouse

Regenerable warehouse schemas, transforms, partition/compaction declarations,
and query source live here. Raw evidence remains authoritative and large
analytical data is never committed to Git.

Warehouse construction requires a fresh immutable integrity assessment with
`analytical_admissible=true`. Quarantined or incomplete evidence fails before any
derived database is promoted; integrity admission does not imply trusted execution
or certification qualification.
