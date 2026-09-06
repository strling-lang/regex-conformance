# Identity Registry

Durable namespace declarations, identity modes, schema-family references, and
qualified external crosswalk metadata belong here.

`namespaces.v1.json` remains the exact registry used by already-generated
qualification and evidence artifacts. `namespaces.v2.json` is its additive
successor for permanent semantic-entity and applicability-coordinate
identities. Both use the same typed `rcid`/`opid` grammar; the successor is not
a second identity system.

`scientific-identities.v1.json` is the canonical semantic-entity binding and
persistent identity lock. Readable keys are compatibility metadata. The
scientific and content identity rules, migration graph, and safe allocation
procedure are documented in
[`../../docs/architecture/scientific-identities.md`](../../docs/architecture/scientific-identities.md).
