---
applyTo: "campaigns/**,reports/**,verifier/**,warehouse/**,certification/**,tools/campaigns/**"
---

# External evidence and execution guidance

Keep raw observations, physical attempts, logical segments, operational state,
spools, diagnostics, and warehouse datasets outside Git. Tracked campaign
manifests and compact reports must be deterministic, schema-validated,
traceable projections of declared sources or immutable evidence. Never rewrite
an observation or correction history; add qualification, quarantine,
invalidation, supersession, or replacement state.

Design compilation is distinct from execution. Do not use Docker, realize an
environment, run a target, execute a vertical slice, or start the 100K campaign
without explicit authorization and validated external roots.
