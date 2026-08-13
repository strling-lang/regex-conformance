# Adapter Protocol

The governed language-neutral protocol covers capability negotiation, bounded
framing, typed data domains, initial state, target options and environment
inputs, native indices, captures, replacements, diagnostics, errors, limits,
and version evolution. Its content-addressed revision binds the exact handshake,
request, and response schema bytes.

Sessions begin with one capability handshake and then exchange uint32
big-endian-length-prefixed canonical JSON objects. Implementations reject
duplicate keys, ambiguous numeric values, invalid Unicode, unbounded structures,
truncated frames, and incompatible protocol/schema/capability offers. Requests
bind one adapter manifest, target profile, and target release; responses retain
that identity and distinguish target observations from adapter failures.

The protocol preserves native behavior and explicitly grants no canonical,
normative, semantic, or adapter-side verdict authority. See
[the minimal adapter architecture](../docs/architecture/minimal-thin-adapters.md)
and `adapter-protocol.v1.json`.
