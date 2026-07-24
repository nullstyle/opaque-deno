# Security

`@nullstyle/opaque` and its `opaque-zig` cryptographic dependency have not
received an independent security audit. This beta is experimental and must not
be represented as production-safe.

The currently pinned v0.3.0 candidate is not releasable: a full-memory probe
finds the exact ephemeral OPRF blind and registration-start state in internal
WASM linear memory after allocator reset. Password and complete framed input
copies are scrubbed, but the remaining protocol state still fails this package's
release policy. `deno task publish:check` reproduces the probe and blocks
publication.

Applications must also use HTTPS, persistent independent secrets, durable
credential and session stores, CSRF protection, rate limiting, and an
independently reviewed release artifact.
