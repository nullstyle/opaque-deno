# Security

`@nullstyle/opaque` and its `opaque-zig` cryptographic dependency have not
received an independent security audit. This beta is experimental and must not
be represented as production-safe.

## Linear-memory secret scrubbing

The pinned `opaque-zig` v0.3.2 candidate passes this package's full-memory
probe. `deno task publish:check` drives a complete register + login lifecycle
through all nine production exports and scans the whole of WASM linear memory
after each one; no 16-byte window of any input, output, or derived secret
survives `resetAllocator`.

This replaces an earlier blocker. Through v0.3.1 the probe found ephemeral
secrets — including the server private key, both `exportKey`s, and the
fake-record masking key — left behind in the WASM shadow stack, which shares the
exported linear memory: deep call frames kept copies that neither the arena wipe
nor the handlers' explicit zeroing reached. Upstream v0.3.2 zeroes the entire
shadow-stack region in `resetAllocator`. The same probe reports 82 residues
against v0.3.1 and none against v0.3.2, so it is a live check, not a formality.

One caveat is unchanged upstream: a WebAssembly **trap** leaves linear memory
unscrubbed. A trap permanently poisons the adapter, and the shared instance is
scrubbed by snapshot-and-restore before any further operation runs; hosts using
`./raw` directly must discard a trapped instance themselves.

## Deployment requirements

Applications must also use HTTPS, persistent independent secrets, durable
credential and session stores, CSRF protection, rate limiting, and an
independently reviewed release artifact.
