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

## What publication is gated on

`deno task publish:check` refuses to publish unless all of the following hold,
each verified offline and read-only:

- `wasm.lock.json` declares an `origin` this repository knows how to verify. An
  origin is a routing key into a set of verifiers, not a claim that is trusted
  on its own; supporting a new supply chain means adding a verifier.
- For the vendored-submodule origin: `.gitmodules` points at the upstream the
  lock names, the submodule is checked out at the pinned commit, and this
  repository's recorded gitlink is that same commit — so a fresh clone
  reproduces the reviewed source tree.
- Both committed copies of the artifact (`src/opaque.wasm`, which is what the
  package ships, and `vendor/opaque.wasm`, the build output of record) hash to
  the `sha256` and `byteLength` the lock records.
- The package actually ships that artifact and the lock describing it.
- `signedOff` names the exact commit and `sha256` a human reviewed, and both
  still match what the tree ships. Every other check compares two things inside
  this repository, so a rebuild makes them agree again by construction; this one
  goes stale the moment the pin or the bytes change, and a stale sign-off blocks
  publication until someone reviews the new artifact and records it.
- The full-memory secret probe above passes against the binary that ships, along
  with the export, custom-section, and ABI checks that `artifact:check` runs.

The honest limit: this proves the pinned source and the reviewed bytes, but it
does not re-run Zig and Binaryen, so it cannot prove the shipped binary was
produced from that source. Only `mise run build-wasm` with the pinned toolchain
establishes that link, and it is the check that catches a drifted compiler. Nor
is any of this a barrier against a compromised maintainer: the lock and the
submodule pin live in the same repository and move in the same commit. Its value
is that every provenance claim becomes falsifiable and lands in a reviewable
diff. Nothing here verifies a signature — the upstream tag is annotated but
unsigned — and edits to the vendored working tree are invisible to it, which is
tolerable only because the shipped WASM is committed and hash-checked.

Running the gate requires a real git working tree with the submodule
initialized, from the primary worktree; an exported tarball or a linked
`git worktree` fails closed rather than skipping the check.

## Deployment requirements

Applications must also use HTTPS, persistent independent secrets, durable
credential and session stores, CSRF protection, rate limiting, and an
independently reviewed release artifact.
