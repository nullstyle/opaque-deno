# `@nullstyle/opaque`

OPAQUE password authentication for Deno and Fresh, backed by the `opaque-zig`
WebAssembly implementation. Passwords are stretched with Argon2id inside a
browser module worker and are never sent to the server.

> [!WARNING]
> This package and `opaque-zig` have not received an independent security audit.
> This beta is experimental. Rate-limit every authentication endpoint, protect
> state-changing routes against CSRF, and arrange an expert review before using
> it for sensitive production accounts.

## Server

```ts
import { createOpaqueAuthServer } from "jsr:@nullstyle/opaque";
import { DenoKvOpaqueStore } from "jsr:@nullstyle/opaque/kv";

const kv = await Deno.openKv();
const auth = await createOpaqueAuthServer({
  context: "com.example.my-app/auth/v1",
  serverKeySeed: decodeSecret(Deno.env.get("OPAQUE_SERVER_KEY_SEED")),
  oprfSeed: decodeSecret(Deno.env.get("OPAQUE_OPRF_SEED")),
  fakeRecordSeed: decodeSecret(Deno.env.get("OPAQUE_FAKE_RECORD_SEED")),
  store: new DenoKvOpaqueStore(kv),
  sessionProvider,
});

Deno.serve((request) => auth.handle(request));
```

The three seeds are persistent application secrets: 32, 64, and 32 bytes
respectively. Never generate replacements during normal startup. `context` is
also required and must remain identical on the server and browser client.

## Browser client

```ts
import { createOpaqueClient } from "jsr:@nullstyle/opaque/client";

const auth = createOpaqueClient({ context: "com.example.my-app/auth/v1" });
const { exportKey } = await auth.login(identifier, password);
// Use or copy exportKey, then wipe it as soon as possible.
exportKey.fill(0);
auth.dispose();
```

`register()` and `login()` return the 64-byte client `exportKey`. The OPAQUE
session key is wiped and never exposed by the high-level API.

## Fresh

`createOpaqueFreshMiddleware(auth)` adapts the same web-standard handler to a
Fresh middleware function without taking a runtime dependency on Fresh. Order
middleware as: CSRF protection, OPAQUE routes, then session authentication. Only
import `@nullstyle/opaque/client` from islands; it has no server secret and no
WASM bundled in. The worker fetches the immutable, hash-versioned WASM asset
from the auth handler.

## Storage and sessions

The default export defines `OpaqueAuthStore` and the structural
`WebSessionProvider` interface. `DenoKvOpaqueStore` is available from `./kv` and
requires `--unstable-kv`. `MemoryOpaqueStore` from `./testing` is only for tests
and local demonstrations.

Identifiers are exact UTF-8 by default. Pass one `canonicalizeIdentifier`
callback if the application has a documented normalization policy; it is applied
before every storage operation.

Advanced consumers can use the ABI adapter from `./raw`. The WASM ships as the
real `src/opaque.wasm` binary (loaded with a static `import`); JSR publishes
that file, not the submodule source. It is built from the vendored `opaque-zig`
source under `vendor/opaque-zig` — a git submodule pinned to `v0.3.2-2-ga177f83`
— by `mise run build-wasm`, which runs `zig build wasm` plus the pinned Binaryen
130 `wasm-opt -Oz` pipeline (2,310,767 → 263,399 bytes) and re-verifies the
result against `wasm.lock.json`. The committed `src/opaque.wasm` is the source
of truth; `deno task check` verifies it without needing the Zig toolchain.

Each instance reserves 20.6 MiB of WASM linear memory, nearly all of it the
Argon2id working set. Server-side operations share one instance per isolate.

To rebuild, run `git submodule update --init` once, then `mise run build-wasm`.
Reproducing the byte-identical binary requires Zig `0.17.0-dev.1252+e4b325c19`
on PATH (opaque-zig tracks the Zig `0.17.0-dev` line, which mise cannot pin
exactly) plus Binaryen 130.

Licensed under MIT. The `opaque-zig` artifact is available under MIT OR
Apache-2.0; see `wasm.lock.json` for exact provenance.

The WASM is built from the pinned `opaque-zig` submodule and reproduces the
recorded checksum. That candidate passes this package's full-memory secret probe
— see [SECURITY.md](SECURITY.md) — which through v0.3.1 found ephemeral secrets
left in the WASM shadow stack. `deno task publish:check` runs the probe on every
publish attempt, alongside the artifact and provenance checks described in
[SECURITY.md](SECURITY.md): the shipped binary must hash to the value
`wasm.lock.json` records, and the `opaque-zig` submodule must be pinned — both
in the working checkout and in this repository's recorded gitlink — at the
commit the lock names.
