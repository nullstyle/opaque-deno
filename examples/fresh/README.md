# Fresh consumer fixture

This Fresh 2.3 and Vite 7 application consumes the sibling `@nullstyle/opaque`
and `@nullstyle/paseto` packages through local import-map entries. It
demonstrates the intended middleware order, a browser-only
`createOpaqueClient()` island, and a protected route backed by a revocable
PASETO session.

> **Warning**: this fixture deliberately uses deterministic test-only secrets
> and process-local memory stores. Never copy those values or stores into an
> application. Load independent, persistent OPAQUE and PASETO secrets from a
> secret manager and use durable storage.

```sh
deno task check
deno task build
deno task e2e
```

`deno task e2e` builds the production Fresh server, launches it on an available
local port, and runs registration, bad-password login, successful login,
protected-page, and logout flows in Chromium. Successful completion also proves
that Vite emitted the module Worker and that the hash-versioned OPAQUE WASM
asset executed in a real browser.
