# Bare Deno consumer fixture

This fixture composes the local `@nullstyle/opaque` and `@nullstyle/paseto`
packages behind one web-standard `Deno.serve` handler. It serves the OPAQUE auth
routes, immutable browser WASM asset, and a PASETO-protected `/protected`
endpoint.

> **Warning:** `app.ts` deliberately uses deterministic test-only secrets and
> process-local memory stores so the integration test is self-contained. Never
> reuse these values or stores in an application. Load independent persisted
> secrets and use durable credential and session stores in every deployment.

Run the real worker/WASM integration test:

```sh
deno task check
deno task test
```

Or start the local fixture at `http://127.0.0.1:8000`:

```sh
deno task start
```

The integration test performs registration, generic wrong-password rejection,
login, protected-route authentication, client logout, and immediate session
revocation. Deno's `fetch` does not maintain a browser cookie jar, so a tiny
Deno-only worker shim provides that browser behavior before loading the real
OPAQUE worker unchanged. The test also captures the issued `Set-Cookie` value
through an explicit hook so its parent can probe the protected route. The client
streams the real WASM asset from the fixture.
