import { createOpaqueAuthServer } from "@nullstyle/opaque";
import { createOpaqueFreshMiddleware } from "@nullstyle/opaque/fresh";
import { MemoryOpaqueStore } from "@nullstyle/opaque/testing";
import { PasetoSessionManager } from "@nullstyle/paseto";
import { createPasetoFreshMiddleware } from "@nullstyle/paseto/fresh";
import { MemorySessionStore } from "@nullstyle/paseto/testing";
import { App, staticFiles } from "fresh";
import { AUTH_CONTEXT } from "./auth_context.ts";
import { define, type State } from "./utils.ts";

/*
 * WARNING: TEST FIXTURE ONLY.
 *
 * These deterministic secrets and process-local stores make browser tests
 * repeatable. A real application must load independent, persistent secrets
 * from a secret manager and use durable credential/session stores.
 */
const TEST_ONLY_SERVER_KEY_SEED = deterministicBytes(32, 0x11);
const TEST_ONLY_OPRF_SEED = deterministicBytes(64, 0x41);
const TEST_ONLY_FAKE_RECORD_SEED = deterministicBytes(32, 0x91);
const TEST_ONLY_PASETO_KEY = deterministicBytes(32, 0xc1);

const opaqueStore = new MemoryOpaqueStore();
const sessionStore = new MemorySessionStore();
const sessions = new PasetoSessionManager({
  keyRing: { active: TEST_ONLY_PASETO_KEY },
  store: sessionStore,
  issuer: "opaque-deno-fresh-example",
  audience: "opaque-deno-fresh-browser",
  ttlSeconds: 15 * 60,
  cookie: { insecureDevelopment: true, sameSite: "Lax" },
});
TEST_ONLY_PASETO_KEY.fill(0);
const opaque = await createOpaqueAuthServer({
  context: AUTH_CONTEXT,
  serverKeySeed: TEST_ONLY_SERVER_KEY_SEED,
  oprfSeed: TEST_ONLY_OPRF_SEED,
  fakeRecordSeed: TEST_ONLY_FAKE_RECORD_SEED,
  store: opaqueStore,
  sessionProvider: sessions,
});
TEST_ONLY_SERVER_KEY_SEED.fill(0);
TEST_ONLY_OPRF_SEED.fill(0);
TEST_ONLY_FAKE_RECORD_SEED.fill(0);

export const app = new App<State>();

app.use(staticFiles());
// Middleware order is deliberate: CSRF, OPAQUE endpoints, session state.
app.use(define.middleware(async (ctx) => {
  if (["GET", "HEAD", "OPTIONS"].includes(ctx.req.method)) {
    return await ctx.next();
  }
  const expectedOrigin = new URL(ctx.req.url).origin;
  if (ctx.req.headers.get("origin") !== expectedOrigin) {
    return new Response("Cross-site request rejected", { status: 403 });
  }
  return await ctx.next();
}));
app.use(createOpaqueFreshMiddleware<State>(opaque));
app.use(createPasetoFreshMiddleware({ sessions }));

app.fsRoutes();

function deterministicBytes(length: number, offset: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (offset + index) & 0xff);
}
