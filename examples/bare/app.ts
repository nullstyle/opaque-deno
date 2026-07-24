import {
  createOpaqueAuthServer,
  type OpaqueAuthServer,
  type SessionMutation,
  type WebSessionProvider,
} from "@nullstyle/opaque";
import { MemoryOpaqueStore } from "@nullstyle/opaque/testing";
import { PasetoSessionManager } from "@nullstyle/paseto";
import { MemorySessionStore } from "@nullstyle/paseto/testing";

export const OPAQUE_CONTEXT = "dev.nullstyle.opaque-deno/bare-fixture/v1";

/** Optional observability hook used by the Deno integration test's cookie jar. */
export interface BareAppOptions {
  onSessionCreated?: (mutation: SessionMutation) => void;
}

/** A complete in-memory bare-Deno OPAQUE and PASETO application fixture. */
export interface BareApp {
  handler(request: Request): Promise<Response>;
  auth: OpaqueAuthServer;
  sessions: PasetoSessionManager;
  dispose(): void;
}

/**
 * Create the bare-Deno fixture.
 *
 * This intentionally uses deterministic credentials and process-local stores.
 * Real applications must load independent persisted secrets and durable stores.
 */
export async function createBareApp(
  options: BareAppOptions = {},
): Promise<BareApp> {
  // deno-lint-ignore no-console
  console.warn(
    "WARNING: bare fixture uses deterministic TEST-ONLY secrets and in-memory stores; never deploy them",
  );

  const pasetoKey = deterministicBytes(32, 0x91);
  const sessions = new PasetoSessionManager({
    keyRing: { active: pasetoKey },
    store: new MemorySessionStore(),
    issuer: "dev.nullstyle.opaque-deno/bare-fixture",
    audience: "bare-fixture",
    ttlSeconds: 15 * 60,
    cookie: { insecureDevelopment: true },
  });
  pasetoKey.fill(0);

  const sessionProvider: WebSessionProvider = options.onSessionCreated
    ? {
      async create(subject, request) {
        const mutation = await sessions.create(subject, request);
        options.onSessionCreated?.(mutation);
        return mutation;
      },
      authenticate: (request) => sessions.authenticate(request),
      destroy: (request) => sessions.destroy(request),
    }
    : sessions;

  const serverKeySeed = deterministicBytes(32, 0x11);
  const oprfSeed = deterministicBytes(64, 0x31);
  const fakeRecordSeed = deterministicBytes(32, 0x71);
  let auth: OpaqueAuthServer;
  try {
    auth = await createOpaqueAuthServer({
      context: OPAQUE_CONTEXT,
      serverKeySeed,
      oprfSeed,
      fakeRecordSeed,
      store: new MemoryOpaqueStore(),
      sessionProvider,
    });
  } catch (error) {
    sessions.dispose();
    throw error;
  } finally {
    serverKeySeed.fill(0);
    oprfSeed.fill(0);
    fakeRecordSeed.fill(0);
  }

  return {
    auth,
    sessions,
    async handler(request): Promise<Response> {
      const authResponse = await auth.route(request);
      if (authResponse) return authResponse;

      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/protected") {
        const session = await sessions.authenticate(request);
        return session
          ? Response.json({ subject: session.subject })
          : Response.json({ error: "unauthorized" }, { status: 401 });
      }
      if (request.method === "GET" && url.pathname === "/") {
        return Response.json({ service: "opaque-deno bare fixture" });
      }
      return new Response("Not found", { status: 404 });
    },
    dispose(): void {
      auth.dispose();
      sessions.dispose();
    },
  };
}

function deterministicBytes(length: number, start: number): Uint8Array {
  return Uint8Array.from(
    { length },
    (_, index) => (start + index * 17) & 0xff,
  );
}
