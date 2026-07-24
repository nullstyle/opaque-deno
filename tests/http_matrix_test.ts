import { loadOpaqueWasmBytes } from "../src/wasm.ts";
import {
  createOpaqueAuthServer,
  type OpaqueAuthServer,
} from "../src/server.ts";
import {
  base64UrlToBytes,
  buildLoginFinishInput,
  buildLoginStartInput,
  buildRegistrationFinishInput,
  buildRegistrationStartInput,
  bytesToBase64Url,
  instantiateOpaqueWasm,
  OPAQUE_SIZES,
  type OpaqueWasm,
} from "../src/raw.ts";
import { MemoryOpaqueStore } from "../src/testing.ts";
import type {
  AuthenticatedSession,
  LoginAttempt,
  OpaqueAuthStore,
  OpaqueCredential,
  RegistrationAttempt,
  SessionMutation,
  WebSessionProvider,
} from "../src/types.ts";
import { assert, assertBytesEqual, assertEquals } from "./assert.ts";

const ORIGIN = "https://opaque.test";
const CONTEXT = new TextEncoder().encode(
  "com.nullstyle.opaque-deno.http-test/v1",
);

Deno.test({
  name:
    "HTTP ceremonies bind attempts, reject duplicate/replay, and hide unknown users",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const store = new InspectingStore();
    const sessions = new CountingSessionProvider();
    const auth = await makeAuth({ store, sessions });
    const client = await clientWasm();

    try {
      const registrationStart = client.registrationStart(
        buildRegistrationStartInput({
          blindUniform: filled(OPAQUE_SIZES.blindUniform, 0x11),
          password: new TextEncoder().encode("correct horse battery staple"),
        }),
      );
      const blind = registrationStart.slice(0, OPAQUE_SIZES.blind);
      const registrationRequest = registrationStart.slice(OPAQUE_SIZES.blind);

      // Both starts precede credential creation, exercising the atomic finish.
      const firstStart = await post(auth, "register/start", {
        identifier: "alice@example.test",
        registrationRequest: bytesToBase64Url(registrationRequest),
      });
      const secondStart = await post(auth, "register/start", {
        identifier: "alice@example.test",
        registrationRequest: bytesToBase64Url(registrationRequest),
      });
      assertEquals(firstStart.response.status, 200);
      assertEquals(secondStart.response.status, 200);

      const registrationFinish = client.registrationFinish(
        buildRegistrationFinishInput({
          blind,
          envelopeNonce: filled(OPAQUE_SIZES.nonce, 0x22),
          registrationResponse: responseBytes(
            firstStart.body,
            "registrationResponse",
            OPAQUE_SIZES.registrationResponse,
          ),
          password: new TextEncoder().encode(
            "correct horse battery staple",
          ),
          context: CONTEXT,
        }),
      );
      const registrationRecord = registrationFinish.slice(
        0,
        OPAQUE_SIZES.registrationRecord,
      );
      const registrationId = responseString(firstStart.body, "registrationId");
      const firstFinish = await post(auth, "register/finish", {
        registrationId,
        registrationRecord: bytesToBase64Url(registrationRecord),
      });
      assertEquals(firstFinish.response.status, 200);

      const racingFinish = await post(auth, "register/finish", {
        registrationId: responseString(secondStart.body, "registrationId"),
        registrationRecord: bytesToBase64Url(registrationRecord),
      });
      assertEquals(racingFinish.response.status, 409);
      assertEquals(racingFinish.body.error, "identifier already registered");

      const registrationReplay = await post(auth, "register/finish", {
        registrationId,
        registrationRecord: bytesToBase64Url(registrationRecord),
      });
      assertEquals(registrationReplay.response.status, 400);
      assertEquals(registrationReplay.body.error, "invalid request");

      const duplicateStart = await post(auth, "register/start", {
        identifier: "alice@example.test",
        registrationRequest: bytesToBase64Url(registrationRequest),
      });
      assertEquals(duplicateStart.response.status, 409);

      const loginStart = client.loginStart(buildLoginStartInput({
        blindUniform: filled(OPAQUE_SIZES.blindUniform, 0x33),
        clientNonce: filled(OPAQUE_SIZES.nonce, 0x44),
        clientKeyshareSeed: filled(OPAQUE_SIZES.seed, 0x55),
        password: new TextEncoder().encode("correct horse battery staple"),
      }));
      const clientLoginState = loginStart.slice(
        0,
        OPAQUE_SIZES.clientLoginState,
      );
      const ke1 = loginStart.slice(OPAQUE_SIZES.clientLoginState);
      const loginA = await post(auth, "login/start", {
        identifier: "alice@example.test",
        ke1: bytesToBase64Url(ke1),
      });
      const loginB = await post(auth, "login/start", {
        identifier: "alice@example.test",
        ke1: bytesToBase64Url(ke1),
      });
      assertEquals(loginA.response.status, 200);
      assertEquals(loginB.response.status, 200);

      const loginFinish = client.loginFinish(buildLoginFinishInput({
        clientLoginState,
        ke2: responseBytes(loginA.body, "ke2", OPAQUE_SIZES.ke2),
        password: new TextEncoder().encode("correct horse battery staple"),
        context: CONTEXT,
      }));
      const ke3 = loginFinish.slice(0, OPAQUE_SIZES.ke3);

      // A valid KE3 is bound to login A's server state, not merely the account.
      const crossed = await post(auth, "login/finish", {
        loginId: responseString(loginB.body, "loginId"),
        ke3: bytesToBase64Url(ke3),
      });
      assertGenericUnauthorized(crossed);

      const finishBody = {
        loginId: responseString(loginA.body, "loginId"),
        ke3: bytesToBase64Url(ke3),
      };
      const concurrent = await Promise.all([
        post(auth, "login/finish", finishBody),
        post(auth, "login/finish", finishBody),
      ]);
      assertEquals(
        concurrent.map((result) => result.response.status).sort().join(","),
        "200,401",
      );
      assertEquals(sessions.createdSubjects.length, 1);
      const successfulFinish = concurrent.find((result) =>
        result.response.status === 200
      );
      assert(successfulFinish);
      assert(successfulFinish.response.headers.has("set-cookie"));
      assertBytesEqual(
        loginFinish.slice(OPAQUE_SIZES.ke3 + OPAQUE_SIZES.sessionKey),
        registrationFinish.slice(OPAQUE_SIZES.registrationRecord),
      );

      const replay = await post(auth, "login/finish", finishBody);
      assertGenericUnauthorized(replay);

      const wrongStart = client.loginStart(buildLoginStartInput({
        blindUniform: filled(OPAQUE_SIZES.blindUniform, 0x66),
        clientNonce: filled(OPAQUE_SIZES.nonce, 0x77),
        clientKeyshareSeed: filled(OPAQUE_SIZES.seed, 0x88),
        password: new TextEncoder().encode("wrong password"),
      }));
      const wrongKe1 = wrongStart.slice(OPAQUE_SIZES.clientLoginState);
      const known = await post(auth, "login/start", {
        identifier: "alice@example.test",
        ke1: bytesToBase64Url(wrongKe1),
      });
      const unknown = await post(auth, "login/start", {
        identifier: "nobody@example.test",
        ke1: bytesToBase64Url(wrongKe1),
      });
      assertEquals(known.response.status, unknown.response.status);
      assertEquals(known.response.status, 200);
      assertEquals(
        Object.keys(known.body).sort().join(","),
        Object.keys(unknown.body).sort().join(","),
      );
      assertEquals(
        responseBytes(known.body, "ke2", OPAQUE_SIZES.ke2).byteLength,
        OPAQUE_SIZES.ke2,
      );
      assertEquals(
        responseBytes(unknown.body, "ke2", OPAQUE_SIZES.ke2).byteLength,
        OPAQUE_SIZES.ke2,
      );

      const invalidKe3 = bytesToBase64Url(new Uint8Array(OPAQUE_SIZES.ke3));
      const knownFinish = await post(auth, "login/finish", {
        loginId: responseString(known.body, "loginId"),
        ke3: invalidKe3,
      });
      const unknownFinish = await post(auth, "login/finish", {
        loginId: responseString(unknown.body, "loginId"),
        ke3: invalidKe3,
      });
      assertGenericUnauthorized(knownFinish);
      assertGenericUnauthorized(unknownFinish);
      assertEquals(
        await knownFinish.response.clone().text(),
        await unknownFinish.response.clone().text(),
      );

      // The server owns and wipes every state object returned by takeLoginAttempt.
      assert(store.takenLoginStates.length >= 4);
      for (const state of store.takenLoginStates) {
        assert(
          state.every((byte) => byte === 0),
          "server login state was not wiped",
        );
      }

      registrationStart.fill(0);
      registrationFinish.fill(0);
      loginStart.fill(0);
      loginFinish.fill(0);
      wrongStart.fill(0);
    } finally {
      auth.dispose();
    }
  },
});

Deno.test("HTTP attempt expiry maps to generic protocol errors and wipes login state", async () => {
  const store = new InspectingStore();
  const auth = await makeAuth({
    store,
    sessions: new CountingSessionProvider(),
    attemptTtlMs: 1,
  });
  const client = await clientWasm();

  try {
    const registrationStart = client.registrationStart(
      buildRegistrationStartInput({
        blindUniform: filled(OPAQUE_SIZES.blindUniform, 0x12),
        password: Uint8Array.of(1),
      }),
    );
    const registration = await post(auth, "register/start", {
      identifier: "expiring@example.test",
      registrationRequest: bytesToBase64Url(
        registrationStart.slice(OPAQUE_SIZES.blind),
      ),
    });
    assertEquals(registration.response.status, 200);

    const loginStart = client.loginStart(buildLoginStartInput({
      blindUniform: filled(OPAQUE_SIZES.blindUniform, 0x23),
      clientNonce: filled(OPAQUE_SIZES.nonce, 0x34),
      clientKeyshareSeed: filled(OPAQUE_SIZES.seed, 0x45),
      password: Uint8Array.of(1),
    }));
    const login = await post(auth, "login/start", {
      identifier: "unknown-expiring@example.test",
      ke1: bytesToBase64Url(loginStart.slice(OPAQUE_SIZES.clientLoginState)),
    });
    assertEquals(login.response.status, 200);
    await delay(10);

    const expiredRegistration = await post(auth, "register/finish", {
      registrationId: responseString(registration.body, "registrationId"),
      registrationRecord: bytesToBase64Url(
        new Uint8Array(OPAQUE_SIZES.registrationRecord),
      ),
    });
    assertEquals(expiredRegistration.response.status, 400);

    const expiredLogin = await post(auth, "login/finish", {
      loginId: responseString(login.body, "loginId"),
      ke3: bytesToBase64Url(new Uint8Array(OPAQUE_SIZES.ke3)),
    });
    assertGenericUnauthorized(expiredLogin);
    assertEquals(store.takenLoginStates.length, 1);
    assert(store.takenLoginStates[0].every((byte) => byte === 0));
  } finally {
    auth.dispose();
  }
});

Deno.test("HTTP routes enforce wire format and status mappings", async () => {
  const auth = await makeAuth({
    store: new MemoryOpaqueStore(),
    sessions: new CountingSessionProvider(),
  });
  try {
    const method = await auth.handle(
      new Request(`${ORIGIN}/api/auth/register/start`),
    );
    assertEquals(method.status, 405);
    assertEquals(method.headers.get("allow"), "POST");

    const malformedCases: Request[] = [
      new Request(`${ORIGIN}/api/auth/register/start`, {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: "{}",
      }),
      new Request(`${ORIGIN}/api/auth/register/start`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "not-json",
      }),
      jsonRequest("register/start", { version: 2 }),
      jsonRequest("register/start", {
        version: 1,
        identifier: "alice",
        registrationRequest: "not+base64",
      }),
      jsonRequest("register/start", {
        version: 1,
        identifier: "alice",
        registrationRequest: bytesToBase64Url(Uint8Array.of(1)),
      }),
      jsonRequest("login/finish", {
        version: 1,
        loginId: "",
        ke3: bytesToBase64Url(new Uint8Array(OPAQUE_SIZES.ke3)),
      }),
    ];
    for (const request of malformedCases) {
      const response = await auth.handle(request);
      assertEquals(response.status, 400);
      assertEquals((await response.json()).error, "invalid request");
      assertEquals(response.headers.get("cache-control"), "no-store");
    }

    const missing = await auth.handle(new Request(`${ORIGIN}/api/auth/nope`));
    assertEquals(missing.status, 404);
  } finally {
    auth.dispose();
  }

  const denied = await makeAuth({
    store: new MemoryOpaqueStore(),
    sessions: new CountingSessionProvider(),
    authorizeRegistration: () => null,
  });
  try {
    const response = await post(denied, "register/start", {
      identifier: "denied@example.test",
      registrationRequest: bytesToBase64Url(
        new Uint8Array(OPAQUE_SIZES.registrationRequest),
      ),
    });
    assertEquals(response.response.status, 403);
    assertEquals(response.body.error, "registration denied");
  } finally {
    denied.dispose();
  }

  const unavailable = await makeAuth({
    store: new UnavailableStore(),
    sessions: new CountingSessionProvider(),
  });
  try {
    const response = await post(unavailable, "login/start", {
      identifier: "alice",
      ke1: bytesToBase64Url(new Uint8Array(OPAQUE_SIZES.ke1)),
    });
    assertEquals(response.response.status, 503);
    assertEquals(response.body.error, "service unavailable");
  } finally {
    unavailable.dispose();
  }
});

Deno.test("immutable WASM route exposes exact asset headers", async () => {
  const auth = await makeAuth({
    store: new MemoryOpaqueStore(),
    sessions: new CountingSessionProvider(),
  });
  try {
    assert(auth.assetPath.startsWith("/api/auth/opaque."));
    assert(auth.assetPath.endsWith(".wasm"));
    const response = await auth.handle(
      new Request(`${ORIGIN}${auth.assetPath}`),
    );
    const bytes = new Uint8Array(await response.arrayBuffer());
    assertEquals(response.status, 200);
    assertEquals(response.headers.get("content-type"), "application/wasm");
    assertEquals(
      response.headers.get("cache-control"),
      "public, max-age=31536000, immutable",
    );
    assert(response.headers.get("etag")?.startsWith('"sha256-'));
    assertEquals(
      response.headers.get("content-length"),
      String(bytes.byteLength),
    );
    assertEquals(response.headers.get("x-content-type-options"), "nosniff");
    assertEquals(
      response.headers.get("cross-origin-resource-policy"),
      "same-origin",
    );

    const method = await auth.handle(
      new Request(`${ORIGIN}${auth.assetPath}`, {
        method: "POST",
      }),
    );
    assertEquals(method.status, 405);
    assertEquals(method.headers.get("allow"), "GET");
  } finally {
    auth.dispose();
  }
});

interface AuthOptions {
  store: OpaqueAuthStore;
  sessions: WebSessionProvider;
  attemptTtlMs?: number;
  authorizeRegistration?: () => null;
}

function makeAuth(options: AuthOptions): Promise<OpaqueAuthServer> {
  return createOpaqueAuthServer({
    context: CONTEXT,
    serverKeySeed: filled(32, 1),
    oprfSeed: filled(64, 2),
    fakeRecordSeed: filled(32, 3),
    store: options.store,
    sessionProvider: options.sessions,
    attemptTtlMs: options.attemptTtlMs,
    authorizeRegistration: options.authorizeRegistration,
  });
}

let clientWasmPromise: Promise<OpaqueWasm> | undefined;
function clientWasm(): Promise<OpaqueWasm> {
  clientWasmPromise ??= loadOpaqueWasmBytes().then(instantiateOpaqueWasm);
  return clientWasmPromise;
}

function jsonRequest(path: string, body: Record<string, unknown>): Request {
  return new Request(`${ORIGIN}/api/auth/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function post(
  auth: OpaqueAuthServer,
  path: string,
  body: Record<string, unknown>,
): Promise<{ response: Response; body: Record<string, unknown> }> {
  const response = await auth.handle(
    jsonRequest(path, { version: 1, ...body }),
  );
  const clone = response.clone();
  return {
    response,
    body: await clone.json() as Record<string, unknown>,
  };
}

function responseString(body: Record<string, unknown>, name: string): string {
  const value = body[name];
  assert(typeof value === "string" && value.length > 0, `${name} is missing`);
  return value;
}

function responseBytes(
  body: Record<string, unknown>,
  name: string,
  length: number,
): Uint8Array {
  const value = base64UrlToBytes(responseString(body, name));
  assertEquals(value.byteLength, length);
  return value;
}

function assertGenericUnauthorized(
  result: { response: Response; body: Record<string, unknown> },
): void {
  assertEquals(result.response.status, 401);
  assertEquals(result.body.version, 1);
  assertEquals(result.body.ok, false);
  assertEquals(Object.keys(result.body).sort().join(","), "ok,version");
  assertEquals(result.response.headers.get("cache-control"), "no-store");
}

function filled(length: number, value: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

class InspectingStore implements OpaqueAuthStore {
  readonly #memory = new MemoryOpaqueStore();
  readonly takenLoginStates: Uint8Array[] = [];

  getCredential(identifier: string): Promise<OpaqueCredential | null> {
    return this.#memory.getCredential(identifier);
  }

  createCredential(credential: OpaqueCredential): Promise<boolean> {
    return this.#memory.createCredential(credential);
  }

  putRegistrationAttempt(attempt: RegistrationAttempt): Promise<void> {
    return this.#memory.putRegistrationAttempt(attempt);
  }

  takeRegistrationAttempt(id: string): Promise<RegistrationAttempt | null> {
    return this.#memory.takeRegistrationAttempt(id);
  }

  putLoginAttempt(attempt: LoginAttempt): Promise<void> {
    return this.#memory.putLoginAttempt(attempt);
  }

  async takeLoginAttempt(id: string): Promise<LoginAttempt | null> {
    const attempt = await this.#memory.takeLoginAttempt(id);
    if (attempt) this.takenLoginStates.push(attempt.serverLoginState);
    return attempt;
  }
}

class CountingSessionProvider implements WebSessionProvider {
  readonly createdSubjects: string[] = [];

  create(subject: string, _request: Request): Promise<SessionMutation> {
    this.createdSubjects.push(subject);
    return Promise.resolve({ setCookie: "session=test; HttpOnly; Secure" });
  }

  authenticate(_request: Request): Promise<AuthenticatedSession | null> {
    return Promise.resolve(null);
  }

  destroy(_request: Request): Promise<SessionMutation> {
    return Promise.resolve({ setCookie: "session=; Max-Age=0" });
  }
}

class UnavailableStore implements OpaqueAuthStore {
  getCredential(_identifier: string): Promise<OpaqueCredential | null> {
    return Promise.reject(new Error("database offline"));
  }

  createCredential(_credential: OpaqueCredential): Promise<boolean> {
    return Promise.reject(new Error("database offline"));
  }

  putRegistrationAttempt(_attempt: RegistrationAttempt): Promise<void> {
    return Promise.reject(new Error("database offline"));
  }

  takeRegistrationAttempt(_id: string): Promise<RegistrationAttempt | null> {
    return Promise.reject(new Error("database offline"));
  }

  putLoginAttempt(_attempt: LoginAttempt): Promise<void> {
    return Promise.reject(new Error("database offline"));
  }

  takeLoginAttempt(_id: string): Promise<LoginAttempt | null> {
    return Promise.reject(new Error("database offline"));
  }
}
