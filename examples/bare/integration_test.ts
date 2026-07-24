import {
  createOpaqueClient,
  OpaqueAuthenticationError,
  type OpaqueClient,
} from "@nullstyle/opaque/client";
import type { SessionMutation } from "@nullstyle/opaque";
import { createBareApp, OPAQUE_CONTEXT } from "./app.ts";

Deno.test("real worker and WASM complete the bare-Deno auth lifecycle", async () => {
  let createdSession: SessionMutation | undefined;
  const app = await createBareApp({
    onSessionCreated: (mutation) => createdSession = mutation,
  });
  const server = Deno.serve(
    {
      hostname: "127.0.0.1",
      port: 0,
      onListen: () => {},
    },
    app.handler,
  );
  const address = server.addr as Deno.NetAddr;
  const baseUrl = `http://${address.hostname}:${address.port}`;
  let client: OpaqueClient | undefined;
  let registrationKey: Uint8Array | undefined;

  try {
    client = createOpaqueClient({
      context: OPAQUE_CONTEXT,
      baseUrl,
      workerUrl: new URL("./cookie_worker.ts", import.meta.url),
    });

    const registration = await client.register(
      "reader@example.test",
      "correct horse battery staple",
    );
    assertEquals(registration.exportKey.byteLength, 64);
    registrationKey = registration.exportKey.slice();
    registration.exportKey.fill(0);

    const genericFailure = await captureError(() =>
      client!.login("reader@example.test", "wrong password")
    );
    assert(genericFailure instanceof OpaqueAuthenticationError);
    assertEquals(genericFailure.message, "wrong identifier or password");

    const login = await client.login(
      "reader@example.test",
      "correct horse battery staple",
    );
    assertBytesEqual(login.exportKey, registrationKey);
    login.exportKey.fill(0);

    assert(createdSession?.session);
    const cookie = cookiePair(createdSession.setCookie);
    const protectedResponse = await fetch(`${baseUrl}/protected`, {
      headers: { cookie },
    });
    assertEquals(protectedResponse.status, 200);
    const protectedBody = await protectedResponse.json();
    assertEquals(
      (protectedBody as { subject: string }).subject,
      createdSession.session.subject,
    );

    await client.logout();

    const revokedResponse = await fetch(`${baseUrl}/protected`, {
      headers: { cookie },
    });
    assertEquals(revokedResponse.status, 401);
  } finally {
    registrationKey?.fill(0);
    client?.dispose();
    await server.shutdown();
    app.dispose();
  }
});

async function captureError(operation: () => Promise<unknown>): Promise<Error> {
  try {
    await operation();
  } catch (error) {
    if (error instanceof Error) return error;
    throw new Error("operation rejected with a non-Error value");
  }
  throw new Error("operation unexpectedly succeeded");
}

function cookiePair(setCookie: string): string {
  const pair = setCookie.split(";", 1)[0];
  assert(pair.includes("="));
  return pair;
}

function assert(
  condition: unknown,
  message = "assertion failed",
): asserts condition {
  if (!condition) throw new Error(message);
}

function assertEquals<T>(actual: T, expected: T): void {
  if (!Object.is(actual, expected)) {
    throw new Error(`expected ${String(expected)}, received ${String(actual)}`);
  }
}

function assertBytesEqual(actual: Uint8Array, expected: Uint8Array): void {
  assertEquals(actual.byteLength, expected.byteLength);
  for (let index = 0; index < actual.byteLength; index++) {
    if (actual[index] !== expected[index]) {
      throw new Error(`byte arrays differ at index ${index}`);
    }
  }
}
