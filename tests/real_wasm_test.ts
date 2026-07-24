import { createOpaqueClient } from "../src/client.ts";
import { loadOpaqueWasmBytes } from "../src/wasm.ts";
import { createOpaqueAuthServer } from "../src/server.ts";
import { buildRegistrationStartInput, OpaqueWasm } from "../src/raw.ts";
import { MemoryOpaqueStore } from "../src/testing.ts";
import type {
  AuthenticatedSession,
  SessionMutation,
  WebSessionProvider,
} from "../src/types.ts";
import {
  assert,
  assertBytesEqual,
  assertEquals,
  assertRejects,
} from "./assert.ts";

Deno.test({
  name: "production WASM artifact has ABI v5 and no test exports",
  async fn() {
    const module = await WebAssembly.compile(
      (await loadOpaqueWasmBytes()).slice().buffer as ArrayBuffer,
    );
    const exports = new Set(
      WebAssembly.Module.exports(module).map((entry) => entry.name),
    );
    assert(exports.has("serverCreateFakeRecord"));
    assert(!exports.has("registrationFinishIdentityTestVector"));
    const instance = await WebAssembly.instantiate(module);
    assertEquals((instance.exports.version as () => number)(), 5);
  },
});

Deno.test("registration start does not retain its exact password or input", async () => {
  const module = await WebAssembly.compile(
    (await loadOpaqueWasmBytes()).slice().buffer as ArrayBuffer,
  );
  const instance = await WebAssembly.instantiate(module);
  const wasm = new OpaqueWasm(instance);
  wasm.assertVersion();
  wasm.assertLengths();
  const password = Uint8Array.from(
    { length: 48 },
    (_, index) => (index * 73 + 19) & 0xff,
  );
  const blindUniform = Uint8Array.from(
    { length: 64 },
    (_, index) => (index * 151 + 37) & 0xff,
  );
  const input = buildRegistrationStartInput({ blindUniform, password });
  const output = wasm.registrationStart(input);
  try {
    const memory = new Uint8Array(
      (instance.exports.memory as WebAssembly.Memory).buffer,
    );
    assertEquals(findBytes(memory, input), -1);
    assertEquals(findBytes(memory, password), -1);
  } finally {
    input.fill(0);
    output.fill(0);
    password.fill(0);
    blindUniform.fill(0);
  }
});

Deno.test("recover() scrubs linear memory and keeps the instance usable", async () => {
  const module = await WebAssembly.compile(
    (await loadOpaqueWasmBytes()).slice().buffer as ArrayBuffer,
  );
  const instance = await WebAssembly.instantiate(module);
  const memory = instance.exports.memory as WebAssembly.Memory;
  const wasm = new OpaqueWasm(instance);
  wasm.snapshot();
  wasm.assertVersion();
  wasm.assertLengths();

  const password = Uint8Array.from(
    { length: 48 },
    (_, i) => (i * 73 + 19) & 0xff,
  );
  const blindUniform = Uint8Array.from(
    { length: 64 },
    (_, i) => (i * 151 + 37) & 0xff,
  );
  // Exercise the allocator, then plant a secret in the heap region (well above
  // the ~1 MiB of static data) to simulate memory a trap could leave dirty.
  wasm.registrationStart(
    buildRegistrationStartInput({ blindUniform, password }),
  )
    .fill(0);
  const secret = Uint8Array.from(
    { length: 64 },
    (_, i) => (i * 211 + 5) & 0xff,
  );
  new Uint8Array(memory.buffer).set(secret, 4_000_000);
  assert(findBytes(new Uint8Array(memory.buffer), secret) >= 0);

  wasm.recover();

  // The planted secret is gone and the allocator was reset cleanly.
  assertEquals(findBytes(new Uint8Array(memory.buffer), secret), -1);
  assertEquals(wasm.poisoned, false);
  wasm.assertVersion();
  const again = wasm.registrationStart(
    buildRegistrationStartInput({ blindUniform, password }),
  );
  assert(again.byteLength > 0);
  again.fill(0);
  password.fill(0);
  blindUniform.fill(0);
  secret.fill(0);
});

Deno.test("recover() refuses to run without a prior snapshot", async () => {
  const module = await WebAssembly.compile(
    (await loadOpaqueWasmBytes()).slice().buffer as ArrayBuffer,
  );
  const wasm = new OpaqueWasm(await WebAssembly.instantiate(module));
  let message = "";
  try {
    wasm.recover();
  } catch (error) {
    message = error instanceof Error ? error.message : String(error);
  }
  assert(message.includes("not armed for recovery"));
});

Deno.test({
  name:
    "worker client registers and authenticates through the standard handler",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const sessions = new TestSessionProvider();
    const auth = await createOpaqueAuthServer({
      context: "com.nullstyle.opaque-deno.test/v1",
      serverKeySeed: new Uint8Array(32).fill(1),
      oprfSeed: new Uint8Array(64).fill(2),
      fakeRecordSeed: new Uint8Array(32).fill(3),
      store: new MemoryOpaqueStore(),
      sessionProvider: sessions,
    });
    const http = Deno.serve({
      hostname: "127.0.0.1",
      port: 0,
      onListen() {},
    }, (request) => auth.handle(request));
    const address = http.addr as Deno.NetAddr;
    const origin = `http://127.0.0.1:${address.port}`;
    const client = createOpaqueClient({
      context: "com.nullstyle.opaque-deno.test/v1",
      baseUrl: origin,
    });

    try {
      const asset = await fetch(`${origin}${auth.assetPath}`);
      assertEquals(asset.status, 200);
      assertEquals(asset.headers.get("content-type"), "application/wasm");
      assert(asset.headers.get("cache-control")?.includes("immutable"));
      await asset.body?.cancel();

      const registration = await client.register(
        "Alice@example.test",
        "correct horse battery staple",
      );
      assertEquals(registration.exportKey.byteLength, 64);
      const login = await client.login(
        "Alice@example.test",
        "correct horse battery staple",
      );
      assertBytesEqual(login.exportKey, registration.exportKey);
      assert(sessions.subjectForLastCreate.length > 0);
      assertEquals(sessions.createdSubjects.length, 1);

      await assertRejects(
        () => client.login("Alice@example.test", "wrong password"),
        (error) =>
          assertEquals((error as Error).name, "OpaqueAuthenticationError"),
      );
      await assertRejects(
        () => client.login("unknown@example.test", "wrong password"),
        (error) =>
          assertEquals((error as Error).name, "OpaqueAuthenticationError"),
      );
      await assertRejects(() =>
        client.register("Alice@example.test", "another password")
      );

      const wrongType = await fetch(`${origin}/api/auth/login/start`, {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: JSON.stringify({ version: 1 }),
      });
      assertEquals(wrongType.status, 400);

      await client.logout();
      assertEquals(sessions.destroyCount, 1);
      registration.exportKey.fill(0);
      login.exportKey.fill(0);
    } finally {
      client.dispose();
      await http.shutdown();
      auth.dispose();
    }
  },
});

class TestSessionProvider implements WebSessionProvider {
  readonly createdSubjects: string[] = [];
  subjectForLastCreate = "";
  destroyCount = 0;

  create(subject: string, _request: Request): Promise<SessionMutation> {
    this.createdSubjects.push(subject);
    this.subjectForLastCreate = subject;
    const session: AuthenticatedSession = {
      subject,
      sessionId: crypto.randomUUID(),
      issuedAt: new Date(),
      expiresAt: new Date(Date.now() + 60_000),
    };
    return Promise.resolve({
      setCookie: "__Host-session=test; Secure; HttpOnly; Path=/",
      session,
    });
  }

  authenticate(_request: Request): Promise<AuthenticatedSession | null> {
    return Promise.resolve(null);
  }

  destroy(_request: Request): Promise<SessionMutation> {
    this.destroyCount += 1;
    return Promise.resolve({
      setCookie: "__Host-session=; Max-Age=0; Secure; HttpOnly; Path=/",
    });
  }
}

function findBytes(haystack: Uint8Array, needle: Uint8Array): number {
  outer:
  for (
    let offset = 0;
    offset <= haystack.byteLength - needle.byteLength;
    offset++
  ) {
    if (haystack[offset] !== needle[0]) continue;
    for (let index = 1; index < needle.byteLength; index++) {
      if (haystack[offset + index] !== needle[index]) continue outer;
    }
    return offset;
  }
  return -1;
}
