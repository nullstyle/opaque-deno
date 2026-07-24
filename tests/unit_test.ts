import { base64UrlToBytes, bytesToBase64Url, OpaqueWasm } from "../src/raw.ts";
import { MemoryOpaqueStore } from "../src/testing.ts";
import {
  assert,
  assertBytesEqual,
  assertEquals,
  assertRejects,
} from "./assert.ts";

Deno.test("base64url encoding is canonical and strict", async () => {
  const bytes = Uint8Array.of(0, 1, 2, 253, 254, 255);
  assertEquals(bytesToBase64Url(bytes), "AAEC_f7_");
  assertBytesEqual(base64UrlToBytes("AAEC_f7_"), bytes);
  await assertRejects(() => base64UrlToBytes("not+base64"));
  await assertRejects(() => base64UrlToBytes("a"));
});

Deno.test("MemoryOpaqueStore creates credentials atomically and consumes attempts once", async () => {
  const store = new MemoryOpaqueStore();
  const now = new Date();
  const credential = {
    identifier: "alice@example.test",
    subject: "subject-1",
    credentialIdentifier: Uint8Array.of(1, 2),
    registrationRecord: new Uint8Array(192).fill(3),
    createdAt: now,
    updatedAt: now,
  };
  assert(await store.createCredential(credential));
  assertEquals(await store.createCredential(credential), false);
  const loaded = await store.getCredential(credential.identifier);
  assert(loaded);
  loaded.registrationRecord.fill(9);
  assertEquals(
    (await store.getCredential(credential.identifier))?.registrationRecord[0],
    3,
  );

  await store.putLoginAttempt({
    id: "one-shot",
    identifier: credential.identifier,
    subject: credential.subject,
    serverLoginState: new Uint8Array(128),
    expiresAt: new Date(Date.now() + 1_000),
  });
  const results = await Promise.all([
    store.takeLoginAttempt("one-shot"),
    store.takeLoginAttempt("one-shot"),
  ]);
  assertEquals(results.filter(Boolean).length, 1);
});

Deno.test("OpaqueWasm permanently poisons an instance after a trap", async () => {
  const wasm = new OpaqueWasm(trappingInstance());

  await assertRejects(
    () => wasm.registrationStart(Uint8Array.of(1)),
    (error) => assert((error as Error).message.includes("trapped")),
  );
  assert(wasm.poisoned);
  await assertRejects(
    () => wasm.registrationStart(Uint8Array.of(1)),
    (error) => assert((error as Error).message.includes("poisoned")),
  );
});

function trappingInstance(): WebAssembly.Instance {
  const memory = new WebAssembly.Memory({ initial: 1 });
  let nextPointer = 1024;
  const invalidInput = () => 2;
  const exports = {
    memory,
    allocate(length: number): number {
      const pointer = nextPointer;
      nextPointer += length;
      return pointer;
    },
    free(): void {},
    resetAllocator(): void {
      nextPointer = 1024;
    },
    version: () => 5,
    registrationRequestLen: () => 32,
    registrationResponseLen: () => 64,
    registrationRecordLen: () => 192,
    ke1Len: () => 96,
    ke2Len: () => 320,
    ke3Len: () => 64,
    serverKeyPairLen: () => 64,
    registrationStart(): number {
      throw new WebAssembly.RuntimeError("synthetic trap");
    },
    registrationFinish: invalidInput,
    serverRegistrationResponse: invalidInput,
    serverKeyPair: invalidInput,
    serverCreateFakeRecord: invalidInput,
    loginStart: invalidInput,
    loginFinish: invalidInput,
    serverLoginStart: invalidInput,
    serverLoginFinish: invalidInput,
  };
  return { exports } as unknown as WebAssembly.Instance;
}
