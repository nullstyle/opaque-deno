import { DenoKvOpaqueStore } from "../src/kv.ts";
import { assert, assertEquals } from "./assert.ts";

Deno.test("DenoKvOpaqueStore atomically creates credentials and consumes attempts", async () => {
  const kv = await Deno.openKv(":memory:");
  try {
    const store = new DenoKvOpaqueStore(kv, {
      prefix: ["test", crypto.randomUUID()],
    });
    const now = new Date();
    const credential = {
      identifier: "alice",
      subject: "subject-1",
      credentialIdentifier: new TextEncoder().encode("alice"),
      registrationRecord: new Uint8Array(192),
      createdAt: now,
      updatedAt: now,
    };
    const created = await Promise.all([
      store.createCredential(credential),
      store.createCredential(credential),
    ]);
    assertEquals(created.filter(Boolean).length, 1);

    await store.putRegistrationAttempt({
      id: "single-use",
      identifier: "alice",
      subject: "subject-1",
      credentialIdentifier: new TextEncoder().encode("alice"),
      expiresAt: new Date(Date.now() + 10_000),
    });
    const taken = await Promise.all([
      store.takeRegistrationAttempt("single-use"),
      store.takeRegistrationAttempt("single-use"),
    ]);
    assertEquals(taken.filter(Boolean).length, 1);
    assert(taken.find(Boolean)?.expiresAt instanceof Date);

    await store.putLoginAttempt({
      id: "single-use-login",
      identifier: "missing-user",
      subject: null,
      serverLoginState: new Uint8Array(128).fill(7),
      expiresAt: new Date(Date.now() + 10_000),
    });
    const loginTaken = await Promise.all([
      store.takeLoginAttempt("single-use-login"),
      store.takeLoginAttempt("single-use-login"),
    ]);
    assertEquals(loginTaken.filter(Boolean).length, 1);
    assertEquals(loginTaken.find(Boolean)?.subject, null);
    assertEquals(loginTaken.find(Boolean)?.serverLoginState[0], 7);
  } finally {
    kv.close();
  }
});
