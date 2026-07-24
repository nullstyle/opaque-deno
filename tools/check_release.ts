import {
  buildLoginFinishInput,
  buildLoginStartInput,
  buildRegistrationFinishInput,
  buildRegistrationStartInput,
  buildServerCreateFakeRecordInput,
  buildServerLoginFinishInput,
  buildServerLoginStartInput,
  buildServerRegistrationResponseInput,
  OpaqueWasm,
} from "../src/raw.ts";

/** Smallest residue window worth calling a leak, in bytes. */
const MIN_MATCH = 16;

const lock = JSON.parse(
  await Deno.readTextFile(new URL("../wasm.lock.json", import.meta.url)),
) as {
  artifact: string;
  releasePending?: boolean;
  origin?: string;
};

const failures: string[] = [];
if (lock.releasePending !== false || lock.origin !== "github-release") {
  failures.push(
    "wasm.lock.json still identifies a local pinned build; download and verify " +
      "an official opaque-zig release asset first",
  );
}

try {
  await verifyLinearMemoryScrubbing(lock.artifact);
} catch (error) {
  failures.push(error instanceof Error ? error.message : String(error));
}

if (failures.length > 0) {
  console.error(`Refusing to publish:\n- ${failures.join("\n- ")}`);
  Deno.exit(1);
}

/**
 * Assert that no secret survives anywhere in linear memory.
 *
 * Drives a full register + login lifecycle through every production export
 * using this package's own ABI builders — the exact call pattern the library
 * uses in production — and after each operation scans ALL of linear memory for
 * any {@link MIN_MATCH}-byte window of every secret seen so far. Secrets
 * accumulate, so a leak that a later operation happens to overwrite is still
 * reported at the point it was first observable.
 *
 * opaque-zig zeroes the whole shadow-stack region in `resetAllocator` as of
 * v0.3.2; before that, deep call frames kept copies of blinds, AKE keys, and
 * session keys in linear memory. This probe is what verifies that claim
 * downstream: it finds 82 residues in the v0.3.1 artifact and none in v0.3.2.
 *
 * A WebAssembly trap is out of scope here — it leaves memory unscrubbed by
 * design, and `OpaqueInstancePool` handles that path by snapshot/restore.
 */
async function verifyLinearMemoryScrubbing(artifact: string): Promise<void> {
  const bytes = await Deno.readFile(new URL(`../${artifact}`, import.meta.url));
  const module = await WebAssembly.compile(bytes);
  const instance = await WebAssembly.instantiate(module);
  const memory = (instance.exports as { memory: WebAssembly.Memory }).memory;
  const wasm = new OpaqueWasm(instance);
  wasm.assertVersion();
  wasm.assertLengths();

  const initialByteLength = memory.buffer.byteLength;
  const findings: string[] = [];

  // Sliding windows of every secret, bucketed by their first two bytes, so each
  // operation costs a single pass over the (multi-MiB) memory no matter how many
  // needles are live. A naive per-needle scan is far too slow to be usable.
  const buckets: Array<
    Array<{ label: string; window: Uint8Array; offset: number }> | undefined
  > = new Array(65536);

  // A window of one repeated byte carries no secret-identifying information and
  // matches ambient scrubbed memory trivially — the OPAQUE fake record's
  // envelope is all-zero by design, and would otherwise "match" every zeroed
  // address. Skipping these costs nothing: the same secret's high-entropy
  // windows (e.g. the fake record's masking_key) are still indexed.
  const track = (label: string, value: Uint8Array): Uint8Array => {
    for (let start = 0; start + MIN_MATCH <= value.byteLength; start += 1) {
      const window = value.slice(start, start + MIN_MATCH);
      if (window.every((byte) => byte === window[0])) continue;
      (buckets[window[0] | (window[1] << 8)] ??= []).push({
        label,
        window,
        offset: start,
      });
    }
    return value;
  };

  const assertClean = (afterOperation: string): void => {
    const view = new Uint8Array(memory.buffer);
    const limit = view.byteLength - MIN_MATCH;
    const reported = new Set<string>();
    for (let at = 0; at <= limit; at += 1) {
      const candidates = buckets[view[at] | (view[at + 1] << 8)];
      if (candidates === undefined) continue;
      for (const { label, window, offset } of candidates) {
        if (reported.has(label)) continue;
        let match = true;
        for (let index = 2; index < MIN_MATCH; index += 1) {
          if (view[at + index] !== window[index]) {
            match = false;
            break;
          }
        }
        if (match) {
          reported.add(label);
          findings.push(
            `${MIN_MATCH} bytes of ${label} (offset ${offset}) survive ` +
              `${afterOperation} at linear-memory offset ${at}`,
          );
        }
      }
    }
    if (memory.buffer.byteLength !== initialByteLength) {
      findings.push(`linear memory grew during ${afterOperation}`);
    }
  };

  const material = (length: number, step: number, seed: number) =>
    Uint8Array.from({ length }, (_, index) => (index * step + seed) & 0xff);
  const encoder = new TextEncoder();
  const context = encoder.encode("release-check/v1");
  const credentialIdentifier = encoder.encode("release-check@example.test");

  const password = track("the password", material(48, 73, 19));
  const oprfSeed = track("the OPRF seed", material(64, 151, 37));
  const serverSeed = track("the server seed", material(32, 97, 11));
  const fakeSeed = track("the fake-record seed", material(32, 89, 53));
  const registrationBlind = track(
    "the registration blind",
    material(64, 131, 7),
  );
  const envelopeNonce = track("the envelope nonce", material(32, 41, 23));
  const loginBlind = track("the login blind", material(64, 167, 29));
  const clientNonce = track("the client nonce", material(32, 59, 61));
  const clientKeyshareSeed = track(
    "the client keyshare seed",
    material(32, 103, 71),
  );
  const maskingNonce = track("the masking nonce", material(32, 113, 83));
  const serverNonce = track("the server nonce", material(32, 127, 91));
  const serverKeyshareSeed = track(
    "the server keyshare seed",
    material(32, 139, 101),
  );

  const keys = wasm.serverKeyPair(serverSeed);
  track("the server private key", keys.sk);
  track("the server public key", keys.pk);
  assertClean("serverKeyPair");

  const registrationStartOutput = track(
    "the registration-start state",
    wasm.registrationStart(
      track(
        "the registration-start input",
        buildRegistrationStartInput({
          blindUniform: registrationBlind,
          password,
        }),
      ),
    ),
  );
  assertClean("registrationStart");

  const blind = track("the OPRF blind", registrationStartOutput.slice(0, 32));
  const registrationResponse = track(
    "the registration response",
    wasm.serverRegistrationResponse(
      buildServerRegistrationResponseInput({
        registrationRequest: registrationStartOutput.slice(32, 64),
        serverPublicKey: keys.pk,
        credentialIdentifier,
        oprfSeed,
      }),
    ),
  );
  assertClean("serverRegistrationResponse");

  const registrationFinishOutput = track(
    "the registration-finish output",
    wasm.registrationFinish(
      track(
        "the registration-finish input",
        buildRegistrationFinishInput({
          blind,
          envelopeNonce,
          registrationResponse,
          password,
          context,
        }),
      ),
    ),
  );
  assertClean("registrationFinish");

  const registrationRecord = track(
    "the registration record",
    registrationFinishOutput.slice(0, 192),
  );
  track("the registration exportKey", registrationFinishOutput.slice(192, 256));

  const loginStartOutput = track(
    "the login-start state",
    wasm.loginStart(
      track(
        "the login-start input",
        buildLoginStartInput({
          blindUniform: loginBlind,
          clientNonce,
          clientKeyshareSeed,
          password,
        }),
      ),
    ),
  );
  assertClean("loginStart");

  const serverLoginStartOutput = track(
    "the server login state",
    wasm.serverLoginStart(
      track(
        "the server login-start input",
        buildServerLoginStartInput({
          serverPrivateKey: keys.sk,
          serverPublicKey: keys.pk,
          registrationRecord,
          oprfSeed,
          ke1: loginStartOutput.slice(160, 256),
          maskingNonce,
          serverNonce,
          serverKeyshareSeed,
          credentialIdentifier,
          context,
        }),
      ),
    ),
  );
  assertClean("serverLoginStart");

  const loginFinishOutput = track(
    "the login-finish output",
    wasm.loginFinish(
      track(
        "the login-finish input",
        buildLoginFinishInput({
          clientLoginState: loginStartOutput.slice(0, 160),
          ke2: serverLoginStartOutput.slice(128, 448),
          password,
          context,
        }),
      ),
    ),
  );
  assertClean("loginFinish");

  track("the client session key", loginFinishOutput.slice(64, 128));
  track("the login exportKey", loginFinishOutput.slice(128, 192));

  track(
    "the server login-finish output",
    wasm.serverLoginFinish(
      buildServerLoginFinishInput({
        serverLoginState: serverLoginStartOutput.slice(0, 128),
        ke3: loginFinishOutput.slice(0, 64),
      }),
    ),
  );
  assertClean("serverLoginFinish");

  // A leaked fake-record masking_key would let an observer distinguish fake
  // records from real ones, defeating the point of the fake record.
  const fakeRecord = track(
    "the fake record",
    wasm.serverCreateFakeRecord(
      buildServerCreateFakeRecordInput({
        oprfSeed,
        seed: fakeSeed,
        credentialIdentifier,
      }),
    ),
  );
  track("the fake-record masking key", fakeRecord.slice(32, 96));
  assertClean("serverCreateFakeRecord");

  bytes.fill(0);
  if (findings.length > 0) {
    throw new Error(
      `opaque-zig leaves secrets in linear memory:\n  - ${
        findings.join("\n  - ")
      }`,
    );
  }
}
