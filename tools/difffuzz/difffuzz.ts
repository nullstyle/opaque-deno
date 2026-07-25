/**
 * Differential fuzzer: opaque-zig (the WASM this package ships) against an
 * independent OPAQUE implementation (github.com/bytemare/opaque, via the Go
 * oracle in ./oracle-go).
 *
 * Registration is compared byte-for-byte: both sides run it with the same
 * injected randomness, so every message and the exportKey must agree exactly.
 * Login is cross-executed in both directions -- each implementation's client
 * against the other's server -- and both must derive the same session key.
 * Unlike a self-test, neither side gets to define what "correct" means, which
 * is why this catches protocol errors that reading the code does not.
 *
 * The blind and the server key are derived by opaque-zig and injected into the
 * oracle: the two expand seeds into scalars differently, and what is under test
 * is the protocol, not the RNG.
 *
 * Usage:
 *   deno run -A tools/difffuzz/difffuzz.ts [--cases N] [--seed N] [--only N]
 *                                          [--selftest] [--fast] [--verbose]
 *
 *   --selftest  prove the harness can fail before trusting that it passes
 *   --fast      weak Argon2id parameters (high throughput; exercises the OPRF,
 *               envelope, transcript and MAC paths, but not the shipped KSF)
 *   --only      run one case index and print both sides in full
 *
 * Every case is a pure function of (seed, index), so a failure is replayed with
 * `--seed <seed> --only <index>`.
 */

import {
  buildLoginFinishInput,
  buildLoginStartInput,
  buildRegistrationFinishInput,
  buildRegistrationStartInput,
  buildServerLoginFinishInput,
  buildServerLoginStartInput,
  buildServerRegistrationResponseInput,
  instantiateOpaqueWasm,
  type OpaqueWasm,
} from "../../src/raw.ts";

const root = new URL("../../", import.meta.url);

/** opaque-zig's shipped KSF: Argon2id OWASP params (src/opaque.zig). */
const KSF_PRODUCTION = {
  time: 2,
  memory: 19 * 1024,
  threads: 1,
  length: 64,
  salt: "00".repeat(16),
};

/**
 * Weak parameters for high-volume runs. opaque-zig's WASM hard-codes the
 * production KSF, so --fast is only usable once the oracle is known to agree
 * on the KSF itself; it is kept for driving the non-KSF paths at volume.
 */
const KSF_FAST = { ...KSF_PRODUCTION, time: 1, memory: 8, threads: 1 };

interface Case {
  index: number;
  password: Uint8Array;
  context: Uint8Array;
  blindUniform: Uint8Array;
  envelopeNonce: Uint8Array;
  oprfSeed: Uint8Array;
  serverSeed: Uint8Array;
  credentialIdentifier: Uint8Array;
  clientIdentity: Uint8Array;
  serverIdentity: Uint8Array;
  // AKE material, used by the login path.
  loginBlindUniform: Uint8Array;
  clientNonce: Uint8Array;
  clientKeyshareSeed: Uint8Array;
  maskingNonce: Uint8Array;
  serverNonce: Uint8Array;
  serverKeyshareSeed: Uint8Array;
}

/** sfc32, seeded per case so any failure replays from (seed, index) alone. */
function rng(seed: number, index: number): () => number {
  let a = seed ^ 0x9e3779b9, b = index ^ 0x243f6a88, c = 0xb7e15162, d = 1;
  for (let i = 0; i < 12; i += 1) step();
  function step(): number {
    a >>>= 0;
    b >>>= 0;
    c >>>= 0;
    d >>>= 0;
    const t = (a + b | 0) + d | 0;
    d = d + 1 | 0;
    a = b ^ b >>> 9;
    b = c + (c << 3) | 0;
    c = c << 21 | c >>> 11;
    c = c + t | 0;
    return (t >>> 0) / 4294967296;
  }
  return step;
}

/**
 * Build one case. Lengths are drawn from a distribution that favours the
 * boundaries where framing bugs live: empty, one byte, and the long tail.
 */
function makeCase(seed: number, index: number): Case {
  const next = rng(seed, index);
  const byte = () => Math.floor(next() * 256) & 0xff;
  const bytes = (n: number) => Uint8Array.from({ length: n }, byte);
  const len = (max: number, allowEmpty: boolean): number => {
    const roll = next();
    if (allowEmpty && roll < 0.15) return 0;
    if (roll < 0.3) return 1;
    if (roll > 0.95) return max;
    return 1 + Math.floor(next() * max);
  };
  // Occasionally use degenerate byte patterns: all-zero and all-0xff inputs
  // are where padding and constant-time comparisons tend to go wrong.
  const patterned = (n: number): Uint8Array => {
    const roll = next();
    if (roll < 0.08) return new Uint8Array(n);
    if (roll < 0.16) return new Uint8Array(n).fill(0xff);
    return bytes(n);
  };

  return {
    index,
    password: patterned(len(64, true)),
    context: patterned(len(32, true)),
    blindUniform: bytes(64),
    envelopeNonce: patterned(32),
    oprfSeed: patterned(64),
    serverSeed: patterned(32),
    credentialIdentifier: patterned(len(32, false)),
    clientIdentity: patterned(len(32, true)),
    serverIdentity: patterned(len(32, true)),
    loginBlindUniform: bytes(64),
    // AKE nonces stay uniformly random rather than `patterned`: bytemare's
    // deserializer rejects an all-zero nonce as a malformed message, while
    // opaque-zig accepts whatever the caller supplies. Feeding degenerate
    // nonces therefore only re-tests that one known difference, and costs the
    // cross-execution check on ~18% of cases. A real caller uses a CSPRNG.
    clientNonce: bytes(32),
    clientKeyshareSeed: bytes(32),
    maskingNonce: bytes(32),
    serverNonce: bytes(32),
    serverKeyshareSeed: bytes(32),
  };
}

function hex(value: Uint8Array): string {
  return Array.from(value, (b) => b.toString(16).padStart(2, "0")).join("");
}

interface Side {
  registrationRequest?: string;
  registrationResponse?: string;
  registrationRecord?: string;
  exportKey?: string;
  // Login (AKE) results.
  ke1?: string;
  ke2?: string;
  ke3?: string;
  clientMac?: string;
  sessionKey?: string;
  ok?: boolean;
  error?: string;
}

interface ZigSide extends Side {
  blind?: string;
  sk?: string;
  pk?: string;
}

/**
 * Run one case through the WASM this package ships, keeping whatever completed.
 *
 * Partial results matter: when opaque-zig rejects an input the oracle accepts,
 * that disagreement is itself a finding, and discarding the earlier messages
 * would hide it.
 */
function runZig(wasm: OpaqueWasm, testCase: Case): ZigSide {
  const side: ZigSide = {};
  try {
    const keys = wasm.serverKeyPair(testCase.serverSeed);
    side.sk = hex(keys.sk);
    side.pk = hex(keys.pk);

    const start = wasm.registrationStart(
      buildRegistrationStartInput({
        blindUniform: testCase.blindUniform,
        password: testCase.password,
      }),
    );
    const blind = start.slice(0, 32);
    const request = start.slice(32, 64);
    side.blind = hex(blind);
    side.registrationRequest = hex(request);

    const response = wasm.serverRegistrationResponse(
      buildServerRegistrationResponseInput({
        registrationRequest: request,
        serverPublicKey: keys.pk,
        credentialIdentifier: testCase.credentialIdentifier,
        oprfSeed: testCase.oprfSeed,
      }),
    );
    side.registrationResponse = hex(response);

    const finish = wasm.registrationFinish(
      buildRegistrationFinishInput({
        blind,
        envelopeNonce: testCase.envelopeNonce,
        registrationResponse: response,
        password: testCase.password,
        context: testCase.context,
        serverIdentity: testCase.serverIdentity,
        clientIdentity: testCase.clientIdentity,
      }),
    );
    side.registrationRecord = hex(finish.slice(0, 192));
    side.exportKey = hex(finish.slice(192, 256));
  } catch (error) {
    side.error = error instanceof Error ? error.message : String(error);
  }
  return side;
}

/**
 * Login-path positive controls. Each must make the cross-execution fail: if a
 * tampered KE2/KE3 still authenticates, or a wrong password still recovers the
 * envelope, the check is not testing what it claims.
 */
type LoginControl = "ke2" | "ke3" | "password";

const LOGIN_CONTROLS: Record<LoginControl, string> = {
  ke2: "a flipped bit in the server's KE2 must fail the client's MAC check",
  ke3: "a flipped bit in the client's KE3 must fail the server's MAC check",
  password: "a password that was never registered must not authenticate",
};

/**
 * Cross-execute the login (AKE) path in both directions.
 *
 * KE1 is compared byte-for-byte: the blind and the client's ephemeral AKE key
 * are both recoverable from opaque-zig's client state (`Nsk + Nsk + ke1_len`),
 * so the message is fully determined on both sides.
 *
 * KE2 cannot be pinned that way -- opaque-zig derives the server's ephemeral
 * key from a seed internally and never exposes the scalar. Rather than
 * reimplement that derivation here (which would mean testing an implementation
 * against a reimplementation of itself, and putting the bug in both), each side
 * consumes the other's messages and both must arrive at the same session key.
 * That is the property that actually matters, and it covers the transcript,
 * the MAC and the context -- none of which the registration path reaches.
 *
 * Returns one message per failed assertion; empty means both directions agreed.
 */
async function checkLogin(
  wasm: OpaqueWasm,
  oracle: Oracle,
  testCase: Case,
  registrationRecord: string,
  registrationExportKey: string,
  ksf: typeof KSF_PRODUCTION,
  loginControl?: LoginControl,
): Promise<string[]> {
  const failures: string[] = [];
  const keys = wasm.serverKeyPair(testCase.serverSeed);

  // Guards against a vacuous pass: two undefined session keys compare equal.
  const expectKey = (label: string, value: string | undefined): void => {
    if (value === undefined || value.length !== 128) {
      failures.push(
        `${label} is missing or not 64 bytes (${value?.length ?? "absent"})`,
      );
    }
  };
  const flip = (value: string): string => {
    const last = parseInt(value.slice(-2), 16) ^ 0x01;
    return value.slice(0, -2) + last.toString(16).padStart(2, "0");
  };

  // A login password that differs from the registered one must not
  // authenticate; used as a control.
  const loginPassword = loginControl === "password"
    ? Uint8Array.from([...testCase.password, 0x21])
    : testCase.password;

  const shared = {
    password: hex(loginPassword),
    context: hex(testCase.context),
    oprfSeed: hex(testCase.oprfSeed),
    serverPrivateKey: hex(keys.sk),
    serverPublicKey: hex(keys.pk),
    credentialIdentifier: hex(testCase.credentialIdentifier),
    clientIdentity: hex(testCase.clientIdentity),
    serverIdentity: hex(testCase.serverIdentity),
    ksf,
  };

  // --- Direction A: opaque-zig client against the oracle's server ----------
  const start = wasm.loginStart(
    buildLoginStartInput({
      blindUniform: testCase.loginBlindUniform,
      clientNonce: testCase.clientNonce,
      clientKeyshareSeed: testCase.clientKeyshareSeed,
      password: loginPassword,
    }),
  );
  const clientLoginState = start.slice(0, 160);
  const ke1Zig = start.slice(160, 256);

  // state = blind || ephemeral AKE private key || ke1
  const loginBlind = clientLoginState.slice(0, 32);
  const clientEphemeralSecret = clientLoginState.slice(32, 64);

  const parity = await oracle.ask({
    ...shared,
    op: "loginClientStart",
    sessionId: "parity",
    blind: hex(loginBlind),
    clientEphemeralSecret: hex(clientEphemeralSecret),
    clientNonce: hex(testCase.clientNonce),
  });
  if (parity.error !== undefined) {
    failures.push(`oracle could not reproduce KE1: ${parity.error}`);
  } else if (parity.ke1 !== hex(ke1Zig)) {
    failures.push(
      `ke1 differs with identical randomness:\n` +
        `    opaque-zig: ${hex(ke1Zig)}\n` +
        `    bytemare:   ${parity.ke1}`,
    );
  }

  const serverA = await oracle.ask({
    ...shared,
    op: "loginServer",
    record: registrationRecord,
    ke1: hex(ke1Zig),
    maskingNonce: hex(testCase.maskingNonce),
    serverNonce: hex(testCase.serverNonce),
  });
  if (serverA.error !== undefined) {
    failures.push(`oracle server rejected opaque-zig's KE1: ${serverA.error}`);
  } else {
    expectKey("oracle server session key", serverA.sessionKey);
    const ke2ForZig = loginControl === "ke2"
      ? flip(serverA.ke2 ?? "")
      : serverA.ke2 ?? "";
    let finish: Uint8Array | undefined;
    try {
      finish = wasm.loginFinish(
        buildLoginFinishInput({
          clientLoginState,
          ke2: hexToBytes(ke2ForZig),
          password: loginPassword,
          context: testCase.context,
          serverIdentity: testCase.serverIdentity,
          clientIdentity: testCase.clientIdentity,
        }),
      );
    } catch (error) {
      failures.push(
        `opaque-zig rejected the oracle's KE2: ` +
          `${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (finish !== undefined) {
      const ke3 = finish.slice(0, 64);
      const sessionKey = hex(finish.slice(64, 128));
      const exportKey = hex(finish.slice(128, 192));
      if (sessionKey !== serverA.sessionKey) {
        failures.push(
          `session keys disagree (opaque-zig client / oracle server):\n` +
            `    opaque-zig: ${sessionKey}\n` +
            `    bytemare:   ${serverA.sessionKey}`,
        );
      }
      if (exportKey !== registrationExportKey) {
        failures.push(
          `login exportKey differs from registration exportKey ` +
            `(opaque-zig client):\n    login:        ${exportKey}\n` +
            `    registration: ${registrationExportKey}`,
        );
      }
      const finishA = await oracle.ask({
        ...shared,
        op: "loginServerFinish",
        ke3: loginControl === "ke3" ? flip(hex(ke3)) : hex(ke3),
        clientMac: serverA.clientMac,
      });
      if (finishA.error !== undefined) {
        failures.push(
          `oracle server rejected opaque-zig's KE3: ${finishA.error}`,
        );
      }
    }
  }

  // --- Direction B: the oracle's client against opaque-zig's server --------
  const clientB = await oracle.ask({
    ...shared,
    op: "loginClientStart",
    sessionId: "reverse",
    clientNonce: hex(testCase.clientNonce),
  });
  if (clientB.error !== undefined) {
    failures.push(`oracle client could not start: ${clientB.error}`);
    return failures;
  }

  let serverStart: Uint8Array | undefined;
  try {
    serverStart = wasm.serverLoginStart(
      buildServerLoginStartInput({
        serverPrivateKey: keys.sk,
        serverPublicKey: keys.pk,
        registrationRecord: hexToBytes(registrationRecord),
        oprfSeed: testCase.oprfSeed,
        ke1: hexToBytes(clientB.ke1 ?? ""),
        maskingNonce: testCase.maskingNonce,
        serverNonce: testCase.serverNonce,
        serverKeyshareSeed: testCase.serverKeyshareSeed,
        credentialIdentifier: testCase.credentialIdentifier,
        context: testCase.context,
        serverIdentity: testCase.serverIdentity,
        clientIdentity: testCase.clientIdentity,
      }),
    );
  } catch (error) {
    failures.push(
      `opaque-zig server rejected the oracle's KE1: ` +
        `${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (serverStart === undefined) return failures;

  const serverLoginState = serverStart.slice(0, 128);
  const ke2Zig = serverStart.slice(128, 448);

  const clientFinishB = await oracle.ask({
    ...shared,
    op: "loginClientFinish",
    sessionId: "reverse",
    ke2: hex(ke2Zig),
  });
  if (clientFinishB.error !== undefined) {
    failures.push(
      `oracle client rejected opaque-zig's KE2: ${clientFinishB.error}`,
    );
    return failures;
  }
  expectKey("oracle client session key", clientFinishB.sessionKey);
  if (clientFinishB.exportKey !== registrationExportKey) {
    failures.push(
      `login exportKey differs from registration exportKey ` +
        `(oracle client):\n    login:        ${clientFinishB.exportKey}\n` +
        `    registration: ${registrationExportKey}`,
    );
  }

  try {
    const serverFinish = wasm.serverLoginFinish(
      buildServerLoginFinishInput({
        serverLoginState,
        ke3: hexToBytes(clientFinishB.ke3 ?? ""),
      }),
    );
    const serverSessionKey = hex(serverFinish.slice(0, 64));
    if (serverSessionKey !== clientFinishB.sessionKey) {
      failures.push(
        `session keys disagree (oracle client / opaque-zig server):\n` +
          `    bytemare:   ${clientFinishB.sessionKey}\n` +
          `    opaque-zig: ${serverSessionKey}`,
      );
    }
  } catch (error) {
    failures.push(
      `opaque-zig server rejected the oracle's KE3: ` +
        `${error instanceof Error ? error.message : String(error)}`,
    );
  }

  return failures;
}

function hexToBytes(value: string): Uint8Array {
  const out = new Uint8Array(value.length / 2);
  for (let at = 0; at < out.length; at += 1) {
    out[at] = parseInt(value.slice(at * 2, at * 2 + 2), 16);
  }
  return out;
}

/**
 * Differences in input validation that are understood and accepted, so a run
 * reports them as agreements-by-exception rather than noise -- while still
 * failing if one ever stops holding, or a new one appears.
 */
const KNOWN_DIFFERENCES: ReadonlyArray<{
  applies: (testCase: Case) => boolean;
  zigAccepts: boolean;
  note: string;
}> = [
  {
    applies: (testCase) => testCase.context.length === 0,
    zigAccepts: false,
    note: "opaque-zig requires a non-empty context (domain separation is " +
      "mandatory in this package's API); bytemare permits an empty one. " +
      "A deliberate strictness difference, not a defect.",
  },
];

/** A long-lived oracle process speaking newline-delimited JSON. */
class Oracle {
  #process: Deno.ChildProcess;
  #writer: WritableStreamDefaultWriter<Uint8Array>;
  #lines: ReadableStreamDefaultReader<string>;

  constructor(path: string) {
    this.#process = new Deno.Command(path, {
      stdin: "piped",
      stdout: "piped",
      stderr: "inherit",
    }).spawn();
    this.#writer = this.#process.stdin.getWriter();
    this.#lines = this.#process.stdout
      .pipeThrough(new TextDecoderStream())
      .pipeThrough(new LineStream())
      .getReader();
  }

  async ask(payload: unknown): Promise<Side> {
    await this.#writer.write(
      new TextEncoder().encode(`${JSON.stringify(payload)}\n`),
    );
    const { value, done } = await this.#lines.read();
    if (done || value === undefined) throw new Error("oracle closed");
    return JSON.parse(value) as Side;
  }

  async close(): Promise<void> {
    await this.#writer.close();
    this.#lines.cancel();
    await this.#process.status;
  }
}

/** Split a text stream into lines. */
class LineStream extends TransformStream<string, string> {
  constructor() {
    let buffer = "";
    super({
      transform(chunk, controller) {
        buffer += chunk;
        const parts = buffer.split("\n");
        buffer = parts.pop() ?? "";
        for (const part of parts) if (part !== "") controller.enqueue(part);
      },
      flush(controller) {
        if (buffer !== "") controller.enqueue(buffer);
      },
    });
  }
}

const FIELDS = [
  "registrationRequest",
  "registrationResponse",
  "registrationRecord",
  "exportKey",
] as const;

/**
 * Deliberate divergences, used as positive controls.
 *
 * A comparison that has never failed is not evidence: these prove the harness
 * detects a difference, and *where*. Each mode also says something specific --
 * `ksf` diverging only in the record and exportKey is what demonstrates the
 * Argon2id parameters are genuinely being exercised on both sides rather than
 * agreeing vacuously.
 */
type Control = "ksf" | "context" | "identity" | "blind" | "credential";

/**
 * What each control must change, and why. `--selftest` asserts the observed
 * divergence is exactly this set, so the harness proves its own sensitivity
 * and these cryptographic facts stay asserted rather than assumed.
 */
const CONTROL_EXPECTATIONS: Record<
  Control,
  { fields: readonly (typeof FIELDS)[number][]; because: string }
> = {
  ksf: {
    fields: ["registrationRecord", "exportKey"],
    because:
      "the KSF runs on the OPRF output during finalize, so it moves the " +
      "envelope and exportKey but nothing the client or server sent earlier. " +
      "This is what proves both sides really run Argon2id with these exact " +
      "parameters, rather than agreeing for some unrelated reason.",
  },
  identity: {
    fields: ["registrationRecord"],
    because:
      "the client identity is authenticated by the envelope tag but is not " +
      "an input to the exportKey, which derives from the randomized password " +
      "and the envelope nonce alone.",
  },
  credential: {
    fields: ["registrationResponse", "registrationRecord", "exportKey"],
    because:
      "the credential identifier selects the per-client OPRF key, so the " +
      "server's evaluation changes and everything derived from it follows. " +
      "The request is client-side and cannot move.",
  },
  blind: {
    fields: ["registrationRequest", "registrationResponse"],
    because:
      "unblinding cancels the blind exactly, so a different blind changes " +
      "both messages on the wire and nothing afterwards. A divergence in the " +
      "record here would mean the blind was leaking into the output.",
  },
  context: {
    fields: [],
    because:
      "the context binds the AKE transcript, not the registration envelope " +
      "(RFC 9807). Both implementations agreeing it is a no-op is correct, " +
      "and marks the coverage gap the login path would close.",
  },
};

function corrupt(
  payload: Record<string, unknown>,
  mode: Control,
): Record<string, unknown> {
  const flipLastByte = (value: string): string => {
    if (value === "") return "01";
    const head = value.slice(0, -2);
    const last = parseInt(value.slice(-2), 16) ^ 0x01;
    return head + last.toString(16).padStart(2, "0");
  };
  const ksf = payload.ksf as typeof KSF_PRODUCTION;
  switch (mode) {
    case "ksf":
      return { ...payload, ksf: { ...ksf, time: ksf.time + 1 } };
    case "context":
      return { ...payload, context: flipLastByte(payload.context as string) };
    case "identity":
      return {
        ...payload,
        clientIdentity: flipLastByte(payload.clientIdentity as string),
      };
    case "credential":
      return {
        ...payload,
        credentialIdentifier: flipLastByte(
          payload.credentialIdentifier as string,
        ),
      };
    case "blind":
      return { ...payload, blind: flipLastByte(payload.blind as string) };
  }
}

interface BatchOptions {
  seed: number;
  cases: number;
  only?: number;
  ksf: typeof KSF_PRODUCTION;
  control?: Control;
  verbose: boolean;
  quiet?: boolean;
  skipLogin?: boolean;
}

interface BatchResult {
  checked: number;
  mismatched: number;
  zigRejected: number;
  oracleRejected: number;
  validationDivergences: number;
  knownDifferences: number;
  bothRejected: number;
  loginChecked: number;
  loginFailures: number;
  diverged: Set<string>;
}

async function runBatch(
  wasm: OpaqueWasm,
  oracle: Oracle,
  options: BatchOptions,
): Promise<BatchResult> {
  const result: BatchResult = {
    checked: 0,
    mismatched: 0,
    zigRejected: 0,
    oracleRejected: 0,
    validationDivergences: 0,
    knownDifferences: 0,
    bothRejected: 0,
    loginChecked: 0,
    loginFailures: 0,
    diverged: new Set<string>(),
  };

  for (let n = 0; n < options.cases; n += 1) {
    const index = options.only ?? n;
    const testCase = makeCase(options.seed, index);
    const zig = runZig(wasm, testCase);

    // Without a blind there is nothing to hold the oracle to, so the case
    // cannot be compared at all.
    if (zig.blind === undefined) {
      result.zigRejected += 1;
      if (options.verbose) {
        console.log(
          `case ${index}: opaque-zig error before OPRF: ${zig.error}`,
        );
      }
      continue;
    }

    const payload = {
      op: "register",
      password: hex(testCase.password),
      context: hex(testCase.context),
      blind: zig.blind,
      envelopeNonce: hex(testCase.envelopeNonce),
      oprfSeed: hex(testCase.oprfSeed),
      serverPrivateKey: zig.sk,
      serverPublicKey: zig.pk,
      credentialIdentifier: hex(testCase.credentialIdentifier),
      clientIdentity: hex(testCase.clientIdentity),
      serverIdentity: hex(testCase.serverIdentity),
      ksf: options.ksf,
    };
    const go = await oracle.ask(
      options.control ? corrupt(payload, options.control) : payload,
    );

    // Accept/reject disagreement is a finding in its own right: two conformant
    // implementations should not differ on which inputs are valid.
    const zigAccepted = zig.exportKey !== undefined;
    const goAccepted = go.error === undefined;
    if (zigAccepted !== goAccepted) {
      const known = KNOWN_DIFFERENCES.find((entry) =>
        entry.applies(testCase) && entry.zigAccepts === zigAccepted
      );
      if (known !== undefined) {
        result.knownDifferences += 1;
        if (options.verbose) {
          console.log(`case ${index}: known difference -- ${known.note}`);
        }
      } else {
        result.validationDivergences += 1;
        if (!options.quiet) {
          console.log(`\nVALIDATION DIVERGENCE at case ${index}:`);
          console.log(
            `  replay: --seed ${options.seed} --only ${index}`,
          );
          console.log(
            `  opaque-zig ${
              zigAccepted ? "accepted" : `rejected: ${zig.error}`
            }`,
          );
          console.log(
            `  bytemare   ${goAccepted ? "accepted" : `rejected: ${go.error}`}`,
          );
          console.log(`  password=${hex(testCase.password)}`);
          console.log(`  context=${hex(testCase.context)}`);
          console.log(
            `  credentialIdentifier=${hex(testCase.credentialIdentifier)}`,
          );
        }
      }
      continue;
    }

    if (!zigAccepted) {
      // Both rejected: agreement, nothing further to compare.
      result.bothRejected += 1;
      continue;
    }

    result.checked += 1;
    const diverged = FIELDS.filter((field) => zig[field] !== go[field]);
    for (const field of diverged) result.diverged.add(field);
    if (diverged.length > 0) {
      result.mismatched += 1;
      if (!options.quiet) {
        console.log(`\nDIVERGENCE at case ${index} (seed ${options.seed}):`);
        console.log(
          `  replay: --seed ${options.seed} --only ${index}` +
            (options.control ? ` --control ${options.control}` : ""),
        );
        for (const field of diverged) {
          console.log(`  ${field}:`);
          console.log(`    opaque-zig: ${zig[field]}`);
          console.log(`    bytemare:   ${go[field]}`);
        }
        console.log(`  password=${hex(testCase.password)}`);
        console.log(`  context=${hex(testCase.context)}`);
        console.log(
          `  credentialIdentifier=${hex(testCase.credentialIdentifier)}`,
        );
        console.log(`  clientIdentity=${hex(testCase.clientIdentity)}`);
        console.log(`  serverIdentity=${hex(testCase.serverIdentity)}`);
      }
    } else if (options.verbose) {
      console.log(`case ${index}: agree on all ${FIELDS.length} fields`);
      for (const field of FIELDS) console.log(`  ${field}: ${zig[field]}`);
    }

    // Login runs only on an agreed registration: with a divergent record the
    // two sides would be logging in against different credentials, and every
    // downstream failure would be a restatement of the same finding.
    if (diverged.length === 0 && !options.skipLogin) {
      const loginFailures = await checkLogin(
        wasm,
        oracle,
        testCase,
        zig.registrationRecord ?? "",
        zig.exportKey ?? "",
        options.ksf,
      );
      if (loginFailures.length > 0) {
        result.loginFailures += 1;
        if (!options.quiet) {
          console.log(`\nLOGIN DIVERGENCE at case ${index}:`);
          console.log(`  replay: --seed ${options.seed} --only ${index}`);
          for (const failure of loginFailures) console.log(`  ${failure}`);
        }
      } else {
        result.loginChecked += 1;
        if (options.verbose) {
          console.log(`case ${index}: login agrees in both directions`);
        }
      }
    }
  }

  return result;
}

/**
 * Assert every control produces exactly the divergence it should.
 *
 * This is the harness testing itself: it fails both when a control stops being
 * detected (the comparison went blind) and when one diverges more widely than
 * the protocol says it can.
 */
async function selfTest(
  wasm: OpaqueWasm,
  oracle: Oracle,
  seed: number,
  cases: number,
): Promise<boolean> {
  console.log("Control checks -- each must diverge in exactly these fields:\n");
  let ok = true;
  for (const mode of Object.keys(CONTROL_EXPECTATIONS) as Control[]) {
    const expectation = CONTROL_EXPECTATIONS[mode];
    const batch = await runBatch(wasm, oracle, {
      seed,
      cases,
      ksf: KSF_PRODUCTION,
      control: mode,
      verbose: false,
      quiet: true,
      skipLogin: true,
    });
    const observed = [...batch.diverged].sort();
    const expected = [...expectation.fields].sort();
    const agree = batch.checked > 0 &&
      observed.length === expected.length &&
      observed.every((field, at) => field === expected[at]);
    ok &&= agree;
    console.log(
      `  ${agree ? "ok  " : "FAIL"} ${mode.padEnd(11)} ` +
        `expected [${expected.join(", ") || "none"}]` +
        (agree ? "" : `, observed [${observed.join(", ") || "none"}]`) +
        (batch.checked === 0 ? " (no cases compared!)" : ""),
    );
    if (!agree) console.log(`         ${expectation.because}`);
  }

  console.log("\nLogin controls -- each must make cross-execution fail:\n");
  for (const mode of Object.keys(LOGIN_CONTROLS) as LoginControl[]) {
    let detected = 0;
    let attempted = 0;
    for (let index = 0; index < cases; index += 1) {
      const testCase = makeCase(seed, index);
      const zig = runZig(wasm, testCase);
      if (zig.exportKey === undefined || zig.registrationRecord === undefined) {
        continue;
      }
      attempted += 1;
      const failures = await checkLogin(
        wasm,
        oracle,
        testCase,
        zig.registrationRecord,
        zig.exportKey,
        KSF_PRODUCTION,
        mode,
      );
      if (failures.length > 0) detected += 1;
    }
    const agree = attempted > 0 && detected === attempted;
    ok &&= agree;
    console.log(
      `  ${agree ? "ok  " : "FAIL"} ${mode.padEnd(11)} ` +
        `${detected}/${attempted} rejected -- ${LOGIN_CONTROLS[mode]}`,
    );
  }
  return ok;
}

if (import.meta.main) {
  const args = Deno.args;
  const flag = (name: string, fallback: number): number => {
    const at = args.indexOf(`--${name}`);
    return at >= 0 ? Number(args[at + 1]) : fallback;
  };
  const seed = flag("seed", 1);
  const only = args.includes("--only") ? flag("only", 0) : undefined;
  const cases = only !== undefined ? 1 : flag("cases", 50);
  const verbose = args.includes("--verbose") || only !== undefined;
  const ksf = args.includes("--fast") ? KSF_FAST : KSF_PRODUCTION;
  const controlAt = args.indexOf("--control");
  const control = controlAt >= 0 ? args[controlAt + 1] as Control : undefined;
  const selftest = args.includes("--selftest");

  const oraclePath = new URL("oracle-go/oracle", import.meta.url).pathname;
  try {
    await Deno.stat(oraclePath);
  } catch {
    console.error(
      `oracle binary missing; build it first:\n` +
        `  (cd tools/difffuzz/oracle-go && go build -o oracle .)`,
    );
    Deno.exit(2);
  }

  const wasm = await instantiateOpaqueWasm(
    await Deno.readFile(new URL("src/opaque.wasm", root)),
  );
  const oracle = new Oracle(oraclePath);
  const started = performance.now();

  if (selftest) {
    const ok = await selfTest(wasm, oracle, seed, Math.min(cases, 3));
    await oracle.close();
    console.log(
      `\n${ok ? "harness is sensitive" : "HARNESS IS NOT SENSITIVE"} ` +
        `(${((performance.now() - started) / 1000).toFixed(1)}s)`,
    );
    Deno.exit(ok ? 0 : 1);
  }

  const batch = await runBatch(wasm, oracle, {
    seed,
    cases,
    only,
    ksf,
    control,
    verbose,
  });
  await oracle.close();

  const seconds = (performance.now() - started) / 1000;
  console.log(
    `\nregistration: ${batch.checked} compared, ${batch.mismatched} divergent, ` +
      `${batch.validationDivergences} divergent validation, ` +
      `${batch.knownDifferences} known differences, ` +
      `${batch.zigRejected} unusable`,
  );
  console.log(
    `login:        ${batch.loginChecked} cross-executed both ways, ` +
      `${batch.loginFailures} divergent`,
  );
  console.log(
    `(${seconds.toFixed(1)}s, ${(batch.checked / seconds).toFixed(1)} cases/s)`,
  );
  const failed = control === undefined &&
    (batch.mismatched > 0 || batch.validationDivergences > 0 ||
      batch.loginFailures > 0);
  Deno.exit(failed ? 1 : 0);
}
