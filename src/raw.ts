/** Low-level, dependency-free adapter for the pinned opaque-zig WASM ABI. */

export { OPAQUE_WASM_ABI_VERSION } from "./artifact.ts";

/** Numeric status codes returned by opaque-zig ABI operations. */
export const OPAQUE_WASM_STATUS: Readonly<{
  ok: number;
  protocolError: number;
  invalidInput: number;
  outOfMemory: number;
}> = Object.freeze({
  ok: 0,
  protocolError: 1,
  invalidInput: 2,
  outOfMemory: 3,
});

/** Fixed byte sizes for the ristretto255 ABI v5 suite. */
export const OPAQUE_SIZES: Readonly<{
  blindUniform: number;
  blind: number;
  nonce: number;
  seed: number;
  hash: number;
  publicKey: number;
  mac: number;
  sessionKey: number;
  exportKey: number;
  registrationRequest: number;
  registrationResponse: number;
  registrationRecord: number;
  ke1: number;
  ke2: number;
  ke3: number;
  clientLoginState: number;
  serverLoginState: number;
}> = Object.freeze({
  blindUniform: 64,
  blind: 32,
  nonce: 32,
  seed: 32,
  hash: 64,
  publicKey: 32,
  mac: 64,
  sessionKey: 64,
  exportKey: 64,
  registrationRequest: 32,
  registrationResponse: 64,
  registrationRecord: 192,
  ke1: 96,
  ke2: 320,
  ke3: 64,
  clientLoginState: 160,
  serverLoginState: 128,
});

const OUTPUT_DESCRIPTOR_BYTES = 8;
const OPERATIONS: readonly OpaqueOperation[] = [
  "registrationStart",
  "registrationFinish",
  "serverRegistrationResponse",
  "serverKeyPair",
  "serverCreateFakeRecord",
  "loginStart",
  "loginFinish",
  "serverLoginStart",
  "serverLoginFinish",
] as const;

/** Names of production opaque-zig operations. */
export type OpaqueOperation =
  | "registrationStart"
  | "registrationFinish"
  | "serverRegistrationResponse"
  | "serverKeyPair"
  | "serverCreateFakeRecord"
  | "loginStart"
  | "loginFinish"
  | "serverLoginStart"
  | "serverLoginFinish";
/** C-compatible signature shared by opaque-zig operation exports. */
export type OpaqueWasmOperation = (
  inputPointer: number,
  inputLength: number,
  outputPointer: number,
) => number;

/** Validated production exports exposed by opaque-zig ABI v5. */
export type OpaqueExports = WebAssembly.Exports & {
  memory: WebAssembly.Memory;
  allocate(byteLength: number): number;
  free(pointer: number, byteLength: number): void;
  resetAllocator(): void;
  version(): number;
  registrationRequestLen(): number;
  registrationResponseLen(): number;
  registrationRecordLen(): number;
  ke1Len(): number;
  ke2Len(): number;
  ke3Len(): number;
  serverKeyPairLen(): number;
} & { [K in OpaqueOperation]: OpaqueWasmOperation };

/** Optional transcript identities shared by client and server operations. */
export interface IdentityOptions {
  /** Non-empty application context mixed into the transcript. */
  context?: Uint8Array;
  /** Optional server identity bytes. */
  serverIdentity?: Uint8Array | null;
  /** Optional client identity bytes. */
  clientIdentity?: Uint8Array | null;
}

/** Raw client registration-start inputs. */
export interface RegistrationStartInput {
  /** Uniform random material used to derive the OPRF blind. */
  blindUniform: Uint8Array;
  /** Password bytes, owned and wiped by the caller. */
  password: Uint8Array;
}

/** Raw client registration-finish inputs. */
export interface RegistrationFinishInput extends IdentityOptions {
  /** Registration state returned by registration start. */
  blind: Uint8Array;
  /** Fresh 32-byte envelope nonce. */
  envelopeNonce: Uint8Array;
  /** Server registration response. */
  registrationResponse: Uint8Array;
  /** Password bytes, owned and wiped by the caller. */
  password: Uint8Array;
}

/** Raw server registration-response inputs. */
export interface ServerRegistrationResponseInput {
  /** Client registration request. */
  registrationRequest: Uint8Array;
  /** Long-term server public key. */
  serverPublicKey: Uint8Array;
  /** Application credential identifier bytes. */
  credentialIdentifier: Uint8Array;
  /** Persistent 64-byte OPRF seed. */
  oprfSeed: Uint8Array;
}

/** Raw deterministic fake-record inputs. */
export interface ServerCreateFakeRecordInput {
  /** Persistent 64-byte OPRF seed. */
  oprfSeed: Uint8Array;
  /** Persistent 32-byte fake-record seed. */
  seed: Uint8Array;
  /** Application credential identifier bytes. */
  credentialIdentifier: Uint8Array;
}

/** Raw client login-start inputs. */
export interface LoginStartInput {
  /** Uniform random material used to derive the OPRF blind. */
  blindUniform: Uint8Array;
  /** Fresh client nonce. */
  clientNonce: Uint8Array;
  /** Fresh client key-share seed. */
  clientKeyshareSeed: Uint8Array;
  /** Password bytes, owned and wiped by the caller. */
  password: Uint8Array;
}

/** Raw client login-finish inputs. */
export interface LoginFinishInput extends IdentityOptions {
  /** Secret client state returned by login start. */
  clientLoginState: Uint8Array;
  /** Server KE2 response. */
  ke2: Uint8Array;
  /** Password bytes, owned and wiped by the caller. */
  password: Uint8Array;
}

/** Raw server login-start inputs. */
export interface ServerLoginStartInput extends IdentityOptions {
  /** Long-term server private key. */
  serverPrivateKey: Uint8Array;
  /** Long-term server public key. */
  serverPublicKey: Uint8Array;
  /** Real or deterministic fake registration record. */
  registrationRecord: Uint8Array;
  /** Persistent 64-byte OPRF seed. */
  oprfSeed: Uint8Array;
  /** Client KE1 message. */
  ke1: Uint8Array;
  /** Fresh masking nonce. */
  maskingNonce: Uint8Array;
  /** Fresh server nonce. */
  serverNonce: Uint8Array;
  /** Fresh server key-share seed. */
  serverKeyshareSeed: Uint8Array;
  /** Application credential identifier bytes. */
  credentialIdentifier: Uint8Array;
}

/** Raw server login-finish inputs. */
export interface ServerLoginFinishInput {
  /** Secret server state returned by login start. */
  serverLoginState: Uint8Array;
  /** Client KE3 message. */
  ke3: Uint8Array;
}

/** A normal status-code failure returned by opaque-zig. */
export class OpaqueWasmError extends Error {
  /** Create a typed ABI status error. */
  constructor(readonly operation: string, readonly status: number) {
    super(
      `OPAQUE WASM ${operation} failed with status ${
        statusName(status)
      } (${status})`,
    );
    this.name = "OpaqueWasmError";
  }
}

/**
 * A hardened adapter around one WASM instance.
 *
 * Returned bytes are copies in the JavaScript heap and must be wiped by their
 * owner. A WebAssembly trap poisons this adapter permanently; discard it.
 */
export class OpaqueWasm {
  readonly #exports: OpaqueExports;
  #poisoned = false;
  #pristine: Uint8Array | undefined;

  /** Wrap and validate a newly instantiated opaque-zig module. */
  constructor(
    instanceOrResult:
      | WebAssembly.Instance
      | WebAssembly.WebAssemblyInstantiatedSource,
  ) {
    const instance = "instance" in instanceOrResult
      ? instanceOrResult.instance
      : instanceOrResult;
    this.#exports = assertOpaqueExports(instance.exports);
  }

  /** Wrap the export namespace of a statically imported opaque-zig module. */
  static fromExports(exports: WebAssembly.Exports): OpaqueWasm {
    return new OpaqueWasm({ exports } as WebAssembly.Instance);
  }

  /** Whether a WebAssembly trap made this instance permanently unusable. */
  get poisoned(): boolean {
    return this.#poisoned;
  }

  /**
   * Snapshot the pristine linear memory so {@link recover} can restore it after
   * a trap. Call once, before any secret-bearing operation. Only the non-zero
   * prefix is retained: the remainder is zero at instantiation, so restoring the
   * prefix and zeroing the rest reproduces a fresh instance without copying the
   * module's full (multi-MiB) memory.
   */
  snapshot(): void {
    const buffer = this.#exports.memory.buffer;
    // WASM memory is 64 KiB-page aligned, so the length is a multiple of four.
    const words = new Uint32Array(buffer);
    let end = words.length;
    while (end > 0 && words[end - 1] === 0) end -= 1;
    this.#pristine = new Uint8Array(buffer).slice(0, end * 4);
  }

  /**
   * Wipe any secrets a trap left in linear memory and make the instance usable
   * again by restoring the pristine snapshot and resetting the allocator. This
   * replaces re-instantiation for the statically imported module, which has no
   * `WebAssembly.Module` handle to instantiate from. Requires {@link snapshot}.
   */
  recover(): void {
    if (this.#pristine === undefined) {
      throw new Error("OPAQUE WASM instance was not armed for recovery");
    }
    const memory = new Uint8Array(this.#exports.memory.buffer);
    memory.fill(0);
    memory.set(this.#pristine);
    this.#exports.resetAllocator();
    this.#poisoned = false;
  }

  /** Return the module's ABI version. */
  version(): number {
    this.#assertUsable();
    return this.#exports.version();
  }

  /** Assert that the module exposes the expected ABI version. */
  assertVersion(expected = 5): void {
    const actual = this.version();
    if (actual !== expected) {
      throw new TypeError(
        `Unsupported OPAQUE WASM ABI version ${actual}; expected ${expected}`,
      );
    }
  }

  /** Assert all protocol message lengths against the pinned suite. */
  assertLengths(): void {
    const actual = {
      registrationRequest: this.#exports.registrationRequestLen(),
      registrationResponse: this.#exports.registrationResponseLen(),
      registrationRecord: this.#exports.registrationRecordLen(),
      ke1: this.#exports.ke1Len(),
      ke2: this.#exports.ke2Len(),
      ke3: this.#exports.ke3Len(),
      serverKeyPair: this.#exports.serverKeyPairLen(),
    };
    const expected = { ...OPAQUE_SIZES, serverKeyPair: 64 };
    for (const name of Object.keys(actual) as (keyof typeof actual)[]) {
      if (actual[name] !== expected[name]) {
        throw new TypeError(
          `OPAQUE WASM ${name} length is ${actual[name]}; expected ${
            expected[name]
          }`,
        );
      }
    }
  }

  /** Invoke client registration start. */
  registrationStart(input: Uint8Array): Uint8Array {
    return this.callBytes("registrationStart", input);
  }
  /** Invoke client registration finish. */
  registrationFinish(input: Uint8Array): Uint8Array {
    return this.callBytes("registrationFinish", input);
  }
  /** Invoke server registration response generation. */
  serverRegistrationResponse(input: Uint8Array): Uint8Array {
    return this.callBytes("serverRegistrationResponse", input);
  }
  /** Build a deterministic fake registration record. */
  serverCreateFakeRecord(input: Uint8Array): Uint8Array {
    return this.callBytes("serverCreateFakeRecord", input);
  }
  /** Invoke client login start. */
  loginStart(input: Uint8Array): Uint8Array {
    return this.callBytes("loginStart", input);
  }
  /** Invoke client login finish. */
  loginFinish(input: Uint8Array): Uint8Array {
    return this.callBytes("loginFinish", input);
  }
  /** Invoke server login start. */
  serverLoginStart(input: Uint8Array): Uint8Array {
    return this.callBytes("serverLoginStart", input);
  }
  /** Invoke server login finish. */
  serverLoginFinish(input: Uint8Array): Uint8Array {
    return this.callBytes("serverLoginFinish", input);
  }

  /** Derive the long-term server key pair from a persistent seed. */
  serverKeyPair(seed: Uint8Array): { sk: Uint8Array; pk: Uint8Array } {
    const out = this.callBytes(
      "serverKeyPair",
      fixed(seed, "seed", OPAQUE_SIZES.seed),
    );
    try {
      if (out.byteLength !== 64) {
        throw new RangeError("OPAQUE WASM returned an invalid server key pair");
      }
      return { sk: out.slice(0, 32), pk: out.slice(32) };
    } finally {
      out.fill(0);
    }
  }

  /** Invoke one named raw ABI operation. */
  callBytes(operation: OpaqueOperation, input: Uint8Array): Uint8Array {
    this.#assertUsable();
    if (!OPERATIONS.includes(operation)) {
      throw new TypeError(`Unknown OPAQUE operation: ${operation}`);
    }
    assertBytes(input, "OPAQUE operation input");
    const fn = this.#exports[operation];
    let inputPointer = 0;
    let outputPointer = 0;
    try {
      inputPointer = this.#allocate(input.byteLength);
      outputPointer = this.#allocate(OUTPUT_DESCRIPTOR_BYTES);
      this.#memoryBytes().set(input, inputPointer);
      const view = this.#memoryView();
      view.setUint32(outputPointer, 0, true);
      view.setUint32(outputPointer + 4, 0, true);
      let status: number;
      try {
        status = fn(inputPointer, input.byteLength, outputPointer);
      } catch (error) {
        if (error instanceof WebAssembly.RuntimeError) {
          this.#poisoned = true;
          throw new Error(
            `OPAQUE WASM ${operation} trapped; discard this instance`,
            { cause: error },
          );
        }
        throw error;
      }
      if (status !== OPAQUE_WASM_STATUS.ok) {
        throw new OpaqueWasmError(operation, status);
      }
      return this.#copyAndFree(
        view.getUint32(outputPointer, true),
        view.getUint32(outputPointer + 4, true),
      );
    } finally {
      if (!this.#poisoned) {
        this.#free(inputPointer, input.byteLength);
        this.#free(outputPointer, OUTPUT_DESCRIPTOR_BYTES);
        this.#exports.resetAllocator();
      }
    }
  }

  #assertUsable(): void {
    if (this.#poisoned) {
      throw new Error("OPAQUE WASM instance was poisoned by a previous trap");
    }
  }

  #allocate(byteLength: number): number {
    assertByteLength(byteLength);
    if (byteLength === 0) return 0;
    const pointer = this.#exports.allocate(byteLength);
    if (pointer === 0) {
      throw new RangeError("OPAQUE WASM allocator returned null");
    }
    this.#assertRange(pointer, byteLength);
    return pointer;
  }

  #free(pointer: number, byteLength: number): void {
    if (pointer === 0 && byteLength === 0) return;
    this.#assertRange(pointer, byteLength);
    this.#memoryBytes().fill(0, pointer, pointer + byteLength);
    this.#exports.free(pointer, byteLength);
  }

  #copyAndFree(pointer: number, byteLength: number): Uint8Array {
    assertByteLength(byteLength);
    if (byteLength === 0) return new Uint8Array();
    if (pointer === 0) {
      throw new RangeError("OPAQUE WASM returned null for a non-empty result");
    }
    this.#assertRange(pointer, byteLength);
    try {
      return this.#memoryBytes().slice(pointer, pointer + byteLength);
    } finally {
      this.#free(pointer, byteLength);
    }
  }

  #assertRange(pointer: number, byteLength: number): void {
    const end = pointer + byteLength;
    if (
      !Number.isSafeInteger(pointer) || !Number.isSafeInteger(end) ||
      pointer < 0 || end > this.#exports.memory.buffer.byteLength
    ) {
      throw new RangeError("OPAQUE WASM memory range is invalid");
    }
  }

  #memoryBytes(): Uint8Array {
    return new Uint8Array(this.#exports.memory.buffer);
  }
  #memoryView(): DataView {
    return new DataView(this.#exports.memory.buffer);
  }
}

/** Encode a client registration-start input. */
export function buildRegistrationStartInput(
  input: RegistrationStartInput,
): Uint8Array {
  return concat(
    fixed(input.blindUniform, "blindUniform", 64),
    bytes(input.password, "password"),
  );
}

/** Encode a client registration-finish input. */
export function buildRegistrationFinishInput(
  input: RegistrationFinishInput,
): Uint8Array {
  return concat(
    fixed(input.blind, "blind", 32),
    fixed(input.envelopeNonce, "envelopeNonce", 32),
    fixed(input.registrationResponse, "registrationResponse", 64),
    opaque16(input.password, "password"),
    opaque16(input.context ?? new Uint8Array(), "context"),
    opaque16(input.serverIdentity ?? new Uint8Array(), "serverIdentity"),
    opaque16(input.clientIdentity ?? new Uint8Array(), "clientIdentity"),
  );
}

/** Encode a server registration-response input. */
export function buildServerRegistrationResponseInput(
  input: ServerRegistrationResponseInput,
): Uint8Array {
  return concat(
    fixed(input.registrationRequest, "registrationRequest", 32),
    fixed(input.serverPublicKey, "serverPublicKey", 32),
    opaque16(input.credentialIdentifier, "credentialIdentifier"),
    fixed(input.oprfSeed, "oprfSeed", 64),
  );
}

/** Encode a deterministic fake-record input. */
export function buildServerCreateFakeRecordInput(
  input: ServerCreateFakeRecordInput,
): Uint8Array {
  return concat(
    fixed(input.oprfSeed, "oprfSeed", 64),
    fixed(input.seed, "seed", 32),
    opaque16(input.credentialIdentifier, "credentialIdentifier"),
  );
}

/** Encode a client login-start input. */
export function buildLoginStartInput(input: LoginStartInput): Uint8Array {
  return concat(
    fixed(input.blindUniform, "blindUniform", 64),
    fixed(input.clientNonce, "clientNonce", 32),
    fixed(input.clientKeyshareSeed, "clientKeyshareSeed", 32),
    bytes(input.password, "password"),
  );
}

/** Encode a client login-finish input. */
export function buildLoginFinishInput(input: LoginFinishInput): Uint8Array {
  return concat(
    fixed(input.clientLoginState, "clientLoginState", 160),
    fixed(input.ke2, "ke2", 320),
    opaque16(input.password, "password"),
    opaque16(input.context ?? new Uint8Array(), "context"),
    opaque16(input.serverIdentity ?? new Uint8Array(), "serverIdentity"),
    opaque16(input.clientIdentity ?? new Uint8Array(), "clientIdentity"),
  );
}

/** Encode a server login-start input. */
export function buildServerLoginStartInput(
  input: ServerLoginStartInput,
): Uint8Array {
  return concat(
    fixed(input.serverPrivateKey, "serverPrivateKey", 32),
    fixed(input.serverPublicKey, "serverPublicKey", 32),
    fixed(input.registrationRecord, "registrationRecord", 192),
    fixed(input.oprfSeed, "oprfSeed", 64),
    fixed(input.ke1, "ke1", 96),
    fixed(input.maskingNonce, "maskingNonce", 32),
    fixed(input.serverNonce, "serverNonce", 32),
    fixed(input.serverKeyshareSeed, "serverKeyshareSeed", 32),
    opaque16(input.credentialIdentifier, "credentialIdentifier"),
    opaque16(input.context ?? new Uint8Array(), "context"),
    opaque16(input.serverIdentity ?? new Uint8Array(), "serverIdentity"),
    opaque16(input.clientIdentity ?? new Uint8Array(), "clientIdentity"),
  );
}

/** Encode a server login-finish input. */
export function buildServerLoginFinishInput(
  input: ServerLoginFinishInput,
): Uint8Array {
  return concat(
    fixed(input.serverLoginState, "serverLoginState", 128),
    fixed(input.ke3, "ke3", 64),
  );
}

/** Validate the shape of a production opaque-zig export table. */
export function assertOpaqueExports(
  exports: WebAssembly.Exports,
): OpaqueExports {
  if (!(exports.memory instanceof WebAssembly.Memory)) {
    throw new TypeError("OPAQUE WASM must export memory");
  }
  const functions = [
    "allocate",
    "free",
    "resetAllocator",
    "version",
    "registrationRequestLen",
    "registrationResponseLen",
    "registrationRecordLen",
    "ke1Len",
    "ke2Len",
    "ke3Len",
    "serverKeyPairLen",
    ...OPERATIONS,
  ];
  for (const name of functions) {
    if (typeof exports[name] !== "function") {
      throw new TypeError(`OPAQUE WASM must export function ${name}`);
    }
  }
  return exports as OpaqueExports;
}

/** Instantiate and validate ABI v5 from raw bytes, a module, or an HTTP response. */
export async function instantiateOpaqueWasm(
  source: ArrayBuffer | Uint8Array | WebAssembly.Module | Response,
): Promise<OpaqueWasm> {
  let instance: WebAssembly.Instance;
  if (source instanceof WebAssembly.Module) {
    instance = await WebAssembly.instantiate(source);
  } else if (source instanceof Response) {
    if (!source.ok) {
      throw new Error(`Failed to fetch OPAQUE WASM: HTTP ${source.status}`);
    }
    try {
      instance =
        (await WebAssembly.instantiateStreaming(source.clone())).instance;
    } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      instance =
        (await WebAssembly.instantiate(await source.arrayBuffer())).instance;
    }
  } else {
    const bytes = source instanceof Uint8Array ? source.slice().buffer : source;
    instance = (await WebAssembly.instantiate(bytes as ArrayBuffer)).instance;
  }
  const wasm = new OpaqueWasm(instance);
  wasm.assertVersion();
  wasm.assertLengths();
  return wasm;
}

/** Encode a JavaScript string as UTF-8 bytes. */
export function utf8Encode(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/** Encode bytes as unpadded base64url. */
export function bytesToBase64Url(value: Uint8Array): string {
  assertBytes(value, "value");
  let binary = "";
  for (let offset = 0; offset < value.byteLength; offset += 0x8000) {
    binary += String.fromCharCode(...value.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(
    /=+$/,
    "",
  );
}

/** Decode strict unpadded base64url. */
export function base64UrlToBytes(value: string): Uint8Array {
  if (
    typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value) ||
    value.length % 4 === 1
  ) {
    throw new RangeError("invalid base64url value");
  }
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "=",
  );
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(
    parts.reduce((total, part) => total + part.byteLength, 0),
  );
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function opaque16(value: Uint8Array, name: string): Uint8Array {
  const body = bytes(value, name);
  if (body.byteLength > 0xffff) throw new RangeError(`${name} is too long`);
  const out = new Uint8Array(body.byteLength + 2);
  new DataView(out.buffer).setUint16(0, body.byteLength, false);
  out.set(body, 2);
  return out;
}

function fixed(value: Uint8Array, name: string, length: number): Uint8Array {
  const result = bytes(value, name);
  if (result.byteLength !== length) {
    throw new RangeError(`${name} must be ${length} bytes`);
  }
  return result;
}

function bytes(value: Uint8Array, name: string): Uint8Array {
  assertBytes(value, name);
  return value;
}

function assertBytes(
  value: unknown,
  name: string,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}

function assertByteLength(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RangeError("byte length must be a uint32");
  }
}

function statusName(status: number): string {
  return Object.entries(OPAQUE_WASM_STATUS).find(([, value]) =>
    value === status
  )?.[0] ?? "unknown";
}
