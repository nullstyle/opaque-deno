import {
  OPAQUE_WASM_ARTIFACT_ID,
  OPAQUE_WASM_SHA256,
  opaqueWasmAssetPath,
} from "./artifact.ts";
import {
  base64UrlToBytes,
  buildServerCreateFakeRecordInput,
  buildServerLoginFinishInput,
  buildServerLoginStartInput,
  buildServerRegistrationResponseInput,
  bytesToBase64Url,
  OPAQUE_SIZES,
  OPAQUE_WASM_STATUS,
  OpaqueWasmError,
  utf8Encode,
} from "./raw.ts";
import {
  allowOpenRegistration,
  type AuthenticatedSession,
  type AuthorizeRegistration,
  type OpaqueAuthStore,
  OpaqueStorageUnavailableError,
  type SessionMutation,
  type WebSessionProvider,
} from "./types.ts";
import { loadOpaqueWasmBytes, OpaqueInstancePool } from "./wasm.ts";

const WIRE_VERSION = 1;
const DEFAULT_PREFIX = "/api/auth";
const DEFAULT_ATTEMPT_TTL_MS = 5 * 60 * 1000;
const MAX_BODY_BYTES = 32 * 1024;

/** Persistent secrets, adapters, and policy used to configure an auth server. */
export interface CreateOpaqueAuthServerOptions {
  /** Non-empty application transcript context shared with browser clients. */
  context: string | Uint8Array;
  /** Persistent 32-byte server key seed. */
  serverKeySeed: Uint8Array;
  /** Persistent 64-byte OPRF seed. */
  oprfSeed: Uint8Array;
  /** Persistent 32-byte fake-record seed. */
  fakeRecordSeed: Uint8Array;
  /** Credential and attempt persistence adapter. */
  store: OpaqueAuthStore;
  /** Structurally typed web-session provider. */
  sessionProvider: WebSessionProvider;
  /** Authentication URL prefix, defaulting to `/api/auth`. */
  prefix?: string;
  /** Single-use attempt lifetime in milliseconds. */
  attemptTtlMs?: number;
  /** One application-wide identifier normalization policy. */
  canonicalizeIdentifier?: (identifier: string) => string;
  /** Registration authorization hook; defaults to open UUID subjects. */
  authorizeRegistration?: AuthorizeRegistration;
}

/** Direct server inputs for registration start. */
export interface OpaqueRegistrationStartInput {
  /** User-supplied identifier before canonicalization. */
  identifier: string;
  /** 32-byte client registration request. */
  registrationRequest: Uint8Array;
  /** Original request for registration policy checks. */
  request: Request;
}
/** Direct server result from registration start. */
export interface OpaqueRegistrationStartResult {
  /** Opaque single-use registration attempt identifier. */
  registrationId: string;
  /** 64-byte server registration response. */
  registrationResponse: Uint8Array;
}
/** Direct server inputs for registration finish. */
export interface OpaqueRegistrationFinishInput {
  /** Opaque single-use registration attempt identifier. */
  registrationId: string;
  /** 192-byte client registration record. */
  registrationRecord: Uint8Array;
}
/** Direct server inputs for login start. */
export interface OpaqueLoginStartInput {
  /** User-supplied identifier before canonicalization. */
  identifier: string;
  /** 96-byte client KE1 message. */
  ke1: Uint8Array;
}
/** Direct server result from login start. */
export interface OpaqueLoginStartResult {
  /** Opaque single-use login attempt identifier. */
  loginId: string;
  /** 320-byte server KE2 message. */
  ke2: Uint8Array;
}
/** Direct server inputs for login finish. */
export interface OpaqueLoginFinishInput {
  /** Opaque single-use login attempt identifier. */
  loginId: string;
  /** 64-byte client KE3 message. */
  ke3: Uint8Array;
  /** Original request passed to the session provider. */
  request: Request;
}

/** A configured OPAQUE server and web-standard authentication handler. */
export class OpaqueAuthServer {
  /** Normalized URL prefix served by this instance. */
  readonly prefix: string;
  /** Hash-versioned immutable WASM asset path. */
  readonly assetPath: string;
  readonly #pool: OpaqueInstancePool;
  readonly #store: OpaqueAuthStore;
  readonly #sessions: WebSessionProvider;
  readonly #context: Uint8Array;
  readonly #serverPrivateKey: Uint8Array;
  readonly #serverPublicKey: Uint8Array;
  readonly #oprfSeed: Uint8Array;
  readonly #fakeRecordSeed: Uint8Array;
  readonly #ttlMs: number;
  readonly #canonicalize: (identifier: string) => string;
  readonly #authorize: AuthorizeRegistration;
  #disposed = false;

  private constructor(
    options: CreateOpaqueAuthServerOptions,
    pool: OpaqueInstancePool,
    keys: { sk: Uint8Array; pk: Uint8Array },
    context: Uint8Array,
  ) {
    this.prefix = normalizePrefix(options.prefix ?? DEFAULT_PREFIX);
    this.assetPath = opaqueWasmAssetPath(this.prefix);
    this.#pool = pool;
    this.#store = options.store;
    this.#sessions = options.sessionProvider;
    this.#context = context;
    this.#serverPrivateKey = keys.sk;
    this.#serverPublicKey = keys.pk;
    this.#oprfSeed = options.oprfSeed.slice();
    this.#fakeRecordSeed = options.fakeRecordSeed.slice();
    this.#ttlMs = options.attemptTtlMs ?? DEFAULT_ATTEMPT_TTL_MS;
    this.#canonicalize = options.canonicalizeIdentifier ??
      ((identifier) => identifier);
    this.#authorize = options.authorizeRegistration ?? allowOpenRegistration();
  }

  /** Initialize the verified module pool and derive the server key pair. */
  static async create(
    options: CreateOpaqueAuthServerOptions,
  ): Promise<OpaqueAuthServer> {
    const context = typeof options.context === "string"
      ? utf8Encode(options.context)
      : options.context.slice();
    fixed(context, "context", undefined, false);
    if (context.byteLength > 0xffff) {
      throw new RangeError(
        "context must fit in the OPAQUE uint16 length prefix",
      );
    }
    fixed(options.serverKeySeed, "serverKeySeed", 32);
    fixed(options.oprfSeed, "oprfSeed", 64);
    fixed(options.fakeRecordSeed, "fakeRecordSeed", 32);
    if (
      !Number.isSafeInteger(options.attemptTtlMs ?? DEFAULT_ATTEMPT_TTL_MS) ||
      (options.attemptTtlMs ?? DEFAULT_ATTEMPT_TTL_MS) < 1
    ) {
      throw new RangeError("attemptTtlMs must be a positive integer");
    }
    const pool = await OpaqueInstancePool.create();
    const seed = options.serverKeySeed.slice();
    try {
      const keys = await pool.withInstance((wasm) => wasm.serverKeyPair(seed));
      return new OpaqueAuthServer(options, pool, keys, context);
    } finally {
      seed.fill(0);
    }
  }

  /** Run server registration start and persist a bound, expiring attempt. */
  async registrationStart(
    input: OpaqueRegistrationStartInput,
  ): Promise<OpaqueRegistrationStartResult> {
    this.#assertActive();
    const identifier = this.#identifier(input.identifier);
    fixed(
      input.registrationRequest,
      "registrationRequest",
      OPAQUE_SIZES.registrationRequest,
    );
    const existing = await this.#fromStore(() =>
      this.#store.getCredential(identifier)
    );
    if (existing) {
      wipeCredential(existing);
      throw new DuplicateIdentifierError();
    }
    const authorization = await this.#authorize({
      identifier,
      request: input.request,
    });
    if (
      !authorization || typeof authorization.subject !== "string" ||
      authorization.subject.length === 0
    ) {
      throw new RegistrationDeniedError();
    }
    const credentialIdentifier = utf8Encode(identifier);
    if (credentialIdentifier.byteLength > 0xffff) {
      throw new BadRequestError("identifier is too long");
    }
    try {
      const registrationResponse = await this.#pool.withInstance((wasm) =>
        callWithWipedInput(
          buildServerRegistrationResponseInput({
            registrationRequest: input.registrationRequest,
            serverPublicKey: this.#serverPublicKey,
            credentialIdentifier,
            oprfSeed: this.#oprfSeed,
          }),
          (frame) => wasm.serverRegistrationResponse(frame),
        )
      );
      fixed(
        registrationResponse,
        "registrationResponse",
        OPAQUE_SIZES.registrationResponse,
      );
      const registrationId = crypto.randomUUID();
      await this.#fromStore(() =>
        this.#store.putRegistrationAttempt({
          id: registrationId,
          identifier,
          subject: authorization.subject,
          credentialIdentifier,
          expiresAt: new Date(Date.now() + this.#ttlMs),
        })
      );
      return { registrationId, registrationResponse };
    } finally {
      credentialIdentifier.fill(0);
    }
  }

  /** Consume a registration attempt and atomically create its credential. */
  async registrationFinish(
    input: OpaqueRegistrationFinishInput,
  ): Promise<void> {
    this.#assertActive();
    validId(input.registrationId, "registrationId");
    fixed(
      input.registrationRecord,
      "registrationRecord",
      OPAQUE_SIZES.registrationRecord,
    );
    const attempt = await this.#fromStore(() =>
      this.#store.takeRegistrationAttempt(input.registrationId)
    );
    if (!attempt) {
      throw new BadRequestError("invalid registration attempt");
    }
    try {
      if (attempt.expiresAt.getTime() <= Date.now()) {
        throw new BadRequestError("invalid registration attempt");
      }
      const now = new Date();
      const registrationRecord = input.registrationRecord.slice();
      try {
        const created = await this.#fromStore(() =>
          this.#store.createCredential({
            identifier: attempt.identifier,
            subject: attempt.subject,
            credentialIdentifier: attempt.credentialIdentifier,
            registrationRecord,
            createdAt: now,
            updatedAt: now,
          })
        );
        if (!created) throw new DuplicateIdentifierError();
      } finally {
        registrationRecord.fill(0);
      }
    } finally {
      attempt.credentialIdentifier.fill(0);
    }
  }

  /** Run login start with a real or deterministic fake credential record. */
  async loginStart(
    input: OpaqueLoginStartInput,
  ): Promise<OpaqueLoginStartResult> {
    this.#assertActive();
    const identifier = this.#identifier(input.identifier);
    fixed(input.ke1, "ke1", OPAQUE_SIZES.ke1);
    const credential = await this.#fromStore(() =>
      this.#store.getCredential(identifier)
    );
    const credentialIdentifier = credential?.credentialIdentifier.slice() ??
      utf8Encode(identifier);
    let record: Uint8Array | undefined;
    let output: Uint8Array | undefined;
    try {
      record = credential?.registrationRecord.slice() ??
        await this.#pool.withInstance((wasm) =>
          callWithWipedInput(
            buildServerCreateFakeRecordInput({
              oprfSeed: this.#oprfSeed,
              seed: this.#fakeRecordSeed,
              credentialIdentifier,
            }),
            (frame) => wasm.serverCreateFakeRecord(frame),
          )
        );
      const registrationRecord = record;
      fixed(
        registrationRecord,
        "registrationRecord",
        OPAQUE_SIZES.registrationRecord,
      );
      output = await this.#pool.withInstance((wasm) =>
        callWithWipedInput(
          buildServerLoginStartInput({
            serverPrivateKey: this.#serverPrivateKey,
            serverPublicKey: this.#serverPublicKey,
            registrationRecord,
            oprfSeed: this.#oprfSeed,
            ke1: input.ke1,
            maskingNonce: randomBytes(32),
            serverNonce: randomBytes(32),
            serverKeyshareSeed: randomBytes(32),
            credentialIdentifier,
            context: this.#context,
          }),
          (frame) => wasm.serverLoginStart(frame),
        )
      );
      fixed(
        output,
        "server login output",
        OPAQUE_SIZES.serverLoginState + OPAQUE_SIZES.ke2,
      );
      const loginId = crypto.randomUUID();
      const serverLoginState = output.slice(0, OPAQUE_SIZES.serverLoginState);
      const ke2 = output.slice(OPAQUE_SIZES.serverLoginState);
      try {
        await this.#fromStore(() =>
          this.#store.putLoginAttempt({
            id: loginId,
            identifier,
            subject: credential?.subject ?? null,
            serverLoginState,
            expiresAt: new Date(Date.now() + this.#ttlMs),
          })
        );
      } finally {
        serverLoginState.fill(0);
      }
      return { loginId, ke2 };
    } finally {
      output?.fill(0);
      record?.fill(0);
      credentialIdentifier.fill(0);
      if (credential) wipeCredential(credential);
    }
  }

  /** Consume login state, verify KE3, and create a web session on success. */
  async loginFinish(
    input: OpaqueLoginFinishInput,
  ): Promise<SessionMutation | null> {
    this.#assertActive();
    validId(input.loginId, "loginId");
    fixed(input.ke3, "ke3", OPAQUE_SIZES.ke3);
    const attempt = await this.#fromStore(() =>
      this.#store.takeLoginAttempt(input.loginId)
    );
    if (!attempt || attempt.expiresAt.getTime() <= Date.now()) {
      attempt?.serverLoginState.fill(0);
      return null;
    }
    let sessionKey: Uint8Array | undefined;
    try {
      sessionKey = await this.#pool.withInstance((wasm) =>
        callWithWipedInput(
          buildServerLoginFinishInput({
            serverLoginState: attempt.serverLoginState,
            ke3: input.ke3,
          }),
          (frame) => wasm.serverLoginFinish(frame),
        )
      );
      fixed(sessionKey, "sessionKey", OPAQUE_SIZES.sessionKey);
    } catch (error) {
      if (error instanceof OpaqueWasmError) return null;
      throw error;
    } finally {
      sessionKey?.fill(0);
      attempt.serverLoginState.fill(0);
    }
    if (attempt.subject === null) return null;
    return await this.#sessions.create(attempt.subject, input.request);
  }

  /** Authenticate a request through the configured session provider. */
  authenticate(request: Request): Promise<AuthenticatedSession | null> {
    this.#assertActive();
    return this.#sessions.authenticate(request);
  }

  /** Destroy the request's session through the configured provider. */
  logout(request: Request): Promise<SessionMutation> {
    this.#assertActive();
    return this.#sessions.destroy(request);
  }

  /** Route known auth endpoints; return null so middleware can delegate unknown paths. */
  async route(request: Request): Promise<Response | null> {
    const url = new URL(request.url);
    if (url.pathname === this.assetPath) {
      if (request.method !== "GET") return methodNotAllowed("GET");
      return this.#assetResponse();
    }
    const path = url.pathname.startsWith(`${this.prefix}/`)
      ? url.pathname.slice(this.prefix.length + 1)
      : null;
    if (
      !path ||
      ![
        "register/start",
        "register/finish",
        "login/start",
        "login/finish",
        "logout",
      ].includes(path)
    ) {
      return null;
    }
    if (request.method !== "POST") return methodNotAllowed("POST");
    try {
      switch (path) {
        case "register/start": {
          const body = await readBody(request);
          const registrationRequest = requiredBytes(
            body,
            "registrationRequest",
            OPAQUE_SIZES.registrationRequest,
          );
          let result: OpaqueRegistrationStartResult;
          try {
            result = await this.registrationStart({
              identifier: requiredString(body, "identifier"),
              registrationRequest,
              request,
            });
          } finally {
            registrationRequest.fill(0);
          }
          return json({
            version: WIRE_VERSION,
            registrationId: result.registrationId,
            registrationResponse: bytesToBase64Url(result.registrationResponse),
          });
        }
        case "register/finish": {
          const body = await readBody(request);
          const registrationRecord = requiredBytes(
            body,
            "registrationRecord",
            OPAQUE_SIZES.registrationRecord,
          );
          try {
            await this.registrationFinish({
              registrationId: requiredString(body, "registrationId"),
              registrationRecord,
            });
          } finally {
            registrationRecord.fill(0);
          }
          return json({ version: WIRE_VERSION, ok: true });
        }
        case "login/start": {
          const body = await readBody(request);
          const ke1 = requiredBytes(body, "ke1", OPAQUE_SIZES.ke1);
          let result: OpaqueLoginStartResult;
          try {
            result = await this.loginStart({
              identifier: requiredString(body, "identifier"),
              ke1,
            });
          } finally {
            ke1.fill(0);
          }
          return json({
            version: WIRE_VERSION,
            loginId: result.loginId,
            ke2: bytesToBase64Url(result.ke2),
          });
        }
        case "login/finish": {
          const body = await readBody(request);
          const ke3 = requiredBytes(body, "ke3", OPAQUE_SIZES.ke3);
          let mutation: SessionMutation | null;
          try {
            mutation = await this.loginFinish({
              loginId: requiredString(body, "loginId"),
              ke3,
              request,
            });
          } finally {
            ke3.fill(0);
          }
          return mutation
            ? json({ version: WIRE_VERSION, ok: true }, 200, {
              "set-cookie": mutation.setCookie,
            })
            : json({ version: WIRE_VERSION, ok: false }, 401);
        }
        case "logout": {
          const mutation = await this.logout(request);
          return json({ version: WIRE_VERSION, ok: true }, 200, {
            "set-cookie": mutation.setCookie,
          });
        }
      }
    } catch (error) {
      if (error instanceof BadRequestError) {
        return json({ version: WIRE_VERSION, error: "invalid request" }, 400);
      }
      if (error instanceof OpaqueWasmError) {
        return error.status === OPAQUE_WASM_STATUS.outOfMemory
          ? json({ version: WIRE_VERSION, error: "service unavailable" }, 503)
          : json({ version: WIRE_VERSION, error: "invalid request" }, 400);
      }
      if (error instanceof DuplicateIdentifierError) {
        return json({
          version: WIRE_VERSION,
          error: "identifier already registered",
        }, 409);
      }
      if (error instanceof RegistrationDeniedError) {
        return json(
          { version: WIRE_VERSION, error: "registration denied" },
          403,
        );
      }
      if (error instanceof OpaqueStorageUnavailableError) {
        return json(
          { version: WIRE_VERSION, error: "service unavailable" },
          503,
        );
      }
      return json({ version: WIRE_VERSION, error: "internal error" }, 500);
    }
    return null;
  }

  /** A complete handler suitable for direct use with `Deno.serve`. */
  async handle(request: Request): Promise<Response> {
    return await this.route(request) ??
      new Response("Not found", { status: 404 });
  }

  /** Wipe server secrets and close the instance pool. */
  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#serverPrivateKey.fill(0);
    this.#serverPublicKey.fill(0);
    this.#oprfSeed.fill(0);
    this.#fakeRecordSeed.fill(0);
    this.#context.fill(0);
    this.#pool.close();
  }

  async #assetResponse(): Promise<Response> {
    const bytes = await loadOpaqueWasmBytes();
    return new Response(bytes.slice().buffer, {
      headers: {
        "content-type": "application/wasm",
        "content-length": String(bytes.byteLength),
        "cache-control": "public, max-age=31536000, immutable",
        "etag": `"sha256-${OPAQUE_WASM_SHA256}"`,
        "x-content-type-options": "nosniff",
        "cross-origin-resource-policy": "same-origin",
      },
    });
  }

  #identifier(raw: string): string {
    if (typeof raw !== "string") {
      throw new BadRequestError("identifier must be a string");
    }
    const identifier = this.#canonicalize(raw);
    if (typeof identifier !== "string" || identifier.length === 0) {
      throw new BadRequestError("identifier must not be empty");
    }
    if (hasUnpairedSurrogate(identifier)) {
      throw new BadRequestError("identifier must be valid Unicode text");
    }
    if (utf8Encode(identifier).byteLength > 0xffff) {
      throw new BadRequestError("identifier is too long");
    }
    return identifier;
  }

  async #fromStore<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof OpaqueStorageUnavailableError) throw error;
      throw new OpaqueStorageUnavailableError(undefined, { cause: error });
    }
  }

  #assertActive(): void {
    if (this.#disposed) throw new Error("OPAQUE auth server is disposed");
  }
}

/** Configure and initialize an OPAQUE server. */
export function createOpaqueAuthServer(
  options: CreateOpaqueAuthServerOptions,
): Promise<OpaqueAuthServer> {
  return OpaqueAuthServer.create(options);
}

class BadRequestError extends Error {}
class DuplicateIdentifierError extends Error {}
class RegistrationDeniedError extends Error {}

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function callWithWipedInput(
  input: Uint8Array,
  operation: (input: Uint8Array) => Uint8Array,
): Uint8Array {
  try {
    return operation(input);
  } finally {
    input.fill(0);
  }
}

function wipeCredential(credential: {
  credentialIdentifier: Uint8Array;
  registrationRecord: Uint8Array;
}): void {
  credential.credentialIdentifier.fill(0);
  credential.registrationRecord.fill(0);
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function fixed(
  value: Uint8Array,
  name: string,
  length?: number,
  allowEmpty = true,
): void {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
  if (!allowEmpty && value.byteLength === 0) {
    throw new RangeError(`${name} must not be empty`);
  }
  if (length !== undefined && value.byteLength !== length) {
    throw new RangeError(`${name} must be ${length} bytes`);
  }
}

function validId(value: string, name: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length > 128) {
    throw new BadRequestError(`${name} is invalid`);
  }
}

function normalizePrefix(prefix: string): string {
  if (
    !prefix.startsWith("/") || prefix === "/" || prefix.includes("?") ||
    prefix.includes("#")
  ) {
    throw new TypeError("prefix must be an absolute path such as /api/auth");
  }
  return prefix.replace(/\/+$/, "");
}

async function readBody(request: Request): Promise<Record<string, unknown>> {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]
    .trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new BadRequestError("content-type must be application/json");
  }
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    throw new BadRequestError("request body is too large");
  }
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) {
    throw new BadRequestError("request body is too large");
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new BadRequestError("invalid JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new BadRequestError("JSON body must be an object");
  }
  const body = value as Record<string, unknown>;
  if (body.version !== WIRE_VERSION) {
    throw new BadRequestError("unsupported wire version");
  }
  return body;
}

function requiredString(body: Record<string, unknown>, name: string): string {
  const value = body[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new BadRequestError(`${name} is required`);
  }
  return value;
}

function requiredBytes(
  body: Record<string, unknown>,
  name: string,
  length: number,
): Uint8Array {
  try {
    const value = base64UrlToBytes(requiredString(body, name));
    fixed(value, name, length);
    return value;
  } catch (error) {
    if (error instanceof BadRequestError) throw error;
    throw new BadRequestError(`${name} is invalid`);
  }
}

function json(value: unknown, status = 200, headers?: HeadersInit): Response {
  return Response.json(value, {
    status,
    headers: { ...headers, "cache-control": "no-store" },
  });
}

function methodNotAllowed(allow: string): Response {
  return json({ version: WIRE_VERSION, error: "method not allowed" }, 405, {
    allow,
  });
}

/** JSON protocol version used by the standard HTTP routes. */
export const OPAQUE_HTTP_WIRE_VERSION: number = WIRE_VERSION;
/** Short content identifier included in the immutable WASM asset path. */
export const OPAQUE_WASM_ASSET_ID: string = OPAQUE_WASM_ARTIFACT_ID;
