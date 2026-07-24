import {
  base64UrlToBytes,
  buildLoginFinishInput,
  buildLoginStartInput,
  buildRegistrationFinishInput,
  buildRegistrationStartInput,
  bytesToBase64Url,
  OPAQUE_SIZES,
  OPAQUE_WASM_STATUS,
  OpaqueWasm,
  OpaqueWasmError,
} from "./raw.ts";

interface WorkerRequest {
  id: number;
  operation: "register" | "login" | "logout";
  identifier?: string;
  password?: ArrayBuffer;
  context: Uint8Array;
  prefix: string;
  baseUrl: string;
  wasmUrl: string;
}

let wasmPromise: Promise<OpaqueWasm> | undefined;
let loadedWasmUrl: string | undefined;
const workerScope = globalThis as unknown as {
  onmessage:
    | ((event: MessageEvent<WorkerRequest>) => void | Promise<void>)
    | null;
  postMessage(message: unknown, transfer?: Transferable[]): void;
};

workerScope.onmessage = async (
  event: MessageEvent<WorkerRequest>,
): Promise<void> => {
  const message = event.data;
  try {
    if (message.operation === "logout") {
      await postJson(authUrl(message.baseUrl, message.prefix, "logout"), {
        version: 1,
      });
      workerScope.postMessage({ id: message.id, ok: true });
      return;
    }
    if (!message.password || !message.identifier) {
      throw new TypeError("missing worker authentication input");
    }
    const password = new Uint8Array(message.password);
    try {
      const exportKey = message.operation === "register"
        ? await register(
          message.identifier,
          password,
          message.context,
          message.prefix,
          message.baseUrl,
          message.wasmUrl,
        )
        : await login(
          message.identifier,
          password,
          message.context,
          message.prefix,
          message.baseUrl,
          message.wasmUrl,
        );
      workerScope.postMessage({
        id: message.id,
        ok: true,
        exportKey: exportKey.buffer,
      }, [exportKey.buffer]);
    } finally {
      password.fill(0);
    }
  } catch (error) {
    workerScope.postMessage({
      id: message.id,
      ok: false,
      error: {
        name: error instanceof Error ? error.name : "Error",
        message: safeMessage(error),
      },
    });
  }
};

async function register(
  identifier: string,
  password: Uint8Array,
  context: Uint8Array,
  prefix: string,
  baseUrl: string,
  wasmUrl: string,
): Promise<Uint8Array> {
  const wasm = await getWasm(wasmUrl);
  let start: Uint8Array | undefined;
  let finish: Uint8Array | undefined;
  try {
    start = callWithWipedInput(
      wasm,
      "registrationStart",
      buildRegistrationStartInput({
        blindUniform: randomBytes(OPAQUE_SIZES.blindUniform),
        password,
      }),
    );
    requireLength(
      start,
      OPAQUE_SIZES.blind + OPAQUE_SIZES.registrationRequest,
      "registration start output",
    );
    const response = await postJson(
      authUrl(baseUrl, prefix, "register/start"),
      {
        version: 1,
        identifier,
        registrationRequest: bytesToBase64Url(
          start.subarray(OPAQUE_SIZES.blind),
        ),
      },
    );
    const registrationId = responseString(response, "registrationId");
    const registrationResponse = responseBytes(
      response,
      "registrationResponse",
      OPAQUE_SIZES.registrationResponse,
    );
    finish = callWithWipedInput(
      wasm,
      "registrationFinish",
      buildRegistrationFinishInput({
        blind: start.subarray(0, OPAQUE_SIZES.blind),
        envelopeNonce: randomBytes(OPAQUE_SIZES.nonce),
        registrationResponse,
        password,
        context,
      }),
    );
    requireLength(
      finish,
      OPAQUE_SIZES.registrationRecord + OPAQUE_SIZES.exportKey,
      "registration finish output",
    );
    await postJson(authUrl(baseUrl, prefix, "register/finish"), {
      version: 1,
      registrationId,
      registrationRecord: bytesToBase64Url(
        finish.subarray(0, OPAQUE_SIZES.registrationRecord),
      ),
    });
    return finish.slice(OPAQUE_SIZES.registrationRecord);
  } catch (error) {
    if (wasm.poisoned) wasmPromise = undefined;
    throw error;
  } finally {
    start?.fill(0);
    finish?.fill(0);
  }
}

async function login(
  identifier: string,
  password: Uint8Array,
  context: Uint8Array,
  prefix: string,
  baseUrl: string,
  wasmUrl: string,
): Promise<Uint8Array> {
  const wasm = await getWasm(wasmUrl);
  let start: Uint8Array | undefined;
  let finish: Uint8Array | undefined;
  try {
    start = callWithWipedInput(
      wasm,
      "loginStart",
      buildLoginStartInput({
        blindUniform: randomBytes(OPAQUE_SIZES.blindUniform),
        clientNonce: randomBytes(OPAQUE_SIZES.nonce),
        clientKeyshareSeed: randomBytes(OPAQUE_SIZES.seed),
        password,
      }),
    );
    requireLength(
      start,
      OPAQUE_SIZES.clientLoginState + OPAQUE_SIZES.ke1,
      "login start output",
    );
    const response = await postJson(authUrl(baseUrl, prefix, "login/start"), {
      version: 1,
      identifier,
      ke1: bytesToBase64Url(start.subarray(OPAQUE_SIZES.clientLoginState)),
    });
    const loginId = responseString(response, "loginId");
    const ke2 = responseBytes(response, "ke2", OPAQUE_SIZES.ke2);
    try {
      finish = callWithWipedInput(
        wasm,
        "loginFinish",
        buildLoginFinishInput({
          clientLoginState: start.subarray(
            0,
            OPAQUE_SIZES.clientLoginState,
          ),
          ke2,
          password,
          context,
        }),
      );
    } catch (error) {
      if (
        error instanceof OpaqueWasmError &&
        error.status === OPAQUE_WASM_STATUS.protocolError
      ) {
        await consumeLoginAttempt(baseUrl, prefix, loginId);
        throw new OpaqueAuthenticationError();
      }
      throw error;
    }
    requireLength(
      finish,
      OPAQUE_SIZES.ke3 + OPAQUE_SIZES.sessionKey + OPAQUE_SIZES.exportKey,
      "login finish output",
    );
    const sessionKey = finish.subarray(
      OPAQUE_SIZES.ke3,
      OPAQUE_SIZES.ke3 + OPAQUE_SIZES.sessionKey,
    );
    try {
      await postJson(authUrl(baseUrl, prefix, "login/finish"), {
        version: 1,
        loginId,
        ke3: bytesToBase64Url(finish.subarray(0, OPAQUE_SIZES.ke3)),
      }, true);
    } finally {
      sessionKey.fill(0);
    }
    return finish.slice(OPAQUE_SIZES.ke3 + OPAQUE_SIZES.sessionKey);
  } catch (error) {
    if (wasm.poisoned) wasmPromise = undefined;
    if (error instanceof HttpError && error.status === 401) {
      throw new OpaqueAuthenticationError();
    }
    throw error;
  } finally {
    start?.fill(0);
    finish?.fill(0);
  }
}

async function getWasm(url: string): Promise<OpaqueWasm> {
  if (loadedWasmUrl !== url) {
    loadedWasmUrl = url;
    wasmPromise = undefined;
  }
  wasmPromise ??= instantiate(url);
  return await wasmPromise;
}

async function instantiate(url: string): Promise<OpaqueWasm> {
  const response = await fetch(url, { credentials: "same-origin" });
  if (!response.ok) {
    throw new Error(`Failed to fetch OPAQUE WASM: HTTP ${response.status}`);
  }
  let result: WebAssembly.WebAssemblyInstantiatedSource;
  try {
    result = await WebAssembly.instantiateStreaming(response.clone());
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
    result = await WebAssembly.instantiate(await response.arrayBuffer());
  }
  const wasm = new OpaqueWasm(result);
  wasm.assertVersion();
  wasm.assertLengths();
  return wasm;
}

async function postJson(
  url: string,
  body: Record<string, unknown>,
  authentication = false,
): Promise<Record<string, unknown>> {
  const response = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  let data: unknown;
  try {
    data = await response.json();
  } catch {
    throw new HttpError(
      response.status,
      "authentication service returned invalid JSON",
    );
  }
  if (!response.ok) {
    throw new HttpError(
      response.status,
      authentication ? "authentication failed" : errorMessage(data),
    );
  }
  if (
    !data || typeof data !== "object" || Array.isArray(data) ||
    (data as Record<string, unknown>).version !== 1
  ) {
    throw new Error("authentication service returned an unsupported response");
  }
  return data as Record<string, unknown>;
}

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = "HttpError";
  }
}
class OpaqueAuthenticationError extends Error {
  constructor() {
    super("wrong identifier or password");
    this.name = "OpaqueAuthenticationError";
  }
}

function responseString(value: Record<string, unknown>, name: string): string {
  const field = value[name];
  if (typeof field !== "string" || field.length === 0) {
    throw new Error(`authentication response is missing ${name}`);
  }
  return field;
}
function responseBytes(
  value: Record<string, unknown>,
  name: string,
  length: number,
): Uint8Array {
  const field = base64UrlToBytes(responseString(value, name));
  requireLength(field, length, name);
  return field;
}
function requireLength(value: Uint8Array, length: number, name: string): void {
  if (value.byteLength !== length) {
    throw new RangeError(`${name} must be ${length} bytes`);
  }
}
function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function callWithWipedInput(
  wasm: OpaqueWasm,
  operation:
    | "registrationStart"
    | "registrationFinish"
    | "loginStart"
    | "loginFinish",
  input: Uint8Array,
): Uint8Array {
  try {
    return wasm[operation](input);
  } finally {
    input.fill(0);
  }
}
function errorMessage(value: unknown): string {
  if (
    value && typeof value === "object" &&
    typeof (value as { error?: unknown }).error === "string"
  ) {
    return (value as { error: string }).error;
  }
  return "authentication request failed";
}
function safeMessage(error: unknown): string {
  if (error instanceof OpaqueAuthenticationError) return error.message;
  if (error instanceof HttpError) return error.message;
  if (error instanceof Error) return error.message;
  return "OPAQUE operation failed";
}

function authUrl(baseUrl: string, prefix: string, path: string): string {
  const value = `${prefix}/${path}`;
  return baseUrl ? new URL(value, baseUrl).href : value;
}

async function consumeLoginAttempt(
  baseUrl: string,
  prefix: string,
  loginId: string,
): Promise<void> {
  try {
    await postJson(
      authUrl(baseUrl, prefix, "login/finish"),
      {
        version: 1,
        loginId,
        ke3: bytesToBase64Url(randomBytes(OPAQUE_SIZES.ke3)),
      },
      true,
    );
  } catch {
    // Best effort: the server consumes the attempt before returning 401.
  }
}

export {};
