import { opaqueWasmAssetPath } from "./artifact.ts";
import { utf8Encode } from "./raw.ts";

/** Browser worker, transcript, and endpoint configuration. */
export interface CreateOpaqueClientOptions {
  /** Must exactly match the non-empty application context configured on the server. */
  context: string | Uint8Array;
  /** Auth route prefix. Defaults to `/api/auth`. */
  prefix?: string;
  /** Absolute application origin. Normally inferred by the browser. */
  baseUrl?: string | URL;
  /** Override the immutable WASM asset URL, primarily for reverse proxies. */
  wasmUrl?: string | URL;
  /** Override the module worker URL, primarily for test harnesses. */
  workerUrl?: string | URL;
}

/** Successful high-level registration or login result. */
export interface OpaqueClientResult {
  /** Client-only 64-byte OPAQUE export key. Wipe it after use. */
  exportKey: Uint8Array;
}

/** High-level worker-backed browser authentication client. */
export interface OpaqueClient {
  /** Register a new identifier without sending the password to the server. */
  register(
    identifier: string,
    password: string | Uint8Array,
  ): Promise<OpaqueClientResult>;
  /** Authenticate an identifier and return its client-only export key. */
  login(
    identifier: string,
    password: string | Uint8Array,
  ): Promise<OpaqueClientResult>;
  /** Destroy the current web session. */
  logout(): Promise<void>;
  /** Terminate the module worker and reject pending operations. */
  dispose(): void;
}

/** A generic login failure that does not reveal whether an identifier exists. */
export class OpaqueAuthenticationError extends Error {
  /** Create the generic, enumeration-resistant authentication error. */
  constructor() {
    super("wrong identifier or password");
    this.name = "OpaqueAuthenticationError";
  }
}

interface WorkerSuccess {
  id: number;
  ok: true;
  exportKey?: ArrayBuffer;
}
interface WorkerFailure {
  id: number;
  ok: false;
  error: { name: string; message: string };
}
type WorkerResponse = WorkerSuccess | WorkerFailure;

/** A high-level OPAQUE browser client whose protocol work runs in a module worker. */
export function createOpaqueClient(
  options: CreateOpaqueClientOptions,
): OpaqueClient {
  const context = typeof options.context === "string"
    ? utf8Encode(options.context)
    : options.context.slice();
  if (context.byteLength === 0) {
    throw new RangeError("context must not be empty");
  }
  const prefix = normalizePrefix(options.prefix ?? "/api/auth");
  // Keep the default constructor in Vite's statically analyzable form so the
  // worker and its imports are emitted as a bundled JavaScript asset.
  const worker = options.workerUrl === undefined
    ? new Worker(new URL("./worker.ts", import.meta.url), { type: "module" })
    : new Worker(options.workerUrl, { type: "module" });
  let nextId = 1;
  let disposed = false;
  let terminalError: Error | undefined;
  const pending = new Map<number, {
    resolve(value: OpaqueClientResult | void): void;
    reject(reason: unknown): void;
  }>();

  worker.onmessage = (event: MessageEvent<WorkerResponse>): void => {
    const message = event.data;
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    if (message.ok) {
      request.resolve(
        message.exportKey
          ? { exportKey: new Uint8Array(message.exportKey) }
          : undefined,
      );
    } else {
      const error = message.error.name === "OpaqueAuthenticationError"
        ? new OpaqueAuthenticationError()
        : new Error(message.error.message);
      if (!(error instanceof OpaqueAuthenticationError)) {
        error.name = message.error.name;
      }
      request.reject(error);
    }
  };
  worker.onerror = (event): void => {
    event.preventDefault();
    terminalError = new Error(`OPAQUE worker failed: ${event.message}`);
    worker.terminate();
    failAll(terminalError);
  };

  function request(
    operation: "register" | "login" | "logout",
    identifier?: string,
    password?: string | Uint8Array,
  ): Promise<OpaqueClientResult | void> {
    if (terminalError) return Promise.reject(terminalError);
    if (disposed) return Promise.reject(new Error("OPAQUE client is disposed"));
    if (
      operation !== "logout" &&
      (typeof identifier !== "string" || identifier.length === 0)
    ) {
      return Promise.reject(new TypeError("identifier must not be empty"));
    }
    const passwordBytes = operation === "logout"
      ? undefined
      : typeof password === "string"
      ? utf8Encode(password)
      : password?.slice();
    if (
      operation !== "logout" &&
      (!passwordBytes || passwordBytes.byteLength === 0)
    ) {
      return Promise.reject(new TypeError("password must not be empty"));
    }
    const id = nextId++;
    const promise = new Promise<OpaqueClientResult | void>((resolve, reject) =>
      pending.set(id, { resolve, reject })
    );
    const baseUrl = String(
      options.baseUrl ?? globalThis.location?.origin ?? "",
    );
    const wasmUrl = String(
      options.wasmUrl ?? resolveUrl(opaqueWasmAssetPath(prefix), baseUrl),
    );
    if (passwordBytes) {
      worker.postMessage(
        {
          id,
          operation,
          identifier,
          password: passwordBytes.buffer,
          context,
          prefix,
          baseUrl,
          wasmUrl,
        },
        [passwordBytes.buffer],
      );
    } else {
      worker.postMessage({ id, operation, context, prefix, baseUrl, wasmUrl });
    }
    return promise;
  }

  function failAll(error: Error): void {
    for (const request of pending.values()) request.reject(error);
    pending.clear();
  }

  return {
    register: (identifier, password) =>
      request("register", identifier, password) as Promise<OpaqueClientResult>,
    login: (identifier, password) =>
      request("login", identifier, password) as Promise<OpaqueClientResult>,
    logout: () => request("logout") as Promise<void>,
    dispose(): void {
      if (disposed) return;
      disposed = true;
      context.fill(0);
      worker.terminate();
      failAll(new Error("OPAQUE client was disposed"));
    },
  };
}

function normalizePrefix(prefix: string): string {
  if (!prefix.startsWith("/") || prefix === "/") {
    throw new TypeError("prefix must be an absolute path");
  }
  return prefix.replace(/\/+$/, "");
}

function resolveUrl(path: string, baseUrl: string): string {
  return baseUrl ? new URL(path, baseUrl).href : path;
}
