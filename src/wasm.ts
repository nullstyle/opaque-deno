import { OPAQUE_WASM_BYTE_LENGTH, OPAQUE_WASM_SHA256 } from "./artifact.ts";
import { OpaqueWasm } from "./raw.ts";
// Deno (2.1+) instantiates this statically imported module once per isolate and
// exposes its exports directly; no base64 decode, decompression, or runtime
// compile is required. The module has no host imports, so instantiation needs
// no import object and no permissions.
import * as opaqueExports from "./opaque.wasm";

/** The `.wasm` asset next to this module, used to serve bytes to browsers. */
const wasmUrl = new URL("./opaque.wasm", import.meta.url);
let bytesPromise: Promise<Uint8Array> | undefined;

/**
 * Read and verify the raw WASM bytes for the HTTP asset endpoint and tests.
 * Reads the co-located file directly when local (`file:`) and fetches it once
 * when the package is consumed remotely (e.g. `https:` from JSR); memoized.
 */
export function loadOpaqueWasmBytes(): Promise<Uint8Array> {
  bytesPromise ??= (async () => {
    const bytes = wasmUrl.protocol === "file:"
      ? await Deno.readFile(wasmUrl)
      : new Uint8Array(await (await fetch(wasmUrl)).arrayBuffer());
    if (bytes.byteLength !== OPAQUE_WASM_BYTE_LENGTH) {
      throw new TypeError(
        `OPAQUE WASM is ${bytes.byteLength} bytes; expected ${OPAQUE_WASM_BYTE_LENGTH}`,
      );
    }
    const digest = hex(await crypto.subtle.digest("SHA-256", bytes));
    if (digest !== OPAQUE_WASM_SHA256) {
      throw new TypeError(
        `OPAQUE WASM hash is ${digest}; expected ${OPAQUE_WASM_SHA256}`,
      );
    }
    return bytes;
  })();
  return bytesPromise;
}

/**
 * Serialized access to the single, process-wide opaque-zig instance.
 *
 * A statically imported WebAssembly module is instantiated once per isolate, so
 * there is exactly one instance to share across every {@link OpaqueInstancePool}
 * handle. Operations run one at a time on a shared queue — in a single-threaded
 * isolate synchronous WASM calls cannot interleave anyway, and this also orders
 * trap recovery before the next operation. After a trap the instance is scrubbed
 * and restored in place ({@link OpaqueWasm.recover}) rather than re-instantiated,
 * since the static import exposes no `WebAssembly.Module` to rebuild from.
 */
export class OpaqueInstancePool {
  static #wasm: OpaqueWasm | undefined;
  static #chain: Promise<void> = Promise.resolve();
  #closed = false;

  private constructor(private readonly wasm: OpaqueWasm) {}

  /** Arm the shared instance (once) and return a handle to it. */
  static create(): Promise<OpaqueInstancePool> {
    if (!OpaqueInstancePool.#wasm) {
      const wasm = OpaqueWasm.fromExports(
        opaqueExports as unknown as WebAssembly.Exports,
      );
      // Snapshot pristine memory before any operation writes secrets, then
      // validate the pinned ABI.
      wasm.snapshot();
      wasm.assertVersion();
      wasm.assertLengths();
      OpaqueInstancePool.#wasm = wasm;
    }
    return Promise.resolve(new OpaqueInstancePool(OpaqueInstancePool.#wasm));
  }

  withInstance<T>(
    operation: (wasm: OpaqueWasm) => T | Promise<T>,
  ): Promise<T> {
    if (this.#closed) {
      return Promise.reject(new Error("OPAQUE instance pool is closed"));
    }
    const run = OpaqueInstancePool.#chain.then(() => {
      if (this.#closed) throw new Error("OPAQUE instance pool is closed");
      return operation(this.wasm);
    });
    // Keep the shared queue alive and recover after a trap, regardless of
    // whether this operation resolved or rejected.
    OpaqueInstancePool.#chain = run.then(
      OpaqueInstancePool.#afterRelease,
      OpaqueInstancePool.#afterRelease,
    );
    return run;
  }

  /** Reject this handle's future operations; the shared instance lives on. */
  close(): void {
    this.#closed = true;
  }

  static #afterRelease(): void {
    const wasm = OpaqueInstancePool.#wasm;
    if (wasm?.poisoned) {
      // If recovery fails the instance stays poisoned and every further call
      // rejects via OpaqueWasm's usability guard, so the queue never wedges.
      try {
        wasm.recover();
      } catch {
        // Intentionally ignored; poisoned instance rejects subsequent calls.
      }
    }
  }
}

function hex(value: ArrayBuffer): string {
  return Array.from(
    new Uint8Array(value),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
}
