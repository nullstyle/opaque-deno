import { fresh } from "@fresh/plugin-vite";
import { defineConfig, type Plugin } from "vite";
import wasmPlugin from "vite-plugin-wasm";

// The CJS default export is callable at runtime; Deno's type resolver sees the
// module namespace, so narrow it to its real call signature.
const wasm = wasmPlugin as unknown as () => Plugin;

// @nullstyle/opaque loads its WASM two ways: a static `import` for the server
// instance pool (which vite-plugin-wasm inlines) and a runtime
// `new URL("./opaque.wasm", import.meta.url)` read to serve the exact bytes to
// browsers. Vite doesn't emit that file for the bundled SSR module, so place a
// copy next to the SSR bundle where the runtime read resolves.
function emitOpaqueWasm(): Plugin {
  return {
    name: "emit-opaque-wasm",
    apply: "build",
    async generateBundle(options) {
      if (!options.dir?.endsWith("server")) return;
      this.emitFile({
        type: "asset",
        fileName: "opaque.wasm",
        source: await Deno.readFile(
          new URL("../../src/opaque.wasm", import.meta.url),
        ),
      });
    },
  };
}

// The browser bundle fetches the WASM at runtime and needs neither plugin.
export default defineConfig({
  plugins: [wasm(), emitOpaqueWasm(), fresh()],
});
