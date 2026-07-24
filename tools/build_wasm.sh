#!/usr/bin/env bash
#
# Rebuild the OPAQUE WASM from the vendored opaque-zig submodule and refresh the
# committed artifacts. This is an on-demand task: normal `deno task check`/`ci`
# stays pure-Deno and only verifies the committed src/opaque.wasm against
# wasm.lock.json.
#
# Requires:
#   - The vendor/opaque-zig submodule (this script initializes it).
#   - Zig 0.17.0-dev.1252+e4b325c19 on PATH (e.g. via zvm, or a manual install).
#     mise cannot pin an exact 0.17.0-dev build; a different Zig can change the
#     output bytes. See wasm.lock.json / README.md. Upstream records the same
#     build as OPAQUE_PINNED_ZIG and asserts it via `mise run zig-pin-check`,
#     which can be run inside vendor/opaque-zig to confirm the match.
#   - mise, which provides the pinned Binaryen 130 `wasm-opt`.
#
set -euo pipefail
cd "$(dirname "$0")/.."

git submodule update --init vendor/opaque-zig

# Zig comes from PATH (the pinned dev build); wasm-opt from mise's Binaryen 130.
( cd vendor/opaque-zig && mise exec "aqua:WebAssembly/binaryen@130" -- \
    zig build --cache-dir .zig-cache wasm )

cp vendor/opaque-zig/zig-out/wasm/opaque.wasm vendor/opaque.wasm

# Re-verify the rebuilt binary against wasm.lock.json (sha256/byteLength/exports/
# sections/ABI/zero-imports) and refresh src/opaque.wasm + src/artifact.ts.
# A toolchain drift that changes the bytes makes this step fail loudly.
deno task artifact

echo "OK: rebuilt vendor/opaque.wasm from vendor/opaque-zig and refreshed" \
  "src/opaque.wasm (verified against wasm.lock.json)."
