import { buildRegistrationStartInput, OpaqueWasm } from "../src/raw.ts";

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

async function verifyLinearMemoryScrubbing(artifact: string): Promise<void> {
  const bytes = await Deno.readFile(
    new URL(`../${artifact}`, import.meta.url),
  );
  const module = await WebAssembly.compile(bytes);
  const instance = await WebAssembly.instantiate(module);
  const wasm = new OpaqueWasm(instance);
  wasm.assertVersion();
  wasm.assertLengths();

  const password = Uint8Array.from(
    { length: 48 },
    (_, index) => (index * 73 + 19) & 0xff,
  );
  const blindUniform = Uint8Array.from(
    { length: 64 },
    (_, index) => (index * 151 + 37) & 0xff,
  );
  const input = buildRegistrationStartInput({ blindUniform, password });
  const output = wasm.registrationStart(input);
  try {
    const memory = new Uint8Array(
      (instance.exports.memory as WebAssembly.Memory).buffer,
    );
    for (
      const [name, secret] of [
        ["registration input", input],
        ["password", password],
        ["blind uniform input", blindUniform],
        ["registration start state", output],
      ] as const
    ) {
      const offset = findBytes(memory, secret);
      if (offset >= 0) {
        throw new Error(
          `opaque-zig leaves the exact ${name} in linear memory at offset ${offset}`,
        );
      }
    }
  } finally {
    input.fill(0);
    output.fill(0);
    password.fill(0);
    blindUniform.fill(0);
    bytes.fill(0);
  }
}

function findBytes(haystack: Uint8Array, needle: Uint8Array): number {
  outer:
  for (
    let offset = 0;
    offset <= haystack.byteLength - needle.byteLength;
    offset += 1
  ) {
    if (haystack[offset] !== needle[0]) continue;
    for (let index = 1; index < needle.byteLength; index += 1) {
      if (haystack[offset + index] !== needle[index]) continue outer;
    }
    return offset;
  }
  return -1;
}
