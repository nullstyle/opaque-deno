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

/** The `wasm.lock.json` schema this gate knows how to verify. */
const SCHEMA_VERSION = 2;

const root = new URL("../", import.meta.url);

type Lock = {
  schemaVersion: number;
  /** The build output of record, written by `mise run build-wasm`. */
  artifact: string;
  /** The copy JSR actually ships; what the digest check and probe target. */
  publishedArtifact: string;
  origin: string;
  vendoredPath?: string;
  releasePending?: boolean;
  sha256: string;
  byteLength: number;
  upstream: {
    repository: string;
    tag: string;
    commit: string;
    wasmAbiVersion: number;
    releaseAsset?: { tag: string; name: string; sha256: string };
  };
  postProcessing: unknown;
  hardening?: { linearMemoryScrubVerified?: boolean };
};

/**
 * Artifact origins this gate can verify, keyed by trust model.
 *
 * `origin` is a routing key, not a credential: asserting it buys nothing on its
 * own, because each handler has to prove offline that the repository really is
 * in the model its key names. Supporting a new supply chain means adding a key
 * with a verifier, never loosening an existing one.
 */
const SUPPORTED_ORIGINS: Record<string, (lock: Lock) => Promise<void>> = {
  "vendored-submodule": verifyVendoredSubmodule,
  "github-release": verifyGithubReleaseAsset,
};

const lock = JSON.parse(
  await Deno.readTextFile(new URL("wasm.lock.json", root)),
) as Lock;

// Checked before anything else: a lock this gate does not understand cannot be
// meaningfully verified, and reading it anyway only produces misleading
// failures about fields that moved or changed meaning.
if (lock.schemaVersion !== SCHEMA_VERSION) {
  console.error(
    `Refusing to publish:\n- wasm.lock.json declares schemaVersion ` +
      `${lock.schemaVersion}, but this gate verifies schemaVersion ` +
      `${SCHEMA_VERSION}. Migrate the lock and re-read tools/check_release.ts ` +
      `before publishing.`,
  );
  Deno.exit(1);
}

const failures: string[] = [];

/** Run one gate condition; a thrown message becomes one publish blocker. */
async function gate(condition: () => Promise<void> | void): Promise<void> {
  try {
    await condition();
  } catch (error) {
    failures.push(error instanceof Error ? error.message : String(error));
  }
}

await gate(async () => {
  const verify = SUPPORTED_ORIGINS[lock.origin];
  if (verify === undefined) {
    throw new Error(
      `wasm.lock.json declares origin ${JSON.stringify(lock.origin)}, which ` +
        `this gate cannot verify. Set it to one of: ` +
        `${Object.keys(SUPPORTED_ORIGINS).join(", ")} — or add a verifier ` +
        `for the new origin in tools/check_release.ts. Do not widen the ` +
        `allowlist just to make a publish pass.`,
    );
  }
  await verify(lock);
});

await gate(() => {
  if (lock.releasePending !== false) {
    throw new Error(
      `wasm.lock.json has releasePending: true — this pin is not signed off ` +
        `for release. Review upstream.commit ${lock.upstream.commit} ` +
        `(${lock.upstream.tag}) and sha256 ${lock.sha256}, then set ` +
        `"releasePending": false in the same commit that ships them.`,
    );
  }
});

await gate(() => {
  if (lock.hardening?.linearMemoryScrubVerified !== true) {
    throw new Error(
      `wasm.lock.json does not claim hardening.linearMemoryScrubVerified. ` +
        `Resolve the scrubbing blocker upstream, confirm with ` +
        `\`deno task release:check\`, then set the flag to true.`,
    );
  }
});

// Both committed copies are checked against the same recorded digest, so they
// cannot drift from each other or from the hash a human signed off on.
await gate(() =>
  verifyArtifactDigest(lock.publishedArtifact, "`deno task artifact`")
);
await gate(() => verifyArtifactDigest(lock.artifact, "`mise run build-wasm`"));
await gate(verifyPublishedFiles);

await gate(() => verifyLinearMemoryScrubbing(lock.publishedArtifact));

if (failures.length > 0) {
  console.error(`Refusing to publish:\n- ${failures.join("\n- ")}`);
  Deno.exit(1);
}

/**
 * Assert that a committed artifact is byte-for-byte the one the lock records.
 *
 * Without this the publish path verifies nothing about the shipped binary: a
 * corrupted or stale `src/opaque.wasm` would publish cleanly, and the runtime
 * constants in `src/artifact.ts` would describe a file that no longer exists.
 */
async function verifyArtifactDigest(
  path: string,
  remedy: string,
): Promise<void> {
  let bytes: Uint8Array;
  try {
    bytes = await Deno.readFile(new URL(path, root));
  } catch {
    throw new Error(`${path} is missing; run ${remedy} to regenerate it`);
  }
  const sha256 = hex(await crypto.subtle.digest("SHA-256", bytes));
  if (bytes.byteLength !== lock.byteLength || sha256 !== lock.sha256) {
    throw new Error(
      `${path} does not match wasm.lock.json: ${bytes.byteLength} bytes, ` +
        `sha256 ${sha256}; the lock records ${lock.byteLength} bytes, ` +
        `sha256 ${lock.sha256}. Run ${remedy}, or update the lock only if ` +
        `you are deliberately shipping a rebuilt artifact.`,
    );
  }
}

/** Assert the package actually ships the artifact and lock this gate verified. */
async function verifyPublishedFiles(): Promise<void> {
  const config = JSON.parse(
    await Deno.readTextFile(new URL("deno.json", root)),
  ) as { publish?: { include?: string[] } };
  const include = config.publish?.include ?? [];
  for (const path of [lock.publishedArtifact, "wasm.lock.json"]) {
    if (!include.includes(path)) {
      throw new Error(
        `deno.json publish.include does not ship ${path}, so this gate would ` +
          `verify a file the package never publishes. Add ${path} to ` +
          `publish.include in deno.json.`,
      );
    }
  }
}

/**
 * Verify the vendored-submodule supply chain, read-only.
 *
 * Proves three things a reviewer would otherwise take on faith: the submodule
 * points at the upstream the lock names, the working checkout sits at the
 * pinned commit, and the repository itself records that commit — so a fresh
 * clone reproduces the source tree the reviewer inspected.
 *
 * It cannot prove the committed WASM was built from that source; only
 * `mise run build-wasm` with the pinned toolchain establishes that link. See
 * SECURITY.md.
 */
async function verifyVendoredSubmodule(lock: Lock): Promise<void> {
  const path = lock.vendoredPath;
  if (path === undefined) {
    throw new Error(
      `wasm.lock.json origin "vendored-submodule" requires a vendoredPath ` +
        `field naming the submodule directory.`,
    );
  }
  const declared = parseGitmodules(
    await Deno.readTextFile(new URL(".gitmodules", root)),
  ).get(path);
  if (declared === undefined) {
    throw new Error(
      `.gitmodules declares no submodule at ${path}, but wasm.lock.json says ` +
        `the artifact was built from one. Restore the submodule entry, or ` +
        `fix vendoredPath in wasm.lock.json.`,
    );
  }
  const normalize = (url: string) =>
    url.replace(/\.git$/, "").replace(/\/+$/, "");
  if (normalize(declared.url ?? "") !== normalize(lock.upstream.repository)) {
    throw new Error(
      `.gitmodules points ${path} at ${declared.url}, but wasm.lock.json ` +
        `pins ${lock.upstream.repository}. Point them at the same upstream ` +
        `before publishing.`,
    );
  }

  const head = await readHeadCommit(
    await resolveGitDir(new URL(`${path}/`, root), path),
  );
  if (head !== lock.upstream.commit) {
    throw new Error(
      `${path} is checked out at ${head}, but wasm.lock.json pins ` +
        `${lock.upstream.commit} (${lock.upstream.tag}). Run ` +
        `\`git submodule update --init --force ${path}\`; if the new commit ` +
        `is intended, rebuild with \`mise run build-wasm\` and update the lock.`,
    );
  }

  const recorded = await readIndexGitlink(await resolveGitDir(root, "."), path);
  if (recorded !== lock.upstream.commit) {
    throw new Error(
      `this repository records ${recorded} for ${path}, but wasm.lock.json ` +
        `pins ${lock.upstream.commit}, so a fresh clone would not reproduce ` +
        `the reviewed source tree. Run \`git add ${path}\` and commit the pin.`,
    );
  }
}

/**
 * Verify a downloaded upstream release asset.
 *
 * Unused today, and deliberately kept: it is what makes a release-asset flow
 * publishable without touching any other check, and it stops `github-release`
 * from becoming a free pass. The shipped artifact must be the asset itself,
 * unmodified, so no local post-processing may have run.
 */
function verifyGithubReleaseAsset(lock: Lock): Promise<void> {
  const asset = lock.upstream.releaseAsset;
  if (asset === undefined) {
    throw new Error(
      `wasm.lock.json origin "github-release" requires upstream.releaseAsset ` +
        `{ tag, name, sha256 } recording the verified asset; add it, or set ` +
        `origin to "vendored-submodule".`,
    );
  }
  if (asset.sha256 !== lock.sha256) {
    throw new Error(
      `wasm.lock.json ships sha256 ${lock.sha256} but records release asset ` +
        `${asset.name} (${asset.tag}) as ${asset.sha256}. A release-asset ` +
        `build must ship the asset unmodified.`,
    );
  }
  if (lock.postProcessing !== null) {
    throw new Error(
      `wasm.lock.json records local postProcessing for a release-asset ` +
        `origin. Set "postProcessing": null, or publish the locally built ` +
        `artifact under origin "vendored-submodule".`,
    );
  }
  return Promise.resolve();
}

/** Minimal reader for the `[submodule "…"]` sections of `.gitmodules`. */
function parseGitmodules(text: string): Map<string, Record<string, string>> {
  const sections = new Map<string, Record<string, string>>();
  let current: Record<string, string> | undefined;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    const header = line.match(/^\[submodule\s+"(.*)"\]$/);
    if (header !== null) {
      current = {};
      sections.set(header[1], current);
      continue;
    }
    if (line.startsWith("[")) {
      current = undefined;
      continue;
    }
    const pair = line.match(/^(\w+)\s*=\s*(.*)$/);
    if (pair !== null && current !== undefined) {
      current[pair[1]] = pair[2].trim();
    }
  }
  // Sections are keyed by name; git keys submodules by path, so re-index.
  return new Map(
    [...sections].map(([name, entry]) => [entry.path ?? name, entry]),
  );
}

/** Resolve a working tree's git directory, following a `gitdir:` pointer file. */
async function resolveGitDir(workdir: URL, label: string): Promise<URL> {
  const pointer = new URL(".git", workdir);
  let info: Deno.FileInfo;
  try {
    info = await Deno.stat(pointer);
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
    throw new Error(
      `${label} has no .git entry: the pinned submodule is not checked out. ` +
        `Run \`git submodule update --init ${label}\` and publish again.`,
    );
  }
  if (info.isDirectory) return new URL(".git/", workdir);
  const target = (await Deno.readTextFile(pointer))
    .match(/^gitdir:\s*(.+?)\s*$/m)?.[1];
  if (target === undefined) {
    throw new Error(
      `${label}/.git is not a gitdir pointer; repair the checkout`,
    );
  }
  const resolved = new URL(`${target.replace(/\/+$/, "")}/`, workdir);
  if (!resolved.href.startsWith(root.href)) {
    throw new Error(
      `${label} resolves its git directory to ${resolved.pathname}, outside ` +
        `the repository, which \`--allow-read=.\` cannot read (a linked ` +
        `\`git worktree\`?). Publish from the primary worktree.`,
    );
  }
  return resolved;
}

/** Resolve HEAD to a commit id, following symrefs into loose or packed refs. */
async function readHeadCommit(gitDir: URL): Promise<string> {
  let cursor = "HEAD";
  for (let hop = 0; hop < 8; hop += 1) {
    const text = await readTextIfExists(new URL(cursor, gitDir));
    if (text === undefined) {
      const packed = await readTextIfExists(new URL("packed-refs", gitDir));
      const target = packed === undefined
        ? undefined
        : lookupPackedRef(packed, cursor);
      if (target !== undefined) return target;
      throw new Error(
        `cannot resolve ${cursor} in ${gitDir.pathname}: no loose ref and no ` +
          `packed-refs entry. Re-run \`git submodule update --init --force\`.`,
      );
    }
    const value = text.trim();
    if (/^[0-9a-f]{40}$/.test(value)) return value;
    const symref = value.match(/^ref:\s*(\S+)$/);
    if (symref === null) {
      throw new Error(
        `unrecognised ref content in ${gitDir.pathname}${cursor}`,
      );
    }
    cursor = symref[1];
  }
  throw new Error(`symref chain too deep in ${gitDir.pathname}`);
}

function lookupPackedRef(packed: string, refName: string): string | undefined {
  for (const line of packed.split("\n")) {
    if (line === "" || line.startsWith("#") || line.startsWith("^")) continue;
    if (line.indexOf(" ") === 40 && line.slice(41) === refName) {
      return line.slice(0, 40);
    }
  }
  return undefined;
}

/**
 * Read the commit a repository records for a gitlink path, from `.git/index`.
 *
 * This is what a fresh clone would check out, which HEAD alone cannot tell us:
 * a locally moved submodule leaves the recorded pin untouched, and a staged one
 * moves the pin without moving HEAD. Anything this parser does not fully
 * understand is an error, never a skipped check.
 */
async function readIndexGitlink(gitDir: URL, path: string): Promise<string> {
  const index = await Deno.readFile(new URL("index", gitDir));
  const view = new DataView(index.buffer, index.byteOffset, index.byteLength);
  if (new TextDecoder().decode(index.subarray(0, 4)) !== "DIRC") {
    throw new Error(`${gitDir.pathname}index is not a git index file`);
  }
  const version = view.getUint32(4);
  if (version !== 2 && version !== 3) {
    throw new Error(
      `this gate cannot read git index version ${version} (v4 path ` +
        `compression or a split index), so it cannot confirm the recorded ` +
        `submodule commit. Run \`git update-index --index-version 2\` (and ` +
        `unset \`feature.manyFiles\`/\`index.version\`) before publishing.`,
    );
  }
  const wanted = new TextEncoder().encode(path);
  let at = 12;
  for (let remaining = view.getUint32(8); remaining > 0; remaining -= 1) {
    const start = at;
    const mode = view.getUint32(start + 24);
    const flags = view.getUint16(start + 60);
    let nameAt = start + 62;
    if (version >= 3 && (flags & 0x4000) !== 0) nameAt += 2;
    const declared = flags & 0x0fff;
    const nameEnd = declared < 0x0fff
      ? nameAt + declared
      : index.indexOf(0, nameAt);
    if (nameEnd < 0) throw new Error("truncated git index entry");
    const name = index.subarray(nameAt, nameEnd);
    at = start + Math.ceil((nameEnd - start + 1) / 8) * 8;
    if (name.length !== wanted.length) continue;
    if (!name.every((byte, position) => byte === wanted[position])) continue;
    if (mode !== 0o160000) {
      throw new Error(
        `${path} is recorded with mode ${mode.toString(8)}, not a submodule ` +
          `gitlink; restore it with \`git submodule update --init\`.`,
      );
    }
    return hex(index.subarray(start + 40, start + 60));
  }
  throw new Error(
    `${path} has no entry in ${gitDir.pathname}index, so this repository ` +
      `does not record a pinned commit for it. Run \`git add ${path}\`.`,
  );
}

async function readTextIfExists(url: URL): Promise<string | undefined> {
  try {
    return await Deno.readTextFile(url);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return undefined;
    throw error;
  }
}

function hex(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
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
  const bytes = await Deno.readFile(new URL(artifact, root));
  const module = await WebAssembly.compile(bytes);
  const instance = await WebAssembly.instantiate(module);
  const memory = (instance.exports as { memory: WebAssembly.Memory }).memory;
  const wasm = new OpaqueWasm(instance);
  wasm.assertVersion(lock.upstream.wasmAbiVersion);
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
