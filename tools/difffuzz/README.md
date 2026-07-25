# Differential fuzzing

Cross-checks the OPAQUE implementation this package ships (`src/opaque.wasm`,
built from `opaque-zig`) against an independent one
([`github.com/bytemare/opaque`](https://github.com/bytemare/opaque)).

Both sides run the same protocol with the same injected randomness, so every
protocol message and the `exportKey` must agree byte-for-byte. The point is that
**neither side gets to define what "correct" means**: a self-test can only
confirm the implementation agrees with itself, while a divergence here is a real
bug in one of the two. This is the check most likely to find a protocol-level
error that reading the code does not.

## Running it

```bash
deno task difffuzz:build
```

```bash
deno task difffuzz --cases 500
```

It is deliberately **not** part of `deno task ci`: it needs a Go toolchain and a
built oracle binary, neither of which a TypeScript contributor should have to
install. Run it when changing the WASM pin, and periodically at volume.

Every case is a pure function of `(seed, index)`, so any failure replays
exactly:

```bash
deno task difffuzz --seed 1 --only 2 --verbose
```

## Prove it can fail, first

```bash
deno task difffuzz --selftest
```

A comparison that has never failed is not evidence. `--selftest` injects five
deliberate divergences and asserts each moves **exactly** the fields the
protocol says it must — so the harness fails both when it goes blind and when a
change diverges more widely than it should:

| control      | must diverge in             | why it is that set                                                                                                                                                                                           |
| ------------ | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ksf`        | record, exportKey           | the KSF runs on the OPRF output at finalize, so it cannot move earlier messages. This is what proves both sides really run Argon2id with the same parameters rather than agreeing for some unrelated reason. |
| `identity`   | record                      | the client identity is authenticated by the envelope tag but is not an input to the exportKey.                                                                                                               |
| `credential` | response, record, exportKey | the credential identifier selects the per-client OPRF key; the request is client-side and cannot move.                                                                                                       |
| `blind`      | request, response           | unblinding cancels the blind exactly. A record divergence here would mean the blind was leaking into the output.                                                                                             |
| `context`    | _nothing_                   | the context binds the AKE transcript, not the registration envelope (RFC 9807).                                                                                                                              |

It also runs three login controls, each of which must make cross-execution fail:
a flipped bit in KE2 (the client's MAC check), a flipped bit in KE3 (the
server's MAC check), and a password that was never registered. Without these,
"the session keys matched" could pass vacuously — two absent keys compare equal.

## What it covers

**Registration**, compared byte-for-byte: OPRF blind/evaluate/finalize, the KSF,
the envelope (masking key and auth tag), identity binding, and the `exportKey` —
against the exact `src/opaque.wasm` this package publishes, with the shipped
Argon2id parameters.

**Login (AKE)**, cross-executed in both directions — opaque-zig's client against
the oracle's server, and the oracle's client against opaque-zig's server. Each
run asserts that both sides derive the **same session key**, that the login
`exportKey` equals the one registration produced, and that each side accepts the
other's final message. This is where the context, the transcript and the MACs
are actually exercised.

KE1 is additionally compared byte-for-byte, because opaque-zig's client state is
`blind || ephemeral AKE key || ke1`, so both secrets can be lifted out and
injected into the oracle.

KE2 deliberately is **not**. opaque-zig derives the server's ephemeral key from
a seed internally and never exposes the scalar, and reimplementing that
derivation here would mean testing an implementation against a reimplementation
of itself — a bug in the copy would either mask a real divergence or invent a
false one. Cross-execution keeps the oracle independent.

Accept/reject disagreements are compared too, not skipped: two conformant
implementations should not differ on which inputs are valid.

## Known differences

Asserted rather than ignored — a run fails if one stops holding or a new one
appears:

- **Empty context.** `opaque-zig` rejects it (this package makes domain
  separation mandatory); `bytemare` permits it. A deliberate strictness
  difference, not a defect.
- **All-zero AKE nonces.** `bytemare`'s deserializer rejects a KE1/KE2 carrying
  an all-zero nonce as malformed; `opaque-zig` accepts whatever nonce the caller
  supplies. Defense in depth on one side rather than a defect on the other — a
  real caller uses a CSPRNG, and this package always does. The generator
  therefore keeps AKE nonces uniformly random, so cases exercise the protocol
  rather than re-testing this one difference.

## Not covered yet

- **Malformed and adversarial messages** — currently every case is a well-formed
  transcript. The login controls tamper with KE2 and KE3, but only to prove the
  MAC checks fire; systematic fuzzing of invalid group elements, low-order
  points and truncated framing still belongs here.
- **Byte-exact KE2**, for the reason given above. The session-key agreement
  covers the same ground semantically, but a divergence would be localised less
  precisely.
- Anything about timing or memory: see the secret-residue probe in
  `tools/check_release.ts`.

## A note on findings

The first divergence this harness reported was a bug in the harness: the oracle
passed an empty Go slice where `nil` means "no identity", so `bytemare` skipped
the RFC 9807 rule that substitutes the server public key. Both implementations
were correct. Chase a divergence to ground truth before believing it — and note
that the finding was still useful, because reaching that conclusion required
proving both sides implement the substitution rule identically.
