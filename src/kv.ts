import type {
  LoginAttempt,
  OpaqueAuthStore,
  OpaqueCredential,
  RegistrationAttempt,
} from "./types.ts";

/** Deno KV-backed credential and single-use attempt store. Requires `--unstable-kv`. */
export class DenoKvOpaqueStore implements OpaqueAuthStore {
  readonly #kv: Deno.Kv;
  readonly #prefix: Deno.KvKey;

  /** Create a store using an injected KV database and optional key prefix. */
  constructor(kv: Deno.Kv, options: { prefix?: Deno.KvKey } = {}) {
    this.#kv = kv;
    this.#prefix = [...(options.prefix ?? ["opaque"])] as Deno.KvKey;
  }

  /** Look up a stored credential. */
  async getCredential(identifier: string): Promise<OpaqueCredential | null> {
    const entry = await this.#kv.get<SerializedCredential>(
      this.#key("credential", identifier),
    );
    return entry.value ? deserializeCredential(entry.value) : null;
  }

  /** Atomically create a credential unless its identifier already exists. */
  async createCredential(credential: OpaqueCredential): Promise<boolean> {
    const key = this.#key("credential", credential.identifier);
    const existing = await this.#kv.get(key);
    if (existing.value !== null) return false;
    const result = await this.#kv.atomic().check(existing).set(
      key,
      serializeCredential(credential),
    ).commit();
    return result.ok;
  }

  /** Store a registration attempt with native KV expiry. */
  async putRegistrationAttempt(attempt: RegistrationAttempt): Promise<void> {
    await this.#kv.set(
      this.#key("registration", attempt.id),
      serializeRegistration(attempt),
      {
        expireIn: expireIn(attempt.expiresAt),
      },
    );
  }

  /** Atomically take and delete a registration attempt. */
  takeRegistrationAttempt(id: string): Promise<RegistrationAttempt | null> {
    return this.#take<SerializedRegistration, RegistrationAttempt>(
      this.#key("registration", id),
      deserializeRegistration,
    );
  }

  /** Store a login attempt with native KV expiry. */
  async putLoginAttempt(attempt: LoginAttempt): Promise<void> {
    await this.#kv.set(
      this.#key("login", attempt.id),
      serializeLogin(attempt),
      {
        expireIn: expireIn(attempt.expiresAt),
      },
    );
  }

  /** Atomically take and delete a login attempt. */
  takeLoginAttempt(id: string): Promise<LoginAttempt | null> {
    return this.#take<SerializedLogin, LoginAttempt>(
      this.#key("login", id),
      deserializeLogin,
    );
  }

  async #take<S, T>(
    key: Deno.KvKey,
    decode: (value: S) => T,
  ): Promise<T | null> {
    for (;;) {
      const entry = await this.#kv.get<S>(key);
      if (entry.value === null) return null;
      const result = await this.#kv.atomic().check(entry).delete(key).commit();
      if (result.ok) return decode(entry.value);
    }
  }

  #key(kind: string, value: string): Deno.KvKey {
    return [...this.#prefix, kind, value] as Deno.KvKey;
  }
}

interface SerializedCredential {
  identifier: string;
  subject: string;
  credentialIdentifier: Uint8Array;
  registrationRecord: Uint8Array;
  createdAt: number;
  updatedAt: number;
}
interface SerializedRegistration {
  id: string;
  identifier: string;
  subject: string;
  credentialIdentifier: Uint8Array;
  expiresAt: number;
}
interface SerializedLogin {
  id: string;
  identifier: string;
  subject: string | null;
  serverLoginState: Uint8Array;
  expiresAt: number;
}

function serializeCredential(value: OpaqueCredential): SerializedCredential {
  return {
    ...value,
    createdAt: value.createdAt.getTime(),
    updatedAt: value.updatedAt.getTime(),
  };
}
function deserializeCredential(value: SerializedCredential): OpaqueCredential {
  return {
    ...value,
    createdAt: new Date(value.createdAt),
    updatedAt: new Date(value.updatedAt),
  };
}
function serializeRegistration(
  value: RegistrationAttempt,
): SerializedRegistration {
  return { ...value, expiresAt: value.expiresAt.getTime() };
}
function deserializeRegistration(
  value: SerializedRegistration,
): RegistrationAttempt {
  return { ...value, expiresAt: new Date(value.expiresAt) };
}
function serializeLogin(value: LoginAttempt): SerializedLogin {
  return { ...value, expiresAt: value.expiresAt.getTime() };
}
function deserializeLogin(value: SerializedLogin): LoginAttempt {
  return { ...value, expiresAt: new Date(value.expiresAt) };
}
function expireIn(expiresAt: Date): number {
  return Math.max(1, expiresAt.getTime() - Date.now());
}
