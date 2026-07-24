import type {
  LoginAttempt,
  OpaqueAuthStore,
  OpaqueCredential,
  RegistrationAttempt,
} from "./types.ts";

/** In-memory development store. Do not use it for production credentials. */
export class MemoryOpaqueStore implements OpaqueAuthStore {
  readonly #credentials = new Map<string, OpaqueCredential>();
  readonly #registrations = new Map<string, RegistrationAttempt>();
  readonly #logins = new Map<string, LoginAttempt>();

  /** Look up a cloned in-memory credential. */
  getCredential(identifier: string): Promise<OpaqueCredential | null> {
    return Promise.resolve(
      cloneCredential(this.#credentials.get(identifier) ?? null),
    );
  }

  /** Create a credential unless its identifier already exists. */
  createCredential(credential: OpaqueCredential): Promise<boolean> {
    if (this.#credentials.has(credential.identifier)) {
      return Promise.resolve(false);
    }
    this.#credentials.set(credential.identifier, cloneCredential(credential)!);
    return Promise.resolve(true);
  }

  /** Store a cloned registration attempt. */
  putRegistrationAttempt(attempt: RegistrationAttempt): Promise<void> {
    this.#registrations.set(attempt.id, cloneRegistration(attempt));
    return Promise.resolve();
  }

  /** Take and delete one registration attempt. */
  takeRegistrationAttempt(id: string): Promise<RegistrationAttempt | null> {
    const value = this.#registrations.get(id);
    this.#registrations.delete(id);
    return Promise.resolve(value ? cloneRegistration(value) : null);
  }

  /** Store a cloned login attempt. */
  putLoginAttempt(attempt: LoginAttempt): Promise<void> {
    this.#logins.set(attempt.id, cloneLogin(attempt));
    return Promise.resolve();
  }

  /** Take, delete, and clone one login attempt. */
  takeLoginAttempt(id: string): Promise<LoginAttempt | null> {
    const value = this.#logins.get(id);
    this.#logins.delete(id);
    return Promise.resolve(value ? cloneLogin(value) : null);
  }
}

function cloneCredential(
  value: OpaqueCredential | null,
): OpaqueCredential | null {
  return value && {
    ...value,
    credentialIdentifier: value.credentialIdentifier.slice(),
    registrationRecord: value.registrationRecord.slice(),
    createdAt: new Date(value.createdAt),
    updatedAt: new Date(value.updatedAt),
  };
}

function cloneRegistration(value: RegistrationAttempt): RegistrationAttempt {
  return {
    ...value,
    credentialIdentifier: value.credentialIdentifier.slice(),
    expiresAt: new Date(value.expiresAt),
  };
}

function cloneLogin(value: LoginAttempt): LoginAttempt {
  return {
    ...value,
    serverLoginState: value.serverLoginState.slice(),
    expiresAt: new Date(value.expiresAt),
  };
}
