/**
 * A stored OPAQUE credential.
 *
 * Store methods must copy byte fields before resolving. Values returned from
 * lookups are caller-owned copies so authentication code can wipe them.
 */
export interface OpaqueCredential {
  /** Canonical application identifier. */
  identifier: string;
  /** Stable application account subject. */
  subject: string;
  /** Exact bytes used as the OPAQUE credential identifier. */
  credentialIdentifier: Uint8Array;
  /** Serialized OPAQUE registration record. */
  registrationRecord: Uint8Array;
  /** Credential creation time. */
  createdAt: Date;
  /** Credential update time. */
  updatedAt: Date;
}

/** State binding one registration finish call to its authorized start call. */
export interface RegistrationAttempt {
  /** Opaque single-use attempt identifier. */
  id: string;
  /** Canonical application identifier. */
  identifier: string;
  /** Authorized application account subject. */
  subject: string;
  /** Exact bytes used as the OPAQUE credential identifier. */
  credentialIdentifier: Uint8Array;
  /** Time after which this attempt must be rejected. */
  expiresAt: Date;
}

/** Secret state binding one login finish call to its start call. */
export interface LoginAttempt {
  /** Opaque single-use attempt identifier. */
  id: string;
  /** Canonical application identifier. */
  identifier: string;
  /** Account subject, or null for an anti-enumeration fake record. */
  subject: string | null;
  /** Secret OPAQUE server state that must be wiped after consumption. */
  serverLoginState: Uint8Array;
  /** Time after which this attempt must be rejected. */
  expiresAt: Date;
}

/** Persistence contract for credentials and single-use protocol attempts. */
export interface OpaqueAuthStore {
  /** Look up a credential, returning caller-owned byte-array copies. */
  getCredential(identifier: string): Promise<OpaqueCredential | null>;
  /** Atomically create a credential and copy its bytes before resolving. */
  createCredential(credential: OpaqueCredential): Promise<boolean>;
  /** Persist a copied pending registration attempt until its expiry. */
  putRegistrationAttempt(attempt: RegistrationAttempt): Promise<void>;
  /** Atomically take and delete one attempt, returning caller-owned bytes. */
  takeRegistrationAttempt(id: string): Promise<RegistrationAttempt | null>;
  /** Persist a copied pending login attempt until its expiry. */
  putLoginAttempt(attempt: LoginAttempt): Promise<void>;
  /** Atomically take and delete one attempt, returning caller-owned bytes. */
  takeLoginAttempt(id: string): Promise<LoginAttempt | null>;
}

/** The authenticated session shape shared structurally with session packages. */
export interface AuthenticatedSession {
  /** Stable application account subject. */
  subject: string;
  /** Unique web-session identifier. */
  sessionId: string;
  /** Session issue time. */
  issuedAt: Date;
  /** Session expiry time. */
  expiresAt: Date;
}

/** Cookie mutation returned by a session provider. */
export interface SessionMutation {
  /** Complete Set-Cookie header value to send to the browser. */
  setCookie: string;
  /** Newly created session, when applicable. */
  session?: AuthenticatedSession;
}

/** Session-provider-neutral contract consumed by OPAQUE HTTP handlers. */
export interface WebSessionProvider {
  /** Create a session for an authenticated subject. */
  create(subject: string, request: Request): Promise<SessionMutation>;
  /** Authenticate the session carried by a request. */
  authenticate(request: Request): Promise<AuthenticatedSession | null>;
  /** Revoke the request's session and return a cookie-clearing mutation. */
  destroy(request: Request): Promise<SessionMutation>;
}

/** Inputs passed to an application's registration authorization hook. */
export interface RegistrationAuthorizationInput {
  /** Canonical identifier requested by the client. */
  identifier: string;
  /** Original web request for invitation or policy checks. */
  request: Request;
}

/** Return the application subject to authorize registration, or null to deny it. */
export type AuthorizeRegistration = (
  input: RegistrationAuthorizationInput,
) => Promise<{ subject: string } | null> | { subject: string } | null;

/** Explicitly marks a transient persistence failure for HTTP 503 mapping. */
export class OpaqueStorageUnavailableError extends Error {
  /** Mark a persistence error as transient service unavailability. */
  constructor(
    message = "OPAQUE storage is unavailable",
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "OpaqueStorageUnavailableError";
  }
}

/** Open registration assigns an opaque UUID subject to every new identifier. */
export function allowOpenRegistration(): AuthorizeRegistration {
  return () => ({ subject: crypto.randomUUID() });
}
