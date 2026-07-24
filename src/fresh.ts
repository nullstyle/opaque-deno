import type { OpaqueAuthServer } from "./server.ts";
import type { AuthenticatedSession, WebSessionProvider } from "./types.ts";

/** Minimal structural subset of a Fresh middleware context. */
export interface FreshLikeContext<State = Record<string, unknown>> {
  /** Incoming web-standard request. */
  req: Request;
  /** Application-defined per-request state. */
  state: State;
  /** Continue to the next Fresh middleware or route. */
  next(): Response | Promise<Response>;
}

/** Adapt an OPAQUE server to Fresh's web-standard middleware contract. */
export function createOpaqueFreshMiddleware<State = Record<string, unknown>>(
  auth: OpaqueAuthServer,
): (context: FreshLikeContext<State>) => Promise<Response> {
  return async (context) =>
    await auth.route(context.req) ?? await context.next();
}

/** Authenticate a session and place it in Fresh state before continuing. */
export function createSessionFreshMiddleware<
  State extends Record<string, unknown>,
>(
  provider: WebSessionProvider,
  stateKey = "session",
): (context: FreshLikeContext<State>) => Promise<Response> {
  return async (context) => {
    (context.state as Record<string, unknown>)[stateKey] = await provider
      .authenticate(context.req) as
        | AuthenticatedSession
        | null;
    return await context.next();
  };
}
