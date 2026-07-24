import {
  createOpaqueClient,
  OpaqueAuthenticationError,
} from "@nullstyle/opaque/client";
import { useEffect, useMemo, useState } from "preact/hooks";
import { AUTH_CONTEXT } from "../auth_context.ts";

interface AuthPanelProps {
  authenticated: boolean;
  subject?: string;
}

type Mode = "login" | "register";

export default function AuthPanel(props: AuthPanelProps) {
  const [mode, setMode] = useState<Mode>("login");
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const client = useMemo(
    () => createOpaqueClient({ context: AUTH_CONTEXT }),
    [],
  );

  useEffect(() => () => client.dispose(), [client]);

  async function authenticate(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (pending) return;
    setPending(true);
    setMessage("");
    setError("");
    try {
      const result = mode === "register"
        ? await client.register(identifier, password)
        : await client.login(identifier, password);
      result.exportKey.fill(0);
      setPassword("");
      if (mode === "register") {
        setMode("login");
        setMessage("Registration complete. Sign in to continue.");
      } else {
        location.assign("/protected");
      }
    } catch (cause) {
      setError(
        cause instanceof OpaqueAuthenticationError
          ? "Wrong identifier or password."
          : cause instanceof Error
          ? cause.message
          : "Authentication failed.",
      );
    } finally {
      setPending(false);
    }
  }

  async function logout(): Promise<void> {
    if (pending) return;
    setPending(true);
    setError("");
    try {
      await client.logout();
      location.assign("/");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Logout failed.");
      setPending(false);
    }
  }

  if (props.authenticated) {
    return (
      <div class="session-actions">
        <a class="button secondary-button" href="/protected">
          Open protected page
        </a>
        <button
          class="button danger-button"
          type="button"
          disabled={pending}
          onClick={logout}
        >
          {pending ? "Signing out..." : "Sign out"}
        </button>
        {props.subject && <span class="sr-only">{props.subject}</span>}
        {error && <p class="form-error" role="alert">{error}</p>}
      </div>
    );
  }

  return (
    <div class="auth-card">
      <div class="mode-switch" aria-label="Authentication mode">
        <button
          type="button"
          aria-pressed={mode === "login"}
          onClick={() => {
            setMode("login");
            setError("");
            setMessage("");
          }}
        >
          Sign in
        </button>
        <button
          type="button"
          aria-pressed={mode === "register"}
          onClick={() => {
            setMode("register");
            setError("");
            setMessage("");
          }}
        >
          Register
        </button>
      </div>

      <form onSubmit={authenticate}>
        <label for="identifier">Email or username</label>
        <input
          id="identifier"
          name="identifier"
          type="text"
          autocomplete="username"
          required
          value={identifier}
          onInput={(event) => setIdentifier(event.currentTarget.value)}
        />

        <label for="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autocomplete={mode === "register"
            ? "new-password"
            : "current-password"}
          minlength={8}
          required
          value={password}
          onInput={(event) => setPassword(event.currentTarget.value)}
        />

        <button class="button primary-button" type="submit" disabled={pending}>
          {pending
            ? mode === "register" ? "Registering..." : "Signing in..."
            : mode === "register"
            ? "Create account"
            : "Sign in"}
        </button>
      </form>

      <div class="status-region" aria-live="polite">
        {message && <p class="form-message">{message}</p>}
        {error && <p class="form-error" role="alert">{error}</p>}
      </div>
    </div>
  );
}
