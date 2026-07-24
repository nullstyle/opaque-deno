import AuthPanel from "../islands/AuthPanel.tsx";
import { define } from "../utils.ts";

export const handler = define.handlers({
  GET(ctx) {
    if (ctx.state.session === null) {
      return new Response(null, {
        status: 303,
        headers: { location: "/" },
      });
    }
    return { data: undefined };
  },
});

export default define.page(function Protected(ctx) {
  const session = ctx.state.session!;

  return (
    <main class="page-shell">
      <header class="brand-bar">
        <a class="brand" href="/" aria-label="Opaque Access home">
          <span class="brand-mark" aria-hidden="true">O</span>
          <span>Opaque Access</span>
        </a>
        <span class="environment-label authenticated-label">Authenticated</span>
      </header>

      <section class="protected-layout" aria-labelledby="protected-title">
        <div class="success-mark" aria-hidden="true">OK</div>
        <p class="eyebrow">Session verified</p>
        <h1 id="protected-title">Protected session</h1>
        <p class="protected-copy">
          Signed in as <strong>{session.subject}</strong>
        </p>
        <AuthPanel authenticated subject={session.subject} />
      </section>
    </main>
  );
});
