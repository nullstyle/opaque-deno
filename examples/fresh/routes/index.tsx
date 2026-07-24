import AuthPanel from "../islands/AuthPanel.tsx";
import { define } from "../utils.ts";

export default define.page(function Home(ctx) {
  const session = ctx.state.session;
  return (
    <main class="page-shell">
      <header class="brand-bar">
        <a class="brand" href="/" aria-label="Opaque Access home">
          <span class="brand-mark" aria-hidden="true">O</span>
          <span>Opaque Access</span>
        </a>
        <span class="environment-label">Fresh example</span>
      </header>

      <section class="auth-layout" aria-labelledby="auth-title">
        <div class="intro">
          <p class="eyebrow">Private by design</p>
          <h1 id="auth-title">Password auth without password exposure.</h1>
          <p class="intro-copy">
            A working OPAQUE ceremony backed by revocable PASETO sessions.
          </p>
          <div class="protocol-strip" aria-label="Authentication protocol">
            <span>OPAQUE</span>
            <span class="protocol-line" aria-hidden="true" />
            <span>PASETO v4.local</span>
          </div>
        </div>

        <AuthPanel
          authenticated={session !== null}
          subject={session?.subject}
        />
      </section>
    </main>
  );
});
