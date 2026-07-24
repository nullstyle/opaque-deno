import { chromium, type Locator, type Page } from "playwright";

const fixtureDirectory = decodeURIComponent(
  new URL("../", import.meta.url).pathname,
);

Deno.test({
  name: "Fresh runs OPAQUE in a browser worker and protects a PASETO session",
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    await buildFixture();
    const port = reservePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    const server = new Deno.Command(Deno.execPath(), {
      cwd: fixtureDirectory,
      args: ["serve", "-A", "--port", String(port), "_fresh/server.js"],
      stdout: "null",
      stderr: "piped",
    }).spawn();
    const serverErrors = new Response(server.stderr).text();
    let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;

    try {
      await waitForServer(baseUrl, server.status);
      browser = await chromium.launch({ headless: true });
      const context = await browser.newContext();
      const page = await context.newPage();
      page.setDefaultTimeout(120_000);

      const pageErrors: string[] = [];
      const browserEvents: string[] = [];
      let wasmResponse:
        | { url: string; contentType: string | undefined }
        | undefined;
      page.on("pageerror", (error) => pageErrors.push(error.message));
      page.on("worker", (worker) => {
        browserEvents.push(`worker ${worker.url()}`);
      });
      page.on("requestfailed", (request) => {
        browserEvents.push(
          `failed ${request.url()} ${
            request.failure()?.errorText ?? "unknown"
          }`,
        );
      });
      page.on("response", (response) => {
        if (response.url().includes("/api/auth/")) {
          browserEvents.push(`${response.status()} ${response.url()}`);
        }
        if (
          response.url().includes("/api/auth/opaque.") &&
          response.url().endsWith(".wasm")
        ) {
          wasmResponse = {
            url: response.url(),
            contentType: response.headers()["content-type"],
          };
        }
      });

      await page.goto(baseUrl);
      await assertVisibleText(page.getByRole("heading", {
        name: "Password auth without password exposure.",
      }));

      await fillCredentials(page, "reader@example.test", "not-the-password");
      await page.getByRole("button", { name: "Sign in", exact: true }).last()
        .click();
      await assertVisibleText(
        page.getByRole("alert"),
        "Wrong identifier or password.",
        () => diagnostic(browserEvents, pageErrors),
      );

      await page.getByRole("button", { name: "Register", exact: true }).click();
      await fillCredentials(
        page,
        "reader@example.test",
        "correct horse battery staple",
      );
      await page.getByRole("button", { name: "Create account" }).click();
      await assertVisibleText(
        page.getByText("Registration complete. Sign in to continue."),
      );

      await fillCredentials(
        page,
        "reader@example.test",
        "still-wrong-password",
      );
      await page.getByRole("button", { name: "Sign in", exact: true }).last()
        .click();
      await assertVisibleText(
        page.getByRole("alert"),
        "Wrong identifier or password.",
        () => diagnostic(browserEvents, pageErrors),
      );

      await fillCredentials(
        page,
        "reader@example.test",
        "correct horse battery staple",
      );
      await page.getByRole("button", { name: "Sign in", exact: true }).last()
        .click();
      await page.waitForURL(`${baseUrl}/protected`);
      await assertVisibleText(
        page.getByRole("heading", { name: "Protected session" }),
      );

      assert(wasmResponse !== undefined, "browser did not request OPAQUE WASM");
      assert(
        wasmResponse.contentType === "application/wasm",
        `unexpected WASM content type: ${wasmResponse.contentType}`,
      );

      await page.getByRole("button", { name: "Sign out" }).click();
      await page.waitForURL(baseUrl + "/");
      await page.goto(`${baseUrl}/protected`);
      await page.waitForURL(baseUrl + "/");
      assert(
        pageErrors.length === 0,
        `browser emitted errors: ${pageErrors.join("; ")}`,
      );
    } finally {
      await browser?.close();
      try {
        server.kill("SIGTERM");
      } catch {
        // The child may already have exited after a startup failure.
      }
      const status = await server.status;
      const errors = await serverErrors;
      if (!status.success && status.signal !== "SIGTERM" && errors.length > 0) {
        console.error(errors);
      }
    }
  },
});

async function fillCredentials(
  page: Page,
  identifier: string,
  password: string,
): Promise<void> {
  await page.getByLabel("Email or username").fill(identifier);
  await page.getByLabel("Password", { exact: true }).fill(password);
}

async function assertVisibleText(
  locator: Locator,
  text?: string,
  failureDetail?: () => string,
): Promise<void> {
  try {
    await locator.waitFor({ state: "visible", timeout: 30_000 });
  } catch (cause) {
    throw new Error(
      `expected visible browser content; ${
        failureDetail?.() ?? "no diagnostics"
      }`,
      { cause },
    );
  }
  if (text !== undefined) {
    const actual = (await locator.textContent())?.trim();
    assert(
      actual === text,
      `expected ${JSON.stringify(text)}, got ${JSON.stringify(actual)}`,
    );
  }
}

function diagnostic(events: string[], errors: string[]): string {
  return `events=[${events.join("; ")}], errors=[${errors.join("; ")}]`;
}

async function buildFixture(): Promise<void> {
  const command = new Deno.Command(Deno.execPath(), {
    cwd: fixtureDirectory,
    args: ["task", "build"],
    stdout: "piped",
    stderr: "piped",
  });
  const output = await command.output();
  if (!output.success) {
    throw new Error(
      `Fresh build failed:\n${new TextDecoder().decode(output.stdout)}\n${
        new TextDecoder().decode(output.stderr)
      }`,
    );
  }
}

function reservePort(): number {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (listener.addr as Deno.NetAddr).port;
  listener.close();
  return port;
}

async function waitForServer(
  baseUrl: string,
  status: Promise<Deno.CommandStatus>,
): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const ready = await Promise.race([
      fetch(baseUrl).then((response) => response.ok).catch(() => false),
      status.then(() => false),
    ]);
    if (ready) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Fresh server did not become ready");
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}
