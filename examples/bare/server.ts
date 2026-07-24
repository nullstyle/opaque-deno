import { createBareApp } from "./app.ts";

const app = await createBareApp();
const server = Deno.serve(
  { hostname: "127.0.0.1", port: 8000 },
  app.handler,
);

try {
  await server.finished;
} finally {
  app.dispose();
}
