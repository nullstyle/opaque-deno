import { define } from "../utils.ts";

export default define.page(function AppShell({ Component }) {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="theme-color" content="#0d3833" />
        <title>Opaque Access</title>
      </head>
      <body>
        <Component />
      </body>
    </html>
  );
});
