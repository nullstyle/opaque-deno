// Deno fetch intentionally has no browser cookie jar. Install the smallest
// same-origin jar needed by this integration test, then run the real client
// worker unchanged.
const nativeFetch = globalThis.fetch.bind(globalThis);
let cookie: string | undefined;
let cookieOrigin: string | undefined;
const queuedMessages: MessageEvent[] = [];
const workerScope = globalThis as unknown as {
  onmessage: ((event: MessageEvent) => void | Promise<void>) | null;
};

workerScope.onmessage = (event): void => {
  queuedMessages.push(event);
};

globalThis.fetch = async (
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> => {
  const request = new Request(input, init);
  const origin = new URL(request.url).origin;
  const headers = new Headers(request.headers);
  if (cookie && cookieOrigin === origin) headers.set("cookie", cookie);

  const response = await nativeFetch(new Request(request, { headers }));
  const setCookie = response.headers.get("set-cookie");
  if (setCookie) {
    const pair = setCookie.split(";", 1)[0];
    cookie = pair.endsWith("=") ? undefined : pair;
    cookieOrigin = cookie ? origin : undefined;
  }
  return response;
};

await import("../../src/worker.ts");

const handleMessage = workerScope.onmessage;
if (!handleMessage) throw new Error("OPAQUE worker did not install a handler");
for (const event of queuedMessages) await handleMessage(event);
