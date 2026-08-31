//! Browser-only raw-Port driver for C21 overlap ordering. Never shipped.

import { PROVIDER_PORT_NAME } from "../src/background/provider-port.js";

interface BrowserPort {
  readonly onMessage: {
    addListener(listener: (message: unknown) => void): void;
  };
  readonly onDisconnect: {
    addListener(listener: () => void): void;
  };
  postMessage(message: unknown): void;
}

interface BrowserRuntime {
  connect(options: { readonly name: string }): BrowserPort;
}

const runtime = (globalThis as unknown as {
  readonly chrome: { readonly runtime: BrowserRuntime };
}).chrome.runtime;
const pageOrigin = location.origin;
let nextPortIndex = 0;

addEventListener("message", (event) => {
  if (
    event.source !== window ||
    event.origin !== pageOrigin ||
    typeof event.data !== "object" ||
    event.data === null ||
    (event.data as { readonly type?: unknown }).type !== "warden:test:open-port"
  ) {
    return;
  }
  const request = (event.data as { readonly request?: unknown }).request;
  const index = nextPortIndex++;
  const port = runtime.connect({ name: PROVIDER_PORT_NAME });
  port.onMessage.addListener((message) => {
    postMessage({
      type: "warden:test:port-message",
      index,
      payload: message,
    }, pageOrigin);
  });
  port.onDisconnect.addListener(() => {
    postMessage({ type: "warden:test:port-disconnect", index }, pageOrigin);
  });
  port.postMessage(request);
  postMessage({ type: "warden:test:port-opened", index }, pageOrigin);
});
