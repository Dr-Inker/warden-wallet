//! Browser-only C22 content entry. Never copied into the product extension.

import { ProviderContentTransportOwner } from "../src/content/provider-content-transport.js";
import type { ContentRuntimeApi, ContentWindowApi } from "../src/content/bridge.js";

const chromeApi = (globalThis as unknown as {
  readonly chrome: { readonly runtime: ContentRuntimeApi };
}).chrome;

const owner = new ProviderContentTransportOwner(
  window as unknown as ContentWindowApi,
  chromeApi.runtime,
);

addEventListener("message", (event) => {
  if (
    event.source !== window ||
    event.origin !== location.origin ||
    typeof event.data !== "object" ||
    event.data === null ||
    (event.data as { readonly type?: unknown }).type !==
      "warden:test:content-status-request"
  ) {
    return;
  }
  const nonce = (event.data as { readonly nonce?: unknown }).nonce;
  if (typeof nonce !== "string") return;
  postMessage({
    type: "warden:test:content-status-response",
    nonce,
    pendingCount: owner.pendingCount,
  }, location.origin);
});

Object.assign(globalThis, {
  // Keep a browser-test inspection anchor without exposing it to page JS.
  __wardenProviderContentTransport: owner,
});
