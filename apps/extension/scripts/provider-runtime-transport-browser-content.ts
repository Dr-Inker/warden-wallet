//! Browser-only C21 content entry. Never copied into the product extension.

import { ProviderContentTransportOwner } from "../src/content/provider-content-transport.js";
import type { ContentRuntimeApi, ContentWindowApi } from "../src/content/bridge.js";

const chromeApi = (globalThis as unknown as {
  readonly chrome: { readonly runtime: ContentRuntimeApi };
}).chrome;

const owner = new ProviderContentTransportOwner(
  window as unknown as ContentWindowApi,
  chromeApi.runtime,
);

Object.assign(globalThis, {
  // Keep a browser-test inspection anchor without exposing it to page JS.
  __wardenProviderContentTransport: owner,
});
