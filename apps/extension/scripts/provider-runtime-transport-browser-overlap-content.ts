//! Browser-only raw-Port driver for C22 overlap ordering. Never shipped.

import { PROVIDER_PORT_NAME } from "../src/background/provider-port.js";
import { PAGE_PROVIDER_RESPONSE_TYPE } from "../src/provider-protocol.js";
import {
  readPageProviderReceiptEnvelope,
  readProviderTransportTerminalEnvelope,
} from "../src/provider-delivery-protocol.js";

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
const receiptPorts = new Map<string, BrowserPort>();

addEventListener("message", (event) => {
  if (
    event.source !== window ||
    event.origin !== pageOrigin ||
    typeof event.data !== "object" ||
    event.data === null
  ) {
    return;
  }
  const receipt = readPageProviderReceiptEnvelope(event.data);
  if (receipt !== null) {
    receiptPorts.get(receipt.payload.correlationId)?.postMessage(receipt.payload);
    return;
  }
  if ((event.data as { readonly type?: unknown }).type !== "warden:test:open-port") {
    return;
  }
  const request = (event.data as { readonly request?: unknown }).request;
  const index = nextPortIndex++;
  const port = runtime.connect({ name: PROVIDER_PORT_NAME });
  port.onMessage.addListener((message) => {
    const terminal = readProviderTransportTerminalEnvelope(message);
    if (terminal !== null) {
      receiptPorts.set(terminal.correlationId, port);
      postMessage({
        version: 1,
        type: PAGE_PROVIDER_RESPONSE_TYPE,
        payload: terminal,
      }, pageOrigin);
    }
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
