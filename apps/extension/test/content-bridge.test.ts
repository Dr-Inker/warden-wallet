import { describe, expect, it } from "vitest";

import {
  PAGE_PROVIDER_REQUEST_TYPE,
  PAGE_PROVIDER_RESPONSE_TYPE,
  PROVIDER_PORT_NAME,
  MAX_PROVIDER_REQUESTS_PER_DOCUMENT,
  installPageProviderBridge,
  type ContentPortDisconnectEvent,
  type ContentPortMessageEvent,
  type ContentRuntimeApi,
  type ContentRuntimePort,
  type ContentWindowApi,
  type ContentWindowMessageEvent,
  type ContentWindowMessageListener,
} from "../src/content/bridge.js";

const ORIGIN = "https://dapp.example";
const CORRELATION_ID = "bridge_request_0123456789";

class MessageEventOwner implements ContentPortMessageEvent {
  readonly listeners = new Set<(message: unknown) => void>();

  addListener(listener: (message: unknown) => void): void {
    this.listeners.add(listener);
  }

  removeListener(listener: (message: unknown) => void): void {
    this.listeners.delete(listener);
  }

  emit(message: unknown): void {
    for (const listener of [...this.listeners]) listener(message);
  }
}

class DisconnectEventOwner implements ContentPortDisconnectEvent {
  readonly listeners = new Set<() => void>();

  addListener(listener: () => void): void {
    this.listeners.add(listener);
  }

  removeListener(listener: () => void): void {
    this.listeners.delete(listener);
  }

  emit(): void {
    for (const listener of [...this.listeners]) listener();
  }
}

class MockPort implements ContentRuntimePort {
  readonly onMessage = new MessageEventOwner();
  readonly onDisconnect = new DisconnectEventOwner();
  readonly posted: unknown[] = [];
  disconnectCalls = 0;
  throwOnPost = false;

  postMessage(message: unknown): void {
    if (this.throwOnPost) throw new Error("structured clone failed");
    this.posted.push(message);
  }

  disconnect(): void {
    this.disconnectCalls++;
  }
}

class MockRuntime implements ContentRuntimeApi {
  readonly ports: MockPort[] = [];
  readonly connectCalls: unknown[] = [];
  throwEveryPost = false;

  get port(): MockPort {
    const port = this.ports.at(-1);
    if (port === undefined) throw new Error("no Port has been opened");
    return port;
  }

  connect(connectInfo: { readonly name: string }): ContentRuntimePort {
    this.connectCalls.push(connectInfo);
    const port = new MockPort();
    port.throwOnPost = this.throwEveryPost;
    this.ports.push(port);
    return port;
  }
}

class MockWindow implements ContentWindowApi {
  readonly location = { origin: ORIGIN };
  readonly listeners = new Set<ContentWindowMessageListener>();
  readonly posted: Array<{ readonly message: unknown; readonly targetOrigin: string }> = [];
  throwOnPost = false;

  addEventListener(type: "message", listener: ContentWindowMessageListener): void {
    expect(type).toBe("message");
    this.listeners.add(listener);
  }

  removeEventListener(type: "message", listener: ContentWindowMessageListener): void {
    expect(type).toBe("message");
    this.listeners.delete(listener);
  }

  postMessage(message: unknown, targetOrigin: string): void {
    if (this.throwOnPost) throw new Error("window disappeared");
    this.posted.push({ message, targetOrigin });
  }

  emit(data: unknown, overrides: Partial<ContentWindowMessageEvent> = {}): void {
    const event: ContentWindowMessageEvent = {
      data,
      origin: ORIGIN,
      source: this,
      ...overrides,
    };
    for (const listener of [...this.listeners]) listener(event);
  }
}

function requestPayload(): Record<string, unknown> {
  return {
    version: 1,
    type: "request",
    correlationId: CORRELATION_ID,
    method: "standard:connect",
    params: {},
  };
}

function requestEnvelope(payload: unknown = requestPayload()): Record<string, unknown> {
  return { version: 1, type: PAGE_PROVIDER_REQUEST_TYPE, payload };
}

function unavailableResponse(): Record<string, unknown> {
  return {
    version: 1,
    type: "response",
    correlationId: CORRELATION_ID,
    ok: false,
    error: {
      code: "WARDEN_METHOD_UNAVAILABLE",
      message: "Warden provider methods are not enabled",
    },
  };
}

describe("isolated-world page provider bridge", () => {
  it("opens only the named Port and transports the untrusted payload unchanged", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const payload = requestPayload();

    installPageProviderBridge(page, runtime);
    expect(runtime.connectCalls).toEqual([]);
    page.emit(requestEnvelope(payload));

    expect(runtime.connectCalls).toEqual([{ name: PROVIDER_PORT_NAME }]);
    expect(runtime.port.posted).toEqual([payload]);
    expect(runtime.port.posted[0]).toBe(payload);
  });

  it("does not wake the background for unrelated page traffic", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    installPageProviderBridge(page, runtime);

    page.emit({ type: "analytics" });
    page.emit(requestEnvelope(), { source: {} });
    page.emit(requestEnvelope(), { origin: "https://attacker.example" });

    expect(runtime.connectCalls).toEqual([]);
    expect(runtime.ports).toEqual([]);
  });

  it("ignores cross-context, forged-origin, wrong-direction, and open outer envelopes", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    installPageProviderBridge(page, runtime);

    page.emit(requestEnvelope(), { source: {} });
    page.emit(requestEnvelope(), { origin: "https://attacker.example" });
    page.emit({ version: 1, type: PAGE_PROVIDER_RESPONSE_TYPE, payload: requestPayload() });
    page.emit({ ...requestEnvelope(), origin: ORIGIN });
    page.emit({ version: 2, type: PAGE_PROVIDER_REQUEST_TYPE, payload: requestPayload() });
    page.emit({ version: 1, type: PAGE_PROVIDER_REQUEST_TYPE });
    page.emit(null);

    expect(runtime.connectCalls).toEqual([]);
    expect(runtime.ports).toEqual([]);
  });

  it("does not interpret or add authority to a matching inner payload", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const forged = { origin: "https://forged.example", approved: true };
    installPageProviderBridge(page, runtime);

    page.emit(requestEnvelope(forged));

    expect(runtime.port.posted).toEqual([forged]);
  });

  it("returns only the exact unavailable response in a direction-tagged envelope", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    installPageProviderBridge(page, runtime);
    page.emit(requestEnvelope());

    const response = unavailableResponse();
    runtime.port.onMessage.emit(response);

    expect(page.posted).toEqual([
      {
        message: {
          version: 1,
          type: PAGE_PROVIDER_RESPONSE_TYPE,
          payload: response,
        },
        targetOrigin: ORIGIN,
      },
    ]);
  });

  it("fails closed instead of forwarding an unexpected background payload", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    installPageProviderBridge(page, runtime);
    page.emit(requestEnvelope());

    runtime.port.onMessage.emit({ privateKey: "must-not-cross" });
    page.emit(requestEnvelope());

    expect(page.posted).toEqual([]);
    expect(runtime.port.disconnectCalls).toBe(1);
    expect(page.listeners.size).toBe(0);
    expect(runtime.port.onMessage.listeners.size).toBe(0);
    expect(runtime.port.onDisconnect.listeners.size).toBe(0);
    expect(runtime.port.posted).toEqual([requestPayload()]);
  });

  it.each([
    ["extra root field", { ...unavailableResponse(), account: "must-not-cross" }],
    ["short correlation", { ...unavailableResponse(), correlationId: "short" }],
    ["success discriminator", { ...unavailableResponse(), ok: true }],
    [
      "wrong error code",
      { ...unavailableResponse(), error: { ...unavailableResponse().error as object, code: "OTHER" } },
    ],
    [
      "open error object",
      { ...unavailableResponse(), error: { ...unavailableResponse().error as object, detail: "leak" } },
    ],
  ])("closes on a background response with %s", (_label, malformed) => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    installPageProviderBridge(page, runtime);
    page.emit(requestEnvelope());

    runtime.port.onMessage.emit(malformed);

    expect(page.posted).toEqual([]);
    expect(page.listeners.size).toBe(0);
    expect(runtime.port.disconnectCalls).toBe(1);
  });

  it("reconnects lazily on the next request after Chrome disconnects the worker Port", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    installPageProviderBridge(page, runtime);
    page.emit(requestEnvelope());
    const firstPort = runtime.port;

    firstPort.onDisconnect.emit();
    expect(page.listeners.size).toBe(1);
    page.emit(requestEnvelope({ ...requestPayload(), correlationId: "bridge_reconnect_0123456" }));

    expect(firstPort.disconnectCalls).toBe(0);
    expect(runtime.connectCalls).toEqual([
      { name: PROVIDER_PORT_NAME },
      { name: PROVIDER_PORT_NAME },
    ]);
    expect(runtime.port).not.toBe(firstPort);
    expect(runtime.port.posted).toEqual([
      { ...requestPayload(), correlationId: "bridge_reconnect_0123456" },
    ]);
  });

  it("retries one stale Port once without closing the document bridge", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    installPageProviderBridge(page, runtime);
    page.emit(requestEnvelope());
    const stalePort = runtime.port;
    stalePort.throwOnPost = true;
    const retryPayload = {
      ...requestPayload(),
      correlationId: "bridge_stale_retry_01234",
    };

    page.emit(requestEnvelope(retryPayload));

    expect(stalePort.disconnectCalls).toBe(1);
    expect(runtime.ports).toHaveLength(2);
    expect(runtime.port.posted).toEqual([retryPayload]);
    expect(page.listeners.size).toBe(1);
  });

  it("does not let reconnects bypass the per-document request ceiling", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    installPageProviderBridge(page, runtime);

    for (let index = 0; index < MAX_PROVIDER_REQUESTS_PER_DOCUMENT; index++) {
      page.emit(requestEnvelope());
    }
    page.emit(requestEnvelope());

    expect(runtime.connectCalls).toHaveLength(1);
    expect(runtime.port.posted).toHaveLength(MAX_PROVIDER_REQUESTS_PER_DOCUMENT);
    expect(runtime.port.disconnectCalls).toBe(1);
    expect(page.listeners.size).toBe(0);
  });

  it("disposal is idempotent and a page clone failure closes the whole bridge", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const bridge = installPageProviderBridge(page, runtime);
    runtime.throwEveryPost = true;

    page.emit(requestEnvelope());
    bridge.dispose();

    expect(runtime.ports).toHaveLength(2);
    expect(runtime.ports.map((port) => port.disconnectCalls)).toEqual([1, 1]);
    expect(page.listeners.size).toBe(0);
    expect(runtime.port.onMessage.listeners.size).toBe(0);
    expect(runtime.port.onDisconnect.listeners.size).toBe(0);
  });
});
