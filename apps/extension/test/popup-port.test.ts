import { describe, expect, it } from "vitest";

import {
  MAX_ACTIVE_POPUP_PORTS,
  MAX_POPUP_REQUESTS_PER_PORT,
  installUnavailablePopupBoundary,
} from "../src/background/popup-port.js";
import type {
  ProviderConnectEvent,
  ProviderDisconnectEvent,
  ProviderMessageEvent,
  ProviderRuntimePort,
} from "../src/background/provider-port.js";
import {
  POPUP_PORT_NAME,
  PopupProtocolError,
  createUnavailablePopupResponse,
  parsePopupRequest,
} from "../src/popup-protocol.js";

const EXTENSION_ID = "a".repeat(32);
const DOCUMENT_ID = "123e4567-e89b-12d3-a456-426614174000";

function popupSender(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    documentId: DOCUMENT_ID,
    documentLifecycle: "active",
    frameId: 0,
    id: EXTENSION_ID,
    origin: `chrome-extension://${EXTENSION_ID}`,
    tab: { id: 23, url: `chrome-extension://${EXTENSION_ID}/popup.html` },
    url: `chrome-extension://${EXTENSION_ID}/popup.html`,
    ...overrides,
  };
}

function contentSender(): Record<string, unknown> {
  return {
    documentId: DOCUMENT_ID,
    documentLifecycle: "active",
    frameId: 0,
    id: EXTENSION_ID,
    origin: "https://dapp.example",
    tab: { id: 23, url: "https://dapp.example/" },
    url: "https://dapp.example/",
  };
}

function request(
  correlationId = "popup_request_01234567",
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    version: 1,
    type: "request",
    correlationId,
    method: "popup:getBoundaryStatus",
    params: {},
    ...overrides,
  };
}

class MockMessageEvent implements ProviderMessageEvent {
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

class MockDisconnectEvent implements ProviderDisconnectEvent {
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

class MockConnectEvent implements ProviderConnectEvent {
  readonly listeners = new Set<(port: ProviderRuntimePort) => void>();

  addListener(listener: (port: ProviderRuntimePort) => void): void {
    this.listeners.add(listener);
  }

  removeListener(listener: (port: ProviderRuntimePort) => void): void {
    this.listeners.delete(listener);
  }

  emit(port: ProviderRuntimePort): void {
    for (const listener of [...this.listeners]) listener(port);
  }
}

class MockPort implements ProviderRuntimePort {
  readonly onMessage = new MockMessageEvent();
  readonly onDisconnect = new MockDisconnectEvent();
  readonly posted: unknown[] = [];
  disconnectCalls = 0;

  constructor(
    readonly name = POPUP_PORT_NAME,
    readonly sender: unknown = popupSender(),
  ) {}

  postMessage(message: unknown): void {
    this.posted.push(message);
  }

  disconnect(): void {
    this.disconnectCalls++;
    this.onDisconnect.emit();
  }
}

describe("closed zero-authority popup protocol", () => {
  it("copies and freezes the only accepted request shape", () => {
    const raw = request();
    const parsed = parsePopupRequest(raw);
    raw.correlationId = "mutated_request_012345";

    expect(parsed).toEqual({
      version: 1,
      type: "request",
      correlationId: "popup_request_01234567",
      method: "popup:getBoundaryStatus",
      params: {},
    });
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.params)).toBe(true);
  });

  it.each([
    ["unknown method", { method: "popup:getAccounts" }],
    ["provider method", { method: "standard:connect" }],
    ["extra authority field", { approved: true }],
    ["short correlation", { correlationId: "too_short" }],
    ["nonempty params", { params: { account: "forged" } }],
  ])("rejects %s", (_label, overrides) => {
    expect(() => parsePopupRequest(request(undefined, overrides))).toThrow(
      PopupProtocolError,
    );
  });

  it("creates one exact unavailable response and no authority-bearing result", () => {
    const response = createUnavailablePopupResponse("popup_request_01234567");
    expect(response).toEqual({
      version: 1,
      type: "response",
      correlationId: "popup_request_01234567",
      ok: false,
      error: {
        code: "WARDEN_POPUP_UNAVAILABLE",
        message: "Warden popup methods are not enabled",
      },
    });
    expect(Object.isFrozen(response)).toBe(true);
    expect(Object.isFrozen(response.error)).toBe(true);
    expect(response).not.toHaveProperty("result");
  });
});

describe("privileged popup runtime boundary", () => {
  it("accepts the exact extension page, parses its schema, and returns unavailable", () => {
    const onConnect = new MockConnectEvent();
    const boundary = installUnavailablePopupBoundary({ id: EXTENSION_ID, onConnect });
    const port = new MockPort();
    onConnect.emit(port);

    expect(port.onMessage.listeners.size).toBe(1);
    expect(port.onDisconnect.listeners.size).toBe(1);
    port.onMessage.emit(request());
    expect(port.posted).toEqual([
      {
        version: 1,
        type: "response",
        correlationId: "popup_request_01234567",
        ok: false,
        error: {
          code: "WARDEN_POPUP_UNAVAILABLE",
          message: "Warden popup methods are not enabled",
        },
      },
    ]);
    expect(port.disconnectCalls).toBe(0);
    boundary.dispose();
  });

  it("accepts Chrome's tabless action-popup sender shape", () => {
    const onConnect = new MockConnectEvent();
    const boundary = installUnavailablePopupBoundary({ id: EXTENSION_ID, onConnect });
    const port = new MockPort(POPUP_PORT_NAME, {
      id: EXTENSION_ID,
      origin: `chrome-extension://${EXTENSION_ID}`,
      url: `chrome-extension://${EXTENSION_ID}/popup.html`,
    });
    onConnect.emit(port);
    port.onMessage.emit(request("popup_action_012345678"));
    expect(port.posted).toEqual([
      createUnavailablePopupResponse("popup_action_012345678"),
    ]);
    expect(port.disconnectCalls).toBe(0);
    boundary.dispose();
  });

  it("rejects a same-extension-id content script before accepting any payload", () => {
    const onConnect = new MockConnectEvent();
    installUnavailablePopupBoundary({ id: EXTENSION_ID, onConnect });
    const port = new MockPort(POPUP_PORT_NAME, contentSender());
    onConnect.emit(port);

    expect(port.disconnectCalls).toBe(1);
    expect(port.onMessage.listeners.size).toBe(0);
    expect(port.posted).toEqual([]);
  });

  it.each([
    ["another extension", popupSender({ id: "b".repeat(32) })],
    [
      "unallowlisted extension page",
      popupSender({
        url: `chrome-extension://${EXTENSION_ID}/approval.html`,
        tab: { id: 23, url: `chrome-extension://${EXTENSION_ID}/approval.html` },
      }),
    ],
    ["nested extension frame", popupSender({ frameId: 2 })],
  ])("rejects %s", (_label, sender) => {
    const onConnect = new MockConnectEvent();
    installUnavailablePopupBoundary({ id: EXTENSION_ID, onConnect });
    const port = new MockPort(POPUP_PORT_NAME, sender);
    onConnect.emit(port);
    expect(port.disconnectCalls).toBe(1);
    expect(port.onMessage.listeners.size).toBe(0);
  });

  it("disconnects a valid page when its popup payload is malformed", () => {
    const onConnect = new MockConnectEvent();
    installUnavailablePopupBoundary({ id: EXTENSION_ID, onConnect });
    const port = new MockPort();
    onConnect.emit(port);
    port.onMessage.emit(request("popup_bad_method_0123", { method: "standard:connect" }));
    expect(port.disconnectCalls).toBe(1);
    expect(port.posted).toEqual([]);
    expect(port.onMessage.listeners.size).toBe(0);
  });

  it("rejects duplicate correlations and bounds total work on a long-lived popup Port", () => {
    const onConnect = new MockConnectEvent();
    installUnavailablePopupBoundary({ id: EXTENSION_ID, onConnect });
    const duplicate = new MockPort();
    onConnect.emit(duplicate);
    duplicate.onMessage.emit(request());
    duplicate.onMessage.emit(request());
    expect(duplicate.posted).toHaveLength(1);
    expect(duplicate.disconnectCalls).toBe(1);

    const bounded = new MockPort(POPUP_PORT_NAME, popupSender({ documentId: "bounded-popup" }));
    onConnect.emit(bounded);
    for (let index = 0; index < MAX_POPUP_REQUESTS_PER_PORT; index++) {
      bounded.onMessage.emit(
        request(`popup_total_${index.toString().padStart(8, "0")}`),
      );
    }
    expect(bounded.posted).toHaveLength(MAX_POPUP_REQUESTS_PER_PORT);
    bounded.onMessage.emit(request("popup_total_over_limit"));
    expect(bounded.disconnectCalls).toBe(1);
    expect(bounded.posted).toHaveLength(MAX_POPUP_REQUESTS_PER_PORT);
  });

  it("owns one Port per popup document and releases it on disconnect", () => {
    const onConnect = new MockConnectEvent();
    const boundary = installUnavailablePopupBoundary({ id: EXTENSION_ID, onConnect });
    const first = new MockPort();
    const duplicate = new MockPort();
    onConnect.emit(first);
    onConnect.emit(duplicate);
    expect(first.disconnectCalls).toBe(0);
    expect(duplicate.disconnectCalls).toBe(1);

    first.onDisconnect.emit();
    const replacement = new MockPort();
    onConnect.emit(replacement);
    expect(replacement.disconnectCalls).toBe(0);
    expect(replacement.onMessage.listeners.size).toBe(1);
    boundary.dispose();
    expect(replacement.disconnectCalls).toBe(1);
    expect(onConnect.listeners.size).toBe(0);
  });

  it("bounds concurrent popup Ports and releases capacity on disconnect", () => {
    const onConnect = new MockConnectEvent();
    const boundary = installUnavailablePopupBoundary({ id: EXTENSION_ID, onConnect });
    const accepted = Array.from({ length: MAX_ACTIVE_POPUP_PORTS }, (_, index) => {
      const port = new MockPort(
        POPUP_PORT_NAME,
        popupSender({ documentId: `popup-capacity-${index}` }),
      );
      onConnect.emit(port);
      expect(port.disconnectCalls).toBe(0);
      return port;
    });

    const overflow = new MockPort(
      POPUP_PORT_NAME,
      popupSender({ documentId: "popup-capacity-overflow" }),
    );
    onConnect.emit(overflow);
    expect(overflow.disconnectCalls).toBe(1);
    expect(overflow.onMessage.listeners.size).toBe(0);

    accepted[0]?.onDisconnect.emit();
    const replacement = new MockPort(
      POPUP_PORT_NAME,
      popupSender({ documentId: "popup-capacity-replacement" }),
    );
    onConnect.emit(replacement);
    expect(replacement.disconnectCalls).toBe(0);
    boundary.dispose();
  });
});
