import { describe, expect, it, vi } from "vitest";

import {
  DEFAULT_PROVIDER_REQUEST_TTL_MS,
  MAX_ACTIVE_PROVIDER_PORTS,
  MAX_PENDING_PROVIDER_REQUESTS,
  MAX_PROVIDER_REQUEST_IDS_PER_SESSION,
  MAX_PROVIDER_REQUESTS_PER_PORT,
  PROVIDER_PORT_NAME,
  ProviderPortSession,
  ProviderPortStateError,
  ProviderRequestCancelledError,
  createUnavailableProviderResponse,
  installUnavailableProviderBoundary,
  type ProviderConnectEvent,
  type ProviderDisconnectEvent,
  type ProviderMessageEvent,
  type ProviderRandomSource,
  type ProviderRuntimePort,
  type ProviderTimerSource,
} from "../src/background/provider-port.js";
import { classifyProviderSender } from "../src/background/sender-provenance.js";

const EXTENSION_ID = "a".repeat(32);
const DOCUMENT_ID = "123e4567-e89b-12d3-a456-426614174000";
const ACCOUNT_ADDRESS = "11111111111111111111111111111111";

function providerSender(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    documentId: DOCUMENT_ID,
    documentLifecycle: "active",
    frameId: 4,
    id: EXTENSION_ID,
    origin: "https://iframe.example",
    tab: { id: 19, url: "https://host.example/parent" },
    url: "https://iframe.example/embedded",
    ...overrides,
  };
}

function request(
  correlationId = "request_0123456789abcdef",
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    version: 1,
    type: "request",
    correlationId,
    method: "solana:signTransaction",
    params: { accountAddress: ACCOUNT_ADDRESS, transaction: [1, 2, 3] },
    ...overrides,
  };
}

function provenance() {
  return classifyProviderSender({ runtimeId: EXTENSION_ID, sender: providerSender() });
}

class SequenceRandom implements ProviderRandomSource {
  calls = 0;
  private readonly values: readonly number[];

  constructor(values: readonly number[]) {
    this.values = values;
  }

  getRandomValues(target: Uint8Array): Uint8Array {
    const value = this.values[Math.min(this.calls, this.values.length - 1)] ?? 0;
    this.calls++;
    target.fill(value);
    return target;
  }
}

class CounterRandom implements ProviderRandomSource {
  private counter = 0;

  getRandomValues(target: Uint8Array): Uint8Array {
    target.fill(0);
    target[target.length - 2] = (this.counter >>> 8) & 0xff;
    target[target.length - 1] = this.counter & 0xff;
    this.counter++;
    return target;
  }
}

class ManualTimers implements ProviderTimerSource {
  private nextId = 1;
  readonly pending = new Map<number, { callback: () => void; delayMs: number }>();

  setTimeout(callback: () => void, delayMs: number): unknown {
    const id = this.nextId++;
    this.pending.set(id, { callback, delayMs });
    return id;
  }

  clearTimeout(handle: unknown): void {
    this.pending.delete(handle as number);
  }

  runNext(): void {
    const next = this.pending.entries().next().value as
      | [number, { callback: () => void; delayMs: number }]
      | undefined;
    if (next === undefined) throw new Error("no pending timer");
    this.pending.delete(next[0]);
    next[1].callback();
  }
}

class MockMessageEvent implements ProviderMessageEvent {
  readonly listeners = new Set<(message: unknown) => void>();
  throwOnAdd = false;

  addListener(listener: (message: unknown) => void): void {
    if (this.throwOnAdd) throw new Error("listener install failed");
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
  throwOnPost = false;

  constructor(
    readonly name = PROVIDER_PORT_NAME,
    readonly sender: unknown = providerSender(),
  ) {}

  postMessage(message: unknown): void {
    if (this.throwOnPost) throw new Error("port already gone");
    this.posted.push(message);
  }

  disconnect(): void {
    this.disconnectCalls++;
    this.onDisconnect.emit();
  }
}

describe("per-provider-Port request owner", () => {
  it("uses browser Web Crypto for the production-default 128-bit id source", () => {
    const randomSpy = vi.spyOn(globalThis.crypto, "getRandomValues");
    try {
      const session = new ProviderPortSession(provenance());
      const owned = session.open(request());
      expect(owned.id).toMatch(/^req_[0-9a-f]{32}$/);
      expect(randomSpy).toHaveBeenCalledOnce();
      const target = randomSpy.mock.calls[0]?.[0];
      expect(target).toBeInstanceOf(Uint8Array);
      expect(target).toHaveLength(16);
      expect(session.finish(owned)).toBe(true);
    } finally {
      randomSpy.mockRestore();
    }
  });

  it("mints a separate 128-bit request id and freezes the browser-owned lease", () => {
    const random = new SequenceRandom([0x5a]);
    const session = new ProviderPortSession(provenance(), {
      randomSource: random,
      readNow: () => 1_000,
    });
    const owned = session.open(request());

    expect(owned).toMatchObject({
      id: `req_${"5a".repeat(16)}`,
      createdAt: 1_000,
      expiresAt: 1_000 + DEFAULT_PROVIDER_REQUEST_TTL_MS,
      provenance: {
        origin: "https://iframe.example",
        tabId: 19,
        frameId: 4,
        documentId: DOCUMENT_ID,
      },
      request: { correlationId: "request_0123456789abcdef" },
    });
    expect(owned.id).not.toContain(owned.request.correlationId);
    expect(random.calls).toBe(1);
    expect(Object.isFrozen(owned)).toBe(true);
    expect(Object.isFrozen(owned.provenance)).toBe(true);
    expect(owned.signal.aborted).toBe(false);
    expect(session.pendingCount).toBe(1);
  });

  it("owns copied request bytes instead of a page-mutable array", () => {
    const transaction = [1, 2, 3];
    const raw = request("request_mutation_012345", {
      params: { accountAddress: ACCOUNT_ADDRESS, transaction },
    });
    const session = new ProviderPortSession(provenance(), {
      randomSource: new SequenceRandom([1]),
    });
    const owned = session.open(raw);
    if (owned.request.method !== "solana:signTransaction") {
      throw new Error("parser returned the wrong method discriminator");
    }

    transaction[0] = 99;
    expect(owned.request.params.transaction).toEqual([1, 2, 3]);
    expect(Object.isFrozen(owned.request.params.transaction)).toBe(true);
  });

  it("rejects a duplicate in-flight page correlation without cancelling the owner", () => {
    const session = new ProviderPortSession(provenance(), {
      randomSource: new SequenceRandom([1, 2]),
    });
    const first = session.open(request());
    expect(() => session.open(request())).toThrow(ProviderPortStateError);
    expect(first.signal.aborted).toBe(false);
    expect(session.pendingCount).toBe(1);
  });

  it("allows a correlation only after settlement and gives it a new internal id", () => {
    const session = new ProviderPortSession(provenance(), {
      randomSource: new SequenceRandom([1, 2]),
    });
    const first = session.open(request());
    expect(session.finish(first)).toBe(true);
    const second = session.open(request());
    expect(second.id).not.toBe(first.id);
  });

  it("retries a pending random-id collision instead of aliasing two requests", () => {
    const random = new SequenceRandom([1, 1, 2]);
    const session = new ProviderPortSession(provenance(), { randomSource: random });
    const first = session.open(request("request_first_01234567"));
    const second = session.open(request("request_second_0123456"));
    expect(first.id).toBe(`req_${"01".repeat(16)}`);
    expect(second.id).toBe(`req_${"02".repeat(16)}`);
    expect(random.calls).toBe(3);
  });

  it("never reuses an issued id after the earlier request settles", () => {
    const random = new SequenceRandom([1]);
    const session = new ProviderPortSession(provenance(), { randomSource: random });
    const first = session.open(request("request_first_01234567"));
    expect(session.finish(first)).toBe(true);
    expect(() => session.open(request("request_second_0123456"))).toThrow(
      "could not mint a unique request id",
    );
  });

  it("bounds concurrent requests per port", () => {
    const session = new ProviderPortSession(provenance(), {
      randomSource: new CounterRandom(),
    });
    for (let index = 0; index < MAX_PENDING_PROVIDER_REQUESTS; index++) {
      session.open(request(`request_pending_${index.toString().padStart(8, "0")}`));
    }
    expect(() => session.open(request("request_pending_over_cap"))).toThrow(
      "too many pending requests",
    );
  });

  it("bounds the issued-id set instead of leaking memory for a forever port", () => {
    const session = new ProviderPortSession(provenance(), {
      randomSource: new CounterRandom(),
    });
    for (let index = 0; index < MAX_PROVIDER_REQUESTS_PER_PORT; index++) {
      const owned = session.open(request(`request_total_${index.toString().padStart(8, "0")}`));
      expect(session.finish(owned)).toBe(true);
    }
    expect(() => session.open(request("request_total_over_cap"))).toThrow(
      "request limit reached",
    );
  });

  it("bounds an explicitly raised reconnect-attempt id budget", () => {
    expect(() => new ProviderPortSession(provenance(), {
      requestLimit: MAX_PROVIDER_REQUEST_IDS_PER_SESSION + 1,
    })).toThrow(`request limit must be 1..${MAX_PROVIDER_REQUEST_IDS_PER_SESSION}`);

    const session = new ProviderPortSession(provenance(), {
      randomSource: new CounterRandom(),
      requestLimit: 2,
    });
    const first = session.open(request("request_limit_first_0001"));
    expect(session.finish(first)).toBe(true);
    const second = session.open(request("request_limit_second_001"));
    expect(session.finish(second)).toBe(true);
    expect(() => session.open(request("request_limit_overflow_01"))).toThrow(
      "request limit reached",
    );
  });

  it("cancels at the exact absolute expiry boundary before finish can win", () => {
    let now = 10_000;
    const session = new ProviderPortSession(provenance(), {
      randomSource: new SequenceRandom([1]),
      readNow: () => now,
      requestTtlMs: 500,
    });
    const owned = session.open(request());
    now = 10_499;
    expect(session.reapExpired()).toBe(0);
    expect(owned.signal.aborted).toBe(false);
    now = 10_500;
    expect(session.finish(owned)).toBe(false);
    expect(owned.signal.aborted).toBe(true);
    expect(owned.signal.reason).toBeInstanceOf(ProviderRequestCancelledError);
    expect(owned.signal.reason).toMatchObject({ reason: "expired" });
    expect(session.pendingCount).toBe(0);
  });

  it("actively aborts an idle lease at expiry and resists an early timer", () => {
    let now = 10_000;
    const timers = new ManualTimers();
    const session = new ProviderPortSession(provenance(), {
      randomSource: new SequenceRandom([1]),
      timerSource: timers,
      readNow: () => now,
      requestTtlMs: 500,
    });
    const owned = session.open(request());
    expect([...timers.pending.values()].map((timer) => timer.delayMs)).toEqual([500]);

    now = 10_499;
    timers.runNext();
    expect(owned.signal.aborted).toBe(false);
    expect([...timers.pending.values()].map((timer) => timer.delayMs)).toEqual([1]);

    now = 10_500;
    timers.runNext();
    expect(owned.signal.aborted).toBe(true);
    expect(owned.signal.reason).toMatchObject({ reason: "expired" });
    expect(session.pendingCount).toBe(0);
    expect(timers.pending.size).toBe(0);
  });

  it("never returns a lease if the absolute clock crosses expiry during open", () => {
    const times = [10_000, 10_000, 10_500];
    const session = new ProviderPortSession(provenance(), {
      randomSource: new SequenceRandom([1]),
      timerSource: new ManualTimers(),
      readNow: () => times.shift() ?? 10_500,
      requestTtlMs: 500,
    });
    expect(() => session.open(request())).toThrow("request expired while opening");
    expect(session.pendingCount).toBe(0);
  });

  it("disconnect synchronously aborts every lease and permanently closes the owner", () => {
    const session = new ProviderPortSession(provenance(), {
      randomSource: new SequenceRandom([1, 2]),
    });
    const first = session.open(request("request_first_01234567"));
    const second = session.open(request("request_second_0123456"));
    session.disconnect();
    expect(first.signal.aborted).toBe(true);
    expect(second.signal.aborted).toBe(true);
    expect(first.signal.reason).toMatchObject({ reason: "disconnect" });
    expect(session.pendingCount).toBe(0);
    expect(session.closed).toBe(true);
    expect(() => session.open(request("request_after_disconnect"))).toThrow(
      "provider port is closed",
    );
  });

  it("account change cancels pending work but leaves the same port able to reconnect", () => {
    const session = new ProviderPortSession(provenance(), {
      randomSource: new SequenceRandom([1, 2]),
    });
    const first = session.open(request("request_first_01234567"));
    expect(session.cancelPending("account-change")).toBe(1);
    expect(first.signal.reason).toMatchObject({ reason: "account-change" });
    expect(session.closed).toBe(false);
    expect(session.open(request("request_second_0123456")).signal.aborted).toBe(false);
  });

  it("settlement removes ownership without mislabelling success as cancellation", () => {
    const session = new ProviderPortSession(provenance(), {
      randomSource: new SequenceRandom([1]),
    });
    const owned = session.open(request());
    session.assertActive(owned);
    expect(session.finish(owned)).toBe(true);
    expect(owned.signal.aborted).toBe(false);
    expect(() => session.assertActive(owned)).toThrow("request is no longer owned");
    expect(session.finish(owned)).toBe(false);
  });

  it("cannot settle another port's lease even if a test source repeats its id", () => {
    const firstSession = new ProviderPortSession(provenance(), {
      randomSource: new SequenceRandom([1]),
    });
    const secondSession = new ProviderPortSession(provenance(), {
      randomSource: new SequenceRandom([1]),
    });
    const first = firstSession.open(request("request_first_01234567"));
    const second = secondSession.open(request("request_second_0123456"));
    expect(first.id).toBe(second.id);
    expect(secondSession.finish(first)).toBe(false);
    secondSession.assertActive(second);
    expect(secondSession.pendingCount).toBe(1);
    firstSession.disconnect();
    secondSession.disconnect();
  });

  it("rejects malformed input before consuming entropy or creating ownership", () => {
    const random = new SequenceRandom([1]);
    const session = new ProviderPortSession(provenance(), { randomSource: random });
    expect(() => session.open(request("request_bad_method_0123", { method: "warden:unlock" }))).toThrow();
    expect(random.calls).toBe(0);
    expect(session.pendingCount).toBe(0);
  });
});

describe("zero-privilege provider runtime boundary", () => {
  it("returns one closed unavailable response without exposing the security id", () => {
    const response = createUnavailableProviderResponse("request_0123456789abcdef");
    expect(response).toEqual({
      version: 1,
      type: "response",
      correlationId: "request_0123456789abcdef",
      ok: false,
      error: {
        code: "WARDEN_METHOD_UNAVAILABLE",
        message: "Warden provider methods are not enabled",
      },
    });
    expect(Object.isFrozen(response)).toBe(true);
    expect(Object.isFrozen(response.error)).toBe(true);
    expect(JSON.stringify(response)).not.toContain("req_");
  });

  it("classifies and parses the named provider channel, then fails unavailable", () => {
    const onConnect = new MockConnectEvent();
    const boundary = installUnavailableProviderBoundary({ id: EXTENSION_ID, onConnect });
    const port = new MockPort();
    onConnect.emit(port);
    expect(port.onMessage.listeners.size).toBe(1);
    expect(port.onDisconnect.listeners.size).toBe(1);

    port.onMessage.emit(request());
    expect(port.posted).toEqual([createUnavailableProviderResponse("request_0123456789abcdef")]);
    expect(port.disconnectCalls).toBe(0);
    boundary.dispose();
  });

  it("disconnects an unknown channel without installing message listeners", () => {
    const onConnect = new MockConnectEvent();
    installUnavailableProviderBoundary({ id: EXTENSION_ID, onConnect });
    const port = new MockPort("warden:privileged-ui:v1");
    onConnect.emit(port);
    expect(port.disconnectCalls).toBe(1);
    expect(port.onMessage.listeners.size).toBe(0);
  });

  it("keeps exactly one port owner for one browser document identity", () => {
    const onConnect = new MockConnectEvent();
    const boundary = installUnavailableProviderBoundary({ id: EXTENSION_ID, onConnect });
    const first = new MockPort();
    const duplicate = new MockPort();
    onConnect.emit(first);
    onConnect.emit(duplicate);
    expect(first.disconnectCalls).toBe(0);
    expect(first.onMessage.listeners.size).toBe(1);
    expect(duplicate.disconnectCalls).toBe(1);
    expect(duplicate.onMessage.listeners.size).toBe(0);
    boundary.dispose();
  });

  it("caps active provider ports across distinct browser documents", () => {
    const onConnect = new MockConnectEvent();
    const boundary = installUnavailableProviderBoundary({ id: EXTENSION_ID, onConnect });
    const ports: MockPort[] = [];
    for (let index = 0; index < MAX_ACTIVE_PROVIDER_PORTS; index++) {
      const port = new MockPort(
        PROVIDER_PORT_NAME,
        providerSender({ documentId: `document-${index.toString().padStart(4, "0")}` }),
      );
      ports.push(port);
      onConnect.emit(port);
      expect(port.disconnectCalls).toBe(0);
    }
    const overflow = new MockPort(
      PROVIDER_PORT_NAME,
      providerSender({ documentId: "document-overflow" }),
    );
    onConnect.emit(overflow);
    expect(overflow.disconnectCalls).toBe(1);
    expect(overflow.onMessage.listeners.size).toBe(0);
    boundary.dispose();
    expect(ports.every((port) => port.disconnectCalls === 1)).toBe(true);
  });

  it.each([
    ["wrong extension owner", providerSender({ id: "b".repeat(32) })],
    ["missing document", providerSender({ documentId: undefined })],
    [
      "extension UI pretending to be provider",
      {
        documentId: DOCUMENT_ID,
        id: EXTENSION_ID,
        origin: `chrome-extension://${EXTENSION_ID}`,
        url: `chrome-extension://${EXTENSION_ID}/popup.html`,
      },
    ],
  ])("disconnects %s before accepting a payload", (_label, sender) => {
    const onConnect = new MockConnectEvent();
    installUnavailableProviderBoundary({ id: EXTENSION_ID, onConnect });
    const port = new MockPort(PROVIDER_PORT_NAME, sender);
    onConnect.emit(port);
    expect(port.disconnectCalls).toBe(1);
    expect(port.onMessage.listeners.size).toBe(0);
  });

  it("disconnects on a forged page context and ignores every later message", () => {
    const onConnect = new MockConnectEvent();
    installUnavailableProviderBoundary({ id: EXTENSION_ID, onConnect });
    const port = new MockPort();
    onConnect.emit(port);
    port.onMessage.emit(request("request_forged_ctx_0123", { origin: "https://forged.example" }));
    expect(port.disconnectCalls).toBe(1);
    expect(port.posted).toEqual([]);
    expect(port.onMessage.listeners.size).toBe(0);
    port.onMessage.emit(request());
    expect(port.posted).toEqual([]);
  });

  it("releases the exact document owner when Chrome reports port disconnect", () => {
    const onConnect = new MockConnectEvent();
    installUnavailableProviderBoundary({ id: EXTENSION_ID, onConnect });
    const port = new MockPort();
    onConnect.emit(port);
    expect(port.onMessage.listeners.size).toBe(1);
    port.onDisconnect.emit();
    expect(port.onMessage.listeners.size).toBe(0);
    expect(port.onDisconnect.listeners.size).toBe(0);
    expect(port.disconnectCalls).toBe(0);
    port.onMessage.emit(request());
    expect(port.posted).toEqual([]);

    const replacement = new MockPort();
    onConnect.emit(replacement);
    expect(replacement.disconnectCalls).toBe(0);
    expect(replacement.onMessage.listeners.size).toBe(1);
  });

  it("fails closed when posting the unavailable response races a dead port", () => {
    const onConnect = new MockConnectEvent();
    installUnavailableProviderBoundary({ id: EXTENSION_ID, onConnect });
    const port = new MockPort();
    port.throwOnPost = true;
    onConnect.emit(port);
    expect(() => port.onMessage.emit(request())).not.toThrow();
    expect(port.disconnectCalls).toBe(1);
    expect(port.onMessage.listeners.size).toBe(0);
  });

  it("rolls back a partially installed port when message-listener setup fails", () => {
    const onConnect = new MockConnectEvent();
    installUnavailableProviderBoundary({ id: EXTENSION_ID, onConnect });
    const port = new MockPort();
    port.onMessage.throwOnAdd = true;
    onConnect.emit(port);
    expect(port.disconnectCalls).toBe(1);
    expect(port.onMessage.listeners.size).toBe(0);
    expect(port.onDisconnect.listeners.size).toBe(0);
  });

  it("dispose removes the global listener and disconnects every active port", () => {
    const onConnect = new MockConnectEvent();
    const boundary = installUnavailableProviderBoundary({ id: EXTENSION_ID, onConnect });
    const first = new MockPort();
    const second = new MockPort(
      PROVIDER_PORT_NAME,
      providerSender({ documentId: "second-active-document" }),
    );
    onConnect.emit(first);
    onConnect.emit(second);
    expect(first.disconnectCalls).toBe(0);
    expect(second.disconnectCalls).toBe(0);
    expect(onConnect.listeners.size).toBe(1);
    boundary.dispose();
    expect(onConnect.listeners.size).toBe(0);
    expect(first.disconnectCalls).toBe(1);
    expect(second.disconnectCalls).toBe(1);
    boundary.dispose();
    expect(first.disconnectCalls).toBe(1);
  });
});
