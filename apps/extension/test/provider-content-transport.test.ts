import { describe, expect, it } from "vitest";

import {
  createProviderTerminalFailureResponse,
  createSignedTransactionProviderResponse,
} from "../src/background/provider-terminal-protocol.js";
import type {
  ContentPortDisconnectEvent,
  ContentPortMessageEvent,
  ContentRuntimeApi,
  ContentRuntimePort,
  ContentWindowApi,
  ContentWindowMessageEvent,
  ContentWindowMessageListener,
} from "../src/content/bridge.js";
import {
  DEFAULT_PROVIDER_CONTENT_REQUEST_TTL_MS,
  MAX_PROVIDER_CONTENT_PENDING_REQUESTS,
  MAX_PROVIDER_CONTENT_RECOVERY_ATTEMPTS,
  MAX_PROVIDER_CONTENT_REQUEST_TTL_MS,
  MAX_PROVIDER_CONTENT_REQUESTS_PER_DOCUMENT,
  ProviderContentTransportOwner,
  type ProviderContentTimerSource,
} from "../src/content/provider-content-transport.js";
import {
  ProviderPageRequestOwner,
  ProviderPageTerminalError,
  type ProviderPageRandomSource,
  type ProviderPageTimerSource,
  type ProviderPageWindowApi,
} from "../src/page/provider-request-owner.js";
import {
  PAGE_PROVIDER_REQUEST_TYPE,
  PAGE_PROVIDER_RESPONSE_TYPE,
  PROVIDER_PORT_NAME,
  createUnavailableProviderResponse,
} from "../src/provider-protocol.js";

const ORIGIN = "https://dapp.example";
const ACCOUNT = "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";
const CORRELATION_ID = "content_request_0123456789";

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
  postHook: ((message: unknown) => void) | null = null;

  postMessage(message: unknown): void {
    if (this.throwOnPost) throw new Error("Port is disconnected");
    this.posted.push(message);
    this.postHook?.(message);
  }

  disconnect(): void {
    this.disconnectCalls++;
  }
}

class MockRuntime implements ContentRuntimeApi {
  readonly ports: MockPort[] = [];
  readonly connectCalls: unknown[] = [];
  failConnectCount = 0;
  throwOnEveryPost = false;
  connectHook: ((port: MockPort) => void) | null = null;

  get port(): MockPort {
    const value = this.ports.at(-1);
    if (value === undefined) throw new Error("no Port has been opened");
    return value;
  }

  connect(connectInfo: { readonly name: string }): ContentRuntimePort {
    this.connectCalls.push(connectInfo);
    if (this.failConnectCount > 0) {
      this.failConnectCount--;
      throw new Error("worker unavailable");
    }
    const port = new MockPort();
    port.throwOnPost = this.throwOnEveryPost;
    this.ports.push(port);
    this.connectHook?.(port);
    return port;
  }
}

class MockWindow implements ContentWindowApi, ProviderPageWindowApi {
  readonly location = { origin: ORIGIN };
  readonly listeners = new Set<ContentWindowMessageListener>();
  readonly posted: Array<{ readonly message: unknown; readonly targetOrigin: string }> = [];
  dispatchPosts = false;
  throwOnPost = false;
  postHook: ((message: unknown) => void) | null = null;

  addEventListener(type: "message", listener: ContentWindowMessageListener): void {
    expect(type).toBe("message");
    this.listeners.add(listener);
  }

  removeEventListener(type: "message", listener: ContentWindowMessageListener): void {
    expect(type).toBe("message");
    this.listeners.delete(listener);
  }

  postMessage(message: unknown, targetOrigin: string): void {
    if (this.throwOnPost) throw new Error("document disappeared");
    this.posted.push({ message, targetOrigin });
    this.postHook?.(message);
    if (this.dispatchPosts) this.emit(message);
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

function signRequest(
  correlationId = CORRELATION_ID,
  transaction: number[] = [1, 2, 3],
): {
  version: number;
  type: string;
  correlationId: string;
  method: string;
  params: {
    accountAddress: string;
    transaction: number[];
    chain: string;
    options: { preflightCommitment: string; minContextSlot: number };
  };
} {
  return {
    version: 1,
    type: "request",
    correlationId,
    method: "solana:signTransaction",
    params: {
      accountAddress: ACCOUNT,
      transaction,
      chain: "solana:devnet",
      options: {
        preflightCommitment: "confirmed",
        minContextSlot: 42,
      },
    },
  };
}

function requestEnvelope(payload: unknown): Record<string, unknown> {
  return { version: 1, type: PAGE_PROVIDER_REQUEST_TYPE, payload };
}

function responseEnvelope(payload: unknown): Record<string, unknown> {
  return { version: 1, type: PAGE_PROVIDER_RESPONSE_TYPE, payload };
}

class FixedRandom implements ProviderPageRandomSource {
  getRandomValues(target: Uint8Array): Uint8Array {
    target.fill(0x44);
    return target;
  }
}

class InertTimers implements ProviderPageTimerSource {
  setTimeout(): unknown {
    return 1;
  }

  clearTimeout(): void {}
}

class ContentTimers implements ProviderContentTimerSource {
  readonly timers = new Map<
    number,
    { readonly callback: () => void; readonly delayMs: number }
  >();
  nextId = 1;

  setTimeout(callback: () => void, delayMs: number): unknown {
    const id = this.nextId++;
    this.timers.set(id, { callback, delayMs });
    return id;
  }

  clearTimeout(handle: unknown): void {
    this.timers.delete(handle as number);
  }

  fire(id: number): void {
    const timer = this.timers.get(id);
    if (timer === undefined) throw new Error(`timer ${id} is absent`);
    this.timers.delete(id);
    timer.callback();
  }
}

const PAGE_CORRELATION_ID = `page_${"44".repeat(16)}`;

describe("C20 bounded content provider transport", () => {
  it("opens lazily and retains one canonical copy instead of attacker-owned request data", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = new ProviderContentTransportOwner(page, runtime);
    const transaction = [1, 2, 3];
    const request = signRequest(CORRELATION_ID, transaction);

    page.emit({ type: "analytics" });
    expect(runtime.connectCalls).toEqual([]);
    page.emit(requestEnvelope(request));
    transaction[0] = 255;
    request.params.accountAddress = "attacker";

    expect(runtime.connectCalls).toEqual([{ name: PROVIDER_PORT_NAME }]);
    expect(runtime.port.posted).toEqual([signRequest()]);
    expect(runtime.port.posted[0]).not.toBe(request);
    expect(owner.pendingCount).toBe(1);
    expect(owner.issuedCount).toBe(1);
  });

  it("resends the identical retained payload once after worker Port loss", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = new ProviderContentTransportOwner(page, runtime);
    page.emit(requestEnvelope(signRequest()));
    const firstPort = runtime.port;
    const retained = firstPort.posted[0];

    firstPort.onDisconnect.emit();

    expect(runtime.ports).toHaveLength(2);
    expect(runtime.port.posted).toHaveLength(1);
    expect(runtime.port.posted[0]).toBe(retained);
    expect(firstPort.onMessage.listeners.size).toBe(0);
    expect(firstPort.onDisconnect.listeners.size).toBe(0);
    expect(owner.pendingCount).toBe(1);

    runtime.port.onDisconnect.emit();
    expect(runtime.ports).toHaveLength(2);
    expect(owner.pendingCount).toBe(1);
    expect(MAX_PROVIDER_CONTENT_RECOVERY_ATTEMPTS).toBe(1);
  });

  it("recovers every eligible outstanding request over one fresh Port", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = new ProviderContentTransportOwner(page, runtime);
    page.emit(requestEnvelope(signRequest("content_request_1111111111", [1])));
    page.emit(requestEnvelope(signRequest("content_request_2222222222", [2])));
    const firstPort = runtime.port;
    const retained = [...firstPort.posted];

    firstPort.onDisconnect.emit();

    expect(runtime.ports).toHaveLength(2);
    expect(runtime.port.posted).toHaveLength(2);
    expect(runtime.port.posted[0]).toBe(retained[0]);
    expect(runtime.port.posted[1]).toBe(retained[1]);
    expect(owner.pendingCount).toBe(2);
  });

  it("does not reconnect after an idle Port disconnect", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = new ProviderContentTransportOwner(page, runtime);
    page.emit(requestEnvelope(signRequest()));
    const port = runtime.port;
    port.onMessage.emit(
      createProviderTerminalFailureResponse(CORRELATION_ID, "WARDEN_USER_REJECTED"),
    );
    expect(owner.pendingCount).toBe(0);

    port.onDisconnect.emit();

    expect(runtime.ports).toHaveLength(1);
    expect(runtime.connectCalls).toHaveLength(1);
  });

  it("forwards the existing exact unavailable response without widening it", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = new ProviderContentTransportOwner(page, runtime);
    page.emit(requestEnvelope(signRequest()));

    runtime.port.onMessage.emit(createUnavailableProviderResponse(CORRELATION_ID));

    expect(owner.pendingCount).toBe(0);
    expect(page.posted).toEqual([
      {
        message: responseEnvelope(createUnavailableProviderResponse(CORRELATION_ID)),
        targetOrigin: ORIGIN,
      },
    ]);
  });

  it("ignores a stale Port and removes pending state before page delivery", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = new ProviderContentTransportOwner(page, runtime);
    page.emit(requestEnvelope(signRequest()));
    const firstPort = runtime.port;
    firstPort.onDisconnect.emit();
    const secondPort = runtime.port;
    let observedPending = -1;
    page.postHook = () => {
      observedPending = owner.pendingCount;
      secondPort.onMessage.emit(
        createProviderTerminalFailureResponse(CORRELATION_ID, "WARDEN_REQUEST_FAILED"),
      );
    };

    firstPort.onMessage.emit(
      createSignedTransactionProviderResponse(CORRELATION_ID, Uint8Array.of(7)),
    );
    expect(page.posted).toEqual([]);
    secondPort.onMessage.emit(
      createProviderTerminalFailureResponse(CORRELATION_ID, "WARDEN_REQUEST_CANCELLED"),
    );

    expect(observedPending).toBe(0);
    expect(owner.pendingCount).toBe(0);
    expect(page.posted).toEqual([
      {
        message: responseEnvelope(
          createProviderTerminalFailureResponse(
            CORRELATION_ID,
            "WARDEN_REQUEST_CANCELLED",
          ),
        ),
        targetOrigin: ORIGIN,
      },
    ]);
  });

  it("copies strict signed bytes before forwarding and ignores an unknown terminal id", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = new ProviderContentTransportOwner(page, runtime);
    page.emit(requestEnvelope(signRequest()));

    runtime.port.onMessage.emit(
      createSignedTransactionProviderResponse(
        "content_unknown_01234567",
        Uint8Array.of(1),
      ),
    );
    expect(owner.pendingCount).toBe(1);
    expect(page.posted).toEqual([]);

    const response = {
      version: 1,
      type: "response",
      correlationId: CORRELATION_ID,
      ok: true,
      result: { signedTransaction: [9, 8, 7] },
    };
    runtime.port.onMessage.emit(response);
    response.result.signedTransaction[0] = 0;

    expect(page.posted).toEqual([
      {
        message: responseEnvelope(
          createSignedTransactionProviderResponse(
            CORRELATION_ID,
            Uint8Array.of(9, 8, 7),
          ),
        ),
        targetOrigin: ORIGIN,
      },
    ]);
  });

  it("uses the single recovery budget for a synchronous stale-Port failure", () => {
    const runtime = new MockRuntime();
    runtime.throwOnEveryPost = true;
    const page = new MockWindow();
    const owner = new ProviderContentTransportOwner(page, runtime);

    page.emit(requestEnvelope(signRequest()));

    expect(runtime.ports).toHaveLength(2);
    expect(runtime.ports.map((port) => port.disconnectCalls)).toEqual([1, 1]);
    expect(owner.pendingCount).toBe(1);
    expect(page.listeners.size).toBe(1);
  });

  it("uses the single recovery budget when the first connect attempt throws", () => {
    const runtime = new MockRuntime();
    runtime.failConnectCount = 1;
    const page = new MockWindow();
    const owner = new ProviderContentTransportOwner(page, runtime);
    page.emit(requestEnvelope(signRequest()));

    expect(runtime.connectCalls).toHaveLength(2);
    expect(runtime.ports).toHaveLength(1);
    expect(runtime.port.posted).toEqual([signRequest()]);
    runtime.port.onDisconnect.emit();
    expect(runtime.connectCalls).toHaveLength(2);
    expect(owner.pendingCount).toBe(1);
  });

  it("evicts by absolute time without fabricating a page terminal response", () => {
    let now = 1_000;
    const timers = new ContentTimers();
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = new ProviderContentTransportOwner(page, runtime, {
      readNow: () => now,
      requestTtlMs: 100,
      timerSource: timers,
    });
    page.emit(requestEnvelope(signRequest()));
    const port = runtime.port;
    expect([...timers.timers.values()].map(({ delayMs }) => delayMs)).toEqual([100]);

    now = 1_050;
    timers.fire(1);
    expect(owner.pendingCount).toBe(1);
    expect([...timers.timers.values()].map(({ delayMs }) => delayMs)).toEqual([50]);

    now = 1_100;
    timers.fire(2);
    port.onMessage.emit(
      createProviderTerminalFailureResponse(CORRELATION_ID, "WARDEN_REQUEST_EXPIRED"),
    );
    port.onDisconnect.emit();

    expect(owner.pendingCount).toBe(0);
    expect(page.posted).toEqual([]);
    expect(runtime.ports).toHaveLength(1);
    expect(DEFAULT_PROVIDER_CONTENT_REQUEST_TTL_MS).toBe(2 * 60 * 1_000);
    expect(MAX_PROVIDER_CONTENT_REQUEST_TTL_MS).toBe(10 * 60 * 1_000);
  });

  it("never posts when initial or recovery connect crosses the absolute deadline", () => {
    let initialNow = 1_000;
    const initialTimers = new ContentTimers();
    const initialRuntime = new MockRuntime();
    initialRuntime.connectHook = () => {
      initialNow = 1_100;
    };
    const initialPage = new MockWindow();
    const initial = new ProviderContentTransportOwner(initialPage, initialRuntime, {
      readNow: () => initialNow,
      requestTtlMs: 100,
      timerSource: initialTimers,
    });
    initialPage.emit(requestEnvelope(signRequest("content_expiry_initial_01")));

    expect(initialRuntime.port.posted).toEqual([]);
    expect(initial.pendingCount).toBe(0);

    let recoveryNow = 2_000;
    const recoveryTimers = new ContentTimers();
    const recoveryRuntime = new MockRuntime();
    const recoveryPage = new MockWindow();
    const recovery = new ProviderContentTransportOwner(
      recoveryPage,
      recoveryRuntime,
      {
        readNow: () => recoveryNow,
        requestTtlMs: 100,
        timerSource: recoveryTimers,
      },
    );
    recoveryPage.emit(requestEnvelope(signRequest("content_expiry_recover_01")));
    const firstPort = recoveryRuntime.port;
    recoveryRuntime.connectHook = () => {
      recoveryNow = 2_100;
    };
    firstPort.onDisconnect.emit();

    expect(recoveryRuntime.ports).toHaveLength(2);
    expect(recoveryRuntime.port.posted).toEqual([]);
    expect(recovery.pendingCount).toBe(0);
    expect(recoveryRuntime.connectCalls).toHaveLength(2);
  });

  it("fails closed on an unexpected background shape without reflecting detail", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = new ProviderContentTransportOwner(page, runtime);
    page.emit(requestEnvelope(signRequest()));

    runtime.port.onMessage.emit({ privateKey: "must-not-cross" });

    expect(page.posted).toEqual([]);
    expect(owner.pendingCount).toBe(0);
    expect(page.listeners.size).toBe(0);
    expect(runtime.port.disconnectCalls).toBe(1);
  });

  it("closes on duplicate correlations and unsupported matching requests", () => {
    const firstRuntime = new MockRuntime();
    const firstPage = new MockWindow();
    const first = new ProviderContentTransportOwner(firstPage, firstRuntime);
    firstPage.emit(requestEnvelope(signRequest()));
    firstPage.emit(requestEnvelope(signRequest()));

    expect(first.pendingCount).toBe(0);
    expect(firstPage.listeners.size).toBe(0);
    expect(firstRuntime.port.disconnectCalls).toBe(1);

    const secondRuntime = new MockRuntime();
    const secondPage = new MockWindow();
    new ProviderContentTransportOwner(secondPage, secondRuntime);
    secondPage.emit(requestEnvelope({
      version: 1,
      type: "request",
      correlationId: "content_connect_012345678",
      method: "standard:connect",
      params: {},
    }));
    expect(secondRuntime.connectCalls).toEqual([]);
    expect(secondPage.listeners.size).toBe(0);
  });

  it("enforces pending and document-lifetime ceilings without a reconnect loop", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = new ProviderContentTransportOwner(page, runtime, {
      pendingLimit: 1,
      requestLimit: 2,
    });
    page.emit(requestEnvelope(signRequest("content_limit_0000000001")));
    page.emit(requestEnvelope(signRequest("content_limit_0000000002")));

    expect(owner.pendingCount).toBe(0);
    expect(runtime.connectCalls).toHaveLength(1);
    expect(page.listeners.size).toBe(0);
    expect(MAX_PROVIDER_CONTENT_PENDING_REQUESTS).toBe(32);
    expect(MAX_PROVIDER_CONTENT_REQUESTS_PER_DOCUMENT).toBe(1_024);
  });

  it("contains hostile proxies and disposes all volatile transport state", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = new ProviderContentTransportOwner(page, runtime);
    const revoked = Proxy.revocable(signRequest(), {});
    revoked.revoke();

    expect(() => page.emit(requestEnvelope(revoked.proxy))).not.toThrow();
    expect(page.listeners.size).toBe(0);
    expect(runtime.connectCalls).toEqual([]);

    const nextRuntime = new MockRuntime();
    const nextPage = new MockWindow();
    const next = new ProviderContentTransportOwner(nextPage, nextRuntime);
    nextPage.emit(requestEnvelope(signRequest()));
    next.dispose();
    next.dispose();
    expect(next.pendingCount).toBe(0);
    expect(nextPage.listeners.size).toBe(0);
    expect(nextRuntime.port.disconnectCalls).toBe(1);
  });

  it("carries one C16 promise over one lost Port without minting a second page request", async () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    page.dispatchPosts = true;
    const transport = new ProviderContentTransportOwner(page, runtime);
    const requestOwner = new ProviderPageRequestOwner(page, {
      randomSource: new FixedRandom(),
      timerSource: new InertTimers(),
    });
    const result = requestOwner.signTransaction({
      accountAddress: ACCOUNT,
      transaction: Uint8Array.of(1, 2, 3),
      chain: "solana:devnet",
      options: { preflightCommitment: "confirmed", minContextSlot: 42 },
    });
    const rejection = expect(result).rejects.toMatchObject({
      name: "ProviderPageTerminalError",
      code: "WARDEN_REQUEST_CANCELLED",
    } satisfies Partial<ProviderPageTerminalError>);
    const firstPort = runtime.port;
    const retained = firstPort.posted[0];

    firstPort.onDisconnect.emit();
    expect(runtime.port.posted[0]).toBe(retained);
    runtime.port.onMessage.emit(
      createProviderTerminalFailureResponse(
        PAGE_CORRELATION_ID,
        "WARDEN_REQUEST_CANCELLED",
      ),
    );

    await rejection;
    expect(requestOwner.pendingCount).toBe(0);
    expect(transport.pendingCount).toBe(0);
    expect(page.posted.filter(({ message }) =>
      (message as { readonly type?: unknown }).type === PAGE_PROVIDER_REQUEST_TYPE
    )).toHaveLength(1);
    requestOwner.dispose();
    transport.dispose();
  });
});
