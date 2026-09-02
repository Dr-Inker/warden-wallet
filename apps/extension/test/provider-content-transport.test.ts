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
  type ProviderContentMessagePort,
  type ProviderContentMessagePortListener,
  type ProviderContentTimerSource,
  type ProviderContentTransportOptions,
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
import {
  createProviderTransportCancelEnvelope,
  createPageProviderReceiptEnvelope,
  createProviderTransportReceiptEnvelope,
  createProviderTransportRequestEnvelope,
  createProviderTransportSettledEnvelope,
  createProviderTransportTerminalEnvelope,
  readProviderCapabilityEnvelope,
  readProviderTransportReceiptEnvelope,
  readProviderTransportCancelEnvelope,
  readProviderTransportTerminalEnvelope,
} from "../src/provider-delivery-protocol.js";

const ORIGIN = "https://dapp.example";
const ACCOUNT = "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";
const CORRELATION_ID = "content_request_0123456789";
const RECEIPT_ID = `delivery_${"cd".repeat(32)}`;
const DEFAULT_EXPIRES_AT = Date.now() + DEFAULT_PROVIDER_CONTENT_REQUEST_TTL_MS;

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
  autoSettleReceipts = true;

  postMessage(message: unknown): void {
    if (this.throwOnPost) throw new Error("Port is disconnected");
    this.posted.push(message);
    this.postHook?.(message);
    const receipt = readProviderTransportReceiptEnvelope(message);
    if (this.autoSettleReceipts && receipt !== null) {
      this.onMessage.emit(createProviderTransportSettledEnvelope(
        receipt.correlationId,
        receipt.receiptId,
        receipt.expiresAt,
      ));
    }
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
  autoSettleReceipts = true;
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
    port.autoSettleReceipts = this.autoSettleReceipts;
    this.ports.push(port);
    this.connectHook?.(port);
    return port;
  }
}

/**
 * One end of the X-1 capability channel. `port1` stays with the content owner;
 * `port2` is what the grant transfers into the document. A message posted on
 * one end reaches the other end's listeners, so the joint test wires a real
 * page owner through it; with nobody listening on the far end, `port1`
 * simulates the page's delivery receipt instead.
 */
class MockChannelPort implements ProviderContentMessagePort {
  readonly listeners = new Set<ProviderContentMessagePortListener>();
  readonly posted: unknown[] = [];
  peer: MockChannelPort | null = null;
  starts = 0;
  closes = 0;
  throwOnPost = false;
  autoReceipt = true;
  postHook: ((message: unknown) => void) | null = null;

  addEventListener(
    type: "message",
    listener: ProviderContentMessagePortListener,
  ): void {
    expect(type).toBe("message");
    this.listeners.add(listener);
  }

  removeEventListener(
    type: "message",
    listener: ProviderContentMessagePortListener,
  ): void {
    expect(type).toBe("message");
    this.listeners.delete(listener);
  }

  postMessage(message: unknown): void {
    if (this.throwOnPost) throw new Error("capability channel is closed");
    this.posted.push(message);
    this.postHook?.(message);
    const peer = this.peer;
    if (peer !== null && peer.listeners.size > 0) {
      peer.deliver(message);
      return;
    }
    if (!this.autoReceipt) return;
    const outer = message as { readonly type?: unknown; readonly payload?: unknown };
    if (outer.type !== PAGE_PROVIDER_RESPONSE_TYPE) return;
    const terminal = readProviderTransportTerminalEnvelope(outer.payload);
    if (terminal === null) return;
    this.deliver(createPageProviderReceiptEnvelope(
      createProviderTransportReceiptEnvelope(
        terminal.correlationId,
        terminal.receiptId,
        terminal.expiresAt,
      ),
    ));
  }

  start(): void {
    this.starts++;
  }

  close(): void {
    this.closes++;
  }

  deliver(data: unknown): void {
    for (const listener of [...this.listeners]) listener({ data });
  }
}

class MockChannel {
  readonly port1 = new MockChannelPort();
  readonly port2 = new MockChannelPort();

  constructor() {
    this.port1.peer = this.port2;
    this.port2.peer = this.port1;
  }
}

class MockWindow implements ContentWindowApi, ProviderPageWindowApi {
  readonly location = { origin: ORIGIN };
  readonly listeners = new Set<ContentWindowMessageListener>();
  readonly posted: Array<{ readonly message: unknown; readonly targetOrigin: string }> = [];
  readonly grants: Array<{
    readonly message: unknown;
    readonly targetOrigin: string;
    readonly transfer: readonly unknown[];
  }> = [];
  readonly channel = new MockChannel();
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

  postMessage(
    message: unknown,
    targetOrigin: string,
    transfer?: readonly unknown[],
  ): void {
    if (this.throwOnPost) throw new Error("document disappeared");
    // The capability grant is recorded apart from ordinary page traffic so
    // every `posted` assertion stays about what a page script can observe.
    if (readProviderCapabilityEnvelope(message) !== null) {
      this.grants.push({ message, targetOrigin, transfer: transfer ?? [] });
      return;
    }
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

  /** Replay the recorded grant into the document, transfer list included. */
  handOffCapability(): void {
    const grant = this.grants.at(-1);
    if (grant === undefined) throw new Error("no capability grant was posted");
    this.emit(grant.message, { ports: grant.transfer } as never);
  }
}

function transport(
  page: MockWindow,
  runtime: MockRuntime,
  options: ProviderContentTransportOptions = {},
): ProviderContentTransportOwner {
  return new ProviderContentTransportOwner(page, runtime, {
    channelSource: () => page.channel,
    ...options,
  });
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

function requestEnvelope(
  payload: unknown,
  expiresAt = DEFAULT_EXPIRES_AT,
): Record<string, unknown> {
  return {
    version: 1,
    type: PAGE_PROVIDER_REQUEST_TYPE,
    payload: createProviderTransportRequestEnvelope(expiresAt, payload),
  };
}

function responseEnvelope(payload: unknown): Record<string, unknown> {
  const response = payload as { readonly correlationId: string };
  return {
    version: 1,
    type: PAGE_PROVIDER_RESPONSE_TYPE,
    payload: createProviderTransportTerminalEnvelope(
      response.correlationId,
      RECEIPT_ID,
      DEFAULT_EXPIRES_AT,
      payload,
    ),
  };
}

function terminalEnvelope(payload: unknown, expiresAt = DEFAULT_EXPIRES_AT) {
  const response = payload as { readonly correlationId: string };
  return createProviderTransportTerminalEnvelope(
    response.correlationId,
    RECEIPT_ID,
    expiresAt,
    payload,
  );
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
    const owner = transport(page, runtime);
    const transaction = [1, 2, 3];
    const request = signRequest(CORRELATION_ID, transaction);

    page.emit({ type: "analytics" });
    expect(runtime.connectCalls).toEqual([]);
    page.emit(requestEnvelope(request));
    transaction[0] = 255;
    request.params.accountAddress = "attacker";

    expect(runtime.connectCalls).toEqual([{ name: PROVIDER_PORT_NAME }]);
    expect(runtime.port.posted).toEqual([
      createProviderTransportRequestEnvelope(DEFAULT_EXPIRES_AT, signRequest()),
    ]);
    expect(runtime.port.posted[0]).not.toBe(request);
    expect(owner.pendingCount).toBe(1);
    expect(owner.issuedCount).toBe(1);
  });

  it("resends the identical retained payload once after worker Port loss", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = transport(page, runtime);
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
    const owner = transport(page, runtime);
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
    const owner = transport(page, runtime);
    page.emit(requestEnvelope(signRequest()));
    const port = runtime.port;
    port.onMessage.emit(
      terminalEnvelope(
        createProviderTerminalFailureResponse(CORRELATION_ID, "WARDEN_USER_REJECTED"),
      ),
    );
    expect(owner.pendingCount).toBe(0);

    port.onDisconnect.emit();

    expect(runtime.ports).toHaveLength(1);
    expect(runtime.connectCalls).toHaveLength(1);
  });

  it("forwards the existing exact unavailable response without widening it", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = transport(page, runtime);
    page.emit(requestEnvelope(signRequest()));

    runtime.port.onMessage.emit(terminalEnvelope(
      createUnavailableProviderResponse(CORRELATION_ID),
    ));

    expect(owner.pendingCount).toBe(0);
    // The terminal crosses the capability, never the window.
    expect(page.posted).toEqual([]);
    expect(page.channel.port1.posted).toEqual([
      responseEnvelope(createUnavailableProviderResponse(CORRELATION_ID)),
    ]);
  });

  it("ignores a stale Port and retains pending state until page receipt", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = transport(page, runtime);
    page.emit(requestEnvelope(signRequest()));
    const firstPort = runtime.port;
    firstPort.onDisconnect.emit();
    const secondPort = runtime.port;
    let observedPending = -1;
    page.channel.port1.postHook = () => {
      observedPending = owner.pendingCount;
    };

    firstPort.onMessage.emit(
      terminalEnvelope(
        createSignedTransactionProviderResponse(CORRELATION_ID, Uint8Array.of(7)),
      ),
    );
    expect(page.channel.port1.posted).toEqual([]);
    secondPort.onMessage.emit(
      terminalEnvelope(
        createProviderTerminalFailureResponse(CORRELATION_ID, "WARDEN_REQUEST_CANCELLED"),
      ),
    );

    expect(observedPending).toBe(1);
    expect(owner.pendingCount).toBe(0);
    expect(page.channel.port1.posted).toEqual([
      responseEnvelope(
        createProviderTerminalFailureResponse(
          CORRELATION_ID,
          "WARDEN_REQUEST_CANCELLED",
        ),
      ),
    ]);
  });

  it("recovers a lost receipt and retains state until the exact settled ack", () => {
    const runtime = new MockRuntime();
    runtime.autoSettleReceipts = false;
    const page = new MockWindow();
    page.channel.port1.autoReceipt = false;
    const owner = transport(page, runtime);
    page.emit(requestEnvelope(signRequest()));
    const firstPort = runtime.port;
    const retainedRequest = firstPort.posted[0];
    const terminal = terminalEnvelope(
      createProviderTerminalFailureResponse(
        CORRELATION_ID,
        "WARDEN_REQUEST_CANCELLED",
      ),
    );
    const receipt = createProviderTransportReceiptEnvelope(
      CORRELATION_ID,
      RECEIPT_ID,
      DEFAULT_EXPIRES_AT,
    );

    firstPort.onMessage.emit(terminal);
    expect(owner.pendingCount).toBe(1);
    expect(page.channel.port1.posted).toHaveLength(1);

    page.channel.port1.deliver(createPageProviderReceiptEnvelope(receipt));
    expect(owner.pendingCount).toBe(1);
    expect(firstPort.posted).toEqual([retainedRequest, receipt]);

    firstPort.onDisconnect.emit();
    const replacement = runtime.port;
    expect(replacement.posted).toEqual([retainedRequest]);
    replacement.onMessage.emit(terminal);

    expect(owner.pendingCount).toBe(1);
    expect(page.channel.port1.posted).toHaveLength(1);
    expect(replacement.posted).toEqual([retainedRequest, receipt]);

    replacement.onMessage.emit(createProviderTransportSettledEnvelope(
      CORRELATION_ID,
      RECEIPT_ID,
      DEFAULT_EXPIRES_AT,
    ));
    expect(owner.pendingCount).toBe(0);
  });

  it("copies strict signed bytes before forwarding and ignores an unknown terminal id", () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = transport(page, runtime);
    page.emit(requestEnvelope(signRequest()));

    runtime.port.onMessage.emit(
      terminalEnvelope(
        createSignedTransactionProviderResponse(
          "content_unknown_01234567",
          Uint8Array.of(1),
        ),
      ),
    );
    expect(owner.pendingCount).toBe(1);
    expect(page.channel.port1.posted).toEqual([]);

    const response = {
      version: 1,
      type: "response",
      correlationId: CORRELATION_ID,
      ok: true,
      result: { signedTransaction: [9, 8, 7] },
    };
    runtime.port.onMessage.emit(terminalEnvelope(response));
    response.result.signedTransaction[0] = 0;

    expect(page.channel.port1.posted).toEqual([
      responseEnvelope(
        createSignedTransactionProviderResponse(
          CORRELATION_ID,
          Uint8Array.of(9, 8, 7),
        ),
      ),
    ]);
  });

  it("uses the single recovery budget for a synchronous stale-Port failure", () => {
    const runtime = new MockRuntime();
    runtime.throwOnEveryPost = true;
    const page = new MockWindow();
    const owner = transport(page, runtime);

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
    const owner = transport(page, runtime);
    page.emit(requestEnvelope(signRequest()));

    expect(runtime.connectCalls).toHaveLength(2);
    expect(runtime.ports).toHaveLength(1);
    expect(runtime.port.posted).toEqual([
      createProviderTransportRequestEnvelope(DEFAULT_EXPIRES_AT, signRequest()),
    ]);
    runtime.port.onDisconnect.emit();
    expect(runtime.connectCalls).toHaveLength(2);
    expect(owner.pendingCount).toBe(1);
  });

  it("evicts by absolute time without fabricating a page terminal response", () => {
    let now = 1_000;
    const timers = new ContentTimers();
    const runtime = new MockRuntime();
    const page = new MockWindow();
    const owner = transport(page, runtime, {
      readNow: () => now,
      requestTtlMs: 100,
      timerSource: timers,
    });
    page.emit(requestEnvelope(signRequest(), 1_100));
    const port = runtime.port;
    expect([...timers.timers.values()].map(({ delayMs }) => delayMs)).toEqual([100]);

    now = 1_050;
    timers.fire(1);
    expect(owner.pendingCount).toBe(1);
    expect([...timers.timers.values()].map(({ delayMs }) => delayMs)).toEqual([50]);

    now = 1_100;
    timers.fire(2);
    const cancellation = readProviderTransportCancelEnvelope(port.posted.at(-1));
    expect(cancellation).toEqual(createProviderTransportCancelEnvelope(
      1_100,
      signRequest(),
    ));
    port.onMessage.emit(
      terminalEnvelope(
        createProviderTerminalFailureResponse(CORRELATION_ID, "WARDEN_REQUEST_EXPIRED"),
        1_100,
      ),
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
    const initial = transport(initialPage, initialRuntime, {
      readNow: () => initialNow,
      requestTtlMs: 100,
      timerSource: initialTimers,
    });
    initialPage.emit(requestEnvelope(signRequest("content_expiry_initial_01"), 1_100));

    expect(initialRuntime.port.posted).toEqual([]);
    expect(initial.pendingCount).toBe(0);

    let recoveryNow = 2_000;
    const recoveryTimers = new ContentTimers();
    const recoveryRuntime = new MockRuntime();
    const recoveryPage = new MockWindow();
    const recovery = transport(
      recoveryPage,
      recoveryRuntime,
      {
        readNow: () => recoveryNow,
        requestTtlMs: 100,
        timerSource: recoveryTimers,
      },
    );
    recoveryPage.emit(requestEnvelope(signRequest("content_expiry_recover_01"), 2_100));
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
    const owner = transport(page, runtime);
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
    const first = transport(firstPage, firstRuntime);
    firstPage.emit(requestEnvelope(signRequest()));
    firstPage.emit(requestEnvelope(signRequest()));

    expect(first.pendingCount).toBe(0);
    expect(firstPage.listeners.size).toBe(0);
    expect(firstRuntime.port.disconnectCalls).toBe(1);

    const secondRuntime = new MockRuntime();
    const secondPage = new MockWindow();
    transport(secondPage, secondRuntime);
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
    const owner = transport(page, runtime, {
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
    const owner = transport(page, runtime);
    const revoked = Proxy.revocable(signRequest(), {});
    revoked.revoke();

    expect(() => page.emit(requestEnvelope(revoked.proxy))).not.toThrow();
    expect(page.listeners.size).toBe(0);
    expect(runtime.connectCalls).toEqual([]);

    const nextRuntime = new MockRuntime();
    const nextPage = new MockWindow();
    const next = transport(nextPage, nextRuntime);
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
    const contentOwner = transport(page, runtime);
    const requestOwner = new ProviderPageRequestOwner(page, {
      randomSource: new FixedRandom(),
      timerSource: new InertTimers(),
    });
    // The content owner minted the grant at `document_start`; hand the
    // transferred port to the main-world owner exactly as Chrome would.
    page.handOffCapability();
    expect(requestOwner.hasCapability).toBe(true);
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
      terminalEnvelope(
        createProviderTerminalFailureResponse(
          PAGE_CORRELATION_ID,
          "WARDEN_REQUEST_CANCELLED",
        ),
        ((retained as { readonly expiresAt: number }).expiresAt),
      ),
    );

    await rejection;
    expect(requestOwner.pendingCount).toBe(0);
    expect(contentOwner.pendingCount).toBe(0);
    expect(page.posted.filter(({ message }) =>
      (message as { readonly type?: unknown }).type === PAGE_PROVIDER_REQUEST_TYPE
    )).toHaveLength(1);
    // The terminal and its receipt never touched `window`.
    expect(page.posted.filter(({ message }) =>
      (message as { readonly type?: unknown }).type !== PAGE_PROVIDER_REQUEST_TYPE
    )).toEqual([]);
    requestOwner.dispose();
    contentOwner.dispose();
  });

  it("refuses to settle a page promise from a same-window forgery end to end", async () => {
    const runtime = new MockRuntime();
    const page = new MockWindow();
    page.dispatchPosts = true;
    const contentOwner = transport(page, runtime);
    const requestOwner = new ProviderPageRequestOwner(page, {
      randomSource: new FixedRandom(),
      timerSource: new InertTimers(),
    });
    page.handOffCapability();
    const result = requestOwner.signTransaction({
      accountAddress: ACCOUNT,
      transaction: Uint8Array.of(1, 2, 3),
      chain: "solana:devnet",
      options: { preflightCommitment: "confirmed", minContextSlot: 42 },
    });
    const retained = runtime.port.posted[0] as { readonly expiresAt: number };

    // A same-document script replays the exact envelope shape the capability
    // carries, on the window, with the correlation and deadline it just saw.
    page.emit({
      version: 1,
      type: PAGE_PROVIDER_RESPONSE_TYPE,
      payload: terminalEnvelope(
        createSignedTransactionProviderResponse(
          PAGE_CORRELATION_ID,
          Uint8Array.of(6, 6, 6),
        ),
        retained.expiresAt,
      ),
    });
    expect(requestOwner.pendingCount).toBe(1);

    runtime.port.onMessage.emit(terminalEnvelope(
      createSignedTransactionProviderResponse(
        PAGE_CORRELATION_ID,
        Uint8Array.of(1, 2, 3),
      ),
      retained.expiresAt,
    ));

    await expect(result).resolves.toEqual(Uint8Array.of(1, 2, 3));
    expect(contentOwner.pendingCount).toBe(0);
    requestOwner.dispose();
    contentOwner.dispose();
  });
});
