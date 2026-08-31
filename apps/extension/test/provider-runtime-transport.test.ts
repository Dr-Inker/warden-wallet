import { describe, expect, it, vi } from "vitest";

import {
  createProviderTerminalFailureResponse,
  type ProviderTerminalResponse,
} from "../src/background/provider-terminal-protocol.js";
import {
  MAX_PENDING_PROVIDER_REQUESTS,
  PROVIDER_PORT_NAME,
  type ProviderConnectEvent,
  type ProviderDisconnectEvent,
  type ProviderMessageEvent,
  type ProviderRandomSource,
  type ProviderRuntimeApi,
  type ProviderRuntimePort,
  type ProviderTimerSource,
} from "../src/background/provider-port.js";
import type { ProviderOperationDigestSource } from "../src/background/provider-operation.js";
import {
  MAX_PROVIDER_RUNTIME_REPLAYS_PER_REQUEST,
  ProviderRuntimeTransportOwner,
  type ProviderRuntimeTransportFlow,
  type ProviderRuntimeTransportLease,
} from "../src/background/provider-runtime-transport.js";
import {
  createProviderTransportCancelEnvelope,
  createProviderTransportReceiptEnvelope,
  createProviderTransportRequestEnvelope,
  readProviderTransportSettledEnvelope,
  readProviderTransportTerminalEnvelope,
  type ProviderTransportRequestEnvelope,
} from "../src/provider-delivery-protocol.js";

const EXTENSION_ID = "a".repeat(32);
const DOCUMENT_ID = "123e4567-e89b-12d3-a456-426614174000";
const ACCOUNT = "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";
const CORRELATION_ID = "runtime_request_01234567";
const DEFAULT_EXPIRES_AT = Date.now() + 2 * 60 * 1_000;

function providerSender(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    documentId: DOCUMENT_ID,
    documentLifecycle: "active",
    frameId: 4,
    id: EXTENSION_ID,
    origin: "https://dapp.example",
    tab: { id: 19, url: "https://dapp.example/app" },
    url: "https://dapp.example/app",
    ...overrides,
  };
}

function request(
  correlationId = CORRELATION_ID,
  transaction: number[] = [1, 2, 3],
  expiresAt = DEFAULT_EXPIRES_AT,
): ProviderTransportRequestEnvelope {
  return createProviderTransportRequestEnvelope(expiresAt, {
    version: 1,
    type: "request",
    correlationId,
    method: "solana:signTransaction",
    params: {
      accountAddress: ACCOUNT,
      transaction,
      chain: "solana:devnet",
      options: { preflightCommitment: "confirmed", minContextSlot: 42 },
    },
  });
}

class MessageEventOwner implements ProviderMessageEvent {
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

class DisconnectEventOwner implements ProviderDisconnectEvent {
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

class ConnectEventOwner implements ProviderConnectEvent {
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
  readonly onMessage = new MessageEventOwner();
  readonly onDisconnect = new DisconnectEventOwner();
  readonly posted: unknown[] = [];
  disconnectCalls = 0;
  throwOnPost = false;
  postHook: (() => void) | null = null;

  constructor(
    readonly name = PROVIDER_PORT_NAME,
    readonly sender: unknown = providerSender(),
  ) {}

  postMessage(message: unknown): void {
    if (this.throwOnPost) throw new Error("Port is disconnected");
    this.posted.push(message);
    this.postHook?.();
  }

  disconnect(): void {
    this.disconnectCalls++;
    this.onDisconnect.emit();
  }
}

class MockRuntime implements ProviderRuntimeApi {
  readonly id = EXTENSION_ID;
  readonly onConnect = new ConnectEventOwner();
}

class CounterRandom implements ProviderRandomSource {
  count = 0;

  getRandomValues(target: Uint8Array): Uint8Array {
    target.fill(0);
    target[target.length - 1] = ++this.count;
    return target;
  }
}

class InertTimers implements ProviderTimerSource {
  setTimeout(): unknown {
    return 1;
  }

  clearTimeout(): void {}
}

class FirstDigestGate implements ProviderOperationDigestSource {
  calls = 0;
  completed = 0;
  private release: (() => void) | null = null;

  async digest(bytes: Uint8Array): Promise<Uint8Array> {
    this.calls++;
    if (this.calls === 1) {
      await new Promise<void>((resolve) => {
        this.release = resolve;
      });
    }
    const result = new Uint8Array(
      await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes).buffer),
    );
    this.completed++;
    return result;
  }

  releaseFirst(): void {
    if (this.release === null) throw new Error("first digest is not pending");
    const release = this.release;
    this.release = null;
    release();
  }
}

class CountingDigest implements ProviderOperationDigestSource {
  calls = 0;
  completed = 0;

  async digest(bytes: Uint8Array): Promise<Uint8Array> {
    this.calls++;
    const result = new Uint8Array(
      await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes).buffer),
    );
    this.completed++;
    return result;
  }
}

class NeverDigest implements ProviderOperationDigestSource {
  calls = 0;

  digest(): Promise<Uint8Array> {
    this.calls++;
    return new Promise(() => {});
  }
}

class DeferredFlow implements ProviderRuntimeTransportFlow {
  readonly leases: ProviderRuntimeTransportLease[] = [];
  readonly resolvers: Array<(value: unknown) => void> = [];

  deliver(lease: ProviderRuntimeTransportLease): Promise<unknown> {
    this.leases.push(lease);
    return new Promise((resolve) => this.resolvers.push(resolve));
  }
}

function owner(
  runtime: MockRuntime,
  flow: ProviderRuntimeTransportFlow,
  overrides: {
    readNow?: () => number;
    requestTtlMs?: number;
    digestSource?: ProviderOperationDigestSource;
  } = {},
): ProviderRuntimeTransportOwner {
  return new ProviderRuntimeTransportOwner(runtime, flow, {
    randomSource: new CounterRandom(),
    timerSource: new InertTimers(),
    ...overrides,
  });
}

async function eventually(assertion: () => void): Promise<void> {
  await vi.waitFor(assertion, { timeout: 2_000, interval: 1 });
}

function failure(correlationId = CORRELATION_ID): ProviderTerminalResponse {
  return createProviderTerminalFailureResponse(
    correlationId,
    "WARDEN_REQUEST_CANCELLED",
  );
}

function terminalPayloads(port: MockPort): unknown[] {
  return port.posted.flatMap((message) => {
    const terminal = readProviderTransportTerminalEnvelope(message);
    return terminal === null ? [] : [terminal.payload];
  });
}

function receiptFor(port: MockPort, index = 0) {
  const terminals = port.posted.flatMap((message) => {
    const terminal = readProviderTransportTerminalEnvelope(message);
    return terminal === null ? [] : [terminal];
  });
  const terminal = terminals[index];
  if (terminal === undefined) throw new Error("terminal delivery is absent");
  return createProviderTransportReceiptEnvelope(
    terminal.correlationId,
    terminal.receiptId,
    terminal.expiresAt,
  );
}

describe("C22 background delivery settlement transport", () => {
  it("preserves one live lease across an overlapping exact replacement", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const digestSource = new CountingDigest();
    const transport = owner(runtime, flow, { digestSource });
    const first = new MockPort();
    runtime.onConnect.emit(first);
    first.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(1));
    const lease = flow.leases[0]!;
    const owned = lease.owned;

    const replacement = new MockPort();
    runtime.onConnect.emit(replacement);
    replacement.onMessage.emit(request());
    await eventually(() => expect(digestSource.completed).toBe(4));

    expect(first.disconnectCalls).toBe(1);
    expect(first.onMessage.listeners.size).toBe(0);
    expect(first.onDisconnect.listeners.size).toBe(0);
    expect(flow.leases).toEqual([lease]);
    expect(lease.owned).toBe(owned);
    expect(() => lease.assertActive()).not.toThrow();

    lease.postMessage(failure());
    expect(lease.finish()).toBe(true);
    flow.resolvers[0]?.(Object.freeze({ kind: "delivered", replayed: false }));
    expect(first.posted).toEqual([]);
    expect(terminalPayloads(replacement)).toEqual([failure()]);
    transport.dispose();
  });

  it("does not let a superseded Port mint authority after operation hashing", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const digestSource = new FirstDigestGate();
    const transport = owner(runtime, flow, { digestSource });
    const first = new MockPort();
    runtime.onConnect.emit(first);
    first.onMessage.emit(request());
    await eventually(() => expect(digestSource.calls).toBe(1));

    const replacement = new MockPort();
    runtime.onConnect.emit(replacement);
    digestSource.releaseFirst();
    await eventually(() => expect(digestSource.completed).toBe(2));
    await Promise.resolve();

    expect(flow.leases).toEqual([]);
    replacement.onMessage.emit(request());
    await eventually(() => expect(digestSource.completed).toBe(4));

    expect(flow.leases).toHaveLength(1);
    expect(first.disconnectCalls).toBe(1);
    flow.leases[0]!.postMessage(failure());
    expect(flow.leases[0]!.finish()).toBe(true);
    flow.resolvers[0]?.(Object.freeze({ kind: "delivered", replayed: false }));
    expect(first.posted).toEqual([]);
    expect(terminalPayloads(replacement)).toEqual([failure()]);
    transport.dispose();
  });

  it("does not deliver to a replacement before its exact request is verified", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow);
    const first = new MockPort();
    runtime.onConnect.emit(first);
    first.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(1));

    const replacement = new MockPort();
    runtime.onConnect.emit(replacement);

    expect(() => flow.leases[0]!.assertActive()).not.toThrow();
    expect(() => flow.leases[0]!.postMessage(failure())).toThrow(
      "delivery Port has not presented the exact request",
    );
    expect(first.posted).toEqual([]);
    expect(replacement.posted).toEqual([]);
    transport.dispose();
  });

  it("moves multiple exact live correlations without cross-routing them", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const digestSource = new CountingDigest();
    const transport = owner(runtime, flow, { digestSource });
    const first = new MockPort();
    const firstCorrelation = "runtime_multi_first_0001";
    const secondCorrelation = "runtime_multi_second_001";
    runtime.onConnect.emit(first);
    first.onMessage.emit(request(firstCorrelation, [1, 2, 3]));
    first.onMessage.emit(request(secondCorrelation, [4, 5, 6]));
    await eventually(() => expect(flow.leases).toHaveLength(2));
    expect(digestSource.completed).toBe(4);

    const replacement = new MockPort();
    runtime.onConnect.emit(replacement);
    replacement.onMessage.emit(request(firstCorrelation, [1, 2, 3]));
    replacement.onMessage.emit(request(secondCorrelation, [4, 5, 6]));
    await eventually(() => expect(digestSource.completed).toBe(8));

    expect(flow.leases).toHaveLength(2);
    for (let index = 0; index < flow.leases.length; index++) {
      const lease = flow.leases[index]!;
      lease.postMessage(failure(lease.owned.request.correlationId));
      expect(lease.finish()).toBe(true);
      flow.resolvers[index]?.(Object.freeze({ kind: "delivered", replayed: false }));
    }
    expect(first.posted).toEqual([]);
    expect(terminalPayloads(replacement)).toEqual([
      failure(firstCorrelation),
      failure(secondCorrelation),
    ]);
    transport.dispose();
  });

  it("bounds messages queued behind a stalled operation digest", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const digestSource = new NeverDigest();
    const transport = owner(runtime, flow, { digestSource });
    const port = new MockPort();
    runtime.onConnect.emit(port);
    port.onMessage.emit(request("runtime_queue_00000000"));
    await eventually(() => expect(digestSource.calls).toBe(1));

    for (let index = 1; index < MAX_PENDING_PROVIDER_REQUESTS; index++) {
      port.onMessage.emit(request(`runtime_queue_${index.toString().padStart(8, "0")}`));
    }
    expect(port.disconnectCalls).toBe(0);
    port.onMessage.emit(request("runtime_queue_over_capacity"));

    expect(port.disconnectCalls).toBe(1);
    expect(transport.activeDocumentCount).toBe(0);
    expect(flow.leases).toEqual([]);
    transport.dispose();
  });

  it("does not mint authority when hashing crosses the receive deadline", async () => {
    let now = 1_000;
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const digestSource = new FirstDigestGate();
    const transport = owner(runtime, flow, {
      digestSource,
      readNow: () => now,
      requestTtlMs: 100,
    });
    const port = new MockPort();
    runtime.onConnect.emit(port);
    port.onMessage.emit(request(CORRELATION_ID, [1, 2, 3], 1_100));
    await eventually(() => expect(digestSource.calls).toBe(1));

    now = 1_100;
    digestSource.releaseFirst();
    await eventually(() => expect(port.disconnectCalls).toBe(1));

    expect(flow.leases).toEqual([]);
    expect(transport.activeDocumentCount).toBe(0);
    transport.dispose();
  });

  it("makes an old callback powerless after replacement", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow);
    const first = new MockPort();
    runtime.onConnect.emit(first);
    first.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(1));
    const staleMessage = [...first.onMessage.listeners][0]!;
    const staleDisconnect = [...first.onDisconnect.listeners][0]!;

    const replacement = new MockPort();
    runtime.onConnect.emit(replacement);
    staleMessage(request("runtime_stale_01234567"));
    staleDisconnect();

    expect(transport.activeDocumentCount).toBe(1);
    expect(flow.leases).toHaveLength(1);
    replacement.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(1));
    transport.dispose();
  });

  it("aborts the old volatile lease when disconnect wins before reconnect", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow);
    const first = new MockPort();
    runtime.onConnect.emit(first);
    first.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(1));
    const oldLease = flow.leases[0]!;

    first.onDisconnect.emit();
    expect(() => oldLease.assertActive()).toThrow();
    expect(oldLease.owned.signal.aborted).toBe(true);

    const replacement = new MockPort();
    runtime.onConnect.emit(replacement);
    replacement.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(2));
    const newLease = flow.leases[1]!;

    expect(newLease.owned).not.toBe(oldLease.owned);
    expect(newLease.owned.id).not.toBe(oldLease.owned.id);
    expect(newLease.owned.provenance).toEqual(oldLease.owned.provenance);
    expect(newLease.owned.request).toEqual(oldLease.owned.request);
    expect(() => newLease.assertActive()).not.toThrow();
    transport.dispose();
  });

  it("reposts one staged terminal on a verified replacement and settles only on receipt", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow);
    const first = new MockPort();
    runtime.onConnect.emit(first);
    first.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(1));
    flow.leases[0]!.postMessage(failure());
    expect(flow.leases[0]!.finish()).toBe(true);
    flow.resolvers[0]?.(Object.freeze({ kind: "delivered", replayed: false }));

    const replacement = new MockPort();
    runtime.onConnect.emit(replacement);
    replacement.onMessage.emit(request());
    await eventually(() => expect(terminalPayloads(replacement)).toEqual([failure()]));

    expect(flow.leases).toHaveLength(1);
    expect(() => flow.leases[0]!.assertActive()).not.toThrow();
    replacement.onMessage.emit(receiptFor(replacement));
    await eventually(() => expect(replacement.posted.some((message) =>
      readProviderTransportSettledEnvelope(message) !== null
    )).toBe(true));
    expect(() => flow.leases[0]!.assertActive()).toThrow();
    replacement.onMessage.emit(request());
    await eventually(() => expect(replacement.disconnectCalls).toBe(1));
    expect(flow.leases).toHaveLength(1);
    expect(MAX_PROVIDER_RUNTIME_REPLAYS_PER_REQUEST).toBe(1);
    transport.dispose();
  });

  it("refuses a receipt that arrives before the flow finishes delivery", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow);
    const port = new MockPort();
    runtime.onConnect.emit(port);
    port.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(1));

    flow.leases[0]!.postMessage(failure());
    port.onMessage.emit(receiptFor(port));
    await eventually(() => expect(port.disconnectCalls).toBe(1));

    expect(flow.leases[0]!.owned.signal.aborted).toBe(true);
    expect(flow.leases[0]!.finish()).toBe(false);
    expect(transport.activeDocumentCount).toBe(0);
  });

  it("refuses settlement until the flow returns exact delivery proof", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow);
    const port = new MockPort();
    runtime.onConnect.emit(port);
    port.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(1));
    const lease = flow.leases[0]!;

    lease.postMessage(failure());
    expect(lease.finish()).toBe(true);
    port.onMessage.emit(receiptFor(port));
    await eventually(() => expect(port.disconnectCalls).toBe(1));

    expect(lease.owned.signal.aborted).toBe(true);
    expect(transport.activeDocumentCount).toBe(0);
  });

  it("refuses a forged receipt after terminal enqueue and flow completion", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow);
    const port = new MockPort();
    runtime.onConnect.emit(port);
    port.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(1));
    const lease = flow.leases[0]!;
    lease.postMessage(failure());
    expect(lease.finish()).toBe(true);
    flow.resolvers[0]?.(Object.freeze({ kind: "delivered", replayed: false }));
    const exact = receiptFor(port);

    port.onMessage.emit(createProviderTransportReceiptEnvelope(
      exact.correlationId,
      `delivery_${"ff".repeat(32)}`,
      exact.expiresAt,
    ));
    await eventually(() => expect(port.disconnectCalls).toBe(1));

    expect(lease.owned.signal.aborted).toBe(true);
    expect(transport.activeDocumentCount).toBe(0);
  });

  it("accepts only an exact identity-bound cancellation at the carried deadline", async () => {
    let now = 1_000;
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow, {
      readNow: () => now,
      requestTtlMs: 100,
    });
    const port = new MockPort();
    const carried = request(CORRELATION_ID, [1, 2, 3], 1_100) as {
      readonly payload: unknown;
    };
    runtime.onConnect.emit(port);
    port.onMessage.emit(carried);
    await eventually(() => expect(flow.leases).toHaveLength(1));

    now = 1_100;
    port.onMessage.emit(createProviderTransportCancelEnvelope(
      1_100,
      carried.payload,
    ));
    await eventually(() => expect(flow.leases[0]!.owned.signal.aborted).toBe(true));

    expect(terminalPayloads(port)).toEqual([]);
    expect(port.disconnectCalls).toBe(0);
    expect(transport.activeDocumentCount).toBe(1);
    transport.dispose();
  });

  it("fails closed when one correlation changes payload on replacement", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow);
    const first = new MockPort();
    runtime.onConnect.emit(first);
    first.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(1));

    const replacement = new MockPort();
    runtime.onConnect.emit(replacement);
    replacement.onMessage.emit(request(CORRELATION_ID, [9, 9, 9]));
    await eventually(() => expect(replacement.disconnectCalls).toBe(1));

    expect(flow.leases).toHaveLength(1);
    expect(flow.leases[0]!.owned.signal.aborted).toBe(true);
    expect(transport.activeDocumentCount).toBe(0);
  });

  it("fails closed when an exact replay changes the carried deadline", async () => {
    let now = 1_000;
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow, {
      readNow: () => now,
      requestTtlMs: 100,
    });
    const first = new MockPort();
    runtime.onConnect.emit(first);
    first.onMessage.emit(request(CORRELATION_ID, [1, 2, 3], 1_100));
    await eventually(() => expect(flow.leases).toHaveLength(1));

    now = 1_050;
    const replacement = new MockPort();
    runtime.onConnect.emit(replacement);
    replacement.onMessage.emit(request(CORRELATION_ID, [1, 2, 3], 1_149));
    await eventually(() => expect(replacement.disconnectCalls).toBe(1));

    expect(flow.leases).toHaveLength(1);
    expect(flow.leases[0]!.owned.signal.aborted).toBe(true);
    expect(transport.activeDocumentCount).toBe(0);
  });

  it("refuses provenance drift under the same browser document id", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow);
    const first = new MockPort();
    runtime.onConnect.emit(first);
    first.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(1));

    const collision = new MockPort(
      PROVIDER_PORT_NAME,
      providerSender({
        origin: "https://other.example",
        url: "https://other.example/",
      }),
    );
    runtime.onConnect.emit(collision);

    expect(first.disconnectCalls).toBe(1);
    expect(collision.disconnectCalls).toBe(1);
    expect(flow.leases[0]!.owned.signal.aborted).toBe(true);
    expect(transport.activeDocumentCount).toBe(0);
  });

  it("does not release delivery ownership across a re-entrant Port replacement", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow);
    const first = new MockPort();
    runtime.onConnect.emit(first);
    first.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(1));
    const lease = flow.leases[0]!;
    const replacement = new MockPort();
    first.postHook = () => runtime.onConnect.emit(replacement);

    expect(() => lease.postMessage(failure())).toThrow();
    expect(lease.finish()).toBe(false);
    expect(terminalPayloads(first)).toEqual([failure()]);
    expect(replacement.posted).toEqual([]);
    transport.dispose();
  });

  it("contains malformed Ports, senders, requests, and dependency results", async () => {
    const runtime = new MockRuntime();
    const flow: ProviderRuntimeTransportFlow = {
      async deliver(lease): Promise<unknown> {
        lease.assertActive();
        return { kind: "delivered", replayed: "yes" };
      },
    };
    const transport = owner(runtime, flow);
    const wrongName = new MockPort("other");
    const wrongSender = new MockPort(
      PROVIDER_PORT_NAME,
      providerSender({ id: "b".repeat(32) }),
    );
    runtime.onConnect.emit(wrongName);
    runtime.onConnect.emit(wrongSender);
    expect(wrongName.disconnectCalls).toBe(1);
    expect(wrongSender.disconnectCalls).toBe(1);

    const malformed = new MockPort();
    runtime.onConnect.emit(malformed);
    malformed.onMessage.emit({ privateKey: "must-not-cross" });
    await eventually(() => expect(malformed.disconnectCalls).toBe(1));

    const badResult = new MockPort();
    runtime.onConnect.emit(badResult);
    badResult.onMessage.emit(request("runtime_bad_result_0001"));
    await eventually(() => expect(badResult.disconnectCalls).toBe(1));
    expect(transport.activeDocumentCount).toBe(0);
    transport.dispose();
  });

  it("keeps the first absolute deadline when a finished request is replayed", async () => {
    let now = 1_000;
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow, {
      readNow: () => now,
      requestTtlMs: 100,
    });
    const first = new MockPort();
    runtime.onConnect.emit(first);
    first.onMessage.emit(request(CORRELATION_ID, [1, 2, 3], 1_100));
    await eventually(() => expect(flow.leases).toHaveLength(1));
    expect(flow.leases[0]!.owned.expiresAt).toBe(1_100);
    flow.leases[0]!.postMessage(failure());
    expect(flow.leases[0]!.finish()).toBe(true);
    flow.resolvers[0]?.(Object.freeze({ kind: "delivered", replayed: false }));
    first.onDisconnect.emit();

    now = 1_050;
    const replacement = new MockPort();
    runtime.onConnect.emit(replacement);
    replacement.onMessage.emit(request(CORRELATION_ID, [1, 2, 3], 1_100));
    await eventually(() => expect(flow.leases).toHaveLength(2));
    expect(flow.leases[1]!.owned.createdAt).toBe(1_050);
    expect(flow.leases[1]!.owned.expiresAt).toBe(1_100);

    now = 1_100;
    const afterDeadline = new MockPort();
    runtime.onConnect.emit(afterDeadline);
    afterDeadline.onMessage.emit(request(CORRELATION_ID, [1, 2, 3], 1_100));
    await eventually(() => expect(afterDeadline.disconnectCalls).toBe(1));
    expect(flow.leases).toHaveLength(2);
    transport.dispose();
  });

  it("scrubs all document leases on disposal", async () => {
    const runtime = new MockRuntime();
    const flow = new DeferredFlow();
    const transport = owner(runtime, flow);
    const port = new MockPort();
    runtime.onConnect.emit(port);
    port.onMessage.emit(request());
    await eventually(() => expect(flow.leases).toHaveLength(1));

    transport.dispose();
    transport.dispose();

    expect(flow.leases[0]!.owned.signal.aborted).toBe(true);
    expect(port.disconnectCalls).toBe(1);
    expect(runtime.onConnect.listeners.size).toBe(0);
    expect(transport.activeDocumentCount).toBe(0);
  });
});
