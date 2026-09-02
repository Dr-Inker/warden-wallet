import { describe, expect, it, vi } from "vitest";

import {
  MAX_PAGE_PROVIDER_PENDING_REQUESTS,
  MAX_PAGE_PROVIDER_REQUESTS_PER_DOCUMENT,
  ProviderPageMethodUnavailableError,
  ProviderPageRequestDisposedError,
  ProviderPageRequestOwner,
  ProviderPageRequestStateError,
  ProviderPageRequestTimeoutError,
  ProviderPageTerminalError,
  type ProviderPageMessagePortApi,
  type ProviderPageMessagePortListener,
  type ProviderPageRandomSource,
  type ProviderPageTimerSource,
  type ProviderPageWindowApi,
  type ProviderPageWindowMessageEvent,
  type ProviderPageWindowMessageListener,
} from "../src/page/provider-request-owner.js";
import {
  PAGE_PROVIDER_RECEIPT_TYPE,
  PROVIDER_TRANSPORT_REQUEST_TYPE,
  createProviderCapabilityEnvelope,
  createProviderTransportTerminalEnvelope,
} from "../src/provider-delivery-protocol.js";

const ORIGIN = "https://dapp.example";
const ACCOUNT = "11111111111111111111111111111111";
const RECEIPT_ID = `delivery_${"ab".repeat(32)}`;
const DEADLINES = new Map<string, number>();

function randomBytes(lastByte: number): Uint8Array {
  const bytes = new Uint8Array(16);
  bytes[15] = lastByte;
  return bytes;
}

function correlationId(lastByte: number): string {
  return `page_${"00".repeat(15)}${lastByte.toString(16).padStart(2, "0")}`;
}

class SequenceRandom implements ProviderPageRandomSource {
  readonly values: Uint8Array[];
  calls = 0;

  constructor(...values: Uint8Array[]) {
    this.values = values.map((value) => value.slice());
  }

  getRandomValues(target: Uint8Array): Uint8Array {
    this.calls++;
    const value = this.values.shift();
    if (value === undefined) throw new Error("random sequence exhausted");
    target.set(value);
    return target;
  }
}

class FakeTimers implements ProviderPageTimerSource {
  readonly timers = new Map<number, { readonly callback: () => void; readonly delayMs: number }>();
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

/**
 * Stands in for the `MessagePort` the isolated content owner transfers into the
 * document. Holding this object is the whole capability: nothing a same-page
 * script can construct reaches `deliver`.
 */
class MockCapabilityPort implements ProviderPageMessagePortApi {
  readonly listeners = new Set<ProviderPageMessagePortListener>();
  readonly posted: unknown[] = [];
  starts = 0;
  closes = 0;
  throwOnAddListener = false;

  addEventListener(
    type: "message",
    listener: ProviderPageMessagePortListener,
  ): void {
    expect(type).toBe("message");
    if (this.throwOnAddListener) throw new Error("port realm failed");
    this.listeners.add(listener);
  }

  removeEventListener(
    type: "message",
    listener: ProviderPageMessagePortListener,
  ): void {
    expect(type).toBe("message");
    this.listeners.delete(listener);
  }

  postMessage(message: unknown): void {
    this.posted.push(message);
  }

  start(): void {
    this.starts++;
  }

  close(): void {
    this.closes++;
  }

  /** Deliver a terminal response the way the granted channel would. */
  deliver(data: unknown): void {
    for (const listener of [...this.listeners]) listener({ data });
  }
}

class MockPage implements ProviderPageWindowApi {
  readonly location = { origin: ORIGIN };
  readonly listeners = new Set<ProviderPageWindowMessageListener>();
  readonly posted: Array<{ readonly message: unknown; readonly targetOrigin: string }> = [];
  throwOnPost = false;
  throwAfterListenerAdd = false;
  postHook: (() => void) | null = null;

  addEventListener(
    type: "message",
    listener: ProviderPageWindowMessageListener,
  ): void {
    expect(type).toBe("message");
    this.listeners.add(listener);
    if (this.throwAfterListenerAdd) throw new Error("listener realm failed");
  }

  removeEventListener(
    type: "message",
    listener: ProviderPageWindowMessageListener,
  ): void {
    expect(type).toBe("message");
    this.listeners.delete(listener);
  }

  postMessage(message: unknown, targetOrigin: string): void {
    this.postHook?.();
    if (this.throwOnPost) throw new Error("window disappeared");
    this.posted.push({ message, targetOrigin });
    try {
      const outer = message as {
        readonly type?: unknown;
        readonly payload?: {
          readonly type?: unknown;
          readonly expiresAt?: unknown;
          readonly payload?: { readonly correlationId?: unknown };
        };
      };
      if (
        outer.type === "warden:provider:request" &&
        outer.payload?.type === PROVIDER_TRANSPORT_REQUEST_TYPE &&
        Number.isSafeInteger(outer.payload.expiresAt) &&
        typeof outer.payload.payload?.correlationId === "string"
      ) {
        DEADLINES.set(
          outer.payload.payload.correlationId,
          outer.payload.expiresAt as number,
        );
      }
    } catch {
      // Tests also exercise hostile values; recording is observational only.
    }
  }

  emit(data: unknown, overrides: Partial<ProviderPageWindowMessageEvent> = {}): void {
    const event: ProviderPageWindowMessageEvent = {
      data,
      origin: ORIGIN,
      source: this,
      ...overrides,
    };
    for (const listener of [...this.listeners]) listener(event);
  }

  /** Push a one-shot capability grant the way the content owner would. */
  grant(
    port: MockCapabilityPort = new MockCapabilityPort(),
    overrides: Partial<ProviderPageWindowMessageEvent> = {},
  ): MockCapabilityPort {
    this.emit(createProviderCapabilityEnvelope(), { ports: [port], ...overrides });
    return port;
  }
}

function input(transaction = new Uint8Array([1, 2, 3])) {
  return {
    accountAddress: ACCOUNT,
    transaction,
    chain: "solana:devnet" as const,
    options: {
      preflightCommitment: "confirmed" as const,
      minContextSlot: 42,
    },
  };
}

function successResponse(id: string, bytes: number[] = [9, 8, 7]) {
  const payload = {
    version: 1,
    type: "response",
    correlationId: id,
    ok: true,
    result: { signedTransaction: bytes },
  };
  return {
    version: 1,
    type: "warden:provider:response",
    payload: createProviderTransportTerminalEnvelope(
      id,
      RECEIPT_ID,
      DEADLINES.get(id) ?? 1,
      payload,
    ),
  };
}

function unavailableResponse(id: string) {
  const payload = {
    version: 1,
    type: "response",
    correlationId: id,
    ok: false,
    error: {
      code: "WARDEN_METHOD_UNAVAILABLE",
      message: "Warden provider methods are not enabled",
    },
  };
  return {
    version: 1,
    type: "warden:provider:response",
    payload: createProviderTransportTerminalEnvelope(
      id,
      RECEIPT_ID,
      DEADLINES.get(id) ?? 1,
      payload,
    ),
  };
}

function terminalFailureResponse(
  id: string,
  code: "WARDEN_USER_REJECTED" | "WARDEN_REQUEST_CANCELLED" |
    "WARDEN_REQUEST_EXPIRED" | "WARDEN_REQUEST_FAILED",
) {
  const messages = {
    WARDEN_USER_REJECTED: "User rejected the request",
    WARDEN_REQUEST_CANCELLED: "Provider request was cancelled",
    WARDEN_REQUEST_EXPIRED: "Provider request expired",
    WARDEN_REQUEST_FAILED: "Provider request failed",
  } as const;
  const payload = {
    version: 1,
    type: "response",
    correlationId: id,
    ok: false,
    error: { code, message: messages[code] },
  };
  return {
    version: 1,
    type: "warden:provider:response",
    payload: createProviderTransportTerminalEnvelope(
      id,
      RECEIPT_ID,
      DEADLINES.get(id) ?? 1,
      payload,
    ),
  };
}

function postedPayload(page: MockPage, index = 0): Record<string, unknown> {
  const requests = page.posted.filter(({ message }) =>
    (message as { readonly type?: unknown }).type === "warden:provider:request"
  );
  return (requests[index]!.message as {
    readonly payload: { readonly payload: Record<string, unknown> };
  }).payload.payload;
}

describe("C16 main-world provider request owner", () => {
  it("registers before send, posts one canonical copied request, and copies the result", async () => {
    const page = new MockPage();
    const random = new SequenceRandom(randomBytes(1));
    const owner = new ProviderPageRequestOwner(page, { randomSource: random });
    const capability = page.grant();
    const transaction = new Uint8Array([1, 2, 3]);
    page.postHook = () => expect(owner.pendingCount).toBe(1);

    const result = owner.signTransaction(input(transaction));
    transaction[0] = 255;

    const id = correlationId(1);
    expect(page.posted).toEqual([
      {
        message: {
          version: 1,
          type: "warden:provider:request",
          payload: {
            version: 1,
            type: PROVIDER_TRANSPORT_REQUEST_TYPE,
            expiresAt: DEADLINES.get(id),
            payload: {
              version: 1,
              type: "request",
              correlationId: id,
              method: "solana:signTransaction",
              params: {
                accountAddress: ACCOUNT,
                transaction: [1, 2, 3],
                chain: "solana:devnet",
                options: {
                  preflightCommitment: "confirmed",
                  minContextSlot: 42,
                },
              },
            },
          },
        },
        targetOrigin: ORIGIN,
      },
    ]);

    const responseBytes = [9, 8, 7];
    capability.deliver(successResponse(id, responseBytes));
    responseBytes[0] = 0;
    const signed = await result;

    expect(signed).toEqual(new Uint8Array([9, 8, 7]));
    expect(owner.pendingCount).toBe(0);
    expect(capability.posted).toEqual([
      {
        version: 1,
        type: PAGE_PROVIDER_RECEIPT_TYPE,
        payload: {
          version: 1,
          type: "warden:provider:transport-receipt",
          correlationId: id,
          receiptId: RECEIPT_ID,
          expiresAt: DEADLINES.get(id),
        },
      },
    ]);
    expect(page.posted).toHaveLength(1);
  });

  it("ignores a well-formed same-window terminal forgery against a pending request", async () => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
    });
    const capability = page.grant();
    const result = owner.signTransaction(input());
    const id = correlationId(1);

    // Exactly what a same-document script can build: the owner's own window,
    // the owner's own origin, the correlation id it just broadcast, the
    // deadline it just broadcast, and a well-formed receipt id.
    const forgery = successResponse(id, [66, 66, 66]);
    expect(forgery.payload.correlationId).toBe(id);
    expect(forgery.payload.expiresAt).toBe(DEADLINES.get(id));
    page.emit(forgery);
    page.emit(forgery, { ports: [] });
    page.emit(terminalFailureResponse(id, "WARDEN_USER_REJECTED"));

    expect(owner.pendingCount).toBe(1);
    expect(capability.posted).toEqual([]);

    capability.deliver(successResponse(id, [4, 5, 6]));
    await expect(result).resolves.toEqual(new Uint8Array([4, 5, 6]));
  });

  it("never settles a request while no capability has been granted", async () => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
    });
    const result = owner.signTransaction(input());
    const id = correlationId(1);

    expect(owner.hasCapability).toBe(false);
    page.emit(successResponse(id, [7, 7, 7]));
    expect(owner.pendingCount).toBe(1);

    const capability = page.grant();
    expect(owner.hasCapability).toBe(true);
    capability.deliver(successResponse(id, [1, 1, 1]));
    await expect(result).resolves.toEqual(new Uint8Array([1, 1, 1]));
  });

  it("claims the first capability grant and refuses every later one", async () => {
    const page = new MockPage();
    const refusals: string[] = [];
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
      onCapabilityRefused: (reason) => refusals.push(reason),
    });
    const granted = page.grant();
    const attacker = page.grant();
    const result = owner.signTransaction(input());
    const id = correlationId(1);

    expect(owner.capabilityRefusalCount).toBe(1);
    expect(refusals).toEqual(["capability already claimed"]);
    expect(attacker.listeners.size).toBe(0);
    expect(attacker.starts).toBe(0);
    attacker.deliver(successResponse(id, [66]));
    expect(owner.pendingCount).toBe(1);

    granted.deliver(successResponse(id, [1, 2, 3]));
    await expect(result).resolves.toEqual(new Uint8Array([1, 2, 3]));
    expect(granted.starts).toBe(1);
  });

  it("refuses malformed and wrong-context capability grants without claiming one", () => {
    const page = new MockPage();
    const refusals: string[] = [];
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
      onCapabilityRefused: (reason) => refusals.push(reason),
    });
    const grant = createProviderCapabilityEnvelope();
    const foreign = new MockCapabilityPort();

    page.emit(grant, { ports: [foreign], source: {} });
    page.emit(grant, { ports: [foreign], origin: "https://attacker.example" });
    expect(owner.capabilityRefusalCount).toBe(0);

    page.emit(grant);
    page.emit(grant, { ports: [] });
    page.emit(grant, { ports: [foreign, new MockCapabilityPort()] });
    page.emit(grant, { ports: [{ postMessage: () => {} }] });
    page.emit({ version: 1, type: "warden:provider:capability", extra: true }, {
      ports: [foreign],
    });

    expect(owner.hasCapability).toBe(false);
    expect(owner.capabilityRefusalCount).toBe(4);
    expect(new Set(refusals)).toEqual(
      new Set(["capability grant carried no transferred port"]),
    );
    expect(foreign.listeners.size).toBe(0);
    owner.dispose();
  });

  it("settles parallel requests by correlation even when responses reverse order", async () => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1), randomBytes(2)),
    });
    const capability = page.grant();

    const first = owner.signTransaction(input(new Uint8Array([1])));
    const second = owner.signTransaction(input(new Uint8Array([2])));
    capability.deliver(successResponse(correlationId(2), [22]));
    capability.deliver(successResponse(correlationId(1), [11]));

    await expect(first).resolves.toEqual(new Uint8Array([11]));
    await expect(second).resolves.toEqual(new Uint8Array([22]));
    expect(owner.pendingCount).toBe(0);
  });

  it("ignores every replay after first terminal settlement and never reuses its id", async () => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(
        randomBytes(1),
        randomBytes(1),
        randomBytes(2),
      ),
    });
    const capability = page.grant();

    const first = owner.signTransaction(input(new Uint8Array([1])));
    capability.deliver(successResponse(correlationId(1), [10]));
    capability.deliver(successResponse(correlationId(1), [99]));
    await expect(first).resolves.toEqual(new Uint8Array([10]));

    const second = owner.signTransaction(input(new Uint8Array([2])));
    expect(postedPayload(page, 1).correlationId).toBe(correlationId(2));
    capability.deliver(successResponse(correlationId(1), [88]));
    expect(owner.pendingCount).toBe(1);
    capability.deliver(successResponse(correlationId(2), [20]));
    await expect(second).resolves.toEqual(new Uint8Array([20]));
  });

  it("rejects unavailable once and ignores a later forged success for that tombstone", async () => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
    });
    const capability = page.grant();
    const result = owner.signTransaction(input());

    capability.deliver(unavailableResponse(correlationId(1)));
    capability.deliver(successResponse(correlationId(1), [55]));

    await expect(result).rejects.toBeInstanceOf(ProviderPageMethodUnavailableError);
    expect(owner.pendingCount).toBe(0);
  });

  it.each([
    ["WARDEN_USER_REJECTED", "User rejected the request"],
    ["WARDEN_REQUEST_CANCELLED", "Provider request was cancelled"],
    ["WARDEN_REQUEST_EXPIRED", "Provider request expired"],
    ["WARDEN_REQUEST_FAILED", "Provider request failed"],
  ] as const)("maps exact terminal %s without accepting background detail", async (code, message) => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
    });
    const capability = page.grant();
    const result = owner.signTransaction(input());

    capability.deliver(terminalFailureResponse(correlationId(1), code));

    await expect(result).rejects.toMatchObject({
      name: "ProviderPageTerminalError",
      code,
      message,
    } satisfies Partial<ProviderPageTerminalError>);
    expect(owner.pendingCount).toBe(0);
  });

  it("ignores open or mismatched terminal failure messages", async () => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
    });
    const capability = page.grant();
    const result = owner.signTransaction(input());
    const exact = terminalFailureResponse(
      correlationId(1),
      "WARDEN_USER_REJECTED",
    );

    capability.deliver({
      ...exact,
      payload: { ...exact.payload, detail: "must not cross" },
    });
    capability.deliver({
      ...exact,
      payload: {
        ...exact.payload,
        payload: {
          ...(exact.payload.payload as { readonly error: Record<string, unknown> }),
          error: {
            ...(exact.payload.payload as { readonly error: Record<string, unknown> }).error,
            message: "internal exception",
          },
        },
      },
    });
    expect(owner.pendingCount).toBe(1);

    capability.deliver(exact);
    await expect(result).rejects.toBeInstanceOf(ProviderPageTerminalError);
  });

  it("ignores unknown, open, accessor, and malformed capability deliveries", async () => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
    });
    const capability = page.grant();
    const result = owner.signTransaction(input());
    const id = correlationId(1);

    capability.deliver(successResponse(correlationId(9)));
    capability.deliver({ ...successResponse(id), extra: true });
    capability.deliver({
      ...successResponse(id),
      payload: { ...successResponse(id).payload, extra: true },
    });
    const sparse = new Array<number>(2);
    sparse[1] = 7;
    capability.deliver(successResponse(id, sparse));
    capability.deliver(
      Object.defineProperty({}, "version", { enumerable: true, get: () => 1 }),
    );

    expect(owner.pendingCount).toBe(1);
    capability.deliver(successResponse(id, [4, 5, 6]));
    await expect(result).resolves.toEqual(new Uint8Array([4, 5, 6]));
  });

  it("retains a tombstone when posting throws so the same id cannot alias a retry", async () => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(
        randomBytes(1),
        randomBytes(1),
        randomBytes(2),
      ),
    });
    const capability = page.grant();
    page.throwOnPost = true;

    await expect(owner.signTransaction(input(new Uint8Array([1])))).rejects.toThrow(
      "request transport failed",
    );
    page.throwOnPost = false;
    const second = owner.signTransaction(input(new Uint8Array([2])));
    expect(postedPayload(page).correlationId).toBe(correlationId(2));
    capability.deliver(successResponse(correlationId(2), [2]));
    await expect(second).resolves.toEqual(new Uint8Array([2]));
  });

  it("enforces independently bounded pending and lifetime request counts", async () => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(
        randomBytes(1),
        randomBytes(2),
        randomBytes(3),
      ),
      pendingLimit: 1,
      requestLimit: 2,
    });
    const capability = page.grant();

    const first = owner.signTransaction(input(new Uint8Array([1])));
    await expect(owner.signTransaction(input(new Uint8Array([2])))).rejects.toThrow(
      "too many pending requests",
    );
    expect(page.posted.filter(({ message }) =>
      (message as { readonly type?: unknown }).type === "warden:provider:request"
    )).toHaveLength(1);
    capability.deliver(successResponse(correlationId(1), [1]));
    await first;

    const second = owner.signTransaction(input(new Uint8Array([2])));
    capability.deliver(successResponse(correlationId(2), [2]));
    await second;
    await expect(owner.signTransaction(input(new Uint8Array([3])))).rejects.toThrow(
      "request limit reached",
    );
    expect(MAX_PAGE_PROVIDER_PENDING_REQUESTS).toBeGreaterThanOrEqual(1);
    expect(MAX_PAGE_PROVIDER_REQUESTS_PER_DOCUMENT).toBeGreaterThanOrEqual(2);
  });

  it("expires by absolute time, ignores late delivery, and retains the expired id", async () => {
    let now = 1_000;
    const timers = new FakeTimers();
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(
        randomBytes(1),
        randomBytes(1),
        randomBytes(2),
      ),
      timerSource: timers,
      readNow: () => now,
      requestTtlMs: 100,
    });
    const capability = page.grant();

    const first = owner.signTransaction(input(new Uint8Array([1])));
    expect([...timers.timers.values()].map((timer) => timer.delayMs)).toEqual([100]);
    now = 1_100;
    timers.fire(1);
    capability.deliver(successResponse(correlationId(1), [99]));
    await expect(first).rejects.toBeInstanceOf(ProviderPageRequestTimeoutError);

    const second = owner.signTransaction(input(new Uint8Array([2])));
    expect(postedPayload(page, 1).correlationId).toBe(correlationId(2));
    capability.deliver(successResponse(correlationId(2), [2]));
    await expect(second).resolves.toEqual(new Uint8Array([2]));
  });

  it("rechecks absolute expiry when a timer fires early or is delayed", async () => {
    let now = 10;
    const timers = new FakeTimers();
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1), randomBytes(2)),
      timerSource: timers,
      readNow: () => now,
      requestTtlMs: 100,
    });
    const capability = page.grant();

    const early = owner.signTransaction(input(new Uint8Array([1])));
    now = 60;
    timers.fire(1);
    expect([...timers.timers.values()].map((timer) => timer.delayMs)).toEqual([50]);
    capability.deliver(successResponse(correlationId(1), [1]));
    await expect(early).resolves.toEqual(new Uint8Array([1]));

    const delayed = owner.signTransaction(input(new Uint8Array([2])));
    now = 1_000;
    capability.deliver(successResponse(correlationId(2), [2]));
    await expect(delayed).rejects.toBeInstanceOf(ProviderPageRequestTimeoutError);
  });

  it("disposal rejects every pending promise, closes the capability, and is idempotent", async () => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1), randomBytes(2)),
    });
    const capability = page.grant();
    const first = owner.signTransaction(input(new Uint8Array([1])));
    const second = owner.signTransaction(input(new Uint8Array([2])));

    owner.dispose();
    owner.dispose();
    capability.deliver(successResponse(correlationId(1), [1]));

    await expect(first).rejects.toBeInstanceOf(ProviderPageRequestDisposedError);
    await expect(second).rejects.toBeInstanceOf(ProviderPageRequestDisposedError);
    expect(page.listeners.size).toBe(0);
    expect(capability.listeners.size).toBe(0);
    expect(capability.closes).toBe(1);
    expect(owner.pendingCount).toBe(0);
    await expect(owner.signTransaction(input())).rejects.toBeInstanceOf(
      ProviderPageRequestDisposedError,
    );

    let getterCalls = 0;
    const hostile = Object.defineProperty({}, "accountAddress", {
      enumerable: true,
      get: () => {
        getterCalls++;
        return ACCOUNT;
      },
    });
    await expect(owner.signTransaction(hostile as never)).rejects.toBeInstanceOf(
      ProviderPageRequestDisposedError,
    );
    expect(getterCalls).toBe(0);
  });

  it("closes every pending promise when the granted port cannot be bound", async () => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
    });
    const pending = owner.signTransaction(input());
    const broken = new MockCapabilityPort();
    broken.throwOnAddListener = true;

    page.grant(broken);

    await expect(pending).rejects.toThrow("capability port setup failed");
    expect(page.listeners.size).toBe(0);
  });

  it("rolls back a listener that is installed immediately before registration throws", () => {
    const page = new MockPage();
    page.throwAfterListenerAdd = true;

    expect(() => new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
    })).toThrow("response listener installation failed");
    expect(page.listeners.size).toBe(0);

    page.throwAfterListenerAdd = false;
    const retry = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
    });
    expect(page.listeners.size).toBe(1);
    retry.dispose();
  });

  it("permits only one owner for a document, even after that owner is disposed", () => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
    });

    expect(() => new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(2)),
    })).toThrow("document already has a request owner");
    owner.dispose();
    expect(() => new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(3)),
    })).toThrow("document already has a request owner");
  });

  it("rejects a non-function capability observer before claiming a window", () => {
    const page = new MockPage();
    expect(() => new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
      onCapabilityRefused: 7 as never,
    })).toThrow("onCapabilityRefused must be a function");
    expect(page.listeners.size).toBe(0);
  });

  it("survives an observer that throws while refusing a second grant", () => {
    const page = new MockPage();
    const observer = vi.fn(() => {
      throw new Error("observer exploded");
    });
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(randomBytes(1)),
      onCapabilityRefused: observer,
    });
    const granted = page.grant();
    page.grant();

    expect(observer).toHaveBeenCalledTimes(1);
    expect(owner.capabilityRefusalCount).toBe(1);
    expect(granted.listeners.size).toBe(1);
    owner.dispose();
  });

  it("rejects hostile inputs before consuming randomness or sending", async () => {
    const page = new MockPage();
    const random = new SequenceRandom(randomBytes(1));
    const owner = new ProviderPageRequestOwner(page, { randomSource: random });
    page.grant();
    const getter = Object.defineProperty(
      { accountAddress: ACCOUNT, transaction: new Uint8Array([1]) },
      "chain",
      { enumerable: true, get: () => "solana:devnet" },
    );

    for (const malformed of [
      { ...input(), extra: true },
      { ...input(), transaction: new Uint8Array() },
      { ...input(), transaction: [1, 2, 3] },
      { ...input(), options: { unknown: true } },
      getter,
    ]) {
      await expect(owner.signTransaction(malformed as never)).rejects.toBeInstanceOf(
        ProviderPageRequestStateError,
      );
    }

    expect(random.calls).toBe(0);
    expect(page.posted).toEqual([]);
  });

  it("rejects exhausted random collisions without reusing a prior correlation", async () => {
    const page = new MockPage();
    const owner = new ProviderPageRequestOwner(page, {
      randomSource: new SequenceRandom(
        randomBytes(1),
        ...Array.from({ length: 8 }, () => randomBytes(1)),
      ),
    });
    const capability = page.grant();
    const first = owner.signTransaction(input());
    capability.deliver(successResponse(correlationId(1), [1]));
    await first;

    await expect(owner.signTransaction(input())).rejects.toThrow(
      "could not mint a unique correlation id",
    );
    expect(page.posted.filter(({ message }) =>
      (message as { readonly type?: unknown }).type === "warden:provider:request"
    )).toHaveLength(1);
  });
});
