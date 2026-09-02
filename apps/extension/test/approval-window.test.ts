import { describe, expect, it } from "vitest";

import {
  createPendingApprovalRecord,
  resolveApprovalRecord,
  snapshotApprovalRecord,
  type ApprovalRecord,
} from "@warden/core/approval";
import {
  APPROVAL_WINDOW_ASSUMED_SCREEN_HEIGHT,
  APPROVAL_WINDOW_ASSUMED_SCREEN_WIDTH,
  APPROVAL_WINDOW_HEIGHT,
  APPROVAL_WINDOW_WIDTH,
  MAX_ACTIVE_APPROVAL_WINDOWS,
  ApprovalWindowStateError,
  installApprovalWindowOwner,
  type ApprovalWindowsApi,
} from "../src/background/approval-window.js";
import {
  MAX_APPROVAL_WINDOWS_PER_DOCUMENT,
  MAX_APPROVAL_WINDOWS_PER_ORIGIN,
  ProviderOriginCapacityError,
} from "../src/background/provider-origin-capacity.js";

const EXTENSION_ID = "a".repeat(32);
const REQUEST_ID = `req_${"ab".repeat(16)}`;

function requestId(index: number): string {
  return `req_${index.toString(16).padStart(32, "0")}`;
}

function record(id = REQUEST_ID): ApprovalRecord {
  return createPendingApprovalRecord({
    id,
    origin: "https://dapp.example",
    tabId: 7,
    frameId: 0,
    documentId: `provider-document-${id}`,
    account: new Uint8Array(32).fill(0x11),
    method: "solana:signTransaction",
    chain: "solana:devnet",
    genesisHash: new Uint8Array(32).fill(0x22),
    programId: new Uint8Array(32).fill(0x33),
    rawMessage: Uint8Array.of(1, 2, 3),
    policyVersion: 1,
    createdAt: 1_000,
    expiresAt: 2_000,
  });
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolveValue, rejectValue) => {
    resolve = resolveValue;
    reject = rejectValue;
  });
  return { promise, resolve, reject };
}

async function flush(): Promise<void> {
  for (let index = 0; index < 32; index++) await Promise.resolve();
}

class RemovedEvent {
  readonly listeners = new Set<(windowId: number) => void>();

  addListener(listener: (windowId: number) => void): void {
    this.listeners.add(listener);
  }

  removeListener(listener: (windowId: number) => void): void {
    this.listeners.delete(listener);
  }

  emit(windowId: number): void {
    for (const listener of [...this.listeners]) listener(windowId);
  }
}

class FakeWindows implements ApprovalWindowsApi {
  readonly onRemoved = new RemovedEvent();
  readonly createCalls: unknown[] = [];
  readonly getCalls: number[] = [];
  readonly removeCalls: number[] = [];
  readonly existing = new Set<number>();
  createImpl: ApprovalWindowsApi["create"] | undefined;
  getImpl: ApprovalWindowsApi["get"] | undefined;
  removeImpl: ApprovalWindowsApi["remove"] | undefined;
  nextId = 1;

  async create(options: Parameters<ApprovalWindowsApi["create"]>[0]) {
    this.createCalls.push(Object.freeze({ ...options }));
    if (this.createImpl !== undefined) return this.createImpl(options);
    const id = this.nextId++;
    this.existing.add(id);
    return { id };
  }

  async get(windowId: number) {
    this.getCalls.push(windowId);
    if (this.getImpl !== undefined) return this.getImpl(windowId);
    if (!this.existing.has(windowId)) throw new Error("No window with id");
    return { id: windowId };
  }

  async remove(windowId: number): Promise<void> {
    this.removeCalls.push(windowId);
    if (this.removeImpl !== undefined) return this.removeImpl(windowId);
    if (!this.existing.delete(windowId)) throw new Error("No window with id");
    this.onRemoved.emit(windowId);
  }
}

class MemoryOwner {
  readonly records = new Map<string, ApprovalRecord>();
  readonly operations: string[] = [];
  readImpl: ((id: string) => Promise<ApprovalRecord | null>) | undefined;
  cancelImpl: ((id: string) => Promise<ApprovalRecord>) | undefined;

  constructor(...records: ApprovalRecord[]) {
    for (const value of records) this.records.set(value.id, snapshotApprovalRecord(value));
  }

  async read(id: string): Promise<ApprovalRecord | null> {
    this.operations.push(`read:${id}`);
    if (this.readImpl !== undefined) return this.readImpl(id);
    const value = this.records.get(id);
    return value === undefined ? null : snapshotApprovalRecord(value);
  }

  async cancel(id: string): Promise<ApprovalRecord> {
    this.operations.push(`cancel:${id}`);
    if (this.cancelImpl !== undefined) return this.cancelImpl(id);
    const current = this.records.get(id);
    if (current === undefined || current.state !== "pending") {
      throw new Error("transition refused");
    }
    const cancelled = resolveApprovalRecord(current, "cancelled", 1_100);
    this.records.set(id, cancelled);
    return snapshotApprovalRecord(cancelled);
  }
}

function install(
  owner: MemoryOwner,
  windows = new FakeWindows(),
  overrides: {
    readonly ready?: Promise<unknown>;
    readonly onFatal?: (error: unknown) => void;
    readonly random?: () => number;
  } = {},
) {
  const fatals: unknown[] = [];
  const installed = installApprovalWindowOwner(windows, {
    runtimeId: EXTENSION_ID,
    approvals: owner,
    ready: overrides.ready ?? Promise.resolve(),
    onFatal: overrides.onFatal ?? ((error) => fatals.push(error)),
    // Injected so placement is deterministic under test; production uses the
    // platform CSPRNG-backed Math.random default.
    random: overrides.random ?? (() => 0),
  });
  return { installed, windows, fatals };
}

describe("background-owned approval windows", () => {
  it("opens only the fixed extension review URL in one fixed popup after two pending checks", async () => {
    const owner = new MemoryOwner(record());
    const { installed, windows } = install(owner);
    const controller = new AbortController();

    await expect(installed.launch(REQUEST_ID, controller.signal)).resolves.toBeUndefined();

    expect(APPROVAL_WINDOW_WIDTH).toBe(720);
    expect(APPROVAL_WINDOW_HEIGHT).toBe(600);
    expect(MAX_ACTIVE_APPROVAL_WINDOWS).toBe(16);
    expect(windows.createCalls).toEqual([{
      url: `chrome-extension://${EXTENSION_ID}/approval.html?request=${REQUEST_ID}`,
      type: "popup",
      focused: true,
      width: 720,
      height: 600,
      left: 0,
      top: 0,
      setSelfAsOpener: false,
    }]);
    expect(windows.getCalls).toEqual([1]);
    expect(owner.operations).toEqual([
      `read:${REQUEST_ID}`,
      `read:${REQUEST_ID}`,
    ]);
    expect(Object.keys(installed).sort()).toEqual(["dispose", "launch"]);
  });

  it("registers the close listener synchronously while readiness is pending", async () => {
    const ready = deferred<void>();
    const owner = new MemoryOwner(record());
    const { installed, windows } = install(owner, new FakeWindows(), {
      ready: ready.promise,
    });

    const opening = installed.launch(REQUEST_ID, new AbortController().signal);
    expect(windows.onRemoved.listeners.size).toBe(1);
    expect(owner.operations).toEqual([]);
    expect(windows.createCalls).toEqual([]);

    ready.resolve();
    await opening;
  });

  it.each([
    "req_ABCDEFABCDEFABCDEFABCDEFABCDEFAB",
    "req_ab",
    "approval_abababababababababababababababab",
    "req_abababababababababababababababab?next=https://evil.example",
  ])("refuses malformed request id %s before reading or opening", async (id) => {
    const owner = new MemoryOwner(record());
    const { installed, windows } = install(owner);

    await expect(installed.launch(id, new AbortController().signal)).rejects.toThrow(
      ApprovalWindowStateError,
    );
    expect(owner.operations).toEqual([]);
    expect(windows.createCalls).toEqual([]);
  });

  it("refuses a missing or terminal record before opening a window", async () => {
    const missingOwner = new MemoryOwner();
    const missing = install(missingOwner);
    await expect(
      missing.installed.launch(REQUEST_ID, new AbortController().signal),
    ).rejects.toThrow("pending approval is unavailable");
    expect(missing.windows.createCalls).toEqual([]);

    const terminalOwner = new MemoryOwner(
      resolveApprovalRecord(record(), "rejected", 1_100),
    );
    const terminal = install(terminalOwner);
    await expect(
      terminal.installed.launch(REQUEST_ID, new AbortController().signal),
    ).rejects.toThrow("pending approval is unavailable");
    expect(terminal.windows.createCalls).toEqual([]);
  });

  it("reserves each request and the global cap before asynchronous work", async () => {
    const ready = deferred<void>();
    const records = Array.from(
      { length: MAX_ACTIVE_APPROVAL_WINDOWS + 1 },
      (_, index) => record(requestId(index + 1)),
    );
    const owner = new MemoryOwner(...records);
    const { installed, windows } = install(owner, new FakeWindows(), {
      ready: ready.promise,
    });
    const controller = new AbortController();
    const first = installed.launch(records[0]!.id, controller.signal);

    await expect(installed.launch(records[0]!.id, controller.signal)).rejects.toThrow(
      "already owns an approval window",
    );
    const openings = [first];
    for (const value of records.slice(1, MAX_ACTIVE_APPROVAL_WINDOWS)) {
      openings.push(installed.launch(value.id, controller.signal));
    }
    await expect(
      installed.launch(records[MAX_ACTIVE_APPROVAL_WINDOWS]!.id, controller.signal),
    ).rejects.toThrow("approval window capacity exhausted");
    expect(owner.operations).toEqual([]);
    expect(windows.createCalls).toEqual([]);

    ready.resolve();
    await Promise.all(openings);
  });

  it("gives each origin and document a share beneath the global window cap", async () => {
    const ready = deferred<void>();
    const records = Array.from(
      { length: MAX_ACTIVE_APPROVAL_WINDOWS + 2 },
      (_, index) => record(requestId(index + 1)),
    );
    const owner = new MemoryOwner(...records);
    const { installed, windows } = install(owner, new FakeWindows(), {
      ready: ready.promise,
    });
    const controller = new AbortController();
    const openings: Promise<void>[] = [];
    const scope = (origin: string, documentId: string) =>
      Object.freeze({ origin, documentId });

    // A hostile origin fills its own share across as many documents as it has.
    let next = 0;
    for (let index = 0; index < MAX_APPROVAL_WINDOWS_PER_ORIGIN; index++) {
      openings.push(installed.launch(
        records[next++]!.id,
        controller.signal,
        scope("https://hostile.example", `hostile-document-${index}`),
      ));
    }
    await expect(installed.launch(
      records[next]!.id,
      controller.signal,
      scope("https://hostile.example", "hostile-document-extra"),
    )).rejects.toBeInstanceOf(ProviderOriginCapacityError);
    await expect(installed.launch(
      records[next]!.id,
      controller.signal,
      scope("https://hostile.example", "hostile-document-extra"),
    )).rejects.toThrow(
      "origin https://hostile.example may hold at most 4 open approval windows",
    );

    // One document may not hold two windows even inside its origin's share.
    openings.push(installed.launch(
      records[next++]!.id,
      controller.signal,
      scope("https://victim.example", "victim-document"),
    ));
    await expect(installed.launch(
      records[next]!.id,
      controller.signal,
      scope("https://victim.example", "victim-document"),
    )).rejects.toThrow(
      "document victim-document of origin https://victim.example " +
        "may hold at most 1 open approval windows",
    );

    // The victim origin is still served on a second document.
    openings.push(installed.launch(
      records[next++]!.id,
      controller.signal,
      scope("https://victim.example", "victim-document-2"),
    ));
    expect(MAX_APPROVAL_WINDOWS_PER_DOCUMENT).toBe(1);
    expect(MAX_APPROVAL_WINDOWS_PER_ORIGIN).toBe(4);
    expect(windows.createCalls).toEqual([]);

    ready.resolve();
    await Promise.all(openings);
  });

  it("still enforces the global window cap across many origins", async () => {
    const ready = deferred<void>();
    const records = Array.from(
      { length: MAX_ACTIVE_APPROVAL_WINDOWS + 1 },
      (_, index) => record(requestId(index + 1)),
    );
    const owner = new MemoryOwner(...records);
    const { installed } = install(owner, new FakeWindows(), {
      ready: ready.promise,
    });
    const controller = new AbortController();
    const openings = records.slice(0, MAX_ACTIVE_APPROVAL_WINDOWS).map(
      (value, index) => installed.launch(value.id, controller.signal, {
        origin: `https://site-${Math.floor(index / MAX_APPROVAL_WINDOWS_PER_ORIGIN)}.example`,
        documentId: `document-${index}`,
      }),
    );

    await expect(installed.launch(
      records[MAX_ACTIVE_APPROVAL_WINDOWS]!.id,
      controller.signal,
      { origin: "https://late.example", documentId: "late-document" },
    )).rejects.toThrow("approval window capacity exhausted");

    ready.resolve();
    await Promise.all(openings);
  });

  it("refuses a malformed capacity scope", async () => {
    const owner = new MemoryOwner(record());
    const { installed, windows } = install(owner);

    await expect(installed.launch(
      REQUEST_ID,
      new AbortController().signal,
      { origin: "", documentId: "d" },
    )).rejects.toBeInstanceOf(ApprovalWindowStateError);
    expect(windows.createCalls).toEqual([]);
  });

  it("cancels without opening when the provider lifetime is already aborted", async () => {
    const owner = new MemoryOwner(record());
    const { installed, windows } = install(owner);
    const controller = new AbortController();
    controller.abort();

    await expect(installed.launch(REQUEST_ID, controller.signal)).rejects.toThrow(
      "approval request lifetime ended",
    );
    expect(windows.createCalls).toEqual([]);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("cancelled");
  });

  it("closes and cancels a window when the provider lifetime aborts", async () => {
    const owner = new MemoryOwner(record());
    const { installed, windows, fatals } = install(owner);
    const controller = new AbortController();
    await installed.launch(REQUEST_ID, controller.signal);

    controller.abort();
    await flush();

    expect(windows.removeCalls).toEqual([1]);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("cancelled");
    expect(fatals).toEqual([]);
  });

  it("removes a late-created window and cancels when abort wins chrome.windows.create", async () => {
    const created = deferred<{ id: number }>();
    const windows = new FakeWindows();
    windows.createImpl = async () => created.promise;
    const owner = new MemoryOwner(record());
    const { installed } = install(owner, windows);
    const controller = new AbortController();
    const opening = installed.launch(REQUEST_ID, controller.signal);
    await flush();
    controller.abort();
    created.resolve({ id: 37 });

    await expect(opening).rejects.toThrow("approval request lifetime ended");
    expect(windows.removeCalls).toEqual([37]);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("cancelled");
  });

  it.each([
    ["rejected create", async (): Promise<never> => {
      throw new Error("create denied");
    }],
    ["missing result", async (): Promise<undefined> => undefined],
    ["missing id", async (): Promise<{}> => ({})],
    ["negative id", async (): Promise<{ id: number }> => ({ id: -1 })],
    ["fractional id", async (): Promise<{ id: number }> => ({ id: 1.5 })],
  ] as const)("cancels a pending record after %s", async (_label, createImpl) => {
    const windows = new FakeWindows();
    windows.createImpl = createImpl;
    const owner = new MemoryOwner(record());
    const { installed } = install(owner, windows);

    await expect(
      installed.launch(REQUEST_ID, new AbortController().signal),
    ).rejects.toBeDefined();
    expect(owner.records.get(REQUEST_ID)?.state).toBe("cancelled");
  });

  it("uses chrome.windows.get to detect create-to-close races and cancels", async () => {
    const windows = new FakeWindows();
    windows.getImpl = async () => Promise.reject(new Error("No window with id"));
    const owner = new MemoryOwner(record());
    const { installed } = install(owner, windows);

    await expect(
      installed.launch(REQUEST_ID, new AbortController().signal),
    ).rejects.toThrow("approval window disappeared during launch");
    expect(windows.getCalls).toEqual([1]);
    expect(windows.removeCalls).toEqual([1]);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("cancelled");
  });

  it("closes and cancels when the second durable read is no longer pending", async () => {
    const owner = new MemoryOwner(record());
    let reads = 0;
    owner.readImpl = async (id) => {
      reads++;
      const current = owner.records.get(id);
      if (current === undefined) return null;
      if (reads === 2 && current.state === "pending") {
        owner.records.set(id, resolveApprovalRecord(current, "rejected", 1_100));
      }
      return snapshotApprovalRecord(owner.records.get(id)!);
    };
    const { installed, windows } = install(owner);

    await expect(
      installed.launch(REQUEST_ID, new AbortController().signal),
    ).rejects.toThrow("approval stopped being pending during launch");
    expect(windows.removeCalls).toEqual([1]);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("rejected");
    expect(owner.operations).toEqual([
      `read:${REQUEST_ID}`,
      `read:${REQUEST_ID}`,
    ]);
  });

  it("maps a browser close to the exact durable request and frees capacity", async () => {
    const records = Array.from(
      { length: MAX_ACTIVE_APPROVAL_WINDOWS + 1 },
      (_, index) => record(requestId(index + 1)),
    );
    const owner = new MemoryOwner(...records);
    const { installed, windows, fatals } = install(owner);
    const controller = new AbortController();
    await Promise.all(records.slice(0, MAX_ACTIVE_APPROVAL_WINDOWS).map(
      (value) => installed.launch(value.id, controller.signal),
    ));

    windows.onRemoved.emit(999_999);
    windows.existing.delete(1);
    windows.onRemoved.emit(1);
    await flush();

    expect(owner.records.get(records[0]!.id)?.state).toBe("cancelled");
    expect(owner.records.get(records[1]!.id)?.state).toBe("pending");
    await expect(
      installed.launch(records[MAX_ACTIVE_APPROVAL_WINDOWS]!.id, controller.signal),
    ).resolves.toBeUndefined();
    expect(fatals).toEqual([]);
  });

  it("accepts a concurrent terminal winner when durable cancellation loses", async () => {
    const owner = new MemoryOwner(record());
    owner.cancelImpl = async (id) => {
      const current = owner.records.get(id)!;
      owner.records.set(id, resolveApprovalRecord(current, "rejected", 1_100));
      throw new Error("cancel lost CAS");
    };
    const { installed, windows, fatals } = install(owner);
    await installed.launch(REQUEST_ID, new AbortController().signal);

    windows.existing.delete(1);
    windows.onRemoved.emit(1);
    await flush();

    expect(owner.records.get(REQUEST_ID)?.state).toBe("rejected");
    expect(fatals).toEqual([]);
  });

  it("reports fatal when cancellation fails and the record is still pending", async () => {
    const cancellationError = new Error("cancel storage failure");
    const owner = new MemoryOwner(record());
    owner.cancelImpl = async () => Promise.reject(cancellationError);
    const { installed, windows, fatals } = install(owner);
    await installed.launch(REQUEST_ID, new AbortController().signal);

    windows.existing.delete(1);
    windows.onRemoved.emit(1);
    await flush();

    expect(fatals).toEqual([cancellationError]);
  });

  it("reports an aggregate fatal when cancellation and its proving read both fail", async () => {
    const owner = new MemoryOwner(record());
    owner.cancelImpl = async () => Promise.reject(new Error("cancel storage failure"));
    let reads = 0;
    owner.readImpl = async (id) => {
      reads++;
      if (reads > 2) throw new Error("read storage failure");
      return snapshotApprovalRecord(owner.records.get(id)!);
    };
    const { installed, windows, fatals } = install(owner);
    await installed.launch(REQUEST_ID, new AbortController().signal);

    windows.existing.delete(1);
    windows.onRemoved.emit(1);
    await flush();

    expect(fatals).toHaveLength(1);
    expect(fatals[0]).toBeInstanceOf(AggregateError);
  });

  it("disposes synchronously, closes owned windows, and starts no late repository work", async () => {
    const owner = new MemoryOwner(record());
    const { installed, windows, fatals } = install(owner);
    await installed.launch(REQUEST_ID, new AbortController().signal);
    const operationsBeforeDispose = [...owner.operations];

    installed.dispose();
    expect(windows.onRemoved.listeners.size).toBe(0);
    expect(windows.removeCalls).toEqual([1]);
    await flush();

    expect(owner.operations).toEqual(operationsBeforeDispose);
    expect(fatals).toEqual([]);
    await expect(
      installed.launch(requestId(999), new AbortController().signal),
    ).rejects.toThrow("approval window owner is disposed");
  });

  it("settles a readiness-blocked launch promptly on disposal without repository work", async () => {
    const ready = deferred<void>();
    const owner = new MemoryOwner(record());
    const { installed } = install(owner, new FakeWindows(), {
      ready: ready.promise,
    });
    let settled = false;
    const opening = installed.launch(
      REQUEST_ID,
      new AbortController().signal,
    ).then(
      () => "fulfilled" as const,
      (error: unknown) => {
        settled = true;
        return error;
      },
    );

    installed.dispose();
    await flush();
    expect(settled).toBe(true);
    await expect(opening).resolves.toBeInstanceOf(ApprovalWindowStateError);
    expect(owner.operations).toEqual([]);
  });

  it("settles during a hung create and removes the browser window if create resolves late", async () => {
    const created = deferred<{ id: number }>();
    const windows = new FakeWindows();
    windows.createImpl = async () => created.promise;
    const owner = new MemoryOwner(record());
    const { installed } = install(owner, windows);
    let settled = false;
    const opening = installed.launch(
      REQUEST_ID,
      new AbortController().signal,
    ).then(
      () => "fulfilled" as const,
      (error: unknown) => {
        settled = true;
        return error;
      },
    );
    await flush();
    expect(windows.createCalls).toHaveLength(1);

    installed.dispose();
    await flush();
    expect(settled).toBe(true);
    await expect(opening).resolves.toBeInstanceOf(ApprovalWindowStateError);

    created.resolve({ id: 73 });
    await flush();
    expect(windows.removeCalls).toEqual([73]);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("pending");
  });
});

describe("approval window placement (audit A-1: predictable click target)", () => {
  const maxLeft = APPROVAL_WINDOW_ASSUMED_SCREEN_WIDTH - APPROVAL_WINDOW_WIDTH;
  const maxTop = APPROVAL_WINDOW_ASSUMED_SCREEN_HEIGHT - APPROVAL_WINDOW_HEIGHT;

  it("assumes a screen at least as large as the window it is placing", () => {
    expect(maxLeft).toBeGreaterThan(0);
    expect(maxTop).toBeGreaterThan(0);
  });

  it("derives left and top from the injected RNG across the whole placement range", async () => {
    const draws = [0.25, 0.75];
    let index = 0;
    const owner = new MemoryOwner(record());
    const { installed, windows } = install(owner, new FakeWindows(), {
      random: () => draws[index++]!,
    });

    await installed.launch(REQUEST_ID, new AbortController().signal);

    expect(index).toBe(2);
    expect(windows.createCalls).toEqual([{
      url: `chrome-extension://${EXTENSION_ID}/approval.html?request=${REQUEST_ID}`,
      type: "popup",
      focused: true,
      width: APPROVAL_WINDOW_WIDTH,
      height: APPROVAL_WINDOW_HEIGHT,
      left: Math.floor(0.25 * (maxLeft + 1)),
      top: Math.floor(0.75 * (maxTop + 1)),
      setSelfAsOpener: false,
    }]);
  });

  it("reaches both ends of the range and never leaves the assumed screen", async () => {
    for (const [draw, expectedLeft, expectedTop] of [
      [0, 0, 0],
      [0.999_999, maxLeft, maxTop],
    ] as const) {
      const owner = new MemoryOwner(record());
      const { installed, windows } = install(owner, new FakeWindows(), {
        random: () => draw,
      });
      await installed.launch(REQUEST_ID, new AbortController().signal);
      const created = windows.createCalls[0] as { left: number; top: number };
      expect(created.left).toBe(expectedLeft);
      expect(created.top).toBe(expectedTop);
    }
  });

  it("clamps a hostile or broken RNG onto the screen instead of failing the launch", async () => {
    for (const random of [
      () => 1,
      () => -1,
      () => Number.NaN,
      () => Number.POSITIVE_INFINITY,
      (): number => {
        throw new Error("rng unavailable");
      },
    ]) {
      const owner = new MemoryOwner(record());
      const { installed, windows } = install(owner, new FakeWindows(), { random });
      await expect(
        installed.launch(REQUEST_ID, new AbortController().signal),
      ).resolves.toBeUndefined();
      const created = windows.createCalls[0] as { left: number; top: number };
      expect(Number.isSafeInteger(created.left)).toBe(true);
      expect(Number.isSafeInteger(created.top)).toBe(true);
      expect(created.left).toBeGreaterThanOrEqual(0);
      expect(created.left).toBeLessThanOrEqual(maxLeft);
      expect(created.top).toBeGreaterThanOrEqual(0);
      expect(created.top).toBeLessThanOrEqual(maxTop);
    }
  });

  it("does not reuse one position for two launches from the default RNG", async () => {
    const positions = new Set<string>();
    for (let attempt = 0; attempt < 24; attempt++) {
      const owner = new MemoryOwner(record());
      const windows = new FakeWindows();
      // No `random` override: this exercises the production default.
      const installed = installApprovalWindowOwner(windows, {
        runtimeId: EXTENSION_ID,
        approvals: owner,
        ready: Promise.resolve(),
        onFatal: () => undefined,
      });
      await installed.launch(REQUEST_ID, new AbortController().signal);
      const created = windows.createCalls[0] as { left: number; top: number };
      positions.add(`${created.left}x${created.top}`);
      installed.dispose();
    }
    expect(positions.size).toBeGreaterThan(1);
  });
});
