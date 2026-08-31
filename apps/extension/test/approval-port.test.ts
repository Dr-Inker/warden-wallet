import { describe, expect, it } from "vitest";

import {
  createPendingApprovalRecord,
  resolveApprovalRecord,
  snapshotApprovalRecord,
  type ApprovalRecord,
} from "@warden/core/approval";
import {
  MAX_ACTIVE_APPROVAL_UI_PORTS,
  installApprovalReviewBoundary,
  type ApprovalReviewActions,
  type ApprovalReviewOwner,
} from "../src/background/approval-port.js";
import type {
  ProviderConnectEvent,
  ProviderDisconnectEvent,
  ProviderMessageEvent,
  ProviderRuntimePort,
} from "../src/background/provider-port.js";
import {
  APPROVAL_UI_PORT_NAME,
  createApprovalApprovedResponse,
  createApprovalReviewResponse,
  createApprovalRejectedResponse,
  type ApprovalReviewDetails,
} from "../src/approval-protocol.js";

const EXTENSION_ID = "a".repeat(32);
const REQUEST_ID = `req_${"ab".repeat(16)}`;
const OTHER_REQUEST_ID = `req_${"cd".repeat(16)}`;
const PUBLIC_KEY = "1".repeat(32);

function record(id = REQUEST_ID): ApprovalRecord {
  return createPendingApprovalRecord({
    id,
    origin: "https://dapp.example",
    tabId: 7,
    frameId: 0,
    documentId: "provider-document",
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

function review(id = REQUEST_ID): ApprovalReviewDetails {
  return Object.freeze({
    kind: "memo-v1",
    requestId: id,
    origin: "https://dapp.example",
    method: "solana:signTransaction",
    chain: "solana:devnet",
    genesisHash: PUBLIC_KEY,
    account: PUBLIC_KEY,
    sessionSigner: PUBLIC_KEY,
    sessionAccount: PUBLIC_KEY,
    registry: PUBLIC_KEY,
    wardenProgram: PUBLIC_KEY,
    memoProgram: PUBLIC_KEY,
    recentBlockhash: PUBLIC_KEY,
    memo: "Review this exact memo",
    memoByteLength: 22,
    computeUnitLimit: 600_000,
    heapFrameBytes: 131_072,
    messageByteLength: 333,
    messageDigest: "11".repeat(32),
    policyVersion: 1,
    createdAt: 1_000,
    expiresAt: 2_000,
  });
}

function approvalSender(
  id = REQUEST_ID,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const url = `chrome-extension://${EXTENSION_ID}/approval.html?request=${id}`;
  return {
    documentId: `approval-document-${id}`,
    documentLifecycle: "active",
    frameId: 0,
    id: EXTENSION_ID,
    origin: `chrome-extension://${EXTENSION_ID}`,
    tab: { id: 23, url },
    url,
    ...overrides,
  };
}

function contentSender(): Record<string, unknown> {
  return {
    documentId: "content-document",
    documentLifecycle: "active",
    frameId: 0,
    id: EXTENSION_ID,
    origin: "https://dapp.example",
    tab: { id: 7, url: "https://dapp.example/" },
    url: "https://dapp.example/",
  };
}

function request(
  method: "approval:getReview" | "approval:approve" | "approval:reject",
  id = REQUEST_ID,
  correlationId = `approval_${
    method === "approval:getReview"
      ? "review"
      : method === "approval:approve"
        ? "approve"
        : "reject"
  }_0123456789`,
): Record<string, unknown> {
  return {
    version: 1,
    type: "request",
    correlationId,
    method,
    params: { requestId: id },
  };
}

class MockMessageEvent implements ProviderMessageEvent {
  readonly listeners = new Set<(message: unknown) => void>();
  addListener(listener: (message: unknown) => void): void { this.listeners.add(listener); }
  removeListener(listener: (message: unknown) => void): void { this.listeners.delete(listener); }
  emit(message: unknown): void { for (const listener of [...this.listeners]) listener(message); }
}

class MockDisconnectEvent implements ProviderDisconnectEvent {
  readonly listeners = new Set<() => void>();
  addListener(listener: () => void): void { this.listeners.add(listener); }
  removeListener(listener: () => void): void { this.listeners.delete(listener); }
  emit(): void { for (const listener of [...this.listeners]) listener(); }
}

class MockConnectEvent implements ProviderConnectEvent {
  readonly listeners = new Set<(port: ProviderRuntimePort) => void>();
  addListener(listener: (port: ProviderRuntimePort) => void): void { this.listeners.add(listener); }
  removeListener(listener: (port: ProviderRuntimePort) => void): void { this.listeners.delete(listener); }
  emit(port: ProviderRuntimePort): void { for (const listener of [...this.listeners]) listener(port); }
}

class MockPort implements ProviderRuntimePort {
  readonly onMessage = new MockMessageEvent();
  readonly onDisconnect = new MockDisconnectEvent();
  readonly posted: unknown[] = [];
  disconnectCalls = 0;

  constructor(
    readonly name = APPROVAL_UI_PORT_NAME,
    readonly sender: unknown = approvalSender(),
  ) {}

  postMessage(message: unknown): void { this.posted.push(message); }
  disconnect(): void {
    this.disconnectCalls++;
    this.onDisconnect.emit();
  }
}

class MemoryOwner implements ApprovalReviewOwner {
  readonly records = new Map<string, ApprovalRecord>();
  readonly operations: string[] = [];
  cancelFailure: Error | undefined;

  constructor(...records: ApprovalRecord[]) {
    for (const value of records) this.records.set(value.id, snapshotApprovalRecord(value));
  }

  async read(id: string): Promise<ApprovalRecord | null> {
    this.operations.push(`read:${id}`);
    const value = this.records.get(id);
    return value === undefined ? null : snapshotApprovalRecord(value);
  }

  async reject(id: string): Promise<ApprovalRecord> {
    this.operations.push(`reject:${id}`);
    return this.transition(id, "rejected");
  }

  async cancel(id: string): Promise<ApprovalRecord> {
    this.operations.push(`cancel:${id}`);
    if (this.cancelFailure !== undefined) throw this.cancelFailure;
    return this.transition(id, "cancelled");
  }

  approveForTest(id: string): void {
    this.transition(id, "approved");
  }

  private transition(
    id: string,
    state: "approved" | "rejected" | "cancelled",
  ): ApprovalRecord {
    const current = this.records.get(id);
    if (current === undefined || current.state !== "pending") {
      throw new Error("transition refused");
    }
    const resolved = resolveApprovalRecord(current, state, 1_100);
    this.records.set(id, resolved);
    return snapshotApprovalRecord(resolved);
  }
}

class MemoryActions implements ApprovalReviewActions {
  readonly calls: Array<
    | { readonly method: "canApprove"; readonly id: string; readonly digest: Uint8Array }
    | { readonly method: "approve" | "settle"; readonly id: string }
  > = [];
  canApproveResult = true;
  approveResult = true;
  settleResult = true;

  constructor(readonly owner: MemoryOwner) {}

  canApprove(id: string, digest: Uint8Array): boolean {
    this.calls.push({ method: "canApprove", id, digest: digest.slice() });
    return this.canApproveResult;
  }

  async approve(id: string): Promise<boolean> {
    this.calls.push({ method: "approve", id });
    if (this.approveResult) this.owner.approveForTest(id);
    return this.approveResult;
  }

  async settle(id: string): Promise<boolean> {
    this.calls.push({ method: "settle", id });
    return this.settleResult;
  }
}

async function flush(): Promise<void> {
  for (let index = 0; index < 8; index++) await Promise.resolve();
}

function install(
  owner: MemoryOwner,
  onFatal: (error: unknown) => void = () => {},
  actions?: ApprovalReviewActions,
) {
  const onConnect = new MockConnectEvent();
  const boundary = installApprovalReviewBoundary(
    { id: EXTENSION_ID, onConnect },
    {
      approvals: owner,
      actions,
      ready: Promise.resolve(),
      projectReview: (value) => review(value.id),
      onFatal,
    },
  );
  return { onConnect, boundary };
}

describe("approval review runtime boundary", () => {
  it("renders one exact pending record and cancels it when its document Port dies", async () => {
    const owner = new MemoryOwner(record());
    const { onConnect } = install(owner);
    const port = new MockPort();
    onConnect.emit(port);
    port.onMessage.emit(request("approval:getReview"));
    await flush();

    expect(port.posted).toEqual([
      createApprovalReviewResponse("approval_review_0123456789", review()),
    ]);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("pending");

    port.onDisconnect.emit();
    await flush();
    expect(owner.records.get(REQUEST_ID)?.state).toBe("cancelled");
  });

  it("persists an explicit rejection before acknowledging it", async () => {
    const owner = new MemoryOwner(record());
    const actions = new MemoryActions(owner);
    actions.canApproveResult = false;
    const { onConnect } = install(owner, () => {}, actions);
    const port = new MockPort();
    onConnect.emit(port);
    port.onMessage.emit(request("approval:getReview"));
    await flush();
    port.onMessage.emit(request("approval:reject"));
    await flush();

    expect(owner.records.get(REQUEST_ID)?.state).toBe("rejected");
    expect(port.posted.at(-1)).toEqual(
      createApprovalRejectedResponse("approval_reject_0123456789", REQUEST_ID),
    );
    expect(actions.calls.at(-1)).toEqual({ method: "settle", id: REQUEST_ID });
    port.onDisconnect.emit();
    await flush();
    expect(owner.records.get(REQUEST_ID)?.state).toBe("rejected");
  });

  it("invokes one background-bound approval action without accepting a digest or bytes", async () => {
    const owner = new MemoryOwner(record());
    const actions = new MemoryActions(owner);
    const expectedDigest = owner.records.get(REQUEST_ID)!.messageDigest.slice();
    const { onConnect } = install(owner, () => {}, actions);
    const port = new MockPort();
    onConnect.emit(port);

    port.onMessage.emit(request("approval:getReview"));
    await flush();
    expect(port.posted.at(-1)).toEqual(
      createApprovalReviewResponse("approval_review_0123456789", review(), true),
    );

    const approveRequest = request("approval:approve");
    expect(Object.keys(approveRequest.params as object)).toEqual(["requestId"]);
    port.onMessage.emit(approveRequest);
    await flush();

    expect(actions.calls).toEqual([
      { method: "canApprove", id: REQUEST_ID, digest: expectedDigest },
      { method: "approve", id: REQUEST_ID },
      { method: "settle", id: REQUEST_ID },
    ]);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("approved");
    expect(port.posted.at(-1)).toEqual(
      createApprovalApprovedResponse("approval_approve_0123456789", REQUEST_ID),
    );
    expect(JSON.stringify(port.posted.at(-1))).not.toContain("transactionBytes");
  });

  it("burns a forged approval action when no exact live capability exists", async () => {
    const owner = new MemoryOwner(record());
    const actions = new MemoryActions(owner);
    actions.canApproveResult = false;
    const { onConnect } = install(owner, () => {}, actions);
    const port = new MockPort();
    onConnect.emit(port);
    port.onMessage.emit(request("approval:getReview"));
    await flush();

    expect(port.posted.at(-1)).toEqual(
      createApprovalReviewResponse("approval_review_0123456789", review(), false),
    );
    port.onMessage.emit(request("approval:approve"));
    await flush();

    expect(port.disconnectCalls).toBe(1);
    expect(actions.calls.some((call) => call.method === "approve")).toBe(false);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("cancelled");
    expect(actions.calls.at(-1)).toEqual({ method: "settle", id: REQUEST_ID });
  });

  it("derives the id from browser provenance and burns it on a payload mismatch", async () => {
    const owner = new MemoryOwner(record(), record(OTHER_REQUEST_ID));
    const { onConnect } = install(owner);
    const port = new MockPort();
    onConnect.emit(port);
    port.onMessage.emit(request("approval:getReview", OTHER_REQUEST_ID));
    await flush();

    expect(port.disconnectCalls).toBe(1);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("cancelled");
    expect(owner.records.get(OTHER_REQUEST_ID)?.state).toBe("pending");
  });

  it("rejects a content script before reading or cancelling any record", async () => {
    const owner = new MemoryOwner(record());
    const { onConnect } = install(owner);
    const port = new MockPort(APPROVAL_UI_PORT_NAME, contentSender());
    onConnect.emit(port);
    await flush();

    expect(port.disconnectCalls).toBe(1);
    expect(owner.operations).toEqual([]);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("pending");
  });

  it("keeps reads behind readiness and rejects a concurrent second message", async () => {
    let release!: () => void;
    const ready = new Promise<void>((resolve) => { release = resolve; });
    const owner = new MemoryOwner(record());
    const onConnect = new MockConnectEvent();
    installApprovalReviewBoundary(
      { id: EXTENSION_ID, onConnect },
      {
        approvals: owner,
        ready,
        projectReview: (value) => review(value.id),
        onFatal: () => {},
      },
    );
    const port = new MockPort();
    onConnect.emit(port);
    port.onMessage.emit(request("approval:getReview"));
    expect(owner.operations).toEqual([]);
    port.onMessage.emit(request("approval:reject"));
    release();
    await flush();

    expect(port.disconnectCalls).toBe(1);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("cancelled");
    expect(owner.operations).not.toContain(`reject:${REQUEST_ID}`);
  });

  it("owns one Port per request, bounds total pages, and releases capacity", async () => {
    const records = Array.from({ length: MAX_ACTIVE_APPROVAL_UI_PORTS + 1 }, (_, index) =>
      record(`req_${index.toString(16).padStart(32, "0")}`));
    const owner = new MemoryOwner(...records);
    const { onConnect } = install(owner);
    const ports = records.map((value, index) => new MockPort(
      APPROVAL_UI_PORT_NAME,
      approvalSender(value.id, {
        documentId: `approval-capacity-${index}`,
        tab: { id: 100 + index },
      }),
    ));
    for (let index = 0; index < MAX_ACTIVE_APPROVAL_UI_PORTS; index++) {
      onConnect.emit(ports[index]!);
    }
    const duplicate = new MockPort(
      APPROVAL_UI_PORT_NAME,
      approvalSender(records[0]!.id, { documentId: "approval-duplicate", tab: { id: 500 } }),
    );
    onConnect.emit(duplicate);
    onConnect.emit(ports.at(-1)!);

    expect(duplicate.disconnectCalls).toBe(1);
    expect(ports.at(-1)!.disconnectCalls).toBe(1);
    ports[0]!.onDisconnect.emit();
    await flush();
    onConnect.emit(ports.at(-1)!);
    expect(ports.at(-1)!.disconnectCalls).toBe(1);
    expect(ports.at(-1)!.onMessage.listeners.size).toBe(1);
  });

  it("reports a cancellation failure only when the durable record is still pending", async () => {
    const owner = new MemoryOwner(record());
    owner.cancelFailure = new Error("IndexedDB cancellation failed");
    const fatals: unknown[] = [];
    const { onConnect } = install(owner, (error) => fatals.push(error));
    const port = new MockPort();
    onConnect.emit(port);
    port.onDisconnect.emit();
    await flush();

    expect(owner.records.get(REQUEST_ID)?.state).toBe("pending");
    expect(fatals).toHaveLength(1);
    expect(String(fatals[0])).toContain("IndexedDB cancellation failed");
  });

  it("disposes synchronously without scheduling owner calls after parent closure", async () => {
    const owner = new MemoryOwner(record());
    const { onConnect, boundary } = install(owner);
    const port = new MockPort();
    onConnect.emit(port);

    boundary.dispose();
    await flush();

    expect(port.disconnectCalls).toBe(1);
    expect(owner.operations).toEqual([]);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("pending");
    expect(onConnect.listeners.size).toBe(0);
  });

  it("abandons a queued disconnect cancellation when parent disposal takes ownership", async () => {
    const owner = new MemoryOwner(record());
    const { onConnect, boundary } = install(owner);
    const port = new MockPort();
    onConnect.emit(port);

    port.onDisconnect.emit();
    boundary.dispose();
    await flush();

    expect(owner.operations).toEqual([]);
    expect(owner.records.get(REQUEST_ID)?.state).toBe("pending");
  });
});
