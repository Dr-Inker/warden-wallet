import {
  approvalDigestsEqual,
  completeApprovalSigningAttempt,
  createApprovalSigningAttempt,
  createPendingApprovalRecord,
  failApprovalSigningAttempt,
  resolveApprovalRecord,
  snapshotApprovalRecord,
  snapshotApprovalSigningRecord,
  type ApprovalRecord,
  type ApprovalSigningRecord,
  type ApprovalTerminalState,
} from "@warden/core/approval";
import { PublicKey } from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import type { OwnedProviderRequest } from "../src/background/provider-port.js";
import {
  bindProviderOperation,
  createPreparingProviderOperation,
  deriveProviderOperationIdentity,
  failProviderOperation,
  snapshotProviderOperation,
  type ProviderOperationFailureCode,
  type ProviderOperationRecord,
} from "../src/background/provider-operation.js";
import {
  ProviderTerminalOutcomeOwner,
  ProviderTerminalOutcomeStateError,
} from "../src/background/provider-terminal-outcome.js";
import { ProviderSignedResultFlowOwner } from "../src/background/provider-signed-result-flow.js";
import {
  createProviderTerminalFailureResponse,
  isProviderTerminalFailureResponse,
  providerTerminalFailureMessage,
  type ProviderTerminalFailureCode,
  type ProviderTerminalResponse,
} from "../src/background/provider-terminal-protocol.js";
import type { ProviderTerminalDeliveryLease } from "../src/background/provider-terminal-result.js";
import {
  ProviderPageRequestOwner,
  ProviderPageTerminalError,
  type ProviderPageRandomSource,
  type ProviderPageTimerSource,
  type ProviderPageWindowApi,
  type ProviderPageWindowMessageEvent,
  type ProviderPageWindowMessageListener,
} from "../src/page/provider-request-owner.js";
import {
  PAGE_PROVIDER_RESPONSE_TYPE,
} from "../src/provider-protocol.js";

const EXTENSION_ID = "a".repeat(32);
const ORIGIN = "https://dapp.example";
const ACCOUNT = "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";
const APPROVAL_ID = `req_${"22".repeat(16)}`;

function owned(
  overrides: Partial<OwnedProviderRequest["request"]["params"]> = {},
  correlationId = "request_0123456789abcdef",
): OwnedProviderRequest {
  return Object.freeze({
    id: `req_${"11".repeat(16)}`,
    provenance: Object.freeze({
      kind: "provider" as const,
      extensionId: EXTENSION_ID,
      documentId: "document-0123456789",
      origin: ORIGIN,
      tabId: 9,
      frameId: 2,
    }),
    request: Object.freeze({
      version: 1 as const,
      type: "request" as const,
      correlationId,
      method: "solana:signTransaction" as const,
      params: Object.freeze({
        requestedAccountAddress: ACCOUNT,
        transaction: Object.freeze([1, 2, 3]),
        chain: "solana:devnet" as const,
        options: Object.freeze({
          preflightCommitment: "confirmed" as const,
          minContextSlot: 7,
        }),
        ...overrides,
      }),
    }),
    createdAt: 1_000,
    expiresAt: 61_000,
    signal: new AbortController().signal,
  });
}

class FlowPage implements ProviderPageWindowApi {
  readonly location = { origin: ORIGIN };
  readonly listeners = new Set<ProviderPageWindowMessageListener>();
  readonly posted: Array<{ readonly message: unknown; readonly targetOrigin: string }> = [];

  addEventListener(
    _type: "message",
    listener: ProviderPageWindowMessageListener,
  ): void {
    this.listeners.add(listener);
  }

  removeEventListener(
    _type: "message",
    listener: ProviderPageWindowMessageListener,
  ): void {
    this.listeners.delete(listener);
  }

  postMessage(message: unknown, targetOrigin: string): void {
    this.posted.push({ message, targetOrigin });
  }

  emit(data: unknown): void {
    const event: ProviderPageWindowMessageEvent = {
      data,
      origin: ORIGIN,
      source: this,
    };
    for (const listener of [...this.listeners]) listener(event);
  }
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

function pendingApproval(
  value: OwnedProviderRequest,
  overrides: Partial<Parameters<typeof createPendingApprovalRecord>[0]> = {},
): ApprovalRecord {
  return createPendingApprovalRecord({
    id: APPROVAL_ID,
    origin: value.provenance.origin,
    tabId: value.provenance.tabId,
    frameId: value.provenance.frameId,
    documentId: value.provenance.documentId,
    account: new PublicKey(ACCOUNT).toBytes(),
    method: "solana:signTransaction",
    chain: "solana:devnet",
    genesisHash: new Uint8Array(32).fill(3),
    programId: new Uint8Array(32).fill(4),
    rawMessage: Uint8Array.of(5, 6, 7),
    policyVersion: 8,
    createdAt: 1_000,
    expiresAt: 61_000,
    ...overrides,
  });
}

function terminalApproval(
  value: OwnedProviderRequest,
  state: ApprovalTerminalState,
  overrides: Partial<Parameters<typeof createPendingApprovalRecord>[0]> = {},
): ApprovalRecord {
  const pending = pendingApproval(value, overrides);
  return resolveApprovalRecord(
    pending,
    state,
    state === "expired" ? 61_000 : 1_100,
  );
}

function signingRecord(
  approval: ApprovalRecord,
  state: "signing" | "signed" | "failed",
): ApprovalSigningRecord {
  const attempt = createApprovalSigningAttempt({
    id: approval.id,
    messageDigest: approval.messageDigest,
    attemptId: `attempt_${"33".repeat(16)}`,
    attemptNumber: 1,
    startedAt: 1_200,
  });
  const outcome = state === "signing"
    ? attempt
    : state === "signed"
      ? completeApprovalSigningAttempt(attempt, Uint8Array.of(9, 8, 7), 1_300)
      : failApprovalSigningAttempt(attempt, "signing-failed", 1_300);
  return snapshotApprovalSigningRecord({ approval, outcome });
}

async function boundOperation(
  value: OwnedProviderRequest,
  approval: ApprovalRecord,
): Promise<ProviderOperationRecord> {
  const identity = await deriveProviderOperationIdentity(value);
  const preparing = createPreparingProviderOperation({
    identity,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
    now: 1_000,
  });
  try {
    return bindProviderOperation(preparing, {
      key: identity.key,
      expectedRequestDigest: identity.requestDigest,
      approvalId: approval.id,
      approvalDigest: approval.messageDigest,
      now: 1_050,
    });
  } finally {
    identity.requestDigest.fill(0);
    preparing.requestDigest.fill(0);
  }
}

async function failedOperation(
  value: OwnedProviderRequest,
  code: ProviderOperationFailureCode,
): Promise<ProviderOperationRecord> {
  const identity = await deriveProviderOperationIdentity(value);
  const preparing = createPreparingProviderOperation({
    identity,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
    now: 1_000,
  });
  try {
    return failProviderOperation(
      preparing,
      code,
      code === "expired" ? value.expiresAt : 1_050,
    );
  } finally {
    identity.requestDigest.fill(0);
    preparing.requestDigest.fill(0);
  }
}

class MemoryOperations {
  constructor(
    readonly record: ProviderOperationRecord,
    readonly returnRegardlessOfKey = false,
  ) {}

  async read(input: { readonly key: string }): Promise<ProviderOperationRecord | null> {
    if (!this.returnRegardlessOfKey && input.key !== this.record.key) return null;
    return snapshotProviderOperation(this.record);
  }
}

class MemoryApprovals {
  constructor(
    readonly approval: ApprovalRecord | null,
    readonly signing: ApprovalSigningRecord | null = null,
  ) {}

  async read(id: string): Promise<ApprovalRecord | null> {
    if (this.approval === null || this.approval.id !== id) return null;
    return snapshotApprovalRecord(this.approval);
  }

  async readSigning(
    id: string,
    expectedDigest: Uint8Array,
  ): Promise<ApprovalSigningRecord | null> {
    if (
      this.signing === null ||
      this.signing.approval.id !== id ||
      !approvalDigestsEqual(this.signing.approval.messageDigest, expectedDigest)
    ) {
      return null;
    }
    return snapshotApprovalSigningRecord(this.signing);
  }
}

function deliveryLease(value: OwnedProviderRequest) {
  let active = true;
  let finishResult = true;
  let throwOnPost = false;
  const posts: ProviderTerminalResponse[] = [];
  const lease: ProviderTerminalDeliveryLease = Object.freeze({
    owned: value,
    assertActive(): void {
      if (!active || value.signal.aborted) throw new Error("inactive request");
    },
    postMessage(message: ProviderTerminalResponse): void {
      if (throwOnPost) throw new Error("Port enqueue failed");
      posts.push(message);
    },
    finish(): boolean {
      if (!active || !finishResult) return false;
      active = false;
      return true;
    },
  });
  return {
    lease,
    posts,
    get active() {
      return active;
    },
    set finishResult(value: boolean) {
      finishResult = value;
    },
    set throwOnPost(value: boolean) {
      throwOnPost = value;
    },
  };
}

function owner(
  operations: MemoryOperations,
  approvals: MemoryApprovals,
  deliverSigned: (lease: ProviderTerminalDeliveryLease) => Promise<unknown>,
) {
  return new ProviderTerminalOutcomeOwner({
    operations,
    approvals,
    signed: { deliver: deliverSigned },
    readNow: () => 1_400,
  });
}

describe("C19 durable provider terminal outcome", () => {
  it("delegates an exact signed outcome to C14 and never constructs signed bytes", async () => {
    const value = owned();
    const approval = terminalApproval(value, "approved");
    const operation = await boundOperation(value, approval);
    const signing = signingRecord(approval, "signed");
    const current = deliveryLease(value);
    let calls = 0;
    const outcome = owner(
      new MemoryOperations(operation),
      new MemoryApprovals(approval, signing),
      async (received) => {
        calls++;
        expect(received).toBe(current.lease);
        return true;
      },
    );

    await expect(outcome.deliver(current.lease)).resolves.toBe(true);
    expect(calls).toBe(1);
    expect(current.posts).toEqual([]);
    expect(current.active).toBe(true);
  });

  it.each([
    ["preparation-failed", "WARDEN_REQUEST_FAILED"],
    ["request-cancelled", "WARDEN_REQUEST_CANCELLED"],
    ["worker-restarted", "WARDEN_REQUEST_CANCELLED"],
    ["expired", "WARDEN_REQUEST_EXPIRED"],
  ] as const)(
    "maps terminal operation %s to only %s",
    async (operationCode, expectedCode) => {
      const value = owned();
      const operation = await failedOperation(value, operationCode);
      const current = deliveryLease(value);
      let signedCalls = 0;
      const outcome = owner(
        new MemoryOperations(operation),
        new MemoryApprovals(null),
        async () => {
          signedCalls++;
          return true;
        },
      );

      await expect(outcome.deliver(current.lease)).resolves.toBe(true);
      expect(signedCalls).toBe(0);
      expect(current.active).toBe(false);
      expect(current.posts).toEqual([
        createProviderTerminalFailureResponse(
          value.request.correlationId,
          expectedCode,
        ),
      ]);
    },
  );

  it.each([
    ["rejected", "WARDEN_USER_REJECTED"],
    ["cancelled", "WARDEN_REQUEST_CANCELLED"],
    ["expired", "WARDEN_REQUEST_EXPIRED"],
    ["invalidated", "WARDEN_REQUEST_FAILED"],
  ] as const)(
    "maps exact approval state %s to only %s",
    async (approvalState, expectedCode) => {
      const value = owned();
      const approval = terminalApproval(value, approvalState);
      const operation = await boundOperation(value, approval);
      const current = deliveryLease(value);
      const outcome = owner(
        new MemoryOperations(operation),
        new MemoryApprovals(approval),
        async () => {
          throw new Error("a terminal failure must not reach C14");
        },
      );

      await expect(outcome.deliver(current.lease)).resolves.toBe(true);
      expect(current.posts[0]).toMatchObject({
        correlationId: value.request.correlationId,
        ok: false,
        error: {
          code: expectedCode,
          message: providerTerminalFailureMessage(expectedCode),
        },
      });
      expect(isProviderTerminalFailureResponse(current.posts[0])).toBe(true);
    },
  );

  it("maps an exact failed signing attempt to one generic non-leaking failure", async () => {
    const value = owned();
    const approval = terminalApproval(value, "approved");
    const operation = await boundOperation(value, approval);
    const signing = signingRecord(approval, "failed");
    const current = deliveryLease(value);
    const outcome = owner(
      new MemoryOperations(operation),
      new MemoryApprovals(approval, signing),
      async () => {
        throw new Error("failed signing must not reach C14");
      },
    );

    await expect(outcome.deliver(current.lease)).resolves.toBe(true);
    expect(current.posts).toEqual([
      createProviderTerminalFailureResponse(
        value.request.correlationId,
        "WARDEN_REQUEST_FAILED",
      ),
    ]);
    expect(JSON.stringify(current.posts)).not.toContain("signing-failed");
  });

  it("composes C18 false-terminal scheduling through C19 into C16's original Promise", async () => {
    const page = new FlowPage();
    const pageOwner = new ProviderPageRequestOwner(page, {
      randomSource: new FixedRandom(),
      timerSource: new InertTimers(),
      readNow: () => 1_000,
    });
    const pageResult = pageOwner.signTransaction({
      accountAddress: ACCOUNT,
      transaction: Uint8Array.of(1, 2, 3),
      chain: "solana:devnet",
    });
    const envelope = page.posted[0]!.message as {
      readonly payload: { readonly correlationId: string };
    };
    const value = owned({}, envelope.payload.correlationId);
    const approval = terminalApproval(value, "rejected");
    const operation = await boundOperation(value, approval);
    let signedCalls = 0;
    const terminal = new ProviderTerminalOutcomeOwner({
      operations: new MemoryOperations(operation),
      approvals: new MemoryApprovals(approval),
      signed: {
        async deliver() {
          signedCalls++;
          return true;
        },
      },
      readNow: () => 1_400,
    });
    const flow = new ProviderSignedResultFlowOwner({
      approvals: {
        async launch() {
          return Object.freeze({
            kind: "opened" as const,
            approval: Object.freeze({}),
            terminal: Promise.resolve(false),
          });
        },
      },
      results: terminal,
    });
    const current = deliveryLease(value);
    const lease: ProviderTerminalDeliveryLease = Object.freeze({
      owned: value,
      assertActive: current.lease.assertActive.bind(current.lease),
      postMessage(message: ProviderTerminalResponse): void {
        page.emit(Object.freeze({
          version: 1,
          type: PAGE_PROVIDER_RESPONSE_TYPE,
          payload: message,
        }));
      },
      finish: current.lease.finish.bind(current.lease),
    });

    await expect(flow.deliver(lease)).resolves.toEqual({
      kind: "delivered",
      replayed: false,
    });
    await expect(pageResult).rejects.toMatchObject({
      name: "ProviderPageTerminalError",
      code: "WARDEN_USER_REJECTED",
    } satisfies Partial<ProviderPageTerminalError>);
    expect(signedCalls).toBe(0);
    expect(pageOwner.pendingCount).toBe(0);
    pageOwner.dispose();
  });

  it("recovers a retained failed operation after C13/C15 rejects replay", async () => {
    const value = owned();
    const operation = await failedOperation(value, "worker-restarted");
    const terminal = new ProviderTerminalOutcomeOwner({
      operations: new MemoryOperations(operation),
      approvals: new MemoryApprovals(null),
      signed: {
        async deliver() {
          throw new Error("failed operation must not reach C14");
        },
      },
      readNow: () => 1_400,
    });
    const flow = new ProviderSignedResultFlowOwner({
      approvals: {
        async launch() {
          throw new Error("operation previously failed as worker-restarted");
        },
      },
      results: terminal,
    });
    const current = deliveryLease(value);

    await expect(flow.deliver(current.lease)).resolves.toEqual({
      kind: "delivered",
      replayed: true,
    });
    expect(current.posts).toEqual([
      createProviderTerminalFailureResponse(
        value.request.correlationId,
        "WARDEN_REQUEST_CANCELLED",
      ),
    ]);
  });

  it.each(["preparing", "pending", "signing"] as const)(
    "refuses non-terminal durable %s state without posting or guessing",
    async (state) => {
      const value = owned();
      const approval = state === "preparing"
        ? null
        : state === "pending"
          ? pendingApproval(value)
          : terminalApproval(value, "approved");
      let operation: ProviderOperationRecord;
      if (state === "preparing") {
        const identity = await deriveProviderOperationIdentity(value);
        operation = createPreparingProviderOperation({
          identity,
          createdAt: value.createdAt,
          expiresAt: value.expiresAt,
          now: 1_000,
        });
        identity.requestDigest.fill(0);
      } else {
        operation = await boundOperation(value, approval!);
      }
      const signing = state === "signing"
        ? signingRecord(approval!, "signing")
        : null;
      const current = deliveryLease(value);
      const outcome = owner(
        new MemoryOperations(operation),
        new MemoryApprovals(approval, signing),
        async () => true,
      );

      await expect(outcome.deliver(current.lease)).rejects.toThrow(
        ProviderTerminalOutcomeStateError,
      );
      expect(current.posts).toEqual([]);
      expect(current.active).toBe(true);
    },
  );

  it("requires C14's exact true proof for a signed branch", async () => {
    const value = owned();
    const approval = terminalApproval(value, "approved");
    const operation = await boundOperation(value, approval);
    const signing = signingRecord(approval, "signed");
    const current = deliveryLease(value);
    const outcome = owner(
      new MemoryOperations(operation),
      new MemoryApprovals(approval, signing),
      async () => ({ delivered: true }),
    );

    await expect(outcome.deliver(current.lease)).rejects.toThrow(
      "signed terminal delivery returned no proof",
    );
    expect(current.posts).toEqual([]);
  });

  it("rejects request, approval, and signing substitution before any page message", async () => {
    const original = owned();
    const approval = terminalApproval(original, "approved");
    const operation = await boundOperation(original, approval);
    const signing = signingRecord(approval, "failed");

    const changedRequest = owned({ transaction: Object.freeze([1, 2, 4]) });
    const changedLease = deliveryLease(changedRequest);
    await expect(owner(
      new MemoryOperations(operation, true),
      new MemoryApprovals(approval, signing),
      async () => true,
    ).deliver(changedLease.lease)).rejects.toThrow(
      "different browser request",
    );
    expect(changedLease.posts).toEqual([]);

    const wrongApproval = terminalApproval(original, "rejected", {
      origin: "https://other.example",
    });
    const wrongOperation = await boundOperation(original, wrongApproval);
    const wrongLease = deliveryLease(original);
    await expect(owner(
      new MemoryOperations(wrongOperation),
      new MemoryApprovals(wrongApproval),
      async () => true,
    ).deliver(wrongLease.lease)).rejects.toThrow(
      "differs from the exact provider operation",
    );
    expect(wrongLease.posts).toEqual([]);

    const substitutedApproval = terminalApproval(original, "approved", {
      origin: "https://other.example",
    });
    const substitutedSigning = signingRecord(substitutedApproval, "failed");
    const signingLease = deliveryLease(original);
    await expect(owner(
      new MemoryOperations(operation),
      new MemoryApprovals(approval, substitutedSigning),
      async () => true,
    ).deliver(signingLease.lease)).rejects.toThrow(
      "signing outcome differs from the exact approval binding",
    );
    expect(signingLease.posts).toEqual([]);
  });

  it("preserves the fail-closed verdict when a hostile signing value also breaks cleanup", async () => {
    const value = owned();
    const approval = terminalApproval(value, "approved");
    const operation = await boundOperation(value, approval);
    const hostile = new Proxy({}, {
      ownKeys() {
        throw new Error("revoked signing realm");
      },
      get(_target, property) {
        if (property === "then") return undefined;
        throw new Error("cleanup getter must not win");
      },
    });
    const current = deliveryLease(value);
    const outcome = new ProviderTerminalOutcomeOwner({
      operations: new MemoryOperations(operation),
      approvals: {
        read: async () => snapshotApprovalRecord(approval),
        readSigning: async () => hostile as never,
      },
      signed: { deliver: async () => true },
      readNow: () => 1_400,
    });

    await expect(outcome.deliver(current.lease)).rejects.toThrow(
      "durable signing outcome is malformed",
    );
    expect(current.posts).toEqual([]);
  });

  it("does not treat Port enqueue as acknowledgment and permits durable replay", async () => {
    const value = owned();
    const operation = await failedOperation(value, "worker-restarted");
    const outcome = owner(
      new MemoryOperations(operation),
      new MemoryApprovals(null),
      async () => true,
    );

    const enqueueFailure = deliveryLease(value);
    enqueueFailure.throwOnPost = true;
    await expect(outcome.deliver(enqueueFailure.lease)).rejects.toThrow(
      "Port enqueue failed",
    );
    expect(enqueueFailure.posts).toEqual([]);
    expect(enqueueFailure.active).toBe(true);

    const lostRelease = deliveryLease(value);
    lostRelease.finishResult = false;
    await expect(outcome.deliver(lostRelease.lease)).rejects.toThrow(
      "delivery ownership was lost after posting",
    );
    expect(lostRelease.posts).toHaveLength(1);
    expect(lostRelease.active).toBe(true);

    const replacement = deliveryLease(value);
    await expect(outcome.deliver(replacement.lease)).resolves.toBe(true);
    expect(replacement.posts).toEqual(lostRelease.posts);
    expect(replacement.active).toBe(false);
  });

  it("keeps the failure protocol closed, exact, and total on hostile values", () => {
    const correlationId = "request_0123456789abcdef";
    const exact = createProviderTerminalFailureResponse(
      correlationId,
      "WARDEN_USER_REJECTED",
    );
    expect(isProviderTerminalFailureResponse(exact)).toBe(true);
    expect(isProviderTerminalFailureResponse({ ...exact, detail: "leak" })).toBe(false);
    expect(isProviderTerminalFailureResponse({
      ...exact,
      error: { ...exact.error, message: "internal stack" },
    })).toBe(false);
    expect(isProviderTerminalFailureResponse({
      ...exact,
      error: { code: "WARDEN_UNKNOWN", message: exact.error.message },
    })).toBe(false);
    expect(isProviderTerminalFailureResponse(new Proxy({}, {
      ownKeys() {
        throw new Error("revoked realm");
      },
    }))).toBe(false);
    expect(() => createProviderTerminalFailureResponse(
      "short",
      "WARDEN_REQUEST_FAILED",
    )).toThrow("correlation id is malformed");
    expect(() => providerTerminalFailureMessage("UNKNOWN" as ProviderTerminalFailureCode))
      .toThrow("terminal failure code is unsupported");
  });
});
