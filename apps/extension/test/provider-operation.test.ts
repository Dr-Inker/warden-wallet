import { describe, expect, it } from "vitest";
import { PublicKey } from "@solana/web3.js";

import {
  createPendingApprovalRecord,
  digestApprovalMessage,
  resolveApprovalRecord,
  snapshotApprovalRecord,
} from "@warden/core/approval";
import type { SignedSessionApproval } from "@warden/core/transaction/session-approval";

import type { OwnedProviderRequest } from "../src/background/provider-port.js";
import {
  ProviderOperationOwner,
  ProviderOperationStateError,
  bindProviderOperation,
  createPreparingProviderOperation,
  deriveProviderOperationIdentity,
  deriveProviderOperationIdentityFromRequest,
  failProviderOperation,
  snapshotProviderOperation,
  type ProviderOperationClaim,
  type ProviderOperationIdentity,
  type ProviderOperationRecord,
  type ProviderOperationRepository,
} from "../src/background/provider-operation.js";
import {
  ProviderTerminalResultOwner,
  ProviderTerminalResultStateError,
  type ProviderTerminalDeliveryLease,
} from "../src/background/provider-terminal-result.js";
import {
  createSignedTransactionProviderResponse,
  isSignedTransactionProviderResponse,
} from "../src/background/provider-terminal-protocol.js";

const APPROVAL_ID = `req_${"ab".repeat(16)}`;
const APPROVAL_MESSAGE = Uint8Array.of(1, 2, 3);
const APPROVAL_DIGEST = digestApprovalMessage(APPROVAL_MESSAGE);
const EXTENSION_ID = "a".repeat(32);

function owned(overrides: {
  readonly correlationId?: string;
  readonly documentId?: string;
  readonly transaction?: readonly number[];
  readonly minContextSlot?: number | null;
  readonly id?: string;
  readonly createdAt?: number;
  readonly expiresAt?: number;
} = {}): OwnedProviderRequest {
  return Object.freeze({
    id: overrides.id ?? `req_${"11".repeat(16)}`,
    provenance: Object.freeze({
      kind: "provider" as const,
      extensionId: EXTENSION_ID,
      documentId: overrides.documentId ?? "document-0123456789",
      origin: "https://dapp.example",
      tabId: 9,
      frameId: 2,
    }),
    request: Object.freeze({
      version: 1 as const,
      type: "request" as const,
      correlationId: overrides.correlationId ?? "request_0123456789abcdef",
      method: "solana:signTransaction" as const,
      params: Object.freeze({
        requestedAccountAddress: "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2",
        transaction: Object.freeze([...(overrides.transaction ?? [1, 2, 3])]),
        chain: "solana:devnet" as const,
        options: Object.freeze({
          preflightCommitment: "confirmed" as const,
          minContextSlot: overrides.minContextSlot ?? 7,
        }),
      }),
    }),
    createdAt: overrides.createdAt ?? 1_000,
    expiresAt: overrides.expiresAt ?? 61_000,
    signal: new AbortController().signal,
  });
}

function identityEqual(
  left: ProviderOperationIdentity,
  right: ProviderOperationIdentity,
): boolean {
  return left.key === right.key &&
    left.extensionId === right.extensionId &&
    left.origin === right.origin &&
    left.tabId === right.tabId &&
    left.frameId === right.frameId &&
    left.documentId === right.documentId &&
    left.correlationId === right.correlationId &&
    left.method === right.method &&
    left.requestDigest.every((byte, index) => byte === right.requestDigest[index]);
}

class MemoryProviderOperations implements ProviderOperationRepository {
  readonly records = new Map<string, ProviderOperationRecord>();

  async claim(input: {
    readonly identity: ProviderOperationIdentity;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly now: number;
  }): Promise<ProviderOperationClaim> {
    const current = this.records.get(input.identity.key);
    if (current !== undefined) {
      if (!identityEqual(current, input.identity)) throw new Error("identity collision");
      return { created: false, record: snapshotProviderOperation(current) };
    }
    const record = createPreparingProviderOperation(input);
    this.records.set(record.key, record);
    return { created: true, record: snapshotProviderOperation(record) };
  }

  async read(input: {
    readonly key: string;
    readonly now: number;
  }): Promise<ProviderOperationRecord | null> {
    const current = this.records.get(input.key);
    return current === undefined ? null : snapshotProviderOperation(current);
  }

  async bind(input: {
    readonly key: string;
    readonly expectedRequestDigest: Uint8Array;
    readonly approvalId: string;
    readonly approvalDigest: Uint8Array;
    readonly now: number;
  }): Promise<ProviderOperationRecord> {
    const current = this.records.get(input.key);
    if (current === undefined) throw new Error("missing operation");
    const bound = bindProviderOperation(current, input);
    this.records.set(bound.key, bound);
    return snapshotProviderOperation(bound);
  }

  async fail(input: {
    readonly key: string;
    readonly expectedRequestDigest: Uint8Array;
    readonly failureCode: "preparation-failed" | "request-cancelled";
    readonly now: number;
  }): Promise<ProviderOperationRecord> {
    const current = this.records.get(input.key);
    if (current === undefined) throw new Error("missing operation");
    const failed = failProviderOperation(current, input.failureCode, input.now);
    this.records.set(failed.key, failed);
    return snapshotProviderOperation(failed);
  }

  async invalidatePreparing(now: number): Promise<number> {
    let count = 0;
    for (const [key, current] of this.records) {
      if (current.state !== "preparing") continue;
      this.records.set(key, failProviderOperation(current, "worker-restarted", now));
      count++;
    }
    return count;
  }

  close(): void {}
}

function requestLease(value: OwnedProviderRequest) {
  return Object.freeze({
    owned: value,
    assertActive(): void {
      if (value.signal.aborted) throw new Error("inactive request");
    },
  });
}

function signedResult(
  id = APPROVAL_ID,
  digest = APPROVAL_DIGEST,
): SignedSessionApproval {
  return Object.freeze({
    id,
    get messageDigest(): Uint8Array {
      return digest.slice();
    },
    get transactionBytes(): Uint8Array {
      return Uint8Array.of(9, 8, 7, 6);
    },
    get signature(): Uint8Array {
      return new Uint8Array(64).fill(0x55);
    },
  });
}

function approvalReader(
  value: OwnedProviderRequest,
  overrides: { readonly documentId?: string } = {},
) {
  if (value.request.method !== "solana:signTransaction") {
    throw new Error("test request must be signTransaction");
  }
  const pending = createPendingApprovalRecord({
    id: APPROVAL_ID,
    origin: value.provenance.origin,
    tabId: value.provenance.tabId,
    frameId: value.provenance.frameId,
    documentId: overrides.documentId ?? value.provenance.documentId,
    account: new PublicKey(
      value.request.params.requestedAccountAddress,
    ).toBytes(),
    method: "solana:signTransaction",
    chain: value.request.params.chain ?? "solana:devnet",
    genesisHash: new Uint8Array(32).fill(0x22),
    programId: new Uint8Array(32).fill(0x33),
    rawMessage: APPROVAL_MESSAGE,
    policyVersion: 1,
    createdAt: 1_000,
    expiresAt: 61_000,
  });
  const approved = resolveApprovalRecord(pending, "approved", 1_200);
  return Object.freeze({
    async read(id: string) {
      return id === approved.id ? snapshotApprovalRecord(approved) : null;
    },
    async readSigning() {
      return null;
    },
  });
}

describe("durable provider operation identity", () => {
  it("survives a Port/worker remint but changes for every request or browser provenance input", async () => {
    const firstOwned = owned();
    if (firstOwned.request.method !== "solana:signTransaction") {
      throw new Error("test request has the wrong method");
    }
    const first = await deriveProviderOperationIdentity(firstOwned);
    const transportIdentity = await deriveProviderOperationIdentityFromRequest({
      provenance: firstOwned.provenance,
      request: firstOwned.request,
    });
    const reminted = await deriveProviderOperationIdentity(owned({
      id: `req_${"22".repeat(16)}`,
      createdAt: 2_000,
      expiresAt: 62_000,
    }));
    const changedCorrelation = await deriveProviderOperationIdentity(owned({
      correlationId: "request_fedcba9876543210",
    }));
    const changedDocument = await deriveProviderOperationIdentity(owned({
      documentId: "document-fedcba9876",
    }));
    const changedTransaction = await deriveProviderOperationIdentity(owned({
      transaction: [1, 2, 4],
    }));
    const changedOptions = await deriveProviderOperationIdentity(owned({
      minContextSlot: 8,
    }));

    expect(reminted.key).toBe(first.key);
    expect(reminted.requestDigest).toEqual(first.requestDigest);
    expect(transportIdentity.key).toBe(first.key);
    expect(transportIdentity.requestDigest).toEqual(first.requestDigest);
    expect(new Set([
      first.key,
      changedCorrelation.key,
      changedDocument.key,
      changedTransaction.key,
      changedOptions.key,
    ])).toHaveProperty("size", 5);
    first.requestDigest.fill(0);
    expect(reminted.requestDigest).not.toEqual(first.requestDigest);
    transportIdentity.requestDigest.fill(0);
  });

  it("strictly copy-owns preparing, bound, and failed records", async () => {
    const identity = await deriveProviderOperationIdentity(owned());
    const preparing = createPreparingProviderOperation({
      identity,
      createdAt: 1_000,
      expiresAt: 61_000,
      now: 1_100,
    });
    const digest = APPROVAL_DIGEST.slice();
    const bound = bindProviderOperation(preparing, {
      key: preparing.key,
      expectedRequestDigest: preparing.requestDigest,
      approvalId: APPROVAL_ID,
      approvalDigest: digest,
      now: 1_200,
    });
    digest.fill(0);

    expect(bound).toMatchObject({
      state: "bound",
      approvalId: APPROVAL_ID,
      failureCode: null,
      resolvedAt: 1_200,
    });
    expect(bound.approvalDigest).toEqual(APPROVAL_DIGEST);
    expect(() => failProviderOperation(bound, "preparation-failed", 1_300))
      .toThrow(ProviderOperationStateError);

    const failed = failProviderOperation(preparing, "preparation-failed", 1_200);
    const malformed = { ...failed, extra: true };
    expect(() => snapshotProviderOperation(malformed)).toThrow(
      ProviderOperationStateError,
    );
  });

  it("keeps the unshipped success schema closed and copy-owned", () => {
    const bytes = Uint8Array.of(1, 2, 3);
    const response = createSignedTransactionProviderResponse(
      "request_0123456789abcdef",
      bytes,
    );
    bytes.fill(0);
    expect(response.result.signedTransaction).toEqual([1, 2, 3]);
    expect(isSignedTransactionProviderResponse({ ...response, extra: true })).toBe(false);

    const revoked = Proxy.revocable([1, 2, 3], {});
    revoked.revoke();
    expect(() => isSignedTransactionProviderResponse({
      ...response,
      result: { signedTransaction: revoked.proxy },
    })).not.toThrow();
    expect(isSignedTransactionProviderResponse({
      ...response,
      result: { signedTransaction: revoked.proxy },
    })).toBe(false);

    const revokedResponse = Proxy.revocable(response, {});
    revokedResponse.revoke();
    expect(() => isSignedTransactionProviderResponse(revokedResponse.proxy))
      .not.toThrow();
    expect(isSignedTransactionProviderResponse(revokedResponse.proxy)).toBe(false);
  });
});

describe("provider operation owner", () => {
  it("lets one concurrent claimant prepare and makes every retry reuse its durable binding", async () => {
    const repository = new MemoryProviderOperations();
    const owner = new ProviderOperationOwner(repository, { readNow: () => 1_100 });
    const firstOwned = owned();
    const secondOwned = owned({ id: `req_${"22".repeat(16)}` });
    let prepareCalls = 0;
    let release!: () => void;
    let signalPrepareStarted!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const prepareStarted = new Promise<void>((resolve) => {
      signalPrepareStarted = resolve;
    });
    const prepare = async () => {
      prepareCalls++;
      signalPrepareStarted();
      await blocked;
      return { id: APPROVAL_ID, messageDigest: APPROVAL_DIGEST };
    };

    const first = owner.prepare(requestLease(firstOwned), prepare);
    await prepareStarted;
    await expect(owner.prepare(requestLease(secondOwned), prepare)).rejects.toThrow(
      "already being prepared",
    );
    release();
    const created = await first;
    const replayed = await owner.prepare(requestLease(secondOwned), prepare);

    expect(prepareCalls).toBe(1);
    expect(created.created).toBe(true);
    expect(replayed.created).toBe(false);
    expect(replayed.record).toMatchObject({
      state: "bound",
      approvalId: APPROVAL_ID,
    });
    expect(replayed.record.approvalDigest).toEqual(APPROVAL_DIGEST);
  });

  it("does not retry a retained interrupted claim, including after startup invalidation", async () => {
    const repository = new MemoryProviderOperations();
    const owner = new ProviderOperationOwner(repository, { readNow: () => 1_100 });
    const value = owned();
    const identity = await deriveProviderOperationIdentity(value);
    await repository.claim({
      identity,
      createdAt: value.createdAt,
      expiresAt: value.expiresAt,
      now: 1_100,
    });
    let calls = 0;
    const prepare = async () => {
      calls++;
      return { id: APPROVAL_ID, messageDigest: APPROVAL_DIGEST };
    };

    await expect(owner.prepare(requestLease(value), prepare)).rejects.toThrow(
      "already being prepared",
    );
    await expect(owner.invalidateAfterWorkerRestart()).resolves.toBe(1);
    await expect(owner.prepare(requestLease(value), prepare)).rejects.toThrow(
      "previously failed",
    );
    expect(calls).toBe(0);
  });

  it("rechecks Port liveness after the durable claim before preparation", async () => {
    let release!: () => void;
    let claimStarted!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = new Promise<void>((resolve) => {
      claimStarted = resolve;
    });
    class DelayedRepository extends MemoryProviderOperations {
      override async claim(input: Parameters<MemoryProviderOperations["claim"]>[0]) {
        claimStarted();
        await gate;
        return super.claim(input);
      }
    }
    const repository = new DelayedRepository();
    const owner = new ProviderOperationOwner(repository, { readNow: () => 1_100 });
    const controller = new AbortController();
    const value = Object.freeze({ ...owned(), signal: controller.signal });
    let calls = 0;
    const preparing = owner.prepare(requestLease(value), async () => {
      calls++;
      return { id: APPROVAL_ID, messageDigest: APPROVAL_DIGEST };
    });
    await started;
    controller.abort();
    release();

    await expect(preparing).rejects.toThrow("inactive request");
    expect(calls).toBe(0);
    const identity = await deriveProviderOperationIdentity(value);
    await expect(repository.read({ key: identity.key, now: 1_100 })).resolves
      .toMatchObject({ state: "failed", failureCode: "request-cancelled" });
  });
});

describe("provider terminal result delivery", () => {
  async function boundRepository() {
    const repository = new MemoryProviderOperations();
    const value = owned();
    const identity = await deriveProviderOperationIdentity(value);
    const claimed = await repository.claim({
      identity,
      createdAt: value.createdAt,
      expiresAt: value.expiresAt,
      now: 1_100,
    });
    await repository.bind({
      key: identity.key,
      expectedRequestDigest: identity.requestDigest,
      approvalId: APPROVAL_ID,
      approvalDigest: APPROVAL_DIGEST,
      now: 1_200,
    });
    return { repository, value, claimed };
  }

  it("posts only a strict signed-transaction response and then releases the exact live lease", async () => {
    const { repository, value } = await boundRepository();
    const posts: unknown[] = [];
    let finished = 0;
    const lease: ProviderTerminalDeliveryLease = Object.freeze({
      ...requestLease(value),
      postMessage(message: unknown): void {
        posts.push(message);
      },
      finish(): boolean {
        finished++;
        return true;
      },
    });
    const owner = new ProviderTerminalResultOwner({
      operations: repository,
      approvals: approvalReader(value),
      readNow: () => 1_300,
      readSigned: async () => signedResult(),
    });

    await expect(owner.deliver(lease)).resolves.toBe(true);
    expect(posts).toHaveLength(1);
    expect(isSignedTransactionProviderResponse(posts[0])).toBe(true);
    expect(posts[0]).toEqual(createSignedTransactionProviderResponse(
      value.request.correlationId,
      Uint8Array.of(9, 8, 7, 6),
    ));
    expect(finished).toBe(1);
  });

  it("does not mark delivery, finish, or re-sign when postMessage fails", async () => {
    const { repository, value } = await boundRepository();
    let reads = 0;
    let finishes = 0;
    const owner = new ProviderTerminalResultOwner({
      operations: repository,
      approvals: approvalReader(value),
      readNow: () => 1_300,
      readSigned: async () => {
        reads++;
        return signedResult();
      },
    });
    const failing: ProviderTerminalDeliveryLease = Object.freeze({
      ...requestLease(value),
      postMessage(): void {
        throw new Error("Port disconnected");
      },
      finish(): boolean {
        finishes++;
        return true;
      },
    });
    await expect(owner.deliver(failing)).rejects.toThrow("Port disconnected");
    expect(finishes).toBe(0);

    const posts: unknown[] = [];
    const retry: ProviderTerminalDeliveryLease = Object.freeze({
      ...requestLease(owned({ id: `req_${"22".repeat(16)}` })),
      postMessage(message: unknown): void {
        posts.push(message);
      },
      finish: () => true,
    });
    await expect(owner.deliver(retry)).resolves.toBe(true);
    expect(reads).toBe(2);
    expect(posts).toHaveLength(1);
  });

  it("releases nothing for an unbound operation or a result with a different digest", async () => {
    const repository = new MemoryProviderOperations();
    const value = owned();
    const identity = await deriveProviderOperationIdentity(value);
    await repository.claim({
      identity,
      createdAt: value.createdAt,
      expiresAt: value.expiresAt,
      now: 1_100,
    });
    const posts: unknown[] = [];
    const lease: ProviderTerminalDeliveryLease = Object.freeze({
      ...requestLease(value),
      postMessage: (message: unknown) => posts.push(message),
      finish: () => true,
    });
    const owner = new ProviderTerminalResultOwner({
      operations: repository,
      approvals: approvalReader(value),
      readNow: () => 1_200,
      readSigned: async () => signedResult(
        APPROVAL_ID,
        new Uint8Array(32).fill(0x99),
      ),
    });
    await expect(owner.deliver(lease)).rejects.toThrow(
      ProviderTerminalResultStateError,
    );
    expect(posts).toEqual([]);

    await repository.bind({
      key: identity.key,
      expectedRequestDigest: identity.requestDigest,
      approvalId: APPROVAL_ID,
      approvalDigest: APPROVAL_DIGEST,
      now: 1_250,
    });
    await expect(owner.deliver(lease)).rejects.toThrow("different digest");
    expect(posts).toEqual([]);
  });

  it("rejects a journal mapping to another browser document before result replay", async () => {
    const { repository, value } = await boundRepository();
    let signedReads = 0;
    const owner = new ProviderTerminalResultOwner({
      operations: repository,
      approvals: approvalReader(value, { documentId: "another-document" }),
      readNow: () => 1_300,
      readSigned: async () => {
        signedReads++;
        return signedResult();
      },
    });
    const posts: unknown[] = [];
    await expect(owner.deliver(Object.freeze({
      ...requestLease(value),
      postMessage: (message: unknown) => posts.push(message),
      finish: () => true,
    }))).rejects.toThrow("differs from the exact provider operation");
    expect(signedReads).toBe(0);
    expect(posts).toEqual([]);
  });

  it("finds no replay mapping when the exact requested transaction changes", async () => {
    const { repository, value } = await boundRepository();
    let signedReads = 0;
    const owner = new ProviderTerminalResultOwner({
      operations: repository,
      approvals: approvalReader(value),
      readNow: () => 1_300,
      readSigned: async () => {
        signedReads++;
        return signedResult();
      },
    });
    const changed = owned({
      id: `req_${"22".repeat(16)}`,
      transaction: [1, 2, 4],
    });
    const posts: unknown[] = [];

    await expect(owner.deliver(Object.freeze({
      ...requestLease(changed),
      postMessage: (message: unknown) => posts.push(message),
      finish: () => true,
    }))).rejects.toThrow("durable operation is absent");
    expect(signedReads).toBe(0);
    expect(posts).toEqual([]);
  });
});
