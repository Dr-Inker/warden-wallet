import { describe, expect, it } from "vitest";

import {
  createPendingApprovalRecord,
  resolveApprovalRecord,
  snapshotApprovalRecord,
  type ApprovalRecord,
} from "@warden/core/approval";
import type {
  PreparedSessionApproval,
  SessionApprovalRequest,
  SignedSessionApproval,
} from "@warden/core/transaction/session-approval";

import {
  ProviderPortSession,
  type OwnedProviderRequest,
  type ProviderRandomSource,
  type ProviderTimerSource,
} from "../src/background/provider-port.js";
import {
  MAX_ACTIVE_PROVIDER_APPROVAL_REQUESTS,
  ProviderApprovalRequestOwner,
  ProviderApprovalRequestStateError,
  type ProviderApprovalCoordinator,
  type ProviderPreparedApprovalHandle,
  type ProviderApprovalSelectionInput,
  type ProviderApprovalSelectionResolver,
  type ProviderRequestLease,
} from "../src/background/provider-approval-request.js";
import {
  MAX_PROVIDER_APPROVAL_REQUESTS_PER_ORIGIN,
  ProviderOriginCapacityError,
} from "../src/background/provider-origin-capacity.js";
import {
  ProviderApprovalOperationOwner,
} from "../src/background/provider-approval-operation.js";
import {
  ProviderApprovalActionOwner,
  type ProviderApprovalActionRegistration,
} from "../src/background/provider-approval-action.js";
import {
  ProviderSignedResultFlowOwner,
} from "../src/background/provider-signed-result-flow.js";
import {
  ProviderOperationOwner,
  bindProviderOperation,
  createPreparingProviderOperation,
  failProviderOperation,
  snapshotProviderOperation,
  type ProviderOperationClaim,
  type ProviderOperationFailureCode,
  type ProviderOperationIdentity,
  type ProviderOperationRecord,
  type ProviderOperationRepository,
} from "../src/background/provider-operation.js";
import {
  ProviderTerminalResultOwner,
  type ProviderTerminalDeliveryLease,
} from "../src/background/provider-terminal-result.js";
import type { ProviderSignedTransactionResponse } from "../src/background/provider-terminal-protocol.js";
import { classifyProviderSender } from "../src/background/sender-provenance.js";
import {
  ProviderPageRequestOwner,
  type ProviderPageMessagePortApi,
  type ProviderPageMessagePortListener,
  type ProviderPageWindowApi,
  type ProviderPageWindowMessageEvent,
  type ProviderPageWindowMessageListener,
} from "../src/page/provider-request-owner.js";
import {
  PAGE_PROVIDER_RESPONSE_TYPE,
  readPageProviderRequestEnvelope,
} from "../src/provider-protocol.js";
import {
  createProviderCapabilityEnvelope,
  readProviderCapabilityRequestEnvelope,
  createProviderTransportTerminalEnvelope,
  readProviderTransportRequestEnvelope,
} from "../src/provider-delivery-protocol.js";

const EXTENSION_ID = "a".repeat(32);
const DOCUMENT_ID = "123e4567-e89b-12d3-a456-426614174000";
const ACCOUNT_ADDRESS = "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";
const ACCOUNT = new Uint8Array(32).fill(0x11);
const APPROVAL_ID = `req_${"ab".repeat(16)}`;
const DELIVERY_RECEIPT_ID = `delivery_${"ef".repeat(32)}`;

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

class FixedRandom implements ProviderRandomSource {
  getRandomValues(target: Uint8Array): Uint8Array {
    target.fill(0x44);
    return target;
  }
}

class InertTimers implements ProviderTimerSource {
  setTimeout(): unknown {
    return 1;
  }

  clearTimeout(): void {}
}

function rawRequest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 1,
    type: "request",
    correlationId: "request_0123456789abcdef",
    method: "solana:signTransaction",
    params: {
      accountAddress: ACCOUNT_ADDRESS,
      transaction: [1, 2, 3],
      chain: "solana:devnet",
    },
    ...overrides,
  };
}

function providerLease(
  request: Record<string, unknown> = rawRequest(),
  origin = "https://iframe.example",
): {
  readonly session: ProviderPortSession;
  readonly owned: OwnedProviderRequest;
  readonly lease: ProviderRequestLease;
} {
  const provenance = classifyProviderSender({
    runtimeId: EXTENSION_ID,
    sender: {
      documentId: DOCUMENT_ID,
      documentLifecycle: "active",
      frameId: 4,
      id: EXTENSION_ID,
      origin,
      tab: { id: 19, url: "https://host.example/parent" },
      url: `${origin}/embedded`,
    },
  });
  const session = new ProviderPortSession(provenance, {
    randomSource: new FixedRandom(),
    timerSource: new InertTimers(),
    readNow: () => 1_000,
  });
  const owned = session.open(request);
  return {
    session,
    owned,
    lease: Object.freeze({
      owned,
      assertActive: () => session.assertActive(owned),
    }),
  };
}

class MemoryApprovals {
  readonly records = new Map<string, ApprovalRecord>();
  readonly reads: string[] = [];
  readImpl: ((id: string) => Promise<ApprovalRecord | null>) | undefined;

  async read(id: string): Promise<ApprovalRecord | null> {
    this.reads.push(id);
    if (this.readImpl !== undefined) return this.readImpl(id);
    const current = this.records.get(id);
    return current === undefined ? null : snapshotApprovalRecord(current);
  }

  async readSigning(): Promise<null> {
    return null;
  }
}

/** Stands in for the X-1 capability port the content owner transfers. */
class FlowCapabilityPort implements ProviderPageMessagePortApi {
  readonly listeners = new Set<ProviderPageMessagePortListener>();
  readonly posted: unknown[] = [];

  addEventListener(
    type: "message",
    listener: ProviderPageMessagePortListener,
  ): void {
    expect(type).toBe("message");
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

  start(): void {}

  close(): void {}

  deliver(data: unknown): void {
    for (const listener of [...this.listeners]) listener({ data });
  }
}

class FlowPage implements ProviderPageWindowApi {
  readonly location = { origin: "https://iframe.example" };
  readonly listeners = new Set<ProviderPageWindowMessageListener>();
  readonly posted: Array<{ readonly message: unknown; readonly targetOrigin: string }> = [];
  readonly capability = new FlowCapabilityPort();

  addEventListener(
    type: "message",
    listener: ProviderPageWindowMessageListener,
  ): void {
    expect(type).toBe("message");
    this.listeners.add(listener);
  }

  removeEventListener(
    type: "message",
    listener: ProviderPageWindowMessageListener,
  ): void {
    expect(type).toBe("message");
    this.listeners.delete(listener);
  }

  postMessage(message: unknown, targetOrigin: string): void {
    // The one capability claim is not page-visible provider traffic.
    if (readProviderCapabilityRequestEnvelope(message) !== null) return;
    this.posted.push({ message, targetOrigin });
  }

  emit(data: unknown, ports?: readonly unknown[]): void {
    const event: ProviderPageWindowMessageEvent = {
      data,
      origin: this.location.origin,
      source: this,
      ...(ports === undefined ? {} : { ports }),
    };
    for (const listener of [...this.listeners]) listener(event);
  }

  /** Push the one-shot capability grant into the document. */
  grant(): FlowCapabilityPort {
    this.emit(createProviderCapabilityEnvelope(), [this.capability]);
    return this.capability;
  }
}

class MemoryProviderOperations implements ProviderOperationRepository {
  readonly records = new Map<string, ProviderOperationRecord>();
  readonly events: string[] = [];
  bindGate: Promise<void> | undefined;
  bindStarted: (() => void) | undefined;
  bindError: unknown;

  async claim(input: {
    readonly identity: ProviderOperationIdentity;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly now: number;
  }): Promise<ProviderOperationClaim> {
    const current = this.records.get(input.identity.key);
    if (current !== undefined) {
      this.events.push("operation.claim-replay");
      return { created: false, record: snapshotProviderOperation(current) };
    }
    const record = createPreparingProviderOperation(input);
    this.records.set(record.key, record);
    this.events.push("operation.claim-commit");
    return { created: true, record: snapshotProviderOperation(record) };
  }

  async read(input: {
    readonly key: string;
    readonly now: number;
  }): Promise<ProviderOperationRecord | null> {
    void input.now;
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
    this.events.push("operation.bind-start");
    this.bindStarted?.();
    await this.bindGate;
    if (this.bindError !== undefined) throw this.bindError;
    const current = this.records.get(input.key);
    if (current === undefined) throw new Error("missing provider operation");
    const bound = bindProviderOperation(current, input);
    this.records.set(bound.key, bound);
    this.events.push("operation.bind-commit");
    return snapshotProviderOperation(bound);
  }

  async fail(input: {
    readonly key: string;
    readonly expectedRequestDigest: Uint8Array;
    readonly failureCode: ProviderOperationFailureCode;
    readonly now: number;
  }): Promise<ProviderOperationRecord> {
    const current = this.records.get(input.key);
    if (current === undefined) throw new Error("missing provider operation");
    if (!current.requestDigest.every(
      (byte, index) => byte === input.expectedRequestDigest[index],
    )) {
      throw new Error("provider operation digest mismatch");
    }
    const failed = failProviderOperation(current, input.failureCode, input.now);
    this.records.set(failed.key, failed);
    this.events.push("operation.fail-commit");
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

function approvalFromRequest(
  request: SessionApprovalRequest,
  id = APPROVAL_ID,
): ApprovalRecord {
  return createPendingApprovalRecord({
    id,
    origin: request.origin,
    tabId: request.tabId,
    frameId: request.frameId,
    documentId: request.documentId,
    account: request.requestedAccount,
    method: request.method,
    chain: request.chain,
    genesisHash: new Uint8Array(32).fill(0x22),
    programId: new Uint8Array(32).fill(0x33),
    rawMessage: Uint8Array.of(9, 8, 7),
    policyVersion: 4,
    createdAt: 1_000,
    expiresAt: 2_000,
  });
}

function preparedFromRecord(record: ApprovalRecord): PreparedSessionApproval {
  return Object.freeze({
    id: record.id,
    messageDigest: record.messageDigest.slice(),
    account: record.account.slice(),
    chain: record.chain,
    blockhash: new Uint8Array(32).fill(0x55),
    lastValidBlockHeight: 500,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
  });
}

class FakeCoordinator implements ProviderApprovalCoordinator {
  readonly prepareCalls: SessionApprovalRequest[] = [];
  readonly approveCalls: { readonly id: string; readonly digest: Uint8Array }[] = [];
  readonly cancelCalls: string[] = [];
  prepareImpl: ((request: SessionApprovalRequest) => Promise<PreparedSessionApproval>) | undefined;
  approveImpl: ((
    id: string,
    digest: Uint8Array,
  ) => Promise<SignedSessionApproval>) | undefined;
  cancelImpl: ((id: string) => Promise<ApprovalRecord>) | undefined;

  constructor(readonly approvals: MemoryApprovals) {}

  async prepare(request: SessionApprovalRequest): Promise<PreparedSessionApproval> {
    this.prepareCalls.push(Object.freeze({
      ...request,
      requestedAccount: request.requestedAccount.slice(),
      sourceTransactionBytes: request.sourceTransactionBytes.slice(),
    }));
    if (this.prepareImpl !== undefined) return this.prepareImpl(request);
    const record = approvalFromRequest(request);
    this.approvals.records.set(record.id, snapshotApprovalRecord(record));
    return preparedFromRecord(record);
  }

  async cancel(id: string): Promise<ApprovalRecord> {
    this.cancelCalls.push(id);
    if (this.cancelImpl !== undefined) return this.cancelImpl(id);
    const current = this.approvals.records.get(id);
    if (current === undefined || current.state !== "pending") {
      throw new Error("transition refused");
    }
    const cancelled = resolveApprovalRecord(current, "cancelled", 1_100);
    this.approvals.records.set(id, cancelled);
    return snapshotApprovalRecord(cancelled);
  }

  async approve(
    id: string,
    digest: Uint8Array,
  ): Promise<SignedSessionApproval> {
    this.approveCalls.push({ id, digest: digest.slice() });
    if (this.approveImpl !== undefined) return this.approveImpl(id, digest);
    const current = this.approvals.records.get(id);
    if (current === undefined || current.state !== "pending") {
      throw new Error("approval refused");
    }
    const approved = resolveApprovalRecord(current, "approved", 1_100);
    this.approvals.records.set(id, approved);
    return Object.freeze({
      id,
      messageDigest: digest.slice(),
      transactionBytes: Uint8Array.of(1, 2, 3, 4),
      signature: new Uint8Array(64).fill(0x55),
    });
  }
}

class FakeSelectionResolver implements ProviderApprovalSelectionResolver {
  readonly calls: ProviderApprovalSelectionInput[] = [];
  readonly authority = new AbortController();
  resolveImpl: ((input: ProviderApprovalSelectionInput) => Promise<{
    readonly account: Uint8Array;
    readonly chain: "solana:devnet";
    readonly coordinator: ProviderApprovalCoordinator;
    readonly authoritySignal: AbortSignal;
  }>) | undefined;

  constructor(readonly coordinator: ProviderApprovalCoordinator) {}

  async resolve(input: ProviderApprovalSelectionInput) {
    this.calls.push(input);
    if (this.resolveImpl !== undefined) return this.resolveImpl(input);
    return {
      account: ACCOUNT.slice(),
      chain: "solana:devnet" as const,
      coordinator: this.coordinator,
      authoritySignal: this.authority.signal,
    };
  }
}

class FakeLauncher {
  readonly calls: { readonly id: string; readonly signal: AbortSignal }[] = [];
  launchImpl: ((id: string, signal: AbortSignal) => Promise<void>) | undefined;

  async launch(id: string, signal: AbortSignal): Promise<void> {
    this.calls.push({ id, signal });
    return this.launchImpl?.(id, signal);
  }
}

function install(overrides: {
  readonly approvals?: MemoryApprovals;
  readonly coordinator?: FakeCoordinator;
  readonly resolver?: FakeSelectionResolver;
  readonly launcher?: FakeLauncher;
} = {}) {
  const approvals = overrides.approvals ?? new MemoryApprovals();
  const coordinator = overrides.coordinator ?? new FakeCoordinator(approvals);
  const resolver = overrides.resolver ?? new FakeSelectionResolver(coordinator);
  const launcher = overrides.launcher ?? new FakeLauncher();
  const fatals: unknown[] = [];
  const owner = new ProviderApprovalRequestOwner({
    approvals,
    selection: resolver,
    windows: launcher,
    onFatal: (error) => fatals.push(error),
  });
  return { approvals, coordinator, resolver, launcher, fatals, owner };
}

describe("provider-bound session approval preparation", () => {
  it("keeps a proven approval hidden until its prepared handle is explicitly opened", async () => {
    const { session, lease } = providerLease();
    const installed = install();

    const handle = await installed.owner.prepare(lease);

    expect(installed.coordinator.prepareCalls).toHaveLength(1);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("pending");
    expect(installed.launcher.calls).toEqual([]);
    expect(Object.keys(handle).sort()).toEqual([
      "account",
      "approve",
      "cancel",
      "chain",
      "id",
      "messageDigest",
      "open",
      "settle",
      "signal",
      "terminal",
    ]);

    const firstOpen = handle.open();
    const concurrentOpen = handle.open();
    expect(concurrentOpen).toBe(firstOpen);
    await expect(firstOpen).resolves.toBeUndefined();
    await expect(handle.open()).resolves.toBeUndefined();
    expect(installed.launcher.calls).toHaveLength(1);

    await expect(handle.cancel()).resolves.toBe(true);
    session.disconnect();
  });

  it("owns one exact durable signing attempt without releasing signed bytes", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const handle = await installed.owner.prepare(lease);
    const expectedDigest = handle.messageDigest;

    const first = handle.approve();
    const concurrent = handle.approve();
    expect(concurrent).toBe(first);
    await expect(first).resolves.toBe(true);
    await expect(handle.terminal).resolves.toBe(true);

    expect(installed.coordinator.approveCalls).toEqual([{
      id: APPROVAL_ID,
      digest: expectedDigest,
    }]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("approved");
    expect(handle.signal.aborted).toBe(false);
    expect(installed.owner.activeCount).toBe(1);
    await expect(handle.settle()).resolves.toBe(true);
    expect(handle.signal.aborted).toBe(true);
    expect(installed.owner.activeCount).toBe(0);
    session.disconnect();
  });

  it("scrubs a coordinator result and poisons the owner when its digest changes", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const handle = await installed.owner.prepare(lease);
    const returnedDigest = new Uint8Array(32).fill(0xee);
    const returnedTransaction = Uint8Array.of(4, 3, 2, 1);
    const returnedSignature = new Uint8Array(64).fill(0xaa);
    installed.coordinator.approveImpl = async (id) => {
      const current = installed.approvals.records.get(id)!;
      installed.approvals.records.set(
        id,
        resolveApprovalRecord(current, "approved", 1_100),
      );
      return {
        id,
        messageDigest: returnedDigest,
        transactionBytes: returnedTransaction,
        signature: returnedSignature,
      };
    };

    await expect(handle.approve()).rejects.toThrow(
      "signed approval differs from the exact durable binding",
    );
    expect(returnedDigest).toEqual(new Uint8Array(32));
    expect(returnedTransaction).toEqual(new Uint8Array(4));
    expect(returnedSignature).toEqual(new Uint8Array(64));
    expect(installed.fatals).toHaveLength(1);
    await expect(handle.terminal).resolves.toBe(false);
    await flush();
    expect(installed.owner.activeCount).toBe(0);
    session.disconnect();
  });

  it("refuses success when signed bytes lack an exact approved durable row", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const handle = await installed.owner.prepare(lease);
    installed.coordinator.approveImpl = async (id, digest) => ({
      id,
      messageDigest: digest.slice(),
      transactionBytes: Uint8Array.of(1, 2, 3),
      signature: new Uint8Array(64).fill(0x44),
    });

    const approval = handle.approve();
    await expect(approval).rejects.toThrow("terminal record is required");
    expect(handle.approve()).toBe(approval);
    expect(installed.coordinator.approveCalls).toHaveLength(1);
    expect(installed.fatals).toHaveLength(1);
    await expect(handle.terminal).resolves.toBe(false);
    await flush();
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("cancelled");
    session.disconnect();
  });

  it("suppresses a durable signing result when keyring authority ends in flight", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const handle = await installed.owner.prepare(lease);
    let terminalSettled = false;
    void handle.terminal.then(() => {
      terminalSettled = true;
    });
    const signed = deferred<SignedSessionApproval>();
    const returnedTransaction = Uint8Array.of(7, 7, 7);
    const returnedSignature = new Uint8Array(64).fill(0x77);
    installed.coordinator.approveImpl = (id, digest) => {
      const current = installed.approvals.records.get(id)!;
      installed.approvals.records.set(
        id,
        resolveApprovalRecord(current, "approved", 1_100),
      );
      return signed.promise.then(() => ({
        id,
        messageDigest: digest,
        transactionBytes: returnedTransaction,
        signature: returnedSignature,
      }));
    };

    const approving = handle.approve();
    await flush();
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("approved");
    expect(terminalSettled).toBe(false);
    installed.resolver.authority.abort();
    await flush();
    expect(terminalSettled).toBe(false);
    signed.resolve(Object.freeze({
      id: APPROVAL_ID,
      messageDigest: handle.messageDigest,
      transactionBytes: returnedTransaction,
      signature: returnedSignature,
    }));

    await expect(approving).rejects.toThrow("selected keyring authority is revoked");
    await expect(handle.terminal).resolves.toBe(true);
    expect(returnedTransaction).toEqual(new Uint8Array(3));
    expect(returnedSignature).toEqual(new Uint8Array(64));
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("approved");
    expect(installed.fatals).toEqual([]);
    expect(handle.signal.aborted).toBe(true);
    session.disconnect();
  });

  it("cancels a hidden prepared approval when its Port disconnects before open", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const handle = await installed.owner.prepare(lease);

    session.disconnect();
    await flush();

    expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("cancelled");
    await expect(handle.terminal).resolves.toBe(false);
    expect(installed.launcher.calls).toEqual([]);
    await expect(handle.open()).rejects.toThrow("request is no longer owned");
    expect(installed.launcher.calls).toEqual([]);
  });

  it("builds coordinator input only from the live browser lease and proven selection", async () => {
    const { session, lease } = providerLease();
    const installed = install();

    const handle = await installed.owner.launch(lease);

    expect(MAX_ACTIVE_PROVIDER_APPROVAL_REQUESTS).toBe(32);
    expect(installed.resolver.calls).toHaveLength(1);
    expect(installed.resolver.calls[0]).toMatchObject({
      requestedAccountAddress: ACCOUNT_ADDRESS,
      requestedChain: "solana:devnet",
      method: "solana:signTransaction",
      signal: lease.owned.signal,
    });
    expect(Object.keys(installed.resolver.calls[0]!).sort()).toEqual([
      "method",
      "requestedAccountAddress",
      "requestedChain",
      "signal",
    ]);
    expect(installed.coordinator.prepareCalls).toHaveLength(1);
    expect(installed.coordinator.prepareCalls[0]).toMatchObject({
      origin: "https://iframe.example",
      tabId: 19,
      frameId: 4,
      documentId: DOCUMENT_ID,
      method: "solana:signTransaction",
      chain: "solana:devnet",
    });
    expect(installed.coordinator.prepareCalls[0]!.requestedAccount).toEqual(ACCOUNT);
    expect(installed.coordinator.prepareCalls[0]!.sourceTransactionBytes).toEqual(
      Uint8Array.of(1, 2, 3),
    );
    expect(installed.launcher.calls).toHaveLength(1);
    expect(installed.launcher.calls[0]!.id).toBe(APPROVAL_ID);
    expect(installed.launcher.calls[0]!.signal).not.toBe(lease.owned.signal);
    expect(installed.launcher.calls[0]!.signal.aborted).toBe(false);
    expect(handle.id).toBe(APPROVAL_ID);
    expect(handle.id).not.toBe(lease.owned.id);
    expect(handle.account).toEqual(ACCOUNT);
    expect(handle.chain).toBe("solana:devnet");
    expect(Object.keys(handle).sort()).toEqual([
      "account",
      "cancel",
      "chain",
      "id",
      "messageDigest",
      "settle",
    ]);

    const rejected = resolveApprovalRecord(
      installed.approvals.records.get(APPROVAL_ID)!,
      "rejected",
      1_100,
    );
    installed.approvals.records.set(APPROVAL_ID, rejected);
    await expect(handle.settle()).resolves.toBe(true);
    expect(installed.owner.activeCount).toBe(0);
    session.disconnect();
    await flush();
    expect(installed.coordinator.cancelCalls).toEqual([]);
  });

  it.each([
    ["standard:connect", { silent: false }],
    [
      "solana:signAndSendTransaction",
      {
        accountAddress: ACCOUNT_ADDRESS,
        transaction: [1, 2, 3],
        chain: "solana:devnet",
      },
    ],
  ])("refuses unsupported %s before authority or window work", async (method, params) => {
    const { session, lease } = providerLease(rawRequest({ method, params }));
    const installed = install();
    await expect(installed.owner.launch(lease)).rejects.toBeInstanceOf(
      ProviderApprovalRequestStateError,
    );
    expect(installed.resolver.calls).toEqual([]);
    expect(installed.coordinator.prepareCalls).toEqual([]);
    expect(installed.launcher.calls).toEqual([]);
    session.disconnect();
  });

  it("refuses a resolver-selected account or chain that differs from the page request", async () => {
    const first = providerLease();
    const firstInstalled = install();
    firstInstalled.resolver.resolveImpl = async () => ({
      account: new Uint8Array(32).fill(0x12),
      chain: "solana:devnet",
      coordinator: firstInstalled.coordinator,
      authoritySignal: firstInstalled.resolver.authority.signal,
    });
    await expect(firstInstalled.owner.launch(first.lease)).rejects.toThrow(
      "selected account does not equal the requested account",
    );
    expect(firstInstalled.coordinator.prepareCalls).toEqual([]);
    first.session.disconnect();

    const second = providerLease();
    const secondInstalled = install();
    secondInstalled.resolver.resolveImpl = async () => ({
      account: ACCOUNT.slice(),
      chain: "solana:mainnet" as "solana:devnet",
      coordinator: secondInstalled.coordinator,
      authoritySignal: secondInstalled.resolver.authority.signal,
    });
    await expect(secondInstalled.owner.launch(second.lease)).rejects.toThrow(
      "selected chain does not equal the requested chain",
    );
    expect(secondInstalled.coordinator.prepareCalls).toEqual([]);
    second.session.disconnect();
  });

  it("stops after delayed selection when the provider disconnects", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const selection = deferred<{
      readonly account: Uint8Array;
      readonly chain: "solana:devnet";
      readonly coordinator: ProviderApprovalCoordinator;
      readonly authoritySignal: AbortSignal;
    }>();
    installed.resolver.resolveImpl = () => selection.promise;
    const launching = installed.owner.launch(lease);
    session.disconnect();
    selection.resolve({
      account: ACCOUNT.slice(),
      chain: "solana:devnet",
      coordinator: installed.coordinator,
      authoritySignal: installed.resolver.authority.signal,
    });

    await expect(launching).rejects.toThrow("request is no longer owned");
    expect(installed.coordinator.prepareCalls).toEqual([]);
    expect(installed.launcher.calls).toEqual([]);
    expect(installed.approvals.records.size).toBe(0);
  });

  it("refuses a keyring authority revoked in the resolver Promise settlement gap", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    installed.resolver.resolveImpl = async () => {
      queueMicrotask(() => installed.resolver.authority.abort());
      return {
        account: ACCOUNT.slice(),
        chain: "solana:devnet" as const,
        coordinator: installed.coordinator,
        authoritySignal: installed.resolver.authority.signal,
      };
    };

    await expect(installed.owner.launch(lease)).rejects.toThrow(
      "selected keyring authority is revoked",
    );
    expect(installed.coordinator.prepareCalls).toEqual([]);
    expect(installed.approvals.records.size).toBe(0);
    expect(installed.launcher.calls).toEqual([]);
    session.disconnect();
  });

  it("cancels an exact row when keyring authority is revoked during preparation", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const entered = deferred<void>();
    const release = deferred<void>();
    installed.coordinator.prepareImpl = async (request) => {
      entered.resolve();
      await release.promise;
      const record = approvalFromRequest(request);
      installed.approvals.records.set(record.id, record);
      return preparedFromRecord(record);
    };

    const launching = installed.owner.launch(lease);
    await entered.promise;
    installed.resolver.authority.abort();
    release.resolve();

    await expect(launching).rejects.toThrow("selected keyring authority is revoked");
    expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("cancelled");
    expect(installed.launcher.calls).toEqual([]);
    session.disconnect();
  });

  it("aborts the window lifetime and cancels when keyring authority changes after launch", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const handle = await installed.owner.launch(lease);
    const windowSignal = installed.launcher.calls[0]!.signal;

    installed.resolver.authority.abort();
    expect(windowSignal.aborted).toBe(true);
    await flush();

    expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("cancelled");
    await expect(handle.cancel()).resolves.toBe(false);
    expect(installed.owner.activeCount).toBe(0);
    session.disconnect();
  });

  it("disconnect during window creation cancels only the exact durable request", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const opened = deferred<void>();
    installed.launcher.launchImpl = () => opened.promise;
    const unrelated = approvalFromRequest({
      origin: "https://other.example",
      tabId: 20,
      frameId: 0,
      documentId: "other-document",
      requestedAccount: ACCOUNT,
      method: "solana:signTransaction",
      chain: "solana:devnet",
      sourceTransactionBytes: Uint8Array.of(4),
    }, `req_${"cd".repeat(16)}`);
    installed.approvals.records.set(unrelated.id, unrelated);

    const launching = installed.owner.launch(lease);
    await flush();
    expect(installed.launcher.calls).toHaveLength(1);
    session.disconnect();
    await flush();
    expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("cancelled");
    expect(installed.approvals.records.get(unrelated.id)?.state).toBe("pending");
    opened.resolve();
    await expect(launching).rejects.toThrow("request is no longer owned");
    expect(installed.fatals).toEqual([]);
  });

  it("cancels the exact prepared row when opening the approval window fails", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const openFailure = new Error("window create failed");
    installed.launcher.launchImpl = async () => Promise.reject(openFailure);

    await expect(installed.owner.launch(lease)).rejects.toBe(openFailure);
    expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("cancelled");
    expect(installed.owner.activeCount).toBe(0);
    expect(installed.fatals).toEqual([]);
    session.disconnect();
  });

  it("does not launch when authoritative preparation reports a state change", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const authorityChange = new Error("authority changed");
    installed.coordinator.prepareImpl = async (request) => {
      const current = approvalFromRequest(request);
      installed.approvals.records.set(current.id, current);
      installed.approvals.records.set(
        current.id,
        resolveApprovalRecord(current, "cancelled", 1_100),
      );
      throw authorityChange;
    };

    await expect(installed.owner.launch(lease)).rejects.toBe(authorityChange);
    expect(installed.launcher.calls).toEqual([]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("cancelled");
    expect(installed.coordinator.cancelCalls).toEqual([]);
    session.disconnect();
  });

  it("accepts a launcher's independently proven terminal cancellation race", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const openFailure = new Error("window disappeared");
    installed.launcher.launchImpl = async (id) => {
      const current = installed.approvals.records.get(id)!;
      installed.approvals.records.set(
        id,
        resolveApprovalRecord(current, "cancelled", 1_100),
      );
      throw openFailure;
    };

    await expect(installed.owner.launch(lease)).rejects.toBe(openFailure);
    expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
    expect(installed.approvals.reads).toEqual([APPROVAL_ID, APPROVAL_ID]);
    expect(installed.fatals).toEqual([]);
    session.disconnect();
  });

  it("reports fatal when failed cleanup leaves the exact durable row pending", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    installed.launcher.launchImpl = async () => Promise.reject(new Error("window failed"));
    installed.coordinator.cancelImpl = async () => Promise.reject(new Error("cancel failed"));

    await expect(installed.owner.launch(lease)).rejects.toThrow(
      "durable approval cancellation is unproven",
    );
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("pending");
    expect(installed.fatals).toHaveLength(1);
    expect(installed.owner.activeCount).toBe(0);
    session.disconnect();
  });

  it("cancels a coordinator result whose prepared account binding is inconsistent", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    installed.coordinator.prepareImpl = async (request) => {
      const record = approvalFromRequest(request);
      installed.approvals.records.set(record.id, record);
      return Object.freeze({
        ...preparedFromRecord(record),
        account: new Uint8Array(32).fill(0x77),
      });
    };

    await expect(installed.owner.launch(lease)).rejects.toThrow(
      "prepared account differs from the proven selection",
    );
    expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
    expect(installed.launcher.calls).toEqual([]);
    session.disconnect();
  });

  it("recovers a valid durable locator before cancelling a malformed prepared result", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    installed.coordinator.prepareImpl = async (request) => {
      const record = approvalFromRequest(request);
      installed.approvals.records.set(record.id, record);
      return {
        ...preparedFromRecord(record),
        blockhash: new Uint8Array(31),
      } as unknown as PreparedSessionApproval;
    };

    await expect(installed.owner.launch(lease)).rejects.toThrow(
      "prepared blockhash must contain exactly 32 bytes",
    );
    expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("cancelled");
    expect(installed.launcher.calls).toEqual([]);
    expect(installed.fatals).toEqual([]);
    session.disconnect();
  });

  it("fails closed when a resolved preparation has no trustworthy cleanup locator", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    installed.coordinator.prepareImpl = async (request) => {
      const record = approvalFromRequest(request);
      installed.approvals.records.set(record.id, record);
      return {
        ...preparedFromRecord(record),
        id: "page_chosen_id",
      } as unknown as PreparedSessionApproval;
    };

    await expect(installed.owner.launch(lease)).rejects.toThrow(
      "durable approval cleanup target is unproven after preparation",
    );
    expect(installed.coordinator.cancelCalls).toEqual([]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("pending");
    expect(installed.fatals).toHaveLength(1);
    expect(installed.launcher.calls).toEqual([]);
    session.disconnect();
  });

  it("never cancels a durable locator that does not bind to the browser request", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    installed.coordinator.prepareImpl = async (request) => {
      const unrelated = approvalFromRequest({
        ...request,
        origin: "https://unrelated.example",
      });
      installed.approvals.records.set(unrelated.id, unrelated);
      return preparedFromRecord(unrelated);
    };

    await expect(installed.owner.launch(lease)).rejects.toThrow(
      "durable approval cleanup target is unproven after preparation",
    );
    expect(installed.coordinator.cancelCalls).toEqual([]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("pending");
    expect(installed.fatals).toHaveLength(1);
    expect(installed.launcher.calls).toEqual([]);
    session.disconnect();
  });

  it("serializes duplicate ownership while the first request is preparing", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const selection = deferred<{
      readonly account: Uint8Array;
      readonly chain: "solana:devnet";
      readonly coordinator: ProviderApprovalCoordinator;
      readonly authoritySignal: AbortSignal;
    }>();
    installed.resolver.resolveImpl = () => selection.promise;
    const first = installed.owner.launch(lease);

    await expect(installed.owner.launch(lease)).rejects.toThrow(
      "provider request already has an approval owner",
    );
    selection.resolve({
      account: ACCOUNT.slice(),
      chain: "solana:devnet",
      coordinator: installed.coordinator,
      authoritySignal: installed.resolver.authority.signal,
    });
    const handle = await first;
    await expect(handle.cancel()).resolves.toBe(true);
    expect(installed.coordinator.prepareCalls).toHaveLength(1);
    expect(installed.launcher.calls).toHaveLength(1);
    session.disconnect();
  });

  it("reserves capacity before asynchronous authority resolution", async () => {
    const installed = install();
    const selection = deferred<{
      readonly account: Uint8Array;
      readonly chain: "solana:devnet";
      readonly coordinator: ProviderApprovalCoordinator;
      readonly authoritySignal: AbortSignal;
    }>();
    installed.resolver.resolveImpl = () => selection.promise;
    // X-2: the global cap is only reachable across enough distinct origins.
    const leases = Array.from(
      { length: MAX_ACTIVE_PROVIDER_APPROVAL_REQUESTS + 1 },
      (_, index) => providerLease(
        rawRequest(),
        `https://site-${Math.floor(index / MAX_PROVIDER_APPROVAL_REQUESTS_PER_ORIGIN)}.example`,
      ),
    );
    const launches = leases.slice(0, MAX_ACTIVE_PROVIDER_APPROVAL_REQUESTS)
      .map(({ lease: current }) => installed.owner.launch(current));

    expect(installed.owner.activeCount).toBe(MAX_ACTIVE_PROVIDER_APPROVAL_REQUESTS);
    await expect(
      installed.owner.launch(leases[MAX_ACTIVE_PROVIDER_APPROVAL_REQUESTS]!.lease),
    ).rejects.toThrow("too many active provider approval requests");
    for (const { session } of leases) session.disconnect();
    selection.resolve({
      account: ACCOUNT.slice(),
      chain: "solana:devnet",
      coordinator: installed.coordinator,
      authoritySignal: installed.resolver.authority.signal,
    });
    const results = await Promise.allSettled(launches);
    expect(results.every((result) => result.status === "rejected")).toBe(true);
    expect(installed.owner.activeCount).toBe(0);
    expect(installed.coordinator.prepareCalls).toEqual([]);
  });

  it("serves a second origin after the first has used its whole share", async () => {
    const installed = install();
    const selection = deferred<{
      readonly account: Uint8Array;
      readonly chain: "solana:devnet";
      readonly coordinator: ProviderApprovalCoordinator;
      readonly authoritySignal: AbortSignal;
    }>();
    installed.resolver.resolveImpl = () => selection.promise;
    const hostile = Array.from(
      { length: MAX_PROVIDER_APPROVAL_REQUESTS_PER_ORIGIN },
      () => providerLease(rawRequest(), "https://hostile.example"),
    );
    const excess = providerLease(rawRequest(), "https://hostile.example");
    const victim = Array.from(
      { length: MAX_PROVIDER_APPROVAL_REQUESTS_PER_ORIGIN },
      () => providerLease(rawRequest(), "https://victim.example"),
    );
    const launches = hostile.map(({ lease: current }) =>
      installed.owner.launch(current)
    );

    expect(installed.owner.activeCount).toBe(
      MAX_PROVIDER_APPROVAL_REQUESTS_PER_ORIGIN,
    );
    await expect(installed.owner.launch(excess.lease)).rejects.toBeInstanceOf(
      ProviderOriginCapacityError,
    );
    await expect(installed.owner.launch(excess.lease)).rejects.toThrow(
      "origin https://hostile.example may hold at most 4 active approval requests",
    );

    // The victim origin is still served while the hostile origin is refused.
    launches.push(...victim.map(({ lease: current }) =>
      installed.owner.launch(current)
    ));
    expect(installed.owner.activeCount).toBe(
      MAX_PROVIDER_APPROVAL_REQUESTS_PER_ORIGIN * 2,
    );
    expect(MAX_PROVIDER_APPROVAL_REQUESTS_PER_ORIGIN).toBe(4);

    for (const { session } of [...hostile, excess, ...victim]) session.disconnect();
    selection.resolve({
      account: ACCOUNT.slice(),
      chain: "solana:devnet",
      coordinator: installed.coordinator,
      authoritySignal: installed.resolver.authority.signal,
    });
    const results = await Promise.allSettled(launches);
    expect(results.every((result) => result.status === "rejected")).toBe(true);
    expect(installed.owner.activeCount).toBe(0);
  });

  it("cancels a preparation that resolves after owner disposal", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const prepared = deferred<PreparedSessionApproval>();
    installed.coordinator.prepareImpl = async (request) => {
      const record = approvalFromRequest(request);
      installed.approvals.records.set(record.id, record);
      return prepared.promise;
    };
    const launching = installed.owner.launch(lease);
    await flush();
    installed.owner.dispose();
    prepared.resolve(preparedFromRecord(installed.approvals.records.get(APPROVAL_ID)!));

    await expect(launching).rejects.toThrow("owner is disposed");
    expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("cancelled");
    expect(installed.launcher.calls).toEqual([]);
    expect(installed.fatals).toEqual([]);
    session.disconnect();
  });

  it("keeps cancellation proof stable while terminal settlement is in flight", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const handle = await installed.owner.launch(lease);
    const terminalRead = deferred<ApprovalRecord | null>();
    installed.approvals.readImpl = () => terminalRead.promise;

    const settling = handle.settle();
    await flush();
    await expect(handle.cancel()).resolves.toBe(true);
    terminalRead.resolve(snapshotApprovalRecord(
      installed.approvals.records.get(APPROVAL_ID)!,
    ));
    await expect(settling).resolves.toBe(true);
    expect(installed.owner.activeCount).toBe(0);
    expect(installed.fatals).toEqual([]);
    session.disconnect();
  });

  it("settles a handle only with an exact terminal durable binding", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const handle = await installed.owner.launch(lease);
    const pending = installed.approvals.records.get(APPROVAL_ID)!;

    await expect(handle.settle()).rejects.toThrow("terminal record is required");
    expect(installed.owner.activeCount).toBe(1);

    const terminal = resolveApprovalRecord(pending, "rejected", 1_100);
    installed.approvals.records.set(APPROVAL_ID, terminal);
    await expect(handle.settle()).resolves.toBe(true);
    await expect(handle.settle()).resolves.toBe(false);
    session.disconnect();
    await flush();
    expect(installed.coordinator.cancelCalls).toEqual([]);
  });

  it("poisons the owner when terminal storage no longer has the exact binding", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const handle = await installed.owner.launch(lease);
    const wrong = approvalFromRequest(
      installed.coordinator.prepareCalls[0]!,
      `req_${"ef".repeat(16)}`,
    );
    installed.approvals.records.set(
      APPROVAL_ID,
      resolveApprovalRecord(wrong, "rejected", 1_100),
    );

    await expect(handle.settle()).rejects.toThrow(
      "terminal record binding differs",
    );
    await flush();
    expect(installed.fatals).toHaveLength(1);
    expect(installed.owner.activeCount).toBe(0);
    await expect(installed.owner.launch(lease)).rejects.toThrow(
      "owner is disposed",
    );
    session.disconnect();
  });
});

describe("provider operation to approval composition", () => {
  function composite(
    installed: ReturnType<typeof install>,
    operations: MemoryProviderOperations,
    actions: { register(action: ProviderApprovalActionRegistration): void } =
      new ProviderApprovalActionOwner(),
  ): ProviderApprovalOperationOwner {
    return new ProviderApprovalOperationOwner({
      actions,
      approvals: installed.owner,
      operations: new ProviderOperationOwner(operations, {
        readNow: () => 1_100,
      }),
    });
  }

  it("commits the exact operation binding before making the approval visible", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const operations = new MemoryProviderOperations();
    const actionOwner = new ProviderApprovalActionOwner();
    const actions = {
      register(action: ProviderApprovalActionRegistration): void {
        operations.events.push("action.register");
        actionOwner.register(action);
      },
    };
    installed.coordinator.prepareImpl = async (request) => {
      operations.events.push("approval.prepare");
      const record = approvalFromRequest(request);
      installed.approvals.records.set(record.id, record);
      return preparedFromRecord(record);
    };
    installed.launcher.launchImpl = async () => {
      operations.events.push("window.open");
      expect([...operations.records.values()]).toHaveLength(1);
      expect([...operations.records.values()][0]).toMatchObject({
        state: "bound",
        approvalId: APPROVAL_ID,
      });
    };

    const result = await composite(installed, operations, actions).launch(lease);

    expect(result.kind).toBe("opened");
    expect(operations.events).toEqual([
      "operation.claim-commit",
      "approval.prepare",
      "operation.bind-start",
      "operation.bind-commit",
      "action.register",
      "window.open",
    ]);
    if (result.kind === "opened") {
      expect(Object.keys(result.approval).sort()).toEqual([
        "account",
        "cancel",
        "chain",
        "id",
        "messageDigest",
        "settle",
      ]);
      expect(actionOwner.canApprove(
        result.approval.id,
        result.approval.messageDigest,
      )).toBe(true);
      await expect(actionOwner.approve(result.approval.id)).resolves.toBe(true);
      await expect(result.terminal).resolves.toBe(true);
      expect(installed.coordinator.approveCalls).toHaveLength(1);
      await expect(actionOwner.settle(result.approval.id)).resolves.toBe(true);
      expect(actionOwner.activeCount).toBe(0);
      await expect(result.approval.cancel()).resolves.toBe(false);
    }
    session.disconnect();
  });

  it("cancels the exact approval and keeps it hidden when binding is unproven", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const operations = new MemoryProviderOperations();
    operations.bindError = new Error("IndexedDB transaction aborted");
    installed.launcher.launchImpl = async () => {
      operations.events.push("window.open");
    };

    await expect(composite(installed, operations).launch(lease)).rejects.toThrow(
      "durable approval binding is unproven",
    );

    expect(installed.launcher.calls).toEqual([]);
    expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("cancelled");
    expect([...operations.records.values()][0]?.state).toBe("preparing");
    session.disconnect();
  });

  it("keeps the window hidden and cancels when action registration fails", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const operations = new MemoryProviderOperations();
    const registrationFailure = new Error("action registry unavailable");
    installed.launcher.launchImpl = async () => {
      operations.events.push("window.open");
    };

    await expect(composite(installed, operations, {
      register(): void {
        operations.events.push("action.register");
        throw registrationFailure;
      },
    }).launch(lease)).rejects.toBe(registrationFailure);

    expect(operations.events).toContain("action.register");
    expect(installed.launcher.calls).toEqual([]);
    expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("cancelled");
    expect([...operations.records.values()][0]).toMatchObject({
      state: "bound",
      approvalId: APPROVAL_ID,
    });
    session.disconnect();
  });

  it("cancels a prepared row when its visibility capability is malformed", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const operations = new MemoryProviderOperations();
    const owner = new ProviderApprovalOperationOwner({
      actions: new ProviderApprovalActionOwner(),
      approvals: {
        async prepare(current): Promise<ProviderPreparedApprovalHandle> {
          const handle = await installed.owner.prepare(current);
          return Object.freeze({
            id: handle.id,
            get account(): Uint8Array {
              return handle.account;
            },
            chain: handle.chain,
            get messageDigest(): Uint8Array {
              return handle.messageDigest;
            },
            signal: handle.signal,
            terminal: handle.terminal,
            approve: handle.approve,
            open: undefined,
            settle: handle.settle,
            cancel: handle.cancel,
          }) as unknown as ProviderPreparedApprovalHandle;
        },
      },
      operations: new ProviderOperationOwner(operations, {
        readNow: () => 1_100,
      }),
    });

    await expect(owner.launch(lease)).rejects.toThrow(
      "prepared approval open must be a function",
    );
    expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("cancelled");
    expect(installed.launcher.calls).toEqual([]);
    expect([...operations.records.values()][0]).toMatchObject({
      state: "failed",
      failureCode: "preparation-failed",
    });
    session.disconnect();
  });

  it.each(["Port disconnect", "authority revocation"] as const)(
    "keeps the window hidden across %s in the bind gap",
    async (race) => {
      const { session, lease } = providerLease();
      const installed = install();
      const operations = new MemoryProviderOperations();
      const bindStarted = deferred<void>();
      const releaseBind = deferred<void>();
      operations.bindStarted = bindStarted.resolve;
      operations.bindGate = releaseBind.promise;
      installed.launcher.launchImpl = async () => {
        operations.events.push("window.open");
      };

      const launching = composite(installed, operations).launch(lease);
      await bindStarted.promise;
      if (race === "Port disconnect") session.disconnect();
      else installed.resolver.authority.abort();
      releaseBind.resolve();

      await expect(launching).rejects.toThrow(
        race === "Port disconnect"
          ? "request is no longer owned"
          : "approval action lifetime already ended",
      );
      await flush();
      expect(installed.launcher.calls).toEqual([]);
      expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
      expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("cancelled");
      expect([...operations.records.values()][0]).toMatchObject({
        state: "bound",
        approvalId: APPROVAL_ID,
      });
      session.disconnect();
    },
  );

  it("never prepares or opens again after a bound operation's first window fails", async () => {
    const { session, lease } = providerLease();
    const installed = install();
    const operations = new MemoryProviderOperations();
    const openFailure = new Error("window creation failed");
    installed.launcher.launchImpl = async () => Promise.reject(openFailure);
    const owner = composite(installed, operations);

    await expect(owner.launch(lease)).rejects.toBe(openFailure);
    expect(installed.coordinator.prepareCalls).toHaveLength(1);
    expect(installed.coordinator.cancelCalls).toEqual([APPROVAL_ID]);
    expect([...operations.records.values()][0]).toMatchObject({
      state: "bound",
      approvalId: APPROVAL_ID,
    });

    await expect(owner.launch(lease)).resolves.toEqual({
      kind: "replay-required",
    });
    expect(installed.coordinator.prepareCalls).toHaveLength(1);
    expect(installed.launcher.calls).toHaveLength(1);
    session.disconnect();
  });

  it("composes C17 approval proof through C14 into one C16 page Promise without routing signed bytes through the action", async () => {
    const page = new FlowPage();
    const pageOwner = new ProviderPageRequestOwner(page, {
      randomSource: new FixedRandom(),
      timerSource: new InertTimers(),
      readNow: () => 1_000,
    });
    page.grant();
    const pageResult = pageOwner.signTransaction({
      accountAddress: ACCOUNT_ADDRESS,
      transaction: Uint8Array.of(1, 2, 3),
      chain: "solana:devnet",
    });
    const requestEnvelope = readPageProviderRequestEnvelope(page.posted[0]?.message);
    expect(requestEnvelope).not.toBeNull();
    const transportEnvelope = readProviderTransportRequestEnvelope(
      requestEnvelope!.payload,
    );
    expect(transportEnvelope).not.toBeNull();
    const request = transportEnvelope!.payload as Record<string, unknown>;
    const { session, owned } = providerLease(request);
    const installed = install();
    const operations = new MemoryProviderOperations();
    const actions = new ProviderApprovalActionOwner();
    const visible = deferred<void>();
    const resultReadStarted = deferred<void>();
    const releaseResultRead = deferred<void>();
    installed.launcher.launchImpl = async () => visible.resolve();
    const approvalFlow = composite(installed, operations, actions);
    const resultOwner = new ProviderTerminalResultOwner({
      operations,
      approvals: installed.approvals,
      readNow: () => 1_200,
      readSigned: async (_approvals, id, digest) => {
        resultReadStarted.resolve();
        await releaseResultRead.promise;
        return Object.freeze({
          id,
          messageDigest: digest.slice(),
          transactionBytes: Uint8Array.of(1, 2, 3, 4),
          signature: new Uint8Array(64).fill(0x55),
        });
      },
    });
    const resultFlow = new ProviderSignedResultFlowOwner({
      approvals: approvalFlow,
      results: resultOwner,
    });
    const deliveryLease: ProviderTerminalDeliveryLease = Object.freeze({
      owned,
      assertActive: () => session.assertActive(owned),
      postMessage(message: ProviderSignedTransactionResponse): void {
        page.capability.deliver(Object.freeze({
          version: 1,
          type: PAGE_PROVIDER_RESPONSE_TYPE,
          payload: createProviderTransportTerminalEnvelope(
            message.correlationId,
            DELIVERY_RECEIPT_ID,
            owned.expiresAt,
            message,
          ),
        }));
      },
      finish: () => session.finish(owned),
    });

    const delivering = resultFlow.deliver(deliveryLease);
    await visible.promise;
    const record = installed.approvals.records.get(APPROVAL_ID)!;
    expect(actions.canApprove(APPROVAL_ID, record.messageDigest)).toBe(true);
    await expect(actions.approve(APPROVAL_ID)).resolves.toBe(true);
    await resultReadStarted.promise;
    await expect(actions.settle(APPROVAL_ID)).resolves.toBe(true);
    expect(installed.owner.activeCount).toBe(0);
    expect(pageOwner.pendingCount).toBe(1);
    releaseResultRead.resolve();
    await expect(delivering).resolves.toEqual({
      kind: "delivered",
      replayed: false,
    });
    await expect(pageResult).resolves.toEqual(Uint8Array.of(1, 2, 3, 4));
    expect(installed.coordinator.approveCalls).toHaveLength(1);
    expect(session.pendingCount).toBe(0);

    pageOwner.dispose();
    session.disconnect();
  });

  it("delivers a committed result after keyring revocation while the byte-free approval action still reports lifetime loss", async () => {
    const page = new FlowPage();
    const pageOwner = new ProviderPageRequestOwner(page, {
      randomSource: new FixedRandom(),
      timerSource: new InertTimers(),
      readNow: () => 1_000,
    });
    page.grant();
    const pageResult = pageOwner.signTransaction({
      accountAddress: ACCOUNT_ADDRESS,
      transaction: Uint8Array.of(1, 2, 3),
      chain: "solana:devnet",
    });
    const requestEnvelope = readPageProviderRequestEnvelope(page.posted[0]?.message);
    const transportEnvelope = readProviderTransportRequestEnvelope(
      requestEnvelope!.payload,
    );
    expect(transportEnvelope).not.toBeNull();
    const { session, owned } = providerLease(
      transportEnvelope!.payload as Record<string, unknown>,
    );
    const installed = install();
    const operations = new MemoryProviderOperations();
    const actions = new ProviderApprovalActionOwner();
    const visible = deferred<void>();
    const signingReturned = deferred<void>();
    const durableClaimed = deferred<void>();
    installed.launcher.launchImpl = async () => visible.resolve();
    installed.coordinator.approveImpl = async (id, digest) => {
      const current = installed.approvals.records.get(id)!;
      installed.approvals.records.set(
        id,
        resolveApprovalRecord(current, "approved", 1_100),
      );
      durableClaimed.resolve();
      await signingReturned.promise;
      return Object.freeze({
        id,
        messageDigest: digest,
        transactionBytes: Uint8Array.of(7, 7, 7),
        signature: new Uint8Array(64).fill(0x77),
      });
    };
    const resultFlow = new ProviderSignedResultFlowOwner({
      approvals: composite(installed, operations, actions),
      results: new ProviderTerminalResultOwner({
        operations,
        approvals: installed.approvals,
        readNow: () => 1_200,
        readSigned: async (_approvals, id, digest) => Object.freeze({
          id,
          messageDigest: digest.slice(),
          transactionBytes: Uint8Array.of(7, 7, 7),
          signature: new Uint8Array(64).fill(0x77),
        }),
      }),
    });
    const deliveryLease: ProviderTerminalDeliveryLease = Object.freeze({
      owned,
      assertActive: () => session.assertActive(owned),
      postMessage(message: ProviderSignedTransactionResponse): void {
        page.capability.deliver(Object.freeze({
          version: 1,
          type: PAGE_PROVIDER_RESPONSE_TYPE,
          payload: createProviderTransportTerminalEnvelope(
            message.correlationId,
            DELIVERY_RECEIPT_ID,
            owned.expiresAt,
            message,
          ),
        }));
      },
      finish: () => session.finish(owned),
    });

    const delivering = resultFlow.deliver(deliveryLease);
    await visible.promise;
    const approving = actions.approve(APPROVAL_ID);
    await durableClaimed.promise;
    expect(pageOwner.pendingCount).toBe(1);
    installed.resolver.authority.abort();
    await flush();
    expect(pageOwner.pendingCount).toBe(1);
    signingReturned.resolve();

    await expect(approving).rejects.toThrow("selected keyring authority is revoked");
    await expect(delivering).resolves.toEqual({
      kind: "delivered",
      replayed: false,
    });
    await expect(pageResult).resolves.toEqual(Uint8Array.of(7, 7, 7));
    expect(installed.approvals.records.get(APPROVAL_ID)?.state).toBe("approved");
    expect(installed.fatals).toEqual([]);
    expect(session.pendingCount).toBe(0);

    pageOwner.dispose();
    session.disconnect();
  });

  it("replays the exact committed result after provider loss through replacement worker owners without another prepare or sign", async () => {
    const page = new FlowPage();
    const pageOwner = new ProviderPageRequestOwner(page, {
      randomSource: new FixedRandom(),
      timerSource: new InertTimers(),
      readNow: () => 1_000,
    });
    page.grant();
    const pageResult = pageOwner.signTransaction({
      accountAddress: ACCOUNT_ADDRESS,
      transaction: Uint8Array.of(1, 2, 3),
      chain: "solana:devnet",
    });
    const requestEnvelope = readPageProviderRequestEnvelope(page.posted[0]?.message);
    const transportEnvelope = readProviderTransportRequestEnvelope(
      requestEnvelope!.payload,
    );
    expect(transportEnvelope).not.toBeNull();
    const request = transportEnvelope!.payload as Record<string, unknown>;
    const first = providerLease(request);
    const installed = install();
    const operations = new MemoryProviderOperations();
    const actions = new ProviderApprovalActionOwner();
    const visible = deferred<void>();
    const signingReturned = deferred<void>();
    const durableClaimed = deferred<void>();
    installed.launcher.launchImpl = async () => visible.resolve();
    installed.coordinator.approveImpl = async (id, digest) => {
      const current = installed.approvals.records.get(id)!;
      installed.approvals.records.set(
        id,
        resolveApprovalRecord(current, "approved", 1_100),
      );
      durableClaimed.resolve();
      await signingReturned.promise;
      return Object.freeze({
        id,
        messageDigest: digest,
        transactionBytes: Uint8Array.of(6, 6, 6),
        signature: new Uint8Array(64).fill(0x66),
      });
    };
    const firstResultFlow = new ProviderSignedResultFlowOwner({
      approvals: composite(installed, operations, actions),
      results: new ProviderTerminalResultOwner({
        operations,
        approvals: installed.approvals,
        readNow: () => 1_200,
        readSigned: async (_approvals, id, digest) => Object.freeze({
          id,
          messageDigest: digest.slice(),
          transactionBytes: Uint8Array.of(6, 6, 6),
          signature: new Uint8Array(64).fill(0x66),
        }),
      }),
    });
    const firstLease: ProviderTerminalDeliveryLease = Object.freeze({
      owned: first.owned,
      assertActive: () => first.session.assertActive(first.owned),
      postMessage(): void {
        throw new Error("dead provider Port must not receive a result");
      },
      finish: () => first.session.finish(first.owned),
    });

    const firstDelivery = firstResultFlow.deliver(firstLease);
    await visible.promise;
    const approving = actions.approve(APPROVAL_ID);
    await durableClaimed.promise;
    first.session.disconnect();
    signingReturned.resolve();
    await expect(approving).rejects.toThrow("request is no longer owned");
    await expect(firstDelivery).rejects.toThrow("request is no longer owned");

    // Model a replacement MV3 worker: no previous C12/action/coordinator
    // capability is retained. The bound C14 journal and durable signed result
    // are sufficient, so these trap dependencies must remain untouched.
    let unexpectedPreparations = 0;
    let unexpectedRegistrations = 0;
    const replacementApprovalFlow = new ProviderApprovalOperationOwner({
      actions: {
        register(): void {
          unexpectedRegistrations++;
          throw new Error("replacement worker must not register an action");
        },
      },
      approvals: {
        async prepare(): Promise<ProviderPreparedApprovalHandle> {
          unexpectedPreparations++;
          throw new Error("replacement worker must not prepare an approval");
        },
      },
      operations: new ProviderOperationOwner(operations, {
        readNow: () => 1_300,
      }),
    });
    const replacementFlow = new ProviderSignedResultFlowOwner({
      approvals: replacementApprovalFlow,
      results: new ProviderTerminalResultOwner({
        operations,
        approvals: installed.approvals,
        readNow: () => 1_300,
        readSigned: async (_approvals, id, digest) => Object.freeze({
          id,
          messageDigest: digest.slice(),
          transactionBytes: Uint8Array.of(6, 6, 6),
          signature: new Uint8Array(64).fill(0x66),
        }),
      }),
    });
    const retry = providerLease(request);
    const retryLease: ProviderTerminalDeliveryLease = Object.freeze({
      owned: retry.owned,
      assertActive: () => retry.session.assertActive(retry.owned),
      postMessage(message: ProviderSignedTransactionResponse): void {
        page.capability.deliver(Object.freeze({
          version: 1,
          type: PAGE_PROVIDER_RESPONSE_TYPE,
          payload: createProviderTransportTerminalEnvelope(
            message.correlationId,
            DELIVERY_RECEIPT_ID,
            retry.owned.expiresAt,
            message,
          ),
        }));
      },
      finish: () => retry.session.finish(retry.owned),
    });

    await expect(replacementFlow.deliver(retryLease)).resolves.toEqual({
      kind: "delivered",
      replayed: true,
    });
    await expect(pageResult).resolves.toEqual(Uint8Array.of(6, 6, 6));
    expect(installed.coordinator.prepareCalls).toHaveLength(1);
    expect(installed.coordinator.approveCalls).toHaveLength(1);
    expect(unexpectedPreparations).toBe(0);
    expect(unexpectedRegistrations).toBe(0);
    expect(retry.session.pendingCount).toBe(0);

    pageOwner.dispose();
    retry.session.disconnect();
  });
});
