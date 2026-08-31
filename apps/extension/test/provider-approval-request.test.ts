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
  type ProviderApprovalSelectionInput,
  type ProviderApprovalSelectionResolver,
  type ProviderRequestLease,
} from "../src/background/provider-approval-request.js";
import { classifyProviderSender } from "../src/background/sender-provenance.js";

const EXTENSION_ID = "a".repeat(32);
const DOCUMENT_ID = "123e4567-e89b-12d3-a456-426614174000";
const ACCOUNT_ADDRESS = "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";
const ACCOUNT = new Uint8Array(32).fill(0x11);
const APPROVAL_ID = `req_${"ab".repeat(16)}`;

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
      origin: "https://iframe.example",
      tab: { id: 19, url: "https://host.example/parent" },
      url: "https://iframe.example/embedded",
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
  readonly cancelCalls: string[] = [];
  prepareImpl: ((request: SessionApprovalRequest) => Promise<PreparedSessionApproval>) | undefined;
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
    const leases = Array.from(
      { length: MAX_ACTIVE_PROVIDER_APPROVAL_REQUESTS + 1 },
      () => providerLease(),
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
