//! Still-unreachable C12 provider-to-approval preparation owner.
//!
//! This module deliberately has no runtime Port listener and no production
//! release/RPC factory. It converts one already-parsed, browser-owned provider
//! lease into the existing coordinator's exact request only after a trusted
//! selection resolver proves the requested account and chain. Production keeps
//! using the fixed-unavailable provider boundary while the committed release
//! registry is empty and no result/replay protocol exists.

import {
  APPROVAL_DIGEST_BYTES,
  approvalDigestsEqual,
  snapshotApprovalRecord,
  type ApprovalChain,
  type ApprovalRecord,
} from "@warden/core/approval";
import type {
  PreparedSessionApproval,
  SessionApprovalRequest,
} from "@warden/core/transaction/session-approval";
import { PublicKey } from "@solana/web3.js";

import type { ApprovalWindowLauncher } from "./approval-window.js";
import type { OwnedProviderRequest } from "./provider-port.js";
import type { ProviderChain } from "./provider-message.js";

export const MAX_ACTIVE_PROVIDER_APPROVAL_REQUESTS = 32;

const APPROVAL_ID_PATTERN = /^req_[0-9a-f]{32}$/;
const CHAINS: ReadonlySet<string> = new Set([
  "solana:mainnet",
  "solana:devnet",
  "solana:testnet",
  "solana:localnet",
]);

export class ProviderApprovalRequestStateError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`provider approval request: ${message}`, options);
    this.name = "ProviderApprovalRequestStateError";
  }
}

export interface ProviderRequestLease {
  readonly owned: OwnedProviderRequest;
  /** Absolute expiry and exact Port ownership remain authoritative here. */
  assertActive(): void;
}

export interface ProviderApprovalCoordinator {
  prepare(request: SessionApprovalRequest): Promise<PreparedSessionApproval>;
  cancel(id: string): Promise<ApprovalRecord>;
}

export interface ProviderApprovalSelectionInput {
  readonly method: "solana:signTransaction";
  readonly requestedAccountAddress: string;
  readonly requestedChain: ProviderChain | null;
  /** Cancellation hint. The caller still rechecks the authoritative lease. */
  readonly signal: AbortSignal;
}

export interface ProviderApprovalSelection {
  /** Canonical current SmartAccount selected by trusted extension state. */
  readonly account: Uint8Array;
  /** Revokes this exact authenticated keyring unlock generation. */
  readonly authoritySignal: AbortSignal;
  /** Canonical current chain, backed by a committed release and trusted RPC. */
  readonly chain: ApprovalChain;
  readonly coordinator: ProviderApprovalCoordinator;
}

export interface ProviderApprovalSelectionResolver {
  resolve(input: ProviderApprovalSelectionInput): Promise<ProviderApprovalSelection>;
}

export interface ProviderApprovalRecordReader {
  read(id: string): Promise<ApprovalRecord | null>;
}

export interface ProviderApprovalHandle {
  readonly id: string;
  readonly account: Uint8Array;
  readonly chain: ApprovalChain;
  readonly messageDigest: Uint8Array;
  /** Prove the exact durable row terminal before releasing Port ownership. */
  settle(): Promise<boolean>;
  /** Cancel and prove only this exact durable row non-actionable. */
  cancel(): Promise<boolean>;
}

export interface ProviderPreparedApprovalHandle extends ProviderApprovalHandle {
  /** Open at most once; C15 calls this only after its outer durable bind. */
  open(): Promise<void>;
}

export interface ProviderApprovalRequestOwnerOptions {
  readonly selection: ProviderApprovalSelectionResolver;
  readonly approvals: ProviderApprovalRecordReader;
  readonly windows: ApprovalWindowLauncher;
  /** Parent runtime must close every privileged surface on uncertain cleanup. */
  readonly onFatal: (error: unknown) => void;
}

interface BoundDependencies {
  readonly resolveSelection: ProviderApprovalSelectionResolver["resolve"];
  readonly readApproval: ProviderApprovalRecordReader["read"];
  readonly launchWindow: ApprovalWindowLauncher["launch"];
  readonly onFatal: (error: unknown) => void;
}

interface ApprovalBinding {
  readonly id: string;
  readonly messageDigest: Uint8Array;
  readonly account: Uint8Array;
  readonly chain: ApprovalChain;
  readonly createdAt: number;
  readonly expiresAt: number;
}

interface PreparedSnapshot extends ApprovalBinding {
  readonly blockhash: Uint8Array;
  readonly lastValidBlockHeight: number;
}

interface PreparedCleanupHint {
  readonly id: string;
  readonly messageDigest: Uint8Array;
}

interface RequestBinding {
  readonly origin: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly account: Uint8Array;
  readonly chain: ApprovalChain;
}

interface ActiveEntry {
  readonly owned: OwnedProviderRequest;
  readonly assertRequestActive: () => void;
  readonly authoritySignal: AbortSignal;
  readonly coordinator: ProviderApprovalCoordinator;
  readonly binding: ApprovalBinding;
  readonly lifetimeController: AbortController;
  readonly signals: readonly AbortSignal[];
  readonly onAbort: () => void;
  cancelPromise: Promise<boolean> | undefined;
  openPromise: Promise<void> | undefined;
  active: boolean;
}

function stateError(message: string, cause?: unknown): never {
  throw new ProviderApprovalRequestStateError(
    message,
    cause === undefined ? {} : { cause },
  );
}

function requireObject(value: unknown, name: string): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    value instanceof Uint8Array
  ) {
    stateError(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireMethod<T extends object, K extends keyof T>(
  owner: T,
  key: K,
  name: string,
): T[K] {
  let method: unknown;
  try {
    method = owner[key];
  } catch (error) {
    stateError(`${name} access failed`, error);
  }
  if (typeof method !== "function") stateError(`${name} must be a function`);
  return method.bind(owner) as T[K];
}

function bindDependencies(value: unknown): BoundDependencies {
  const options = requireObject(value, "options");
  const selection = requireObject(
    options.selection,
    "selection resolver",
  ) as unknown as ProviderApprovalSelectionResolver;
  const approvals = requireObject(
    options.approvals,
    "approval reader",
  ) as unknown as ProviderApprovalRecordReader;
  const windows = requireObject(
    options.windows,
    "approval window launcher",
  ) as unknown as ApprovalWindowLauncher;
  const onFatal = options.onFatal;
  if (typeof onFatal !== "function") stateError("onFatal must be a function");
  return Object.freeze({
    resolveSelection: requireMethod(selection, "resolve", "selection.resolve"),
    readApproval: requireMethod(approvals, "read", "approvals.read"),
    launchWindow: requireMethod(windows, "launch", "windows.launch"),
    onFatal: onFatal as (error: unknown) => void,
  });
}

function requireSignal(
  value: unknown,
  name = "provider request signal",
): AbortSignal {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly aborted?: unknown }).aborted !== "boolean" ||
    typeof (value as { readonly addEventListener?: unknown }).addEventListener !== "function" ||
    typeof (value as { readonly removeEventListener?: unknown }).removeEventListener !== "function"
  ) {
    stateError(`${name} is malformed`);
  }
  return value as AbortSignal;
}

function assertAuthorityActive(signal: AbortSignal): void {
  let aborted: boolean;
  try {
    aborted = signal.aborted;
  } catch (error) {
    stateError("selected keyring authority signal access failed", error);
  }
  if (aborted) stateError("selected keyring authority is revoked");
}

function bindLease(value: unknown): {
  readonly owned: OwnedProviderRequest;
  readonly assertActive: () => void;
} {
  const lease = requireObject(
    value,
    "provider request lease",
  ) as unknown as ProviderRequestLease;
  let owned: unknown;
  try {
    owned = lease.owned;
  } catch (error) {
    stateError("provider request lease owned access failed", error);
  }
  if (typeof owned !== "object" || owned === null) {
    stateError("provider request lease has no owned request");
  }
  const request = (owned as Partial<OwnedProviderRequest>).request;
  const provenance = (owned as Partial<OwnedProviderRequest>).provenance;
  if (
    typeof request !== "object" ||
    request === null ||
    typeof provenance !== "object" ||
    provenance === null
  ) {
    stateError("owned provider request is malformed");
  }
  requireSignal((owned as Partial<OwnedProviderRequest>).signal);
  return Object.freeze({
    owned: owned as OwnedProviderRequest,
    assertActive: requireMethod(lease, "assertActive", "lease.assertActive"),
  });
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function requireBytes(value: unknown, length: number, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    stateError(`${name} must contain exactly ${length} bytes`);
  }
  return value.slice();
}

function requireSafeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    stateError(`${name} must be a non-negative safe integer`);
  }
  return value as number;
}

function requireChain(value: unknown, name: string): ApprovalChain {
  if (typeof value !== "string" || !CHAINS.has(value)) {
    stateError(`${name} is unsupported`);
  }
  return value as ApprovalChain;
}

function bindCoordinator(value: unknown): ProviderApprovalCoordinator {
  const coordinator = requireObject(
    value,
    "approval coordinator",
  ) as unknown as ProviderApprovalCoordinator;
  return Object.freeze({
    prepare: requireMethod(coordinator, "prepare", "coordinator.prepare"),
    cancel: requireMethod(coordinator, "cancel", "coordinator.cancel"),
  });
}

function snapshotSelection(
  value: unknown,
  requestedAccountAddress: string,
  requestedChain: ProviderChain | null,
): {
  readonly account: Uint8Array;
  readonly authoritySignal: AbortSignal;
  readonly chain: ApprovalChain;
  readonly coordinator: ProviderApprovalCoordinator;
} {
  const selection = requireObject(
    value,
    "resolved selection",
  ) as unknown as ProviderApprovalSelection;
  const account = requireBytes(selection.account, 32, "selected account");
  let encodedAccount: string;
  try {
    encodedAccount = new PublicKey(account).toBase58();
  } catch (error) {
    account.fill(0);
    stateError("selected account is not a Solana public key", error);
  }
  if (encodedAccount !== requestedAccountAddress) {
    account.fill(0);
    stateError("selected account does not equal the requested account");
  }
  const chain = requireChain(selection.chain, "selected chain");
  if (requestedChain !== null && chain !== requestedChain) {
    account.fill(0);
    stateError("selected chain does not equal the requested chain");
  }
  const coordinator = bindCoordinator(selection.coordinator);
  const authoritySignal = requireSignal(
    selection.authoritySignal,
    "selected keyring authority signal",
  );
  assertAuthorityActive(authoritySignal);
  return Object.freeze({ account, authoritySignal, chain, coordinator });
}

function snapshotPrepared(value: unknown): PreparedSnapshot {
  const prepared = requireObject(
    value,
    "prepared approval",
  ) as unknown as PreparedSessionApproval;
  if (typeof prepared.id !== "string" || !APPROVAL_ID_PATTERN.test(prepared.id)) {
    stateError("prepared approval id is malformed");
  }
  const createdAt = requireSafeInteger(prepared.createdAt, "prepared createdAt");
  const expiresAt = requireSafeInteger(prepared.expiresAt, "prepared expiresAt");
  if (expiresAt <= createdAt) stateError("prepared approval lifetime is malformed");
  return Object.freeze({
    id: prepared.id,
    messageDigest: requireBytes(
      prepared.messageDigest,
      APPROVAL_DIGEST_BYTES,
      "prepared message digest",
    ),
    account: requireBytes(prepared.account, 32, "prepared account"),
    chain: requireChain(prepared.chain, "prepared chain"),
    blockhash: requireBytes(prepared.blockhash, 32, "prepared blockhash"),
    lastValidBlockHeight: requireSafeInteger(
      prepared.lastValidBlockHeight,
      "prepared lastValidBlockHeight",
    ),
    createdAt,
    expiresAt,
  });
}

function snapshotPreparedCleanupHint(value: unknown): PreparedCleanupHint {
  const prepared = requireObject(
    value,
    "prepared approval",
  ) as unknown as Partial<PreparedSessionApproval>;
  if (typeof prepared.id !== "string" || !APPROVAL_ID_PATTERN.test(prepared.id)) {
    stateError("prepared approval id is malformed");
  }
  return Object.freeze({
    id: prepared.id,
    messageDigest: requireBytes(
      prepared.messageDigest,
      APPROVAL_DIGEST_BYTES,
      "prepared message digest",
    ),
  });
}

function clearPrepared(value: PreparedSnapshot | undefined): void {
  value?.messageDigest.fill(0);
  value?.account.fill(0);
  value?.blockhash.fill(0);
}

function clearPreparedCleanupHint(value: PreparedCleanupHint | undefined): void {
  value?.messageDigest.fill(0);
}

function clearBinding(value: ApprovalBinding | undefined): void {
  value?.messageDigest.fill(0);
  value?.account.fill(0);
}

function clearApproval(value: ApprovalRecord | null | undefined): void {
  value?.account.fill(0);
  value?.genesisHash.fill(0);
  value?.programId.fill(0);
  value?.rawMessage.fill(0);
  value?.messageDigest.fill(0);
}

function bindingFromRecord(record: ApprovalRecord): ApprovalBinding {
  return Object.freeze({
    id: record.id,
    messageDigest: record.messageDigest.slice(),
    account: record.account.slice(),
    chain: record.chain,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
  });
}

function cloneBinding(binding: ApprovalBinding): ApprovalBinding {
  return Object.freeze({
    id: binding.id,
    messageDigest: binding.messageDigest.slice(),
    account: binding.account.slice(),
    chain: binding.chain,
    createdAt: binding.createdAt,
    expiresAt: binding.expiresAt,
  });
}

function requestBindingEqual(record: ApprovalRecord, request: RequestBinding): boolean {
  return (
    record.origin === request.origin &&
    record.tabId === request.tabId &&
    record.frameId === request.frameId &&
    record.documentId === request.documentId &&
    record.method === "solana:signTransaction" &&
    record.chain === request.chain &&
    bytesEqual(record.account, request.account)
  );
}

function recordBindingEqual(record: ApprovalRecord, binding: ApprovalBinding): boolean {
  return (
    record.id === binding.id &&
    record.chain === binding.chain &&
    record.createdAt === binding.createdAt &&
    record.expiresAt === binding.expiresAt &&
    bytesEqual(record.account, binding.account) &&
    approvalDigestsEqual(record.messageDigest, binding.messageDigest)
  );
}

function preparedBindingEqual(
  prepared: PreparedSnapshot,
  binding: ApprovalBinding,
): boolean {
  return (
    prepared.id === binding.id &&
    prepared.chain === binding.chain &&
    prepared.createdAt === binding.createdAt &&
    prepared.expiresAt === binding.expiresAt &&
    bytesEqual(prepared.account, binding.account) &&
    approvalDigestsEqual(prepared.messageDigest, binding.messageDigest)
  );
}

function terminalBinding(
  value: unknown,
  binding: ApprovalBinding,
): ApprovalRecord {
  let record: ApprovalRecord;
  try {
    record = snapshotApprovalRecord(value);
  } catch (error) {
    stateError("terminal record is malformed", error);
  }
  if (record.state === "pending") {
    clearApproval(record);
    stateError("terminal record is required");
  }
  if (!recordBindingEqual(record, binding)) {
    clearApproval(record);
    stateError("terminal record binding differs from the prepared approval");
  }
  return record;
}

/**
 * Owns only provider-to-preparation ordering. It cannot approve, sign, send,
 * construct a trusted Connection, choose a release, or serialize a provider
 * success response. Those capabilities remain absent from the emitted worker.
 */
export class ProviderApprovalRequestOwner {
  readonly #dependencies: BoundDependencies;
  readonly #preparing = new Set<OwnedProviderRequest>();
  readonly #active = new Set<ActiveEntry>();
  #disposed = false;
  #fatalReported = false;

  constructor(options: ProviderApprovalRequestOwnerOptions) {
    this.#dependencies = bindDependencies(options);
  }

  get activeCount(): number {
    return this.#preparing.size + this.#active.size;
  }

  #assertUsable(): void {
    if (this.#disposed) stateError("owner is disposed");
  }

  #reportFatal(error: unknown): void {
    if (this.#fatalReported) return;
    this.#fatalReported = true;
    this.#disposed = true;
    for (const entry of [...this.#active]) {
      void this.#cancelEntry(entry).catch(() => undefined);
    }
    try {
      this.#dependencies.onFatal(error);
    } catch {
      // The state error still rejects the operation even if the parent reporter
      // itself is already closed.
    }
  }

  #removeEntry(entry: ActiveEntry): void {
    if (!entry.active) return;
    entry.active = false;
    this.#active.delete(entry);
    for (const signal of entry.signals) {
      try {
        signal.removeEventListener("abort", entry.onAbort);
      } catch {
        // The signal state is already reflected in the durable transition.
      }
    }
    entry.lifetimeController.abort();
  }

  async #readTerminal(binding: ApprovalBinding): Promise<boolean> {
    let observed: ApprovalRecord | null;
    try {
      observed = await this.#dependencies.readApproval(binding.id);
    } catch (error) {
      stateError("durable approval read failed during cancellation proof", error);
    }
    if (observed === null) return true;
    let terminal: ApprovalRecord | undefined;
    try {
      terminal = terminalBinding(observed, binding);
      return true;
    } finally {
      clearApproval(terminal);
      clearApproval(observed);
    }
  }

  #cancelEntry(entry: ActiveEntry): Promise<boolean> {
    if (!entry.active) return Promise.resolve(false);
    if (entry.cancelPromise !== undefined) return entry.cancelPromise;
    entry.cancelPromise = (async () => {
      const binding = cloneBinding(entry.binding);
      let cancellationError: unknown;
      let cancelled: ApprovalRecord | undefined;
      try {
        try {
          const value = await entry.coordinator.cancel(binding.id);
          cancelled = terminalBinding(value, binding);
          return true;
        } catch (error) {
          cancellationError = error;
          try {
            if (await this.#readTerminal(binding)) return true;
          } catch (proofError) {
            cancellationError = new AggregateError(
              [error, proofError],
              "cancellation and terminal proof both failed",
            );
          }
          const failure = new ProviderApprovalRequestStateError(
            "durable approval cancellation is unproven",
            { cause: cancellationError },
          );
          this.#reportFatal(failure);
          throw failure;
        }
      } finally {
        clearApproval(cancelled);
        clearBinding(binding);
        this.#removeEntry(entry);
        clearBinding(entry.binding);
      }
    })();
    return entry.cancelPromise;
  }

  #createEntry(
    owned: OwnedProviderRequest,
    assertRequestActive: () => void,
    authoritySignal: AbortSignal,
    coordinator: ProviderApprovalCoordinator,
    binding: ApprovalBinding,
  ): ActiveEntry {
    const lifetimeController = new AbortController();
    const signals = Object.freeze(
      authoritySignal === owned.signal
        ? [owned.signal]
        : [owned.signal, authoritySignal],
    );
    let entry!: ActiveEntry;
    const onAbort = (): void => {
      lifetimeController.abort();
      void this.#cancelEntry(entry).catch(() => undefined);
    };
    entry = {
      owned,
      assertRequestActive,
      authoritySignal,
      coordinator,
      binding,
      lifetimeController,
      signals,
      onAbort,
      cancelPromise: undefined,
      openPromise: undefined,
      active: true,
    };
    this.#active.add(entry);
    const installed: AbortSignal[] = [];
    try {
      for (const signal of signals) {
        signal.addEventListener("abort", onAbort, { once: true });
        installed.push(signal);
      }
      if (signals.some((signal) => signal.aborted)) onAbort();
    } catch (error) {
      for (const signal of installed) {
        try {
          signal.removeEventListener("abort", onAbort);
        } catch {
          // Registration is already failing closed below.
        }
      }
      this.#active.delete(entry);
      entry.active = false;
      lifetimeController.abort();
      clearBinding(binding);
      stateError("approval lifetime signal binding failed", error);
    }
    return entry;
  }

  /**
   * Re-establish the only cancellation-safe binding from durable state. The
   * coordinator return is merely a locator and digest hint until the record is
   * independently proven to belong to this browser request.
   */
  async #recoverResolvedPreparation(
    owned: OwnedProviderRequest,
    assertRequestActive: () => void,
    authoritySignal: AbortSignal,
    coordinator: ProviderApprovalCoordinator,
    request: RequestBinding,
    hint: PreparedCleanupHint,
  ): Promise<ActiveEntry | undefined> {
    let observed: ApprovalRecord | null;
    try {
      observed = await this.#dependencies.readApproval(hint.id);
    } catch (error) {
      stateError("durable approval read failed after preparation", error);
    }
    if (observed === null) return undefined;

    let record: ApprovalRecord | undefined;
    let binding: ApprovalBinding | undefined;
    try {
      try {
        record = snapshotApprovalRecord(observed);
      } catch (error) {
        stateError("durable prepared approval is malformed", error);
      }
      if (
        record.id !== hint.id ||
        !approvalDigestsEqual(record.messageDigest, hint.messageDigest) ||
        !requestBindingEqual(record, request)
      ) {
        stateError("durable approval does not equal the browser-owned request");
      }
      binding = bindingFromRecord(record);
      if (record.state !== "pending") {
        clearBinding(binding);
        binding = undefined;
        return undefined;
      }
      const entry = this.#createEntry(
        owned,
        assertRequestActive,
        authoritySignal,
        coordinator,
        binding,
      );
      binding = undefined;
      return entry;
    } finally {
      clearBinding(binding);
      clearApproval(record);
      clearApproval(observed);
    }
  }

  #handle(entry: ActiveEntry): ProviderApprovalHandle {
    const account = entry.binding.account.slice();
    const messageDigest = entry.binding.messageDigest.slice();
    return Object.freeze({
      id: entry.binding.id,
      get account(): Uint8Array {
        return account.slice();
      },
      chain: entry.binding.chain,
      get messageDigest(): Uint8Array {
        return messageDigest.slice();
      },
      settle: async (): Promise<boolean> => {
        if (!entry.active) return false;
        const binding = cloneBinding(entry.binding);
        let observed: ApprovalRecord | null;
        try {
          observed = await this.#dependencies.readApproval(binding.id);
        } catch (error) {
          clearBinding(binding);
          stateError("durable terminal settlement read failed", error);
        }
        if (observed === null) {
          clearBinding(binding);
          this.#removeEntry(entry);
          clearBinding(entry.binding);
          return true;
        }
        let terminal: ApprovalRecord | undefined;
        try {
          terminal = terminalBinding(observed, binding);
        } catch (error) {
          if (
            error instanceof ProviderApprovalRequestStateError &&
            !error.message.endsWith("terminal record is required")
          ) {
            this.#reportFatal(error);
          }
          throw error;
        } finally {
          clearBinding(binding);
          clearApproval(terminal);
          clearApproval(observed);
        }
        this.#removeEntry(entry);
        clearBinding(entry.binding);
        return true;
      },
      cancel: (): Promise<boolean> => this.#cancelEntry(entry),
    });
  }

  #openEntry(entry: ActiveEntry): Promise<void> {
    if (entry.openPromise !== undefined) return entry.openPromise;
    // Schedule the first dependency call so the shared Promise is installed
    // before even a synchronously re-entrant launcher can ask to open again.
    entry.openPromise = Promise.resolve().then(async () => {
      try {
        this.#assertUsable();
        entry.assertRequestActive();
        assertAuthorityActive(entry.authoritySignal);
        if (!entry.active) stateError("approval was cancelled before its window opened");

        await this.#dependencies.launchWindow(
          entry.binding.id,
          entry.lifetimeController.signal,
        );
        assertAuthorityActive(entry.authoritySignal);
        this.#assertUsable();
        entry.assertRequestActive();
        if (!entry.active) stateError("approval was cancelled while its window opened");
      } catch (error) {
        if (entry.active) {
          try {
            await this.#cancelEntry(entry);
          } catch (cleanupError) {
            if (cleanupError instanceof ProviderApprovalRequestStateError) {
              throw cleanupError;
            }
            throw new ProviderApprovalRequestStateError(
              "durable approval cancellation is unproven",
              { cause: new AggregateError([error, cleanupError]) },
            );
          }
        }
        throw error;
      }
    });
    return entry.openPromise;
  }

  #preparedHandle(entry: ActiveEntry): ProviderPreparedApprovalHandle {
    const handle = this.#handle(entry);
    return Object.freeze({
      id: handle.id,
      get account(): Uint8Array {
        return handle.account;
      },
      chain: handle.chain,
      get messageDigest(): Uint8Array {
        return handle.messageDigest;
      },
      open: (): Promise<void> => this.#openEntry(entry),
      settle: handle.settle,
      cancel: handle.cancel,
    });
  }

  async prepare(
    leaseValue: ProviderRequestLease,
  ): Promise<ProviderPreparedApprovalHandle> {
    this.#assertUsable();
    const lease = bindLease(leaseValue);
    const { owned } = lease;
    lease.assertActive();
    if (owned.request.method !== "solana:signTransaction") {
      stateError("only solana:signTransaction can enter approval preparation");
    }
    if (
      this.#preparing.has(owned) ||
      [...this.#active].some((entry) => entry.owned === owned)
    ) {
      stateError("provider request already has an approval owner");
    }
    if (this.activeCount >= MAX_ACTIVE_PROVIDER_APPROVAL_REQUESTS) {
      stateError("too many active provider approval requests");
    }
    this.#preparing.add(owned);

    let selection: ReturnType<typeof snapshotSelection> | undefined;
    let request: SessionApprovalRequest | undefined;
    let requestBinding: RequestBinding | undefined;
    let prepared: PreparedSnapshot | undefined;
    let cleanupHint: PreparedCleanupHint | undefined;
    let entry: ActiveEntry | undefined;
    let preparationResolved = false;
    let cleanupProven = false;
    try {
      const input: ProviderApprovalSelectionInput = Object.freeze({
        method: "solana:signTransaction",
        requestedAccountAddress: owned.request.params.requestedAccountAddress,
        requestedChain: owned.request.params.chain,
        signal: owned.signal,
      });
      const resolved = await this.#dependencies.resolveSelection(input);
      this.#assertUsable();
      lease.assertActive();
      selection = snapshotSelection(
        resolved,
        input.requestedAccountAddress,
        input.requestedChain,
      );
      assertAuthorityActive(selection.authoritySignal);

      request = Object.freeze({
        origin: owned.provenance.origin,
        tabId: owned.provenance.tabId,
        frameId: owned.provenance.frameId,
        documentId: owned.provenance.documentId,
        requestedAccount: selection.account.slice(),
        method: "solana:signTransaction",
        chain: selection.chain,
        sourceTransactionBytes: Uint8Array.from(owned.request.params.transaction),
      });
      requestBinding = Object.freeze({
        origin: request.origin,
        tabId: request.tabId,
        frameId: request.frameId,
        documentId: request.documentId,
        account: request.requestedAccount,
        chain: request.chain,
      });
      const preparedValue = await selection.coordinator.prepare(request);
      preparationResolved = true;
      cleanupHint = snapshotPreparedCleanupHint(preparedValue);
      prepared = snapshotPrepared(preparedValue);
      entry = await this.#recoverResolvedPreparation(
        owned,
        lease.assertActive,
        selection.authoritySignal,
        selection.coordinator,
        requestBinding,
        cleanupHint,
      );
      if (entry === undefined) {
        cleanupProven = true;
        stateError("prepared approval has no pending durable row");
      }
      assertAuthorityActive(selection.authoritySignal);
      this.#assertUsable();
      lease.assertActive();
      if (!bytesEqual(prepared.account, entry.binding.account)) {
        stateError("prepared account differs from the proven selection");
      }
      if (prepared.chain !== entry.binding.chain) {
        stateError("prepared chain differs from the proven selection");
      }
      if (!preparedBindingEqual(prepared, entry.binding)) {
        stateError("prepared approval differs from the exact durable binding");
      }

      return this.#preparedHandle(entry);
    } catch (error) {
      if (preparationResolved && entry === undefined && !cleanupProven) {
        if (
          cleanupHint === undefined ||
          requestBinding === undefined ||
          selection === undefined
        ) {
          const failure = new ProviderApprovalRequestStateError(
            "durable approval cleanup target is unproven after preparation",
            { cause: error },
          );
          this.#reportFatal(failure);
          throw failure;
        }
        try {
          entry = await this.#recoverResolvedPreparation(
            owned,
            lease.assertActive,
            selection.authoritySignal,
            selection.coordinator,
            requestBinding,
            cleanupHint,
          );
          cleanupProven = entry === undefined;
        } catch (cleanupError) {
          const failure = new ProviderApprovalRequestStateError(
            "durable approval cleanup target is unproven after preparation",
            {
              cause: new AggregateError(
                [error, cleanupError],
                "preparation result and durable recovery both failed",
              ),
            },
          );
          this.#reportFatal(failure);
          throw failure;
        }
      }
      if (entry !== undefined && entry.active) {
        try {
          await this.#cancelEntry(entry);
        } catch (cleanupError) {
          if (cleanupError instanceof ProviderApprovalRequestStateError) {
            throw cleanupError;
          }
          throw new ProviderApprovalRequestStateError(
            "durable approval cancellation is unproven",
            { cause: new AggregateError([error, cleanupError]) },
          );
        }
      }
      throw error;
    } finally {
      this.#preparing.delete(owned);
      clearPrepared(prepared);
      clearPreparedCleanupHint(cleanupHint);
      request?.requestedAccount.fill(0);
      request?.sourceTransactionBytes.fill(0);
      selection?.account.fill(0);
    }
  }

  async launch(leaseValue: ProviderRequestLease): Promise<ProviderApprovalHandle> {
    const prepared = await this.prepare(leaseValue);
    await prepared.open();
    return Object.freeze({
      id: prepared.id,
      get account(): Uint8Array {
        return prepared.account;
      },
      chain: prepared.chain,
      get messageDigest(): Uint8Array {
        return prepared.messageDigest;
      },
      settle: prepared.settle,
      cancel: prepared.cancel,
    });
  }

  /**
   * Stop new work and cancel every prepared row. A preparation already inside
   * the coordinator is checked again when it returns; worker-restart
   * invalidation remains the persistence backstop if the worker dies first.
   */
  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    for (const entry of [...this.#active]) {
      void this.#cancelEntry(entry).catch(() => undefined);
    }
  }
}
