//! Still-unreachable C14 durable signed-result delivery owner.
//!
//! The approval store remains the sole owner of signed bytes. This owner uses
//! the provider-operation journal only as an exact browser-request -> approval
//! locator, then invokes the core's strict durable replay verifier. A successful
//! `Port.postMessage` is not treated as page acknowledgment, so no delivered bit
//! is persisted and a reconnect can release the same bytes again without
//! signing again.

import {
  APPROVAL_DIGEST_BYTES,
  approvalDigestsEqual,
  snapshotApprovalRecord,
  type ApprovalRecord,
} from "@warden/core/approval";
import { MAX_TX_BYTES } from "@warden/core/constants";
import {
  readSignedSessionApproval,
  type SessionApprovalResultReader,
  type SignedSessionApproval,
} from "@warden/core/transaction/session-approval";
import { PublicKey } from "@solana/web3.js";

import type { OwnedProviderRequest } from "./provider-port.js";
import {
  deriveProviderOperationIdentity,
  providerOperationIdentitiesEqual,
  snapshotProviderOperation,
  type ProviderOperationDigestSource,
  type ProviderOperationRecord,
  type ProviderOperationRepository,
} from "./provider-operation.js";
import {
  createSignedTransactionProviderResponse,
  type ProviderTerminalResponse,
} from "./provider-terminal-protocol.js";

const APPROVAL_ID_PATTERN = /^req_[0-9a-f]{32}$/;

export interface ProviderTerminalDeliveryLease {
  readonly owned: OwnedProviderRequest;
  assertActive(): void;
  /** Synchronous Chrome Port enqueue; it is not a page receipt acknowledgment. */
  postMessage(message: ProviderTerminalResponse): void;
  /** Mark exact enqueue-side flow completion; receipt-aware transports retain ownership. */
  finish(): boolean;
}

export type ProviderSignedResultReader = (
  approvals: ProviderTerminalApprovalReader,
  id: string,
  expectedDigest: Uint8Array,
) => Promise<SignedSessionApproval>;

export interface ProviderTerminalApprovalReader extends SessionApprovalResultReader {
  read(id: string): Promise<ApprovalRecord | null>;
}

export interface ProviderTerminalResultOwnerOptions {
  readonly operations: ProviderOperationRepository;
  readonly approvals: ProviderTerminalApprovalReader;
  readonly readNow?: () => number;
  readonly digestSource?: ProviderOperationDigestSource;
  /** Test seam. Production omits this and uses the core cryptographic verifier. */
  readonly readSigned?: ProviderSignedResultReader;
}

export class ProviderTerminalResultStateError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`provider terminal result: ${message}`, options);
    this.name = "ProviderTerminalResultStateError";
  }
}

interface SignedResultSnapshot {
  readonly id: string;
  readonly messageDigest: Uint8Array;
  readonly transactionBytes: Uint8Array;
  readonly signature: Uint8Array;
}

function stateError(message: string, cause?: unknown): never {
  throw new ProviderTerminalResultStateError(
    message,
    cause === undefined ? {} : { cause },
  );
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function requireClock(value: unknown): () => number {
  if (typeof value !== "function") stateError("readNow must be a function");
  return value as () => number;
}

function requireOperations(value: unknown): Pick<ProviderOperationRepository, "read"> {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as Partial<ProviderOperationRepository>).read !== "function"
  ) {
    stateError("operations must provide read()");
  }
  const operations = value as ProviderOperationRepository;
  return Object.freeze({ read: operations.read.bind(operations) });
}

function requireApprovals(value: unknown): ProviderTerminalApprovalReader {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as Partial<ProviderTerminalApprovalReader>).read !== "function" ||
    typeof (value as Partial<ProviderTerminalApprovalReader>).readSigning !== "function"
  ) {
    stateError("approvals must provide read() and readSigning()");
  }
  const approvals = value as ProviderTerminalApprovalReader;
  return Object.freeze({
    read: approvals.read.bind(approvals),
    readSigning: approvals.readSigning.bind(approvals),
  });
}

function requireReadSigned(value: unknown): ProviderSignedResultReader {
  if (typeof value !== "function") stateError("readSigned must be a function");
  return value as ProviderSignedResultReader;
}

function bindLease(value: unknown): {
  readonly owned: OwnedProviderRequest;
  readonly assertActive: () => void;
  readonly postMessage: (message: ProviderTerminalResponse) => void;
  readonly finish: () => boolean;
} {
  if (typeof value !== "object" || value === null) {
    stateError("delivery lease must be an object");
  }
  const lease = value as Partial<ProviderTerminalDeliveryLease>;
  if (typeof lease.owned !== "object" || lease.owned === null) {
    stateError("delivery lease has no owned provider request");
  }
  for (const method of ["assertActive", "postMessage", "finish"] as const) {
    if (typeof lease[method] !== "function") {
      stateError(`delivery lease must provide ${method}()`);
    }
  }
  return Object.freeze({
    owned: lease.owned as OwnedProviderRequest,
    assertActive: lease.assertActive!.bind(value),
    postMessage: lease.postMessage!.bind(value),
    finish: lease.finish!.bind(value),
  });
}

function snapshotSignedResult(value: unknown): SignedResultSnapshot {
  if (typeof value !== "object" || value === null) {
    stateError("signed result must be an object");
  }
  const result = value as Partial<SignedSessionApproval>;
  let id: unknown;
  let messageDigest: unknown;
  let transactionBytes: unknown;
  let signature: unknown;
  try {
    id = result.id;
    messageDigest = result.messageDigest;
    transactionBytes = result.transactionBytes;
    signature = result.signature;
  } catch (error) {
    stateError("signed result access failed", error);
  }
  if (typeof id !== "string" || !APPROVAL_ID_PATTERN.test(id)) {
    stateError("signed result id is malformed");
  }
  if (
    !(messageDigest instanceof Uint8Array) ||
    messageDigest.length !== APPROVAL_DIGEST_BYTES
  ) {
    stateError("signed result digest is malformed");
  }
  if (
    !(transactionBytes instanceof Uint8Array) ||
    transactionBytes.length === 0 ||
    transactionBytes.length > MAX_TX_BYTES
  ) {
    stateError("signed result transaction is malformed");
  }
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    stateError("signed result signature is malformed");
  }
  return Object.freeze({
    id,
    messageDigest: messageDigest.slice(),
    transactionBytes: transactionBytes.slice(),
    signature: signature.slice(),
  });
}

function clearOperation(value: ProviderOperationRecord | null | undefined): void {
  value?.requestDigest.fill(0);
  value?.approvalDigest?.fill(0);
}

function clearApproval(value: ApprovalRecord | null | undefined): void {
  value?.account.fill(0);
  value?.genesisHash.fill(0);
  value?.programId.fill(0);
  value?.rawMessage.fill(0);
  value?.messageDigest.fill(0);
}

function clearSigned(value: SignedResultSnapshot | undefined): void {
  if (value === undefined) return;
  value.messageDigest.fill(0);
  value.transactionBytes.fill(0);
  value.signature.fill(0);
}

/** Replay and enqueue exactly one already-committed signTransaction result. */
export class ProviderTerminalResultOwner {
  readonly #operations: Pick<ProviderOperationRepository, "read">;
  readonly #approvals: ProviderTerminalApprovalReader;
  readonly #readNow: () => number;
  readonly #digestSource: ProviderOperationDigestSource | undefined;
  readonly #readSigned: ProviderSignedResultReader;

  constructor(optionsValue: ProviderTerminalResultOwnerOptions) {
    if (typeof optionsValue !== "object" || optionsValue === null) {
      stateError("options must be an object");
    }
    this.#operations = requireOperations(optionsValue.operations);
    this.#approvals = requireApprovals(optionsValue.approvals);
    this.#readNow = requireClock(optionsValue.readNow ?? Date.now);
    this.#digestSource = optionsValue.digestSource;
    this.#readSigned = requireReadSigned(
      optionsValue.readSigned ?? readSignedSessionApproval,
    );
  }

  #currentTime(): number {
    let value: unknown;
    try {
      value = this.#readNow();
    } catch (error) {
      stateError("clock read failed", error);
    }
    if (!Number.isSafeInteger(value) || (value as number) < 0) {
      stateError("clock must return a non-negative safe integer");
    }
    return value as number;
  }

  async deliver(leaseValue: ProviderTerminalDeliveryLease): Promise<boolean> {
    const lease = bindLease(leaseValue);
    lease.assertActive();
    const identity = this.#digestSource === undefined
      ? await deriveProviderOperationIdentity(lease.owned)
      : await deriveProviderOperationIdentity(lease.owned, this.#digestSource);
    let operation: ProviderOperationRecord | null | undefined;
    let approval: ApprovalRecord | null | undefined;
    let signed: SignedResultSnapshot | undefined;
    let expectedDigest: Uint8Array | undefined;
    let actualDigest: Uint8Array | undefined;
    let transactionBytes: Uint8Array | undefined;
    try {
      lease.assertActive();
      try {
        const value = await this.#operations.read({
          key: identity.key,
          now: this.#currentTime(),
        });
        operation = value === null ? null : snapshotProviderOperation(value);
      } catch (error) {
        stateError("durable operation read failed", error);
      }
      if (operation === null) stateError("durable operation is absent");
      if (!providerOperationIdentitiesEqual(operation, identity)) {
        stateError("durable operation belongs to a different browser request");
      }
      if (
        operation.state !== "bound" ||
        operation.approvalId === null ||
        operation.approvalDigest === null
      ) {
        stateError(`durable operation is not bound (${operation.state})`);
      }
      expectedDigest = operation.approvalDigest.slice();
      lease.assertActive();
      try {
        const value = await this.#approvals.read(operation.approvalId);
        approval = value === null ? null : snapshotApprovalRecord(value);
      } catch (error) {
        stateError("durable approval binding read failed", error);
      }
      if (approval === null) stateError("durable approval binding is absent");
      let accountAddress: string;
      try {
        accountAddress = new PublicKey(approval.account).toBase58();
      } catch (error) {
        stateError("durable approval account is malformed", error);
      }
      const request = lease.owned.request;
      if (
        request.method !== "solana:signTransaction" ||
        approval.id !== operation.approvalId ||
        approval.state !== "approved" ||
        !approvalDigestsEqual(approval.messageDigest, expectedDigest) ||
        approval.origin !== identity.origin ||
        approval.tabId !== identity.tabId ||
        approval.frameId !== identity.frameId ||
        approval.documentId !== identity.documentId ||
        approval.method !== identity.method ||
        accountAddress !== request.params.requestedAccountAddress ||
        (request.params.chain !== null && approval.chain !== request.params.chain)
      ) {
        stateError("durable approval differs from the exact provider operation");
      }
      lease.assertActive();
      let result: unknown;
      try {
        result = await this.#readSigned(
          this.#approvals,
          operation.approvalId,
          expectedDigest,
        );
      } catch (error) {
        stateError("durable signed result is unavailable", error);
      }
      signed = snapshotSignedResult(result);
      actualDigest = signed.messageDigest;
      if (signed.id !== operation.approvalId) {
        stateError("signed result belongs to a different approval");
      }
      if (!approvalDigestsEqual(actualDigest, expectedDigest)) {
        stateError("signed result has a different digest");
      }
      transactionBytes = signed.transactionBytes;
      const response = createSignedTransactionProviderResponse(
        identity.correlationId,
        transactionBytes,
      );

      // There is intentionally no await between the final live-lease check,
      // Port enqueue, and exact flow completion. C22's adapter retains the
      // in-memory lease until the page's identity-bound receipt returns.
      lease.assertActive();
      lease.postMessage(response);
      if (!lease.finish()) {
        stateError("delivery ownership was lost after posting");
      }
      return true;
    } finally {
      identity.requestDigest.fill(0);
      clearOperation(operation);
      clearApproval(approval);
      clearSigned(signed);
      expectedDigest?.fill(0);
      actualDigest?.fill(0);
      transactionBytes?.fill(0);
    }
  }
}
