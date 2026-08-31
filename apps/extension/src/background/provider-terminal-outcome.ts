//! Still-unreachable C19 durable terminal-outcome delivery owner.
//!
//! A provider operation may end in an exact signed result or in one of a small
//! closed set of page-safe failures. This owner classifies only durable state:
//! the exact operation identity, its exact approval binding, and (for an
//! approved row) the atomic signing outcome. It never converts an exception or
//! a merely-approved row into a page response. Signed bytes remain exclusively
//! owned by C14; this owner delegates the signed branch back to that verifier.

import {
  approvalDigestsEqual,
  snapshotApprovalRecord,
  snapshotApprovalSigningRecord,
  type ApprovalRecord,
  type ApprovalSigningRecord,
} from "@warden/core/approval";
import { PublicKey } from "@solana/web3.js";

import type { OwnedProviderRequest } from "./provider-port.js";
import {
  deriveProviderOperationIdentity,
  providerOperationIdentitiesEqual,
  snapshotProviderOperation,
  type ProviderOperationDigestSource,
  type ProviderOperationFailureCode,
  type ProviderOperationRecord,
} from "./provider-operation.js";
import {
  createProviderTerminalFailureResponse,
  type ProviderTerminalFailureCode,
  type ProviderTerminalResponse,
} from "./provider-terminal-protocol.js";
import type {
  ProviderTerminalApprovalReader,
  ProviderTerminalDeliveryLease,
} from "./provider-terminal-result.js";

export interface ProviderTerminalOperationReader {
  read(input: {
    readonly key: string;
    readonly now: number;
  }): Promise<ProviderOperationRecord | null>;
}

export interface ProviderSignedTerminalDeliverer {
  deliver(lease: ProviderTerminalDeliveryLease): Promise<unknown>;
}

export interface ProviderTerminalOutcomeOwnerOptions {
  readonly operations: ProviderTerminalOperationReader;
  readonly approvals: ProviderTerminalApprovalReader;
  readonly signed: ProviderSignedTerminalDeliverer;
  readonly readNow?: () => number;
  readonly digestSource?: ProviderOperationDigestSource;
}

export class ProviderTerminalOutcomeStateError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`provider terminal outcome: ${message}`, options);
    this.name = "ProviderTerminalOutcomeStateError";
  }
}

interface BoundLease {
  readonly owned: OwnedProviderRequest;
  readonly assertActive: () => void;
  readonly postMessage: (message: ProviderTerminalResponse) => void;
  readonly finish: () => boolean;
}

interface BoundDependencies {
  readonly readOperation: ProviderTerminalOperationReader["read"];
  readonly readApproval: ProviderTerminalApprovalReader["read"];
  readonly readSigning: ProviderTerminalApprovalReader["readSigning"];
  readonly deliverSigned: ProviderSignedTerminalDeliverer["deliver"];
  readonly readNow: () => number;
  readonly digestSource: ProviderOperationDigestSource | undefined;
}

function stateError(message: string, cause?: unknown): never {
  throw new ProviderTerminalOutcomeStateError(
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
  const operations = requireObject(
    options.operations,
    "provider operation reader",
  ) as unknown as ProviderTerminalOperationReader;
  const approvals = requireObject(
    options.approvals,
    "provider approval reader",
  ) as unknown as ProviderTerminalApprovalReader;
  const signed = requireObject(
    options.signed,
    "signed terminal deliverer",
  ) as unknown as ProviderSignedTerminalDeliverer;
  const readNow = options.readNow ?? Date.now;
  if (typeof readNow !== "function") stateError("readNow must be a function");
  const digestSource = options.digestSource;
  if (
    digestSource !== undefined &&
    (
      typeof digestSource !== "object" ||
      digestSource === null ||
      typeof (digestSource as Partial<ProviderOperationDigestSource>).digest !== "function"
    )
  ) {
    stateError("digestSource must provide digest()");
  }
  return Object.freeze({
    readOperation: requireMethod(operations, "read", "operations.read"),
    readApproval: requireMethod(approvals, "read", "approvals.read"),
    readSigning: requireMethod(approvals, "readSigning", "approvals.readSigning"),
    deliverSigned: requireMethod(signed, "deliver", "signed.deliver"),
    readNow: readNow as () => number,
    digestSource: digestSource as ProviderOperationDigestSource | undefined,
  });
}

function requireSignal(value: unknown): AbortSignal {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly aborted?: unknown }).aborted !== "boolean" ||
    typeof (value as { readonly addEventListener?: unknown }).addEventListener !== "function" ||
    typeof (value as { readonly removeEventListener?: unknown }).removeEventListener !== "function"
  ) {
    stateError("provider request signal is malformed");
  }
  return value as AbortSignal;
}

function bindLease(value: unknown): BoundLease {
  const lease = requireObject(
    value,
    "provider terminal delivery lease",
  ) as unknown as ProviderTerminalDeliveryLease;
  let owned: unknown;
  try {
    owned = lease.owned;
  } catch (error) {
    stateError("provider terminal delivery lease owned access failed", error);
  }
  if (typeof owned !== "object" || owned === null) {
    stateError("provider terminal delivery lease has no owned request");
  }
  requireSignal((owned as Partial<OwnedProviderRequest>).signal);
  return Object.freeze({
    owned: owned as OwnedProviderRequest,
    assertActive: requireMethod(lease, "assertActive", "lease.assertActive"),
    postMessage: requireMethod(lease, "postMessage", "lease.postMessage"),
    finish: requireMethod(lease, "finish", "lease.finish"),
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

function approvalsEqual(left: ApprovalRecord, right: ApprovalRecord): boolean {
  return left.version === right.version &&
    left.id === right.id &&
    left.origin === right.origin &&
    left.tabId === right.tabId &&
    left.frameId === right.frameId &&
    left.documentId === right.documentId &&
    bytesEqual(left.account, right.account) &&
    left.method === right.method &&
    left.chain === right.chain &&
    bytesEqual(left.genesisHash, right.genesisHash) &&
    bytesEqual(left.programId, right.programId) &&
    bytesEqual(left.rawMessage, right.rawMessage) &&
    approvalDigestsEqual(left.messageDigest, right.messageDigest) &&
    left.policyVersion === right.policyVersion &&
    left.createdAt === right.createdAt &&
    left.expiresAt === right.expiresAt &&
    left.state === right.state &&
    left.resolvedAt === right.resolvedAt;
}

function operationFailureCode(
  code: ProviderOperationFailureCode,
): ProviderTerminalFailureCode {
  switch (code) {
    case "expired":
      return "WARDEN_REQUEST_EXPIRED";
    case "request-cancelled":
    case "worker-restarted":
      return "WARDEN_REQUEST_CANCELLED";
    case "preparation-failed":
      return "WARDEN_REQUEST_FAILED";
  }
}

function approvalFailureCode(
  state: Exclude<ApprovalRecord["state"], "pending" | "approved">,
): ProviderTerminalFailureCode {
  switch (state) {
    case "rejected":
      return "WARDEN_USER_REJECTED";
    case "cancelled":
      return "WARDEN_REQUEST_CANCELLED";
    case "expired":
      return "WARDEN_REQUEST_EXPIRED";
    case "invalidated":
      return "WARDEN_REQUEST_FAILED";
  }
}

function clearOperation(value: ProviderOperationRecord | null | undefined): void {
  value?.requestDigest.fill(0);
  value?.approvalDigest?.fill(0);
}

function clearApproval(value: ApprovalRecord | null | undefined): void {
  if (value === null || value === undefined) return;
  for (const field of [
    "account",
    "genesisHash",
    "programId",
    "rawMessage",
    "messageDigest",
  ] as const) {
    try {
      value[field].fill(0);
    } catch {
      // Cleanup of a hostile repository value must not mask the fail-closed
      // validation error that made it untrusted.
    }
  }
}

function clearSigning(value: ApprovalSigningRecord | null | undefined): void {
  if (value === null || value === undefined) return;
  try {
    clearApproval(value.approval);
  } catch {
    // A revoked proxy is already rejected by the strict snapshot above.
  }
  for (const field of [
    "messageDigest",
    "transactionBytes",
    "transactionDigest",
  ] as const) {
    try {
      value.outcome[field]?.fill(0);
    } catch {
      // Preserve the validation failure over an adversarial cleanup getter.
    }
  }
}

/** Deliver exactly one durable signed result or one closed terminal failure. */
export class ProviderTerminalOutcomeOwner {
  readonly #dependencies: BoundDependencies;

  constructor(options: ProviderTerminalOutcomeOwnerOptions) {
    this.#dependencies = bindDependencies(options);
  }

  #currentTime(): number {
    let value: unknown;
    try {
      value = this.#dependencies.readNow();
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
    const identity = this.#dependencies.digestSource === undefined
      ? await deriveProviderOperationIdentity(lease.owned)
      : await deriveProviderOperationIdentity(
          lease.owned,
          this.#dependencies.digestSource,
        );
    let operation: ProviderOperationRecord | null | undefined;
    let approval: ApprovalRecord | null | undefined;
    let ownerSigning: ApprovalSigningRecord | null | undefined;
    let signing: ApprovalSigningRecord | undefined;
    let expectedDigest: Uint8Array | undefined;
    let failureCode: ProviderTerminalFailureCode | undefined;
    try {
      lease.assertActive();
      try {
        const value = await this.#dependencies.readOperation({
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

      if (operation.state === "failed") {
        if (operation.failureCode === null) {
          stateError("failed operation has no failure code");
        }
        failureCode = operationFailureCode(operation.failureCode);
      } else {
        if (operation.state !== "bound") {
          stateError("durable operation is not terminal");
        }
        if (operation.approvalId === null || operation.approvalDigest === null) {
          stateError("bound operation has no approval binding");
        }
        expectedDigest = operation.approvalDigest.slice();
        lease.assertActive();
        try {
          const value = await this.#dependencies.readApproval(operation.approvalId);
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

        if (approval.state === "pending") {
          stateError("durable approval is not terminal");
        }
        if (approval.state !== "approved") {
          failureCode = approvalFailureCode(approval.state);
        } else {
          lease.assertActive();
          const digest = expectedDigest.slice();
          try {
            try {
              ownerSigning = await this.#dependencies.readSigning(
                operation.approvalId,
                digest,
              );
            } catch (error) {
              stateError("durable signing outcome read failed", error);
            }
          } finally {
            digest.fill(0);
          }
          if (ownerSigning === null) {
            stateError("approved operation has no durable signing outcome");
          }
          try {
            signing = snapshotApprovalSigningRecord(ownerSigning);
          } catch (error) {
            stateError("durable signing outcome is malformed", error);
          }
          if (!approvalsEqual(signing.approval, approval)) {
            stateError("signing outcome differs from the exact approval binding");
          }
          if (signing.outcome.state === "signing") {
            stateError("durable signing outcome is not terminal");
          }
          if (signing.outcome.state === "signed") {
            lease.assertActive();
            const delivered = await this.#dependencies.deliverSigned(leaseValue);
            if (delivered !== true) {
              stateError("signed terminal delivery returned no proof");
            }
            return true;
          }
          failureCode = "WARDEN_REQUEST_FAILED";
        }
      }

      if (failureCode === undefined) {
        stateError("durable state produced no terminal outcome");
      }
      const response = createProviderTerminalFailureResponse(
        identity.correlationId,
        failureCode,
      );
      // No await may separate the final lease check, enqueue, and release.
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
      clearSigning(signing);
      clearSigning(ownerSigning);
      expectedDigest?.fill(0);
    }
  }
}
