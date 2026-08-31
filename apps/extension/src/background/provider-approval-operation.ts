//! Still-unreachable C15 provider operation -> approval composition owner.
//!
//! The durable provider-operation claim commits before approval preparation in
//! `ProviderOperationOwner`. This owner holds the resulting prepared approval
//! below the visibility boundary until the exact operation -> approval binding
//! is proven durable. A retained binding is replay-only: it never prepares or
//! opens a second approval.

import {
  APPROVAL_DIGEST_BYTES,
  type ApprovalChain,
} from "@warden/core/approval";

import {
  type ProviderApprovalActionRegistration,
} from "./provider-approval-action.js";
import {
  type ProviderApprovalHandle,
  type ProviderPreparedApprovalHandle,
  type ProviderRequestLease,
} from "./provider-approval-request.js";
import {
  type ProviderOperationPreparation,
  type ProviderOperationRequestLease,
  type ProviderOperationResolution,
  snapshotProviderOperation,
} from "./provider-operation.js";

const APPROVAL_ID_PATTERN = /^req_[0-9a-f]{32}$/;
const CHAINS: ReadonlySet<string> = new Set([
  "solana:mainnet",
  "solana:devnet",
  "solana:testnet",
  "solana:localnet",
]);

interface ProviderApprovalPreparer {
  prepare(lease: ProviderRequestLease): Promise<ProviderPreparedApprovalHandle>;
}

interface ProviderOperationBinder {
  prepare(
    lease: ProviderOperationRequestLease,
    prepare: () => Promise<ProviderOperationPreparation>,
  ): Promise<ProviderOperationResolution>;
}

interface ProviderApprovalActionRegistrar {
  register(action: ProviderApprovalActionRegistration): void;
}

export interface ProviderApprovalOperationOwnerOptions {
  readonly actions: ProviderApprovalActionRegistrar;
  readonly approvals: ProviderApprovalPreparer;
  readonly operations: ProviderOperationBinder;
}

export type ProviderApprovalOperationLaunch =
  | Readonly<{
      readonly kind: "opened";
      readonly approval: ProviderApprovalHandle;
    }>
  | Readonly<{
      readonly kind: "replay-required";
    }>;

interface BoundPreparedApproval {
  readonly id: string;
  readonly account: Uint8Array;
  readonly chain: ApprovalChain;
  readonly messageDigest: Uint8Array;
  readonly signal: AbortSignal;
  readonly approve: () => Promise<boolean>;
  readonly open: () => Promise<void>;
  readonly settle: () => Promise<boolean>;
  readonly cancel: () => Promise<boolean>;
}

interface BoundDependencies {
  readonly registerAction: ProviderApprovalActionRegistrar["register"];
  readonly prepareApproval: ProviderApprovalPreparer["prepare"];
  readonly prepareOperation: ProviderOperationBinder["prepare"];
}

export class ProviderApprovalOperationStateError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`provider approval operation: ${message}`, options);
    this.name = "ProviderApprovalOperationStateError";
  }
}

function stateError(message: string, cause?: unknown): never {
  throw new ProviderApprovalOperationStateError(
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
  const actions = requireObject(
    options.actions,
    "approval action owner",
  ) as unknown as ProviderApprovalActionRegistrar;
  const approvals = requireObject(
    options.approvals,
    "approval preparation owner",
  ) as unknown as ProviderApprovalPreparer;
  const operations = requireObject(
    options.operations,
    "provider operation owner",
  ) as unknown as ProviderOperationBinder;
  return Object.freeze({
    registerAction: requireMethod(actions, "register", "actions.register"),
    prepareApproval: requireMethod(approvals, "prepare", "approvals.prepare"),
    prepareOperation: requireMethod(operations, "prepare", "operations.prepare"),
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
    stateError("prepared approval signal is malformed");
  }
  return value as AbortSignal;
}

function requireBytes(value: unknown, length: number, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    stateError(`${name} must contain exactly ${length} bytes`);
  }
  return value.slice();
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function requireApprovalId(value: unknown): string {
  if (typeof value !== "string" || !APPROVAL_ID_PATTERN.test(value)) {
    stateError("prepared approval id is malformed");
  }
  return value;
}

async function bindPreparedApproval(value: unknown): Promise<BoundPreparedApproval> {
  let handle: ProviderPreparedApprovalHandle;
  try {
    handle = requireObject(
      value,
      "prepared approval handle",
    ) as unknown as ProviderPreparedApprovalHandle;
  } catch (error) {
    stateError("approval preparation returned no cleanup-capable handle", error);
  }
  let cancel: () => Promise<boolean>;
  try {
    cancel = requireMethod(handle, "cancel", "prepared approval cancel");
  } catch (error) {
    stateError("prepared approval cleanup capability is unavailable", error);
  }

  let account: Uint8Array | undefined;
  let messageDigest: Uint8Array | undefined;
  try {
    const id = requireApprovalId(handle.id);
    account = requireBytes(handle.account, 32, "prepared approval account");
    messageDigest = requireBytes(
      handle.messageDigest,
      APPROVAL_DIGEST_BYTES,
      "prepared approval message digest",
    );
    const chain = handle.chain;
    if (typeof chain !== "string" || !CHAINS.has(chain)) {
      stateError("prepared approval chain is unsupported");
    }
    return Object.freeze({
      id,
      account,
      chain,
      messageDigest,
      signal: requireSignal(handle.signal),
      approve: requireMethod(handle, "approve", "prepared approval approve"),
      open: requireMethod(handle, "open", "prepared approval open"),
      settle: requireMethod(handle, "settle", "prepared approval settle"),
      cancel,
    });
  } catch (error) {
    account?.fill(0);
    messageDigest?.fill(0);
    try {
      const cleaned = await cancel();
      if (typeof cleaned !== "boolean") {
        stateError("malformed prepared approval cleanup returned no proof");
      }
    } catch (cleanupError) {
      throw new ProviderApprovalOperationStateError(
        "malformed prepared approval cleanup is unproven",
        {
          cause: new AggregateError(
            [error, cleanupError],
            "prepared approval validation and cleanup both failed",
          ),
        },
      );
    }
    throw error;
  }
}

function approvalFacade(handle: BoundPreparedApproval): ProviderApprovalHandle {
  const account = handle.account.slice();
  const messageDigest = handle.messageDigest.slice();
  return Object.freeze({
    id: handle.id,
    get account(): Uint8Array {
      return account.slice();
    },
    chain: handle.chain,
    get messageDigest(): Uint8Array {
      return messageDigest.slice();
    },
    settle: handle.settle,
    cancel: handle.cancel,
  });
}

function requireResolution(value: unknown): ProviderOperationResolution {
  const resolution = requireObject(
    value,
    "provider operation resolution",
  ) as unknown as ProviderOperationResolution;
  if (typeof resolution.created !== "boolean") {
    stateError("provider operation resolution.created must be boolean");
  }
  let record;
  try {
    record = snapshotProviderOperation(resolution.record);
  } catch (error) {
    stateError("provider operation resolution record is malformed", error);
  }
  if (record.state !== "bound") {
    record.requestDigest.fill(0);
    record.approvalDigest?.fill(0);
    stateError("provider operation resolution is not durably bound");
  }
  return Object.freeze({ created: resolution.created, record });
}

function clearPrepared(handle: BoundPreparedApproval | undefined): void {
  handle?.account.fill(0);
  handle?.messageDigest.fill(0);
}

/**
 * Composes the C12/C15 owners with the volatile C17 action registry without a
 * Port listener, trusted RPC factory, or success route. Within this owner,
 * `launch()` remains the sole visibility edge.
 */
export class ProviderApprovalOperationOwner {
  readonly #dependencies: BoundDependencies;

  constructor(options: ProviderApprovalOperationOwnerOptions) {
    this.#dependencies = bindDependencies(options);
  }

  async launch(
    lease: ProviderRequestLease & ProviderOperationRequestLease,
  ): Promise<ProviderApprovalOperationLaunch> {
    let prepared: BoundPreparedApproval | undefined;
    let resolution: ProviderOperationResolution | undefined;
    try {
      const resolutionValue = await this.#dependencies.prepareOperation(
        lease,
        async (): Promise<ProviderOperationPreparation> => {
          const candidateValue = await this.#dependencies.prepareApproval(lease);
          const candidate = await bindPreparedApproval(candidateValue);
          if (prepared !== undefined) {
            try {
              await candidate.cancel();
            } finally {
              clearPrepared(candidate);
            }
            stateError("operation owner invoked approval preparation more than once");
          }
          prepared = candidate;
          return Object.freeze({
            id: candidate.id,
            get messageDigest(): Uint8Array {
              return candidate.messageDigest.slice();
            },
          });
        },
      );
      resolution = requireResolution(resolutionValue);

      if (!resolution.created) {
        if (prepared !== undefined) {
          stateError("replayed operation unexpectedly prepared a new approval");
        }
        return Object.freeze({ kind: "replay-required" });
      }
      if (prepared === undefined) {
        stateError("new operation returned without a prepared approval");
      }
      if (
        resolution.record.approvalId !== prepared.id ||
        resolution.record.approvalDigest === null ||
        !bytesEqual(resolution.record.approvalDigest, prepared.messageDigest)
      ) {
        stateError("durable operation binding differs from the prepared approval");
      }

      const registration: ProviderApprovalActionRegistration = Object.freeze({
        id: prepared.id,
        get messageDigest(): Uint8Array {
          return prepared!.messageDigest.slice();
        },
        signal: prepared.signal,
        approve: prepared.approve,
        settle: prepared.settle,
      });
      const registered = this.#dependencies.registerAction(registration);
      if (registered !== undefined) {
        stateError("approval action registration must complete synchronously");
      }
      const approval = approvalFacade(prepared);
      await prepared.open();
      return Object.freeze({ kind: "opened", approval });
    } catch (error) {
      if (prepared !== undefined) {
        try {
          await prepared.cancel();
        } catch (cleanupError) {
          throw new ProviderApprovalOperationStateError(
            "approval cleanup is unproven after operation failure",
            {
              cause: new AggregateError(
                [error, cleanupError],
                "operation failure and approval cleanup both failed",
              ),
            },
          );
        }
      }
      throw error;
    } finally {
      clearPrepared(prepared);
      resolution?.record.requestDigest.fill(0);
      resolution?.record.approvalDigest?.fill(0);
    }
  }
}
