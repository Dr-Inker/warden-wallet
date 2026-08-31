import {
  APPROVAL_DIGEST_BYTES,
  ApprovalRecordFormatError,
  createPendingApprovalRecord,
  parseApprovalSigningFailureCode,
  type ApprovalCreateParams,
  type ApprovalRecord,
  type ApprovalSigningFailureCode,
  type ApprovalSigningRecord,
  type ApprovalTerminalState,
} from "@warden/core/approval";
import { MAX_TX_BYTES } from "@warden/core/constants";
import type { SessionApprovalOwner } from "@warden/core/transaction/session-approval";

export interface ApprovalTransition {
  readonly id: string;
  readonly state: Exclude<ApprovalTerminalState, "approved">;
  readonly now: number;
}

export interface ApprovalSigningLookup {
  readonly id: string;
  readonly expectedDigest: Uint8Array;
  readonly now: number;
}

export interface ApprovalSigningClaim extends ApprovalSigningLookup {
  readonly attemptId: string;
}

export interface ApprovalSigningCompletion extends ApprovalSigningClaim {
  readonly transactionBytes: Uint8Array;
}

export interface ApprovalSigningFailure extends ApprovalSigningClaim {
  readonly failureCode: ApprovalSigningFailureCode;
}

/** Transactional persistence boundary. Production uses one IndexedDB object store. */
export interface ApprovalRecordRepository {
  create(record: ApprovalRecord, now: number): Promise<ApprovalRecord>;
  read(id: string, now: number): Promise<ApprovalRecord | null>;
  transition(transition: ApprovalTransition): Promise<ApprovalRecord>;
  readSigning(lookup: ApprovalSigningLookup): Promise<ApprovalSigningRecord | null>;
  claimSigning(claim: ApprovalSigningClaim): Promise<ApprovalSigningRecord>;
  completeSigning(completion: ApprovalSigningCompletion): Promise<ApprovalSigningRecord>;
  failSigning(failure: ApprovalSigningFailure): Promise<ApprovalSigningRecord>;
  /** Pending records and unresolved attempts belonged to a dead worker. */
  invalidatePending(now: number): Promise<number>;
  close(): void;
}

export class ApprovalOwnerStateError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`approval owner: ${message}`, options);
    this.name = "ApprovalOwnerStateError";
  }
}

function requireRepository(value: unknown): ApprovalRecordRepository {
  if (typeof value !== "object" || value === null) {
    throw new ApprovalOwnerStateError("repository must be an object");
  }
  const repository = value as Partial<ApprovalRecordRepository>;
  for (const method of [
    "create",
    "read",
    "transition",
    "readSigning",
    "claimSigning",
    "completeSigning",
    "failSigning",
    "invalidatePending",
    "close",
  ] as const) {
    if (typeof repository[method] !== "function") {
      throw new ApprovalOwnerStateError(`repository must provide ${method}()`);
    }
  }
  return value as ApprovalRecordRepository;
}

function requireClock(value: unknown): () => number {
  if (typeof value !== "function") {
    throw new ApprovalOwnerStateError("readNow must be a function");
  }
  return value as () => number;
}

/**
 * Internal C3 owner. It creates only strict background-resolved records and
 * delegates every terminal decision to a transactional repository. It is not a
 * signer, UI, account resolver, decoder, RPC client, or browser message route.
 */
export class ApprovalOwner implements SessionApprovalOwner {
  private readonly repository: ApprovalRecordRepository;
  private readonly readNow: () => number;

  constructor(
    repository: ApprovalRecordRepository,
    options: { readonly readNow?: () => number } = {},
  ) {
    this.repository = requireRepository(repository);
    this.readNow = requireClock(options.readNow ?? Date.now);
  }

  private currentTime(): number {
    let now: unknown;
    try {
      now = this.readNow();
    } catch (error) {
      throw new ApprovalOwnerStateError("clock read failed", { cause: error });
    }
    if (!Number.isSafeInteger(now) || (now as number) < 0) {
      throw new ApprovalOwnerStateError(
        "clock must return a non-negative safe integer",
      );
    }
    return now as number;
  }

  async create(params: ApprovalCreateParams): Promise<ApprovalRecord> {
    const now = this.currentTime();
    const record = createPendingApprovalRecord(params);
    if (record.createdAt > now) {
      throw new ApprovalRecordFormatError("createdAt is in the future");
    }
    if (now >= record.expiresAt) {
      throw new ApprovalRecordFormatError("approval is already expired");
    }
    return this.repository.create(record, now);
  }

  read(id: string): Promise<ApprovalRecord | null> {
    return this.repository.read(id, this.currentTime());
  }

  async claimForSigning(
    id: string,
    expectedDigest: Uint8Array,
    attemptId: string,
  ): Promise<ApprovalSigningRecord> {
    if (
      !(expectedDigest instanceof Uint8Array) ||
      expectedDigest.length !== APPROVAL_DIGEST_BYTES
    ) {
      throw new ApprovalRecordFormatError(
        `expected digest must contain exactly ${APPROVAL_DIGEST_BYTES} bytes`,
      );
    }
    const digest = expectedDigest.slice();
    try {
      return await this.repository.claimSigning({
        id,
        expectedDigest: digest,
        attemptId,
        now: this.currentTime(),
      });
    } finally {
      digest.fill(0);
    }
  }

  async readSigning(
    id: string,
    expectedDigest: Uint8Array,
  ): Promise<ApprovalSigningRecord | null> {
    const digest = this.snapshotDigest(expectedDigest);
    try {
      return await this.repository.readSigning({
        id,
        expectedDigest: digest,
        now: this.currentTime(),
      });
    } finally {
      digest.fill(0);
    }
  }

  async completeSigning(
    id: string,
    expectedDigest: Uint8Array,
    attemptId: string,
    transactionBytesValue: Uint8Array,
  ): Promise<ApprovalSigningRecord> {
    const digest = this.snapshotDigest(expectedDigest);
    if (
      !(transactionBytesValue instanceof Uint8Array) ||
      transactionBytesValue.length === 0 ||
      transactionBytesValue.length > MAX_TX_BYTES
    ) {
      digest.fill(0);
      throw new ApprovalRecordFormatError(
        `signed transaction must contain 1 to ${MAX_TX_BYTES} bytes`,
      );
    }
    const transactionBytes = transactionBytesValue.slice();
    try {
      return await this.repository.completeSigning({
        id,
        expectedDigest: digest,
        attemptId,
        transactionBytes,
        now: this.currentTime(),
      });
    } finally {
      digest.fill(0);
      transactionBytes.fill(0);
    }
  }

  async failSigning(
    id: string,
    expectedDigest: Uint8Array,
    attemptId: string,
    failureCode: ApprovalSigningFailureCode,
  ): Promise<ApprovalSigningRecord> {
    const parsedFailureCode = parseApprovalSigningFailureCode(failureCode);
    const digest = this.snapshotDigest(expectedDigest);
    try {
      return await this.repository.failSigning({
        id,
        expectedDigest: digest,
        attemptId,
        failureCode: parsedFailureCode,
        now: this.currentTime(),
      });
    } finally {
      digest.fill(0);
    }
  }

  private snapshotDigest(value: Uint8Array): Uint8Array {
    if (
      !(value instanceof Uint8Array) ||
      value.length !== APPROVAL_DIGEST_BYTES
    ) {
      throw new ApprovalRecordFormatError(
        `expected digest must contain exactly ${APPROVAL_DIGEST_BYTES} bytes`,
      );
    }
    return value.slice();
  }

  reject(id: string): Promise<ApprovalRecord> {
    return this.repository.transition({
      id,
      state: "rejected",
      now: this.currentTime(),
    });
  }

  cancel(id: string): Promise<ApprovalRecord> {
    return this.repository.transition({
      id,
      state: "cancelled",
      now: this.currentTime(),
    });
  }

  /** MV3 startup must cancel, never restore, approvals whose Ports died. */
  invalidateAfterWorkerRestart(): Promise<number> {
    return this.repository.invalidatePending(this.currentTime());
  }

  close(): void {
    this.repository.close();
  }
}
