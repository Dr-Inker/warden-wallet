import {
  APPROVAL_DIGEST_BYTES,
  ApprovalRecordFormatError,
  createPendingApprovalRecord,
  type ApprovalCreateParams,
  type ApprovalRecord,
  type ApprovalTerminalState,
} from "@warden/core/approval";

export interface ApprovalTransition {
  readonly id: string;
  readonly state: ApprovalTerminalState;
  readonly now: number;
  /** Required for the signing claim; absent for explicit rejection/cancellation. */
  readonly expectedDigest?: Uint8Array;
}

/** Transactional persistence boundary. Production uses one IndexedDB object store. */
export interface ApprovalRecordRepository {
  create(record: ApprovalRecord, now: number): Promise<ApprovalRecord>;
  read(id: string, now: number): Promise<ApprovalRecord | null>;
  transition(transition: ApprovalTransition): Promise<ApprovalRecord>;
  /** Pending records belonged to Ports in a dead worker and cannot be resumed. */
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
export class ApprovalOwner {
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
  ): Promise<ApprovalRecord> {
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
      return await this.repository.transition({
        id,
        state: "approved",
        now: this.currentTime(),
        expectedDigest: digest,
      });
    } finally {
      digest.fill(0);
    }
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
