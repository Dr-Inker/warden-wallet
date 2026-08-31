import {
  APPROVAL_DIGEST_BYTES,
  ApprovalSigningOutcomeFormatError,
  ApprovalRecordFormatError,
  approvalDigestsEqual,
  completeApprovalSigningAttempt,
  createApprovalSigningAttempt,
  failApprovalSigningAttempt,
  parseApprovalSigningFailureCode,
  resolveApprovalRecord,
  retryApprovalSigningAttempt,
  snapshotApprovalSigningOutcome,
  snapshotApprovalSigningRecord,
  snapshotApprovalRecord,
  type ApprovalRecord,
  type ApprovalSigningOutcome,
  type ApprovalSigningFailureCode,
  type ApprovalSigningRecord,
  type ApprovalTerminalState,
} from "@warden/core/approval";
import { MAX_TX_BYTES } from "@warden/core/constants";

import type {
  ApprovalRecordRepository,
  ApprovalSigningClaim,
  ApprovalSigningCompletion,
  ApprovalSigningFailure,
  ApprovalSigningLookup,
  ApprovalTransition,
} from "./approval-owner.js";

export const APPROVAL_DATABASE_VERSION = 1;
export const APPROVAL_OBJECT_STORE_NAME = "approvals";
export const APPROVAL_DATABASE_NAME = "warden-approvals-v1";
export const MAX_PENDING_APPROVAL_RECORDS = 32;
export const MAX_TOTAL_APPROVAL_RECORDS = 128;
export const APPROVAL_TOMBSTONE_RETENTION_MS = 10 * 60 * 1_000;

const APPROVAL_ID_PATTERN = /^req_[0-9a-f]{32}$/;
const APPROVAL_ATTEMPT_ID_PATTERN = /^attempt_[0-9a-f]{32}$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;
const CLIENT_TRANSITION_STATES: ReadonlySet<string> = new Set([
  "rejected",
  "cancelled",
]);

interface StoredApprovalEnvelope {
  readonly id: string;
  readonly approval: ApprovalRecord;
  readonly signing: ApprovalSigningOutcome | null;
}

export class ApprovalStoreError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`approval store: ${message}`, options);
    this.name = "ApprovalStoreError";
  }
}

export class ApprovalRecordNotFoundError extends ApprovalStoreError {
  constructor(id: string) {
    super(`record ${id} does not exist`);
    this.name = "ApprovalRecordNotFoundError";
  }
}

export class ApprovalStateConflictError extends ApprovalStoreError {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalStateConflictError";
  }
}

export class ApprovalDigestMismatchError extends ApprovalStoreError {
  constructor() {
    super("approval digest does not match the stored message");
    this.name = "ApprovalDigestMismatchError";
  }
}

export class ApprovalCapacityError extends ApprovalStoreError {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalCapacityError";
  }
}

export class ApprovalClockError extends ApprovalStoreError {
  constructor(message = "clock moved before durable record time") {
    super(message);
    this.name = "ApprovalClockError";
  }
}

interface RepositoryOptions {
  readonly databaseName?: string;
  readonly indexedDb?: IDBFactory;
}

interface TransactionControl<T> {
  succeed(value: T): void;
  failAfterCommit(error: Error): void;
  abort(error: Error): void;
}

function requireDatabaseName(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    CONTROL_CHARACTER_PATTERN.test(value)
  ) {
    throw new ApprovalStoreError("databaseName is malformed");
  }
  return value;
}

function requireIndexedDb(value: unknown): IDBFactory {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as Partial<IDBFactory>).open !== "function"
  ) {
    throw new ApprovalStoreError("IndexedDB is unavailable");
  }
  return value as IDBFactory;
}

function requireNow(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new ApprovalStoreError("now must be a non-negative safe integer");
  }
  return value as number;
}

function requireId(value: unknown): string {
  if (typeof value !== "string" || !APPROVAL_ID_PATTERN.test(value)) {
    throw new ApprovalStoreError(
      "id must be a background-minted 128-bit request id",
    );
  }
  return value;
}

function requireAttemptId(value: unknown): string {
  if (typeof value !== "string" || !APPROVAL_ATTEMPT_ID_PATTERN.test(value)) {
    throw new ApprovalStoreError(
      "attemptId must be a background-minted 128-bit attempt id",
    );
  }
  return value;
}

function requireExpectedDigest(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== APPROVAL_DIGEST_BYTES) {
    throw new ApprovalRecordFormatError(
      `expected digest must contain exactly ${APPROVAL_DIGEST_BYTES} bytes`,
    );
  }
  return value.slice();
}

function requireTransactionBytes(value: unknown): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    value.length === 0 ||
    value.length > MAX_TX_BYTES
  ) {
    throw new ApprovalRecordFormatError(
      `signed transaction must contain 1 to ${MAX_TX_BYTES} bytes`,
    );
  }
  return value.slice();
}

function requireTransitionState(value: unknown): ApprovalTerminalState {
  if (typeof value !== "string" || !CLIENT_TRANSITION_STATES.has(value)) {
    throw new ApprovalStoreError(
      "client transition must be rejected or cancelled",
    );
  }
  return value as ApprovalTerminalState;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function clearApproval(value: ApprovalRecord | undefined): void {
  value?.account.fill(0);
  value?.genesisHash.fill(0);
  value?.programId.fill(0);
  value?.rawMessage.fill(0);
  value?.messageDigest.fill(0);
}

function clearOutcome(value: ApprovalSigningOutcome | undefined | null): void {
  value?.messageDigest.fill(0);
  value?.transactionBytes?.fill(0);
  value?.transactionDigest?.fill(0);
}

function assertSigningPair(
  approval: ApprovalRecord,
  outcome: ApprovalSigningOutcome,
): void {
  const checked = snapshotApprovalSigningRecord({ approval, outcome });
  clearApproval(checked.approval);
  clearOutcome(checked.outcome);
}

function snapshotStoredEnvelope(value: unknown): StoredApprovalEnvelope {
  let keys: readonly PropertyKey[];
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new ApprovalRecordFormatError("stored value must be an object");
    }
    keys = Reflect.ownKeys(value);
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch (error) {
    if (error instanceof ApprovalRecordFormatError) throw error;
    throw new ApprovalRecordFormatError("stored value shape could not be inspected");
  }

  const envelopeFields = ["approval", "id", "signing"];
  const stringKeys = keys.filter((key): key is string => typeof key === "string").sort();
  const isEnvelope =
    keys.length === envelopeFields.length &&
    stringKeys.length === envelopeFields.length &&
    stringKeys.every((field, index) => field === envelopeFields[index]);

  // Backward-compatible one-way migration for pre-C8 pending/terminal records.
  // A legacy approved tombstone is deliberately rejected: it cannot prove
  // whether signing ever produced bytes.
  if (!isEnvelope) {
    const approval = snapshotApprovalRecord(value);
    if (approval.state === "approved") {
      clearApproval(approval);
      throw new ApprovalRecordFormatError(
        "legacy approved record has no durable signing outcome",
      );
    }
    return Object.freeze({ id: approval.id, approval, signing: null });
  }
  if (prototype !== Object.prototype && prototype !== null) {
    throw new ApprovalRecordFormatError("stored envelope has a custom prototype");
  }
  for (const field of envelopeFields) {
    const descriptor = descriptors[field];
    if (descriptor === undefined || !("value" in descriptor)) {
      throw new ApprovalRecordFormatError(
        `stored envelope ${field} must be an own data property`,
      );
    }
  }

  const idValue = descriptors.id!.value;
  const approvalValue = descriptors.approval!.value;
  const signingValue = descriptors.signing!.value;
  const id = requireId(idValue);
  let approval: ApprovalRecord | undefined;
  let signing: ApprovalSigningOutcome | null | undefined;
  try {
    approval = snapshotApprovalRecord(approvalValue);
    signing = signingValue === null
      ? null
      : snapshotApprovalSigningOutcome(signingValue);
    if (id !== approval.id) {
      throw new ApprovalRecordFormatError("stored envelope id does not match approval");
    }
    if (approval.state === "approved") {
      if (signing === null) {
        throw new ApprovalRecordFormatError(
          "approved record has no durable signing outcome",
        );
      }
      assertSigningPair(approval, signing);
    } else if (signing !== null) {
      throw new ApprovalRecordFormatError(
        "non-approved record must not carry a signing outcome",
      );
    }
    return Object.freeze({ id, approval, signing });
  } catch (error) {
    clearApproval(approval);
    clearOutcome(signing);
    if (
      error instanceof ApprovalRecordFormatError ||
      error instanceof ApprovalSigningOutcomeFormatError
    ) {
      throw error;
    }
    throw new ApprovalRecordFormatError("stored envelope is malformed");
  }
}

function storedEnvelope(
  approvalValue: ApprovalRecord,
  signingValue: ApprovalSigningOutcome | null,
): StoredApprovalEnvelope {
  const approval = snapshotApprovalRecord(approvalValue);
  const signing = signingValue === null
    ? null
    : snapshotApprovalSigningOutcome(signingValue);
  try {
    if (approval.state === "approved") {
      if (signing === null) {
        throw new ApprovalRecordFormatError(
          "approved record has no durable signing outcome",
        );
      }
      assertSigningPair(approval, signing);
    } else if (signing !== null) {
      throw new ApprovalRecordFormatError(
        "non-approved record must not carry a signing outcome",
      );
    }
    return Object.freeze({ id: approval.id, approval, signing });
  } catch (error) {
    clearApproval(approval);
    clearOutcome(signing);
    throw error;
  }
}

function signingRecord(
  stored: StoredApprovalEnvelope,
): ApprovalSigningRecord {
  if (stored.signing === null) {
    throw new ApprovalStateConflictError(
      `record ${stored.id} has no signing outcome`,
    );
  }
  return snapshotApprovalSigningRecord({
    approval: stored.approval,
    outcome: stored.signing,
  });
}

function retentionTimestamp(stored: StoredApprovalEnvelope): number | null {
  if (stored.signing?.resolvedAt !== null && stored.signing?.resolvedAt !== undefined) {
    return stored.signing.resolvedAt;
  }
  return stored.approval.resolvedAt;
}

function transactionFailure(
  transaction: IDBTransaction,
  operationError: Error | undefined,
): Error {
  if (operationError !== undefined) return operationError;
  return new ApprovalStoreError("IndexedDB transaction aborted", {
    cause: transaction.error ?? undefined,
  });
}

function openApprovalDatabase(
  factory: IDBFactory,
  databaseName: string,
): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let upgradeError: Error | undefined;
    const request = factory.open(databaseName, APPROVAL_DATABASE_VERSION);

    const rejectOnce = (error: Error): void => {
      if (settled) return;
      settled = true;
      reject(error);
    };

    request.onblocked = () => {
      rejectOnce(new ApprovalStoreError("IndexedDB schema upgrade is blocked"));
    };
    request.onerror = () => {
      rejectOnce(
        upgradeError ??
          new ApprovalStoreError("IndexedDB open failed", {
            cause: request.error ?? undefined,
          }),
      );
    };
    request.onupgradeneeded = (event) => {
      try {
        if (event.oldVersion !== 0) {
          throw new ApprovalStoreError(
            `unsupported IndexedDB migration from version ${event.oldVersion}`,
          );
        }
        request.result.createObjectStore(APPROVAL_OBJECT_STORE_NAME, {
          keyPath: "id",
        });
      } catch (error) {
        upgradeError = error instanceof Error
          ? error
          : new ApprovalStoreError("IndexedDB schema creation failed");
        request.transaction?.abort();
      }
    };
    request.onsuccess = () => {
      const database = request.result;
      if (settled) {
        database.close();
        return;
      }
      try {
        if (
          database.objectStoreNames.length !== 1 ||
          !database.objectStoreNames.contains(APPROVAL_OBJECT_STORE_NAME)
        ) {
          throw new ApprovalStoreError("IndexedDB schema is unexpected");
        }
        const transaction = database.transaction(
          APPROVAL_OBJECT_STORE_NAME,
          "readonly",
        );
        const store = transaction.objectStore(APPROVAL_OBJECT_STORE_NAME);
        if (store.keyPath !== "id" || store.autoIncrement) {
          throw new ApprovalStoreError("approval object store schema is unexpected");
        }
        database.onversionchange = () => database.close();
        settled = true;
        resolve(database);
      } catch (error) {
        database.close();
        rejectOnce(
          error instanceof Error
            ? error
            : new ApprovalStoreError("IndexedDB schema validation failed"),
        );
      }
    };
  });
}

/**
 * The only production persistence owner for C3 approval records.
 *
 * Every state change is a read-modify-write operation in one readwrite
 * transaction over one object store. IndexedDB serializes overlapping
 * readwrite scopes, so two extension contexts cannot both claim one record.
 */
export class IndexedDbApprovalRecordRepository
implements ApprovalRecordRepository {
  private readonly databasePromise: Promise<IDBDatabase>;
  private closed = false;

  constructor(options: RepositoryOptions = {}) {
    const databaseName = requireDatabaseName(
      options.databaseName ?? APPROVAL_DATABASE_NAME,
    );
    const factory = requireIndexedDb(
      options.indexedDb ?? globalThis.indexedDB,
    );
    this.databasePromise = openApprovalDatabase(factory, databaseName);
  }

  private async database(): Promise<IDBDatabase> {
    if (this.closed) throw new ApprovalStoreError("repository is closed");
    const database = await this.databasePromise;
    if (this.closed) throw new ApprovalStoreError("repository is closed");
    return database;
  }

  private async writeTransaction<T>(
    operation: (
      store: IDBObjectStore,
      control: TransactionControl<T>,
    ) => void,
  ): Promise<T> {
    const database = await this.database();
    return new Promise<T>((resolve, reject) => {
      let transaction: IDBTransaction;
      try {
        transaction = database.transaction(
          APPROVAL_OBJECT_STORE_NAME,
          "readwrite",
          { durability: "strict" },
        );
      } catch (error) {
        reject(new ApprovalStoreError("could not start IndexedDB transaction", {
          cause: error,
        }));
        return;
      }

      let operationError: Error | undefined;
      let postCommitError: Error | undefined;
      let hasResult = false;
      let result: T | undefined;
      const control: TransactionControl<T> = {
        succeed(value) {
          if (hasResult || postCommitError !== undefined) return;
          hasResult = true;
          result = value;
        },
        failAfterCommit(error) {
          postCommitError ??= error;
        },
        abort(error) {
          operationError ??= error;
          try {
            transaction.abort();
          } catch {
            // The transaction may already have aborted due to a request error.
          }
        },
      };

      transaction.oncomplete = () => {
        if (postCommitError !== undefined) {
          reject(postCommitError);
        } else if (!hasResult) {
          reject(new ApprovalStoreError("transaction completed without a result"));
        } else {
          resolve(result as T);
        }
      };
      transaction.onabort = () => {
        reject(transactionFailure(transaction, operationError));
      };
      // Request errors still bubble and abort; this prevents an uncaught event.
      transaction.onerror = () => {};

      try {
        operation(
          transaction.objectStore(APPROVAL_OBJECT_STORE_NAME),
          control,
        );
      } catch (error) {
        control.abort(
          error instanceof Error
            ? error
            : new ApprovalStoreError("transaction operation failed"),
        );
      }
    });
  }

  async create(record: ApprovalRecord, nowValue: number): Promise<ApprovalRecord> {
    const now = requireNow(nowValue);
    const stored = snapshotApprovalRecord(record);
    if (stored.state !== "pending") {
      throw new ApprovalStateConflictError("only pending records can be created");
    }
    if (stored.createdAt > now) throw new ApprovalClockError();
    if (now >= stored.expiresAt) {
      throw new ApprovalStateConflictError("approval is already expired");
    }

    return this.writeTransaction((store, control) => {
      let pendingCount = 0;
      let totalCount = 0;
      let duplicate = false;
      let cleanupFailed = false;
      const request = store.openCursor();

      request.onerror = () => {
        control.abort(new ApprovalStoreError("approval cursor failed", {
          cause: request.error ?? undefined,
        }));
      };
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor === null) {
          if (cleanupFailed || duplicate) return;
          if (pendingCount >= MAX_PENDING_APPROVAL_RECORDS) {
            control.failAfterCommit(new ApprovalCapacityError(
              `at most ${MAX_PENDING_APPROVAL_RECORDS} approvals may be pending`,
            ));
            return;
          }
          if (totalCount >= MAX_TOTAL_APPROVAL_RECORDS) {
            control.failAfterCommit(new ApprovalCapacityError(
              `at most ${MAX_TOTAL_APPROVAL_RECORDS} approval records may be retained`,
            ));
            return;
          }
          const add = store.add(storedEnvelope(stored, null));
          add.onerror = () => {
            control.abort(new ApprovalStateConflictError(
              `record ${stored.id} already exists`,
            ));
          };
          add.onsuccess = () => control.succeed(snapshotApprovalRecord(stored));
          return;
        }

        try {
          const currentStored = snapshotStoredEnvelope(cursor.value);
          const current = currentStored.approval;
          if (cursor.primaryKey !== currentStored.id) {
            throw new ApprovalRecordFormatError("stored key does not match record id");
          }
          if (current.id === stored.id) {
            duplicate = true;
            control.failAfterCommit(new ApprovalStateConflictError(
              `record ${stored.id} already exists`,
            ));
          }
          if (current.state === "pending") {
            if (now < current.createdAt) {
              cursor.delete();
              cleanupFailed = true;
              control.failAfterCommit(new ApprovalClockError());
            } else if (now >= current.expiresAt) {
              cursor.update(storedEnvelope(
                resolveApprovalRecord(current, "expired", now),
                null,
              ));
              totalCount++;
            } else {
              pendingCount++;
              totalCount++;
            }
          } else if (
            retentionTimestamp(currentStored) !== null &&
            now >= retentionTimestamp(currentStored)! &&
            now - retentionTimestamp(currentStored)! >= APPROVAL_TOMBSTONE_RETENTION_MS
          ) {
            cursor.delete();
          } else {
            totalCount++;
          }
          cursor.continue();
        } catch (error) {
          cursor.delete();
          cleanupFailed = true;
          control.failAfterCommit(
            error instanceof ApprovalRecordFormatError
              ? error
              : new ApprovalRecordFormatError("stored record is malformed"),
          );
          cursor.continue();
        }
      };
    });
  }

  async read(idValue: string, nowValue: number): Promise<ApprovalRecord | null> {
    const id = requireId(idValue);
    const now = requireNow(nowValue);
    return this.writeTransaction((store, control) => {
      const request = store.get(id);
      request.onerror = () => {
        control.abort(new ApprovalStoreError("approval read failed", {
          cause: request.error ?? undefined,
        }));
      };
      request.onsuccess = () => {
        if (request.result === undefined) {
          control.succeed(null);
          return;
        }
        try {
          const currentStored = snapshotStoredEnvelope(request.result);
          const current = currentStored.approval;
          if (currentStored.id !== id) {
            throw new ApprovalRecordFormatError("stored key does not match record id");
          }
          if (current.state === "pending" && now < current.createdAt) {
            store.delete(id);
            control.failAfterCommit(new ApprovalClockError());
          } else if (current.state === "pending" && now >= current.expiresAt) {
            const expired = resolveApprovalRecord(current, "expired", now);
            store.put(storedEnvelope(expired, null));
            control.succeed(snapshotApprovalRecord(expired));
          } else {
            control.succeed(snapshotApprovalRecord(current));
          }
        } catch (error) {
          store.delete(id);
          control.failAfterCommit(
            error instanceof ApprovalRecordFormatError
              ? error
              : new ApprovalRecordFormatError("stored record is malformed"),
          );
        }
      };
    });
  }

  async transition(transition: ApprovalTransition): Promise<ApprovalRecord> {
    if (typeof transition !== "object" || transition === null) {
      throw new ApprovalStoreError("transition must be an object");
    }
    const id = requireId(transition.id);
    const state = requireTransitionState(transition.state);
    const now = requireNow(transition.now);
    return this.writeTransaction((store, control) => {
      const request = store.get(id);
      request.onerror = () => {
        control.abort(new ApprovalStoreError("approval transition read failed", {
          cause: request.error ?? undefined,
        }));
      };
      request.onsuccess = () => {
        if (request.result === undefined) {
          control.failAfterCommit(new ApprovalRecordNotFoundError(id));
          return;
        }
        try {
          const currentStored = snapshotStoredEnvelope(request.result);
          const current = currentStored.approval;
          if (currentStored.id !== id) {
            throw new ApprovalRecordFormatError(
              "stored key does not match record id",
            );
          }
          if (current.state !== "pending") {
            control.failAfterCommit(new ApprovalStateConflictError(
              `record ${id} is already ${current.state}`,
            ));
          } else if (now < current.createdAt) {
            store.delete(id);
            control.failAfterCommit(new ApprovalClockError());
          } else if (now >= current.expiresAt) {
            store.put(storedEnvelope(
              resolveApprovalRecord(current, "expired", now),
              null,
            ));
            control.failAfterCommit(new ApprovalStateConflictError(
              `record ${id} has expired`,
            ));
          } else {
            const resolved = resolveApprovalRecord(current, state, now);
            store.put(storedEnvelope(resolved, null));
            control.succeed(snapshotApprovalRecord(resolved));
          }
        } catch (error) {
          store.delete(id);
          control.failAfterCommit(
            error instanceof ApprovalRecordFormatError ||
              error instanceof ApprovalSigningOutcomeFormatError
              ? error
              : new ApprovalRecordFormatError("stored record is malformed"),
          );
        }
      };
    });
  }

  async readSigning(
    lookup: ApprovalSigningLookup,
  ): Promise<ApprovalSigningRecord | null> {
    if (typeof lookup !== "object" || lookup === null) {
      throw new ApprovalStoreError("signing lookup must be an object");
    }
    const id = requireId(lookup.id);
    const expectedDigest = requireExpectedDigest(lookup.expectedDigest);
    requireNow(lookup.now);
    try {
      return await this.writeTransaction((store, control) => {
        const request = store.get(id);
        request.onerror = () => {
          control.abort(new ApprovalStoreError("signing lookup read failed", {
            cause: request.error ?? undefined,
          }));
        };
        request.onsuccess = () => {
          if (request.result === undefined) {
            control.succeed(null);
            return;
          }
          try {
            const current = snapshotStoredEnvelope(request.result);
            if (current.id !== id) {
              throw new ApprovalRecordFormatError(
                "stored key does not match record id",
              );
            }
            if (!approvalDigestsEqual(current.approval.messageDigest, expectedDigest)) {
              control.failAfterCommit(new ApprovalDigestMismatchError());
            } else if (current.approval.state === "pending") {
              control.succeed(null);
            } else if (current.approval.state !== "approved") {
              control.failAfterCommit(new ApprovalStateConflictError(
                `record ${id} is already ${current.approval.state}`,
              ));
            } else {
              control.succeed(signingRecord(current));
            }
          } catch (error) {
            store.delete(id);
            control.failAfterCommit(
              error instanceof ApprovalRecordFormatError ||
                error instanceof ApprovalSigningOutcomeFormatError
                ? error
                : new ApprovalRecordFormatError("stored record is malformed"),
            );
          }
        };
      });
    } finally {
      expectedDigest.fill(0);
    }
  }

  async claimSigning(claim: ApprovalSigningClaim): Promise<ApprovalSigningRecord> {
    if (typeof claim !== "object" || claim === null) {
      throw new ApprovalStoreError("signing claim must be an object");
    }
    const id = requireId(claim.id);
    const expectedDigest = requireExpectedDigest(claim.expectedDigest);
    const attemptId = requireAttemptId(claim.attemptId);
    const now = requireNow(claim.now);
    try {
      return await this.writeTransaction((store, control) => {
        const request = store.get(id);
        request.onerror = () => {
          control.abort(new ApprovalStoreError("signing claim read failed", {
            cause: request.error ?? undefined,
          }));
        };
        request.onsuccess = () => {
          if (request.result === undefined) {
            control.failAfterCommit(new ApprovalRecordNotFoundError(id));
            return;
          }
          try {
            const current = snapshotStoredEnvelope(request.result);
            const approval = current.approval;
            if (current.id !== id) {
              throw new ApprovalRecordFormatError(
                "stored key does not match record id",
              );
            }
            if (approval.state === "pending") {
              if (now < approval.createdAt) {
                store.delete(id);
                control.failAfterCommit(new ApprovalClockError());
                return;
              }
              if (now >= approval.expiresAt) {
                store.put(storedEnvelope(
                  resolveApprovalRecord(approval, "expired", now),
                  null,
                ));
                control.failAfterCommit(new ApprovalStateConflictError(
                  `record ${id} has expired`,
                ));
                return;
              }
              if (!approvalDigestsEqual(approval.messageDigest, expectedDigest)) {
                store.put(storedEnvelope(
                  resolveApprovalRecord(approval, "invalidated", now),
                  null,
                ));
                control.failAfterCommit(new ApprovalDigestMismatchError());
                return;
              }
              const claimed = resolveApprovalRecord(approval, "approved", now);
              const outcome = createApprovalSigningAttempt({
                id,
                messageDigest: expectedDigest,
                attemptId,
                attemptNumber: 1,
                startedAt: now,
              });
              store.put(storedEnvelope(claimed, outcome));
              control.succeed(snapshotApprovalSigningRecord({
                approval: claimed,
                outcome,
              }));
              return;
            }
            if (!approvalDigestsEqual(approval.messageDigest, expectedDigest)) {
              control.failAfterCommit(new ApprovalDigestMismatchError());
              return;
            }
            if (approval.state !== "approved" || current.signing === null) {
              control.failAfterCommit(new ApprovalStateConflictError(
                `record ${id} is already ${approval.state}`,
              ));
              return;
            }
            if (current.signing.state === "signed") {
              control.succeed(signingRecord(current));
              return;
            }
            if (current.signing.state === "signing") {
              if (current.signing.attemptId === attemptId) {
                control.succeed(signingRecord(current));
              } else {
                control.failAfterCommit(new ApprovalStateConflictError(
                  `record ${id} is owned by another signing attempt`,
                ));
              }
              return;
            }
            if (now >= approval.expiresAt) {
              control.failAfterCommit(new ApprovalStateConflictError(
                `record ${id} can no longer be retried after expiry`,
              ));
              return;
            }
            if (current.signing.attemptId === attemptId) {
              control.failAfterCommit(new ApprovalStateConflictError(
                `record ${id} retry must use a fresh signing attempt`,
              ));
              return;
            }
            if (current.signing.attemptNumber === 0xffff_ffff) {
              control.failAfterCommit(new ApprovalStateConflictError(
                `record ${id} exhausted its signing attempts`,
              ));
              return;
            }
            if (
              current.signing.resolvedAt !== null &&
              now < current.signing.resolvedAt
            ) {
              control.failAfterCommit(new ApprovalClockError(
                "clock moved before the prior signing resolution",
              ));
              return;
            }
            const retried = retryApprovalSigningAttempt(
              current.signing,
              attemptId,
              now,
            );
            store.put(storedEnvelope(approval, retried));
            control.succeed(snapshotApprovalSigningRecord({
              approval,
              outcome: retried,
            }));
          } catch (error) {
            store.delete(id);
            control.failAfterCommit(
              error instanceof ApprovalRecordFormatError ||
                error instanceof ApprovalSigningOutcomeFormatError
                ? error
                : new ApprovalRecordFormatError("stored record is malformed"),
            );
          }
        };
      });
    } finally {
      expectedDigest.fill(0);
    }
  }

  async completeSigning(
    completion: ApprovalSigningCompletion,
  ): Promise<ApprovalSigningRecord> {
    if (typeof completion !== "object" || completion === null) {
      throw new ApprovalStoreError("signing completion must be an object");
    }
    const id = requireId(completion.id);
    const expectedDigest = requireExpectedDigest(completion.expectedDigest);
    const attemptId = requireAttemptId(completion.attemptId);
    const now = requireNow(completion.now);
    try {
      const transactionBytes = requireTransactionBytes(completion.transactionBytes);
      try {
        return await this.writeTransaction((store, control) => {
          const request = store.get(id);
          request.onerror = () => {
            control.abort(new ApprovalStoreError("signing completion read failed", {
              cause: request.error ?? undefined,
            }));
          };
          request.onsuccess = () => {
            if (request.result === undefined) {
              control.failAfterCommit(new ApprovalRecordNotFoundError(id));
              return;
            }
            try {
              const current = snapshotStoredEnvelope(request.result);
              if (
                current.id !== id ||
                current.approval.state !== "approved" ||
                current.signing === null ||
                !approvalDigestsEqual(current.approval.messageDigest, expectedDigest)
              ) {
                control.failAfterCommit(new ApprovalStateConflictError(
                  `record ${id} does not own this signing completion`,
                ));
                return;
              }
              if (current.signing.state === "signed") {
                if (
                  current.signing.attemptId === attemptId &&
                  current.signing.transactionBytes !== null &&
                  bytesEqual(current.signing.transactionBytes, transactionBytes)
                ) {
                  control.succeed(signingRecord(current));
                } else {
                  control.failAfterCommit(new ApprovalStateConflictError(
                    `record ${id} already owns a different signed result`,
                  ));
                }
                return;
              }
              if (
                current.signing.state !== "signing" ||
                current.signing.attemptId !== attemptId
              ) {
                control.failAfterCommit(new ApprovalStateConflictError(
                  `record ${id} is not owned by this signing attempt`,
                ));
                return;
              }
              if (now < current.signing.startedAt) {
                control.failAfterCommit(new ApprovalClockError(
                  "clock moved before the signing attempt started",
                ));
                return;
              }
              const completed = completeApprovalSigningAttempt(
                current.signing,
                transactionBytes,
                now,
              );
              store.put(storedEnvelope(current.approval, completed));
              control.succeed(snapshotApprovalSigningRecord({
                approval: current.approval,
                outcome: completed,
              }));
            } catch (error) {
              store.delete(id);
              control.failAfterCommit(
                error instanceof ApprovalRecordFormatError ||
                  error instanceof ApprovalSigningOutcomeFormatError
                  ? error
                  : new ApprovalRecordFormatError("stored record is malformed"),
              );
            }
          };
        });
      } finally {
        transactionBytes.fill(0);
      }
    } finally {
      expectedDigest.fill(0);
    }
  }

  async failSigning(
    failure: ApprovalSigningFailure,
  ): Promise<ApprovalSigningRecord> {
    if (typeof failure !== "object" || failure === null) {
      throw new ApprovalStoreError("signing failure must be an object");
    }
    const id = requireId(failure.id);
    const attemptId = requireAttemptId(failure.attemptId);
    const now = requireNow(failure.now);
    const failureCode: ApprovalSigningFailureCode =
      parseApprovalSigningFailureCode(failure.failureCode);
    const expectedDigest = requireExpectedDigest(failure.expectedDigest);
    try {
      return await this.writeTransaction((store, control) => {
        const request = store.get(id);
        request.onerror = () => {
          control.abort(new ApprovalStoreError("signing failure read failed", {
            cause: request.error ?? undefined,
          }));
        };
        request.onsuccess = () => {
          if (request.result === undefined) {
            control.failAfterCommit(new ApprovalRecordNotFoundError(id));
            return;
          }
          try {
            const current = snapshotStoredEnvelope(request.result);
            if (
              current.id !== id ||
              current.approval.state !== "approved" ||
              current.signing === null ||
              !approvalDigestsEqual(current.approval.messageDigest, expectedDigest)
            ) {
              control.failAfterCommit(new ApprovalStateConflictError(
                `record ${id} does not own this signing failure`,
              ));
              return;
            }
            if (current.signing.state === "failed") {
              if (
                current.signing.attemptId === attemptId &&
                current.signing.failureCode === failureCode
              ) {
                control.succeed(signingRecord(current));
              } else {
                control.failAfterCommit(new ApprovalStateConflictError(
                  `record ${id} already owns a different failed attempt`,
                ));
              }
              return;
            }
            if (
              current.signing.state !== "signing" ||
              current.signing.attemptId !== attemptId
            ) {
              control.failAfterCommit(new ApprovalStateConflictError(
                `record ${id} is not owned by this signing attempt`,
              ));
              return;
            }
            if (now < current.signing.startedAt) {
              control.failAfterCommit(new ApprovalClockError(
                "clock moved before the signing attempt started",
              ));
              return;
            }
            const failed = failApprovalSigningAttempt(
              current.signing,
              failureCode,
              now,
            );
            store.put(storedEnvelope(current.approval, failed));
            control.succeed(snapshotApprovalSigningRecord({
              approval: current.approval,
              outcome: failed,
            }));
          } catch (error) {
            store.delete(id);
            control.failAfterCommit(
              error instanceof ApprovalRecordFormatError ||
                error instanceof ApprovalSigningOutcomeFormatError
                ? error
                : new ApprovalRecordFormatError("stored record is malformed"),
            );
          }
        };
      });
    } finally {
      expectedDigest.fill(0);
    }
  }

  async invalidatePending(nowValue: number): Promise<number> {
    const now = requireNow(nowValue);
    return this.writeTransaction((store, control) => {
      let invalidated = 0;
      const request = store.openCursor();
      request.onerror = () => {
        control.abort(new ApprovalStoreError("approval cursor failed", {
          cause: request.error ?? undefined,
        }));
      };
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor === null) {
          control.succeed(invalidated);
          return;
        }
        try {
          const currentStored = snapshotStoredEnvelope(cursor.value);
          const current = currentStored.approval;
          if (cursor.primaryKey !== currentStored.id) {
            throw new ApprovalRecordFormatError("stored key does not match record id");
          }
          if (current.state === "pending") {
            if (now < current.createdAt) {
              cursor.delete();
              control.failAfterCommit(new ApprovalClockError());
            } else if (now >= current.expiresAt) {
              cursor.update(storedEnvelope(
                resolveApprovalRecord(current, "expired", now),
                null,
              ));
            } else {
              cursor.update(storedEnvelope(
                resolveApprovalRecord(current, "cancelled", now),
                null,
              ));
              invalidated++;
            }
          } else if (
            current.state === "approved" &&
            currentStored.signing?.state === "signing"
          ) {
            if (now < currentStored.signing.startedAt) {
              // Preserve the durable CAS owner. A regressed clock is not
              // authority to erase an approved attempt; startup remains fatal
              // and a later worker can resolve it once time catches up.
              control.failAfterCommit(new ApprovalClockError(
                "clock moved before the unresolved signing attempt started",
              ));
            } else {
              cursor.update(storedEnvelope(
                current,
                failApprovalSigningAttempt(
                  currentStored.signing,
                  "worker-restarted",
                  now,
                ),
              ));
              invalidated++;
            }
          } else if (
            retentionTimestamp(currentStored) !== null &&
            now >= retentionTimestamp(currentStored)! &&
            now - retentionTimestamp(currentStored)! >= APPROVAL_TOMBSTONE_RETENTION_MS
          ) {
            cursor.delete();
          }
          cursor.continue();
        } catch (error) {
          cursor.delete();
          control.failAfterCommit(
            error instanceof ApprovalRecordFormatError
              ? error
              : new ApprovalRecordFormatError("stored record is malformed"),
          );
          cursor.continue();
        }
      };
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    void this.databasePromise.then(
      (database) => database.close(),
      () => {},
    );
  }
}
