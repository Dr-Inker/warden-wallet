import {
  APPROVAL_DIGEST_BYTES,
  ApprovalRecordFormatError,
  approvalDigestsEqual,
  resolveApprovalRecord,
  snapshotApprovalRecord,
  type ApprovalRecord,
  type ApprovalTerminalState,
} from "@warden/core/approval";

import type {
  ApprovalRecordRepository,
  ApprovalTransition,
} from "./approval-owner.js";

export const APPROVAL_DATABASE_VERSION = 1;
export const APPROVAL_OBJECT_STORE_NAME = "approvals";
export const MAX_PENDING_APPROVAL_RECORDS = 32;
export const MAX_TOTAL_APPROVAL_RECORDS = 128;
export const APPROVAL_TOMBSTONE_RETENTION_MS = 10 * 60 * 1_000;

const DEFAULT_DATABASE_NAME = "warden-approvals-v1";
const APPROVAL_ID_PATTERN = /^req_[0-9a-f]{32}$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;
const CLIENT_TRANSITION_STATES: ReadonlySet<string> = new Set([
  "approved",
  "rejected",
  "cancelled",
]);

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
  constructor() {
    super("clock moved before a pending record's creation time");
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

function requireTransitionState(value: unknown): ApprovalTerminalState {
  if (typeof value !== "string" || !CLIENT_TRANSITION_STATES.has(value)) {
    throw new ApprovalStoreError(
      "client transition must be approved, rejected, or cancelled",
    );
  }
  return value as ApprovalTerminalState;
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
      options.databaseName ?? DEFAULT_DATABASE_NAME,
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
          const add = store.add(stored);
          add.onerror = () => {
            control.abort(new ApprovalStateConflictError(
              `record ${stored.id} already exists`,
            ));
          };
          add.onsuccess = () => control.succeed(snapshotApprovalRecord(stored));
          return;
        }

        try {
          const current = snapshotApprovalRecord(cursor.value);
          if (cursor.primaryKey !== current.id) {
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
              cursor.update(resolveApprovalRecord(current, "expired", now));
              totalCount++;
            } else {
              pendingCount++;
              totalCount++;
            }
          } else if (
            current.resolvedAt !== null &&
            now >= current.resolvedAt &&
            now - current.resolvedAt >= APPROVAL_TOMBSTONE_RETENTION_MS
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
          const current = snapshotApprovalRecord(request.result);
          if (current.id !== id) {
            throw new ApprovalRecordFormatError("stored key does not match record id");
          }
          if (current.state === "pending" && now < current.createdAt) {
            store.delete(id);
            control.failAfterCommit(new ApprovalClockError());
          } else if (current.state === "pending" && now >= current.expiresAt) {
            const expired = resolveApprovalRecord(current, "expired", now);
            store.put(expired);
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
    const expectedDigest = transition.expectedDigest?.slice();
    if (state === "approved") {
      if (
        !(expectedDigest instanceof Uint8Array) ||
        expectedDigest.length !== APPROVAL_DIGEST_BYTES
      ) {
        throw new ApprovalRecordFormatError(
          `expected digest must contain exactly ${APPROVAL_DIGEST_BYTES} bytes`,
        );
      }
    } else if (expectedDigest !== undefined) {
      expectedDigest.fill(0);
      throw new ApprovalRecordFormatError(
        "expected digest is only valid for an approved transition",
      );
    }

    try {
      return await this.writeTransaction((store, control) => {
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
            const current = snapshotApprovalRecord(request.result);
            if (current.id !== id) {
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
              store.put(resolveApprovalRecord(current, "expired", now));
              control.failAfterCommit(new ApprovalStateConflictError(
                `record ${id} has expired`,
              ));
            } else if (
              state === "approved" &&
              !approvalDigestsEqual(current.messageDigest, expectedDigest!)
            ) {
              store.put(resolveApprovalRecord(current, "invalidated", now));
              control.failAfterCommit(new ApprovalDigestMismatchError());
            } else {
              const resolved = resolveApprovalRecord(current, state, now);
              store.put(resolved);
              control.succeed(snapshotApprovalRecord(resolved));
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
    } finally {
      expectedDigest?.fill(0);
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
          const current = snapshotApprovalRecord(cursor.value);
          if (cursor.primaryKey !== current.id) {
            throw new ApprovalRecordFormatError("stored key does not match record id");
          }
          if (current.state === "pending") {
            if (now < current.createdAt) {
              cursor.delete();
              control.failAfterCommit(new ApprovalClockError());
            } else if (now >= current.expiresAt) {
              cursor.update(resolveApprovalRecord(current, "expired", now));
            } else {
              cursor.update(resolveApprovalRecord(current, "cancelled", now));
              invalidated++;
            }
          } else if (
            current.resolvedAt !== null &&
            now >= current.resolvedAt &&
            now - current.resolvedAt >= APPROVAL_TOMBSTONE_RETENTION_MS
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
