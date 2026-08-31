//! Still-unreachable C14 IndexedDB provider-operation journal.
//!
//! This database is deliberately separate from the approval database. Atomicity
//! comes from ordering, not a cross-database transaction: the unique operation
//! claim commits first; an interrupted claim is not retried while its bounded
//! journal row is retained. The approval id and digest are attached only after
//! durable approval creation. This sacrifices liveness in the crash gap while
//! preserving at-most-once preparation/signing within that replay horizon.

import {
  ProviderOperationStateError,
  bindProviderOperation,
  createPreparingProviderOperation,
  failProviderOperation,
  providerOperationIdentitiesEqual,
  snapshotProviderOperation,
  snapshotProviderOperationIdentity,
  type ProviderOperationClaim,
  type ProviderOperationFailureCode,
  type ProviderOperationIdentity,
  type ProviderOperationRecord,
  type ProviderOperationRepository,
} from "./provider-operation.js";

export const PROVIDER_OPERATION_DATABASE_VERSION = 1;
export const PROVIDER_OPERATION_DATABASE_NAME = "warden-provider-operations-v1";
export const PROVIDER_OPERATION_OBJECT_STORE_NAME = "providerOperations";
export const MAX_PREPARING_PROVIDER_OPERATIONS = 32;
export const MAX_TOTAL_PROVIDER_OPERATIONS = 128;
export const PROVIDER_OPERATION_RETENTION_MS = 10 * 60 * 1_000;

const PROVIDER_OPERATION_KEY_PATTERN = /^op_[0-9a-f]{64}$/;

export class ProviderOperationStoreError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`provider operation store: ${message}`, options);
    this.name = "ProviderOperationStoreError";
  }
}

export class ProviderOperationNotFoundError extends ProviderOperationStoreError {
  constructor(key: string) {
    super(`operation ${key} does not exist`);
    this.name = "ProviderOperationNotFoundError";
  }
}

export class ProviderOperationConflictError extends ProviderOperationStoreError {
  constructor(message: string) {
    super(message);
    this.name = "ProviderOperationConflictError";
  }
}

export class ProviderOperationCapacityError extends ProviderOperationStoreError {
  constructor(message: string) {
    super(message);
    this.name = "ProviderOperationCapacityError";
  }
}

export class ProviderOperationClockError extends ProviderOperationStoreError {
  constructor() {
    super("clock moved before durable operation time");
    this.name = "ProviderOperationClockError";
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
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new ProviderOperationStoreError("databaseName is malformed");
  }
  return value;
}

function requireIndexedDb(value: unknown): IDBFactory {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as Partial<IDBFactory>).open !== "function"
  ) {
    throw new ProviderOperationStoreError("IndexedDB is unavailable");
  }
  return value as IDBFactory;
}

function requireNow(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new ProviderOperationStoreError(
      "now must be a non-negative safe integer",
    );
  }
  return value as number;
}

function requireKey(value: unknown): string {
  if (typeof value !== "string" || !PROVIDER_OPERATION_KEY_PATTERN.test(value)) {
    throw new ProviderOperationStoreError("operation key is malformed");
  }
  return value;
}

function requireDigest(value: unknown, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new ProviderOperationStateError(
      `${name} must contain exactly 32 bytes`,
    );
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

function identityInput(value: ProviderOperationIdentity): ProviderOperationIdentity {
  return {
    key: value.key,
    extensionId: value.extensionId,
    origin: value.origin,
    tabId: value.tabId,
    frameId: value.frameId,
    documentId: value.documentId,
    correlationId: value.correlationId,
    method: value.method,
    requestDigest: value.requestDigest,
  };
}

function clearRecord(value: ProviderOperationRecord | null | undefined): void {
  value?.requestDigest.fill(0);
  value?.approvalDigest?.fill(0);
}

function retentionTimestamp(record: ProviderOperationRecord): number | null {
  if (record.state === "preparing") return null;
  if (record.state === "bound") return record.expiresAt;
  return record.resolvedAt;
}

function transactionFailure(
  transaction: IDBTransaction,
  operationError?: Error,
): Error {
  if (operationError !== undefined) return operationError;
  return new ProviderOperationStoreError("IndexedDB transaction aborted", {
    cause: transaction.error ?? undefined,
  });
}

function openProviderOperationDatabase(
  factory: IDBFactory,
  databaseName: string,
): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let upgradeError: Error | undefined;
    const request = factory.open(
      databaseName,
      PROVIDER_OPERATION_DATABASE_VERSION,
    );
    const rejectOnce = (error: Error): void => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    request.onblocked = () => {
      rejectOnce(new ProviderOperationStoreError("IndexedDB schema upgrade is blocked"));
    };
    request.onerror = () => {
      rejectOnce(upgradeError ?? new ProviderOperationStoreError(
        "IndexedDB open failed",
        { cause: request.error ?? undefined },
      ));
    };
    request.onupgradeneeded = (event) => {
      try {
        if (event.oldVersion !== 0) {
          throw new ProviderOperationStoreError(
            `unsupported IndexedDB migration from version ${event.oldVersion}`,
          );
        }
        request.result.createObjectStore(
          PROVIDER_OPERATION_OBJECT_STORE_NAME,
          { keyPath: "key" },
        );
      } catch (error) {
        upgradeError = error instanceof Error
          ? error
          : new ProviderOperationStoreError("IndexedDB schema creation failed");
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
          !database.objectStoreNames.contains(PROVIDER_OPERATION_OBJECT_STORE_NAME)
        ) {
          throw new ProviderOperationStoreError("IndexedDB schema is unexpected");
        }
        const transaction = database.transaction(
          PROVIDER_OPERATION_OBJECT_STORE_NAME,
          "readonly",
        );
        const store = transaction.objectStore(PROVIDER_OPERATION_OBJECT_STORE_NAME);
        if (store.keyPath !== "key" || store.autoIncrement) {
          throw new ProviderOperationStoreError(
            "provider operation object store schema is unexpected",
          );
        }
        database.onversionchange = () => database.close();
        settled = true;
        resolve(database);
      } catch (error) {
        database.close();
        rejectOnce(error instanceof Error
          ? error
          : new ProviderOperationStoreError("IndexedDB schema validation failed"));
      }
    };
  });
}

/** Strict IndexedDB CAS owner for provider operation claims and bindings. */
export class IndexedDbProviderOperationRepository
implements ProviderOperationRepository {
  readonly #databasePromise: Promise<IDBDatabase>;
  #closed = false;

  constructor(options: RepositoryOptions = {}) {
    const databaseName = requireDatabaseName(
      options.databaseName ?? PROVIDER_OPERATION_DATABASE_NAME,
    );
    const factory = requireIndexedDb(options.indexedDb ?? globalThis.indexedDB);
    this.#databasePromise = openProviderOperationDatabase(factory, databaseName);
  }

  async #database(): Promise<IDBDatabase> {
    if (this.#closed) throw new ProviderOperationStoreError("repository is closed");
    const database = await this.#databasePromise;
    if (this.#closed) throw new ProviderOperationStoreError("repository is closed");
    return database;
  }

  async #writeTransaction<T>(
    operation: (
      store: IDBObjectStore,
      control: TransactionControl<T>,
    ) => void,
  ): Promise<T> {
    const database = await this.#database();
    return new Promise<T>((resolve, reject) => {
      let transaction: IDBTransaction;
      try {
        transaction = database.transaction(
          PROVIDER_OPERATION_OBJECT_STORE_NAME,
          "readwrite",
          { durability: "strict" },
        );
      } catch (error) {
        reject(new ProviderOperationStoreError(
          "could not start IndexedDB transaction",
          { cause: error },
        ));
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
            // It may already be aborting because a request failed.
          }
        },
      };
      transaction.oncomplete = () => {
        if (postCommitError !== undefined) reject(postCommitError);
        else if (!hasResult) {
          reject(new ProviderOperationStoreError(
            "transaction completed without a result",
          ));
        } else resolve(result as T);
      };
      transaction.onabort = () => {
        reject(transactionFailure(transaction, operationError));
      };
      transaction.onerror = () => {};
      try {
        operation(
          transaction.objectStore(PROVIDER_OPERATION_OBJECT_STORE_NAME),
          control,
        );
      } catch (error) {
        control.abort(error instanceof Error
          ? error
          : new ProviderOperationStoreError("transaction operation failed"));
      }
    });
  }

  async claim(input: {
    readonly identity: ProviderOperationIdentity;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly now: number;
  }): Promise<ProviderOperationClaim> {
    if (typeof input !== "object" || input === null) {
      throw new ProviderOperationStoreError("claim input must be an object");
    }
    const identity = snapshotProviderOperationIdentity(identityInput(input.identity));
    const candidate = createPreparingProviderOperation({
      identity,
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
      now: input.now,
    });
    const now = requireNow(input.now);
    try {
      return await this.#writeTransaction((store, control) => {
        let preparingCount = 0;
        let totalCount = 0;
        let existing: ProviderOperationRecord | undefined;
        let failed = false;
        const cursorRequest = store.openCursor();
        cursorRequest.onerror = () => {
          control.abort(new ProviderOperationStoreError(
            "provider operation cursor failed",
            { cause: cursorRequest.error ?? undefined },
          ));
        };
        cursorRequest.onsuccess = () => {
          const cursor = cursorRequest.result;
          if (cursor === null) {
            if (failed) return;
            if (existing !== undefined) {
              control.succeed(Object.freeze({
                created: false,
                record: snapshotProviderOperation(existing),
              }));
              clearRecord(existing);
              existing = undefined;
              return;
            }
            if (preparingCount >= MAX_PREPARING_PROVIDER_OPERATIONS) {
              control.failAfterCommit(new ProviderOperationCapacityError(
                `at most ${MAX_PREPARING_PROVIDER_OPERATIONS} operations may be preparing`,
              ));
              return;
            }
            if (totalCount >= MAX_TOTAL_PROVIDER_OPERATIONS) {
              control.failAfterCommit(new ProviderOperationCapacityError(
                `at most ${MAX_TOTAL_PROVIDER_OPERATIONS} operations may be retained`,
              ));
              return;
            }
            const add = store.add(candidate);
            add.onerror = () => {
              control.abort(new ProviderOperationConflictError(
                `operation ${candidate.key} already exists`,
              ));
            };
            add.onsuccess = () => control.succeed(Object.freeze({
              created: true,
              record: snapshotProviderOperation(candidate),
            }));
            return;
          }

          let current: ProviderOperationRecord | undefined;
          try {
            current = snapshotProviderOperation(cursor.value);
            if (cursor.primaryKey !== current.key) {
              throw new ProviderOperationStateError(
                "stored primary key does not match operation key",
              );
            }
            if (current.key === candidate.key) {
              if (!providerOperationIdentitiesEqual(current, identity)) {
                failed = true;
                control.abort(new ProviderOperationConflictError(
                  "operation key collision has different browser identity",
                ));
                return;
              }
              if (now < current.createdAt) {
                failed = true;
                control.abort(new ProviderOperationClockError());
                return;
              }
              if (current.state === "preparing" && now >= current.expiresAt) {
                const expired = failProviderOperation(current, "expired", now);
                cursor.update(expired);
                existing = snapshotProviderOperation(expired);
                clearRecord(expired);
              } else {
                existing = snapshotProviderOperation(current);
              }
              totalCount++;
              if (current.state === "preparing" && now < current.expiresAt) {
                preparingCount++;
              }
              cursor.continue();
              return;
            }

            if (current.state === "preparing") {
              if (now < current.createdAt) {
                failed = true;
                control.abort(new ProviderOperationClockError());
                return;
              }
              if (now >= current.expiresAt) {
                const expired = failProviderOperation(current, "expired", now);
                cursor.update(expired);
                clearRecord(expired);
                totalCount++;
              } else {
                preparingCount++;
                totalCount++;
              }
            } else {
              const retainedAt = retentionTimestamp(current)!;
              if (current.state === "failed" && now < retainedAt) {
                failed = true;
                control.abort(new ProviderOperationClockError());
                return;
              }
              if (
                now >= retainedAt &&
                now - retainedAt >= PROVIDER_OPERATION_RETENTION_MS
              ) {
                cursor.delete();
              } else {
                totalCount++;
              }
            }
            cursor.continue();
          } catch (error) {
            if (failed) return;
            failed = true;
            control.abort(error instanceof Error
              ? error
              : new ProviderOperationStateError("stored operation is malformed"));
          } finally {
            clearRecord(current);
          }
        };
      });
    } finally {
      identity.requestDigest.fill(0);
      clearRecord(candidate);
    }
  }

  async read(input: {
    readonly key: string;
    readonly now: number;
  }): Promise<ProviderOperationRecord | null> {
    if (typeof input !== "object" || input === null) {
      throw new ProviderOperationStoreError("read input must be an object");
    }
    const key = requireKey(input.key);
    const now = requireNow(input.now);
    return this.#writeTransaction((store, control) => {
      const request = store.get(key);
      request.onerror = () => control.abort(new ProviderOperationStoreError(
        "provider operation read failed",
        { cause: request.error ?? undefined },
      ));
      request.onsuccess = () => {
        if (request.result === undefined) {
          control.succeed(null);
          return;
        }
        let current: ProviderOperationRecord | undefined;
        try {
          current = snapshotProviderOperation(request.result);
          if (current.key !== key) {
            throw new ProviderOperationStateError(
              "stored primary key does not match operation key",
            );
          }
          if (now < current.createdAt) {
            control.abort(new ProviderOperationClockError());
          } else if (current.state === "preparing" && now >= current.expiresAt) {
            const expired = failProviderOperation(current, "expired", now);
            store.put(expired);
            control.succeed(snapshotProviderOperation(expired));
            clearRecord(expired);
          } else {
            control.succeed(snapshotProviderOperation(current));
          }
        } catch (error) {
          control.abort(error instanceof Error
            ? error
            : new ProviderOperationStateError("stored operation is malformed"));
        } finally {
          clearRecord(current);
        }
      };
    });
  }

  async bind(input: {
    readonly key: string;
    readonly expectedRequestDigest: Uint8Array;
    readonly approvalId: string;
    readonly approvalDigest: Uint8Array;
    readonly now: number;
  }): Promise<ProviderOperationRecord> {
    if (typeof input !== "object" || input === null) {
      throw new ProviderOperationStoreError("bind input must be an object");
    }
    const key = requireKey(input.key);
    const expectedRequestDigest = requireDigest(
      input.expectedRequestDigest,
      "expectedRequestDigest",
    );
    const approvalDigest = requireDigest(input.approvalDigest, "approvalDigest");
    const now = requireNow(input.now);
    try {
      return await this.#writeTransaction((store, control) => {
        const request = store.get(key);
        request.onerror = () => control.abort(new ProviderOperationStoreError(
          "provider operation binding read failed",
          { cause: request.error ?? undefined },
        ));
        request.onsuccess = () => {
          if (request.result === undefined) {
            control.failAfterCommit(new ProviderOperationNotFoundError(key));
            return;
          }
          let current: ProviderOperationRecord | undefined;
          let bound: ProviderOperationRecord | undefined;
          try {
            current = snapshotProviderOperation(request.result);
            if (!bytesEqual(current.requestDigest, expectedRequestDigest)) {
              throw new ProviderOperationConflictError(
                "binding digest differs from durable operation",
              );
            }
            bound = bindProviderOperation(current, {
              key,
              expectedRequestDigest,
              approvalId: input.approvalId,
              approvalDigest,
              now,
            });
            store.put(bound);
            control.succeed(snapshotProviderOperation(bound));
          } catch (error) {
            control.abort(error instanceof Error
              ? error
              : new ProviderOperationStateError("operation binding failed"));
          } finally {
            clearRecord(current);
            clearRecord(bound);
          }
        };
      });
    } finally {
      expectedRequestDigest.fill(0);
      approvalDigest.fill(0);
    }
  }

  async fail(input: {
    readonly key: string;
    readonly expectedRequestDigest: Uint8Array;
    readonly failureCode: ProviderOperationFailureCode;
    readonly now: number;
  }): Promise<ProviderOperationRecord> {
    if (typeof input !== "object" || input === null) {
      throw new ProviderOperationStoreError("failure input must be an object");
    }
    const key = requireKey(input.key);
    const expectedRequestDigest = requireDigest(
      input.expectedRequestDigest,
      "expectedRequestDigest",
    );
    const now = requireNow(input.now);
    try {
      return await this.#writeTransaction((store, control) => {
        const request = store.get(key);
        request.onerror = () => control.abort(new ProviderOperationStoreError(
          "provider operation failure read failed",
          { cause: request.error ?? undefined },
        ));
        request.onsuccess = () => {
          if (request.result === undefined) {
            control.failAfterCommit(new ProviderOperationNotFoundError(key));
            return;
          }
          let current: ProviderOperationRecord | undefined;
          let failed: ProviderOperationRecord | undefined;
          try {
            current = snapshotProviderOperation(request.result);
            if (!bytesEqual(current.requestDigest, expectedRequestDigest)) {
              throw new ProviderOperationConflictError(
                "failure digest differs from durable operation",
              );
            }
            failed = failProviderOperation(current, input.failureCode, now);
            store.put(failed);
            control.succeed(snapshotProviderOperation(failed));
          } catch (error) {
            control.abort(error instanceof Error
              ? error
              : new ProviderOperationStateError("operation failure transition failed"));
          } finally {
            clearRecord(current);
            clearRecord(failed);
          }
        };
      });
    } finally {
      expectedRequestDigest.fill(0);
    }
  }

  async invalidatePreparing(nowValue: number): Promise<number> {
    const now = requireNow(nowValue);
    return this.#writeTransaction((store, control) => {
      let invalidated = 0;
      const request = store.openCursor();
      request.onerror = () => control.abort(new ProviderOperationStoreError(
        "provider operation invalidation cursor failed",
        { cause: request.error ?? undefined },
      ));
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor === null) {
          control.succeed(invalidated);
          return;
        }
        let current: ProviderOperationRecord | undefined;
        let failed: ProviderOperationRecord | undefined;
        try {
          current = snapshotProviderOperation(cursor.value);
          if (cursor.primaryKey !== current.key) {
            throw new ProviderOperationStateError(
              "stored primary key does not match operation key",
            );
          }
          if (now < current.createdAt) {
            control.abort(new ProviderOperationClockError());
            return;
          }
          if (current.state === "preparing") {
            failed = failProviderOperation(
              current,
              now >= current.expiresAt ? "expired" : "worker-restarted",
              now,
            );
            cursor.update(failed);
            invalidated++;
          }
          cursor.continue();
        } catch (error) {
          control.abort(error instanceof Error
            ? error
            : new ProviderOperationStateError("stored operation is malformed"));
        } finally {
          clearRecord(current);
          clearRecord(failed);
        }
      };
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    void this.#databasePromise.then(
      (database) => database.close(),
      () => undefined,
    );
  }
}
