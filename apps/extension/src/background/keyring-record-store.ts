import { decodeKeyringRecordStorageValue } from "@warden/core/keyring";

export const KEYRING_RECORD_STORAGE_KEY = "warden.keyring-record.v1";

export interface KeyringRecordStorageArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

export class KeyringRecordStoreError extends Error {
  constructor(operation: string, cause: unknown) {
    super(`extension keyring record: chrome.storage.local ${operation} failed`, {
      cause,
    });
    this.name = "KeyringRecordStoreError";
  }
}

export class KeyringRecordStoreConsistencyError extends Error {
  constructor(message: string) {
    super(`extension keyring record: ${message}`);
    this.name = "KeyringRecordStoreConsistencyError";
  }
}

function requireStorageResult(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new KeyringRecordStoreConsistencyError(
      "chrome.storage.local get() returned a malformed result",
    );
  }
  return value as Record<string, unknown>;
}

function requireCanonicalRecord(value: unknown): string {
  // The core decoder rejects non-strings, wrong prefixes, non-canonical
  // base64url, unknown versions/flags, hostile KDF costs, malformed lengths,
  // trailing bytes, and malformed encrypted bundle components.
  decodeKeyringRecordStorageValue(value);
  return value as string;
}

/**
 * Own the one persistent encrypted keyring property used by the background.
 *
 * Chrome documents Promise rejection for failed storage operations, but not a
 * transactional/CAS primitive. This owner therefore serializes its own calls,
 * validates before writing, and verifies exact readback. It never removes the
 * prior record as write cleanup: after an acknowledged-but-mismatched readback,
 * destructive cleanup could erase the only valid copy while storage state is
 * ambiguous.
 */
export class PersistentKeyringRecordStore {
  private readonly storage: KeyringRecordStorageArea;
  private storageTail: Promise<void> = Promise.resolve();

  constructor(storage: KeyringRecordStorageArea) {
    if (typeof storage !== "object" || storage === null) {
      throw new TypeError(
        "extension keyring record: storage adapter must be an object",
      );
    }
    for (const method of ["get", "set", "remove"] as const) {
      if (typeof storage[method] !== "function") {
        throw new TypeError(
          `extension keyring record: storage adapter must provide ${method}()`,
        );
      }
    }
    this.storage = storage;
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.storageTail.then(operation, operation);
    this.storageTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async callStorage<T>(
    operation: string,
    call: () => Promise<T>,
  ): Promise<T> {
    try {
      return await call();
    } catch (error) {
      if (
        error instanceof KeyringRecordStoreError ||
        error instanceof KeyringRecordStoreConsistencyError
      ) {
        throw error;
      }
      throw new KeyringRecordStoreError(operation, error);
    }
  }

  private async loadDirect(operation: string): Promise<string | null> {
    const raw = requireStorageResult(
      await this.callStorage(operation, () =>
        this.storage.get(KEYRING_RECORD_STORAGE_KEY),
      ),
    );
    let fields: string[];
    try {
      fields = Object.keys(raw);
    } catch {
      throw new KeyringRecordStoreConsistencyError(
        "chrome.storage.local get() result cannot be inspected",
      );
    }
    if (fields.length === 0) return null;
    if (
      fields.length !== 1 ||
      fields[0] !== KEYRING_RECORD_STORAGE_KEY ||
      !Object.hasOwn(raw, KEYRING_RECORD_STORAGE_KEY)
    ) {
      throw new KeyringRecordStoreConsistencyError(
        "chrome.storage.local get() returned unexpected properties",
      );
    }
    return requireCanonicalRecord(raw[KEYRING_RECORD_STORAGE_KEY]);
  }

  load(): Promise<string | null> {
    return this.enqueue(() => this.loadDirect("get"));
  }

  async replace(value: unknown): Promise<void> {
    // Validate outside the queue and before any storage call. Strings are
    // immutable, so no async caller-mutation race remains after this point.
    const canonical = requireCanonicalRecord(value);
    await this.enqueue(async () => {
      await this.callStorage("set", () =>
        this.storage.set(
          Object.freeze({ [KEYRING_RECORD_STORAGE_KEY]: canonical }),
        ),
      );
      const readback = await this.loadDirect("readback");
      if (readback !== canonical) {
        throw new KeyringRecordStoreConsistencyError(
          "storage readback does not match the requested record",
        );
      }
    });
  }

  async clear(): Promise<void> {
    await this.enqueue(async () => {
      await this.callStorage("remove", () =>
        this.storage.remove(KEYRING_RECORD_STORAGE_KEY),
      );
      if ((await this.loadDirect("clear readback")) !== null) {
        throw new KeyringRecordStoreConsistencyError(
          "storage readback still contains the cleared record",
        );
      }
    });
  }
}
