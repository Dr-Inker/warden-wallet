import { describe, expect, it } from "vitest";

import {
  KeyringFormatError,
  encodeKeyringRecordStorageValue,
  type KeyringRecord,
} from "@warden/core/keyring";
import {
  KEYRING_RECORD_STORAGE_KEY,
  KeyringRecordStoreConsistencyError,
  KeyringRecordStoreError,
  PersistentKeyringRecordStore,
  type KeyringRecordStorageArea,
} from "../src/background/keyring-record-store.js";

const fill = (length: number, value: number): Uint8Array =>
  new Uint8Array(length).fill(value);

function record(seed: number): string {
  const envelope = (
    nonceByte: number,
    ciphertextLength: number,
    ciphertextByte: number,
  ) => ({
    version: 1,
    nonce: fill(12, nonceByte),
    ciphertext: fill(ciphertextLength, ciphertextByte),
  });
  const value: KeyringRecord = {
    metadata: {
      version: 1,
      argon2id: {
        params: { memoryKiB: 64, timeCost: 1, parallelism: 1 },
        salt: fill(16, seed),
      },
      prf: null,
    },
    bundle: {
      version: 1,
      bundleId: fill(16, seed + 1),
      payload: envelope(seed + 2, 17, seed + 3),
      passwordWrap: envelope(seed + 4, 48, seed + 5),
      prfWrap: null,
    },
  };
  return encodeKeyringRecordStorageValue(value);
}

const FIRST_RECORD = record(0x11);
const SECOND_RECORD = record(0x21);

class MockLocalStorage implements KeyringRecordStorageArea {
  readonly operations: string[] = [];
  value: unknown = undefined;
  getHook: (() => Promise<Record<string, unknown>>) | undefined;
  setHook: ((items: Record<string, unknown>) => Promise<void>) | undefined;
  removeHook: (() => Promise<void>) | undefined;

  async get(key: string): Promise<Record<string, unknown>> {
    this.operations.push(`get:${key}`);
    if (this.getHook !== undefined) return this.getHook();
    return this.value === undefined ? {} : { [key]: this.value };
  }

  async set(items: Record<string, unknown>): Promise<void> {
    this.operations.push(`set:${Object.keys(items).join(",")}`);
    if (this.setHook !== undefined) return this.setHook(items);
    this.value = items[KEYRING_RECORD_STORAGE_KEY];
  }

  async remove(key: string): Promise<void> {
    this.operations.push(`remove:${key}`);
    if (this.removeHook !== undefined) return this.removeHook();
    this.value = undefined;
  }
}

function deferred(): { readonly promise: Promise<void>; release(): void } {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

describe("persistent encrypted keyring record store", () => {
  it("loads absence or one exact canonical encrypted record", async () => {
    const storage = new MockLocalStorage();
    const store = new PersistentKeyringRecordStore(storage);
    await expect(store.load()).resolves.toBeNull();

    storage.value = FIRST_RECORD;
    await expect(store.load()).resolves.toBe(FIRST_RECORD);
    expect(storage.operations).toEqual([
      `get:${KEYRING_RECORD_STORAGE_KEY}`,
      `get:${KEYRING_RECORD_STORAGE_KEY}`,
    ]);
  });

  it.each([
    ["object", { ciphertext: "not one canonical record" }],
    ["wrong prefix", "not-warden-keyring"],
    ["padded base64url", `${FIRST_RECORD}=`],
  ])("rejects a stored %s", async (_label, value) => {
    const storage = new MockLocalStorage();
    storage.value = value;
    const store = new PersistentKeyringRecordStore(storage);
    await expect(store.load()).rejects.toThrow(KeyringFormatError);
  });

  it("rejects malformed replacement before touching persistent storage", async () => {
    const storage = new MockLocalStorage();
    storage.value = FIRST_RECORD;
    const store = new PersistentKeyringRecordStore(storage);

    await expect(store.replace("forged-record")).rejects.toThrow(KeyringFormatError);
    expect(storage.value).toBe(FIRST_RECORD);
    expect(storage.operations).toEqual([]);
  });

  it("writes one property and verifies its exact readback", async () => {
    const storage = new MockLocalStorage();
    const store = new PersistentKeyringRecordStore(storage);
    await store.replace(FIRST_RECORD);

    expect(storage.value).toBe(FIRST_RECORD);
    expect(storage.operations).toEqual([
      `set:${KEYRING_RECORD_STORAGE_KEY}`,
      `get:${KEYRING_RECORD_STORAGE_KEY}`,
    ]);
  });

  it("serializes competing replacements through readback", async () => {
    const storage = new MockLocalStorage();
    const firstSet = deferred();
    let sets = 0;
    storage.setHook = async (items) => {
      sets++;
      if (sets === 1) await firstSet.promise;
      storage.value = items[KEYRING_RECORD_STORAGE_KEY];
    };
    const store = new PersistentKeyringRecordStore(storage);

    const first = store.replace(FIRST_RECORD);
    await Promise.resolve();
    const second = store.replace(SECOND_RECORD);
    await Promise.resolve();
    expect(sets).toBe(1);

    firstSet.release();
    await first;
    await second;
    expect(storage.value).toBe(SECOND_RECORD);
    expect(storage.operations).toEqual([
      `set:${KEYRING_RECORD_STORAGE_KEY}`,
      `get:${KEYRING_RECORD_STORAGE_KEY}`,
      `set:${KEYRING_RECORD_STORAGE_KEY}`,
      `get:${KEYRING_RECORD_STORAGE_KEY}`,
    ]);
  });

  it("preserves the prior record when Chrome rejects set", async () => {
    const storage = new MockLocalStorage();
    storage.value = FIRST_RECORD;
    storage.setHook = async () => {
      throw new Error("quota");
    };
    const store = new PersistentKeyringRecordStore(storage);

    await expect(store.replace(SECOND_RECORD)).rejects.toThrow(
      KeyringRecordStoreError,
    );
    expect(storage.value).toBe(FIRST_RECORD);
    expect(storage.operations).toEqual([`set:${KEYRING_RECORD_STORAGE_KEY}`]);
  });

  it("does not destructively clean up an ambiguous readback mismatch", async () => {
    const storage = new MockLocalStorage();
    storage.value = FIRST_RECORD;
    storage.setHook = async () => {
      // Model an acknowledged write whose subsequent read still exposes old data.
    };
    const store = new PersistentKeyringRecordStore(storage);

    await expect(store.replace(SECOND_RECORD)).rejects.toThrow(
      KeyringRecordStoreConsistencyError,
    );
    expect(storage.value).toBe(FIRST_RECORD);
    expect(storage.operations).toEqual([
      `set:${KEYRING_RECORD_STORAGE_KEY}`,
      `get:${KEYRING_RECORD_STORAGE_KEY}`,
    ]);
  });

  it("clears one key and verifies absence", async () => {
    const storage = new MockLocalStorage();
    storage.value = FIRST_RECORD;
    const store = new PersistentKeyringRecordStore(storage);
    await store.clear();

    expect(storage.value).toBeUndefined();
    expect(storage.operations).toEqual([
      `remove:${KEYRING_RECORD_STORAGE_KEY}`,
      `get:${KEYRING_RECORD_STORAGE_KEY}`,
    ]);
  });

  it("rejects a clear whose readback still contains the record", async () => {
    const storage = new MockLocalStorage();
    storage.value = FIRST_RECORD;
    storage.removeHook = async () => {
      // Model an acknowledged remove whose subsequent read still exposes data.
    };
    const store = new PersistentKeyringRecordStore(storage);

    await expect(store.clear()).rejects.toThrow(
      KeyringRecordStoreConsistencyError,
    );
    expect(storage.value).toBe(FIRST_RECORD);
    expect(storage.operations).toEqual([
      `remove:${KEYRING_RECORD_STORAGE_KEY}`,
      `get:${KEYRING_RECORD_STORAGE_KEY}`,
    ]);
  });

  it("normalizes a rejected read to a storage error with its cause", async () => {
    const storage = new MockLocalStorage();
    const cause = new Error("storage unavailable");
    storage.getHook = async () => {
      throw cause;
    };
    const store = new PersistentKeyringRecordStore(storage);

    const failure = await store.load().catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(KeyringRecordStoreError);
    expect((failure as Error & { cause?: unknown }).cause).toBe(cause);
    expect(storage.operations).toEqual([`get:${KEYRING_RECORD_STORAGE_KEY}`]);
  });

  it("rejects storage adapters without the full get/set/remove contract", () => {
    expect(
      () =>
        new PersistentKeyringRecordStore({
          get: async () => ({}),
        } as unknown as KeyringRecordStorageArea),
    ).toThrow("storage adapter must provide set()");
  });
});
