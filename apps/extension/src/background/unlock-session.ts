import {
  KEYRING_BUNDLE_ID_BYTES,
  PUBKEY_BYTES,
  UNWRAP_KEY_BYTES,
  KeyringExpiredError,
  KeyringFormatError,
  KeyringLockedError,
  assertUnlockCheck,
  assertValidUnlockDeadlines,
  registerUnlockAbortCleanup,
  snapshotUnlockCheck,
  touchUnlockSession,
  zeroizeUnwrapKey,
  type KeyringUnwrapKey,
  type UnlockCheck,
  type UnlockDeadlines,
  type UnlockPolicy,
} from "@warden/core/keyring";

export const UNLOCK_SESSION_STORAGE_KEY = "warden.unlock-session.v2";
const LEGACY_UNLOCK_SESSION_STORAGE_KEY_V1 = "warden.unlock-session.v1";

export interface UnlockSessionStorageArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
}

export interface ActivateUnlockSessionParams {
  readonly account: Uint8Array;
  /** Public identifier of the exact encrypted bundle this key can unwrap. */
  readonly bundleId: Uint8Array;
  readonly unwrapKey: KeyringUnwrapKey;
  readonly deadlines: UnlockDeadlines;
}

export interface UnlockSessionLease {
  readonly account: Uint8Array;
  readonly unwrapKey: KeyringUnwrapKey;
  readonly unlock: UnlockCheck;
}

export class UnlockSessionFormatError extends Error {
  constructor(message: string) {
    super(`extension unlock session: ${message}`);
    this.name = "UnlockSessionFormatError";
  }
}

export class UnlockSessionStorageError extends Error {
  constructor(operation: string, cause: unknown) {
    super(`extension unlock session: chrome.storage.session ${operation} failed`, { cause });
    this.name = "UnlockSessionStorageError";
  }
}

interface StoredUnlockSessionV2 {
  readonly version: 2;
  readonly account: number[];
  readonly bundleId: number[];
  readonly kdf: KeyringUnwrapKey["kdf"];
  readonly unwrapKey: number[];
  readonly idleExpiresAt: number;
  readonly hardExpiresAt: number;
}

interface ActiveUnlockSession {
  readonly account: Uint8Array;
  readonly bundleId: Uint8Array;
  readonly unwrapKey: KeyringUnwrapKey;
  deadlines: UnlockDeadlines;
  readonly controller: AbortController;
  committed: boolean;
}

const STORED_FIELDS = [
  "account",
  "bundleId",
  "hardExpiresAt",
  "idleExpiresAt",
  "kdf",
  "unwrapKey",
  "version",
] as const;

function assertObject(value: unknown): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new UnlockSessionFormatError("stored value must be an object");
  }
}

function parseByteArray(value: unknown, length: number, name: string): Uint8Array {
  if (!Array.isArray(value) || value.length !== length) {
    throw new UnlockSessionFormatError(`${name} must contain exactly ${length} bytes`);
  }
  const output = new Uint8Array(length);
  for (let index = 0; index < value.length; index++) {
    const byte = value[index];
    if (!Number.isInteger(byte) || (byte as number) < 0 || (byte as number) > 255) {
      output.fill(0);
      throw new UnlockSessionFormatError(`${name}[${index}] is not a byte`);
    }
    output[index] = byte as number;
  }
  return output;
}

function parseStoredSession(value: unknown): {
  account: Uint8Array;
  bundleId: Uint8Array;
  unwrapKey: KeyringUnwrapKey;
  deadlines: UnlockDeadlines;
} {
  assertObject(value);
  const fields = Object.keys(value).sort();
  if (
    fields.length !== STORED_FIELDS.length ||
    fields.some((field, index) => field !== STORED_FIELDS[index])
  ) {
    throw new UnlockSessionFormatError("stored value has missing or unknown fields");
  }
  if (value.version !== 2) throw new UnlockSessionFormatError("stored version must be 2");
  if (value.kdf !== "argon2id-password" && value.kdf !== "webauthn-prf-hkdf") {
    throw new UnlockSessionFormatError("stored unwrap-key KDF is unknown");
  }
  const account = parseByteArray(value.account, PUBKEY_BYTES, "account");
  let bundleId: Uint8Array | undefined;
  let unwrapKeyBytes: Uint8Array | undefined;
  try {
    bundleId = parseByteArray(value.bundleId, KEYRING_BUNDLE_ID_BYTES, "bundleId");
    unwrapKeyBytes = parseByteArray(value.unwrapKey, UNWRAP_KEY_BYTES, "unwrapKey");
    const deadlines = {
      idleExpiresAt: value.idleExpiresAt as number,
      hardExpiresAt: value.hardExpiresAt as number,
    };
    try {
      assertValidUnlockDeadlines(deadlines);
    } catch (error) {
      throw new UnlockSessionFormatError(
        error instanceof Error ? error.message : "stored deadlines are invalid",
      );
    }
    return {
      account,
      bundleId,
      unwrapKey: { kdf: value.kdf, bytes: unwrapKeyBytes },
      deadlines,
    };
  } catch (error) {
    account.fill(0);
    bundleId?.fill(0);
    unwrapKeyBytes?.fill(0);
    throw error;
  }
}

function scrubStoredArrays(value: unknown): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return;
  const record = value as Record<string, unknown>;
  if (Array.isArray(record.account)) record.account.fill(0);
  if (Array.isArray(record.bundleId)) record.bundleId.fill(0);
  if (Array.isArray(record.unwrapKey)) record.unwrapKey.fill(0);
}

function encodeStoredSession(active: ActiveUnlockSession): StoredUnlockSessionV2 {
  return {
    version: 2,
    account: Array.from(active.account),
    bundleId: Array.from(active.bundleId),
    kdf: active.unwrapKey.kdf,
    unwrapKey: Array.from(active.unwrapKey.bytes),
    idleExpiresAt: active.deadlines.idleExpiresAt,
    hardExpiresAt: active.deadlines.hardExpiresAt,
  };
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function validateActivation(params: ActivateUnlockSessionParams): {
  account: Uint8Array;
  bundleId: Uint8Array;
  unwrapKey: KeyringUnwrapKey;
  deadlines: UnlockDeadlines;
} {
  if (typeof params !== "object" || params === null) {
    throw new UnlockSessionFormatError("activation parameters must be an object");
  }
  if (!(params.account instanceof Uint8Array) || params.account.length !== PUBKEY_BYTES) {
    throw new UnlockSessionFormatError(`account must be exactly ${PUBKEY_BYTES} bytes`);
  }
  if (
    !(params.bundleId instanceof Uint8Array) ||
    params.bundleId.length !== KEYRING_BUNDLE_ID_BYTES
  ) {
    throw new UnlockSessionFormatError(
      `bundleId must be exactly ${KEYRING_BUNDLE_ID_BYTES} bytes`,
    );
  }
  if (typeof params.unwrapKey !== "object" || params.unwrapKey === null) {
    throw new UnlockSessionFormatError("unwrap key must be an object");
  }
  if (
    params.unwrapKey.kdf !== "argon2id-password" &&
    params.unwrapKey.kdf !== "webauthn-prf-hkdf"
  ) {
    throw new UnlockSessionFormatError("unwrap-key KDF is unknown");
  }
  if (
    !(params.unwrapKey.bytes instanceof Uint8Array) ||
    params.unwrapKey.bytes.length !== UNWRAP_KEY_BYTES
  ) {
    throw new UnlockSessionFormatError(`unwrap key must be exactly ${UNWRAP_KEY_BYTES} bytes`);
  }
  try {
    assertValidUnlockDeadlines(params.deadlines);
  } catch (error) {
    throw new UnlockSessionFormatError(
      error instanceof Error ? error.message : "unlock deadlines are invalid",
    );
  }
  return {
    account: params.account.slice(),
    bundleId: params.bundleId.slice(),
    unwrapKey: { kdf: params.unwrapKey.kdf, bytes: params.unwrapKey.bytes.slice() },
    deadlines: {
      idleExpiresAt: params.deadlines.idleExpiresAt,
      hardExpiresAt: params.deadlines.hardExpiresAt,
    },
  };
}

export class UnlockSessionOwner {
  private readonly storage: UnlockSessionStorageArea;
  private readonly readNow: () => number;
  private active: ActiveUnlockSession | undefined;
  private transition = 0;
  private storageTail: Promise<void> = Promise.resolve();

  constructor(
    storage: UnlockSessionStorageArea,
    options: { readonly readNow?: () => number } = {},
  ) {
    if (typeof storage !== "object" || storage === null) {
      throw new UnlockSessionFormatError("storage adapter must be an object");
    }
    for (const method of ["get", "set", "remove"] as const) {
      if (typeof storage[method] !== "function") {
        throw new UnlockSessionFormatError(`storage adapter must provide ${method}()`);
      }
    }
    if (options.readNow !== undefined && typeof options.readNow !== "function") {
      throw new UnlockSessionFormatError("readNow must be a function");
    }
    this.storage = storage;
    this.readNow = options.readNow ?? Date.now;
  }

  private enqueueStorage<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.storageTail.then(operation, operation);
    this.storageTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private storageOperation<T>(name: string, operation: () => Promise<T>): Promise<T> {
    return this.enqueueStorage(async () => {
      try {
        return await operation();
      } catch (error) {
        if (error instanceof UnlockSessionStorageError) throw error;
        throw new UnlockSessionStorageError(name, error);
      }
    });
  }

  private abortActive(active: ActiveUnlockSession | undefined = this.active): void {
    if (active === undefined) return;
    active.controller.abort();
    active.account.fill(0);
    active.bundleId.fill(0);
    zeroizeUnwrapKey(active.unwrapKey);
    if (this.active === active) this.active = undefined;
  }

  private removeStored(): Promise<void> {
    return this.storageOperation("remove", () =>
      this.storage.remove([
        UNLOCK_SESSION_STORAGE_KEY,
        LEGACY_UNLOCK_SESSION_STORAGE_KEY_V1,
      ]),
    );
  }

  private async verifyStored(active: ActiveUnlockSession): Promise<void> {
    const values = await this.storage.get(UNLOCK_SESSION_STORAGE_KEY);
    const raw = values[UNLOCK_SESSION_STORAGE_KEY];
    if (active.controller.signal.aborted) {
      scrubStoredArrays(raw);
      return;
    }
    let parsed: ReturnType<typeof parseStoredSession> | undefined;
    try {
      if (raw === undefined) {
        throw new UnlockSessionFormatError("storage readback is missing");
      }
      parsed = parseStoredSession(raw);
      if (
        !equalBytes(parsed.account, active.account) ||
        !equalBytes(parsed.bundleId, active.bundleId) ||
        parsed.unwrapKey.kdf !== active.unwrapKey.kdf ||
        !equalBytes(parsed.unwrapKey.bytes, active.unwrapKey.bytes) ||
        parsed.deadlines.idleExpiresAt !== active.deadlines.idleExpiresAt ||
        parsed.deadlines.hardExpiresAt !== active.deadlines.hardExpiresAt
      ) {
        throw new UnlockSessionFormatError("storage readback does not match the requested session");
      }
    } finally {
      parsed?.account.fill(0);
      parsed?.bundleId.fill(0);
      if (parsed !== undefined) zeroizeUnwrapKey(parsed.unwrapKey);
      scrubStoredArrays(raw);
    }
  }

  private async writeAndVerify(
    active: ActiveUnlockSession,
    stored: StoredUnlockSessionV2,
    replace: boolean,
  ): Promise<void> {
    try {
      if (replace) {
        await this.storage.remove([
          UNLOCK_SESSION_STORAGE_KEY,
          LEGACY_UNLOCK_SESSION_STORAGE_KEY_V1,
        ]);
      }
      if (active.controller.signal.aborted) return;
      await this.storage.set({ [UNLOCK_SESSION_STORAGE_KEY]: stored });
      if (active.controller.signal.aborted) return;
      await this.verifyStored(active);
    } catch (error) {
      try {
        await this.storage.remove([
          UNLOCK_SESSION_STORAGE_KEY,
          LEGACY_UNLOCK_SESSION_STORAGE_KEY_V1,
        ]);
      } catch (cleanupError) {
        throw new AggregateError(
          [error, cleanupError],
          "extension unlock session write and cleanup both failed",
        );
      }
      throw error;
    }
  }

  private checkFor(active: ActiveUnlockSession): UnlockCheck {
    return snapshotUnlockCheck({
      deadlines: active.deadlines,
      readNow: this.readNow,
      signal: active.controller.signal,
    })!;
  }

  private async assertActive(
    active: ActiveUnlockSession,
    operation: string,
    allowUncommitted = false,
  ): Promise<UnlockCheck> {
    if (!allowUncommitted && !active.committed) throw new KeyringLockedError(operation);
    const unlock = this.checkFor(active);
    try {
      assertUnlockCheck(unlock, operation);
      return unlock;
    } catch (error) {
      if (this.active === active) {
        this.transition++;
        this.abortActive(active);
        await this.removeStored();
      }
      throw error;
    }
  }

  async isUnlocked(): Promise<boolean> {
    if (this.active === undefined) return false;
    try {
      await this.assertActive(this.active, "inspect unlock session");
      return true;
    } catch (error) {
      if (error instanceof KeyringExpiredError || error instanceof KeyringLockedError) return false;
      throw error;
    }
  }

  async unlock(params: ActivateUnlockSessionParams): Promise<void> {
    const callerKeyBytes =
      typeof params === "object" && params !== null &&
      typeof params.unwrapKey === "object" && params.unwrapKey !== null
        ? params.unwrapKey.bytes
        : undefined;
    let validated: ReturnType<typeof validateActivation>;
    try {
      validated = validateActivation(params);
    } finally {
      if (callerKeyBytes instanceof Uint8Array) callerKeyBytes.fill(0);
    }

    const generation = ++this.transition;
    this.abortActive();
    const active: ActiveUnlockSession = {
      ...validated,
      controller: new AbortController(),
      committed: false,
    };
    try {
      assertUnlockCheck(this.checkFor(active), "activate unlock session");
    } catch (error) {
      this.abortActive(active);
      throw error;
    }
    this.active = active;

    const stored = encodeStoredSession(active);
    const onAbort = (): void => {
      stored.unwrapKey.fill(0);
    };
    active.controller.signal.addEventListener("abort", onAbort, { once: true });
    if (active.controller.signal.aborted) onAbort();
    try {
      await this.storageOperation("replace", async () => {
        // One queued operation makes remove→set indivisible relative to every later
        // lock/touch in this worker. Chrome provides no transaction or CAS primitive.
        await this.writeAndVerify(active, stored, true);
      });
      if (this.transition !== generation || this.active !== active) {
        throw new KeyringLockedError("activate unlock session");
      }
      await this.assertActive(active, "activate unlock session", true);
      active.committed = true;
    } catch (error) {
      if (this.active === active) this.abortActive(active);
      throw error;
    } finally {
      active.controller.signal.removeEventListener("abort", onAbort);
      stored.unwrapKey.fill(0);
    }
  }

  async restore(expectedBundleId: Uint8Array): Promise<boolean> {
    if (
      !(expectedBundleId instanceof Uint8Array) ||
      expectedBundleId.length !== KEYRING_BUNDLE_ID_BYTES
    ) {
      throw new UnlockSessionFormatError(
        `expected bundleId must be exactly ${KEYRING_BUNDLE_ID_BYTES} bytes`,
      );
    }
    // Snapshot before the first await so caller mutation cannot retarget a
    // wake-time restore between persistent-record validation and comparison.
    const expected = expectedBundleId.slice();
    const generation = ++this.transition;
    this.abortActive();
    try {
      // storage.session should be cleared on extension update, but do not leave
      // a pre-v2 unwrap-key record behind if a development/profile migration
      // violates that lifecycle assumption.
      await this.storageOperation("remove legacy", () =>
        this.storage.remove(LEGACY_UNLOCK_SESSION_STORAGE_KEY_V1),
      );
      const values = await this.storageOperation("get", () =>
        this.storage.get(UNLOCK_SESSION_STORAGE_KEY),
      );
      const raw = values[UNLOCK_SESSION_STORAGE_KEY];
      let parsed: ReturnType<typeof parseStoredSession> | undefined;
      try {
        // A newer lock/unlock/restore may have queued its own storage mutation
        // while this get was pending. Never enqueue cleanup based on that stale
        // snapshot: it would run after, and could erase, the newer generation.
        if (this.transition !== generation) {
          throw new KeyringLockedError("restore unlock session");
        }
        if (raw === undefined) return false;
        parsed = parseStoredSession(raw);
        if (!equalBytes(parsed.bundleId, expected)) {
          await this.removeStored();
          return false;
        }
        if (this.transition !== generation) {
          throw new KeyringLockedError("restore unlock session");
        }
        const active: ActiveUnlockSession = {
          ...parsed,
          controller: new AbortController(),
          committed: true,
        };
        try {
          assertUnlockCheck(this.checkFor(active), "restore unlock session");
        } catch (error) {
          this.abortActive(active);
          if (error instanceof KeyringExpiredError) {
            await this.removeStored();
            return false;
          }
          throw error;
        }
        this.active = active;
        parsed = undefined;
        return true;
      } catch (error) {
        if (error instanceof UnlockSessionFormatError) {
          await this.removeStored();
        }
        throw error;
      } finally {
        parsed?.account.fill(0);
        parsed?.bundleId.fill(0);
        if (parsed !== undefined) zeroizeUnwrapKey(parsed.unwrapKey);
        scrubStoredArrays(raw);
      }
    } finally {
      expected.fill(0);
    }
  }

  lock(): Promise<void> {
    this.transition++;
    this.abortActive();
    return this.removeStored();
  }

  async touch(policy: UnlockPolicy): Promise<void> {
    const active = this.active;
    if (active === undefined) throw new KeyringLockedError("touch unlock session");
    await this.assertActive(active, "touch unlock session");
    const generation = this.transition;
    let now: number;
    try {
      now = this.readNow();
    } catch {
      await this.assertActive(active, "touch unlock session");
      throw new KeyringFormatError("unlock check readNow failed");
    }
    const deadlines = touchUnlockSession(active.deadlines, now, policy);
    const stored = encodeStoredSession({ ...active, deadlines });
    const removeAbortCleanup = registerUnlockAbortCleanup(this.checkFor(active), () => {
      stored.unwrapKey.fill(0);
    });
    try {
      await this.storageOperation("touch", () =>
        this.writeAndVerify({ ...active, deadlines }, stored, false),
      );
      if (this.transition !== generation || this.active !== active) {
        throw new KeyringLockedError("touch unlock session");
      }
      await this.assertActive(active, "touch unlock session");
      active.deadlines = deadlines;
    } catch (error) {
      if (this.active === active) {
        this.transition++;
        this.abortActive(active);
      }
      throw error;
    } finally {
      removeAbortCleanup();
      stored.unwrapKey.fill(0);
    }
  }

  /**
   * Borrow isolated session bytes for a local computation, then release only the
   * returned bytes after a second live deadline/revocation check. The callback must
   * not perform an irreversible external side effect: no API can retract a signature
   * or plaintext the callback already transmitted before this owner re-checks it.
   */
  async useBytes(
    operation: string,
    use: (lease: UnlockSessionLease) => Promise<Uint8Array>,
  ): Promise<Uint8Array> {
    if (typeof operation !== "string" || operation.length === 0) {
      throw new UnlockSessionFormatError("key-use operation must be a non-empty string");
    }
    if (typeof use !== "function") {
      throw new UnlockSessionFormatError("key use must be a function");
    }
    const active = this.active;
    if (active === undefined) throw new KeyringLockedError(operation);
    const unlock = await this.assertActive(active, operation);
    const account = active.account.slice();
    const unwrapKey: KeyringUnwrapKey = {
      kdf: active.unwrapKey.kdf,
      bytes: active.unwrapKey.bytes.slice(),
    };
    let result: Uint8Array | undefined;
    const removeAbortCleanup = registerUnlockAbortCleanup(unlock, () => {
      account.fill(0);
      zeroizeUnwrapKey(unwrapKey);
      result?.fill(0);
    });
    try {
      try {
        result = await use({ account, unwrapKey, unlock });
      } catch (error) {
        await this.assertActive(active, operation);
        throw error;
      }
      if (!(result instanceof Uint8Array)) {
        throw new UnlockSessionFormatError("key use must return a Uint8Array");
      }
      try {
        await this.assertActive(active, operation);
        return result;
      } catch (error) {
        result.fill(0);
        throw error;
      }
    } finally {
      removeAbortCleanup();
      account.fill(0);
      zeroizeUnwrapKey(unwrapKey);
    }
  }
}
