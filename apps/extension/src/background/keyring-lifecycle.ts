import {
  KEYRING_RECORD_VERSION_2,
  KeyringAuthError,
  KeyringFormatError,
  KeyringLockedError,
  SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION,
  assertUnlockCheck,
  assertValidKeyringContext,
  assertValidUnlockPolicy,
  decodeKeyringRecordStorageValue,
  decodeSessionSignerPayload,
  deriveUnwrapKeyFromPasswordBytesAsync,
  encodeKeyringRecordMetadata,
  openKeyringBundle,
  registerUnlockAbortCleanup,
  startUnlockSession,
  zeroizeUnwrapKey,
  type KeyringContext,
  type KeyringRecord,
  type KeyringUnwrapKey,
  type UnlockCheck,
  type UnlockPolicy,
} from "@warden/core/keyring";
import type {
  SessionApprovalKeyring,
  SessionApprovalSignerLease,
} from "@warden/core/transaction/session-approval";

import {
  PersistentKeyringRecordStore,
  type KeyringRecordStorageArea,
} from "./keyring-record-store.js";
import {
  UnlockSessionOwner,
  type UnlockSessionStorageArea,
} from "./unlock-session.js";

export interface UnlockKeyringWithPasswordParams {
  /** Caller-owned and synchronously overwritten before the first suspension. */
  readonly passwordBytes: Uint8Array;
  readonly policy: UnlockPolicy;
}

export interface SessionSignerLease extends SessionApprovalSignerLease {
  /** Isolated public account copy; overwritten when the callback settles. */
  readonly account: Uint8Array;
  /** AAD-authenticated canonical cluster identity; overwritten on settlement. */
  readonly genesisHash: Uint8Array;
  /** AAD-authenticated Warden deployment; overwritten on settlement. */
  readonly programId: Uint8Array;
  /** Isolated plaintext Ed25519 seed; overwritten when the callback settles. */
  readonly seed: Uint8Array;
  readonly unlock: UnlockCheck;
}

/** Privileged lifecycle surface; production exposes it only through readiness gating. */
export interface KeyringLifecycle extends SessionApprovalKeyring {
  isUnlocked(): Promise<boolean>;
  lock(): Promise<void>;
  replacePersistentRecord(value: unknown): Promise<void>;
  clearPersistentRecord(): Promise<void>;
  unlockWithPassword(params: UnlockKeyringWithPasswordParams): Promise<void>;
  useSessionSignerBytes(
    operation: string,
    use: (lease: SessionSignerLease) => Promise<Uint8Array>,
  ): Promise<Uint8Array>;
}

export class KeyringLifecycleConsistencyError extends Error {
  constructor(message: string) {
    super(`extension keyring lifecycle: ${message}`);
    this.name = "KeyringLifecycleConsistencyError";
  }
}

interface SnapshotContext extends KeyringContext {
  readonly account: Uint8Array;
  readonly genesisHash: Uint8Array;
  readonly programId: Uint8Array;
}

function snapshotSessionSignerContext(value: unknown): SnapshotContext {
  if (typeof value !== "object" || value === null || value instanceof Uint8Array) {
    throw new KeyringFormatError("session-signer context must be an object");
  }
  const context = value as KeyringContext;
  assertValidKeyringContext(context);
  if (context.keyKind !== "session-signer") {
    throw new KeyringFormatError("session-signer context has the wrong key kind");
  }
  if (context.schemaVersion !== SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION) {
    throw new KeyringFormatError(
      `session-signer schema must be ${SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION}`,
    );
  }
  return Object.freeze({
    account: context.account.slice(),
    origin: context.origin,
    keyKind: "session-signer" as const,
    schemaVersion: SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION,
    genesisHash: context.genesisHash.slice(),
    programId: context.programId.slice(),
  });
}

function clearContext(context: SnapshotContext | undefined): void {
  context?.account.fill(0);
  context?.genesisHash.fill(0);
  context?.programId.fill(0);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function canonicalStoredRecord(value: unknown): string {
  const record = decodeKeyringRecordStorageValue(value);
  if (record.metadata.version !== KEYRING_RECORD_VERSION_2) {
    throw new KeyringFormatError(
      "extension keyring requires a self-contained record v2",
    );
  }
  return value as string;
}

const EXTENSION_ID_PATTERN = /^[a-p]{32}$/;

function extensionOrigin(runtimeId: unknown): string {
  if (typeof runtimeId !== "string" || !EXTENSION_ID_PATTERN.test(runtimeId)) {
    throw new KeyringFormatError("keyring lifecycle runtime extension id is malformed");
  }
  return `chrome-extension://${runtimeId}`;
}

/**
 * One authority for the persistent encrypted record and its ephemeral MV3
 * unlock material. Raw record/session owners never escape this class.
 *
 * Every state-changing method increments `transition` and revokes a pending
 * password derivation before its first `await`. Lock and record mutations also
 * synchronously abort leases and clear the in-memory unwrap key. A password
 * unlock checks the same transition and exact persistent record before and
 * after activation, so an unlock started against record A cannot commit after
 * record B wins. Startup restore refuses and clears a same-owner pending unlock;
 * it never adopts a session that the superseded operation had just serialized.
 */
export class KeyringLifecycleOwner implements KeyringLifecycle {
  private readonly records: PersistentKeyringRecordStore;
  private readonly sessions: UnlockSessionOwner;
  private readonly readNow: () => number;
  private readonly expectedOrigin: string;
  private transition = 0;
  private pendingPasswordUnlock: AbortController | undefined;

  constructor(
    localStorage: KeyringRecordStorageArea,
    sessionStorage: UnlockSessionStorageArea,
    runtimeId: string,
    options: { readonly readNow?: () => number } = {},
  ) {
    if (options.readNow !== undefined && typeof options.readNow !== "function") {
      throw new KeyringFormatError("keyring lifecycle readNow must be a function");
    }
    this.records = new PersistentKeyringRecordStore(localStorage);
    this.sessions = new UnlockSessionOwner(sessionStorage, options);
    this.readNow = options.readNow ?? Date.now;
    this.expectedOrigin = extensionOrigin(runtimeId);
  }

  private contextForRecord(recordValue: KeyringRecord | string): SnapshotContext {
    const record = typeof recordValue === "string"
      ? decodeKeyringRecordStorageValue(recordValue)
      : recordValue;
    if (record.metadata.version !== KEYRING_RECORD_VERSION_2) {
      throw new KeyringFormatError(
        "extension keyring requires a self-contained record v2",
      );
    }
    const context = snapshotSessionSignerContext(record.metadata.context);
    if (context.origin !== this.expectedOrigin) {
      clearContext(context);
      throw new KeyringAuthError();
    }
    return context;
  }

  private assertTransition(generation: number, operation: string): void {
    if (this.transition !== generation) throw new KeyringLockedError(operation);
  }

  private revokePendingPasswordUnlock(): boolean {
    const pending = this.pendingPasswordUnlock;
    this.pendingPasswordUnlock = undefined;
    if (pending === undefined) return false;
    pending.abort();
    return true;
  }

  private readCurrentTime(): number {
    try {
      return this.readNow();
    } catch {
      throw new KeyringFormatError("keyring lifecycle readNow failed");
    }
  }

  private async lockAfterFailure(error: unknown, generation: number): Promise<never> {
    // A newer transition already synchronously revoked this generation. Do not
    // let stale cleanup abort a newer unlock that may now own the session.
    if (this.transition !== generation) throw error;
    try {
      await this.lock();
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        "keyring lifecycle failure and session cleanup both failed",
      );
    }
    throw error;
  }

  isUnlocked(): Promise<boolean> {
    return this.sessions.isUnlocked();
  }

  /**
   * Startup-only restore. A public bundle-id match is only a routing check:
   * readiness stays pending until the restored KEK authenticates and decodes
   * the exact current record under its browser-owned context.
   */
  async restore(): Promise<boolean> {
    const generation = ++this.transition;
    const revokedPendingUnlock = this.revokePendingPasswordUnlock();
    let context: SnapshotContext | undefined;
    let proof: Uint8Array | undefined;
    try {
      if (revokedPendingUnlock) {
        await this.sessions.lock();
        this.assertTransition(generation, "restore keyring lifecycle");
        return false;
      }
      const stored = await this.records.load();
      this.assertTransition(generation, "restore keyring lifecycle");
      if (stored === null) {
        await this.sessions.lock();
        this.assertTransition(generation, "restore keyring lifecycle");
        return false;
      }
      const record = decodeKeyringRecordStorageValue(stored);
      context = this.contextForRecord(record);
      const restored = await this.sessions.restore(record.bundle.bundleId);
      this.assertTransition(generation, "restore keyring lifecycle");
      if (!restored) return false;

      proof = await this.sessions.useBytes(
        "authenticate restored keyring session",
        async (session) => {
          let plaintext: Uint8Array | undefined;
          let decodedSeed: Uint8Array | undefined;
          try {
            this.assertTransition(generation, "restore keyring lifecycle");
            if (!equalBytes(session.account, context!.account)) {
              throw new KeyringLifecycleConsistencyError(
                "restored session account does not match the persistent keyring context",
              );
            }
            if (!equalBytes(session.bundleId, record.bundle.bundleId)) {
              throw new KeyringLifecycleConsistencyError(
                "restored session bundle does not match the persistent keyring bundle",
              );
            }
            plaintext = await openKeyringBundle({
              bundle: record.bundle,
              unwrapKey: session.unwrapKey,
              context: context!,
              recordBinding: encodeKeyringRecordMetadata(record.metadata),
              unlock: session.unlock,
            });
            this.assertTransition(generation, "restore keyring lifecycle");
            decodedSeed = decodeSessionSignerPayload(plaintext);
            const readback = await this.records.load();
            this.assertTransition(generation, "restore keyring lifecycle");
            if (readback !== stored) {
              throw new KeyringLifecycleConsistencyError(
                "persistent record changed while authenticating its restored session",
              );
            }
            return new Uint8Array(0);
          } finally {
            plaintext?.fill(0);
            decodedSeed?.fill(0);
          }
        },
      );
      proof.fill(0);
      proof = undefined;
      return true;
    } catch (error) {
      return this.lockAfterFailure(error, generation);
    } finally {
      proof?.fill(0);
      clearContext(context);
    }
  }

  /** Revoke memory synchronously, then remove serialized session material. */
  lock(): Promise<void> {
    this.transition++;
    this.revokePendingPasswordUnlock();
    return this.sessions.lock();
  }

  async replacePersistentRecord(value: unknown): Promise<void> {
    // Reject malformed input before revoking a legitimate active session.
    const canonical = canonicalStoredRecord(value);
    const context = this.contextForRecord(canonical);
    clearContext(context);
    this.transition++;
    this.revokePendingPasswordUnlock();
    const locked = this.sessions.lock();
    await locked;
    await this.records.replace(canonical);
  }

  async clearPersistentRecord(): Promise<void> {
    this.transition++;
    this.revokePendingPasswordUnlock();
    const locked = this.sessions.lock();
    await locked;
    await this.records.clear();
  }

  async unlockWithPassword(params: UnlockKeyringWithPasswordParams): Promise<void> {
    const callerPassword =
      typeof params === "object" && params !== null ? params.passwordBytes : undefined;
    let password: Uint8Array | undefined;
    let context: SnapshotContext | undefined;
    let policy: UnlockPolicy | undefined;
    try {
      if (typeof params !== "object" || params === null) {
        throw new KeyringFormatError("password unlock parameters must be an object");
      }
      if (!(params.passwordBytes instanceof Uint8Array)) {
        throw new KeyringFormatError("passwordBytes must be a Uint8Array");
      }
      password = params.passwordBytes.slice();
      assertValidUnlockPolicy(params.policy);
      policy = Object.freeze({
        idleTimeoutMs: params.policy.idleTimeoutMs,
        hardTimeoutMs: params.policy.hardTimeoutMs,
      });
    } catch (error) {
      password?.fill(0);
      clearContext(context);
      throw error;
    } finally {
      if (callerPassword instanceof Uint8Array) callerPassword.fill(0);
    }

    const generation = ++this.transition;
    this.revokePendingPasswordUnlock();
    const pendingUnlock = new AbortController();
    this.pendingPasswordUnlock = pendingUnlock;
    let unwrapKey: KeyringUnwrapKey | undefined;
    let plaintext: Uint8Array | undefined;
    let decodedSeed: Uint8Array | undefined;
    let sessionCommitted = false;
    const clearPendingSecrets = (): void => {
      password?.fill(0);
      if (unwrapKey !== undefined) zeroizeUnwrapKey(unwrapKey);
      plaintext?.fill(0);
      decodedSeed?.fill(0);
    };
    pendingUnlock.signal.addEventListener("abort", clearPendingSecrets, { once: true });
    try {
      // `lock()` itself would advance our transition a second time, so call the
      // hidden owner directly after this generation has been claimed.
      await this.sessions.lock();
      this.assertTransition(generation, "unlock keyring with password");
      const stored = await this.records.load();
      this.assertTransition(generation, "unlock keyring with password");
      if (stored === null) {
        throw new KeyringLifecycleConsistencyError(
          "cannot unlock without a persistent encrypted record",
        );
      }
      const record = decodeKeyringRecordStorageValue(stored);
      context = this.contextForRecord(record);
      const recordBinding = encodeKeyringRecordMetadata(record.metadata);
      unwrapKey = await deriveUnwrapKeyFromPasswordBytesAsync(
        password!,
        record.metadata.argon2id.salt,
        record.metadata.argon2id.params,
        { signal: pendingUnlock.signal },
      );
      password!.fill(0);
      password = undefined;
      this.assertTransition(generation, "unlock keyring with password");
      plaintext = await openKeyringBundle({
        bundle: record.bundle,
        unwrapKey,
        context: context!,
        recordBinding,
      });
      this.assertTransition(generation, "unlock keyring with password");
      decodedSeed = decodeSessionSignerPayload(plaintext);
      // Authentication and strict schema validation are complete. Activation
      // needs only the KEK, never the plaintext signer seed.
      decodedSeed.fill(0);
      decodedSeed = undefined;
      plaintext.fill(0);
      plaintext = undefined;

      const beforeActivation = await this.records.load();
      this.assertTransition(generation, "unlock keyring with password");
      if (beforeActivation !== stored) {
        throw new KeyringLifecycleConsistencyError(
          "persistent record changed during password authentication",
        );
      }
      const deadlines = startUnlockSession(this.readCurrentTime(), policy!);
      await this.sessions.unlock({
        account: context!.account,
        bundleId: record.bundle.bundleId,
        unwrapKey,
        deadlines,
      });
      sessionCommitted = true;
      this.assertTransition(generation, "unlock keyring with password");

      const afterActivation = await this.records.load();
      this.assertTransition(generation, "unlock keyring with password");
      if (afterActivation !== stored) {
        throw new KeyringLifecycleConsistencyError(
          "persistent record changed while committing its unlock session",
        );
      }
    } catch (error) {
      if (pendingUnlock.signal.aborted) {
        throw new KeyringLockedError("unlock keyring with password");
      }
      if (sessionCommitted && this.transition === generation) {
        return this.lockAfterFailure(error, generation);
      }
      throw error;
    } finally {
      pendingUnlock.signal.removeEventListener("abort", clearPendingSecrets);
      if (this.pendingPasswordUnlock === pendingUnlock) {
        this.pendingPasswordUnlock = undefined;
      }
      password?.fill(0);
      if (unwrapKey !== undefined) zeroizeUnwrapKey(unwrapKey);
      plaintext?.fill(0);
      decodedSeed?.fill(0);
      clearContext(context);
    }
  }

  async useSessionSignerBytes(
    operation: string,
    use: (lease: SessionSignerLease) => Promise<Uint8Array>,
  ): Promise<Uint8Array> {
    if (typeof use !== "function") {
      throw new KeyringFormatError("session-signer use callback must be a function");
    }
    const generation = this.transition;
    let lifecycleFailure = false;
    try {
      return await this.sessions.useBytes(operation, async (session) => {
        let stored: string | null = null;
        let context: SnapshotContext | undefined;
        let plaintext: Uint8Array | undefined;
        let seed: Uint8Array | undefined;
        let result: Uint8Array | undefined;
        let releaseResult = false;
        let removeAbortCleanup = (): void => undefined;
        try {
          try {
            assertUnlockCheck(session.unlock, operation);
            stored = await this.records.load();
            assertUnlockCheck(session.unlock, operation);
            if (stored === null) {
              throw new KeyringLifecycleConsistencyError(
                "persistent record disappeared during session use",
              );
            }
            const record = decodeKeyringRecordStorageValue(stored);
            context = this.contextForRecord(record);
            if (!equalBytes(session.account, context.account)) {
              throw new KeyringLifecycleConsistencyError(
                "active session account does not match the persistent keyring context",
              );
            }
            if (!equalBytes(record.bundle.bundleId, session.bundleId)) {
              throw new KeyringLifecycleConsistencyError(
                "persistent bundle does not match the active unlock session",
              );
            }
            plaintext = await openKeyringBundle({
              bundle: record.bundle,
              unwrapKey: session.unwrapKey,
              context: context,
              recordBinding: encodeKeyringRecordMetadata(record.metadata),
              unlock: session.unlock,
            });
            seed = decodeSessionSignerPayload(plaintext);
            removeAbortCleanup = registerUnlockAbortCleanup(session.unlock, () => {
              seed?.fill(0);
              result?.fill(0);
            });
            assertUnlockCheck(session.unlock, operation);
          } catch (error) {
            lifecycleFailure = true;
            throw error;
          }

          result = await use({
            account: session.account,
            genesisHash: context.genesisHash,
            programId: context.programId,
            seed,
            unlock: session.unlock,
          });
          if (!(result instanceof Uint8Array)) {
            throw new KeyringFormatError(
              "session-signer use callback must return a Uint8Array",
            );
          }

          try {
            assertUnlockCheck(session.unlock, operation);
            const readback = await this.records.load();
            assertUnlockCheck(session.unlock, operation);
            if (readback !== stored) {
              throw new KeyringLifecycleConsistencyError(
                "persistent record changed during session-signer use",
              );
            }
          } catch (error) {
            lifecycleFailure = true;
            throw error;
          }
          releaseResult = true;
          return result;
        } finally {
          removeAbortCleanup();
          plaintext?.fill(0);
          seed?.fill(0);
          if (!releaseResult && result instanceof Uint8Array) result.fill(0);
          clearContext(context);
        }
      });
    } catch (error) {
      if (lifecycleFailure && this.transition === generation) {
        return this.lockAfterFailure(error, generation);
      }
      throw error;
    }
  }
}
