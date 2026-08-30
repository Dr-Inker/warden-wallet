import {
  KeyringFormatError,
  KeyringLockedError,
  SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION,
  assertUnlockCheck,
  assertValidKeyringContext,
  assertValidUnlockPolicy,
  decodeKeyringRecordStorageValue,
  decodeSessionSignerPayload,
  deriveUnwrapKeyFromPasswordBytes,
  encodeKeyringRecordMetadata,
  openKeyringBundle,
  registerUnlockAbortCleanup,
  startUnlockSession,
  zeroizeUnwrapKey,
  type KeyringContext,
  type KeyringUnwrapKey,
  type UnlockCheck,
  type UnlockPolicy,
} from "@warden/core/keyring";

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
  readonly context: KeyringContext;
  readonly policy: UnlockPolicy;
}

export interface SessionSignerLease {
  /** Isolated public account copy; overwritten when the callback settles. */
  readonly account: Uint8Array;
  /** Isolated plaintext Ed25519 seed; overwritten when the callback settles. */
  readonly seed: Uint8Array;
  readonly unlock: UnlockCheck;
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
  decodeKeyringRecordStorageValue(value);
  return value as string;
}

/**
 * One authority for the persistent encrypted record and its ephemeral MV3
 * unlock material. Raw record/session owners never escape this class.
 *
 * Every state-changing method increments `transition` and calls `lock()` on
 * the underlying session owner before its first `await`. That synchronously
 * aborts leases and clears the in-memory unwrap key. A password unlock checks
 * the same transition and exact persistent record before and after activation,
 * so an unlock started against record A cannot commit after record B wins.
 */
export class KeyringLifecycleOwner {
  private readonly records: PersistentKeyringRecordStore;
  private readonly sessions: UnlockSessionOwner;
  private readonly readNow: () => number;
  private transition = 0;

  constructor(
    localStorage: KeyringRecordStorageArea,
    sessionStorage: UnlockSessionStorageArea,
    options: { readonly readNow?: () => number } = {},
  ) {
    if (options.readNow !== undefined && typeof options.readNow !== "function") {
      throw new KeyringFormatError("keyring lifecycle readNow must be a function");
    }
    this.records = new PersistentKeyringRecordStore(localStorage);
    this.sessions = new UnlockSessionOwner(sessionStorage, options);
    this.readNow = options.readNow ?? Date.now;
  }

  private assertTransition(generation: number, operation: string): void {
    if (this.transition !== generation) throw new KeyringLockedError(operation);
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

  /** Startup-only restore, bound to an exact persistent bundle id. */
  async restore(): Promise<boolean> {
    const generation = ++this.transition;
    try {
      const stored = await this.records.load();
      this.assertTransition(generation, "restore keyring lifecycle");
      if (stored === null) {
        await this.sessions.lock();
        this.assertTransition(generation, "restore keyring lifecycle");
        return false;
      }
      const record = decodeKeyringRecordStorageValue(stored);
      const restored = await this.sessions.restore(record.bundle.bundleId);
      this.assertTransition(generation, "restore keyring lifecycle");
      if (!restored) return false;
      const readback = await this.records.load();
      this.assertTransition(generation, "restore keyring lifecycle");
      if (readback !== stored) {
        throw new KeyringLifecycleConsistencyError(
          "persistent record changed while restoring its unlock session",
        );
      }
      return true;
    } catch (error) {
      return this.lockAfterFailure(error, generation);
    }
  }

  /** Revoke memory synchronously, then remove serialized session material. */
  lock(): Promise<void> {
    this.transition++;
    return this.sessions.lock();
  }

  async replacePersistentRecord(value: unknown): Promise<void> {
    // Reject malformed input before revoking a legitimate active session.
    const canonical = canonicalStoredRecord(value);
    this.transition++;
    const locked = this.sessions.lock();
    await locked;
    await this.records.replace(canonical);
  }

  async clearPersistentRecord(): Promise<void> {
    this.transition++;
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
      context = snapshotSessionSignerContext(params.context);
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
    // `lock()` itself would advance our transition a second time, so call the
    // hidden owner directly after this generation has been claimed.
    const priorLocked = this.sessions.lock();
    let unwrapKey: KeyringUnwrapKey | undefined;
    let plaintext: Uint8Array | undefined;
    let decodedSeed: Uint8Array | undefined;
    let sessionCommitted = false;
    try {
      await priorLocked;
      this.assertTransition(generation, "unlock keyring with password");
      const stored = await this.records.load();
      this.assertTransition(generation, "unlock keyring with password");
      if (stored === null) {
        throw new KeyringLifecycleConsistencyError(
          "cannot unlock without a persistent encrypted record",
        );
      }
      const record = decodeKeyringRecordStorageValue(stored);
      const recordBinding = encodeKeyringRecordMetadata(record.metadata);
      unwrapKey = deriveUnwrapKeyFromPasswordBytes(
        password!,
        record.metadata.argon2id.salt,
        record.metadata.argon2id.params,
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
      if (sessionCommitted && this.transition === generation) {
        return this.lockAfterFailure(error, generation);
      }
      throw error;
    } finally {
      password?.fill(0);
      if (unwrapKey !== undefined) zeroizeUnwrapKey(unwrapKey);
      plaintext?.fill(0);
      decodedSeed?.fill(0);
      clearContext(context);
    }
  }

  async useSessionSignerBytes(
    operation: string,
    contextValue: KeyringContext,
    use: (lease: SessionSignerLease) => Promise<Uint8Array>,
  ): Promise<Uint8Array> {
    const context = snapshotSessionSignerContext(contextValue);
    if (typeof use !== "function") {
      clearContext(context);
      throw new KeyringFormatError("session-signer use callback must be a function");
    }
    const generation = this.transition;
    let lifecycleFailure = false;
    try {
      return await this.sessions.useBytes(operation, async (session) => {
        let stored: string | null = null;
        let plaintext: Uint8Array | undefined;
        let seed: Uint8Array | undefined;
        let result: Uint8Array | undefined;
        let releaseResult = false;
        let removeAbortCleanup = (): void => undefined;
        try {
          try {
            assertUnlockCheck(session.unlock, operation);
            if (!equalBytes(session.account, context.account)) {
              throw new KeyringLifecycleConsistencyError(
                "active session account does not match the requested keyring context",
              );
            }
            stored = await this.records.load();
            assertUnlockCheck(session.unlock, operation);
            if (stored === null) {
              throw new KeyringLifecycleConsistencyError(
                "persistent record disappeared during session use",
              );
            }
            const record = decodeKeyringRecordStorageValue(stored);
            if (!equalBytes(record.bundle.bundleId, session.bundleId)) {
              throw new KeyringLifecycleConsistencyError(
                "persistent bundle does not match the active unlock session",
              );
            }
            plaintext = await openKeyringBundle({
              bundle: record.bundle,
              unwrapKey: session.unwrapKey,
              context,
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

          result = await use({ account: session.account, seed, unlock: session.unlock });
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
        }
      });
    } catch (error) {
      if (lifecycleFailure && this.transition === generation) {
        return this.lockAfterFailure(error, generation);
      }
      throw error;
    } finally {
      clearContext(context);
    }
  }
}
