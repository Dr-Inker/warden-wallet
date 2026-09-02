import {
  KEYRING_RECORD_VERSION_2,
  PUBKEY_BYTES,
  KeyringAuthError,
  KeyringFormatError,
  KeyringLockedError,
  SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION,
  assertUnlockCheck,
  assertValidKeyringContext,
  assertValidUnlockPolicy,
  decodeKeyringRecordStorageValue,
  decodeSessionSignerPayload,
  deriveSessionSignerPublicKey,
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
  type UnlockAlarmScheduler,
  type UnlockSessionStorageArea,
} from "./unlock-session.js";

/**
 * The context fields the extension itself pins, as opposed to the ones a record
 * legitimately chooses (the SmartAccount) or the ones already fixed by the
 * record schema (`keyKind`, `schemaVersion`).
 *
 * The record's context is AAD-authenticated, so it cannot be *edited* without
 * the KEK — but a whole record can be REPLACED by a different, validly sealed
 * one. `WRD-KEY-04`'s cross-cluster promise therefore only reaches the trust
 * boundary if the extension compares these bytes to its own expectation instead
 * of taking them from the record it is about to adopt.
 */
export interface ExpectedKeyringContext {
  /** Canonical cluster identity this build adopts records for. */
  readonly genesisHash: Uint8Array;
  /** Warden deployment this build adopts records for. */
  readonly programId: Uint8Array;
}

export interface KeyringLifecycleOptions {
  /**
   * Injected exactly like the extension origin: source-owned configuration, never
   * a value this class or a stored record chooses for itself.
   */
  readonly expectedContext: ExpectedKeyringContext;
  readonly readNow?: () => number;
  /**
   * Browser alarm port used only to wake this worker at the unlock deadline
   * (audit A-2). Omitting it degrades expiry to the pre-existing lazy check.
   */
  readonly alarms?: UnlockAlarmScheduler;
}

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

/** Public identity authenticated by the active encrypted keyring record. */
export interface AuthenticatedSessionIdentity {
  /** Caller-owned SmartAccount copy. */
  readonly account: Uint8Array;
  /** Caller-owned canonical cluster genesis hash. */
  readonly genesisHash: Uint8Array;
  /** Caller-owned Warden deployment id. */
  readonly programId: Uint8Array;
  /** Aborts synchronously when this exact unlock generation is revoked. */
  readonly revocationSignal: AbortSignal;
  /** Caller-owned public half derived from the authenticated signer seed. */
  readonly sessionSigner: Uint8Array;
}

/** Privileged lifecycle surface; production exposes it only through readiness gating. */
export interface KeyringLifecycle extends SessionApprovalKeyring {
  isUnlocked(): Promise<boolean>;
  lock(): Promise<void>;
  replacePersistentRecord(value: unknown): Promise<void>;
  clearPersistentRecord(): Promise<void>;
  unlockWithPassword(params: UnlockKeyringWithPasswordParams): Promise<void>;
  readAuthenticatedSessionIdentity(
    operation: string,
  ): Promise<AuthenticatedSessionIdentity>;
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

/** Copy-own the pinned bytes so a later caller mutation cannot widen the check. */
function snapshotExpectedContext(value: unknown): ExpectedKeyringContext {
  if (typeof value !== "object" || value === null || value instanceof Uint8Array) {
    throw new KeyringFormatError(
      "keyring lifecycle expected context must be an object",
    );
  }
  const expected = value as Partial<ExpectedKeyringContext>;
  const fields: ReadonlyArray<readonly [string, unknown]> = [
    ["genesisHash", expected.genesisHash],
    ["programId", expected.programId],
  ];
  const copies: Uint8Array[] = [];
  for (const [name, bytes] of fields) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== PUBKEY_BYTES) {
      throw new KeyringFormatError(
        `keyring lifecycle expected ${name} must be exactly ${PUBKEY_BYTES} bytes`,
      );
    }
    let combined = 0;
    for (const byte of bytes) combined |= byte;
    if (combined === 0) {
      throw new KeyringFormatError(
        `keyring lifecycle expected ${name} must not be all zero`,
      );
    }
    copies.push(bytes.slice());
  }
  return Object.freeze({ genesisHash: copies[0]!, programId: copies[1]! });
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
  private readonly expectedContext: ExpectedKeyringContext;
  private transition = 0;
  private pendingPasswordUnlock: AbortController | undefined;

  constructor(
    localStorage: KeyringRecordStorageArea,
    sessionStorage: UnlockSessionStorageArea,
    runtimeId: string,
    options: KeyringLifecycleOptions,
  ) {
    if (typeof options !== "object" || options === null) {
      throw new KeyringFormatError("keyring lifecycle options must be an object");
    }
    if (options.readNow !== undefined && typeof options.readNow !== "function") {
      throw new KeyringFormatError("keyring lifecycle readNow must be a function");
    }
    // Resolve the pin before any storage owner exists: a build with no pinned
    // cluster/deployment must not be constructible at all.
    this.expectedContext = snapshotExpectedContext(options.expectedContext);
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
    // Every field this build pins is compared here, not carried out of the
    // record: AEAD authentication proves the context was not edited, never that
    // it is the context this extension is allowed to adopt. `keyKind` and
    // `schemaVersion` are already pinned by `snapshotSessionSignerContext`; the
    // SmartAccount is the record's own choice and has no build-level expectation.
    if (
      context.origin !== this.expectedOrigin ||
      !equalBytes(context.genesisHash, this.expectedContext.genesisHash) ||
      !equalBytes(context.programId, this.expectedContext.programId)
    ) {
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

  /**
   * Eager unlock expiry (audit A-2). Before this existed, expiry was only ever
   * noticed the next time something happened to touch the session, so the
   * serialized unwrap key could sit in `chrome.storage.session` for an unbounded
   * time after both deadlines had passed. The alarm gives that check an
   * occasion; the check itself is the same one every key use runs.
   *
   * This deliberately does NOT take the lifecycle-level `lock()` path: a session
   * expiring must not revoke a password unlock that is concurrently deriving a
   * NEW session, and the session owner already aborts leases, zeroes the unwrap
   * key, and removes the stored record on expiry.
   */
  handleUnlockExpiryAlarm(): Promise<void> {
    return this.sessions.handleExpiryAlarm().then(() => undefined);
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

  /**
   * Authenticate the live record and return only its public selection facts.
   * The seed is opened and schema-checked inside the existing exact-readback
   * lease, used only to derive its public half, and scrubbed before this method
   * returns. A record/session transition suppresses the entire snapshot.
   */
  async readAuthenticatedSessionIdentity(
    operation: string,
  ): Promise<AuthenticatedSessionIdentity> {
    const generation = this.transition;
    let unlock: UnlockCheck | undefined;
    let encoded: Uint8Array | undefined;
    try {
      encoded = await this.useSessionSignerBytes(operation, async (lease) => {
        unlock = lease.unlock;
        const sessionSigner = deriveSessionSignerPublicKey(lease.seed);
        try {
          const identity = new Uint8Array(PUBKEY_BYTES * 4);
          identity.set(lease.account, 0);
          identity.set(lease.genesisHash, PUBKEY_BYTES);
          identity.set(lease.programId, PUBKEY_BYTES * 2);
          identity.set(sessionSigner, PUBKEY_BYTES * 3);
          return identity;
        } finally {
          sessionSigner.fill(0);
        }
      });
      if (unlock === undefined) {
        throw new KeyringLifecycleConsistencyError(
          "authenticated public identity has no unlock generation",
        );
      }
      try {
        assertUnlockCheck(unlock, operation);
      } catch (error) {
        if (this.transition === generation) {
          return this.lockAfterFailure(error, generation);
        }
        throw error;
      }
      if (encoded.length !== PUBKEY_BYTES * 4) {
        throw new KeyringLifecycleConsistencyError(
          "authenticated public identity has the wrong length",
        );
      }
      return Object.freeze({
        account: encoded.slice(0, PUBKEY_BYTES),
        genesisHash: encoded.slice(PUBKEY_BYTES, PUBKEY_BYTES * 2),
        programId: encoded.slice(PUBKEY_BYTES * 2, PUBKEY_BYTES * 3),
        revocationSignal: unlock.signal,
        sessionSigner: encoded.slice(PUBKEY_BYTES * 3, PUBKEY_BYTES * 4),
      });
    } finally {
      encoded?.fill(0);
    }
  }
}
