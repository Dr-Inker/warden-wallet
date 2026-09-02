import { decodeSessionApprovalReview } from "@warden/core/transaction/session-intent";

import {
  restrictStorageToTrustedContexts,
  type ExtensionStorageAccessApi,
  type StorageAreaAccessControl,
} from "./storage-access.js";
import type { UnlockSessionStorageArea } from "./unlock-session.js";
import {
  ProviderPortStateError,
  type ProviderRuntimeApi,
} from "./provider-port.js";
import {
  installRuntimeBoundaries,
  type RuntimeBoundaries,
} from "./runtime-ports.js";
import type { ApprovalReviewOwner } from "./approval-port.js";
import {
  installApprovalWindowOwner,
  type ApprovalWindowLauncher,
  type ApprovalWindowsApi,
  type InstalledApprovalWindowOwner,
} from "./approval-window.js";
import {
  KEYRING_RECORD_STORAGE_KEY,
  type KeyringRecordStorageArea,
} from "./keyring-record-store.js";
import {
  type AuthenticatedSessionIdentity,
  type ExpectedKeyringContext,
  KeyringLifecycleOwner,
  type KeyringLifecycle,
  type SessionSignerLease,
  type UnlockKeyringWithPasswordParams,
} from "./keyring-lifecycle.js";
import { shippedExpectedKeyringContext } from "./expected-keyring-context.js";

/**
 * Startup knobs. `expectedContext` exists so a test (or a future non-default
 * release channel) can name the pin explicitly; omitting it selects the shipped
 * pin, never "no pin".
 */
export interface ExtensionBackgroundOptions {
  readonly readNow?: () => number;
  readonly expectedContext?: ExpectedKeyringContext;
}

export interface ExtensionBackgroundStorageApi extends ExtensionStorageAccessApi {
  readonly local: StorageAreaAccessControl & KeyringRecordStorageArea;
  readonly session: StorageAreaAccessControl & UnlockSessionStorageArea;
}

export interface ExtensionStorageChange {
  readonly oldValue?: unknown;
  readonly newValue?: unknown;
}

export interface ExtensionStorageChangeEvent {
  addListener(listener: (
    changes: Record<string, ExtensionStorageChange>,
    areaName: string,
  ) => void): void;
  removeListener(listener: (
    changes: Record<string, ExtensionStorageChange>,
    areaName: string,
  ) => void): void;
}

export interface ObservableExtensionBackgroundStorageApi
  extends ExtensionBackgroundStorageApi {
  readonly onChanged: ExtensionStorageChangeEvent;
}

export interface ExtensionBackgroundRuntime {
  /** Readiness-gated facade; the raw lifecycle owner never escapes bootstrap. */
  readonly keyring: KeyringLifecycle;
  readonly ready: Promise<boolean>;
}

export interface ExtensionBackgroundChromeApi {
  readonly storage: ObservableExtensionBackgroundStorageApi;
  readonly runtime: ProviderRuntimeApi;
  readonly windows: ApprovalWindowsApi;
}

export interface ExtensionBackgroundApplication extends ExtensionBackgroundRuntime {
  readonly runtimeBoundariesReady: Promise<RuntimeBoundaries>;
  /** Internal-only launcher; no browser message route receives this capability. */
  readonly approvalWindows: ApprovalWindowLauncher;
  /** Rejects on a post-startup record-change cleanup failure. */
  readonly fatal: Promise<never>;
  dispose(): void;
}

/** Shipped startup owns this lifecycle, but exposes none of its record methods. */
export interface ApprovalStartupLifecycle extends ApprovalReviewOwner {
  invalidateAfterWorkerRestart(): Promise<number>;
  close(): void;
}

function requireStorageChangeEvent(value: unknown): ExtensionStorageChangeEvent {
  if (typeof value !== "object" || value === null) {
    throw new TypeError("extension background: storage.onChanged must be an event");
  }
  const event = value as Partial<ExtensionStorageChangeEvent>;
  if (typeof event.addListener !== "function" || typeof event.removeListener !== "function") {
    throw new TypeError(
      "extension background: storage.onChanged must support addListener/removeListener",
    );
  }
  return event as ExtensionStorageChangeEvent;
}

function requireApprovalStartupLifecycle(value: unknown): ApprovalStartupLifecycle {
  if (typeof value !== "object" || value === null) {
    throw new TypeError("extension background: approval lifecycle must be an object");
  }
  const lifecycle = value as Partial<ApprovalStartupLifecycle>;
  if (
    typeof lifecycle.read !== "function" ||
    typeof lifecycle.reject !== "function" ||
    typeof lifecycle.cancel !== "function" ||
    typeof lifecycle.invalidateAfterWorkerRestart !== "function" ||
    typeof lifecycle.close !== "function"
  ) {
    throw new TypeError(
      "extension background: approval lifecycle must support review, rejection, cancellation, invalidation, and close",
    );
  }
  return value as ApprovalStartupLifecycle;
}

export class BackgroundNotReadyError extends Error {
  constructor(operation: string, state: "pending" | "failed", cause?: unknown) {
    super(`extension background: initialization ${state}; ${operation} refused`,
      cause === undefined ? {} : { cause });
    this.name = "BackgroundNotReadyError";
  }
}

class BackgroundReadinessGate {
  #state: "pending" | "ready" | "failed" = "pending";
  #failure: unknown;
  readonly ready: Promise<boolean>;

  constructor(initialization: Promise<boolean>) {
    this.ready = initialization.then(
      (restored) => {
        this.#state = "ready";
        return restored;
      },
      (error: unknown) => {
        this.#state = "failed";
        this.#failure = error;
        throw error;
      },
    );
  }

  error(operation: string): BackgroundNotReadyError | null {
    if (this.#state === "ready") return null;
    return new BackgroundNotReadyError(
      operation,
      this.#state,
      this.#state === "failed" ? this.#failure : undefined,
    );
  }
}

class ReadyKeyringLifecycle implements KeyringLifecycle {
  readonly #owner: KeyringLifecycleOwner;
  readonly #gate: BackgroundReadinessGate;

  constructor(
    owner: KeyringLifecycleOwner,
    gate: BackgroundReadinessGate,
  ) {
    this.#owner = owner;
    this.#gate = gate;
  }

  private run<T>(operation: string, use: () => Promise<T>): Promise<T> {
    const unavailable = this.#gate.error(operation);
    return unavailable === null ? use() : Promise.reject(unavailable);
  }

  isUnlocked(): Promise<boolean> {
    return this.run("read unlock state", () => this.#owner.isUnlocked());
  }

  lock(): Promise<void> {
    return this.run("lock keyring", () => this.#owner.lock());
  }

  replacePersistentRecord(value: unknown): Promise<void> {
    return this.run("replace persistent record", () =>
      this.#owner.replacePersistentRecord(value));
  }

  clearPersistentRecord(): Promise<void> {
    return this.run("clear persistent record", () =>
      this.#owner.clearPersistentRecord());
  }

  unlockWithPassword(params: UnlockKeyringWithPasswordParams): Promise<void> {
    const unavailable = this.#gate.error("unlock keyring with password");
    if (unavailable !== null) {
      if (
        typeof params === "object" &&
        params !== null &&
        params.passwordBytes instanceof Uint8Array
      ) {
        params.passwordBytes.fill(0);
      }
      return Promise.reject(unavailable);
    }
    return this.#owner.unlockWithPassword(params);
  }

  readAuthenticatedSessionIdentity(
    operation: string,
  ): Promise<AuthenticatedSessionIdentity> {
    return this.run(operation, () =>
      this.#owner.readAuthenticatedSessionIdentity(operation));
  }

  useSessionSignerBytes(
    operation: string,
    use: (lease: SessionSignerLease) => Promise<Uint8Array>,
  ): Promise<Uint8Array> {
    return this.run(operation, () => this.#owner.useSessionSignerBytes(operation, use));
  }
}

interface InitializedBackground {
  readonly owner: KeyringLifecycleOwner;
  readonly runtime: ExtensionBackgroundRuntime;
}

function initializeBackground(
  storage: ExtensionBackgroundStorageApi,
  runtimeId: string,
  options: ExtensionBackgroundOptions = {},
  approvalInitialization?: Promise<unknown>,
): InitializedBackground {
  const owner = new KeyringLifecycleOwner(
    storage.local,
    storage.session,
    runtimeId,
    {
      ...options,
      expectedContext: options.expectedContext ?? shippedExpectedKeyringContext(),
    },
  );
  const keyringInitialization = restrictStorageToTrustedContexts(storage)
    .then(() => owner.restore());
  const initialization = approvalInitialization === undefined
    ? keyringInitialization
    : Promise.all([keyringInitialization, approvalInitialization])
      .then(([restored]) => restored);
  const gate = new BackgroundReadinessGate(initialization);
  return {
    owner,
    runtime: {
      keyring: Object.freeze(new ReadyKeyringLifecycle(owner, gate)),
      ready: gate.ready,
    },
  };
}

/**
 * Establish the storage trust boundary before reading even the ephemeral unlock
 * record. The returned promise is the only readiness signal future handlers may
 * await; adding a message surface without awaiting it would reopen the boundary.
 */
export function bootstrapBackground(
  storage: ExtensionBackgroundStorageApi,
  runtimeId: string,
  options: ExtensionBackgroundOptions = {},
): ExtensionBackgroundRuntime {
  return initializeBackground(storage, runtimeId, options).runtime;
}

/**
 * Register the zero-privilege wake listener during top-level worker evaluation.
 * MV3 can dispatch the event that starts a worker before any promise settles, so
 * asynchronous listener registration would miss connections after suspension.
 * Provider and popup boundaries return fixed unavailable responses. The approval
 * page can read/reject/cancel only after `background.ready`; its listener is
 * still registered synchronously so a wake connection is queued behind that
 * mandatory gate rather than missed.
 */
export function startBackground(
  chromeApi: ExtensionBackgroundChromeApi,
  approvalLifecycleValue: ApprovalStartupLifecycle,
): ExtensionBackgroundApplication {
  const approvalLifecycle = requireApprovalStartupLifecycle(
    approvalLifecycleValue,
  );
  let approvalClosed = false;
  const closeApproval = (): void => {
    if (approvalClosed) return;
    approvalClosed = true;
    approvalLifecycle.close();
  };
  let resolveApprovalRuntimeReady!: () => void;
  let rejectApprovalRuntimeReady!: (error: unknown) => void;
  const approvalRuntimeReady = new Promise<void>((resolve, reject) => {
    resolveApprovalRuntimeReady = resolve;
    rejectApprovalRuntimeReady = reject;
  });
  // A failed bootstrap can occur before any approval page connects. Keep the
  // deferred gate observed while preserving its rejection for future handlers.
  void approvalRuntimeReady.catch(() => undefined);
  const queuedApprovalFatals: unknown[] = [];
  let reportApprovalFatal = (error: unknown): void => {
    if (queuedApprovalFatals.length === 0) queuedApprovalFatals.push(error);
  };
  let boundary!: RuntimeBoundaries;
  let boundaryInstalled = false;
  let approvalWindowOwner!: InstalledApprovalWindowOwner;
  let approvalWindowOwnerInstalled = false;
  try {
    boundary = installRuntimeBoundaries(chromeApi.runtime, {
      approvals: approvalLifecycle,
      ready: approvalRuntimeReady,
      projectReview: decodeSessionApprovalReview,
      onFatal: (error) => reportApprovalFatal(error),
    });
    boundaryInstalled = true;
    approvalWindowOwner = installApprovalWindowOwner(chromeApi.windows, {
      runtimeId: chromeApi.runtime.id,
      approvals: approvalLifecycle,
      ready: approvalRuntimeReady,
      onFatal: (error) => reportApprovalFatal(error),
    });
    approvalWindowOwnerInstalled = true;
  } catch (error) {
    rejectApprovalRuntimeReady(error);
    const cleanupErrors: unknown[] = [];
    if (boundaryInstalled) {
      try {
        boundary.dispose();
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
    }
    if (approvalWindowOwnerInstalled) {
      try {
        approvalWindowOwner.dispose();
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
    }
    try {
      closeApproval();
    } catch (cleanupError) {
      cleanupErrors.push(cleanupError);
    }
    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        [error, ...cleanupErrors],
        "runtime registration and background cleanup both failed",
      );
    }
    throw error;
  }
  let background: ExtensionBackgroundRuntime;
  let keyringOwner: KeyringLifecycleOwner;
  try {
    const approvalInitialization = Promise.resolve(
      approvalLifecycle.invalidateAfterWorkerRestart(),
    ).then((invalidated) => {
      if (!Number.isSafeInteger(invalidated) || invalidated < 0) {
        throw new TypeError(
          "extension background: approval invalidation count is malformed",
        );
      }
    });
    const initialized = initializeBackground(
      chromeApi.storage,
      chromeApi.runtime.id,
      {},
      approvalInitialization,
    );
    background = initialized.runtime;
    keyringOwner = initialized.owner;
    void background.ready.then(
      () => resolveApprovalRuntimeReady(),
      (error: unknown) => rejectApprovalRuntimeReady(error),
    );
  } catch (error) {
    rejectApprovalRuntimeReady(error);
    const cleanupErrors: unknown[] = [];
    try {
      boundary.dispose();
    } catch (cleanupError) {
      cleanupErrors.push(cleanupError);
    }
    try {
      approvalWindowOwner.dispose();
    } catch (cleanupError) {
      cleanupErrors.push(cleanupError);
    }
    try {
      closeApproval();
    } catch (cleanupError) {
      cleanupErrors.push(cleanupError);
    }
    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        [error, ...cleanupErrors],
        "background initialization and approval cleanup both failed",
      );
    }
    throw error;
  }
  let disposed = false;
  let fatalSettled = false;
  let storageChanges: ExtensionStorageChangeEvent | undefined;
  let storageListenerRegistered = false;
  let rejectFatal!: (error: unknown) => void;
  const fatal = new Promise<never>((_resolve, reject) => {
    rejectFatal = reject;
  });
  const closeRuntimeSurface = (): unknown[] => {
    const cleanupErrors: unknown[] = [];
    if (storageListenerRegistered) {
      try {
        storageChanges!.removeListener(onStorageChanged);
        storageListenerRegistered = false;
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    try {
      boundary.dispose();
    } catch (error) {
      cleanupErrors.push(error);
    }
    try {
      approvalWindowOwner.dispose();
    } catch (error) {
      cleanupErrors.push(error);
    }
    try {
      closeApproval();
    } catch (error) {
      cleanupErrors.push(error);
    }
    return cleanupErrors;
  };
  const closeFailure = (error: unknown, message: string): unknown => {
    const cleanupErrors = closeRuntimeSurface();
    return cleanupErrors.length === 0
      ? error
      : new AggregateError([error, ...cleanupErrors], message);
  };
  const failClosed = (error: unknown): void => {
    if (fatalSettled) return;
    fatalSettled = true;
    disposed = true;
    rejectFatal(closeFailure(error, "record invalidation and runtime cleanup both failed"));
  };
  reportApprovalFatal = failClosed;
  if (queuedApprovalFatals.length > 0) failClosed(queuedApprovalFatals[0]);
  queuedApprovalFatals.length = 0;
  const onStorageChanged = (
    changes: unknown,
    areaName: string,
  ): void => {
    if (disposed || areaName !== "local") return;
    let recordChanged = false;
    try {
      recordChanged = typeof changes !== "object" || changes === null
        ? true
        : Object.hasOwn(changes, KEYRING_RECORD_STORAGE_KEY);
    } catch {
      // A malformed Chrome event for the local area is not a state on which
      // session authority may safely remain live.
      recordChanged = true;
    }
    if (!recordChanged) return;
    try {
      // lock() increments the transition, aborts leases, and zeroes owned key
      // bytes synchronously before its storage-removal promise is returned.
      void keyringOwner.lock().catch(failClosed);
    } catch (error) {
      failClosed(error);
    }
  };
  try {
    storageChanges = requireStorageChangeEvent(chromeApi.storage.onChanged);
    // Set this before calling Chrome so an adapter that registers and then
    // throws is still rolled back by the catch path.
    storageListenerRegistered = true;
    storageChanges.addListener(onStorageChanged);
  } catch (error) {
    throw closeFailure(error, "storage-change registration and runtime cleanup both failed");
  }
  const runtimeBoundariesReady = background.ready.then(
    () => {
      if (disposed) {
        throw new ProviderPortStateError(
          "background disposed before runtime boundaries became ready",
        );
      }
      return boundary;
    },
    (error: unknown) => {
      disposed = true;
      throw closeFailure(error, "background initialization and runtime cleanup both failed");
    },
  );
  const approvalWindows: ApprovalWindowLauncher = Object.freeze({
    launch(requestId: string, signal: AbortSignal): Promise<void> {
      return approvalWindowOwner.launch(requestId, signal);
    },
  });

  return {
    ...background,
    runtimeBoundariesReady,
    approvalWindows,
    fatal,
    dispose(): void {
      if (disposed) return;
      disposed = true;
      const cleanupErrors = closeRuntimeSurface();
      if (cleanupErrors.length === 1) throw cleanupErrors[0];
      if (cleanupErrors.length > 1) {
        throw new AggregateError(cleanupErrors, "background runtime cleanup failed");
      }
    },
  };
}
