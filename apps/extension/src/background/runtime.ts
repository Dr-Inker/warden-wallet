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
  installUnavailableRuntimeBoundaries,
  type UnavailableRuntimeBoundaries,
} from "./runtime-ports.js";
import {
  KEYRING_RECORD_STORAGE_KEY,
  type KeyringRecordStorageArea,
} from "./keyring-record-store.js";
import {
  KeyringLifecycleOwner,
  type KeyringLifecycle,
  type SessionSignerLease,
  type UnlockKeyringWithPasswordParams,
} from "./keyring-lifecycle.js";

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
}

export interface ExtensionBackgroundApplication extends ExtensionBackgroundRuntime {
  readonly runtimeBoundariesReady: Promise<UnavailableRuntimeBoundaries>;
  /** Rejects on a post-startup record-change cleanup failure. */
  readonly fatal: Promise<never>;
  dispose(): void;
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
  options: { readonly readNow?: () => number } = {},
): InitializedBackground {
  const owner = new KeyringLifecycleOwner(
    storage.local,
    storage.session,
    runtimeId,
    options,
  );
  const initialization = restrictStorageToTrustedContexts(storage)
    .then(() => owner.restore());
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
  options: { readonly readNow?: () => number } = {},
): ExtensionBackgroundRuntime {
  return initializeBackground(storage, runtimeId, options).runtime;
}

/**
 * Register the zero-privilege wake listener during top-level worker evaluation.
 * MV3 can dispatch the event that starts a worker before any promise settles, so
 * asynchronous listener registration would miss connections after suspension.
 * These boundaries can only return fixed unavailable responses; background.ready
 * remains the mandatory gate for every future storage-backed or privileged
 * subsystem.
 */
export function startBackground(
  chromeApi: ExtensionBackgroundChromeApi,
): ExtensionBackgroundApplication {
  const boundary = installUnavailableRuntimeBoundaries(chromeApi.runtime);
  let background: ExtensionBackgroundRuntime;
  let keyringOwner: KeyringLifecycleOwner;
  try {
    const initialized = initializeBackground(
      chromeApi.storage,
      chromeApi.runtime.id,
    );
    background = initialized.runtime;
    keyringOwner = initialized.owner;
  } catch (error) {
    boundary.dispose();
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

  return {
    ...background,
    runtimeBoundariesReady,
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
