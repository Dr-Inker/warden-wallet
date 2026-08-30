import { decodeKeyringRecordStorageValue } from "@warden/core/keyring";

import {
  restrictStorageToTrustedContexts,
  type ExtensionStorageAccessApi,
  type StorageAreaAccessControl,
} from "./storage-access.js";
import {
  UnlockSessionOwner,
  type UnlockSessionStorageArea,
} from "./unlock-session.js";
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
  PersistentKeyringRecordStore,
  type KeyringRecordStorageArea,
} from "./keyring-record-store.js";

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
  readonly sessions: UnlockSessionOwner;
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

/**
 * Establish the storage trust boundary before reading even the ephemeral unlock
 * record. The returned promise is the only readiness signal future handlers may
 * await; adding a message surface without awaiting it would reopen the boundary.
 */
export function bootstrapBackground(
  storage: ExtensionBackgroundStorageApi,
  options: { readonly readNow?: () => number } = {},
): ExtensionBackgroundRuntime {
  const keyringRecords = new PersistentKeyringRecordStore(storage.local);
  const sessions = new UnlockSessionOwner(storage.session, options);
  const ready = restrictStorageToTrustedContexts(storage).then(async () => {
    let persistentBundleId: Uint8Array | null;
    try {
      const persistentRecord = await keyringRecords.load();
      persistentBundleId = persistentRecord === null
        ? null
        : decodeKeyringRecordStorageValue(persistentRecord).bundle.bundleId;
    } catch (error) {
      try {
        await sessions.lock();
      } catch (cleanupError) {
        throw new AggregateError(
          [error, cleanupError],
          "persistent keyring validation and unlock-session cleanup both failed",
        );
      }
      throw error;
    }
    if (persistentBundleId === null) {
      // An unwrap key without its encrypted persistent record has no legitimate
      // consumer. Remove stale session material without ever parsing it.
      await sessions.lock();
      return false;
    }
    return sessions.restore(persistentBundleId);
  });
  // Do not expose the raw persistent-record owner beside the session owner.
  // Record mutation must eventually go through one composed lifecycle owner
  // that revokes any live session before replacing or clearing its record.
  return { sessions, ready };
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
  try {
    background = bootstrapBackground(chromeApi.storage);
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
      void background.sessions.lock().catch(failClosed);
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
