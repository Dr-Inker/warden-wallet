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
  PersistentKeyringRecordStore,
  type KeyringRecordStorageArea,
} from "./keyring-record-store.js";

export interface ExtensionBackgroundStorageApi extends ExtensionStorageAccessApi {
  readonly local: StorageAreaAccessControl & KeyringRecordStorageArea;
  readonly session: StorageAreaAccessControl & UnlockSessionStorageArea;
}

export interface ExtensionBackgroundRuntime {
  readonly sessions: UnlockSessionOwner;
  readonly ready: Promise<boolean>;
}

export interface ExtensionBackgroundChromeApi {
  readonly storage: ExtensionBackgroundStorageApi;
  readonly runtime: ProviderRuntimeApi;
}

export interface ExtensionBackgroundApplication extends ExtensionBackgroundRuntime {
  readonly runtimeBoundariesReady: Promise<UnavailableRuntimeBoundaries>;
  dispose(): void;
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
      boundary.dispose();
      throw error;
    },
  );

  return {
    ...background,
    runtimeBoundariesReady,
    dispose(): void {
      if (disposed) return;
      disposed = true;
      boundary.dispose();
    },
  };
}
