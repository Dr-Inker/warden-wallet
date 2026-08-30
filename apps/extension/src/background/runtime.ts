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
  installUnavailableProviderBoundary,
  ProviderPortStateError,
  type ProviderRuntimeApi,
  type UnavailableProviderBoundary,
} from "./provider-port.js";

export interface ExtensionBackgroundStorageApi extends ExtensionStorageAccessApi {
  readonly local: StorageAreaAccessControl;
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
  readonly providerReady: Promise<UnavailableProviderBoundary>;
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
  const sessions = new UnlockSessionOwner(storage.session, options);
  const ready = restrictStorageToTrustedContexts(storage).then(() => sessions.restore());
  return { sessions, ready };
}

/**
 * Install no message listener until trusted-only storage setup and session
 * restoration have both completed. The installed provider remains deliberately
 * zero privilege and returns METHOD_UNAVAILABLE for every valid method.
 */
export function startBackground(
  chromeApi: ExtensionBackgroundChromeApi,
): ExtensionBackgroundApplication {
  const background = bootstrapBackground(chromeApi.storage);
  let boundary: UnavailableProviderBoundary | undefined;
  let disposed = false;
  const providerReady = background.ready.then(() => {
    if (disposed) {
      throw new ProviderPortStateError("background disposed before provider setup");
    }
    boundary = installUnavailableProviderBoundary(chromeApi.runtime);
    if (disposed) {
      boundary.dispose();
      throw new ProviderPortStateError("background disposed during provider setup");
    }
    return boundary;
  });

  return {
    ...background,
    providerReady,
    dispose(): void {
      if (disposed) return;
      disposed = true;
      boundary?.dispose();
    },
  };
}
