import {
  restrictStorageToTrustedContexts,
  type ExtensionStorageAccessApi,
  type StorageAreaAccessControl,
} from "./storage-access.js";
import {
  UnlockSessionOwner,
  type UnlockSessionStorageArea,
} from "./unlock-session.js";

export interface ExtensionBackgroundStorageApi extends ExtensionStorageAccessApi {
  readonly local: StorageAreaAccessControl;
  readonly session: StorageAreaAccessControl & UnlockSessionStorageArea;
}

export interface ExtensionBackgroundRuntime {
  readonly sessions: UnlockSessionOwner;
  readonly ready: Promise<boolean>;
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
