export interface StorageAreaAccessControl {
  setAccessLevel(options: { accessLevel: "TRUSTED_CONTEXTS" }): Promise<void>;
}

export interface ExtensionStorageAccessApi {
  readonly local: StorageAreaAccessControl;
  readonly session: StorageAreaAccessControl;
}

export async function restrictStorageToTrustedContexts(
  storage: ExtensionStorageAccessApi,
): Promise<void> {
  const trusted = { accessLevel: "TRUSTED_CONTEXTS" } as const;
  // `local` defaults to content-script-visible, while `session` currently defaults
  // closed. Set both explicitly: a platform default is not a Warden policy, and the
  // persistent encrypted record should not become a content-script oracle either.
  await Promise.all([
    storage.local.setAccessLevel(trusted),
    storage.session.setAccessLevel(trusted),
  ]);
}
