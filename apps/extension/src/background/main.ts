import {
  bootstrapBackground,
  type ExtensionBackgroundStorageApi,
} from "./runtime.js";

function requireBackgroundStorage(value: unknown): ExtensionBackgroundStorageApi {
  if (typeof value !== "object" || value === null) {
    throw new Error("Warden extension: Chrome storage API is unavailable");
  }
  const chromeApi = value as { readonly storage?: unknown };
  if (typeof chromeApi.storage !== "object" || chromeApi.storage === null) {
    throw new Error("Warden extension: Chrome storage API is unavailable");
  }
  return chromeApi.storage as ExtensionBackgroundStorageApi;
}

const chromeApi = (globalThis as { readonly chrome?: unknown }).chrome;
const background = bootstrapBackground(requireBackgroundStorage(chromeApi));

// No message/provider surface exists yet. Keep initialization failure visible to
// extension diagnostics while leaving the worker with no callable wallet API.
void background.ready.catch((error: unknown) => {
  console.error("Warden extension background initialization failed", error);
});
