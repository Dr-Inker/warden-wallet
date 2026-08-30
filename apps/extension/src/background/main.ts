import {
  startBackground,
  type ExtensionBackgroundChromeApi,
} from "./runtime.js";

function requireBackgroundChrome(value: unknown): ExtensionBackgroundChromeApi {
  if (typeof value !== "object" || value === null) {
    throw new Error("Warden extension: Chrome API is unavailable");
  }
  const chromeApi = value as { readonly storage?: unknown; readonly runtime?: unknown };
  if (typeof chromeApi.storage !== "object" || chromeApi.storage === null) {
    throw new Error("Warden extension: Chrome storage API is unavailable");
  }
  if (typeof chromeApi.runtime !== "object" || chromeApi.runtime === null) {
    throw new Error("Warden extension: Chrome runtime API is unavailable");
  }
  return chromeApi as ExtensionBackgroundChromeApi;
}

const chromeApi = (globalThis as { readonly chrome?: unknown }).chrome;
const background = startBackground(requireBackgroundChrome(chromeApi));

// The only message surface returns METHOD_UNAVAILABLE after strict provenance
// and schema checks. Keep initialization failure visible to extension diagnostics.
void background.providerReady.catch((error: unknown) => {
  console.error("Warden extension background initialization failed", error);
});
