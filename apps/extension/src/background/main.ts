import {
  startBackground,
  type ExtensionBackgroundChromeApi,
} from "./runtime.js";
import { ApprovalOwner } from "./approval-owner.js";
import { IndexedDbApprovalRecordRepository } from "./approval-store.js";

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
const backgroundChrome = requireBackgroundChrome(chromeApi);
const approvalOwner = new ApprovalOwner(
  new IndexedDbApprovalRecordRepository(),
);
const background = startBackground(backgroundChrome, approvalOwner);

// Provider and popup surfaces remain fixed-unavailable. The separately routed
// approval page can only read/reject/cancel one URL-bound durable request after
// readiness; it has no signing capability. Keep initialization failure visible.
void background.runtimeBoundariesReady.catch((error: unknown) => {
  console.error("Warden extension background initialization failed", error);
});
void background.fatal.catch((error: unknown) => {
  console.error("Warden extension background record invalidation failed", error);
});
