import {
  installPageProviderBridge,
  type ContentRuntimeApi,
  type ContentWindowApi,
} from "./bridge.js";

function requireContentRuntime(value: unknown): ContentRuntimeApi {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly connect?: unknown }).connect !== "function"
  ) {
    throw new Error("Warden extension: content runtime API is unavailable");
  }
  return value as ContentRuntimeApi;
}

const chromeApi = (globalThis as { readonly chrome?: { readonly runtime?: unknown } }).chrome;
const runtime = requireContentRuntime(chromeApi?.runtime);

installPageProviderBridge(
  window as unknown as ContentWindowApi,
  runtime,
);
