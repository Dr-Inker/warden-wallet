import {
  POPUP_PORT_NAME,
  isPopupUnavailableResponse,
} from "../popup-protocol.js";

interface PopupPort {
  readonly onMessage: {
    addListener(listener: (message: unknown) => void): void;
  };
  readonly onDisconnect: {
    addListener(listener: () => void): void;
  };
  postMessage(message: unknown): void;
  disconnect(): void;
}

interface PopupChromeApi {
  readonly runtime: {
    readonly lastError?: { readonly message: string };
    connect(options: { readonly name: string }): PopupPort;
  };
}

function requireChrome(value: unknown): PopupChromeApi {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly runtime?: unknown }).runtime !== "object" ||
    (value as { readonly runtime?: unknown }).runtime === null ||
    typeof ((value as { readonly runtime: { readonly connect?: unknown } }).runtime.connect) !==
      "function"
  ) {
    throw new Error("Warden popup: Chrome runtime API is unavailable");
  }
  return value as PopupChromeApi;
}

function requireStatusElement(): HTMLElement {
  const element = document.querySelector<HTMLElement>("#boundary-status");
  if (element === null) throw new Error("Warden popup: status element is missing");
  return element;
}

function mintCorrelationId(): string {
  const bytes = new Uint8Array(16);
  try {
    globalThis.crypto.getRandomValues(bytes);
    let id = "popup_";
    for (const byte of bytes) id += byte.toString(16).padStart(2, "0");
    return id;
  } finally {
    bytes.fill(0);
  }
}

const status = requireStatusElement();
const retry = document.querySelector<HTMLButtonElement>("#retry-status");
if (retry === null) throw new Error("Warden popup: retry control is missing");
const retryButton = retry;
let cancelCheck: (() => void) | undefined;

function checkBoundary(): void {
  cancelCheck?.();
  retryButton.disabled = true;
  status.dataset.boundary = "checking";
  status.textContent = "Checking the extension connection…";
  let settled = false;
  let port: PopupPort | undefined;
  let timer: ReturnType<typeof globalThis.setTimeout> | undefined;

  function finish(state: "closed" | "unavailable", message: string): void {
    if (settled) return;
    settled = true;
    globalThis.clearTimeout(timer);
    status.dataset.boundary = state;
    status.textContent = message;
    retryButton.disabled = false;
    try {
      port?.disconnect();
    } catch {
      // A vanished worker does not prevent retrying from a new connection.
    }
  }

  cancelCheck = () => {
    settled = true;
    globalThis.clearTimeout(timer);
    try { port?.disconnect(); } catch { /* Already disconnected. */ }
  };

  try {
    const chromeApi = requireChrome(
      (globalThis as { readonly chrome?: unknown }).chrome,
    );
    const correlationId = mintCorrelationId();
    port = chromeApi.runtime.connect({ name: POPUP_PORT_NAME });
    timer = globalThis.setTimeout(() => {
      finish("closed", "The extension did not respond. Check again to reconnect.");
    }, 5_000);

    port.onMessage.addListener((message) => {
      if (settled) return;
      if (
        !isPopupUnavailableResponse(message) ||
        message.correlationId !== correlationId
      ) {
        finish("closed", "Warden's background returned an invalid response.");
        return;
      }
      finish("unavailable", "Wallet controls are not enabled in this pre-alpha build.");
    });

    port.onDisconnect.addListener(() => {
      // Consume Chrome's error without displaying browser-internal wording.
      void chromeApi.runtime.lastError;
      finish("closed", "The extension connection closed. Check again to reconnect.");
    });

    port.postMessage({
      version: 1,
      type: "request",
      correlationId,
      method: "popup:getBoundaryStatus",
      params: {},
    });
  } catch {
    finish("closed", "The extension is unavailable. Load the development extension and check again.");
  }
}

retryButton.addEventListener("click", () => {
  if (!retryButton.disabled) checkBoundary();
});
globalThis.addEventListener("pagehide", () => cancelCheck?.(), { once: true });
checkBoundary();
