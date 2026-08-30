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

const chromeApi = requireChrome(
  (globalThis as { readonly chrome?: unknown }).chrome,
);
const status = requireStatusElement();
const correlationId = mintCorrelationId();
const port = chromeApi.runtime.connect({ name: POPUP_PORT_NAME });
let settled = false;

port.onMessage.addListener((message) => {
  if (settled) return;
  if (
    !isPopupUnavailableResponse(message) ||
    message.correlationId !== correlationId
  ) {
    settled = true;
    status.dataset.boundary = "closed";
    status.textContent = "Warden's background returned an invalid response.";
    port.disconnect();
    return;
  }
  settled = true;
  status.dataset.boundary = "unavailable";
  status.textContent = "Wallet controls are not enabled in this pre-alpha build.";
  port.disconnect();
});

port.onDisconnect.addListener(() => {
  // Read lastError in the callback as Chrome requires, but do not surface
  // browser-internal wording into the UI or treat it as authority.
  void chromeApi.runtime.lastError;
  if (settled) return;
  settled = true;
  status.dataset.boundary = "closed";
  status.textContent = "Warden's background boundary is unavailable.";
});

port.postMessage({
  version: 1,
  type: "request",
  correlationId,
  method: "popup:getBoundaryStatus",
  params: {},
});
