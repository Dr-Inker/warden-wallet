import {
  APPROVAL_UI_PORT_NAME,
  parseApprovalRequestId,
  parseApprovalUiResponse,
  type ApprovalReviewDetails,
} from "../approval-protocol.js";

interface ApprovalUiPort {
  readonly onMessage: {
    addListener(listener: (message: unknown) => void): void;
  };
  readonly onDisconnect: {
    addListener(listener: () => void): void;
  };
  postMessage(message: unknown): void;
  disconnect(): void;
}

interface ApprovalUiChromeApi {
  readonly runtime: {
    readonly id: string;
    readonly lastError?: { readonly message: string };
    connect(options: { readonly name: string }): ApprovalUiPort;
  };
}

function requireChrome(value: unknown): ApprovalUiChromeApi {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly runtime?: unknown }).runtime !== "object" ||
    (value as { readonly runtime?: unknown }).runtime === null
  ) {
    throw new Error("Warden approval: Chrome runtime API is unavailable");
  }
  const runtime = (value as { readonly runtime: Record<string, unknown> }).runtime;
  if (typeof runtime.id !== "string" || typeof runtime.connect !== "function") {
    throw new Error("Warden approval: Chrome runtime API is unavailable");
  }
  return value as ApprovalUiChromeApi;
}

function element<T extends HTMLElement>(selector: string): T {
  const value = document.querySelector<T>(selector);
  if (value === null) throw new Error(`Warden approval: ${selector} is missing`);
  return value;
}

function requestIdFromLocation(runtimeId: string): string {
  const url = new URL(globalThis.location.href);
  const prefix = `chrome-extension://${runtimeId}/approval.html?request=`;
  const candidate = url.search.startsWith("?request=")
    ? url.search.slice("?request=".length)
    : "";
  const requestId = parseApprovalRequestId(candidate);
  if (
    url.protocol !== "chrome-extension:" ||
    url.hostname !== runtimeId ||
    url.pathname !== "/approval.html" ||
    url.hash !== "" ||
    url.href !== `${prefix}${requestId}`
  ) {
    throw new Error("Warden approval: page URL is not one exact request");
  }
  return requestId;
}

function mintCorrelationId(): string {
  const bytes = new Uint8Array(16);
  try {
    globalThis.crypto.getRandomValues(bytes);
    let id = "approval_";
    for (const byte of bytes) id += byte.toString(16).padStart(2, "0");
    return id;
  } finally {
    bytes.fill(0);
  }
}

const NETWORK_LABELS = Object.freeze({
  "solana:mainnet": "Solana Mainnet",
  "solana:devnet": "Solana Devnet",
  "solana:testnet": "Solana Testnet",
  "solana:localnet": "Solana Localnet",
} as const);

const chromeApi = requireChrome(
  (globalThis as { readonly chrome?: unknown }).chrome,
);
const status = element<HTMLElement>("#approval-status");
const origin = element<HTMLElement>("#request-origin");
const memo = element<HTMLElement>("#memo-value");
const network = element<HTMLElement>("#network-value");
const method = element<HTMLElement>("#method-value");
const account = element<HTMLElement>("#account-value");
const digest = element<HTMLElement>("#digest-value");
const policy = element<HTMLElement>("#policy-value");
const expiry = element<HTMLElement>("#expiry-value");
const requestIdElement = element<HTMLElement>("#request-id-value");
const rejectButton = element<HTMLButtonElement>("[data-action=reject]");
const approveButton = element<HTMLButtonElement>("[data-action=approve]");

let port: ApprovalUiPort | undefined;
let requestId: string;
let phase: "awaiting-review" | "review-visible" | "awaiting-reject" | "terminal" =
  "awaiting-review";
let correlationId = "";

function setStatus(state: string, message: string): void {
  status.dataset.state = state;
  status.textContent = message;
}

function closeUi(state: "closed" | "unavailable", message: string): void {
  if (phase === "terminal") return;
  phase = "terminal";
  rejectButton.disabled = true;
  approveButton.disabled = true;
  setStatus(state, message);
  try {
    port?.disconnect();
  } catch {
    // A disappearing background already closes the request's live page lane.
  }
}

function renderReview(review: ApprovalReviewDetails): void {
  if (review.requestId !== requestId) {
    closeUi("closed", "The background returned a different request.");
    return;
  }
  origin.textContent = review.origin;
  memo.textContent = review.memo;
  network.textContent = NETWORK_LABELS[review.chain];
  method.textContent = "Sign transaction";
  account.textContent = review.account;
  digest.textContent = review.messageDigest;
  policy.textContent = String(review.policyVersion);
  expiry.textContent = new Date(review.expiresAt).toISOString();
  requestIdElement.textContent = review.requestId;
  phase = "review-visible";
  rejectButton.disabled = false;
  approveButton.disabled = true;
  setStatus(
    "review",
    "Exact durable message decoded locally. Signing remains unavailable.",
  );
}

try {
  requestId = requestIdFromLocation(chromeApi.runtime.id);
  requestIdElement.textContent = requestId;
  port = chromeApi.runtime.connect({ name: APPROVAL_UI_PORT_NAME });
  correlationId = mintCorrelationId();

  port.onMessage.addListener((message) => {
    if (phase === "terminal") return;
    let response;
    try {
      response = parseApprovalUiResponse(message);
    } catch {
      closeUi("closed", "Warden's background returned an invalid response.");
      return;
    }
    if (response.correlationId !== correlationId) {
      closeUi("closed", "Warden's background returned an unrelated response.");
      return;
    }
    if (!response.ok) {
      closeUi("unavailable", "This approval request is no longer available.");
      return;
    }
    if (phase === "awaiting-review" && response.result.status === "pending") {
      renderReview(response.result.review);
      return;
    }
    if (phase === "awaiting-reject" && response.result.status === "rejected") {
      phase = "terminal";
      rejectButton.disabled = true;
      approveButton.disabled = true;
      setStatus("rejected", "Request rejected. No signature was produced.");
      port?.disconnect();
      return;
    }
    closeUi("closed", "Warden's background returned an unexpected state.");
  });

  port.onDisconnect.addListener(() => {
    void chromeApi.runtime.lastError;
    if (phase === "terminal") return;
    phase = "terminal";
    rejectButton.disabled = true;
    approveButton.disabled = true;
    setStatus("closed", "The approval connection closed. The request was cancelled.");
  });

  rejectButton.addEventListener("click", () => {
    if (phase !== "review-visible" || rejectButton.disabled) return;
    phase = "awaiting-reject";
    rejectButton.disabled = true;
    correlationId = mintCorrelationId();
    setStatus("loading", "Rejecting the durable request…");
    try {
      port?.postMessage({
        version: 1,
        type: "request",
        correlationId,
        method: "approval:reject",
        params: { requestId },
      });
    } catch {
      closeUi("closed", "The rejection request could not be delivered.");
    }
  });

  addEventListener("pagehide", () => {
    try {
      port?.disconnect();
    } catch {
      // Browser teardown is already a closed Port lifetime.
    }
  }, { once: true });

  port.postMessage({
    version: 1,
    type: "request",
    correlationId,
    method: "approval:getReview",
    params: { requestId },
  });
} catch {
  closeUi("closed", "This page does not identify one valid approval request.");
}
