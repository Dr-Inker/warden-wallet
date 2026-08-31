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
const expiry = element<HTMLTimeElement>("#expiry-value");
const expiryCountdown = element<HTMLElement>("#expiry-countdown");
const requestIdElement = element<HTMLElement>("#request-id-value");
const sessionSigner = element<HTMLElement>("#session-signer-value");
const sessionAccount = element<HTMLElement>("#session-account-value");
const registry = element<HTMLElement>("#registry-value");
const wardenProgram = element<HTMLElement>("#warden-program-value");
const memoProgram = element<HTMLElement>("#memo-program-value");
const genesisHash = element<HTMLElement>("#genesis-hash-value");
const recentBlockhash = element<HTMLElement>("#recent-blockhash-value");
const computeLimit = element<HTMLElement>("#compute-limit-value");
const heapFrame = element<HTMLElement>("#heap-frame-value");
const messageSize = element<HTMLElement>("#message-size-value");
const rejectButton = element<HTMLButtonElement>("[data-action=reject]");
const approveButton = element<HTMLButtonElement>("[data-action=approve]");
const capabilityTitle = element<HTMLElement>("#capability-title");
const capabilityMessage = element<HTMLElement>("#capability-message");

let port: ApprovalUiPort | undefined;
let requestId: string;
let phase:
  | "awaiting-review"
  | "review-visible"
  | "awaiting-approve"
  | "awaiting-reject"
  | "terminal" = "awaiting-review";
let correlationId = "";
let expiryWallClock = 0;
let expiryMonotonicDeadline = 0;
let expiryTimer: ReturnType<typeof globalThis.setTimeout> | undefined;

function setStatus(state: string, message: string): void {
  status.dataset.state = state;
  status.textContent = message;
}

function clearExpiryTimer(): void {
  if (expiryTimer === undefined) return;
  globalThis.clearTimeout(expiryTimer);
  expiryTimer = undefined;
}

function remainingLabel(milliseconds: number): string {
  const totalSeconds = Math.max(1, Math.ceil(milliseconds / 1_000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return minutes === 0 ? `${seconds}s` : `${minutes}m ${seconds}s`;
}

function expireUi(): void {
  if (phase === "terminal") return;
  phase = "terminal";
  clearExpiryTimer();
  rejectButton.disabled = true;
  approveButton.disabled = true;
  expiryCountdown.textContent = "Expired";
  setStatus("expired", "Request expired. No signature was produced.");
  try {
    port?.disconnect();
  } catch {
    // The durable owner still resolves expiry on its next clock-aware read.
  }
}

function refreshExpiry(): void {
  clearExpiryTimer();
  if (phase !== "review-visible") return;
  // Use the more conservative of absolute wall time and an anchored monotonic
  // deadline. A backward wall-clock jump may never extend a displayed request;
  // a forward jump closes it on the next tick/resume check.
  const remaining = Math.min(
    expiryWallClock - Date.now(),
    expiryMonotonicDeadline - globalThis.performance.now(),
  );
  if (!Number.isFinite(remaining) || remaining <= 0) {
    expireUi();
    return;
  }
  expiryCountdown.textContent = `Expires in ${remainingLabel(remaining)}`;
  expiryTimer = globalThis.setTimeout(
    refreshExpiry,
    Math.max(50, Math.min(1_000, Math.ceil(remaining))),
  );
}

function closeUi(state: "closed" | "unavailable", message: string): void {
  if (phase === "terminal") return;
  phase = "terminal";
  clearExpiryTimer();
  rejectButton.disabled = true;
  approveButton.disabled = true;
  setStatus(state, message);
  try {
    port?.disconnect();
  } catch {
    // A disappearing background already closes the request's live page lane.
  }
}

function renderReview(review: ApprovalReviewDetails, canApprove: boolean): void {
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
  const expiryIso = new Date(review.expiresAt).toISOString();
  expiry.dateTime = expiryIso;
  expiry.textContent = expiryIso;
  requestIdElement.textContent = review.requestId;
  sessionSigner.textContent = review.sessionSigner;
  sessionAccount.textContent = review.sessionAccount;
  registry.textContent = review.registry;
  wardenProgram.textContent = review.wardenProgram;
  memoProgram.textContent = review.memoProgram;
  genesisHash.textContent = review.genesisHash;
  recentBlockhash.textContent = review.recentBlockhash;
  computeLimit.textContent = `${review.computeUnitLimit.toLocaleString("en-US")} units`;
  heapFrame.textContent = `${review.heapFrameBytes.toLocaleString("en-US")} bytes`;
  messageSize.textContent =
    `${review.messageByteLength.toLocaleString("en-US")} message bytes · ` +
    `${review.memoByteLength.toLocaleString("en-US")} memo bytes`;
  const now = Date.now();
  expiryWallClock = review.expiresAt;
  expiryMonotonicDeadline = globalThis.performance.now() +
    Math.max(0, review.expiresAt - now);
  phase = "review-visible";
  rejectButton.disabled = false;
  approveButton.disabled = !canApprove;
  approveButton.textContent = canApprove ? "Approve and sign" : "Signing unavailable";
  capabilityTitle.textContent = canApprove ? "Signing enabled." : "Review only.";
  capabilityMessage.textContent = canApprove
    ? " Approval signs only this digest-authenticated transaction. Provider delivery remains unavailable in this build."
    : " Signing and provider success are disabled in this build. This page cannot approve, sign, send, or change the account or network.";
  setStatus("review", canApprove
    ? "Exact durable message decoded locally and ready for approval."
    : "Exact durable message decoded locally. Signing remains unavailable.");
  refreshExpiry();
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
      renderReview(response.result.review, response.result.canApprove);
      return;
    }
    if (
      phase === "awaiting-approve" &&
      response.result.status === "approved" &&
      response.result.requestId === requestId
    ) {
      phase = "terminal";
      clearExpiryTimer();
      rejectButton.disabled = true;
      approveButton.disabled = true;
      setStatus(
        "approved",
        "Request approved and signed. Provider delivery remains unavailable.",
      );
      port?.disconnect();
      return;
    }
    if (
      phase === "awaiting-reject" &&
      response.result.status === "rejected" &&
      response.result.requestId === requestId
    ) {
      phase = "terminal";
      clearExpiryTimer();
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
    clearExpiryTimer();
    rejectButton.disabled = true;
    approveButton.disabled = true;
    setStatus(
      "closed",
      "The approval connection closed. The request is no longer actionable.",
    );
  });

  rejectButton.addEventListener("click", () => {
    if (phase !== "review-visible" || rejectButton.disabled) return;
    phase = "awaiting-reject";
    clearExpiryTimer();
    rejectButton.disabled = true;
    approveButton.disabled = true;
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

  approveButton.addEventListener("click", () => {
    if (phase !== "review-visible" || approveButton.disabled) return;
    phase = "awaiting-approve";
    clearExpiryTimer();
    rejectButton.disabled = true;
    approveButton.disabled = true;
    correlationId = mintCorrelationId();
    setStatus("loading", "Signing the exact durable request…");
    try {
      port?.postMessage({
        version: 1,
        type: "request",
        correlationId,
        method: "approval:approve",
        params: { requestId },
      });
    } catch {
      closeUi("closed", "The approval request could not be delivered.");
    }
  });

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") refreshExpiry();
  });
  addEventListener("focus", refreshExpiry);
  addEventListener("pageshow", refreshExpiry);
  addEventListener("pagehide", () => {
    closeUi(
      "closed",
      "This approval page was left. The request is no longer actionable.",
    );
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
