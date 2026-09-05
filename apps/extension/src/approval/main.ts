import {
  APPROVAL_UI_PORT_NAME,
  parseApprovalRequestId,
  parseApprovalUiResponse,
  type ApprovalReviewDetails,
} from "../approval-protocol.js";
import { ApprovalArmGuard } from "./approval-arm.js";

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
const reviewEvidence = element<HTMLElement>("#review-evidence");
const approvalHelp = element<HTMLElement>("#approval-help");

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
/**
 * Audit A-1. The approve control is not armed by the review response; it arms
 * only after this guard's dwell/pointer/trust conditions hold, and a click is
 * turned into an approve request only if the guard also accepts the activation
 * behind it.
 */
const arm = new ApprovalArmGuard();
let approvalEnabled = false;
let armTimer: ReturnType<typeof globalThis.setTimeout> | undefined;

/** One monotonic clock for every arming timestamp, shared with event.timeStamp. */
function armClock(): number {
  return globalThis.performance.now();
}

function setStatus(state: string, message: string): void {
  status.dataset.state = state;
  status.textContent = message;
}

function clearArmTimer(): void {
  if (armTimer === undefined) return;
  globalThis.clearTimeout(armTimer);
  armTimer = undefined;
}

/**
 * Recompute whether the approve control may be pressed, and schedule exactly one
 * re-check when the only outstanding condition is the remaining dwell. The
 * control is disabled in every state that is not "armed, approvable, and still
 * showing this request", so losing focus re-disables it immediately.
 */
function refreshArmState(): void {
  clearArmTimer();
  if (phase !== "review-visible" || !approvalEnabled) {
    approveButton.disabled = true;
    return;
  }
  const now = armClock();
  if (arm.isArmed(now)) {
    approveButton.disabled = false;
    return;
  }
  approveButton.disabled = true;
  const remaining = arm.msUntilArmed(now);
  if (remaining === undefined) return;
  armTimer = globalThis.setTimeout(refreshArmState, Math.max(16, Math.ceil(remaining)));
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
  clearArmTimer();
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
  clearArmTimer();
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
  reviewEvidence.hidden = false;
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
  approvalEnabled = canApprove;
  approvalHelp.hidden = !canApprove;
  // The control stays closed until the guard arms it; a review response is a
  // reason to START the dwell, never a reason to accept a click (audit A-1).
  approveButton.disabled = true;
  arm.noteReviewVisible(armClock());
  if (document.hasFocus()) arm.noteFocus(armClock());
  refreshArmState();
  approveButton.textContent = canApprove ? "Approve and sign" : "Signing unavailable";
  capabilityTitle.textContent = canApprove ? "Signing enabled." : "Review only.";
  capabilityMessage.textContent = canApprove
    ? " Approval signs only this digest-authenticated transaction. The background can return only the durable signed result to the requesting page."
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
      clearArmTimer();
      rejectButton.disabled = true;
      approveButton.disabled = true;
      setStatus(
        "approved",
        "Request approved and signed. The durable result is ready for the requesting page.",
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
      clearArmTimer();
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
    clearArmTimer();
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
    clearArmTimer();
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

  approveButton.addEventListener("click", (event) => {
    if (phase !== "review-visible" || approveButton.disabled) return;
    // Audit A-1. Refuse silently: an untrusted event, an activation primed
    // before the control armed, or a focus/visibility loss inside the dwell
    // produces no approve request and leaves the request pending.
    if (!arm.acceptsActivation(event.timeStamp, event.isTrusted)) {
      refreshArmState();
      return;
    }
    phase = "awaiting-approve";
    clearExpiryTimer();
    clearArmTimer();
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
    if (document.visibilityState === "visible") {
      refreshExpiry();
      if (document.hasFocus()) arm.noteFocus(armClock());
    } else {
      arm.noteVisibilityLoss(armClock());
    }
    refreshArmState();
  });
  addEventListener("focus", () => {
    refreshExpiry();
    arm.noteFocus(armClock());
    refreshArmState();
  });
  addEventListener("blur", () => {
    arm.noteFocusLoss(armClock());
    refreshArmState();
  });
  addEventListener("pageshow", refreshExpiry);
  // One genuine pointer move anywhere in the document is the human-presence
  // half of arming; the press/release pair is scoped to the control itself.
  document.addEventListener("pointermove", (event) => {
    arm.notePointerMove(event.timeStamp, event.isTrusted);
    refreshArmState();
  }, { passive: true });
  approveButton.addEventListener("pointerdown", (event) => {
    arm.notePointerDown(event.timeStamp, event.isTrusted);
  });
  approveButton.addEventListener("pointerup", (event) => {
    arm.notePointerUp(event.timeStamp, event.isTrusted);
  });
  approveButton.addEventListener("keydown", (event) => {
    if (event.repeat && (event.key === "Enter" || event.key === " ")) {
      event.preventDefault();
    }
    arm.noteKeyActivation(event.timeStamp, event.isTrusted, event.key, event.repeat);
  });
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
