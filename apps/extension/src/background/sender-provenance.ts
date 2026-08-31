const EXTENSION_ID_PATTERN = /^[a-p]{32}$/;
const DOCUMENT_ID_PATTERN = /^[\x21-\x7e]+$/;
const UI_PATH_PATTERN = /^\/[A-Za-z0-9._/-]+$/;
const APPROVAL_REQUEST_ID_PATTERN = /^req_[0-9a-f]{32}$/;
const APPROVAL_UI_PATH = "/approval.html";

const MAX_DOCUMENT_ID_LENGTH = 128;
const MAX_ORIGIN_LENGTH = 2_048;
const MAX_SENDER_URL_LENGTH = 8_192;
const MAX_UI_PATH_LENGTH = 256;
const MAX_UI_PATHS = 16;

export class SenderProvenanceError extends Error {
  constructor(message: string) {
    super(`invalid sender provenance: ${message}`);
    this.name = "SenderProvenanceError";
  }
}

export interface ProviderProvenance {
  readonly kind: "provider";
  readonly extensionId: string;
  readonly documentId: string;
  readonly origin: string;
  readonly tabId: number;
  readonly frameId: number;
}

export interface PrivilegedUiProvenance {
  readonly kind: "privileged-ui";
  readonly extensionId: string;
  /** Chrome currently omits documentId for a tabless action popup. */
  readonly documentId: string | null;
  readonly extensionOrigin: string;
  readonly path: string;
  readonly tabId: number | null;
  readonly frameId: number | null;
}

export interface ApprovalUiProvenance {
  readonly kind: "approval-ui";
  readonly extensionId: string;
  readonly documentId: string;
  readonly extensionOrigin: string;
  readonly path: typeof APPROVAL_UI_PATH;
  readonly requestId: string;
  readonly tabId: number;
  readonly frameId: 0;
}

export interface SenderClassifierInput {
  readonly runtimeId: string;
  readonly sender: unknown;
}

export interface PrivilegedUiClassifierInput extends SenderClassifierInput {
  readonly allowedPaths: readonly string[];
}

function invalid(message: string): never {
  throw new SenderProvenanceError(message);
}

function requireRecord(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    invalid(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireRuntimeId(value: unknown): string {
  if (typeof value !== "string" || !EXTENSION_ID_PATTERN.test(value)) {
    invalid("runtime extension id is malformed");
  }
  return value;
}

function requireExtensionOwner(sender: Record<string, unknown>, runtimeId: string): void {
  if (sender.id !== runtimeId) {
    invalid("sender is not owned by this extension");
  }
}

function requireDocumentId(sender: Record<string, unknown>): string {
  const value = sender.documentId;
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_DOCUMENT_ID_LENGTH ||
    !DOCUMENT_ID_PATTERN.test(value)
  ) {
    invalid("document id is missing or malformed");
  }
  return value;
}

function requireActiveLifecycle(sender: Record<string, unknown>): void {
  const lifecycle = sender.documentLifecycle;
  // Chrome describes this field as a creation-time snapshot which may later be
  // stale. It is therefore only a rejection signal, never proof of continued
  // liveness. Provider and tab-hosted UI Ports require documentId; Chrome's current
  // tabless action-popup sender omits both fields, so that lane is instead bound to
  // the exact extension origin/path and the lifetime of the browser-owned Port.
  if (lifecycle !== undefined && lifecycle !== "active") {
    invalid("document was not active when the port opened");
  }
}

function rejectAmbiguousSenderKinds(sender: Record<string, unknown>): void {
  if (sender.nativeApplication !== undefined) {
    invalid("native application senders are not accepted");
  }
}

function requireNonNegativeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    invalid(`${name} must be a non-negative safe integer`);
  }
  return value as number;
}

function requireTabId(sender: Record<string, unknown>): number {
  const tab = requireRecord(sender.tab, "tab");
  return requireNonNegativeInteger(tab.id, "tab id");
}

function requireBoundedString(
  value: unknown,
  name: string,
  maximumLength: number,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    invalid(`${name} is missing, malformed, or too large`);
  }
  return value;
}

function parseUrl(value: string, name: string): URL {
  try {
    return new URL(value);
  } catch {
    invalid(`${name} is not a URL`);
  }
}

function requireWebOrigin(sender: Record<string, unknown>): string {
  const origin = requireBoundedString(sender.origin, "origin", MAX_ORIGIN_LENGTH);
  const parsed = parseUrl(origin, "origin");
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.origin !== origin ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    invalid("origin must be one canonical HTTP(S) origin");
  }
  return origin;
}

function requireMatchingWebUrl(sender: Record<string, unknown>, origin: string): void {
  const value = requireBoundedString(sender.url, "sender URL", MAX_SENDER_URL_LENGTH);
  const parsed = parseUrl(value, "sender URL");
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.origin !== origin ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    invalid("sender URL does not belong to the claimed web origin");
  }
}

function requireAllowedUiPaths(value: unknown): ReadonlySet<string> {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_UI_PATHS) {
    invalid("UI path allowlist is empty or too large");
  }

  const paths = new Set<string>();
  for (const path of value) {
    const pathSegments = typeof path === "string" ? path.slice(1).split("/") : [];
    if (
      typeof path !== "string" ||
      path.length > MAX_UI_PATH_LENGTH ||
      !UI_PATH_PATTERN.test(path) ||
      path.includes("%") ||
      path.includes("\\") ||
      pathSegments.some(
        (segment) => segment === "" || segment === "." || segment === "..",
      )
    ) {
      invalid("UI path allowlist contains a malformed path");
    }
    if (paths.has(path)) {
      invalid("UI path allowlist contains a duplicate path");
    }
    paths.add(path);
  }
  return paths;
}

/**
 * Derive the provider authority tuple solely from Chrome-owned Port.sender data.
 * The top-level tab URL is intentionally ignored: sender.origin/url describe the
 * actual frame, which is the security boundary for nested and cross-origin dapps.
 */
export function classifyProviderSender(input: SenderClassifierInput): ProviderProvenance {
  const runtimeId = requireRuntimeId(input.runtimeId);
  const sender = requireRecord(input.sender, "sender");
  requireExtensionOwner(sender, runtimeId);
  rejectAmbiguousSenderKinds(sender);
  const documentId = requireDocumentId(sender);
  requireActiveLifecycle(sender);
  const tabId = requireTabId(sender);
  const frameId = requireNonNegativeInteger(sender.frameId, "frame id");
  const origin = requireWebOrigin(sender);
  requireMatchingWebUrl(sender, origin);

  return Object.freeze({
    kind: "provider",
    extensionId: runtimeId,
    documentId,
    origin,
    tabId,
    frameId,
  });
}

/**
 * Privilege an extension UI only when Chrome reports this exact extension origin
 * and an exact allowlisted page. A content script shares sender.id, so id equality
 * alone is deliberately insufficient. Tab-hosted UIs must be the top frame.
 */
export function classifyPrivilegedUiSender(
  input: PrivilegedUiClassifierInput,
): PrivilegedUiProvenance {
  const runtimeId = requireRuntimeId(input.runtimeId);
  const sender = requireRecord(input.sender, "sender");
  const allowedPaths = requireAllowedUiPaths(input.allowedPaths);
  requireExtensionOwner(sender, runtimeId);
  rejectAmbiguousSenderKinds(sender);
  const documentId = sender.documentId === undefined
    ? null
    : requireDocumentId(sender);
  requireActiveLifecycle(sender);

  const extensionOrigin = `chrome-extension://${runtimeId}`;
  if (sender.origin !== extensionOrigin) {
    invalid("privileged UI origin does not match this extension");
  }

  const value = requireBoundedString(sender.url, "sender URL", MAX_SENDER_URL_LENGTH);
  const parsed = parseUrl(value, "sender URL");
  if (
    parsed.protocol !== "chrome-extension:" ||
    parsed.hostname !== runtimeId ||
    parsed.port !== "" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    value !== `${extensionOrigin}${parsed.pathname}` ||
    !allowedPaths.has(parsed.pathname)
  ) {
    invalid("privileged UI URL is not an exact allowlisted extension page");
  }

  let tabId: number | null = null;
  let frameId: number | null = null;
  if (sender.tab === undefined) {
    if (sender.frameId !== undefined) {
      invalid("tabless UI sender unexpectedly has a frame id");
    }
  } else {
    if (documentId === null) {
      invalid("tab-hosted privileged UI is missing its document id");
    }
    tabId = requireTabId(sender);
    frameId = requireNonNegativeInteger(sender.frameId, "frame id");
    if (frameId !== 0) {
      invalid("tab-hosted privileged UI must be the top frame");
    }
  }

  return Object.freeze({
    kind: "privileged-ui",
    extensionId: runtimeId,
    documentId,
    extensionOrigin,
    path: parsed.pathname,
    tabId,
    frameId,
  });
}

/**
 * Bind one full-page approval document to the exact request id in Chrome's
 * sender URL. Unlike the tabless action popup, this surface always requires a
 * browser document id, tab id, and top-frame identity. The page repeats the id
 * in its strict protocol message, but that value never overrides this tuple.
 */
export function classifyApprovalUiSender(
  input: SenderClassifierInput,
): ApprovalUiProvenance {
  const runtimeId = requireRuntimeId(input.runtimeId);
  const sender = requireRecord(input.sender, "sender");
  requireExtensionOwner(sender, runtimeId);
  rejectAmbiguousSenderKinds(sender);
  const documentId = requireDocumentId(sender);
  requireActiveLifecycle(sender);

  const extensionOrigin = `chrome-extension://${runtimeId}`;
  if (sender.origin !== extensionOrigin) {
    invalid("approval UI origin does not match this extension");
  }
  const value = requireBoundedString(sender.url, "sender URL", MAX_SENDER_URL_LENGTH);
  const parsed = parseUrl(value, "sender URL");
  const requestId = parsed.search.startsWith("?request=")
    ? parsed.search.slice("?request=".length)
    : "";
  if (
    parsed.protocol !== "chrome-extension:" ||
    parsed.hostname !== runtimeId ||
    parsed.port !== "" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== APPROVAL_UI_PATH ||
    parsed.hash !== "" ||
    !APPROVAL_REQUEST_ID_PATTERN.test(requestId) ||
    value !== `${extensionOrigin}${APPROVAL_UI_PATH}?request=${requestId}`
  ) {
    invalid("approval UI URL is not one exact request page");
  }

  const tabId = requireTabId(sender);
  const frameId = requireNonNegativeInteger(sender.frameId, "frame id");
  if (frameId !== 0) invalid("approval UI must be the tab's top frame");

  return Object.freeze({
    kind: "approval-ui",
    extensionId: runtimeId,
    documentId,
    extensionOrigin,
    path: APPROVAL_UI_PATH,
    requestId,
    tabId,
    frameId: 0,
  });
}
