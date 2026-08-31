import {
  parseProviderRequest,
  type ProviderRequest,
} from "./provider-message.js";
import {
  classifyProviderSender,
  type ProviderProvenance,
} from "./sender-provenance.js";
import {
  MAX_PROVIDER_REQUESTS_PER_DOCUMENT,
  PROVIDER_PORT_NAME,
  createUnavailableProviderResponse,
} from "../provider-protocol.js";

export {
  PROVIDER_PORT_NAME,
  createUnavailableProviderResponse,
} from "../provider-protocol.js";
export type { ProviderUnavailableResponse } from "../provider-protocol.js";
export const DEFAULT_PROVIDER_REQUEST_TTL_MS = 2 * 60 * 1_000;
export const MAX_PROVIDER_REQUEST_TTL_MS = 10 * 60 * 1_000;
export const MAX_PENDING_PROVIDER_REQUESTS = 32;
export const MAX_PROVIDER_REQUESTS_PER_PORT = MAX_PROVIDER_REQUESTS_PER_DOCUMENT;
export const MAX_PROVIDER_REQUEST_IDS_PER_SESSION =
  MAX_PROVIDER_REQUESTS_PER_PORT * 2;
export const MAX_ACTIVE_PROVIDER_PORTS = 256;

const REQUEST_ID_BYTES = 16;
const REQUEST_ID_ATTEMPTS = 8;
const EXTENSION_ID_PATTERN = /^[a-p]{32}$/;

export type ProviderCancellationReason =
  | "expired"
  | "disconnect"
  | "navigation"
  | "account-change"
  | "malformed"
  | "clock-failure"
  | "timer-failure"
  | "boundary-disposed";

export class ProviderPortStateError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`provider port: ${message}`, options);
    this.name = "ProviderPortStateError";
  }
}

export class ProviderRequestCancelledError extends Error {
  readonly reason: ProviderCancellationReason;

  constructor(reason: ProviderCancellationReason) {
    super(`provider request cancelled: ${reason}`);
    this.name = "ProviderRequestCancelledError";
    this.reason = reason;
  }
}

export interface ProviderRandomSource {
  getRandomValues(target: Uint8Array): Uint8Array;
}

export interface ProviderTimerSource {
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface OwnedProviderRequest {
  /** Background-minted security identity. Never echo this to the page. */
  readonly id: string;
  readonly provenance: ProviderProvenance;
  readonly request: ProviderRequest;
  readonly createdAt: number;
  readonly expiresAt: number;
  /** Cancellation hint; authority comes from the owning session's assertActive(). */
  readonly signal: AbortSignal;
}

interface PendingProviderRequest {
  readonly owned: OwnedProviderRequest;
  readonly controller: AbortController;
  expiryTimer: unknown;
}

export interface ProviderPortSessionOptions {
  readonly readNow?: () => number;
  readonly requestTtlMs?: number;
  /** Test seam; production callers omit this and use browser Web Crypto. */
  readonly randomSource?: ProviderRandomSource;
  /** Test seam; an absolute-time recheck remains authoritative over this timer. */
  readonly timerSource?: ProviderTimerSource;
  /** Bounded test/composition seam; production callers omit this. */
  readonly requestLimit?: number;
}

const NO_EXPIRY_TIMER = Symbol("no-expiry-timer");
const DEFAULT_TIMER_SOURCE: ProviderTimerSource = {
  setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
  clearTimeout: (handle) =>
    globalThis.clearTimeout(handle as ReturnType<typeof globalThis.setTimeout>),
};

function stateError(message: string, cause?: unknown): never {
  throw new ProviderPortStateError(message, cause === undefined ? {} : { cause });
}

function requireRandomSource(value: unknown): ProviderRandomSource {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly getRandomValues?: unknown }).getRandomValues !== "function"
  ) {
    stateError("Web Crypto random source is unavailable");
  }
  return value as ProviderRandomSource;
}

function requireTtl(value: unknown): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) <= 0 ||
    (value as number) > MAX_PROVIDER_REQUEST_TTL_MS
  ) {
    stateError(`request TTL must be 1..${MAX_PROVIDER_REQUEST_TTL_MS} milliseconds`);
  }
  return value as number;
}

function requireRequestLimit(value: unknown): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1 ||
    (value as number) > MAX_PROVIDER_REQUEST_IDS_PER_SESSION
  ) {
    stateError(
      `request limit must be 1..${MAX_PROVIDER_REQUEST_IDS_PER_SESSION}`,
    );
  }
  return value as number;
}

function requireTimerSource(value: unknown): ProviderTimerSource {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly setTimeout?: unknown }).setTimeout !== "function" ||
    typeof (value as { readonly clearTimeout?: unknown }).clearTimeout !== "function"
  ) {
    stateError("timer source is unavailable");
  }
  return value as ProviderTimerSource;
}

function copyProvenance(value: ProviderProvenance): ProviderProvenance {
  return Object.freeze({
    kind: value.kind,
    extensionId: value.extensionId,
    documentId: value.documentId,
    origin: value.origin,
    tabId: value.tabId,
    frameId: value.frameId,
  });
}

function encodeRequestId(bytes: Uint8Array): string {
  let encoded = "req_";
  for (const byte of bytes) encoded += byte.toString(16).padStart(2, "0");
  return encoded;
}

/**
 * Owns every request accepted from one browser Port. This is a lifecycle and
 * identity primitive only; it contains no account authorization, approval, key
 * use, signing, decryption, export or RPC dispatch.
 */
export class ProviderPortSession {
  private readonly provenance: ProviderProvenance;
  private readonly readNow: () => number;
  private readonly requestTtlMs: number;
  private readonly requestLimit: number;
  private readonly randomSource: ProviderRandomSource;
  private readonly timerSource: ProviderTimerSource;
  private readonly pending = new Map<string, PendingProviderRequest>();
  private readonly correlationIds = new Set<string>();
  private readonly issuedIds = new Set<string>();
  private isClosed = false;

  constructor(
    provenance: ProviderProvenance,
    options: ProviderPortSessionOptions = {},
  ) {
    if (options.readNow !== undefined && typeof options.readNow !== "function") {
      stateError("readNow must be a function");
    }
    this.provenance = copyProvenance(provenance);
    this.readNow = options.readNow ?? Date.now;
    this.requestTtlMs = requireTtl(
      options.requestTtlMs ?? DEFAULT_PROVIDER_REQUEST_TTL_MS,
    );
    this.requestLimit = requireRequestLimit(
      options.requestLimit ?? MAX_PROVIDER_REQUESTS_PER_PORT,
    );
    this.randomSource = requireRandomSource(options.randomSource ?? globalThis.crypto);
    this.timerSource = requireTimerSource(options.timerSource ?? DEFAULT_TIMER_SOURCE);
  }

  get pendingCount(): number {
    return this.pending.size;
  }

  get closed(): boolean {
    return this.isClosed;
  }

  private currentTime(): number {
    let now: unknown;
    try {
      now = this.readNow();
    } catch (error) {
      stateError("clock read failed", error);
    }
    if (!Number.isSafeInteger(now) || (now as number) < 0) {
      stateError("clock must return a non-negative safe integer");
    }
    return now as number;
  }

  private mintRequestId(): string {
    if (this.issuedIds.size >= this.requestLimit) {
      stateError("request limit reached");
    }
    for (let attempt = 0; attempt < REQUEST_ID_ATTEMPTS; attempt++) {
      const bytes = new Uint8Array(REQUEST_ID_BYTES);
      try {
        const returned = this.randomSource.getRandomValues(bytes);
        if (returned !== bytes) stateError("random source returned a different buffer");
        const id = encodeRequestId(bytes);
        if (!this.issuedIds.has(id)) {
          this.issuedIds.add(id);
          return id;
        }
      } catch (error) {
        if (error instanceof ProviderPortStateError) throw error;
        stateError("Web Crypto request-id generation failed", error);
      } finally {
        bytes.fill(0);
      }
    }
    stateError("could not mint a unique request id");
  }

  private remove(entry: PendingProviderRequest): void {
    this.pending.delete(entry.owned.id);
    this.correlationIds.delete(entry.owned.request.correlationId);
    if (entry.expiryTimer !== NO_EXPIRY_TIMER) {
      try {
        this.timerSource.clearTimeout(entry.expiryTimer);
      } catch {
        // The absolute-time and AbortSignal checks remain authoritative. A
        // platform cleanup failure must not prevent cancellation or settlement.
      } finally {
        entry.expiryTimer = NO_EXPIRY_TIMER;
      }
    }
  }

  private cancelEntry(
    entry: PendingProviderRequest,
    reason: ProviderCancellationReason,
  ): void {
    this.remove(entry);
    entry.controller.abort(new ProviderRequestCancelledError(reason));
  }

  private abortAll(reason: ProviderCancellationReason): number {
    const entries = [...this.pending.values()];
    for (const entry of entries) this.cancelEntry(entry, reason);
    return entries.length;
  }

  private armExpiry(entry: PendingProviderRequest): void {
    const delayMs = entry.owned.expiresAt - this.currentTime();
    if (delayMs <= 0) {
      this.cancelEntry(entry, "expired");
      return;
    }
    try {
      entry.expiryTimer = this.timerSource.setTimeout(() => {
        if (this.pending.get(entry.owned.id) !== entry) return;
        entry.expiryTimer = NO_EXPIRY_TIMER;
        let remainingMs: number;
        try {
          remainingMs = entry.owned.expiresAt - this.currentTime();
        } catch {
          this.cancelEntry(entry, "clock-failure");
          return;
        }
        if (remainingMs <= 0) {
          this.cancelEntry(entry, "expired");
        } else {
          try {
            this.armExpiry(entry);
          } catch {
            this.cancelEntry(entry, "timer-failure");
          }
        }
      }, delayMs);
    } catch (error) {
      stateError("expiry timer setup failed", error);
    }
  }

  reapExpired(): number {
    let now: number;
    try {
      now = this.currentTime();
    } catch (error) {
      this.abortAll("clock-failure");
      throw error;
    }

    let expired = 0;
    for (const entry of [...this.pending.values()]) {
      if (now >= entry.owned.expiresAt) {
        this.cancelEntry(entry, "expired");
        expired++;
      }
    }
    return expired;
  }

  private openAt(value: unknown, absoluteExpiresAt?: number): OwnedProviderRequest {
    if (this.isClosed) stateError("provider port is closed");
    this.reapExpired();
    if (this.pending.size >= MAX_PENDING_PROVIDER_REQUESTS) {
      stateError("too many pending requests");
    }
    if (this.issuedIds.size >= this.requestLimit) {
      stateError("request limit reached");
    }

    const request = parseProviderRequest(value);
    if (this.correlationIds.has(request.correlationId)) {
      stateError("duplicate in-flight correlation id");
    }

    const createdAt = this.currentTime();
    const expiresAt = absoluteExpiresAt ?? createdAt + this.requestTtlMs;
    if (
      !Number.isSafeInteger(expiresAt) ||
      expiresAt <= createdAt ||
      expiresAt - createdAt > this.requestTtlMs
    ) {
      stateError("request absolute expiry is outside the configured lifetime");
    }
    const id = this.mintRequestId();
    const controller = new AbortController();
    const owned = Object.freeze({
      id,
      provenance: this.provenance,
      request,
      createdAt,
      expiresAt,
      signal: controller.signal,
    });
    const entry: PendingProviderRequest = {
      owned,
      controller,
      expiryTimer: NO_EXPIRY_TIMER,
    };
    this.pending.set(id, entry);
    this.correlationIds.add(request.correlationId);
    try {
      this.armExpiry(entry);
    } catch (error) {
      if (this.pending.get(id) === entry) this.cancelEntry(entry, "timer-failure");
      throw error;
    }
    if (this.pending.get(id) !== entry || controller.signal.aborted) {
      stateError("request expired while opening");
    }
    return owned;
  }

  open(value: unknown): OwnedProviderRequest {
    return this.openAt(value);
  }

  /**
   * Open a replacement delivery lease without extending the first accepted
   * request's absolute deadline. Only the C21/C22 document transport uses this;
   * the production unavailable boundary continues to call open().
   */
  openUntil(value: unknown, absoluteExpiresAt: number): OwnedProviderRequest {
    return this.openAt(value, absoluteExpiresAt);
  }

  assertActive(owned: OwnedProviderRequest): void {
    this.reapExpired();
    const entry = this.pending.get(owned.id);
    if (
      entry === undefined ||
      entry.owned !== owned ||
      owned.signal.aborted ||
      this.isClosed
    ) {
      stateError("request is no longer owned by this port");
    }
  }

  finish(owned: OwnedProviderRequest): boolean {
    this.reapExpired();
    const entry = this.pending.get(owned.id);
    if (entry === undefined || entry.owned !== owned) return false;
    this.remove(entry);
    return true;
  }

  cancel(
    owned: OwnedProviderRequest,
    reason: ProviderCancellationReason,
  ): boolean {
    this.reapExpired();
    const entry = this.pending.get(owned.id);
    if (entry === undefined || entry.owned !== owned) return false;
    this.cancelEntry(entry, reason);
    return true;
  }

  cancelPending(reason: ProviderCancellationReason): number {
    return this.abortAll(reason);
  }

  disconnect(reason: ProviderCancellationReason = "disconnect"): void {
    if (this.isClosed) return;
    this.isClosed = true;
    this.abortAll(reason);
  }
}

export interface ProviderMessageEvent {
  addListener(listener: (message: unknown) => void): void;
  removeListener(listener: (message: unknown) => void): void;
}

export interface ProviderDisconnectEvent {
  addListener(listener: () => void): void;
  removeListener(listener: () => void): void;
}

export interface ProviderRuntimePort {
  readonly name: string;
  readonly sender: unknown;
  readonly onMessage: ProviderMessageEvent;
  readonly onDisconnect: ProviderDisconnectEvent;
  postMessage(message: unknown): void;
  disconnect(): void;
}

export interface ProviderConnectEvent {
  addListener(listener: (port: ProviderRuntimePort) => void): void;
  removeListener(listener: (port: ProviderRuntimePort) => void): void;
}

export interface ProviderRuntimeApi {
  readonly id: string;
  readonly onConnect: ProviderConnectEvent;
}

export interface UnavailableProviderBoundary {
  dispose(): void;
}

function requireListenerEvent(
  value: unknown,
  name: string,
): asserts value is { addListener(listener: never): void; removeListener(listener: never): void } {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly addListener?: unknown }).addListener !== "function" ||
    typeof (value as { readonly removeListener?: unknown }).removeListener !== "function"
  ) {
    stateError(`${name} listener event is unavailable`);
  }
}

function requirePort(value: unknown): ProviderRuntimePort {
  if (typeof value !== "object" || value === null) stateError("runtime Port is malformed");
  const port = value as Partial<ProviderRuntimePort>;
  if (
    typeof port.name !== "string" ||
    typeof port.postMessage !== "function" ||
    typeof port.disconnect !== "function"
  ) {
    stateError("runtime Port is malformed");
  }
  requireListenerEvent(port.onMessage, "Port.onMessage");
  requireListenerEvent(port.onDisconnect, "Port.onDisconnect");
  return port as ProviderRuntimePort;
}

function safeDisconnect(port: ProviderRuntimePort): void {
  try {
    port.disconnect();
  } catch {
    // A port that disappeared between classification and rejection is already closed.
  }
}

/**
 * Install the first reachable provider boundary. Every syntactically valid
 * method still receives METHOD_UNAVAILABLE; there is deliberately no dispatch
 * hook here that could reach keys, approvals, accounts, RPC or signing.
 */
export function installUnavailableProviderBoundary(
  runtime: ProviderRuntimeApi,
  options: ProviderPortSessionOptions = {},
): UnavailableProviderBoundary {
  if (
    typeof runtime !== "object" ||
    runtime === null ||
    typeof runtime.id !== "string" ||
    !EXTENSION_ID_PATTERN.test(runtime.id)
  ) {
    stateError("runtime extension id is malformed");
  }
  requireListenerEvent(runtime.onConnect, "runtime.onConnect");

  let disposed = false;
  const active = new Map<string, (
    disconnectPort: boolean,
    reason: ProviderCancellationReason,
  ) => void>();

  const onConnect = (rawPort: ProviderRuntimePort): void => {
    let port: ProviderRuntimePort;
    try {
      port = requirePort(rawPort);
    } catch {
      return;
    }
    if (disposed || port.name !== PROVIDER_PORT_NAME) {
      safeDisconnect(port);
      return;
    }

    let provenance: ProviderProvenance;
    try {
      provenance = classifyProviderSender({ runtimeId: runtime.id, sender: port.sender });
    } catch {
      safeDisconnect(port);
      return;
    }
    if (
      active.has(provenance.documentId) ||
      active.size >= MAX_ACTIVE_PROVIDER_PORTS
    ) {
      safeDisconnect(port);
      return;
    }

    let session: ProviderPortSession;
    try {
      session = new ProviderPortSession(provenance, options);
    } catch {
      safeDisconnect(port);
      return;
    }

    let open = true;
    const close = (
      disconnectPort: boolean,
      reason: ProviderCancellationReason,
    ): void => {
      if (!open) return;
      open = false;
      session.disconnect(reason);
      if (active.get(provenance.documentId) === close) {
        active.delete(provenance.documentId);
      }
      try {
        port.onMessage.removeListener(onMessage);
      } catch {
        // Cancellation above is the authority; listener cleanup is best effort.
      }
      try {
        port.onDisconnect.removeListener(onDisconnect);
      } catch {
        // Cancellation above is the authority; listener cleanup is best effort.
      }
      if (disconnectPort) safeDisconnect(port);
    };

    const onMessage = (message: unknown): void => {
      if (!open) return;
      let owned: OwnedProviderRequest;
      try {
        owned = session.open(message);
      } catch {
        close(true, "malformed");
        return;
      }

      try {
        session.assertActive(owned);
        port.postMessage(
          createUnavailableProviderResponse(owned.request.correlationId),
        );
        if (!session.finish(owned)) close(true, "expired");
      } catch {
        close(true, "disconnect");
      }
    };

    const onDisconnect = (): void => close(false, "disconnect");

    try {
      port.onDisconnect.addListener(onDisconnect);
      port.onMessage.addListener(onMessage);
      active.set(provenance.documentId, close);
    } catch {
      close(true, "disconnect");
    }
  };

  runtime.onConnect.addListener(onConnect);

  return Object.freeze({
    dispose(): void {
      if (disposed) return;
      disposed = true;
      try {
        runtime.onConnect.removeListener(onConnect);
      } finally {
        for (const close of [...active.values()]) close(true, "boundary-disposed");
      }
    },
  });
}
