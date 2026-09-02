//! Still-unreachable C20 content transport recovery owner.
//!
//! This owner is deliberately absent from the production content entry point.
//! It accepts only C16's closed signTransaction request, retains one canonical
//! snapshot per correlation, and permits one automatic resend after Port loss.
//! A resend is transport recovery, not new authority: the background must
//! independently rederive browser provenance and durable operation identity.
//! Exhausted recovery never fabricates a terminal page error; C16's absolute
//! deadline remains authoritative when no durable terminal response arrives.
//!
//! Audit finding X-1: this owner mints one `MessageChannel` per document and
//! transfers `port2` into the page in its constructor — at `document_start`,
//! before any page script runs. Terminal responses and page receipts travel
//! only over that channel; requests keep arriving on `window`, where a
//! same-document script may still spoof or suppress them. The grant is minted
//! exactly once: this owner never answers a page-initiated handshake, so a
//! later same-document script has no path to a second port.

import {
  parseProviderRequest,
  type ProviderSignTransactionRequest,
} from "../background/provider-message.js";
import {
  createProviderTerminalFailureResponse,
  createSignedTransactionProviderResponse,
  isProviderTerminalFailureResponse,
  isSignedTransactionProviderResponse,
  type ProviderSignedTransactionResponse,
  type ProviderTerminalFailureResponse,
} from "../background/provider-terminal-protocol.js";
import {
  MAX_PROVIDER_REQUESTS_PER_DOCUMENT,
  PAGE_PROVIDER_RESPONSE_TYPE,
  PROVIDER_PORT_NAME,
  createUnavailableProviderResponse,
  isProviderUnavailableResponse,
  readPageProviderRequestEnvelope,
  type ProviderUnavailableResponse,
} from "../provider-protocol.js";
import type {
  ContentRuntimeApi,
  ContentRuntimePort,
  ContentWindowApi,
  ContentWindowMessageEvent,
} from "./bridge.js";
import {
  createProviderCapabilityEnvelope,
  createProviderTransportCancelEnvelope,
  createProviderTransportReceiptEnvelope,
  createProviderTransportRequestEnvelope,
  createProviderTransportTerminalEnvelope,
  readPageProviderReceiptEnvelope,
  readProviderTransportRequestEnvelope,
  readProviderTransportSettledEnvelope,
  readProviderTransportTerminalEnvelope,
  type ProviderTransportRequestEnvelope,
  type ProviderTransportTerminalEnvelope,
} from "../provider-delivery-protocol.js";

export const MAX_PROVIDER_CONTENT_PENDING_REQUESTS = 32;
export const MAX_PROVIDER_CONTENT_REQUESTS_PER_DOCUMENT =
  MAX_PROVIDER_REQUESTS_PER_DOCUMENT;
export const MAX_PROVIDER_CONTENT_RECOVERY_ATTEMPTS = 1;
export const DEFAULT_PROVIDER_CONTENT_REQUEST_TTL_MS = 2 * 60 * 1_000;
export const MAX_PROVIDER_CONTENT_REQUEST_TTL_MS = 10 * 60 * 1_000;

const CLAIMED_CONTENT_WINDOWS = new WeakSet<ContentWindowApi>();
const NO_EXPIRY_TIMER = Symbol("no-expiry-timer");

export interface ProviderContentTimerSource {
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(handle: unknown): void;
}

const DEFAULT_TIMER_SOURCE: ProviderContentTimerSource = {
  setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
  clearTimeout: (handle) =>
    globalThis.clearTimeout(handle as ReturnType<typeof globalThis.setTimeout>),
};

export interface ProviderContentMessagePortEvent {
  readonly data: unknown;
}

export type ProviderContentMessagePortListener = (
  event: ProviderContentMessagePortEvent,
) => void;

/** The exact subset of `MessagePort` this owner drives. */
export interface ProviderContentMessagePort {
  addEventListener(
    type: "message",
    listener: ProviderContentMessagePortListener,
  ): void;
  removeEventListener(
    type: "message",
    listener: ProviderContentMessagePortListener,
  ): void;
  postMessage(message: unknown): void;
  start(): void;
  close(): void;
}

export interface ProviderContentMessageChannel {
  readonly port1: ProviderContentMessagePort;
  readonly port2: unknown;
}

export type ProviderContentChannelSource = () => ProviderContentMessageChannel;

/**
 * `window.postMessage` including the transfer list. `ContentWindowApi` models
 * only the two-argument form the shipped bridge uses; the capability grant
 * needs the third, so this owner binds the wider signature itself rather than
 * widening the shipped content-bundle interface.
 */
type PostPageMessage = (
  message: unknown,
  targetOrigin: string,
  transfer?: readonly unknown[],
) => void;

const DEFAULT_CHANNEL_SOURCE: ProviderContentChannelSource = () => {
  const factory = (globalThis as {
    MessageChannel?: new () => ProviderContentMessageChannel;
  }).MessageChannel;
  if (typeof factory !== "function") {
    stateError("MessageChannel is unavailable in this realm");
  }
  return new factory();
};

export interface ProviderContentTransportOptions {
  readonly readNow?: () => number;
  readonly requestTtlMs?: number;
  /** Test seam. Absolute-time checks remain authoritative over this timer. */
  readonly timerSource?: ProviderContentTimerSource;
  /** May only lower the production bound; useful for focused tests. */
  readonly pendingLimit?: number;
  /** May only lower the production bound; useful for focused tests. */
  readonly requestLimit?: number;
  /** Test seam for the X-1 one-shot capability grant. */
  readonly channelSource?: ProviderContentChannelSource;
}

export class ProviderContentTransportStateError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`provider content transport: ${message}`, options);
    this.name = "ProviderContentTransportStateError";
  }
}

interface CanonicalProviderWireRequest {
  readonly version: 1;
  readonly type: "request";
  readonly correlationId: string;
  readonly method: "solana:signTransaction";
  readonly params: Readonly<{
    readonly accountAddress: string;
    readonly transaction: readonly number[];
    readonly options: Readonly<{
      readonly preflightCommitment?: string;
      readonly minContextSlot?: number;
    }>;
    readonly chain?: string;
  }>;
}

interface PendingContentRequest {
  readonly correlationId: string;
  readonly payload: ProviderTransportRequestEnvelope;
  readonly expiresAt: number;
  recoveryAttempts: number;
  lastPortGeneration: number | null;
  terminal: ProviderTransportTerminalEnvelope | null;
  pageReceiptId: string | null;
  receiptSentGeneration: number | null;
  expiryTimer: unknown;
}

interface BoundContentPort {
  readonly generation: number;
  readonly postMessage: (message: unknown) => void;
  readonly disconnect: () => void;
  readonly addMessageListener: (listener: (message: unknown) => void) => void;
  readonly removeMessageListener: (listener: (message: unknown) => void) => void;
  readonly addDisconnectListener: (listener: () => void) => void;
  readonly removeDisconnectListener: (listener: () => void) => void;
  readonly onMessage: (message: unknown) => void;
  readonly onDisconnect: () => void;
  messageListenerInstalled: boolean;
  disconnectListenerInstalled: boolean;
}

type ContentTerminalResponse =
  | ProviderUnavailableResponse
  | ProviderSignedTransactionResponse
  | ProviderTerminalFailureResponse;

interface ContentTerminalDelivery {
  readonly response: ContentTerminalResponse;
  readonly envelope: ProviderTransportTerminalEnvelope;
}

interface ContentRequestSnapshot {
  readonly request: CanonicalProviderWireRequest;
  readonly envelope: ProviderTransportRequestEnvelope;
}

function stateError(message: string, cause?: unknown): never {
  throw new ProviderContentTransportStateError(
    message,
    cause === undefined ? {} : { cause },
  );
}

function requireObject(value: unknown, name: string): Record<PropertyKey, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    stateError(`${name} must be an object`);
  }
  return value as Record<PropertyKey, unknown>;
}

function bindMethod<T>(
  owner: Record<PropertyKey, unknown>,
  key: PropertyKey,
  name: string,
): T {
  let value: unknown;
  try {
    value = owner[key];
  } catch (error) {
    stateError(`${name} access failed`, error);
  }
  if (typeof value !== "function") stateError(`${name} must be a function`);
  return value.bind(owner) as T;
}

function requireBoundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
  name: string,
): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < minimum ||
    (value as number) > maximum
  ) {
    stateError(`${name} must be ${minimum}..${maximum}`);
  }
  return value as number;
}

function requireClock(value: unknown): () => number {
  if (typeof value !== "function") stateError("readNow must be a function");
  return value as () => number;
}

function bindTimerSource(value: unknown): ProviderContentTimerSource {
  const timer = requireObject(value, "timer source");
  return Object.freeze({
    setTimeout: bindMethod<ProviderContentTimerSource["setTimeout"]>(
      timer,
      "setTimeout",
      "timerSource.setTimeout",
    ),
    clearTimeout: bindMethod<ProviderContentTimerSource["clearTimeout"]>(
      timer,
      "clearTimeout",
      "timerSource.clearTimeout",
    ),
  });
}

function requireWebOrigin(value: unknown): string {
  if (typeof value !== "string") stateError("document origin is unavailable");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (error) {
    stateError("document origin is malformed", error);
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.origin !== value ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    stateError("document origin is not one canonical HTTP(S) origin");
  }
  return value;
}

function canonicalWireRequest(
  request: ProviderSignTransactionRequest,
): CanonicalProviderWireRequest {
  const options: Record<string, unknown> = {};
  if (request.params.options.preflightCommitment !== null) {
    options.preflightCommitment = request.params.options.preflightCommitment;
  }
  if (request.params.options.minContextSlot !== null) {
    options.minContextSlot = request.params.options.minContextSlot;
  }
  const params: Record<string, unknown> = {
    accountAddress: request.params.requestedAccountAddress,
    transaction: Object.freeze([...request.params.transaction]),
    options: Object.freeze(options),
  };
  if (request.params.chain !== null) params.chain = request.params.chain;
  return Object.freeze({
    version: 1,
    type: "request",
    correlationId: request.correlationId,
    method: "solana:signTransaction",
    params: Object.freeze(params),
  }) as unknown as CanonicalProviderWireRequest;
}

function snapshotPageRequest(value: unknown): ContentRequestSnapshot | null {
  try {
    const envelope = readProviderTransportRequestEnvelope(value);
    if (envelope === null) return null;
    const request = parseProviderRequest(envelope.payload);
    if (request.method !== "solana:signTransaction") return null;
    const canonical = canonicalWireRequest(request);
    return Object.freeze({
      request: canonical,
      envelope: createProviderTransportRequestEnvelope(
        envelope.expiresAt,
        canonical,
      ),
    });
  } catch {
    return null;
  }
}

function snapshotTerminalResponse(value: unknown): ContentTerminalDelivery | null {
  try {
    const envelope = readProviderTransportTerminalEnvelope(value);
    if (envelope === null) return null;
    let response: ContentTerminalResponse;
    if (isProviderUnavailableResponse(envelope.payload)) {
      response = createUnavailableProviderResponse(envelope.payload.correlationId);
    } else if (isProviderTerminalFailureResponse(envelope.payload)) {
      response = createProviderTerminalFailureResponse(
        envelope.payload.correlationId,
        envelope.payload.error.code,
      );
    } else {
      if (!isSignedTransactionProviderResponse(envelope.payload)) return null;
      let bytes: Uint8Array | undefined;
      try {
        bytes = Uint8Array.from(envelope.payload.result.signedTransaction);
        response = createSignedTransactionProviderResponse(
          envelope.payload.correlationId,
          bytes,
        );
      } finally {
        bytes?.fill(0);
      }
    }
    if (response.correlationId !== envelope.correlationId) return null;
    return Object.freeze({
      response,
      envelope: createProviderTransportTerminalEnvelope(
        envelope.correlationId,
        envelope.receiptId,
        envelope.expiresAt,
        response,
      ),
    });
  } catch {
    return null;
  }
}

function terminalEnvelopesEqual(
  left: ProviderTransportTerminalEnvelope,
  right: ProviderTransportTerminalEnvelope,
): boolean {
  if (
    left.correlationId !== right.correlationId ||
    left.receiptId !== right.receiptId ||
    left.expiresAt !== right.expiresAt
  ) {
    return false;
  }
  const leftValue = left.payload as ContentTerminalResponse;
  const rightValue = right.payload as ContentTerminalResponse;
  if (leftValue.ok !== rightValue.ok) return false;
  if (!leftValue.ok && !rightValue.ok) {
    return leftValue.error.code === rightValue.error.code &&
      leftValue.error.message === rightValue.error.message;
  }
  if (leftValue.ok && rightValue.ok) {
    const leftBytes = leftValue.result.signedTransaction;
    const rightBytes = rightValue.result.signedTransaction;
    return leftBytes.length === rightBytes.length &&
      leftBytes.every((byte, index) => byte === rightBytes[index]);
  }
  return false;
}

function bindPortMethods(value: unknown): Omit<
  BoundContentPort,
  | "generation"
  | "onMessage"
  | "onDisconnect"
  | "messageListenerInstalled"
  | "disconnectListenerInstalled"
> {
  const port = requireObject(value, "runtime Port");
  const messageEvent = requireObject(port.onMessage, "Port.onMessage");
  const disconnectEvent = requireObject(port.onDisconnect, "Port.onDisconnect");
  return Object.freeze({
    postMessage: bindMethod<ContentRuntimePort["postMessage"]>(
      port,
      "postMessage",
      "Port.postMessage",
    ),
    disconnect: bindMethod<ContentRuntimePort["disconnect"]>(
      port,
      "disconnect",
      "Port.disconnect",
    ),
    addMessageListener: bindMethod<ContentRuntimePort["onMessage"]["addListener"]>(
      messageEvent,
      "addListener",
      "Port.onMessage.addListener",
    ),
    removeMessageListener: bindMethod<ContentRuntimePort["onMessage"]["removeListener"]>(
      messageEvent,
      "removeListener",
      "Port.onMessage.removeListener",
    ),
    addDisconnectListener: bindMethod<ContentRuntimePort["onDisconnect"]["addListener"]>(
      disconnectEvent,
      "addListener",
      "Port.onDisconnect.addListener",
    ),
    removeDisconnectListener: bindMethod<ContentRuntimePort["onDisconnect"]["removeListener"]>(
      disconnectEvent,
      "removeListener",
      "Port.onDisconnect.removeListener",
    ),
  });
}

/**
 * Owns one isolated content-script document's volatile request transport.
 * Same-page code remains the caller principal and can forge or suppress window
 * traffic. This owner grants no origin, account, approval, RPC, or key
 * authority; Chrome-owned Port.sender remains the background provenance root.
 */
export class ProviderContentTransportOwner {
  readonly #page: ContentWindowApi;
  readonly #documentOrigin: string;
  readonly #connect: ContentRuntimeApi["connect"];
  readonly #addPageListener: ContentWindowApi["addEventListener"];
  readonly #removePageListener: ContentWindowApi["removeEventListener"];
  readonly #postPageMessage: PostPageMessage;
  readonly #readNow: () => number;
  readonly #requestTtlMs: number;
  readonly #timerSource: ProviderContentTimerSource;
  readonly #pendingLimit: number;
  readonly #requestLimit: number;
  readonly #channelSource: ProviderContentChannelSource;
  readonly #pending = new Map<string, PendingContentRequest>();
  readonly #issued = new Set<string>();
  #capabilityPort: ProviderContentMessagePort | null = null;
  #activePort: BoundContentPort | null = null;
  #nextPortGeneration = 1;
  #open = true;
  #pageListenerInstalled = false;

  readonly #onPageMessage = (event: ContentWindowMessageEvent): void => {
    if (
      !this.#open ||
      event.source !== this.#page ||
      event.origin !== this.#documentOrigin
    ) {
      return;
    }

    let envelope: ReturnType<typeof readPageProviderRequestEnvelope>;
    try {
      envelope = readPageProviderRequestEnvelope(event.data);
    } catch {
      this.#close(true);
      return;
    }
    // Receipts arrive on the capability channel only; the window carries
    // requests and nothing else inbound.
    if (envelope === null) return;
    let snapshot: ContentRequestSnapshot | null;
    try {
      snapshot = snapshotPageRequest(envelope.payload);
    } catch {
      snapshot = null;
    }
    if (snapshot === null) {
      this.#close(true);
      return;
    }
    let now: number;
    try {
      now = this.#currentTime();
    } catch {
      this.#close(true);
      return;
    }
    this.#reapExpiredAt(now);
    const expiresAt = snapshot.envelope.expiresAt;
    if (
      expiresAt <= now ||
      expiresAt - now > this.#requestTtlMs ||
      this.#pending.size >= this.#pendingLimit ||
      this.#issued.size >= this.#requestLimit ||
      this.#issued.has(snapshot.request.correlationId)
    ) {
      this.#close(true);
      return;
    }

    const entry: PendingContentRequest = {
      correlationId: snapshot.request.correlationId,
      payload: snapshot.envelope,
      expiresAt,
      recoveryAttempts: 0,
      lastPortGeneration: null,
      terminal: null,
      pageReceiptId: null,
      receiptSentGeneration: null,
      expiryTimer: NO_EXPIRY_TIMER,
    };
    this.#issued.add(entry.correlationId);
    this.#pending.set(entry.correlationId, entry);
    try {
      this.#armExpiry(entry);
    } catch {
      this.#close(true);
      return;
    }
    if (this.#pending.get(entry.correlationId) !== entry) return;
    this.#dispatchInitial(entry);
  };

  readonly #onCapabilityMessage = (
    event: ProviderContentMessagePortEvent,
  ): void => {
    if (!this.#open) return;
    const receipt = readPageProviderReceiptEnvelope(event.data);
    if (receipt === null) return;
    this.#acceptPageReceipt(receipt.payload);
  };

  constructor(
    pageValue: ContentWindowApi,
    runtimeValue: ContentRuntimeApi,
    options: ProviderContentTransportOptions = {},
  ) {
    const page = requireObject(pageValue, "window API");
    const runtime = requireObject(runtimeValue, "runtime API");
    this.#page = pageValue;
    let origin: unknown;
    try {
      origin = (page.location as { readonly origin?: unknown } | undefined)?.origin;
    } catch (error) {
      stateError("document origin read failed", error);
    }
    this.#documentOrigin = requireWebOrigin(origin);
    this.#addPageListener = bindMethod(
      page,
      "addEventListener",
      "window.addEventListener",
    );
    this.#removePageListener = bindMethod(
      page,
      "removeEventListener",
      "window.removeEventListener",
    );
    this.#postPageMessage = bindMethod<PostPageMessage>(
      page,
      "postMessage",
      "window.postMessage",
    );
    this.#connect = bindMethod(runtime, "connect", "runtime.connect");
    this.#readNow = requireClock(options.readNow ?? Date.now);
    this.#requestTtlMs = requireBoundedInteger(
      options.requestTtlMs ?? DEFAULT_PROVIDER_CONTENT_REQUEST_TTL_MS,
      1,
      MAX_PROVIDER_CONTENT_REQUEST_TTL_MS,
      "requestTtlMs",
    );
    this.#timerSource = bindTimerSource(options.timerSource ?? DEFAULT_TIMER_SOURCE);
    this.#pendingLimit = requireBoundedInteger(
      options.pendingLimit ?? MAX_PROVIDER_CONTENT_PENDING_REQUESTS,
      1,
      MAX_PROVIDER_CONTENT_PENDING_REQUESTS,
      "pendingLimit",
    );
    this.#requestLimit = requireBoundedInteger(
      options.requestLimit ?? MAX_PROVIDER_CONTENT_REQUESTS_PER_DOCUMENT,
      1,
      MAX_PROVIDER_CONTENT_REQUESTS_PER_DOCUMENT,
      "requestLimit",
    );
    const channelSource = options.channelSource ?? DEFAULT_CHANNEL_SOURCE;
    if (typeof channelSource !== "function") {
      stateError("channelSource must be a function");
    }
    this.#channelSource = channelSource;
    if (CLAIMED_CONTENT_WINDOWS.has(this.#page)) {
      stateError("document already has a content transport owner");
    }
    CLAIMED_CONTENT_WINDOWS.add(this.#page);

    try {
      this.#pageListenerInstalled = true;
      this.#addPageListener("message", this.#onPageMessage);
    } catch (error) {
      this.#open = false;
      this.#removePageListenerBestEffort();
      CLAIMED_CONTENT_WINDOWS.delete(this.#page);
      stateError("page listener installation failed", error);
    }

    try {
      this.#grantCapability();
    } catch (error) {
      this.#open = false;
      this.#removePageListenerBestEffort();
      CLAIMED_CONTENT_WINDOWS.delete(this.#page);
      if (error instanceof ProviderContentTransportStateError) throw error;
      stateError("capability grant failed", error);
    }
  }

  /**
   * Mint and transfer the one-shot X-1 capability. Called exactly once, from
   * the constructor, so the port a document receives is bound to the first
   * owner installed in it and cannot be re-requested by page script later.
   */
  #grantCapability(): void {
    let channel: ProviderContentMessageChannel;
    try {
      channel = this.#channelSource();
    } catch (error) {
      if (error instanceof ProviderContentTransportStateError) throw error;
      stateError("capability channel could not be minted", error);
    }
    const local = requireObject(
      (channel as { readonly port1?: unknown } | undefined)?.port1,
      "capability port1",
    );
    const port: ProviderContentMessagePort = Object.freeze({
      addEventListener: bindMethod<ProviderContentMessagePort["addEventListener"]>(
        local,
        "addEventListener",
        "capability port1.addEventListener",
      ),
      removeEventListener: bindMethod<
        ProviderContentMessagePort["removeEventListener"]
      >(
        local,
        "removeEventListener",
        "capability port1.removeEventListener",
      ),
      postMessage: bindMethod<ProviderContentMessagePort["postMessage"]>(
        local,
        "postMessage",
        "capability port1.postMessage",
      ),
      start: bindMethod<ProviderContentMessagePort["start"]>(
        local,
        "start",
        "capability port1.start",
      ),
      close: bindMethod<ProviderContentMessagePort["close"]>(
        local,
        "close",
        "capability port1.close",
      ),
    });
    const transferred = (channel as { readonly port2?: unknown }).port2;
    if (typeof transferred !== "object" || transferred === null) {
      stateError("capability port2 is unavailable");
    }
    this.#capabilityPort = port;
    port.addEventListener("message", this.#onCapabilityMessage);
    port.start();
    this.#postPageMessage(
      createProviderCapabilityEnvelope(),
      this.#documentOrigin,
      [transferred],
    );
  }

  #releaseCapability(): void {
    const port = this.#capabilityPort;
    if (port === null) return;
    this.#capabilityPort = null;
    try {
      port.removeEventListener("message", this.#onCapabilityMessage);
    } catch {
      // The open flag already refuses every later delivery.
    }
    try {
      port.close();
    } catch {
      // A vanished document already tore the channel down.
    }
  }

  get pendingCount(): number {
    return this.#pending.size;
  }

  get issuedCount(): number {
    return this.#issued.size;
  }

  #currentTime(): number {
    let value: unknown;
    try {
      value = this.#readNow();
    } catch (error) {
      stateError("clock read failed", error);
    }
    if (!Number.isSafeInteger(value) || (value as number) < 0) {
      stateError("clock must return a non-negative safe integer");
    }
    return value as number;
  }

  #clearTimer(entry: PendingContentRequest): void {
    if (entry.expiryTimer === NO_EXPIRY_TIMER) return;
    const handle = entry.expiryTimer;
    entry.expiryTimer = NO_EXPIRY_TIMER;
    try {
      this.#timerSource.clearTimeout(handle);
    } catch {
      // Pending-map identity and absolute time remain authoritative.
    }
  }

  #removeEntry(entry: PendingContentRequest): boolean {
    if (this.#pending.get(entry.correlationId) !== entry) return false;
    this.#pending.delete(entry.correlationId);
    this.#clearTimer(entry);
    return true;
  }

  #expireEntry(entry: PendingContentRequest): void {
    if (this.#pending.get(entry.correlationId) !== entry) return;
    const owner = this.#activePort;
    if (
      owner !== null &&
      entry.lastPortGeneration === owner.generation
    ) {
      try {
        owner.postMessage(createProviderTransportCancelEnvelope(
          entry.expiresAt,
          entry.payload.payload,
        ));
      } catch {
        this.#releasePort(owner, true);
      }
    }
    this.#removeEntry(entry);
  }

  #reapExpiredAt(now: number): void {
    for (const entry of [...this.#pending.values()]) {
      if (now >= entry.expiresAt) this.#expireEntry(entry);
    }
  }

  #isFreshPendingEntry(entry: PendingContentRequest): boolean {
    let now: number;
    try {
      now = this.#currentTime();
    } catch {
      this.#close(true);
      return false;
    }
    this.#reapExpiredAt(now);
    return this.#pending.get(entry.correlationId) === entry;
  }

  #armExpiry(entry: PendingContentRequest): void {
    const remainingMs = entry.expiresAt - this.#currentTime();
    if (remainingMs <= 0) {
      this.#expireEntry(entry);
      return;
    }
    entry.expiryTimer = this.#timerSource.setTimeout(() => {
      if (this.#pending.get(entry.correlationId) !== entry) return;
      entry.expiryTimer = NO_EXPIRY_TIMER;
      let now: number;
      try {
        now = this.#currentTime();
      } catch {
        this.#close(true);
        return;
      }
      if (now >= entry.expiresAt) {
        this.#expireEntry(entry);
        return;
      }
      try {
        this.#armExpiry(entry);
      } catch {
        this.#close(true);
      }
    }, remainingMs);
  }

  #bindPort(): BoundContentPort {
    let rawPort: unknown;
    try {
      rawPort = this.#connect({ name: PROVIDER_PORT_NAME });
    } catch (error) {
      stateError("could not open provider Port", error);
    }
    const methods = bindPortMethods(rawPort);
    let owner!: BoundContentPort;
    owner = {
      generation: this.#nextPortGeneration++,
      ...methods,
      onMessage: (message: unknown): void => this.#onPortMessage(owner, message),
      onDisconnect: (): void => this.#onPortDisconnect(owner),
      messageListenerInstalled: false,
      disconnectListenerInstalled: false,
    };
    this.#activePort = owner;

    try {
      owner.messageListenerInstalled = true;
      owner.addMessageListener(owner.onMessage);
      if (!this.#open || this.#activePort !== owner) {
        stateError("provider Port closed during setup");
      }
      owner.disconnectListenerInstalled = true;
      owner.addDisconnectListener(owner.onDisconnect);
      if (!this.#open || this.#activePort !== owner) {
        stateError("provider Port closed during setup");
      }
    } catch (error) {
      this.#releasePort(owner, true);
      if (error instanceof ProviderContentTransportStateError) throw error;
      stateError("Port listener installation failed", error);
    }
    return owner;
  }

  #releasePort(owner: BoundContentPort, disconnectPort: boolean): void {
    if (this.#activePort === owner) this.#activePort = null;
    if (owner.messageListenerInstalled) {
      owner.messageListenerInstalled = false;
      try {
        owner.removeMessageListener(owner.onMessage);
      } catch {
        // Owner identity prevents a retained stale callback from forwarding.
      }
    }
    if (owner.disconnectListenerInstalled) {
      owner.disconnectListenerInstalled = false;
      try {
        owner.removeDisconnectListener(owner.onDisconnect);
      } catch {
        // Owner identity prevents a retained stale callback from reconnecting.
      }
    }
    if (disconnectPort) {
      try {
        owner.disconnect();
      } catch {
        // A vanished document or worker already removed the channel.
      }
    }
  }

  #removePageListenerBestEffort(): void {
    if (!this.#pageListenerInstalled) return;
    this.#pageListenerInstalled = false;
    try {
      this.#removePageListener("message", this.#onPageMessage);
    } catch {
      // The open flag and cleared pending map remain authoritative.
    }
  }

  #close(disconnectPort: boolean): void {
    if (!this.#open) return;
    this.#open = false;
    this.#removePageListenerBestEffort();
    this.#releaseCapability();
    for (const entry of [...this.#pending.values()]) this.#removeEntry(entry);
    if (this.#activePort !== null) {
      this.#releasePort(this.#activePort, disconnectPort);
    }
  }

  #sendReceipt(entry: PendingContentRequest): void {
    const owner = this.#activePort;
    const terminal = entry.terminal;
    if (
      owner === null ||
      terminal === null ||
      entry.pageReceiptId !== terminal.receiptId ||
      entry.lastPortGeneration !== owner.generation ||
      entry.receiptSentGeneration === owner.generation
    ) {
      return;
    }
    entry.receiptSentGeneration = owner.generation;
    try {
      owner.postMessage(createProviderTransportReceiptEnvelope(
        entry.correlationId,
        terminal.receiptId,
        entry.expiresAt,
      ));
    } catch {
      if (entry.receiptSentGeneration === owner.generation) {
        entry.receiptSentGeneration = null;
      }
      if (this.#activePort === owner) this.#releasePort(owner, true);
      this.#recoverGeneration(owner.generation);
      return;
    }
  }

  #acceptPageReceipt(
    receipt: ReturnType<typeof createProviderTransportReceiptEnvelope>,
  ): void {
    let now: number;
    try {
      now = this.#currentTime();
    } catch {
      this.#close(true);
      return;
    }
    this.#reapExpiredAt(now);
    const entry = this.#pending.get(receipt.correlationId);
    if (entry === undefined) return;
    const terminal = entry.terminal;
    if (
      terminal === null ||
      receipt.receiptId !== terminal.receiptId ||
      receipt.expiresAt !== entry.expiresAt
    ) {
      this.#close(true);
      return;
    }
    entry.pageReceiptId = receipt.receiptId;
    this.#sendReceipt(entry);
  }

  #onPortMessage(owner: BoundContentPort, value: unknown): void {
    if (!this.#open || this.#activePort !== owner) return;
    let now: number;
    try {
      now = this.#currentTime();
    } catch {
      this.#close(true);
      return;
    }
    this.#reapExpiredAt(now);
    const settled = readProviderTransportSettledEnvelope(value);
    if (settled !== null) {
      const entry = this.#pending.get(settled.correlationId);
      if (entry === undefined) return;
      if (
        entry.lastPortGeneration !== owner.generation ||
        entry.receiptSentGeneration !== owner.generation ||
        entry.pageReceiptId !== settled.receiptId ||
        entry.terminal?.receiptId !== settled.receiptId ||
        entry.expiresAt !== settled.expiresAt
      ) {
        this.#close(true);
        return;
      }
      this.#removeEntry(entry);
      return;
    }
    const delivery = snapshotTerminalResponse(value);
    if (delivery === null) {
      this.#close(true);
      return;
    }
    const entry = this.#pending.get(delivery.response.correlationId);
    if (
      entry === undefined ||
      entry.lastPortGeneration !== owner.generation
    ) {
      return;
    }

    if (
      delivery.envelope.expiresAt !== entry.expiresAt ||
      (entry.terminal !== null &&
        !terminalEnvelopesEqual(entry.terminal, delivery.envelope))
    ) {
      this.#close(true);
      return;
    }
    entry.terminal = delivery.envelope;
    if (entry.pageReceiptId === delivery.envelope.receiptId) {
      this.#sendReceipt(entry);
      return;
    }

    // Audit finding X-1: the terminal response leaves over the capability, not
    // over `window`, so only the holder of the transferred port can settle the
    // page promise it names.
    const capability = this.#capabilityPort;
    if (capability === null) {
      this.#close(true);
      return;
    }
    try {
      capability.postMessage(Object.freeze({
        version: 1,
        type: PAGE_PROVIDER_RESPONSE_TYPE,
        payload: delivery.envelope,
      }));
    } catch {
      this.#close(true);
    }
  }

  #onPortDisconnect(owner: BoundContentPort): void {
    const wasActive = this.#activePort === owner;
    this.#releasePort(owner, false);
    if (!this.#open || !wasActive) return;
    this.#recoverGeneration(owner.generation);
  }

  #recoverGeneration(generation: number): void {
    if (!this.#open) return;
    let now: number;
    try {
      now = this.#currentTime();
    } catch {
      this.#close(true);
      return;
    }
    this.#reapExpiredAt(now);
    const eligible = [...this.#pending.values()].filter((entry) =>
      entry.lastPortGeneration === generation &&
      entry.recoveryAttempts < MAX_PROVIDER_CONTENT_RECOVERY_ATTEMPTS
    );
    if (eligible.length === 0) return;

    // Spend every affected request's budget before opening a replacement. A
    // synchronous setup/disconnect callback can therefore never recurse into a
    // worker-wake loop.
    for (const entry of eligible) entry.recoveryAttempts++;
    let owner: BoundContentPort;
    try {
      owner = this.#bindPort();
    } catch {
      return;
    }
    for (const entry of eligible) {
      if (!this.#open || this.#activePort !== owner) return;
      if (!this.#isFreshPendingEntry(entry)) continue;
      if (!this.#open || this.#activePort !== owner) return;
      entry.lastPortGeneration = owner.generation;
      try {
        owner.postMessage(entry.payload);
      } catch {
        if (this.#activePort === owner) this.#releasePort(owner, true);
        return;
      }
    }
  }

  #connectForInitial(entry: PendingContentRequest): BoundContentPort | null {
    try {
      return this.#bindPort();
    } catch {
      if (
        entry.recoveryAttempts >= MAX_PROVIDER_CONTENT_RECOVERY_ATTEMPTS
      ) {
        return null;
      }
      entry.recoveryAttempts++;
      try {
        return this.#bindPort();
      } catch {
        return null;
      }
    }
  }

  #dispatchInitial(entry: PendingContentRequest): void {
    let owner = this.#activePort;
    if (owner === null) owner = this.#connectForInitial(entry);
    if (owner === null || !this.#isFreshPendingEntry(entry)) return;
    if (!this.#open || this.#activePort !== owner) return;
    entry.lastPortGeneration = owner.generation;
    try {
      owner.postMessage(entry.payload);
    } catch {
      if (this.#activePort === owner) this.#releasePort(owner, true);
      if (this.#pending.get(entry.correlationId) === entry) {
        this.#recoverGeneration(owner.generation);
      }
    }
  }

  dispose(): void {
    this.#close(true);
  }
}
