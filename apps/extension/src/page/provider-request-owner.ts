//! Still-unreachable C16 main-world request/promise owner.
//!
//! Chrome Port and Window message sends are enqueue operations, not page
//! receipt acknowledgments. This owner therefore makes the page promise the
//! terminal idempotence boundary: it mints a correlation exactly once, installs
//! the pending entry before sending, removes it before first settlement, and
//! retains every issued id as a bounded document-lifetime tombstone. It is not
//! imported by any production entry point yet.

import {
  MAX_PROVIDER_REQUESTS_PER_DOCUMENT,
  PAGE_PROVIDER_REQUEST_TYPE,
  PAGE_PROVIDER_RESPONSE_TYPE,
  isProviderUnavailableResponse,
  type ProviderUnavailableResponse,
} from "../provider-protocol.js";
import {
  parseProviderRequest,
  type ProviderChain,
  type ProviderCommitment,
  type ProviderSignTransactionRequest,
} from "../background/provider-message.js";
import {
  isProviderTerminalFailureResponse,
  isSignedTransactionProviderResponse,
  providerTerminalFailureMessage,
  type ProviderSignedTransactionResponse,
  type ProviderTerminalFailureCode,
  type ProviderTerminalFailureResponse,
} from "../background/provider-terminal-protocol.js";
import {
  createPageProviderReceiptEnvelope,
  createProviderTransportReceiptEnvelope,
  createProviderTransportRequestEnvelope,
  readProviderTransportTerminalEnvelope,
  type ProviderTransportReceiptEnvelope,
} from "../provider-delivery-protocol.js";

export const DEFAULT_PAGE_PROVIDER_REQUEST_TTL_MS = 2 * 60 * 1_000;
export const MAX_PAGE_PROVIDER_REQUEST_TTL_MS = 10 * 60 * 1_000;
export const MAX_PAGE_PROVIDER_PENDING_REQUESTS = 32;
export const MAX_PAGE_PROVIDER_REQUESTS_PER_DOCUMENT =
  MAX_PROVIDER_REQUESTS_PER_DOCUMENT;

const CORRELATION_ID_BYTES = 16;
const CORRELATION_ID_ATTEMPTS = 8;
const NO_EXPIRY_TIMER = Symbol("no-expiry-timer");
const VALIDATION_CORRELATION_ID = "page_validation_0000000000000000";
const CLAIMED_PAGE_WINDOWS = new WeakSet<ProviderPageWindowApi>();

export interface ProviderPageSignTransactionOptions {
  readonly preflightCommitment?: ProviderCommitment;
  readonly minContextSlot?: number;
}

export interface ProviderPageSignTransactionInput {
  readonly accountAddress: string;
  readonly transaction: Uint8Array;
  readonly chain?: ProviderChain;
  readonly options?: Readonly<ProviderPageSignTransactionOptions>;
}

export interface ProviderPageWindowMessageEvent {
  readonly data: unknown;
  readonly origin: string;
  readonly source: unknown;
}

export type ProviderPageWindowMessageListener = (
  event: ProviderPageWindowMessageEvent,
) => void;

export interface ProviderPageWindowApi {
  readonly location: { readonly origin: string };
  addEventListener(
    type: "message",
    listener: ProviderPageWindowMessageListener,
  ): void;
  removeEventListener(
    type: "message",
    listener: ProviderPageWindowMessageListener,
  ): void;
  postMessage(message: unknown, targetOrigin: string): void;
}

export interface ProviderPageRandomSource {
  getRandomValues(target: Uint8Array): Uint8Array;
}

export interface ProviderPageTimerSource {
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface ProviderPageRequestOwnerOptions {
  readonly readNow?: () => number;
  readonly requestTtlMs?: number;
  /** May only lower the production bound; useful for focused tests. */
  readonly pendingLimit?: number;
  /** May only lower the production bound; useful for focused tests. */
  readonly requestLimit?: number;
  /** Test seam. Production callers omit this and use Web Crypto. */
  readonly randomSource?: ProviderPageRandomSource;
  /** Test seam. Absolute-time checks remain authoritative over this timer. */
  readonly timerSource?: ProviderPageTimerSource;
}

export class ProviderPageRequestStateError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`provider page request: ${message}`, options);
    this.name = "ProviderPageRequestStateError";
  }
}

export class ProviderPageMethodUnavailableError extends Error {
  readonly code = "WARDEN_METHOD_UNAVAILABLE" as const;

  constructor() {
    super("Warden provider methods are not enabled");
    this.name = "ProviderPageMethodUnavailableError";
  }
}

export class ProviderPageTerminalError extends Error {
  readonly code: ProviderTerminalFailureCode;

  constructor(code: ProviderTerminalFailureCode) {
    super(providerTerminalFailureMessage(code));
    this.name = "ProviderPageTerminalError";
    this.code = code;
  }
}

export class ProviderPageRequestTimeoutError extends Error {
  constructor() {
    super("provider request timed out");
    this.name = "ProviderPageRequestTimeoutError";
  }
}

export class ProviderPageRequestDisposedError extends Error {
  constructor() {
    super("provider page request owner is disposed");
    this.name = "ProviderPageRequestDisposedError";
  }
}

interface CanonicalSignTransactionParams {
  readonly accountAddress: string;
  readonly transaction: readonly number[];
  readonly chain: ProviderChain | null;
  readonly options: Readonly<ProviderPageSignTransactionOptions>;
}

interface PendingPageRequest {
  readonly correlationId: string;
  readonly expiresAt: number;
  readonly resolve: (transaction: Uint8Array) => void;
  readonly reject: (error: Error) => void;
  expiryTimer: unknown;
}

interface SettledPageReceipt {
  readonly receiptId: string;
  readonly expiresAt: number;
}

interface ProviderPageTerminalDelivery {
  readonly response: ProviderTerminalResponse;
  readonly receipt: ProviderTransportReceiptEnvelope;
}

type ProviderTerminalResponse =
  | ProviderUnavailableResponse
  | ProviderSignedTransactionResponse
  | ProviderTerminalFailureResponse;

const DEFAULT_TIMER_SOURCE: ProviderPageTimerSource = {
  setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
  clearTimeout: (handle) =>
    globalThis.clearTimeout(handle as ReturnType<typeof globalThis.setTimeout>),
};

function stateError(message: string, cause?: unknown): never {
  throw new ProviderPageRequestStateError(
    message,
    cause === undefined ? {} : { cause },
  );
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

function requireRandomSource(value: unknown): ProviderPageRandomSource {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as Partial<ProviderPageRandomSource>).getRandomValues !== "function"
  ) {
    stateError("Web Crypto random source is unavailable");
  }
  const source = value as ProviderPageRandomSource;
  return Object.freeze({ getRandomValues: source.getRandomValues.bind(source) });
}

function requireTimerSource(value: unknown): ProviderPageTimerSource {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as Partial<ProviderPageTimerSource>).setTimeout !== "function" ||
    typeof (value as Partial<ProviderPageTimerSource>).clearTimeout !== "function"
  ) {
    stateError("timer source is unavailable");
  }
  const source = value as ProviderPageTimerSource;
  return Object.freeze({
    setTimeout: source.setTimeout.bind(source),
    clearTimeout: source.clearTimeout.bind(source),
  });
}

function requirePage(value: unknown): ProviderPageWindowApi {
  if (typeof value !== "object" || value === null) {
    stateError("window API is unavailable");
  }
  const page = value as Partial<ProviderPageWindowApi>;
  if (
    typeof page.addEventListener !== "function" ||
    typeof page.removeEventListener !== "function" ||
    typeof page.postMessage !== "function"
  ) {
    stateError("window API is malformed");
  }
  return value as ProviderPageWindowApi;
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

function exactDataRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  name: string,
): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    stateError(`${name} must be an object`);
  }
  const allowed = new Set([...required, ...optional]);
  const result: Record<string, unknown> = {};
  let keys: readonly PropertyKey[];
  try {
    keys = Reflect.ownKeys(value);
  } catch (error) {
    stateError(`${name} fields are inaccessible`, error);
  }
  if (
    keys.some((key) => typeof key !== "string" || !allowed.has(key)) ||
    required.some((field) => !keys.includes(field))
  ) {
    stateError(`${name} has missing or unknown fields`);
  }
  for (const key of keys) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch (error) {
      stateError(`${name}.${String(key)} is inaccessible`, error);
    }
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      stateError(`${name}.${String(key)} must be an enumerable data property`);
    }
    result[key as string] = descriptor.value;
  }
  return Object.freeze(result);
}

function snapshotSignTransactionInput(value: unknown): CanonicalSignTransactionParams {
  const input = exactDataRecord(
    value,
    ["accountAddress", "transaction"],
    ["chain", "options"],
    "signTransaction input",
  );
  if (!(input.transaction instanceof Uint8Array)) {
    stateError("signTransaction transaction must be a Uint8Array");
  }
  let transaction: Uint8Array;
  try {
    transaction = input.transaction.slice();
  } catch (error) {
    stateError("signTransaction transaction could not be copied", error);
  }

  const params: Record<string, unknown> = {
    accountAddress: input.accountAddress,
    transaction: Array.from(transaction),
  };
  transaction.fill(0);
  if (Object.hasOwn(input, "chain")) params.chain = input.chain;
  if (Object.hasOwn(input, "options")) {
    const options = exactDataRecord(
      input.options,
      [],
      ["preflightCommitment", "minContextSlot"],
      "signTransaction options",
    );
    params.options = { ...options };
  }

  let parsed: ProviderSignTransactionRequest;
  try {
    const request = parseProviderRequest({
      version: 1,
      type: "request",
      correlationId: VALIDATION_CORRELATION_ID,
      method: "solana:signTransaction",
      params,
    });
    if (request.method !== "solana:signTransaction") {
      stateError("validated request changed method");
    }
    parsed = request;
  } catch (error) {
    if (error instanceof ProviderPageRequestStateError) throw error;
    stateError("signTransaction input is malformed", error);
  }

  const options: Readonly<ProviderPageSignTransactionOptions> = Object.freeze({
    ...(parsed.params.options.preflightCommitment === null
      ? {}
      : { preflightCommitment: parsed.params.options.preflightCommitment }),
    ...(parsed.params.options.minContextSlot === null
      ? {}
      : { minContextSlot: parsed.params.options.minContextSlot }),
  });
  return Object.freeze({
    accountAddress: parsed.params.requestedAccountAddress,
    transaction: Object.freeze([...parsed.params.transaction]),
    chain: parsed.params.chain,
    options,
  });
}

function createWireRequest(
  correlationId: string,
  input: CanonicalSignTransactionParams,
): ProviderSignTransactionRequest | Readonly<Record<string, unknown>> {
  const params: Record<string, unknown> = {
    accountAddress: input.accountAddress,
    transaction: input.transaction,
    options: input.options,
  };
  if (input.chain !== null) params.chain = input.chain;
  return Object.freeze({
    version: 1,
    type: "request",
    correlationId,
    method: "solana:signTransaction",
    params: Object.freeze(params),
  });
}

function hasExactDataFields(
  value: Record<string, unknown>,
  fields: readonly string[],
): boolean {
  try {
    const keys = Reflect.ownKeys(value);
    return keys.length === fields.length &&
      keys.every((key) => typeof key === "string" && fields.includes(key)) &&
      fields.every((field) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, field);
        return descriptor !== undefined &&
          "value" in descriptor &&
          descriptor.enumerable === true;
      });
  } catch {
    return false;
  }
}

function readTerminalResponseEnvelope(
  value: unknown,
): ProviderPageTerminalDelivery | null {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return null;
    }
    const envelope = value as Record<string, unknown>;
    if (
      !hasExactDataFields(envelope, ["version", "type", "payload"]) ||
      envelope.version !== 1 ||
      envelope.type !== PAGE_PROVIDER_RESPONSE_TYPE
    ) {
      return null;
    }
    const delivery = readProviderTransportTerminalEnvelope(envelope.payload);
    if (delivery === null) return null;
    const payload = delivery.payload;
    const response = isProviderUnavailableResponse(payload)
      ? payload
      : isSignedTransactionProviderResponse(payload)
      ? payload
      : isProviderTerminalFailureResponse(payload)
      ? payload
      : null;
    if (response === null || response.correlationId !== delivery.correlationId) {
      return null;
    }
    return Object.freeze({
      response,
      receipt: createProviderTransportReceiptEnvelope(
        delivery.correlationId,
        delivery.receiptId,
        delivery.expiresAt,
      ),
    });
  } catch {
    return null;
  }
}

function encodeCorrelationId(bytes: Uint8Array): string {
  let encoded = "page_";
  for (const byte of bytes) encoded += byte.toString(16).padStart(2, "0");
  return encoded;
}

/**
 * Owns one main-world document's signTransaction promises. Same-page scripts
 * remain the caller trust principal and can observe, suppress, or forge page
 * traffic; this class grants them no origin, approval, account, or key
 * authority. Its guarantee is narrower: one owner-issued correlation can
 * settle at most one owner-created promise and can never name a later request.
 */
export class ProviderPageRequestOwner {
  readonly #page: ProviderPageWindowApi;
  readonly #documentOrigin: string;
  readonly #readNow: () => number;
  readonly #requestTtlMs: number;
  readonly #pendingLimit: number;
  readonly #requestLimit: number;
  readonly #randomSource: ProviderPageRandomSource;
  readonly #timerSource: ProviderPageTimerSource;
  readonly #pending = new Map<string, PendingPageRequest>();
  readonly #issued = new Set<string>();
  readonly #settledReceipts = new Map<string, SettledPageReceipt>();
  #disposed = false;
  #listenerInstalled = false;

  readonly #onMessage = (event: ProviderPageWindowMessageEvent): void => {
    if (
      this.#disposed ||
      event.source !== this.#page ||
      event.origin !== this.#documentOrigin
    ) {
      return;
    }
    const delivery = readTerminalResponseEnvelope(event.data);
    if (delivery === null) return;
    const { response, receipt } = delivery;

    let now: number;
    try {
      now = this.#currentTime();
    } catch (error) {
      this.#closeAfterFatal(error);
      return;
    }
    this.#reapExpiredAt(now);
    const entry = this.#pending.get(response.correlationId);
    if (entry === undefined) {
      const settled = this.#settledReceipts.get(response.correlationId);
      if (
        settled !== undefined &&
        settled.receiptId === receipt.receiptId &&
        settled.expiresAt === receipt.expiresAt &&
        now < settled.expiresAt
      ) {
        this.#postReceipt(receipt);
      }
      return;
    }
    if (receipt.expiresAt !== entry.expiresAt) {
      this.#closeAfterFatal(
        new ProviderPageRequestStateError("terminal delivery changed the request deadline"),
      );
      return;
    }
    if (now >= entry.expiresAt) {
      this.#rejectEntry(entry, new ProviderPageRequestTimeoutError());
      return;
    }

    this.#settledReceipts.set(entry.correlationId, Object.freeze({
      receiptId: receipt.receiptId,
      expiresAt: receipt.expiresAt,
    }));

    if (isProviderUnavailableResponse(response)) {
      this.#rejectEntry(entry, new ProviderPageMethodUnavailableError());
      this.#postReceipt(receipt);
      return;
    }
    if (isProviderTerminalFailureResponse(response)) {
      this.#rejectEntry(entry, new ProviderPageTerminalError(response.error.code));
      this.#postReceipt(receipt);
      return;
    }
    let bytes: Uint8Array;
    try {
      bytes = Uint8Array.from(response.result.signedTransaction);
    } catch (error) {
      this.#rejectEntry(
        entry,
        new ProviderPageRequestStateError("signed result could not be copied", {
          cause: error,
        }),
      );
      this.#postReceipt(receipt);
      return;
    }
    this.#resolveEntry(entry, bytes);
    this.#postReceipt(receipt);
  };

  constructor(
    pageValue: ProviderPageWindowApi,
    options: ProviderPageRequestOwnerOptions = {},
  ) {
    this.#page = requirePage(pageValue);
    let origin: unknown;
    try {
      origin = this.#page.location?.origin;
    } catch (error) {
      stateError("document origin read failed", error);
    }
    this.#documentOrigin = requireWebOrigin(origin);
    this.#readNow = requireClock(options.readNow ?? Date.now);
    this.#requestTtlMs = requireBoundedInteger(
      options.requestTtlMs ?? DEFAULT_PAGE_PROVIDER_REQUEST_TTL_MS,
      1,
      MAX_PAGE_PROVIDER_REQUEST_TTL_MS,
      "requestTtlMs",
    );
    this.#pendingLimit = requireBoundedInteger(
      options.pendingLimit ?? MAX_PAGE_PROVIDER_PENDING_REQUESTS,
      1,
      MAX_PAGE_PROVIDER_PENDING_REQUESTS,
      "pendingLimit",
    );
    this.#requestLimit = requireBoundedInteger(
      options.requestLimit ?? MAX_PAGE_PROVIDER_REQUESTS_PER_DOCUMENT,
      1,
      MAX_PAGE_PROVIDER_REQUESTS_PER_DOCUMENT,
      "requestLimit",
    );
    this.#randomSource = requireRandomSource(
      options.randomSource ?? globalThis.crypto,
    );
    this.#timerSource = requireTimerSource(
      options.timerSource ?? DEFAULT_TIMER_SOURCE,
    );
    if (CLAIMED_PAGE_WINDOWS.has(this.#page)) {
      stateError("document already has a request owner");
    }
    CLAIMED_PAGE_WINDOWS.add(this.#page);

    try {
      this.#listenerInstalled = true;
      this.#page.addEventListener("message", this.#onMessage);
    } catch (error) {
      this.#disposed = true;
      this.#removeListener();
      CLAIMED_PAGE_WINDOWS.delete(this.#page);
      stateError("response listener installation failed", error);
    }
  }

  get pendingCount(): number {
    return this.#pending.size;
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

  #mintCorrelationId(): string {
    for (let attempt = 0; attempt < CORRELATION_ID_ATTEMPTS; attempt++) {
      const bytes = new Uint8Array(CORRELATION_ID_BYTES);
      try {
        const returned = this.#randomSource.getRandomValues(bytes);
        if (returned !== bytes) {
          stateError("random source returned a different buffer");
        }
        const id = encodeCorrelationId(bytes);
        if (!this.#issued.has(id)) {
          this.#issued.add(id);
          return id;
        }
      } catch (error) {
        if (error instanceof ProviderPageRequestStateError) throw error;
        stateError("Web Crypto correlation generation failed", error);
      } finally {
        bytes.fill(0);
      }
    }
    stateError("could not mint a unique correlation id");
  }

  #clearTimer(entry: PendingPageRequest): void {
    if (entry.expiryTimer === NO_EXPIRY_TIMER) return;
    try {
      this.#timerSource.clearTimeout(entry.expiryTimer);
    } catch {
      // The exact pending-map identity and absolute deadline remain authoritative.
    } finally {
      entry.expiryTimer = NO_EXPIRY_TIMER;
    }
  }

  #removeEntry(entry: PendingPageRequest): boolean {
    if (this.#pending.get(entry.correlationId) !== entry) return false;
    this.#pending.delete(entry.correlationId);
    this.#clearTimer(entry);
    return true;
  }

  #resolveEntry(entry: PendingPageRequest, bytes: Uint8Array): void {
    if (!this.#removeEntry(entry)) {
      bytes.fill(0);
      return;
    }
    entry.resolve(bytes);
  }

  #rejectEntry(entry: PendingPageRequest, error: Error): void {
    if (!this.#removeEntry(entry)) return;
    entry.reject(error);
  }

  #postReceipt(receipt: ProviderTransportReceiptEnvelope): void {
    try {
      this.#page.postMessage(
        createPageProviderReceiptEnvelope(receipt),
        this.#documentOrigin,
      );
    } catch {
      // The promise is already settled. A duplicate exact terminal delivery
      // may retry this idempotent receipt while the document remains alive.
    }
  }

  #reapExpiredAt(now: number): void {
    for (const entry of [...this.#pending.values()]) {
      if (now >= entry.expiresAt) {
        this.#rejectEntry(entry, new ProviderPageRequestTimeoutError());
      }
    }
  }

  #armExpiry(entry: PendingPageRequest): void {
    const remainingMs = entry.expiresAt - this.#currentTime();
    if (remainingMs <= 0) {
      this.#rejectEntry(entry, new ProviderPageRequestTimeoutError());
      return;
    }
    try {
      entry.expiryTimer = this.#timerSource.setTimeout(() => {
        if (this.#pending.get(entry.correlationId) !== entry) return;
        entry.expiryTimer = NO_EXPIRY_TIMER;
        let now: number;
        try {
          now = this.#currentTime();
        } catch (error) {
          this.#closeAfterFatal(error);
          return;
        }
        if (now >= entry.expiresAt) {
          this.#rejectEntry(entry, new ProviderPageRequestTimeoutError());
          return;
        }
        try {
          this.#armExpiry(entry);
        } catch (error) {
          this.#closeAfterFatal(error);
        }
      }, remainingMs);
    } catch (error) {
      stateError("expiry timer setup failed", error);
    }
  }

  #removeListener(): void {
    if (!this.#listenerInstalled) return;
    try {
      this.#page.removeEventListener("message", this.#onMessage);
    } catch {
      // Closing the in-memory owner still removes every settlement capability.
    } finally {
      this.#listenerInstalled = false;
    }
  }

  #closeAfterFatal(error: unknown): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#removeListener();
    const failure = error instanceof Error
      ? error
      : new ProviderPageRequestStateError("request owner failed");
    for (const entry of [...this.#pending.values()]) {
      this.#rejectEntry(entry, failure);
    }
  }

  signTransaction(value: ProviderPageSignTransactionInput): Promise<Uint8Array> {
    let input: CanonicalSignTransactionParams;
    try {
      if (this.#disposed) throw new ProviderPageRequestDisposedError();
      input = snapshotSignTransactionInput(value);
      const now = this.#currentTime();
      this.#reapExpiredAt(now);
      if (this.#pending.size >= this.#pendingLimit) {
        stateError("too many pending requests");
      }
      if (this.#issued.size >= this.#requestLimit) {
        stateError("request limit reached");
      }
      const correlationId = this.#mintCorrelationId();
      const expiresAt = now + this.#requestTtlMs;
      if (!Number.isSafeInteger(expiresAt)) {
        stateError("request expiry overflowed");
      }

      let resolvePromise!: (transaction: Uint8Array) => void;
      let rejectPromise!: (error: Error) => void;
      const promise = new Promise<Uint8Array>((resolve, reject) => {
        resolvePromise = resolve;
        rejectPromise = reject;
      });
      const entry: PendingPageRequest = {
        correlationId,
        expiresAt,
        resolve: resolvePromise,
        reject: rejectPromise,
        expiryTimer: NO_EXPIRY_TIMER,
      };
      this.#pending.set(correlationId, entry);

      try {
        this.#armExpiry(entry);
      } catch (error) {
        this.#rejectEntry(
          entry,
          new ProviderPageRequestStateError("request timer setup failed", {
            cause: error,
          }),
        );
        return promise;
      }
      if (this.#pending.get(correlationId) !== entry) return promise;

      try {
        const request = createProviderTransportRequestEnvelope(
          expiresAt,
          createWireRequest(correlationId, input),
        );
        this.#page.postMessage(
          Object.freeze({
            version: 1,
            type: PAGE_PROVIDER_REQUEST_TYPE,
            payload: request,
          }),
          this.#documentOrigin,
        );
      } catch (error) {
        this.#rejectEntry(
          entry,
          new ProviderPageRequestStateError("request transport failed", {
            cause: error,
          }),
        );
      }
      return promise;
    } catch (error) {
      const failure = error instanceof Error
        ? error
        : new ProviderPageRequestStateError("request creation failed");
      return Promise.reject(failure);
    }
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#removeListener();
    for (const entry of [...this.#pending.values()]) {
      this.#rejectEntry(entry, new ProviderPageRequestDisposedError());
    }
  }
}
