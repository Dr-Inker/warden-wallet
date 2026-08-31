//! Still-unreachable C21 background replacement-Port transport owner.
//!
//! One browser document may replace its current Port without relying on the
//! relative delivery order of the old background/content onDisconnect events.
//! An overlapping replacement preserves a live volatile request only when the
//! complete Chrome provenance and exact cryptographic operation identity match.
//! If background cleanup wins first, the old lease stays aborted forever and a
//! later Port receives a fresh lease whose safety depends on the durable C13-C19
//! replay graph. This module is deliberately absent from the production worker.

import {
  deriveProviderOperationIdentityFromRequest,
  type ProviderOperationDigestSource,
} from "./provider-operation.js";
import {
  parseProviderRequest,
  type ProviderSignTransactionRequest,
} from "./provider-message.js";
import {
  createProviderTerminalFailureResponse,
  createSignedTransactionProviderResponse,
  isProviderTerminalFailureResponse,
  isSignedTransactionProviderResponse,
  type ProviderTerminalResponse,
} from "./provider-terminal-protocol.js";
import {
  MAX_ACTIVE_PROVIDER_PORTS,
  DEFAULT_PROVIDER_REQUEST_TTL_MS,
  MAX_PENDING_PROVIDER_REQUESTS,
  MAX_PROVIDER_REQUEST_TTL_MS,
  MAX_PROVIDER_REQUEST_IDS_PER_SESSION,
  MAX_PROVIDER_REQUESTS_PER_PORT,
  PROVIDER_PORT_NAME,
  ProviderPortSession,
  type OwnedProviderRequest,
  type ProviderCancellationReason,
  type ProviderConnectEvent,
  type ProviderPortSessionOptions,
  type ProviderRuntimeApi,
  type ProviderRuntimePort,
} from "./provider-port.js";
import {
  classifyProviderSender,
  type ProviderProvenance,
} from "./sender-provenance.js";
import type { ProviderTerminalDeliveryLease } from "./provider-terminal-result.js";

export const MAX_PROVIDER_RUNTIME_REPLAYS_PER_REQUEST = 1;
export const MAX_PROVIDER_RUNTIME_ATTEMPTS_PER_REQUEST =
  1 + MAX_PROVIDER_RUNTIME_REPLAYS_PER_REQUEST;
export const MAX_PROVIDER_RUNTIME_DOCUMENTS = MAX_ACTIVE_PROVIDER_PORTS;
export const MAX_PROVIDER_RUNTIME_CORRELATIONS_PER_DOCUMENT =
  MAX_PROVIDER_REQUESTS_PER_PORT;
export const MAX_PROVIDER_RUNTIME_REQUEST_IDS_PER_DOCUMENT =
  MAX_PROVIDER_RUNTIME_CORRELATIONS_PER_DOCUMENT *
  MAX_PROVIDER_RUNTIME_ATTEMPTS_PER_REQUEST;

if (
  MAX_PROVIDER_RUNTIME_REQUEST_IDS_PER_DOCUMENT >
  MAX_PROVIDER_REQUEST_IDS_PER_SESSION
) {
  throw new Error("provider runtime request-id capacity exceeds the session bound");
}

const EXTENSION_ID_PATTERN = /^[a-p]{32}$/;

export interface ProviderRuntimeTransportLease
  extends ProviderTerminalDeliveryLease {}

export interface ProviderRuntimeTransportFlow {
  deliver(lease: ProviderRuntimeTransportLease): Promise<unknown>;
}

export interface ProviderRuntimeTransportOptions
  extends ProviderPortSessionOptions {
  readonly digestSource?: ProviderOperationDigestSource;
}

export class ProviderRuntimeTransportStateError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`provider runtime transport: ${message}`, options);
    this.name = "ProviderRuntimeTransportStateError";
  }
}

interface BoundPort {
  readonly generation: number;
  readonly provenance: ProviderProvenance;
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
  open: boolean;
}

interface ActiveDelivery {
  readonly owned: OwnedProviderRequest;
  postedGeneration: number | null;
}

interface CorrelationBinding {
  readonly correlationId: string;
  readonly operationKey: string;
  readonly expiresAt: number;
  attempts: number;
  lastRequestGeneration: number;
  deliveredGeneration: number | null;
  active: ActiveDelivery | null;
}

interface DocumentRoute {
  readonly provenance: ProviderProvenance;
  readonly session: ProviderPortSession;
  readonly correlations: Map<string, CorrelationBinding>;
  currentPort: BoundPort | null;
  queue: Promise<void>;
  queuedRequests: number;
  open: boolean;
}

interface BoundDependencies {
  readonly deliver: ProviderRuntimeTransportFlow["deliver"];
  readonly readNow: () => number;
  readonly digestSource: ProviderOperationDigestSource | undefined;
  readonly requestTtlMs: number;
  readonly sessionOptions: ProviderPortSessionOptions;
}

function stateError(message: string, cause?: unknown): never {
  throw new ProviderRuntimeTransportStateError(
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
  try {
    return value.bind(owner) as T;
  } catch (error) {
    stateError(`${name} binding failed`, error);
  }
}

function requireClock(value: unknown): () => number {
  if (typeof value !== "function") stateError("readNow must be a function");
  return value as () => number;
}

function requireRequestTtl(value: unknown): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1 ||
    (value as number) > MAX_PROVIDER_REQUEST_TTL_MS
  ) {
    stateError(`requestTtlMs must be 1..${MAX_PROVIDER_REQUEST_TTL_MS}`);
  }
  return value as number;
}

function bindDependencies(
  flowValue: unknown,
  options: ProviderRuntimeTransportOptions,
): BoundDependencies {
  const flow = requireObject(flowValue, "flow owner");
  const requestTtlMs = requireRequestTtl(
    options.requestTtlMs ?? DEFAULT_PROVIDER_REQUEST_TTL_MS,
  );
  const digestSource = options.digestSource;
  if (
    digestSource !== undefined &&
    (typeof digestSource !== "object" ||
      digestSource === null ||
      typeof digestSource.digest !== "function")
  ) {
    stateError("digestSource must provide digest()");
  }
  return Object.freeze({
    deliver: bindMethod<ProviderRuntimeTransportFlow["deliver"]>(
      flow,
      "deliver",
      "flow.deliver",
    ),
    readNow: requireClock(options.readNow ?? Date.now),
    digestSource,
    requestTtlMs,
    sessionOptions: Object.freeze({
      readNow: options.readNow,
      requestTtlMs,
      randomSource: options.randomSource,
      timerSource: options.timerSource,
      requestLimit: MAX_PROVIDER_RUNTIME_REQUEST_IDS_PER_DOCUMENT,
    }),
  });
}

function currentTime(readNow: () => number): number {
  let value: unknown;
  try {
    value = readNow();
  } catch (error) {
    stateError("clock read failed", error);
  }
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    stateError("clock must return a non-negative safe integer");
  }
  return value as number;
}

function provenanceEqual(
  left: ProviderProvenance,
  right: ProviderProvenance,
): boolean {
  return left.kind === right.kind &&
    left.extensionId === right.extensionId &&
    left.documentId === right.documentId &&
    left.origin === right.origin &&
    left.tabId === right.tabId &&
    left.frameId === right.frameId;
}

function canonicalWireRequest(
  request: ProviderSignTransactionRequest,
): Readonly<Record<string, unknown>> {
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
  });
}

function snapshotSignRequest(value: unknown): ProviderSignTransactionRequest {
  let parsed;
  try {
    parsed = parseProviderRequest(value);
  } catch (error) {
    stateError("provider request is malformed", error);
  }
  if (parsed.method !== "solana:signTransaction") {
    stateError("provider method is unsupported");
  }
  return parsed;
}

function snapshotTerminal(value: unknown): ProviderTerminalResponse {
  try {
    if (isProviderTerminalFailureResponse(value)) {
      return createProviderTerminalFailureResponse(
        value.correlationId,
        value.error.code,
      );
    }
    if (!isSignedTransactionProviderResponse(value)) {
      stateError("flow attempted to post a malformed terminal response");
    }
    let bytes: Uint8Array | undefined;
    try {
      bytes = Uint8Array.from(value.result.signedTransaction);
      return createSignedTransactionProviderResponse(value.correlationId, bytes);
    } finally {
      bytes?.fill(0);
    }
  } catch (error) {
    if (error instanceof ProviderRuntimeTransportStateError) throw error;
    stateError("flow terminal response could not be copied", error);
  }
}

function exactDeliveredResult(value: unknown): boolean {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return false;
    }
    const record = value as Record<PropertyKey, unknown>;
    const keys = Reflect.ownKeys(record);
    if (
      keys.length !== 2 ||
      !keys.includes("kind") ||
      !keys.includes("replayed")
    ) {
      return false;
    }
    for (const field of ["kind", "replayed"] as const) {
      const descriptor = Object.getOwnPropertyDescriptor(record, field);
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        descriptor.enumerable !== true
      ) {
        return false;
      }
    }
    return record.kind === "delivered" && typeof record.replayed === "boolean";
  } catch {
    return false;
  }
}

function safeDisconnectRaw(value: unknown): void {
  try {
    if (typeof value !== "object" || value === null) return;
    const disconnect = (value as { readonly disconnect?: unknown }).disconnect;
    if (typeof disconnect === "function") disconnect.call(value);
  } catch {
    // An already-malformed or vanished Port has no usable authority channel.
  }
}

/**
 * Owns the still-internal background side of C20's reconnect. The flow
 * dependency is expected to be C18; this class cannot select accounts, prepare
 * approvals, open windows, read RPC, touch keys, or construct a terminal value.
 */
export class ProviderRuntimeTransportOwner {
  readonly #runtimeId: string;
  readonly #addConnectListener: ProviderConnectEvent["addListener"];
  readonly #removeConnectListener: ProviderConnectEvent["removeListener"];
  readonly #dependencies: BoundDependencies;
  readonly #documents = new Map<string, DocumentRoute>();
  #nextGeneration = 1;
  #disposed = false;
  #connectListenerInstalled = false;

  readonly #onConnect = (rawPort: ProviderRuntimePort): void => {
    this.#acceptPort(rawPort);
  };

  constructor(
    runtimeValue: ProviderRuntimeApi,
    flowValue: ProviderRuntimeTransportFlow,
    options: ProviderRuntimeTransportOptions = {},
  ) {
    const runtime = requireObject(runtimeValue, "runtime API");
    let runtimeId: unknown;
    let onConnectValue: unknown;
    try {
      runtimeId = runtime.id;
      onConnectValue = runtime.onConnect;
    } catch (error) {
      stateError("runtime API access failed", error);
    }
    if (typeof runtimeId !== "string" || !EXTENSION_ID_PATTERN.test(runtimeId)) {
      stateError("runtime extension id is malformed");
    }
    const onConnect = requireObject(onConnectValue, "runtime.onConnect");
    this.#runtimeId = runtimeId;
    this.#addConnectListener = bindMethod(
      onConnect,
      "addListener",
      "runtime.onConnect.addListener",
    );
    this.#removeConnectListener = bindMethod(
      onConnect,
      "removeListener",
      "runtime.onConnect.removeListener",
    );
    this.#dependencies = bindDependencies(flowValue, options);

    try {
      this.#connectListenerInstalled = true;
      this.#addConnectListener(this.#onConnect);
    } catch (error) {
      this.#connectListenerInstalled = false;
      stateError("runtime connect listener installation failed", error);
    }
  }

  get activeDocumentCount(): number {
    return this.#documents.size;
  }

  #newGeneration(): number {
    if (
      !Number.isSafeInteger(this.#nextGeneration) ||
      this.#nextGeneration >= Number.MAX_SAFE_INTEGER
    ) {
      stateError("Port generation capacity exhausted");
    }
    return this.#nextGeneration++;
  }

  #newRoute(provenance: ProviderProvenance): DocumentRoute {
    let session: ProviderPortSession;
    try {
      session = new ProviderPortSession(
        provenance,
        this.#dependencies.sessionOptions,
      );
    } catch (error) {
      stateError("provider document session could not be created", error);
    }
    return {
      provenance,
      session,
      correlations: new Map(),
      currentPort: null,
      queue: Promise.resolve(),
      queuedRequests: 0,
      open: true,
    };
  }

  #bindPort(
    rawValue: unknown,
    route: DocumentRoute,
    provenance: ProviderProvenance,
  ): BoundPort {
    const raw = requireObject(rawValue, "runtime Port");
    const messageEvent = requireObject(raw.onMessage, "Port.onMessage");
    const disconnectEvent = requireObject(raw.onDisconnect, "Port.onDisconnect");
    const postMessage = bindMethod<(message: unknown) => void>(
      raw,
      "postMessage",
      "Port.postMessage",
    );
    const disconnect = bindMethod<() => void>(raw, "disconnect", "Port.disconnect");
    const addMessageListener = bindMethod<ProviderMessageEventMethod>(
      messageEvent,
      "addListener",
      "Port.onMessage.addListener",
    );
    const removeMessageListener = bindMethod<ProviderMessageEventMethod>(
      messageEvent,
      "removeListener",
      "Port.onMessage.removeListener",
    );
    const addDisconnectListener = bindMethod<ProviderDisconnectEventMethod>(
      disconnectEvent,
      "addListener",
      "Port.onDisconnect.addListener",
    );
    const removeDisconnectListener = bindMethod<ProviderDisconnectEventMethod>(
      disconnectEvent,
      "removeListener",
      "Port.onDisconnect.removeListener",
    );
    let owner!: BoundPort;
    owner = {
      generation: this.#newGeneration(),
      provenance,
      postMessage,
      disconnect,
      addMessageListener,
      removeMessageListener,
      addDisconnectListener,
      removeDisconnectListener,
      onMessage: (message: unknown): void => this.#onPortMessage(route, owner, message),
      onDisconnect: (): void => this.#onPortDisconnect(route, owner),
      messageListenerInstalled: false,
      disconnectListenerInstalled: false,
      open: true,
    };
    try {
      owner.messageListenerInstalled = true;
      owner.addMessageListener(owner.onMessage);
      if (!owner.open) stateError("provider Port closed during setup");
      owner.disconnectListenerInstalled = true;
      owner.addDisconnectListener(owner.onDisconnect);
      if (!owner.open) stateError("provider Port closed during setup");
    } catch (error) {
      this.#releasePort(owner, true);
      if (error instanceof ProviderRuntimeTransportStateError) throw error;
      stateError("Port listener installation failed", error);
    }
    return owner;
  }

  #releasePort(owner: BoundPort, disconnectPort: boolean): void {
    if (!owner.open) return;
    owner.open = false;
    if (owner.messageListenerInstalled) {
      owner.messageListenerInstalled = false;
      try {
        owner.removeMessageListener(owner.onMessage);
      } catch {
        // The open flag and route identity make a retained callback stale.
      }
    }
    if (owner.disconnectListenerInstalled) {
      owner.disconnectListenerInstalled = false;
      try {
        owner.removeDisconnectListener(owner.onDisconnect);
      } catch {
        // The open flag and route identity make a retained callback stale.
      }
    }
    if (disconnectPort) {
      try {
        owner.disconnect();
      } catch {
        // The channel is already gone.
      }
    }
  }

  #closeRoute(
    route: DocumentRoute,
    disconnectPort: boolean,
    reason: ProviderCancellationReason,
  ): void {
    if (!route.open) return;
    route.open = false;
    if (this.#documents.get(route.provenance.documentId) === route) {
      this.#documents.delete(route.provenance.documentId);
    }
    route.session.disconnect(reason);
    route.correlations.clear();
    const port = route.currentPort;
    route.currentPort = null;
    if (port !== null) this.#releasePort(port, disconnectPort);
  }

  #acceptPort(rawValue: unknown): void {
    if (this.#disposed) {
      safeDisconnectRaw(rawValue);
      return;
    }
    let raw: Record<PropertyKey, unknown>;
    let name: unknown;
    let sender: unknown;
    try {
      raw = requireObject(rawValue, "runtime Port");
      name = raw.name;
      sender = raw.sender;
    } catch {
      safeDisconnectRaw(rawValue);
      return;
    }
    if (name !== PROVIDER_PORT_NAME) {
      safeDisconnectRaw(rawValue);
      return;
    }
    let provenance: ProviderProvenance;
    try {
      provenance = classifyProviderSender({
        runtimeId: this.#runtimeId,
        sender,
      });
    } catch {
      safeDisconnectRaw(rawValue);
      return;
    }

    let route = this.#documents.get(provenance.documentId);
    if (route !== undefined && !provenanceEqual(route.provenance, provenance)) {
      this.#closeRoute(route, true, "malformed");
      safeDisconnectRaw(rawValue);
      return;
    }
    if (route === undefined) {
      if (this.#documents.size >= MAX_PROVIDER_RUNTIME_DOCUMENTS) {
        safeDisconnectRaw(rawValue);
        return;
      }
      try {
        route = this.#newRoute(provenance);
      } catch {
        safeDisconnectRaw(rawValue);
        return;
      }
    }

    let candidate: BoundPort;
    try {
      candidate = this.#bindPort(rawValue, route, provenance);
    } catch {
      if (this.#documents.get(provenance.documentId) !== route) {
        route.session.disconnect("disconnect");
      }
      safeDisconnectRaw(rawValue);
      return;
    }
    if (!route.open || !candidate.open) {
      this.#releasePort(candidate, true);
      if (this.#documents.get(provenance.documentId) !== route) {
        route.session.disconnect("disconnect");
      }
      return;
    }

    const previous = route.currentPort;
    route.currentPort = candidate;
    this.#documents.set(provenance.documentId, route);
    if (previous !== null) {
      // Publish the replacement before disconnecting the old endpoint. Any
      // retained old callback sees a different route generation and is inert.
      this.#releasePort(previous, true);
    }
  }

  #onPortDisconnect(route: DocumentRoute, owner: BoundPort): void {
    if (!owner.open) return;
    this.#releasePort(owner, false);
    if (!route.open || route.currentPort !== owner) return;
    route.currentPort = null;
    this.#closeRoute(route, false, "disconnect");
  }

  #onPortMessage(
    route: DocumentRoute,
    owner: BoundPort,
    value: unknown,
  ): void {
    if (
      !route.open ||
      !owner.open ||
      route.currentPort !== owner ||
      this.#documents.get(route.provenance.documentId) !== route
    ) {
      return;
    }
    let request: ProviderSignTransactionRequest;
    try {
      request = snapshotSignRequest(value);
    } catch {
      this.#closeRoute(route, true, "malformed");
      return;
    }
    const wire = canonicalWireRequest(request);
    let receivedExpiresAt: number;
    try {
      receivedExpiresAt = currentTime(this.#dependencies.readNow) +
        this.#dependencies.requestTtlMs;
      if (!Number.isSafeInteger(receivedExpiresAt)) {
        stateError("request receive deadline overflowed");
      }
    } catch {
      this.#closeRoute(route, true, "clock-failure");
      return;
    }
    if (route.queuedRequests >= MAX_PENDING_PROVIDER_REQUESTS) {
      this.#closeRoute(route, true, "malformed");
      return;
    }
    route.queuedRequests++;
    route.queue = route.queue.then(async () => {
      await this.#acceptRequest(
        route,
        owner,
        request,
        wire,
        receivedExpiresAt,
      );
    }).catch(() => {
      this.#closeRoute(route, true, "malformed");
    }).finally(() => {
      route.queuedRequests--;
    });
  }

  async #operationKey(
    provenance: ProviderProvenance,
    request: ProviderSignTransactionRequest,
  ): Promise<string> {
    const identity = this.#dependencies.digestSource === undefined
      ? await deriveProviderOperationIdentityFromRequest({ provenance, request })
      : await deriveProviderOperationIdentityFromRequest(
          { provenance, request },
          this.#dependencies.digestSource,
        );
    try {
      return identity.key;
    } finally {
      identity.requestDigest.fill(0);
    }
  }

  async #acceptRequest(
    route: DocumentRoute,
    owner: BoundPort,
    request: ProviderSignTransactionRequest,
    wire: Readonly<Record<string, unknown>>,
    receivedExpiresAt: number,
  ): Promise<void> {
    if (
      !route.open ||
      !owner.open ||
      this.#documents.get(route.provenance.documentId) !== route
    ) {
      return;
    }
    const operationKey = await this.#operationKey(route.provenance, request);
    if (
      !route.open ||
      this.#documents.get(route.provenance.documentId) !== route
    ) {
      return;
    }
    const now = currentTime(this.#dependencies.readNow);
    const existing = route.correlations.get(request.correlationId);
    if (existing === undefined) {
      if (
        route.correlations.size >=
        MAX_PROVIDER_RUNTIME_CORRELATIONS_PER_DOCUMENT
      ) {
        stateError("document correlation capacity exhausted");
      }
      const owned = route.session.openUntil(wire, receivedExpiresAt);
      if (owned.request.method !== "solana:signTransaction") {
        stateError("session changed the accepted request method");
      }
      const binding: CorrelationBinding = {
        correlationId: request.correlationId,
        operationKey,
        expiresAt: owned.expiresAt,
        attempts: 1,
        lastRequestGeneration: owner.generation,
        deliveredGeneration: null,
        active: null,
      };
      route.correlations.set(binding.correlationId, binding);
      this.#startFlow(route, binding, owned);
      return;
    }

    if (
      existing.operationKey !== operationKey ||
      now >= existing.expiresAt ||
      existing.lastRequestGeneration === owner.generation ||
      existing.attempts >= MAX_PROVIDER_RUNTIME_ATTEMPTS_PER_REQUEST
    ) {
      stateError("request replay is stale, duplicate, or changes identity");
    }
    existing.attempts++;
    existing.lastRequestGeneration = owner.generation;
    if (existing.active !== null) {
      route.session.assertActive(existing.active.owned);
      return;
    }
    if (existing.deliveredGeneration === owner.generation) return;
    const owned = route.session.openUntil(wire, existing.expiresAt);
    this.#startFlow(route, existing, owned);
  }

  #startFlow(
    route: DocumentRoute,
    binding: CorrelationBinding,
    owned: OwnedProviderRequest,
  ): void {
    const active: ActiveDelivery = { owned, postedGeneration: null };
    binding.active = active;
    const assertActive = (): void => {
      if (
        !route.open ||
        this.#documents.get(route.provenance.documentId) !== route ||
        route.currentPort === null ||
        binding.active !== active
      ) {
        stateError("delivery lease is no longer active");
      }
      route.session.assertActive(owned);
    };
    const lease: ProviderRuntimeTransportLease = Object.freeze({
      owned,
      assertActive,
      postMessage: (value: ProviderTerminalResponse): void => {
        assertActive();
        if (active.postedGeneration !== null) {
          stateError("delivery lease already enqueued a terminal response");
        }
        const response = snapshotTerminal(value);
        if (response.correlationId !== binding.correlationId) {
          stateError("terminal response changed the request correlation");
        }
        const port = route.currentPort;
        if (port === null) stateError("delivery Port is unavailable");
        const generation = port.generation;
        if (binding.lastRequestGeneration !== generation) {
          stateError("delivery Port has not presented the exact request");
        }
        try {
          port.postMessage(response);
        } catch (error) {
          stateError("terminal response enqueue failed", error);
        }
        if (
          !route.open ||
          route.currentPort !== port ||
          !port.open ||
          binding.active !== active
        ) {
          stateError("delivery Port changed during terminal enqueue");
        }
        active.postedGeneration = generation;
      },
      finish: (): boolean => {
        if (active.postedGeneration === null) return false;
        try {
          assertActive();
        } catch {
          return false;
        }
        if (route.currentPort?.generation !== active.postedGeneration) {
          return false;
        }
        let finished: boolean;
        try {
          finished = route.session.finish(owned);
        } catch {
          return false;
        }
        if (!finished || binding.active !== active) return false;
        binding.active = null;
        binding.deliveredGeneration = active.postedGeneration;
        return true;
      },
    });

    let delivery: Promise<unknown>;
    try {
      delivery = this.#dependencies.deliver(lease);
    } catch (error) {
      delivery = Promise.reject(error);
    }
    void Promise.resolve(delivery).then((result) => {
      if (!exactDeliveredResult(result) || binding.active === active) {
        stateError("flow returned without exact delivery proof");
      }
    }).catch(() => {
      if (
        route.open &&
        this.#documents.get(route.provenance.documentId) === route
      ) {
        this.#closeRoute(route, true, "malformed");
      }
    });
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    if (this.#connectListenerInstalled) {
      this.#connectListenerInstalled = false;
      try {
        this.#removeConnectListener(this.#onConnect);
      } catch {
        // The disposed flag and closed routes remain authoritative.
      }
    }
    for (const route of [...this.#documents.values()]) {
      this.#closeRoute(route, true, "boundary-disposed");
    }
  }
}

type ProviderMessageEventMethod = (listener: (message: unknown) => void) => void;
type ProviderDisconnectEventMethod = (listener: () => void) => void;
