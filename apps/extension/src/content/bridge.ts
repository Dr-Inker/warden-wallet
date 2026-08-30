import {
  PAGE_PROVIDER_REQUEST_TYPE,
  PAGE_PROVIDER_RESPONSE_TYPE,
  PROVIDER_PORT_NAME,
  MAX_PROVIDER_REQUESTS_PER_DOCUMENT,
  createPageProviderResponseEnvelope,
  isProviderUnavailableResponse,
  readPageProviderRequestEnvelope,
} from "../provider-protocol.js";

export {
  PAGE_PROVIDER_REQUEST_TYPE,
  PAGE_PROVIDER_RESPONSE_TYPE,
  PROVIDER_PORT_NAME,
  MAX_PROVIDER_REQUESTS_PER_DOCUMENT,
};

export interface ContentPortMessageEvent {
  addListener(listener: (message: unknown) => void): void;
  removeListener(listener: (message: unknown) => void): void;
}

export interface ContentPortDisconnectEvent {
  addListener(listener: () => void): void;
  removeListener(listener: () => void): void;
}

export interface ContentRuntimePort {
  readonly onMessage: ContentPortMessageEvent;
  readonly onDisconnect: ContentPortDisconnectEvent;
  postMessage(message: unknown): void;
  disconnect(): void;
}

export interface ContentRuntimeApi {
  connect(connectInfo: { readonly name: string }): ContentRuntimePort;
}

export interface ContentWindowMessageEvent {
  readonly data: unknown;
  readonly origin: string;
  readonly source: unknown;
}

export type ContentWindowMessageListener = (event: ContentWindowMessageEvent) => void;

export interface ContentWindowApi {
  readonly location: { readonly origin: string };
  addEventListener(type: "message", listener: ContentWindowMessageListener): void;
  removeEventListener(type: "message", listener: ContentWindowMessageListener): void;
  postMessage(message: unknown, targetOrigin: string): void;
}

export interface PageProviderBridge {
  dispose(): void;
}

interface BoundContentPort {
  readonly port: ContentRuntimePort;
  readonly onMessage: (message: unknown) => void;
  readonly onDisconnect: () => void;
  messageListenerInstalled: boolean;
  disconnectListenerInstalled: boolean;
}

export class PageProviderBridgeError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`page provider bridge: ${message}`, options);
    this.name = "PageProviderBridgeError";
  }
}

function fail(message: string, cause?: unknown): never {
  throw new PageProviderBridgeError(
    message,
    cause === undefined ? {} : { cause },
  );
}

function requireWebOrigin(value: unknown): string {
  if (typeof value !== "string") fail("document origin is unavailable");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (error) {
    fail("document origin is malformed", error);
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.origin !== value ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    fail("document origin is not one canonical HTTP(S) origin");
  }
  return value;
}

function requireListenerEvent(
  value: unknown,
  name: string,
): asserts value is {
  addListener(listener: never): void;
  removeListener(listener: never): void;
} {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly addListener?: unknown }).addListener !== "function" ||
    typeof (value as { readonly removeListener?: unknown }).removeListener !== "function"
  ) {
    fail(`${name} listener event is unavailable`);
  }
}

function requirePort(value: unknown): ContentRuntimePort {
  if (typeof value !== "object" || value === null) fail("runtime Port is malformed");
  const port = value as Partial<ContentRuntimePort>;
  if (typeof port.postMessage !== "function" || typeof port.disconnect !== "function") {
    fail("runtime Port is malformed");
  }
  requireListenerEvent(port.onMessage, "Port.onMessage");
  requireListenerEvent(port.onDisconnect, "Port.onDisconnect");
  return port as ContentRuntimePort;
}

function safeDisconnect(port: ContentRuntimePort): void {
  try {
    port.disconnect();
  } catch {
    // A disappearing document or worker already closed the authority channel.
  }
}

/**
 * Install one isolated-world bridge for one HTTP(S) document. Same-page code
 * can forge or suppress page messages by design; this layer conveys no origin,
 * account, policy, approval, or wallet authority. Chrome-owned Port.sender in
 * the background is the sole provenance source.
 */
export function installPageProviderBridge(
  page: ContentWindowApi,
  runtime: ContentRuntimeApi,
): PageProviderBridge {
  if (typeof page !== "object" || page === null) fail("window API is unavailable");
  if (
    typeof page.addEventListener !== "function" ||
    typeof page.removeEventListener !== "function" ||
    typeof page.postMessage !== "function"
  ) {
    fail("window API is malformed");
  }
  const documentOrigin = requireWebOrigin(page.location?.origin);
  if (
    typeof runtime !== "object" ||
    runtime === null ||
    typeof runtime.connect !== "function"
  ) {
    fail("runtime API is unavailable");
  }

  let open = true;
  let pageListenerInstalled = false;
  let activePort: BoundContentPort | null = null;
  let forwardedRequestCount = 0;

  const releasePort = (
    owner: BoundContentPort,
    disconnectPort: boolean,
  ): void => {
    if (activePort === owner) activePort = null;
    if (owner.messageListenerInstalled) {
      try {
        owner.port.onMessage.removeListener(owner.onMessage);
      } catch {
        // The binding identity and Port teardown remain authoritative.
      } finally {
        owner.messageListenerInstalled = false;
      }
    }
    if (owner.disconnectListenerInstalled) {
      try {
        owner.port.onDisconnect.removeListener(owner.onDisconnect);
      } catch {
        // The binding identity and Port teardown remain authoritative.
      } finally {
        owner.disconnectListenerInstalled = false;
      }
    }
    if (disconnectPort) safeDisconnect(owner.port);
  };

  const close = (disconnectPort: boolean): void => {
    if (!open) return;
    open = false;
    if (pageListenerInstalled) {
      try {
        page.removeEventListener("message", onPageMessage);
      } catch {
        // Port closure below removes background authority even if DOM cleanup fails.
      } finally {
        pageListenerInstalled = false;
      }
    }
    if (activePort !== null) releasePort(activePort, disconnectPort);
  };

  const bindPort = (): BoundContentPort => {
    let port: ContentRuntimePort;
    try {
      port = requirePort(runtime.connect({ name: PROVIDER_PORT_NAME }));
    } catch (error) {
      if (error instanceof PageProviderBridgeError) throw error;
      fail("could not open provider Port", error);
    }

    const owner: BoundContentPort = {
      port,
      messageListenerInstalled: false,
      disconnectListenerInstalled: false,
      onMessage: (message: unknown): void => {
        if (!open || activePort !== owner) return;
        if (!isProviderUnavailableResponse(message)) {
          close(true);
          return;
        }
        try {
          page.postMessage(
            createPageProviderResponseEnvelope(message),
            documentOrigin,
          );
        } catch {
          close(true);
        }
      },
      onDisconnect: (): void => {
        // Do not reconnect eagerly: doing so would wake an idle MV3 worker in
        // every matching frame forever. The next real page request reconnects.
        releasePort(owner, false);
      },
    };
    activePort = owner;

    try {
      owner.messageListenerInstalled = true;
      port.onMessage.addListener(owner.onMessage);
      if (!open || activePort !== owner) fail("provider Port closed during setup");
      owner.disconnectListenerInstalled = true;
      port.onDisconnect.addListener(owner.onDisconnect);
      if (!open || activePort !== owner) fail("provider Port closed during setup");
    } catch (error) {
      releasePort(owner, true);
      if (error instanceof PageProviderBridgeError) throw error;
      fail("Port listener installation failed", error);
    }
    return owner;
  };

  const postPayload = (payload: unknown): void => {
    let owner: BoundContentPort;
    try {
      owner = activePort ?? bindPort();
      owner.port.postMessage(payload);
      return;
    } catch {
      if (activePort !== null) releasePort(activePort, true);
    }

    // Port.postMessage throws synchronously for a disconnected worker and for
    // an uncloneable payload. One fresh-Port retry covers the former; a second
    // failure closes the bridge, bounding the latter to two attempts.
    try {
      owner = bindPort();
      owner.port.postMessage(payload);
    } catch {
      close(true);
    }
  };

  const onPageMessage = (event: ContentWindowMessageEvent): void => {
    if (!open || event.source !== page || event.origin !== documentOrigin) return;
    const envelope = readPageProviderRequestEnvelope(event.data);
    if (envelope === null) return;
    if (forwardedRequestCount >= MAX_PROVIDER_REQUESTS_PER_DOCUMENT) {
      close(true);
      return;
    }
    forwardedRequestCount++;
    // Deliberately do not parse, enrich, or rewrite attacker-controlled data.
    // The service worker applies the closed schema and browser provenance.
    postPayload(envelope.payload);
  };

  const bridge = Object.freeze({
    dispose(): void {
      close(true);
    },
  });

  try {
    pageListenerInstalled = true;
    page.addEventListener("message", onPageMessage);
  } catch (error) {
    close(true);
    fail("listener installation failed", error);
  }

  return bridge;
}
