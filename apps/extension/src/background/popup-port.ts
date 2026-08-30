import {
  MAX_POPUP_REQUESTS_PER_PORT,
  POPUP_PORT_NAME,
  createUnavailablePopupResponse,
  parsePopupRequest,
} from "../popup-protocol.js";
import {
  classifyPrivilegedUiSender,
  type PrivilegedUiProvenance,
} from "./sender-provenance.js";
import type {
  ProviderRuntimeApi,
  ProviderRuntimePort,
} from "./provider-port.js";

export { MAX_POPUP_REQUESTS_PER_PORT } from "../popup-protocol.js";
export const MAX_ACTIVE_POPUP_PORTS = 16;

const EXTENSION_ID_PATTERN = /^[a-p]{32}$/;
const POPUP_PATH = "/popup.html";

export interface UnavailablePopupBoundary {
  dispose(): void;
}

export class PopupPortStateError extends Error {
  constructor(message: string) {
    super(`popup port: ${message}`);
    this.name = "PopupPortStateError";
  }
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
    throw new PopupPortStateError(`${name} listener event is unavailable`);
  }
}

function requirePort(value: unknown): ProviderRuntimePort {
  if (typeof value !== "object" || value === null) {
    throw new PopupPortStateError("runtime Port is malformed");
  }
  const port = value as Partial<ProviderRuntimePort>;
  if (
    typeof port.name !== "string" ||
    typeof port.postMessage !== "function" ||
    typeof port.disconnect !== "function"
  ) {
    throw new PopupPortStateError("runtime Port is malformed");
  }
  requireListenerEvent(port.onMessage, "Port.onMessage");
  requireListenerEvent(port.onDisconnect, "Port.onDisconnect");
  return port as ProviderRuntimePort;
}

function safeDisconnect(port: ProviderRuntimePort): void {
  try {
    port.disconnect();
  } catch {
    // A disappearing or already-rejected Port is already closed.
  }
}

/**
 * Install a separate popup-only lane. Classification grants no capability:
 * the sole valid request receives a fixed unavailable response, and this
 * module has no dispatch hook into storage, accounts, approvals, RPC, or keys.
 */
export function installUnavailablePopupBoundary(
  runtime: ProviderRuntimeApi,
): UnavailablePopupBoundary {
  if (
    typeof runtime !== "object" ||
    runtime === null ||
    typeof runtime.id !== "string" ||
    !EXTENSION_ID_PATTERN.test(runtime.id)
  ) {
    throw new PopupPortStateError("runtime extension id is malformed");
  }
  requireListenerEvent(runtime.onConnect, "runtime.onConnect");

  let disposed = false;
  const active = new Set<(disconnectPort: boolean) => void>();
  const activeDocuments = new Map<string, (disconnectPort: boolean) => void>();

  const onConnect = (rawPort: ProviderRuntimePort): void => {
    let port: ProviderRuntimePort;
    try {
      port = requirePort(rawPort);
    } catch {
      return;
    }
    if (disposed || port.name !== POPUP_PORT_NAME) {
      safeDisconnect(port);
      return;
    }

    let provenance: PrivilegedUiProvenance;
    try {
      provenance = classifyPrivilegedUiSender({
        runtimeId: runtime.id,
        sender: port.sender,
        allowedPaths: [POPUP_PATH],
      });
    } catch {
      safeDisconnect(port);
      return;
    }
    if (
      (provenance.documentId !== null &&
        activeDocuments.has(provenance.documentId)) ||
      active.size >= MAX_ACTIVE_POPUP_PORTS
    ) {
      safeDisconnect(port);
      return;
    }

    let open = true;
    let requestCount = 0;
    const correlations = new Set<string>();
    const close = (disconnectPort: boolean): void => {
      if (!open) return;
      open = false;
      active.delete(close);
      if (
        provenance.documentId !== null &&
        activeDocuments.get(provenance.documentId) === close
      ) {
        activeDocuments.delete(provenance.documentId);
      }
      correlations.clear();
      try {
        port.onMessage.removeListener(onMessage);
      } catch {
        // The open flag is authoritative; listener cleanup is best effort.
      }
      try {
        port.onDisconnect.removeListener(onDisconnect);
      } catch {
        // The open flag is authoritative; listener cleanup is best effort.
      }
      if (disconnectPort) safeDisconnect(port);
    };

    const onMessage = (message: unknown): void => {
      if (!open) return;
      if (requestCount >= MAX_POPUP_REQUESTS_PER_PORT) {
        close(true);
        return;
      }
      let request;
      try {
        request = parsePopupRequest(message);
      } catch {
        close(true);
        return;
      }
      if (correlations.has(request.correlationId)) {
        close(true);
        return;
      }
      correlations.add(request.correlationId);
      requestCount++;
      try {
        port.postMessage(createUnavailablePopupResponse(request.correlationId));
      } catch {
        close(true);
      }
    };

    const onDisconnect = (): void => close(false);

    try {
      port.onDisconnect.addListener(onDisconnect);
      port.onMessage.addListener(onMessage);
      active.add(close);
      if (provenance.documentId !== null) {
        activeDocuments.set(provenance.documentId, close);
      }
    } catch {
      close(true);
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
        for (const close of [...active]) close(true);
      }
    },
  });
}
