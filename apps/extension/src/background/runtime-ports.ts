import {
  installApprovalReviewBoundary,
  type ApprovalReviewBoundary,
  type ApprovalReviewBoundaryOptions,
} from "./approval-port.js";
import {
  installUnavailablePopupBoundary,
  type UnavailablePopupBoundary,
} from "./popup-port.js";
import {
  installUnavailableProviderBoundary,
  type ProviderConnectEvent,
  type ProviderPortSessionOptions,
  type ProviderRuntimeApi,
  type ProviderRuntimePort,
  type UnavailableProviderBoundary,
} from "./provider-port.js";
import { POPUP_PORT_NAME } from "../popup-protocol.js";
import { APPROVAL_UI_PORT_NAME } from "../approval-protocol.js";
import { PROVIDER_PORT_NAME } from "../provider-protocol.js";

export interface RuntimeBoundaries {
  dispose(): void;
}

class RoutedConnectEvent implements ProviderConnectEvent {
  private listener: ((port: ProviderRuntimePort) => void) | null = null;

  addListener(listener: (port: ProviderRuntimePort) => void): void {
    if (this.listener !== null) {
      throw new Error("runtime router: duplicate child listener");
    }
    this.listener = listener;
  }

  removeListener(listener: (port: ProviderRuntimePort) => void): void {
    if (this.listener === listener) this.listener = null;
  }

  emit(port: ProviderRuntimePort): void {
    this.listener?.(port);
  }
}

function safeDisconnectUnknown(value: unknown): void {
  if (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { readonly disconnect?: unknown }).disconnect === "function"
  ) {
    try {
      (value as { disconnect(): void }).disconnect();
    } catch {
      // An already-dead unknown Port is closed.
    }
  }
}

/**
 * Own runtime.onConnect once and route by an exact channel name before either
 * child schema runs. This prevents independent listeners from disconnecting
 * one another's Ports while keeping unknown channels fail-closed.
 */
export function installRuntimeBoundaries(
  runtime: ProviderRuntimeApi,
  approvalOptions: ApprovalReviewBoundaryOptions,
  providerOptions: ProviderPortSessionOptions = {},
): RuntimeBoundaries {
  if (
    typeof runtime !== "object" ||
    runtime === null ||
    typeof runtime.onConnect !== "object" ||
    runtime.onConnect === null ||
    typeof runtime.onConnect.addListener !== "function" ||
    typeof runtime.onConnect.removeListener !== "function"
  ) {
    throw new Error("runtime router: runtime.onConnect is unavailable");
  }

  const providerEvents = new RoutedConnectEvent();
  const popupEvents = new RoutedConnectEvent();
  const approvalEvents = new RoutedConnectEvent();
  let providerBoundary: UnavailableProviderBoundary | null = null;
  let popupBoundary: UnavailablePopupBoundary | null = null;
  let approvalBoundary: ApprovalReviewBoundary | null = null;
  try {
    providerBoundary = installUnavailableProviderBoundary(
      { id: runtime.id, onConnect: providerEvents },
      providerOptions,
    );
    popupBoundary = installUnavailablePopupBoundary({
      id: runtime.id,
      onConnect: popupEvents,
    });
    approvalBoundary = installApprovalReviewBoundary(
      { id: runtime.id, onConnect: approvalEvents },
      approvalOptions,
    );
  } catch (error) {
    approvalBoundary?.dispose();
    popupBoundary?.dispose();
    providerBoundary?.dispose();
    throw error;
  }

  let disposed = false;
  const onConnect = (port: ProviderRuntimePort): void => {
    if (disposed || typeof port !== "object" || port === null) {
      safeDisconnectUnknown(port);
      return;
    }
    if (port.name === PROVIDER_PORT_NAME) {
      providerEvents.emit(port);
    } else if (port.name === POPUP_PORT_NAME) {
      popupEvents.emit(port);
    } else if (port.name === APPROVAL_UI_PORT_NAME) {
      approvalEvents.emit(port);
    } else {
      safeDisconnectUnknown(port);
    }
  };

  try {
    runtime.onConnect.addListener(onConnect);
  } catch (error) {
    approvalBoundary.dispose();
    popupBoundary.dispose();
    providerBoundary.dispose();
    throw error;
  }

  return Object.freeze({
    dispose(): void {
      if (disposed) return;
      disposed = true;
      try {
        runtime.onConnect.removeListener(onConnect);
      } finally {
        try {
          approvalBoundary.dispose();
        } finally {
          try {
            popupBoundary.dispose();
          } finally {
            providerBoundary.dispose();
          }
        }
      }
    },
  });
}
