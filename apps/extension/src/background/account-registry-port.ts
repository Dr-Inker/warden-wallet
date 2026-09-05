import { ACCOUNT_REGISTRY_PORT_NAME, parseAccountRequest, type AccountResponse } from "../account-registry-protocol.js";
import { classifyPrivilegedUiSender } from "./sender-provenance.js";
import type { ProviderRuntimeApi, ProviderRuntimePort } from "./provider-port.js";
import type { AccountRegistryOwner } from "./account-registry.js";

export interface AccountRegistryBoundaryOptions {
  readonly ready: Promise<unknown>;
  readonly accounts: AccountRegistryOwner;
}

/** One bounded request per connection; only Chrome-proven popup documents. */
export function installAccountRegistryBoundary(runtime: ProviderRuntimeApi, options: AccountRegistryBoundaryOptions): { dispose(): void } {
  const connections = new Set<() => void>();
  let disposed = false;
  // Observe startup failure even before a popup requests data.
  void options.ready.catch(() => undefined);
  const onConnect = (port: ProviderRuntimePort): void => {
    const disconnect = (): void => { try { port.disconnect(); } catch { /* Already closed. */ } };
    if (disposed || port.name !== ACCOUNT_REGISTRY_PORT_NAME || connections.size >= 16) {
      disconnect();
      return;
    }
    try {
      classifyPrivilegedUiSender({ runtimeId: runtime.id, sender: port.sender, allowedPaths: ["/popup.html"] });
    } catch {
      disconnect();
      return;
    }
    let active = true;
    let received = false;
    const close = (): void => {
      if (!active) return;
      active = false;
      connections.delete(close);
      clearTimeout(timer);
      try { port.onMessage.removeListener(onMessage); } catch { /* Best effort. */ }
      try { port.onDisconnect.removeListener(close); } catch { /* Best effort. */ }
      disconnect();
    };
    const timer = setTimeout(close, 10_000);
    const onMessage = (value: unknown): void => {
      if (!active) return;
      if (received) { close(); return; }
      received = true;
      let request;
      try { request = parseAccountRequest(value); } catch { close(); return; }
      const header = { version: 1 as const, type: "response" as const, correlationId: request.correlationId };
      const respond = (response: AccountResponse): void => {
        if (!active) return;
        try { port.postMessage(response); } finally { close(); }
      };
      void options.ready.then(async () => {
        if (!active) return;
        const result = await options.accounts.execute(request, () => active);
        respond({ ...header, ok: true, result });
      }).catch(() => {
        try { respond({ ...header, ok: false, error: "ACCOUNTS_UNAVAILABLE" }); } catch { close(); }
      });
    };
    try {
      connections.add(close);
      port.onDisconnect.addListener(close);
      port.onMessage.addListener(onMessage);
    } catch { close(); }
  };
  runtime.onConnect.addListener(onConnect);
  return { dispose(): void {
    if (disposed) return;
    disposed = true;
    try { runtime.onConnect.removeListener(onConnect); } finally {
      for (const close of [...connections]) close();
    }
  } };
}
