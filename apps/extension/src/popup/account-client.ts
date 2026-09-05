import { ACCOUNT_REGISTRY_PORT_NAME, parseAccountResponse, type AccountCommand, type AccountRegistry } from "../account-registry-protocol.js";

interface AccountPort {
  readonly onMessage: { addListener(listener: (value: unknown) => void): void; removeListener(listener: (value: unknown) => void): void };
  readonly onDisconnect: { addListener(listener: () => void): void; removeListener(listener: () => void): void };
  postMessage(value: unknown): void;
  disconnect(): void;
}
export interface AccountClientRuntime {
  readonly lastError?: unknown;
  connect(options: { name: string }): AccountPort;
}

export function requestAccounts(runtime: AccountClientRuntime, command: AccountCommand, signal: AbortSignal): Promise<AccountRegistry> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let port: AccountPort | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (result?: AccountRegistry): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      try { port?.onMessage.removeListener(onMessage); } catch { /* Already gone. */ }
      try { port?.onDisconnect.removeListener(onDisconnect); } catch { /* Already gone. */ }
      try { port?.disconnect(); } catch { /* Already gone. */ }
      if (result !== undefined) resolve(result);
      else reject(new Error("Saved accounts could not be confirmed. Reload accounts before trying again."));
    };
    const abort = (): void => finish();
    const onDisconnect = (): void => { void runtime.lastError; finish(); };
    const correlationId = `accounts_${globalThis.crypto.randomUUID().replaceAll("-", "")}`;
    const onMessage = (value: unknown): void => {
      if (settled) return;
      try {
        const response = parseAccountResponse(value);
        if (response.correlationId !== correlationId || !response.ok) finish();
        else finish(response.result);
      } catch { finish(); }
    };
    if (signal.aborted) { finish(); return; }
    signal.addEventListener("abort", abort, { once: true });
    try {
      port = runtime.connect({ name: ACCOUNT_REGISTRY_PORT_NAME });
      timer = setTimeout(() => finish(), 8_000);
      port.onMessage.addListener(onMessage);
      port.onDisconnect.addListener(onDisconnect);
      port.postMessage({ version: 1, type: "request", correlationId, ...command });
    } catch { finish(); }
  });
}
