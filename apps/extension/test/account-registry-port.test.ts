import { afterEach, describe, expect, it, vi } from "vitest";
import { installAccountRegistryBoundary } from "../src/background/account-registry-port.js";
import { AccountRegistryOwner, ACCOUNT_REGISTRY_STORAGE_KEY } from "../src/background/account-registry.js";
import { ACCOUNT_REGISTRY_PORT_NAME } from "../src/account-registry-protocol.js";

const ID = "a".repeat(32);
const ADDRESS = "FTPSf3Po3uMpD9KRxWZtaqM27t7zCR8k7oAgz22u2eEC";
function event<T extends (...args: never[]) => unknown>() {
  const listeners = new Set<T>();
  return { addListener: (listener: T) => { listeners.add(listener); },
    removeListener: (listener: T) => { listeners.delete(listener); },
    emit: (...args: Parameters<T>) => { for (const listener of [...listeners]) listener(...args); } };
}
function harness(ready: Promise<unknown> = Promise.resolve()) {
  const onConnect = event<(port: ReturnType<typeof makePort>) => void>();
  const data: Record<string, unknown> = {};
  const storage = { get: vi.fn(async (key: string) => Object.hasOwn(data, key) ? { [key]: data[key] } : {}),
    set: vi.fn(async (value: Record<string, unknown>) => { Object.assign(data, value); }) };
  const boundary = installAccountRegistryBoundary({ id: ID, onConnect }, { ready, accounts: new AccountRegistryOwner(storage) });
  function makePort(sender: unknown = { id: ID, url: `chrome-extension://${ID}/popup.html`, origin: `chrome-extension://${ID}` }) {
    const onDisconnect = event<() => void>();
    return { name: ACCOUNT_REGISTRY_PORT_NAME, sender, onMessage: event<(value: unknown) => void>(), onDisconnect,
      postMessage: vi.fn(), disconnect: vi.fn(() => onDisconnect.emit()) };
  }
  function connect(sender?: unknown) { const port = makePort(sender); onConnect.emit(port); return port; }
  return { boundary, storage, data, connect };
}
function addRequest() {
  return { version: 1, type: "request", correlationId: "accounts_port_request1", method: "accounts:add", params: { address: ADDRESS, label: "Primary" } };
}
const drain = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
afterEach(() => vi.useRealTimers());

describe("popup-only account storage boundary", () => {
  it("waits for readiness and saves through a Chrome-proven tabless popup", async () => {
    let ready!: () => void;
    const h = harness(new Promise<void>((resolve) => { ready = resolve; }));
    const port = h.connect();
    port.onMessage.emit(addRequest());
    await drain();
    expect(h.storage.get).not.toHaveBeenCalled();
    ready();
    await drain();
    expect(port.postMessage).toHaveBeenCalledWith({ version: 1, type: "response", correlationId: "accounts_port_request1", ok: true,
      result: { version: 1, accounts: [{ address: ADDRESS, label: "Primary" }], selectedAddress: ADDRESS } });
    expect(Object.keys(h.data)).toEqual([ACCOUNT_REGISTRY_STORAGE_KEY]);
    expect(port.disconnect).toHaveBeenCalledOnce();
    h.boundary.dispose();
  });

  it.each([
    { id: ID, url: "https://evil.example/popup.html", origin: "https://evil.example", frameId: 0 },
    { id: "b".repeat(32), url: `chrome-extension://${ID}/popup.html`, origin: `chrome-extension://${ID}` },
    { id: ID, url: `chrome-extension://${ID}/approval.html`, origin: `chrome-extension://${ID}` },
    { id: ID, url: `chrome-extension://${ID}/popup.html?approved=true`, origin: `chrome-extension://${ID}` },
  ])("rejects forged UI identity without touching storage: %j", async (sender) => {
    const h = harness();
    const port = h.connect(sender);
    port.onMessage.emit(addRequest());
    await drain();
    expect(port.disconnect).toHaveBeenCalledOnce();
    expect(h.storage.get).not.toHaveBeenCalled();
    expect(h.storage.set).not.toHaveBeenCalled();
    h.boundary.dispose();
  });

  it("disposal, disconnect and duplicate requests cancel queued writes before readiness", async () => {
    for (const action of ["dispose", "disconnect", "duplicate"]) {
      let ready!: () => void;
      const h = harness(new Promise<void>((resolve) => { ready = resolve; }));
      const port = h.connect();
      port.onMessage.emit(addRequest());
      if (action === "dispose") h.boundary.dispose();
      else if (action === "disconnect") port.onDisconnect.emit();
      else port.onMessage.emit(addRequest());
      ready();
      await drain();
      expect(h.storage.set).not.toHaveBeenCalled();
      expect(port.postMessage).not.toHaveBeenCalled();
      h.boundary.dispose();
    }
  });

  it("bounds live connections and expires silent ports", () => {
    vi.useFakeTimers();
    const h = harness();
    const ports = Array.from({ length: 16 }, () => h.connect());
    expect(h.connect().disconnect).toHaveBeenCalledOnce();
    vi.advanceTimersByTime(10_000);
    for (const port of ports) expect(port.disconnect).toHaveBeenCalledOnce();
    expect(h.connect().disconnect).not.toHaveBeenCalled();
    h.boundary.dispose();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("reports startup and storage failures with a fixed error and no internal details", async () => {
    const h = harness(Promise.reject(new Error("sensitive internal path")));
    const port = h.connect();
    port.onMessage.emit(addRequest());
    await drain();
    expect(port.postMessage).toHaveBeenCalledWith({ version: 1, type: "response", correlationId: "accounts_port_request1", ok: false, error: "ACCOUNTS_UNAVAILABLE" });
    expect(h.storage.get).not.toHaveBeenCalled();
    h.boundary.dispose();
  });
});
