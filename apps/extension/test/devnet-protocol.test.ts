import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { allowedTestUrl, parseTestRequest, TEST_PORT } from "../src/devnet/protocol.js";

const account = "11111111111111111111111111111111";
const destination = "So11111111111111111111111111111111111111112";
const transfer = { method: "transfer", account, destination, lamports: "1000000" };
describe("devnet website protocol", () => {
  it("accepts the published and fixed localhost test routes", () => {
    expect(allowedTestUrl("https://wardenwallet.io/test/")).toBe("https://wardenwallet.io");
    expect(allowedTestUrl("http://127.0.0.1:4173/test/index.html")).toBe("http://127.0.0.1:4173");
  });
  for (const url of ["https://evil.test/test/", "http://wardenwallet.io/test/", "https://wardenwallet.io/", "http://localhost:9999/test/", "https://wardenwallet.io.evil.test/test/", "https://user@wardenwallet.io/test/"]) it(`rejects ${url}`, () => {
    expect(allowedTestUrl(url)).toBeNull();
  });
  it("limits the channel to connect and a bounded native SOL transfer", () => {
    expect(parseTestRequest({ method: "connect" })).toEqual({ method: "connect" });
    expect(parseTestRequest(transfer)).toEqual(transfer);
    for (const patch of [{ lamports: "0" }, { lamports: "10000001" }, { lamports: 1 }, { lamports: "1e6" }, { destination: account }, { rpc: "https://evil.test" }, { method: "signTransaction" }]) {
      expect(parseTestRequest({ ...transfer, ...patch })).toBeNull();
    }
    expect(parseTestRequest({ method: "connect", transaction: "arbitrary" })).toBeNull();
  });
});

const listeners = <T extends (...args: any[]) => void>() => {
  const callbacks: T[] = [];
  return { addListener: (fn: T) => callbacks.push(fn), fire: (...args: Parameters<T>) => callbacks.forEach(fn => fn(...args)) };
};
function mockPort(sender: Record<string, unknown>, name = TEST_PORT) {
  return { name, sender, postMessage: vi.fn(), disconnect: vi.fn(), onMessage: listeners<(value: unknown) => void>(), onDisconnect: listeners<() => void>() };
}
describe("Chrome-owned devnet request lifetime", () => {
  const id = "a".repeat(32);
  const sender = { url: "https://wardenwallet.io/test/", origin: "https://wardenwallet.io", frameId: 0, documentId: "document-one", tab: { id: 7 } };
  let chrome: any;
  beforeEach(async () => {
    vi.useFakeTimers(); vi.resetModules();
    chrome = { runtime: { id, getURL: (path: string) => `chrome-extension://${id}/${path}`, onConnectExternal: listeners(), onConnect: listeners() },
      action: { onClicked: listeners() }, tabs: { create: vi.fn(async () => ({ id: 10 })), remove: vi.fn(async () => {}), onRemoved: listeners() } };
    vi.stubGlobal("chrome", chrome);
    await import("../src/devnet/background.js");
  });
  afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); vi.unstubAllGlobals(); });
  it("requires Chrome top-level document provenance before opening review", () => {
    for (const changed of [{ ...sender, frameId: 1 }, { ...sender, documentId: undefined }, { ...sender, origin: "https://evil.test" }, { ...sender, id }]) {
      const port = mockPort(changed); chrome.runtime.onConnectExternal.fire(port); port.onMessage.fire({ method: "connect" });
      expect(port.disconnect).toHaveBeenCalled();
    }
    expect(chrome.tabs.create).not.toHaveBeenCalled();
  });
  it("binds the exact review tab and drops a different extension page", async () => {
    const port = mockPort(sender); chrome.runtime.onConnectExternal.fire(port); port.onMessage.fire(transfer);
    await Promise.resolve(); await Promise.resolve();
    const url = chrome.tabs.create.mock.calls[0][0].url;
    const forged = mockPort({ id, url, frameId: 0, documentId: "fake", tab: { id: 99 } }, "warden:devnet-review:v1");
    chrome.runtime.onConnect.fire(forged); await Promise.resolve();
    expect(forged.disconnect).toHaveBeenCalled(); expect(forged.postMessage).not.toHaveBeenCalled();
    const review = mockPort({ id, url, frameId: 0, documentId: "owned", tab: { id: 10 } }, "warden:devnet-review:v1");
    chrome.runtime.onConnect.fire(review); await Promise.resolve();
    expect(review.postMessage).toHaveBeenCalledWith({ origin: sender.origin, request: transfer });
    review.onMessage.fire({ keepAlive: true });
    expect(port.postMessage).not.toHaveBeenCalled();
    review.onMessage.fire({ ok: false, error: "User rejected the request" });
    expect(port.postMessage).toHaveBeenCalledWith({ ok: false, error: "User rejected the request" });
    expect(port.disconnect).toHaveBeenCalled();
  });
  it("expires unanswered requests and bounds an idle page connection", async () => {
    const idle = mockPort(sender); chrome.runtime.onConnectExternal.fire(idle);
    await vi.advanceTimersByTimeAsync(3001); expect(idle.disconnect).toHaveBeenCalled();
    const port = mockPort(sender); chrome.runtime.onConnectExternal.fire(port); port.onMessage.fire({ method: "connect" });
    await vi.advanceTimersByTimeAsync(300_000);
    expect(port.postMessage).toHaveBeenCalledWith({ ok: false, error: expect.stringContaining("expired") });
  });
  it("cannot replay a second page request on the same connection", () => {
    const port = mockPort(sender); chrome.runtime.onConnectExternal.fire(port); port.onMessage.fire({ method: "connect" }); port.onMessage.fire(transfer);
    expect(chrome.tabs.create).toHaveBeenCalledTimes(1); expect(port.disconnect).toHaveBeenCalled();
  });
});
