import { afterEach, describe, expect, it, vi } from "vitest";
import { requestAccounts } from "../src/popup/account-client.js";

function harness() {
  let message: (value: unknown) => void = () => {};
  let disconnect: () => void = () => {};
  const port = {
    onMessage: { addListener: (listener: typeof message) => { message = listener; }, removeListener: vi.fn() },
    onDisconnect: { addListener: (listener: typeof disconnect) => { disconnect = listener; }, removeListener: vi.fn() },
    postMessage: vi.fn(), disconnect: vi.fn(),
  };
  const runtime = { connect: vi.fn(() => port) };
  const controller = new AbortController();
  const pending = requestAccounts(runtime, { method: "accounts:list", params: {} }, controller.signal);
  const response = () => ({ version: 1, type: "response", correlationId: port.postMessage.mock.calls[0]![0].correlationId,
    ok: true, result: { version: 1, accounts: [], selectedAddress: null } });
  return { port, runtime, controller, pending, response, emit: (value: unknown) => message(value), drop: () => disconnect() };
}
afterEach(() => vi.useRealTimers());

describe("account popup request lifecycle", () => {
  it("accepts only the matching response and releases the port and timer", async () => {
    vi.useFakeTimers();
    const h = harness();
    expect(h.runtime.connect).toHaveBeenCalledWith({ name: "warden:accounts:v1" });
    h.emit(h.response());
    await expect(h.pending).resolves.toEqual({ version: 1, accounts: [], selectedAddress: null });
    expect(h.port.disconnect).toHaveBeenCalledOnce();
    expect(h.port.onMessage.removeListener).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(["timeout", "abort", "disconnect", "wrong correlation", "forged result"])("rejects %s and ignores a late success", async (failure) => {
    vi.useFakeTimers();
    const h = harness();
    const rejected = expect(h.pending).rejects.toThrow("Reload accounts");
    if (failure === "timeout") vi.advanceTimersByTime(8_000);
    if (failure === "abort") h.controller.abort();
    if (failure === "disconnect") h.drop();
    if (failure === "wrong correlation") h.emit({ ...h.response(), correlationId: "wrong_correlation_123" });
    if (failure === "forged result") h.emit({ ...h.response(), approved: true });
    h.emit(h.response());
    await rejected;
    expect(h.port.disconnect).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not connect when the page has already closed", async () => {
    const controller = new AbortController();
    controller.abort();
    const connect = vi.fn();
    await expect(requestAccounts({ connect }, { method: "accounts:list", params: {} }, controller.signal)).rejects.toThrow();
    expect(connect).not.toHaveBeenCalled();
  });
});
