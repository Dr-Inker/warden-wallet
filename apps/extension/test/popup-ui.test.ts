import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Exercise the page entrypoint and its event wiring. These tests establish
// connection lifecycle behavior, not Chrome provenance or rendered appearance.
function harness() {
  const status = { dataset: {} as Record<string, string>, textContent: "" };
  const retry = { disabled: true, addEventListener: vi.fn() };
  const ports: ReturnType<typeof newPort>[] = [];
  const events = new Map<string, () => void>();
  function newPort() {
    let message: (value: unknown) => void = () => {};
    let disconnect: () => void = () => {};
    return {
      onMessage: { addListener: (listener: typeof message) => { message = listener; } },
      onDisconnect: { addListener: (listener: typeof disconnect) => { disconnect = listener; } },
      postMessage: vi.fn(),
      disconnect: vi.fn(() => disconnect()),
      emit: (value: unknown) => message(value),
      drop: () => disconnect(),
    };
  }
  const connect = vi.fn(() => {
    const port = newPort();
    ports.push(port);
    return port;
  });
  vi.stubGlobal("chrome", { runtime: { connect } });
  vi.stubGlobal("document", {
    querySelector: (selector: string) => selector === "#boundary-status" ? status : selector === "#retry-status" ? retry : null,
  });
  vi.stubGlobal("addEventListener", (name: string, listener: () => void) => {
    events.set(name, listener);
  });
  retry.addEventListener.mockImplementation((name: string, listener: () => void) => {
    events.set(name, listener);
  });
  function respond(index = 0, correlationId?: string) {
    const port = ports[index]!;
    port.emit({
      version: 1, type: "response", ok: false,
      correlationId: correlationId ?? port.postMessage.mock.calls[0]![0].correlationId,
      error: { code: "WARDEN_POPUP_UNAVAILABLE", message: "Warden popup methods are not enabled" },
    });
  }
  return { status, retry, ports, events, connect, respond };
}

beforeEach(() => {
  vi.resetModules();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("development popup connection lifecycle", () => {
  it("sends only the powerless boundary request and reports unavailable after a matching response", async () => {
    const h = harness();
    await import("../src/popup/main.js");
    expect(h.connect).toHaveBeenCalledWith({ name: "warden:popup:v1" });
    expect(h.ports[0]!.postMessage).toHaveBeenCalledWith({
      version: 1, type: "request", correlationId: expect.stringMatching(/^popup_[0-9a-f]{32}$/),
      method: "popup:getBoundaryStatus", params: {},
    });
    expect(h.retry.disabled).toBe(true);
    h.respond();
    expect(h.status.dataset.boundary).toBe("unavailable");
    expect(h.retry.disabled).toBe(false);
    expect(h.ports[0]!.disconnect).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("closes a silent connection at five seconds and permits a fresh retry", async () => {
    const h = harness();
    await import("../src/popup/main.js");
    vi.advanceTimersByTime(4_999);
    expect(h.status.dataset.boundary).toBe("checking");
    vi.advanceTimersByTime(1);
    expect(h.status.dataset.boundary).toBe("closed");
    expect(h.retry.disabled).toBe(false);
    h.events.get("click")!();
    expect(h.connect).toHaveBeenCalledTimes(2);
    expect(h.retry.disabled).toBe(true);
    h.respond(1);
    expect(h.status.dataset.boundary).toBe("unavailable");
  });

  it("ignores late messages and disconnects from an old attempt while a retry is pending", async () => {
    const h = harness();
    await import("../src/popup/main.js");
    vi.advanceTimersByTime(5_000);
    h.events.get("click")!();
    h.respond(0);
    h.ports[0]!.drop();
    expect(h.status.dataset.boundary).toBe("checking");
    expect(h.retry.disabled).toBe(true);
    const firstId = h.ports[0]!.postMessage.mock.calls[0]![0].correlationId;
    const secondId = h.ports[1]!.postMessage.mock.calls[0]![0].correlationId;
    expect(firstId).not.toBe(secondId);
    h.respond(1);
    expect(h.status.dataset.boundary).toBe("unavailable");
  });

  it("does not start parallel checks on repeated clicks", async () => {
    const h = harness();
    await import("../src/popup/main.js");
    h.events.get("click")!();
    h.events.get("click")!();
    expect(h.connect).toHaveBeenCalledOnce();
  });

  it("fails closed on an unrelated response and ignores a later correct one", async () => {
    const h = harness();
    await import("../src/popup/main.js");
    h.respond(0, "popup_00000000000000000000000000000000");
    h.respond();
    expect(h.status.dataset.boundary).toBe("closed");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("fails closed on unexpected response fields instead of displaying their content", async () => {
    const h = harness();
    await import("../src/popup/main.js");
    h.ports[0]!.emit({ ok: true, message: "unsafe display content" });
    expect(h.status.dataset.boundary).toBe("closed");
    expect(h.status.textContent).not.toContain("unsafe display content");
  });

  it("recovers from synchronous connect failure without an uncaught entrypoint exception", async () => {
    const h = harness();
    h.connect.mockImplementationOnce(() => { throw new Error("internal detail"); });
    await import("../src/popup/main.js");
    expect(h.status.dataset.boundary).toBe("closed");
    expect(h.status.textContent).not.toContain("internal detail");
    h.events.get("click")!();
    h.respond();
    expect(h.status.dataset.boundary).toBe("unavailable");
  });

  it("turns a missing runtime into an actionable status", async () => {
    const h = harness();
    vi.stubGlobal("chrome", undefined);
    await import("../src/popup/main.js");
    expect(h.status.dataset.boundary).toBe("closed");
    expect(h.retry.disabled).toBe(false);
  });

  it("clears the deadline and enables retry when the worker disconnects before replying", async () => {
    const h = harness();
    await import("../src/popup/main.js");
    h.ports[0]!.drop();
    expect(h.status.dataset.boundary).toBe("closed");
    expect(h.retry.disabled).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
    h.events.get("click")!();
    h.respond(1);
    expect(h.status.dataset.boundary).toBe("unavailable");
  });

  it("cleans up when the initial request cannot be posted", async () => {
    const h = harness();
    const connect = h.connect.getMockImplementation()!;
    h.connect.mockImplementationOnce(() => {
      const port = connect();
      port.postMessage.mockImplementationOnce(() => { throw new Error("lost port"); });
      return port;
    });
    await import("../src/popup/main.js");
    expect(h.status.dataset.boundary).toBe("closed");
    expect(h.retry.disabled).toBe(false);
    expect(h.ports[0]!.disconnect).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("cleans up on pagehide and cannot accept a response after the page is left", async () => {
    const h = harness();
    await import("../src/popup/main.js");
    h.events.get("pagehide")!();
    expect(h.ports[0]!.disconnect).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
    h.respond();
    expect(h.status.dataset.boundary).toBe("checking");
  });
});
