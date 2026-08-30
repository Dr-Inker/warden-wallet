import { describe, expect, it } from "vitest";

import {
  bootstrapBackground,
  startBackground,
  type ExtensionBackgroundStorageApi,
} from "../src/background/runtime.js";
import { PROVIDER_PORT_NAME } from "../src/background/provider-port.js";
import type {
  ProviderConnectEvent,
  ProviderDisconnectEvent,
  ProviderMessageEvent,
  ProviderRuntimePort,
} from "../src/background/provider-port.js";

interface Gate {
  readonly promise: Promise<void>;
  release(): void;
}

function gate(): Gate {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

class RuntimeConnectEvent implements ProviderConnectEvent {
  readonly listeners = new Set<(port: ProviderRuntimePort) => void>();

  addListener(listener: (port: ProviderRuntimePort) => void): void {
    this.listeners.add(listener);
  }

  removeListener(listener: (port: ProviderRuntimePort) => void): void {
    this.listeners.delete(listener);
  }

  emit(port: ProviderRuntimePort): void {
    for (const listener of [...this.listeners]) listener(port);
  }
}

class RuntimeMessageEvent implements ProviderMessageEvent {
  readonly listeners = new Set<(message: unknown) => void>();

  addListener(listener: (message: unknown) => void): void {
    this.listeners.add(listener);
  }

  removeListener(listener: (message: unknown) => void): void {
    this.listeners.delete(listener);
  }

  emit(message: unknown): void {
    for (const listener of [...this.listeners]) listener(message);
  }
}

class RuntimeDisconnectEvent implements ProviderDisconnectEvent {
  readonly listeners = new Set<() => void>();

  addListener(listener: () => void): void {
    this.listeners.add(listener);
  }

  removeListener(listener: () => void): void {
    this.listeners.delete(listener);
  }

  emit(): void {
    for (const listener of [...this.listeners]) listener();
  }
}

describe("MV3 background bootstrap", () => {
  it("does not read session material until both storage areas are restricted", async () => {
    const localGate = gate();
    const sessionGate = gate();
    const calls: string[] = [];
    const storage: ExtensionBackgroundStorageApi = {
      local: {
        setAccessLevel: async () => {
          calls.push("local:restrict");
          await localGate.promise;
          calls.push("local:restricted");
        },
      },
      session: {
        setAccessLevel: async () => {
          calls.push("session:restrict");
          await sessionGate.promise;
          calls.push("session:restricted");
        },
        get: async () => {
          calls.push("session:get");
          return {};
        },
        set: async () => undefined,
        remove: async () => undefined,
      },
    };

    const runtime = bootstrapBackground(storage);
    await Promise.resolve();
    expect(calls).toEqual(["local:restrict", "session:restrict"]);
    localGate.release();
    await Promise.resolve();
    expect(calls).not.toContain("session:get");
    sessionGate.release();
    await expect(runtime.ready).resolves.toBe(false);
    expect(calls.slice(-3)).toEqual(["local:restricted", "session:restricted", "session:get"]);
  });

  it("fails closed without reading when access restriction fails", async () => {
    let reads = 0;
    const storage: ExtensionBackgroundStorageApi = {
      local: { setAccessLevel: async () => Promise.reject(new Error("access denied")) },
      session: {
        setAccessLevel: async () => undefined,
        get: async () => {
          reads++;
          return {};
        },
        set: async () => undefined,
        remove: async () => undefined,
      },
    };

    const runtime = bootstrapBackground(storage);
    await expect(runtime.ready).rejects.toThrow("access denied");
    expect(reads).toBe(0);
    await expect(runtime.sessions.isUnlocked()).resolves.toBe(false);
  });

  it("registers the provider wake listener synchronously while readiness remains gated", async () => {
    const localGate = gate();
    const sessionGate = gate();
    const restoreGate = gate();
    const onConnect = new RuntimeConnectEvent();
    const storage: ExtensionBackgroundStorageApi = {
      local: {
        setAccessLevel: async () => localGate.promise,
      },
      session: {
        setAccessLevel: async () => sessionGate.promise,
        get: async () => {
          await restoreGate.promise;
          return {};
        },
        set: async () => undefined,
        remove: async () => undefined,
      },
    };

    const application = startBackground({
      storage,
      runtime: { id: "a".repeat(32), onConnect },
    });
    let providerSettled = false;
    void application.providerReady.finally(() => {
      providerSettled = true;
    });

    // MV3 dispatch can wake a stopped worker before any storage promise settles.
    // This listener must therefore exist during the same top-level script turn.
    expect(onConnect.listeners.size).toBe(1);
    expect(providerSettled).toBe(false);
    localGate.release();
    sessionGate.release();
    await Promise.resolve();
    await Promise.resolve();
    expect(onConnect.listeners.size).toBe(1);
    expect(providerSettled).toBe(false);
    restoreGate.release();
    await application.providerReady;
    expect(providerSettled).toBe(true);
    expect(onConnect.listeners.size).toBe(1);
    application.dispose();
    expect(onConnect.listeners.size).toBe(0);
  });

  it("keeps the synchronous pre-ready surface at METHOD_UNAVAILABLE only", async () => {
    const localGate = gate();
    const sessionGate = gate();
    const onConnect = new RuntimeConnectEvent();
    const onMessage = new RuntimeMessageEvent();
    const onDisconnect = new RuntimeDisconnectEvent();
    const posted: unknown[] = [];
    let reads = 0;
    const storage: ExtensionBackgroundStorageApi = {
      local: { setAccessLevel: async () => localGate.promise },
      session: {
        setAccessLevel: async () => sessionGate.promise,
        get: async () => {
          reads++;
          return {};
        },
        set: async () => undefined,
        remove: async () => undefined,
      },
    };
    const application = startBackground({
      storage,
      runtime: { id: "a".repeat(32), onConnect },
    });
    const port: ProviderRuntimePort = {
      name: PROVIDER_PORT_NAME,
      sender: {
        id: "a".repeat(32),
        documentId: "pre-ready-document",
        documentLifecycle: "active",
        origin: "https://dapp.example",
        url: "https://dapp.example/path",
        tab: { id: 1 },
        frameId: 0,
      },
      onMessage,
      onDisconnect,
      postMessage: (message) => posted.push(message),
      disconnect: () => onDisconnect.emit(),
    };
    onConnect.emit(port);
    onMessage.emit({
      version: 1,
      type: "request",
      correlationId: "pre_ready_0123456789",
      method: "standard:connect",
      params: {},
    });

    expect(reads).toBe(0);
    expect(posted).toEqual([
      {
        version: 1,
        type: "response",
        correlationId: "pre_ready_0123456789",
        ok: false,
        error: {
          code: "WARDEN_METHOD_UNAVAILABLE",
          message: "Warden provider methods are not enabled",
        },
      },
    ]);

    localGate.release();
    sessionGate.release();
    await application.providerReady;
    application.dispose();
  });

  it("removes the synchronous provider listener when trusted storage setup rejects", async () => {
    const onConnect = new RuntimeConnectEvent();
    const storage: ExtensionBackgroundStorageApi = {
      local: { setAccessLevel: async () => Promise.reject(new Error("access denied")) },
      session: {
        setAccessLevel: async () => undefined,
        get: async () => ({}),
        set: async () => undefined,
        remove: async () => undefined,
      },
    };
    const application = startBackground({
      storage,
      runtime: { id: "a".repeat(32), onConnect },
    });
    expect(onConnect.listeners.size).toBe(1);
    await expect(application.providerReady).rejects.toThrow("access denied");
    expect(onConnect.listeners.size).toBe(0);
    application.dispose();
  });

  it("removes the synchronous wake listener when disposed before readiness", async () => {
    const localGate = gate();
    const sessionGate = gate();
    const onConnect = new RuntimeConnectEvent();
    const storage: ExtensionBackgroundStorageApi = {
      local: { setAccessLevel: async () => localGate.promise },
      session: {
        setAccessLevel: async () => sessionGate.promise,
        get: async () => ({}),
        set: async () => undefined,
        remove: async () => undefined,
      },
    };
    const application = startBackground({
      storage,
      runtime: { id: "a".repeat(32), onConnect },
    });
    expect(onConnect.listeners.size).toBe(1);
    application.dispose();
    expect(onConnect.listeners.size).toBe(0);

    localGate.release();
    sessionGate.release();
    await expect(application.providerReady).rejects.toThrow(
      "background disposed before provider setup",
    );
  });

  it("rolls back the wake listener if bootstrap rejects synchronously", () => {
    const onConnect = new RuntimeConnectEvent();
    const malformedStorage = {
      local: { setAccessLevel: async () => undefined },
      session: { setAccessLevel: async () => undefined },
    } as unknown as ExtensionBackgroundStorageApi;

    expect(() =>
      startBackground({
        storage: malformedStorage,
        runtime: { id: "a".repeat(32), onConnect },
      }),
    ).toThrow("storage adapter must provide get()");
    expect(onConnect.listeners.size).toBe(0);
  });
});
