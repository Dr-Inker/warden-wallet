import { describe, expect, it } from "vitest";

import {
  bootstrapBackground,
  startBackground,
  type ExtensionBackgroundStorageApi,
} from "../src/background/runtime.js";
import type {
  ProviderConnectEvent,
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

  it("installs no provider listener until trusted storage setup and restore finish", async () => {
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
    await Promise.resolve();
    expect(onConnect.listeners.size).toBe(0);
    localGate.release();
    sessionGate.release();
    await Promise.resolve();
    await Promise.resolve();
    expect(onConnect.listeners.size).toBe(0);
    restoreGate.release();
    await application.providerReady;
    expect(onConnect.listeners.size).toBe(1);
    application.dispose();
  });

  it("never installs the provider listener when trusted storage setup rejects", async () => {
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
    await expect(application.providerReady).rejects.toThrow("access denied");
    expect(onConnect.listeners.size).toBe(0);
    application.dispose();
  });
});
