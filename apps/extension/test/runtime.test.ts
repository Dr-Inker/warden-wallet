import { describe, expect, it } from "vitest";

import {
  createPendingApprovalRecord,
  resolveApprovalRecord,
  snapshotApprovalRecord,
  type ApprovalRecord,
} from "@warden/core/approval";
import {
  KeyringFormatError,
  KeyringLockedError,
  SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION,
  decodeKeyringRecordStorageValue,
  deriveUnwrapKeyFromPasswordBytes,
  encodeKeyringRecordStorageValue,
  encodeSessionSignerPayload,
  sealKeyringRecord,
  type KeyringContext,
  type KeyringRecord,
} from "@warden/core/keyring";
import {
  BackgroundNotReadyError,
  bootstrapBackground,
  startBackground as startProductionBackground,
  type ApprovalStartupLifecycle,
  type ExtensionBackgroundChromeApi,
  type ExtensionBackgroundStorageApi,
} from "../src/background/runtime.js";
import { KeyringLifecycleOwner } from "../src/background/keyring-lifecycle.js";
import { shippedExpectedKeyringContext } from "../src/background/expected-keyring-context.js";
import { KEYRING_RECORD_STORAGE_KEY } from "../src/background/keyring-record-store.js";
import {
  UNLOCK_SESSION_STORAGE_KEY,
  UnlockSessionStorageError,
} from "../src/background/unlock-session.js";
import { PROVIDER_PORT_NAME } from "../src/background/provider-port.js";
import { POPUP_PORT_NAME } from "../src/popup-protocol.js";
import type {
  ProviderConnectEvent,
  ProviderDisconnectEvent,
  ProviderMessageEvent,
  ProviderRuntimePort,
} from "../src/background/provider-port.js";
import type { ApprovalWindowsApi } from "../src/background/approval-window.js";

interface Gate {
  readonly promise: Promise<void>;
  release(): void;
}

const fill = (length: number, value: number): Uint8Array =>
  new Uint8Array(length).fill(value);
const EXTENSION_ID = "a".repeat(32);
const SESSION_NOW = 1_700_000_000_000;
const PERSISTENT_BUNDLE_ID = fill(16, 0x12);
const SIGNER_PASSWORD = new TextEncoder().encode("runtime integration password");
// Production startup pins the shipped cluster/deployment, so a record the
// composed runtime is expected to adopt must carry exactly those bytes.
const SHIPPED_PINS = shippedExpectedKeyringContext();
const SIGNER_CONTEXT: KeyringContext = {
  account: fill(32, 0x41),
  origin: `chrome-extension://${EXTENSION_ID}`,
  keyKind: "session-signer",
  schemaVersion: SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION,
  genesisHash: SHIPPED_PINS.genesisHash,
  programId: SHIPPED_PINS.programId,
};
const SIGNER_POLICY = {
  idleTimeoutMs: 60_000,
  hardTimeoutMs: 120_000,
};

function runtimeApprovalRecord(): ApprovalRecord {
  return createPendingApprovalRecord({
    id: `req_${"ab".repeat(16)}`,
    origin: "https://runtime.example",
    tabId: 7,
    frameId: 0,
    documentId: "runtime-provider-document",
    account: fill(32, 0x11),
    method: "solana:signTransaction",
    chain: "solana:devnet",
    genesisHash: fill(32, 0x22),
    programId: fill(32, 0x33),
    rawMessage: Uint8Array.of(1, 2, 3),
    policyVersion: 1,
    createdAt: 1_000,
    expiresAt: 2_000,
  });
}

const PERSISTENT_RECORD = encodeKeyringRecordStorageValue({
  metadata: {
    version: 2,
    argon2id: {
      params: { memoryKiB: 64, timeCost: 1, parallelism: 1 },
      salt: fill(16, 0x11),
    },
    prf: null,
    context: SIGNER_CONTEXT,
  },
  bundle: {
    version: 1,
    bundleId: PERSISTENT_BUNDLE_ID,
    payload: {
      version: 1,
      nonce: fill(12, 0x13),
      ciphertext: fill(17, 0x14),
    },
    passwordWrap: {
      version: 1,
      nonce: fill(12, 0x15),
      ciphertext: fill(48, 0x16),
    },
    prfWrap: null,
  },
} satisfies KeyringRecord);

async function signerRecord(): Promise<string> {
  return encodeKeyringRecordStorageValue(
    await sealKeyringRecord({
      metadata: {
        version: 2,
        argon2id: {
          params: { memoryKiB: 64, timeCost: 1, parallelism: 1 },
          salt: fill(16, 0x73),
        },
        prf: null,
        context: SIGNER_CONTEXT,
      },
      plaintext: encodeSessionSignerPayload(fill(32, 0x74)),
      passwordBytes: SIGNER_PASSWORD.slice(),
    }),
  );
}

function storedSession(
  bundleId: Uint8Array,
  unwrapKey: Uint8Array = fill(32, 0x72),
): Record<string, unknown> {
  return {
    version: 2,
    account: Array.from(fill(32, 0x41)),
    bundleId: Array.from(bundleId),
    kdf: "argon2id-password",
    unwrapKey: Array.from(unwrapKey),
    idleExpiresAt: SESSION_NOW + 60_000,
    hardExpiresAt: SESSION_NOW + 120_000,
  };
}

type LocalArea = ExtensionBackgroundStorageApi["local"];

function localArea(
  setAccessLevel: LocalArea["setAccessLevel"],
  overrides: Partial<Omit<LocalArea, "setAccessLevel">> = {},
): LocalArea {
  return {
    setAccessLevel,
    get: async (key) => ({ [key]: PERSISTENT_RECORD }),
    set: async () => undefined,
    remove: async () => undefined,
    ...overrides,
  };
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

type RuntimeStorageChanges = Record<
  string,
  { readonly oldValue?: unknown; readonly newValue?: unknown }
>;

class RuntimeStorageChangeEvent {
  readonly listeners = new Set<(
    changes: RuntimeStorageChanges,
    areaName: string,
  ) => void>();

  addListener(listener: (
    changes: RuntimeStorageChanges,
    areaName: string,
  ) => void): void {
    this.listeners.add(listener);
  }

  removeListener(listener: (
    changes: RuntimeStorageChanges,
    areaName: string,
  ) => void): void {
    this.listeners.delete(listener);
  }

  emit(changes: RuntimeStorageChanges, areaName: string): void {
    for (const listener of [...this.listeners]) listener(changes, areaName);
  }
}

class RuntimeWindowRemovedEvent {
  readonly listeners = new Set<(windowId: number) => void>();

  addListener(listener: (windowId: number) => void): void {
    this.listeners.add(listener);
  }

  removeListener(listener: (windowId: number) => void): void {
    this.listeners.delete(listener);
  }

  emit(windowId: number): void {
    for (const listener of [...this.listeners]) listener(windowId);
  }
}

class RuntimeWindows implements ApprovalWindowsApi {
  readonly onRemoved = new RuntimeWindowRemovedEvent();
  readonly createCalls: unknown[] = [];
  readonly removeCalls: number[] = [];
  readonly existing = new Set<number>();

  async create(options: Parameters<ApprovalWindowsApi["create"]>[0]) {
    this.createCalls.push(Object.freeze({ ...options }));
    this.existing.add(91);
    return { id: 91 };
  }

  async get(windowId: number) {
    if (!this.existing.has(windowId)) throw new Error("No window with id");
    return { id: windowId };
  }

  async remove(windowId: number): Promise<void> {
    this.removeCalls.push(windowId);
    this.existing.delete(windowId);
    this.onRemoved.emit(windowId);
  }
}

function observableStorage(
  storage: ExtensionBackgroundStorageApi,
  onChanged = new RuntimeStorageChangeEvent(),
) {
  return Object.assign(storage, { onChanged });
}

function startBackground(
  chromeApi: Omit<ExtensionBackgroundChromeApi, "windows"> & {
    readonly windows?: ApprovalWindowsApi;
  },
  approvalLifecycle: ApprovalStartupLifecycle = {
    read: async () => null,
    reject: async () => Promise.reject(new Error("approval unavailable")),
    cancel: async () => Promise.reject(new Error("approval unavailable")),
    invalidateAfterWorkerRestart: async () => 0,
    close: () => {},
  },
) {
  return startProductionBackground({
    ...chromeApi,
    windows: chromeApi.windows ?? new RuntimeWindows(),
  }, approvalLifecycle);
}

describe("MV3 background bootstrap", () => {
  it("does not read persistent or session material until both areas are restricted", async () => {
    const localGate = gate();
    const sessionGate = gate();
    const calls: string[] = [];
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(
        async () => {
          calls.push("local:restrict");
          await localGate.promise;
          calls.push("local:restricted");
        },
        {
          get: async (key) => {
            calls.push("local:get");
            return { [key]: PERSISTENT_RECORD };
          },
        },
      ),
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

    const runtime = bootstrapBackground(storage, EXTENSION_ID);
    expect(Object.hasOwn(runtime, "keyringRecords")).toBe(false);
    expect(runtime.keyring).not.toBeInstanceOf(KeyringLifecycleOwner);
    expect(Object.getOwnPropertyNames(runtime.keyring)).toEqual([]);
    await Promise.resolve();
    expect(calls).toEqual(["local:restrict", "session:restrict"]);

    const preReadyPassword = SIGNER_PASSWORD.slice();
    const preReadyUnlock = runtime.keyring.unlockWithPassword({
      passwordBytes: preReadyPassword,
      policy: SIGNER_POLICY,
    });
    expect(preReadyPassword).toEqual(new Uint8Array(preReadyPassword.length));
    await expect(preReadyUnlock).rejects.toThrow(BackgroundNotReadyError);
    await expect(runtime.keyring.isUnlocked()).rejects.toThrow(
      BackgroundNotReadyError,
    );
    await expect(
      runtime.keyring.readAuthenticatedSessionIdentity("select provider account"),
    ).rejects.toThrow(BackgroundNotReadyError);
    expect(calls).toEqual(["local:restrict", "session:restrict"]);
    localGate.release();
    await Promise.resolve();
    expect(calls).not.toContain("session:get");
    sessionGate.release();
    await expect(runtime.ready).resolves.toBe(false);
    await expect(runtime.keyring.isUnlocked()).resolves.toBe(false);
    expect(calls.slice(-4)).toEqual([
      "local:restricted",
      "session:restricted",
      "local:get",
      "session:get",
    ]);
  });

  it("removes stale session material without parsing it when no persistent record exists", async () => {
    let sessionReads = 0;
    let sessionRemovals = 0;
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => undefined, {
        get: async () => ({}),
      }),
      session: {
        setAccessLevel: async () => undefined,
        get: async () => {
          sessionReads++;
          throw new Error("stale session must not be parsed");
        },
        set: async () => undefined,
        remove: async () => {
          sessionRemovals++;
        },
      },
    };

    const runtime = bootstrapBackground(storage, EXTENSION_ID);
    await expect(runtime.ready).resolves.toBe(false);
    expect(sessionReads).toBe(0);
    expect(sessionRemovals).toBe(1);
  });

  it("clears session material and fails closed on a malformed persistent record", async () => {
    let sessionReads = 0;
    let sessionRemovals = 0;
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => undefined, {
        get: async () => ({
          [KEYRING_RECORD_STORAGE_KEY]: "forged-persistent-record",
        }),
      }),
      session: {
        setAccessLevel: async () => undefined,
        get: async () => {
          sessionReads++;
          return {};
        },
        set: async () => undefined,
        remove: async () => {
          sessionRemovals++;
        },
      },
    };

    const runtime = bootstrapBackground(storage, EXTENSION_ID);
    await expect(runtime.ready).rejects.toThrow(KeyringFormatError);
    expect(sessionReads).toBe(0);
    expect(sessionRemovals).toBe(1);
  });

  it("restores only a session bound to the current persistent bundle", async () => {
    const persistentRecord = await signerRecord();
    const decoded = decodeKeyringRecordStorageValue(persistentRecord);
    if (decoded.metadata.version !== 2) throw new Error("test requires record v2");
    const unwrapKey = deriveUnwrapKeyFromPasswordBytes(
      SIGNER_PASSWORD.slice(),
      decoded.metadata.argon2id.salt,
      decoded.metadata.argon2id.params,
    );
    let sessionValue: Record<string, unknown> | undefined = storedSession(
      decoded.bundle.bundleId,
      unwrapKey.bytes,
    );
    unwrapKey.bytes.fill(0);
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => undefined, {
        get: async (key) => ({ [key]: persistentRecord }),
      }),
      session: {
        setAccessLevel: async () => undefined,
        get: async (key) =>
          sessionValue === undefined
            ? {}
            : { [key]: structuredClone(sessionValue) },
        set: async () => undefined,
        remove: async (keys) => {
          const requested = Array.isArray(keys) ? keys : [keys];
          if (requested.includes(UNLOCK_SESSION_STORAGE_KEY)) {
            sessionValue = undefined;
          }
        },
      },
    };

    const runtime = bootstrapBackground(storage, EXTENSION_ID, {
      readNow: () => SESSION_NOW,
    });
    await expect(runtime.ready).resolves.toBe(true);
    await expect(runtime.keyring.isUnlocked()).resolves.toBe(true);
    expect(sessionValue).toBeDefined();
  });

  it("removes a structurally valid session bound to another persistent bundle", async () => {
    let sessionValue: Record<string, unknown> | undefined = storedSession(
      fill(16, 0x99),
    );
    let currentSessionRemovals = 0;
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => undefined),
      session: {
        setAccessLevel: async () => undefined,
        get: async (key) =>
          sessionValue === undefined
            ? {}
            : { [key]: structuredClone(sessionValue) },
        set: async () => undefined,
        remove: async (keys) => {
          const requested = Array.isArray(keys) ? keys : [keys];
          if (requested.includes(UNLOCK_SESSION_STORAGE_KEY)) {
            currentSessionRemovals++;
            sessionValue = undefined;
          }
        },
      },
    };

    const runtime = bootstrapBackground(storage, EXTENSION_ID, {
      readNow: () => SESSION_NOW,
    });
    await expect(runtime.ready).resolves.toBe(false);
    await expect(runtime.keyring.isUnlocked()).resolves.toBe(false);
    expect(currentSessionRemovals).toBe(1);
    expect(sessionValue).toBeUndefined();
  });

  it("fails closed without reading when access restriction fails", async () => {
    let reads = 0;
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => Promise.reject(new Error("access denied"))),
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

    const runtime = bootstrapBackground(storage, EXTENSION_ID);
    await expect(runtime.ready).rejects.toThrow("access denied");
    expect(reads).toBe(0);
    await expect(runtime.keyring.isUnlocked()).rejects.toThrow(
      BackgroundNotReadyError,
    );
  });

  it("registers the provider wake listener synchronously while readiness remains gated", async () => {
    const localGate = gate();
    const sessionGate = gate();
    const restoreGate = gate();
    const onConnect = new RuntimeConnectEvent();
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => localGate.promise),
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
      storage: observableStorage(storage),
      runtime: { id: "a".repeat(32), onConnect },
    });
    let providerSettled = false;
    void application.runtimeBoundariesReady.finally(() => {
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
    await application.runtimeBoundariesReady;
    expect(providerSettled).toBe(true);
    expect(onConnect.listeners.size).toBe(1);
    application.dispose();
    expect(onConnect.listeners.size).toBe(0);
  });

  it("keeps every privileged facade gated until shipped approval startup invalidation settles", async () => {
    const approvalGate = gate();
    const calls: string[] = [];
    let approvalCloses = 0;
    const approvalStartup = {
      read: async () => null,
      reject: async () => Promise.reject(new Error("approval unavailable")),
      cancel: async () => Promise.reject(new Error("approval unavailable")),
      async invalidateAfterWorkerRestart(): Promise<number> {
        calls.push("approval:invalidate");
        await approvalGate.promise;
        calls.push("approval:invalidated");
        return 0;
      },
      close(): void {
        approvalCloses++;
      },
    };
    const onConnect = new RuntimeConnectEvent();
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => undefined, {
        get: async () => ({}),
      }),
      session: {
        setAccessLevel: async () => undefined,
        get: async () => ({}),
        set: async () => undefined,
        remove: async () => undefined,
      },
    };

    const application = startBackground({
      storage: observableStorage(storage),
      runtime: { id: "a".repeat(32), onConnect },
    }, approvalStartup);
    expect(calls).toEqual(["approval:invalidate"]);
    await Promise.resolve();
    await Promise.resolve();
    await expect(application.keyring.isUnlocked()).rejects.toThrow(
      BackgroundNotReadyError,
    );

    approvalGate.release();
    await expect(application.runtimeBoundariesReady).resolves.toBeDefined();
    expect(calls).toEqual(["approval:invalidate", "approval:invalidated"]);
    application.dispose();
    expect(approvalCloses).toBe(1);
  });

  it("closes every runtime surface when approval startup invalidation fails", async () => {
    const onConnect = new RuntimeConnectEvent();
    const onStorageChanged = new RuntimeStorageChangeEvent();
    let approvalCloses = 0;
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => undefined, {
        get: async () => ({}),
      }),
      session: {
        setAccessLevel: async () => undefined,
        get: async () => ({}),
        set: async () => undefined,
        remove: async () => undefined,
      },
    };
    const application = startBackground({
      storage: observableStorage(storage, onStorageChanged),
      runtime: { id: "a".repeat(32), onConnect },
    }, {
      read: async () => null,
      reject: async () => Promise.reject(new Error("approval unavailable")),
      cancel: async () => Promise.reject(new Error("approval unavailable")),
      invalidateAfterWorkerRestart: async () => {
        throw new Error("approval database unavailable");
      },
      close: () => {
        approvalCloses++;
      },
    });

    expect(onConnect.listeners.size).toBe(1);
    expect(onStorageChanged.listeners.size).toBe(1);
    await expect(application.runtimeBoundariesReady).rejects.toThrow(
      "approval database unavailable",
    );
    expect(onConnect.listeners.size).toBe(0);
    expect(onStorageChanged.listeners.size).toBe(0);
    expect(approvalCloses).toBe(1);
    application.dispose();
    expect(approvalCloses).toBe(1);
  });

  it("synchronously revokes a live session when the persistent record changes", async () => {
    const onConnect = new RuntimeConnectEvent();
    const onStorageChanged = new RuntimeStorageChangeEvent();
    const persistentRecord = await signerRecord();
    let sessionValue: unknown;
    let observeRemoval = false;
    let removalObserved!: () => void;
    const changedRecordRemoval = new Promise<void>((resolve) => {
      removalObserved = resolve;
    });
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => undefined, {
        get: async (key) => ({ [key]: persistentRecord }),
      }),
      session: {
        setAccessLevel: async () => undefined,
        get: async (key) => sessionValue === undefined
          ? {}
          : { [key]: structuredClone(sessionValue) },
        set: async (items) => {
          sessionValue = structuredClone(items[UNLOCK_SESSION_STORAGE_KEY]);
        },
        remove: async (keys) => {
          const requested = Array.isArray(keys) ? keys : [keys];
          if (requested.includes(UNLOCK_SESSION_STORAGE_KEY)) {
            sessionValue = undefined;
            if (observeRemoval) removalObserved();
          }
        },
      },
    };
    const application = startBackground({
      storage: observableStorage(storage, onStorageChanged),
      runtime: { id: "a".repeat(32), onConnect },
    });

    // Like runtime.onConnect, this listener must exist during top-level worker
    // evaluation so the storage change that wakes a worker cannot be missed.
    expect(onStorageChanged.listeners.size).toBe(1);
    await application.runtimeBoundariesReady;
    await application.keyring.unlockWithPassword({
      passwordBytes: SIGNER_PASSWORD.slice(),
      policy: SIGNER_POLICY,
    });

    // Wrong area and wrong key are not keyring mutations.
    onStorageChanged.emit(
      { [KEYRING_RECORD_STORAGE_KEY]: { newValue: PERSISTENT_RECORD } },
      "session",
    );
    onStorageChanged.emit({ "warden.unrelated": { newValue: 1 } }, "local");
    await expect(application.keyring.isUnlocked()).resolves.toBe(true);

    const useGate = gate();
    let leaseSignal: AbortSignal | undefined;
    let useEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      useEntered = resolve;
    });
    const pendingUse = application.keyring.useSessionSignerBytes(
      "decrypt",
      async (lease) => {
        leaseSignal = lease.unlock.signal;
        useEntered();
        await useGate.promise;
        return Uint8Array.of(7);
      },
    );
    await entered;
    observeRemoval = true;

    onStorageChanged.emit(
      {
        [KEYRING_RECORD_STORAGE_KEY]: {
          oldValue: persistentRecord,
          newValue: "replacement",
        },
      },
      "local",
    );

    // The event callback must revoke memory before its asynchronous Chrome
    // cleanup settles; otherwise an in-flight key use retains authority.
    expect(leaseSignal!.aborted).toBe(true);
    await expect(application.keyring.isUnlocked()).resolves.toBe(false);
    useGate.release();
    await expect(pendingUse).rejects.toThrow(KeyringLockedError);
    await changedRecordRemoval;
    expect(sessionValue).toBeUndefined();
    expect(onConnect.listeners.size).toBe(1);
    expect(onStorageChanged.listeners.size).toBe(1);

    application.dispose();
    expect(onStorageChanged.listeners.size).toBe(0);
  });

  it("closes every runtime surface when record-change session cleanup fails", async () => {
    const onConnect = new RuntimeConnectEvent();
    const onStorageChanged = new RuntimeStorageChangeEvent();
    const persistentRecord = await signerRecord();
    let sessionValue: unknown;
    let rejectRemove = false;
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => undefined, {
        get: async (key) => ({ [key]: persistentRecord }),
      }),
      session: {
        setAccessLevel: async () => undefined,
        get: async (key) => sessionValue === undefined
          ? {}
          : { [key]: structuredClone(sessionValue) },
        set: async (items) => {
          sessionValue = structuredClone(items[UNLOCK_SESSION_STORAGE_KEY]);
        },
        remove: async (keys) => {
          if (rejectRemove) throw new Error("session cleanup denied");
          const requested = Array.isArray(keys) ? keys : [keys];
          if (requested.includes(UNLOCK_SESSION_STORAGE_KEY)) sessionValue = undefined;
        },
      },
    };
    const application = startBackground({
      storage: observableStorage(storage, onStorageChanged),
      runtime: { id: "a".repeat(32), onConnect },
    });
    await application.runtimeBoundariesReady;
    await application.keyring.unlockWithPassword({
      passwordBytes: SIGNER_PASSWORD.slice(),
      policy: SIGNER_POLICY,
    });
    expect(sessionValue).toBeDefined();

    const activeMessages = new RuntimeMessageEvent();
    const activeDisconnect = new RuntimeDisconnectEvent();
    let activeDisconnects = 0;
    onConnect.emit({
      name: PROVIDER_PORT_NAME,
      sender: {
        id: "a".repeat(32),
        documentId: "fatal-cleanup-document",
        documentLifecycle: "active",
        origin: "https://dapp.example",
        url: "https://dapp.example/path",
        tab: { id: 9 },
        frameId: 0,
      },
      onMessage: activeMessages,
      onDisconnect: activeDisconnect,
      postMessage: () => undefined,
      disconnect: () => {
        activeDisconnects++;
        activeDisconnect.emit();
      },
    });
    expect(activeMessages.listeners.size).toBe(1);

    rejectRemove = true;
    const fatalFailure = application.fatal.catch((error: unknown) => error);
    onStorageChanged.emit(
      { [KEYRING_RECORD_STORAGE_KEY]: { newValue: "replacement" } },
      "local",
    );

    // Local authority is gone even though Chrome refused to remove the stale
    // serialized copy. The worker must also stop accepting every runtime port.
    await expect(application.keyring.isUnlocked()).resolves.toBe(false);
    await expect(fatalFailure).resolves.toBeInstanceOf(UnlockSessionStorageError);
    expect(sessionValue).toBeDefined();
    expect(onConnect.listeners.size).toBe(0);
    expect(onStorageChanged.listeners.size).toBe(0);
    expect(activeDisconnects).toBe(1);
    expect(activeMessages.listeners.size).toBe(0);
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
      local: localArea(async () => localGate.promise),
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
      storage: observableStorage(storage),
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
    await application.runtimeBoundariesReady;
    application.dispose();
  });

  it("routes popup and provider schemas separately before readiness", async () => {
    const localGate = gate();
    const sessionGate = gate();
    const onConnect = new RuntimeConnectEvent();
    let reads = 0;
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => localGate.promise),
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
      storage: observableStorage(storage),
      runtime: { id: "a".repeat(32), onConnect },
    });

    const popupMessages = new RuntimeMessageEvent();
    const popupDisconnect = new RuntimeDisconnectEvent();
    const popupPosted: unknown[] = [];
    const popupPort: ProviderRuntimePort = {
      name: POPUP_PORT_NAME,
      sender: {
        id: "a".repeat(32),
        documentId: "popup-document",
        documentLifecycle: "active",
        origin: `chrome-extension://${"a".repeat(32)}`,
        url: `chrome-extension://${"a".repeat(32)}/popup.html`,
      },
      onMessage: popupMessages,
      onDisconnect: popupDisconnect,
      postMessage: (message) => popupPosted.push(message),
      disconnect: () => popupDisconnect.emit(),
    };
    onConnect.emit(popupPort);
    popupMessages.emit({
      version: 1,
      type: "request",
      correlationId: "popup_runtime_01234567",
      method: "popup:getBoundaryStatus",
      params: {},
    });

    expect(reads).toBe(0);
    expect(popupPosted).toEqual([
      {
        version: 1,
        type: "response",
        correlationId: "popup_runtime_01234567",
        ok: false,
        error: {
          code: "WARDEN_POPUP_UNAVAILABLE",
          message: "Warden popup methods are not enabled",
        },
      },
    ]);

    // The same extension id is not privilege: a web content-script sender on
    // the popup channel must be disconnected by the central router's popup lane.
    const forgedMessages = new RuntimeMessageEvent();
    const forgedDisconnect = new RuntimeDisconnectEvent();
    let forgedDisconnects = 0;
    onConnect.emit({
      name: POPUP_PORT_NAME,
      sender: {
        id: "a".repeat(32),
        documentId: "content-script-document",
        documentLifecycle: "active",
        frameId: 0,
        origin: "https://dapp.example",
        url: "https://dapp.example/",
        tab: { id: 7 },
      },
      onMessage: forgedMessages,
      onDisconnect: forgedDisconnect,
      postMessage: () => {
        throw new Error("forged popup port must never receive a response");
      },
      disconnect: () => {
        forgedDisconnects++;
        forgedDisconnect.emit();
      },
    });
    expect(forgedDisconnects).toBe(1);
    expect(forgedMessages.listeners.size).toBe(0);

    const unknownMessages = new RuntimeMessageEvent();
    const unknownDisconnect = new RuntimeDisconnectEvent();
    let unknownDisconnects = 0;
    onConnect.emit({
      name: "warden:unknown:v1",
      sender: popupPort.sender,
      onMessage: unknownMessages,
      onDisconnect: unknownDisconnect,
      postMessage: () => {
        throw new Error("unknown channel must never receive a response");
      },
      disconnect: () => {
        unknownDisconnects++;
        unknownDisconnect.emit();
      },
    });
    expect(unknownDisconnects).toBe(1);
    expect(unknownMessages.listeners.size).toBe(0);

    localGate.release();
    sessionGate.release();
    await application.runtimeBoundariesReady;
    application.dispose();
  });

  it("removes the synchronous provider listener when trusted storage setup rejects", async () => {
    const onConnect = new RuntimeConnectEvent();
    const onStorageChanged = new RuntimeStorageChangeEvent();
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => Promise.reject(new Error("access denied"))),
      session: {
        setAccessLevel: async () => undefined,
        get: async () => ({}),
        set: async () => undefined,
        remove: async () => undefined,
      },
    };
    const application = startBackground({
      storage: observableStorage(storage, onStorageChanged),
      runtime: { id: "a".repeat(32), onConnect },
    });
    expect(onConnect.listeners.size).toBe(1);
    expect(onStorageChanged.listeners.size).toBe(1);
    await expect(application.runtimeBoundariesReady).rejects.toThrow("access denied");
    expect(onConnect.listeners.size).toBe(0);
    expect(onStorageChanged.listeners.size).toBe(0);
    application.dispose();
  });

  it("removes the synchronous wake listener when disposed before readiness", async () => {
    const localGate = gate();
    const sessionGate = gate();
    const onConnect = new RuntimeConnectEvent();
    const onStorageChanged = new RuntimeStorageChangeEvent();
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => localGate.promise),
      session: {
        setAccessLevel: async () => sessionGate.promise,
        get: async () => ({}),
        set: async () => undefined,
        remove: async () => undefined,
      },
    };
    const application = startBackground({
      storage: observableStorage(storage, onStorageChanged),
      runtime: { id: "a".repeat(32), onConnect },
    });
    expect(onConnect.listeners.size).toBe(1);
    expect(onStorageChanged.listeners.size).toBe(1);
    application.dispose();
    expect(onConnect.listeners.size).toBe(0);
    expect(onStorageChanged.listeners.size).toBe(0);

    localGate.release();
    sessionGate.release();
    await expect(application.runtimeBoundariesReady).rejects.toThrow(
      "background disposed before runtime boundaries became ready",
    );
  });

  it("rolls back the wake listener if bootstrap rejects synchronously", () => {
    const onConnect = new RuntimeConnectEvent();
    const onStorageChanged = new RuntimeStorageChangeEvent();
    const malformedStorage = {
      local: localArea(async () => undefined),
      session: { setAccessLevel: async () => undefined },
    } as unknown as ExtensionBackgroundStorageApi;

    expect(() =>
      startBackground({
        storage: observableStorage(malformedStorage, onStorageChanged),
        runtime: { id: "a".repeat(32), onConnect },
      }),
    ).toThrow("storage adapter must provide get()");
    expect(onConnect.listeners.size).toBe(0);
    expect(onStorageChanged.listeners.size).toBe(0);
  });

  it("rolls back a partially registered storage-change listener", async () => {
    const onConnect = new RuntimeConnectEvent();
    const onStorageChanged = new RuntimeStorageChangeEvent();
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => undefined),
      session: {
        setAccessLevel: async () => undefined,
        get: async () => ({}),
        set: async () => undefined,
        remove: async () => undefined,
      },
    };
    const failingStorageChangeEvent = {
      addListener(listener: Parameters<RuntimeStorageChangeEvent["addListener"]>[0]): void {
        onStorageChanged.addListener(listener);
        throw new Error("listener registration denied");
      },
      removeListener(listener: Parameters<RuntimeStorageChangeEvent["removeListener"]>[0]): void {
        onStorageChanged.removeListener(listener);
      },
    };

    expect(() =>
      startBackground({
        storage: Object.assign(storage, { onChanged: failingStorageChangeEvent }),
        runtime: { id: "a".repeat(32), onConnect },
      }),
    ).toThrow("listener registration denied");
    expect(onConnect.listeners.size).toBe(0);
    expect(onStorageChanged.listeners.size).toBe(0);

    // bootstrapBackground already started before event registration failed;
    // let its storage-only readiness work settle to avoid leaking test work.
    await Promise.resolve();
  });

  it("ships a readiness-gated internal approval-window owner and tears it down before repository close", async () => {
    const onConnect = new RuntimeConnectEvent();
    const onStorageChanged = new RuntimeStorageChangeEvent();
    const windows = new RuntimeWindows();
    const operations: string[] = [];
    let current = runtimeApprovalRecord();
    const approvalLifecycle: ApprovalStartupLifecycle = {
      async read(id) {
        operations.push(`approval:read:${id}`);
        return id === current.id ? snapshotApprovalRecord(current) : null;
      },
      async reject(id) {
        operations.push(`approval:reject:${id}`);
        current = resolveApprovalRecord(current, "rejected", 1_100);
        return snapshotApprovalRecord(current);
      },
      async cancel(id) {
        operations.push(`approval:cancel:${id}`);
        current = resolveApprovalRecord(current, "cancelled", 1_100);
        return snapshotApprovalRecord(current);
      },
      async invalidateAfterWorkerRestart() {
        operations.push("approval:invalidate");
        return 0;
      },
      close() {
        operations.push("approval:close");
      },
    };
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => undefined, { get: async () => ({}) }),
      session: {
        setAccessLevel: async () => undefined,
        get: async () => ({}),
        set: async () => undefined,
        remove: async () => undefined,
      },
    };
    const application = startProductionBackground({
      storage: observableStorage(storage, onStorageChanged),
      runtime: { id: EXTENSION_ID, onConnect },
      windows,
    }, approvalLifecycle);
    const launcher = application.approvalWindows;

    expect(windows.onRemoved.listeners.size).toBe(1);
    expect(onConnect.listeners.size).toBe(1);
    await application.runtimeBoundariesReady;
    await launcher.launch(current.id, new AbortController().signal);
    expect(windows.createCalls).toHaveLength(1);
    expect(operations).toEqual([
      "approval:invalidate",
      `approval:read:${current.id}`,
      `approval:read:${current.id}`,
    ]);

    application.dispose();
    expect(windows.onRemoved.listeners.size).toBe(0);
    expect(onConnect.listeners.size).toBe(0);
    expect(windows.removeCalls).toEqual([91]);
    expect(current.state).toBe("pending");
    expect(operations.at(-1)).toBe("approval:close");
  });

  it("fails the whole runtime closed when a disappeared window cannot be proven terminal", async () => {
    const onConnect = new RuntimeConnectEvent();
    const onStorageChanged = new RuntimeStorageChangeEvent();
    const windows = new RuntimeWindows();
    let current = runtimeApprovalRecord();
    let approvalCloses = 0;
    const cancellationError = new Error("approval cancellation unavailable");
    const approvalLifecycle: ApprovalStartupLifecycle = {
      async read(id) {
        return id === current.id ? snapshotApprovalRecord(current) : null;
      },
      async reject() {
        current = resolveApprovalRecord(current, "rejected", 1_100);
        return snapshotApprovalRecord(current);
      },
      async cancel() {
        throw cancellationError;
      },
      async invalidateAfterWorkerRestart() {
        return 0;
      },
      close() {
        approvalCloses++;
      },
    };
    const storage: ExtensionBackgroundStorageApi = {
      local: localArea(async () => undefined, { get: async () => ({}) }),
      session: {
        setAccessLevel: async () => undefined,
        get: async () => ({}),
        set: async () => undefined,
        remove: async () => undefined,
      },
    };
    const application = startProductionBackground({
      storage: observableStorage(storage, onStorageChanged),
      runtime: { id: EXTENSION_ID, onConnect },
      windows,
    }, approvalLifecycle);
    await application.runtimeBoundariesReady;
    await application.approvalWindows.launch(
      current.id,
      new AbortController().signal,
    );

    windows.existing.delete(91);
    windows.onRemoved.emit(91);
    await expect(application.fatal).rejects.toBe(cancellationError);

    expect(onConnect.listeners.size).toBe(0);
    expect(onStorageChanged.listeners.size).toBe(0);
    expect(windows.onRemoved.listeners.size).toBe(0);
    expect(approvalCloses).toBe(1);
    expect(current.state).toBe("pending");
  });
});
