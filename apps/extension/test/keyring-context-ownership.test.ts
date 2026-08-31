import { describe, expect, it } from "vitest";

import {
  KeyringAuthError,
  SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION,
  encodeKeyringRecordStorageValue,
  encodeSessionSignerPayload,
  prepareKeyringRecordMetadata,
  sealKeyringRecord,
  type KeyringContext,
} from "@warden/core/keyring";
import { KeyringLifecycleOwner } from "../src/background/keyring-lifecycle.js";
import {
  KEYRING_RECORD_STORAGE_KEY,
  type KeyringRecordStorageArea,
} from "../src/background/keyring-record-store.js";
import type { UnlockSessionStorageArea } from "../src/background/unlock-session.js";

const EXTENSION_ID = "a".repeat(32);
const OTHER_EXTENSION_ID = "b".repeat(32);
const NOW = 1_700_000_000_000;
const fill = (length: number, value: number): Uint8Array =>
  new Uint8Array(length).fill(value);
const PASSWORD = new TextEncoder().encode("owned context password");
const CONTEXT: KeyringContext = {
  account: fill(32, 0x41),
  origin: `chrome-extension://${EXTENSION_ID}`,
  keyKind: "session-signer",
  schemaVersion: SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION,
  genesisHash: fill(32, 0x52),
  programId: fill(32, 0x63),
};
const POLICY = { idleTimeoutMs: 60_000, hardTimeoutMs: 120_000 } as const;

class LocalStorage implements KeyringRecordStorageArea {
  constructor(public value: unknown) {}

  async get(key: string): Promise<Record<string, unknown>> {
    return this.value === undefined ? {} : { [key]: this.value };
  }

  async set(items: Record<string, unknown>): Promise<void> {
    this.value = items[KEYRING_RECORD_STORAGE_KEY];
  }

  async remove(): Promise<void> {
    this.value = undefined;
  }
}

class SessionStorage implements UnlockSessionStorageArea {
  readonly values: Record<string, unknown> = {};

  async get(key: string): Promise<Record<string, unknown>> {
    return Object.hasOwn(this.values, key)
      ? { [key]: structuredClone(this.values[key]) }
      : {};
  }

  async set(items: Record<string, unknown>): Promise<void> {
    Object.assign(this.values, structuredClone(items));
  }

  async remove(keys: string | string[]): Promise<void> {
    for (const key of Array.isArray(keys) ? keys : [keys]) delete this.values[key];
  }
}

async function record(context: KeyringContext = CONTEXT): Promise<string> {
  return encodeKeyringRecordStorageValue(
    await sealKeyringRecord({
      metadata: prepareKeyringRecordMetadata({
        argon2idParams: { memoryKiB: 64, timeCost: 1, parallelism: 1 },
        enablePrf: false,
        context,
      }),
      plaintext: encodeSessionSignerPayload(fill(32, 0x74)),
      passwordBytes: PASSWORD.slice(),
    }),
  );
}

describe("background-owned keyring context", () => {
  it("derives account/cluster/program from the record and origin from the runtime id", async () => {
    const lifecycle = new KeyringLifecycleOwner(
      new LocalStorage(await record()),
      new SessionStorage(),
      EXTENSION_ID,
      { readNow: () => NOW },
    );

    await lifecycle.unlockWithPassword({
      passwordBytes: PASSWORD.slice(),
      policy: POLICY,
    });
    const output = await lifecycle.useSessionSignerBytes("sign", async (lease) => {
      expect(lease.account).toEqual(CONTEXT.account);
      expect(lease.genesisHash).toEqual(CONTEXT.genesisHash);
      expect(lease.programId).toEqual(CONTEXT.programId);
      expect(lease.seed).toEqual(fill(32, 0x74));
      return Uint8Array.of(1, 2, 3);
    });
    expect(output).toEqual(Uint8Array.of(1, 2, 3));
  });

  it("rejects a record sealed for another extension origin before activating a session", async () => {
    const copiedContext = {
      ...CONTEXT,
      origin: `chrome-extension://${OTHER_EXTENSION_ID}`,
    };
    const session = new SessionStorage();
    const lifecycle = new KeyringLifecycleOwner(
      new LocalStorage(await record(copiedContext)),
      session,
      EXTENSION_ID,
      { readNow: () => NOW },
    );
    const secret = PASSWORD.slice();

    await expect(
      lifecycle.unlockWithPassword({ passwordBytes: secret, policy: POLICY }),
    ).rejects.toThrow(KeyringAuthError);
    expect(secret).toEqual(new Uint8Array(secret.length));
    await expect(lifecycle.isUnlocked()).resolves.toBe(false);
    expect(session.values).toEqual({});
  });
});
