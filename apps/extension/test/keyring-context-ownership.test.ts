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
const EXPECTED_CONTEXT = {
  genesisHash: fill(32, 0x52),
  programId: fill(32, 0x63),
};
const POLICY = { idleTimeoutMs: 60_000, hardTimeoutMs: 120_000 } as const;

function hex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)!.map((byte) => Number.parseInt(byte, 16)));
}

class LocalStorage implements KeyringRecordStorageArea {
  getHook: ((key: string) => Promise<Record<string, unknown>>) | undefined;

  constructor(public value: unknown) {}

  async get(key: string): Promise<Record<string, unknown>> {
    if (this.getHook !== undefined) return this.getHook(key);
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

async function record(
  context: KeyringContext = CONTEXT,
  seed: Uint8Array = fill(32, 0x74),
): Promise<string> {
  return encodeKeyringRecordStorageValue(
    await sealKeyringRecord({
      metadata: prepareKeyringRecordMetadata({
        argon2idParams: { memoryKiB: 64, timeCost: 1, parallelism: 1 },
        enablePrf: false,
        context,
      }),
      plaintext: encodeSessionSignerPayload(seed),
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
      { expectedContext: EXPECTED_CONTEXT, readNow: () => NOW },
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

  it("returns only authenticated public identity and an RFC-pinned signer public key", async () => {
    const seed = hex(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    );
    const lifecycle = new KeyringLifecycleOwner(
      new LocalStorage(await record(CONTEXT, seed)),
      new SessionStorage(),
      EXTENSION_ID,
      { expectedContext: EXPECTED_CONTEXT, readNow: () => NOW },
    );
    await lifecycle.unlockWithPassword({
      passwordBytes: PASSWORD.slice(),
      policy: POLICY,
    });

    const identity = await lifecycle.readAuthenticatedSessionIdentity(
      "select provider account",
    );

    expect(Object.keys(identity).sort()).toEqual([
      "account",
      "genesisHash",
      "programId",
      "revocationSignal",
      "sessionSigner",
    ]);
    expect(identity.account).toEqual(CONTEXT.account);
    expect(identity.genesisHash).toEqual(CONTEXT.genesisHash);
    expect(identity.programId).toEqual(CONTEXT.programId);
    expect(identity.sessionSigner).toEqual(
      hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    );

    identity.account.fill(0xff);
    identity.sessionSigner.fill(0xff);
    const second = await lifecycle.readAuthenticatedSessionIdentity(
      "select provider account again",
    );
    expect(second.account).toEqual(CONTEXT.account);
    expect(second.sessionSigner).toEqual(
      hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    );
    expect(second.revocationSignal).toBe(identity.revocationSignal);
    expect(identity.revocationSignal.aborted).toBe(false);
    await lifecycle.lock();
    expect(identity.revocationSignal.aborted).toBe(true);
  });

  it("suppresses a public identity snapshot and locks when account/chain context changes in flight", async () => {
    const first = await record();
    const changedContext: KeyringContext = {
      ...CONTEXT,
      account: fill(32, 0x91),
      genesisHash: fill(32, 0x92),
    };
    const second = await record(changedContext, fill(32, 0x93));
    const local = new LocalStorage(first);
    const session = new SessionStorage();
    const lifecycle = new KeyringLifecycleOwner(local, session, EXTENSION_ID, {
      expectedContext: EXPECTED_CONTEXT,
      readNow: () => NOW,
    });
    await lifecycle.unlockWithPassword({
      passwordBytes: PASSWORD.slice(),
      policy: POLICY,
    });
    let reads = 0;
    local.getHook = async (key) => {
      reads++;
      const observed = local.value;
      if (reads === 1) local.value = second;
      return observed === undefined ? {} : { [key]: observed };
    };

    await expect(
      lifecycle.readAuthenticatedSessionIdentity("select provider account"),
    ).rejects.toThrow(/persistent record changed/);
    await expect(lifecycle.isUnlocked()).resolves.toBe(false);
    expect(reads).toBe(2);
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
      { expectedContext: EXPECTED_CONTEXT, readNow: () => NOW },
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
