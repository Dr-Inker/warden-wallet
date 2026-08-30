import { describe, expect, it } from "vitest";

import {
  KeyringAuthError,
  KeyringFormatError,
  KeyringLockedError,
  SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION,
  encodeKeyringRecordStorageValue,
  encodeSessionSignerPayload,
  sealKeyringRecord,
  type KeyringContext,
  type UnlockPolicy,
} from "@warden/core/keyring";
import {
  KeyringLifecycleConsistencyError,
  KeyringLifecycleOwner,
  type SessionSignerLease,
} from "../src/background/keyring-lifecycle.js";
import {
  KEYRING_RECORD_STORAGE_KEY,
  type KeyringRecordStorageArea,
} from "../src/background/keyring-record-store.js";
import {
  UNLOCK_SESSION_STORAGE_KEY,
  type UnlockSessionStorageArea,
} from "../src/background/unlock-session.js";

const fill = (length: number, value: number): Uint8Array =>
  new Uint8Array(length).fill(value);
const NOW = 1_700_000_000_000;
const POLICY: UnlockPolicy = {
  idleTimeoutMs: 15 * 60_000,
  hardTimeoutMs: 8 * 60 * 60_000,
};
const PASSWORD = new TextEncoder().encode("correct horse battery staple");
const SEED = Uint8Array.from({ length: 32 }, (_unused, index) => index + 1);
const CONTEXT: KeyringContext = {
  account: fill(32, 0x41),
  origin: "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  keyKind: "session-signer",
  schemaVersion: SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION,
  genesisHash: fill(32, 0x52),
  programId: fill(32, 0x63),
};

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

class LocalStorage implements KeyringRecordStorageArea {
  value: unknown;
  readonly operations: string[] = [];
  getHook: ((key: string) => Promise<Record<string, unknown>>) | undefined;

  constructor(value?: unknown) {
    this.value = value;
  }

  async get(key: string): Promise<Record<string, unknown>> {
    this.operations.push(`get:${key}`);
    if (this.getHook !== undefined) return this.getHook(key);
    return this.value === undefined ? {} : { [key]: this.value };
  }

  async set(items: Record<string, unknown>): Promise<void> {
    this.operations.push(`set:${Object.keys(items).join(",")}`);
    this.value = items[KEYRING_RECORD_STORAGE_KEY];
  }

  async remove(key: string): Promise<void> {
    this.operations.push(`remove:${key}`);
    this.value = undefined;
  }
}

class SessionStorage implements UnlockSessionStorageArea {
  readonly values: Record<string, unknown> = {};
  readonly operations: string[] = [];

  async get(key: string): Promise<Record<string, unknown>> {
    this.operations.push(`get:${key}`);
    return Object.hasOwn(this.values, key)
      ? { [key]: structuredClone(this.values[key]) }
      : {};
  }

  async set(items: Record<string, unknown>): Promise<void> {
    this.operations.push(`set:${Object.keys(items).join(",")}`);
    Object.assign(this.values, structuredClone(items));
  }

  async remove(keys: string | string[]): Promise<void> {
    const list = Array.isArray(keys) ? keys : [keys];
    this.operations.push(`remove:${list.join(",")}`);
    for (const key of list) delete this.values[key];
  }
}

async function record(
  seed: Uint8Array = SEED,
  password: Uint8Array = PASSWORD,
  context: KeyringContext = CONTEXT,
): Promise<string> {
  const sealed = await sealKeyringRecord({
    metadata: {
      version: 1,
      argon2id: {
        params: { memoryKiB: 64, timeCost: 1, parallelism: 1 },
        salt: fill(16, 0x71),
      },
      prf: null,
    },
    plaintext: encodeSessionSignerPayload(seed),
    passwordBytes: password.slice(),
    context,
  });
  return encodeKeyringRecordStorageValue(sealed);
}

function owner(local: LocalStorage, session = new SessionStorage()) {
  return {
    lifecycle: new KeyringLifecycleOwner(local, session, { readNow: () => NOW }),
    session,
  };
}

describe("composed persistent-record / unlock-session lifecycle", () => {
  it("authenticates one canonical record before activating and releases only an isolated seed lease", async () => {
    const local = new LocalStorage(await record());
    const { lifecycle, session } = owner(local);
    const password = PASSWORD.slice();

    const unlocking = lifecycle.unlockWithPassword({
      passwordBytes: password,
      context: CONTEXT,
      policy: POLICY,
    });
    expect(Array.from(password)).toEqual(new Array(password.length).fill(0));
    await unlocking;

    expect(await lifecycle.isUnlocked()).toBe(true);
    expect(JSON.stringify(session.values[UNLOCK_SESSION_STORAGE_KEY])).not.toContain(
      JSON.stringify(Array.from(SEED)),
    );

    let borrowed: SessionSignerLease | undefined;
    const result = await lifecycle.useSessionSignerBytes(
      "sign transaction",
      CONTEXT,
      async (lease) => {
        borrowed = lease;
        expect(Array.from(lease.account)).toEqual(Array.from(CONTEXT.account));
        expect(Array.from(lease.seed)).toEqual(Array.from(SEED));
        expect(lease.unlock.signal.aborted).toBe(false);
        return Uint8Array.of(7, 8, 9);
      },
    );
    expect(Array.from(result)).toEqual([7, 8, 9]);
    expect(Array.from(borrowed!.account)).toEqual(new Array(32).fill(0));
    expect(Array.from(borrowed!.seed)).toEqual(new Array(32).fill(0));
  });

  it("keeps a wrong password from creating an unlock session and consumes the password bytes", async () => {
    const local = new LocalStorage(await record());
    const { lifecycle, session } = owner(local);
    const password = new TextEncoder().encode("wrong password");

    await expect(
      lifecycle.unlockWithPassword({ passwordBytes: password, context: CONTEXT, policy: POLICY }),
    ).rejects.toThrow(KeyringAuthError);
    expect(Array.from(password)).toEqual(new Array(password.length).fill(0));
    expect(await lifecycle.isUnlocked()).toBe(false);
    expect(session.values[UNLOCK_SESSION_STORAGE_KEY]).toBeUndefined();
  });

  it("refuses the wrong plaintext schema before touching a live session", async () => {
    const local = new LocalStorage(await record());
    const { lifecycle } = owner(local);
    await lifecycle.unlockWithPassword({
      passwordBytes: PASSWORD.slice(),
      context: CONTEXT,
      policy: POLICY,
    });
    const wrongKind = { ...CONTEXT, keyKind: "recovery-secret" as const };

    await expect(
      lifecycle.useSessionSignerBytes("sign", wrongKind, async () => Uint8Array.of(1)),
    ).rejects.toThrow(KeyringFormatError);
    expect(await lifecycle.isUnlocked()).toBe(true);
  });

  it("does not revoke a live session for a replacement rejected before storage", async () => {
    const local = new LocalStorage(await record());
    const { lifecycle } = owner(local);
    await lifecycle.unlockWithPassword({
      passwordBytes: PASSWORD.slice(),
      context: CONTEXT,
      policy: POLICY,
    });

    await expect(lifecycle.replacePersistentRecord("not-a-record")).rejects.toThrow(
      KeyringFormatError,
    );
    expect(await lifecycle.isUnlocked()).toBe(true);
  });

  it("aborts and scrubs a pending signer lease synchronously before replacing its record", async () => {
    const first = await record();
    const second = await record(fill(32, 0x99));
    const local = new LocalStorage(first);
    const { lifecycle } = owner(local);
    await lifecycle.unlockWithPassword({
      passwordBytes: PASSWORD.slice(),
      context: CONTEXT,
      policy: POLICY,
    });
    const callbackGate = gate();
    const callbackEntered = gate();
    const lateOutput = Uint8Array.of(1, 2, 3);
    let borrowed: SessionSignerLease | undefined;
    const pending = lifecycle.useSessionSignerBytes("sign", CONTEXT, async (lease) => {
      borrowed = lease;
      callbackEntered.release();
      await callbackGate.promise;
      return lateOutput;
    });
    await Promise.race([
      callbackEntered.promise,
      pending.then(() => {
        throw new Error("signer use settled before entering its callback");
      }),
    ]);

    const replacing = lifecycle.replacePersistentRecord(second);
    expect(borrowed).toBeDefined();
    const activeBorrowed = borrowed!;
    expect(activeBorrowed.unlock.signal.aborted).toBe(true);
    expect(Array.from(activeBorrowed.seed)).toEqual(new Array(32).fill(0));
    callbackGate.release();

    await expect(pending).rejects.toThrow(KeyringLockedError);
    expect(Array.from(lateOutput)).toEqual([0, 0, 0]);
    await replacing;
    expect(local.value).toBe(second);
    expect(await lifecycle.isUnlocked()).toBe(false);
  });

  it("scrubs a result and locks when an unnotified record swap wins during signer use", async () => {
    const first = await record();
    const second = await record(fill(32, 0x97));
    const local = new LocalStorage(first);
    const { lifecycle, session } = owner(local);
    await lifecycle.unlockWithPassword({
      passwordBytes: PASSWORD.slice(),
      context: CONTEXT,
      policy: POLICY,
    });
    const output = Uint8Array.of(4, 5, 6);
    let borrowed: SessionSignerLease | undefined;

    await expect(
      lifecycle.useSessionSignerBytes("sign", CONTEXT, async (lease) => {
        borrowed = lease;
        // Model a trusted-context write for which the storage.onChanged event
        // has not arrived yet. The final exact readback must still suppress
        // the would-be signature before it escapes this owner.
        local.value = second;
        return output;
      }),
    ).rejects.toThrow(KeyringLifecycleConsistencyError);

    expect(Array.from(output)).toEqual([0, 0, 0]);
    expect(Array.from(borrowed!.account)).toEqual(new Array(32).fill(0));
    expect(Array.from(borrowed!.seed)).toEqual(new Array(32).fill(0));
    expect(await lifecycle.isUnlocked()).toBe(false);
    expect(session.values[UNLOCK_SESSION_STORAGE_KEY]).toBeUndefined();
  });

  it("locks when the persistent record disappears before signer use", async () => {
    const local = new LocalStorage(await record());
    const { lifecycle, session } = owner(local);
    await lifecycle.unlockWithPassword({
      passwordBytes: PASSWORD.slice(),
      context: CONTEXT,
      policy: POLICY,
    });
    local.value = undefined;
    let callbackCalled = false;

    await expect(
      lifecycle.useSessionSignerBytes("sign", CONTEXT, async () => {
        callbackCalled = true;
        return Uint8Array.of(1);
      }),
    ).rejects.toThrow(KeyringLifecycleConsistencyError);

    expect(callbackCalled).toBe(false);
    expect(await lifecycle.isUnlocked()).toBe(false);
    expect(session.values[UNLOCK_SESSION_STORAGE_KEY]).toBeUndefined();
  });

  it("scrubs the lease but preserves the session when local consumer code throws", async () => {
    const local = new LocalStorage(await record());
    const { lifecycle } = owner(local);
    await lifecycle.unlockWithPassword({
      passwordBytes: PASSWORD.slice(),
      context: CONTEXT,
      policy: POLICY,
    });
    let borrowed: SessionSignerLease | undefined;

    await expect(
      lifecycle.useSessionSignerBytes("sign", CONTEXT, async (lease) => {
        borrowed = lease;
        throw new Error("local signer consumer failed");
      }),
    ).rejects.toThrow("local signer consumer failed");

    expect(Array.from(borrowed!.account)).toEqual(new Array(32).fill(0));
    expect(Array.from(borrowed!.seed)).toEqual(new Array(32).fill(0));
    expect(await lifecycle.isUnlocked()).toBe(true);
  });

  it("prevents an unlock of a stale record from committing after a competing replacement", async () => {
    const first = await record();
    const second = await record(fill(32, 0x88));
    const local = new LocalStorage(first);
    const { lifecycle, session } = owner(local);
    const firstRead = gate();
    const firstReadStarted = gate();
    let reads = 0;
    local.getHook = async (key) => {
      reads++;
      if (reads === 1) {
        firstReadStarted.release();
        await firstRead.promise;
      }
      return local.value === undefined ? {} : { [key]: local.value };
    };

    const staleUnlock = lifecycle.unlockWithPassword({
      passwordBytes: PASSWORD.slice(),
      context: CONTEXT,
      policy: POLICY,
    });
    await firstReadStarted.promise;
    const replacing = lifecycle.replacePersistentRecord(second);
    firstRead.release();

    await expect(staleUnlock).rejects.toThrow(KeyringLockedError);
    await replacing;
    expect(local.value).toBe(second);
    expect(session.values[UNLOCK_SESSION_STORAGE_KEY]).toBeUndefined();
  });

  it("clears serialized session material when wake-time record validation fails", async () => {
    const local = new LocalStorage(await record());
    const session = new SessionStorage();
    const first = new KeyringLifecycleOwner(local, session, { readNow: () => NOW });
    await first.unlockWithPassword({
      passwordBytes: PASSWORD.slice(),
      context: CONTEXT,
      policy: POLICY,
    });
    expect(session.values[UNLOCK_SESSION_STORAGE_KEY]).toBeDefined();

    local.value = "malformed-persistent-record";
    const waking = new KeyringLifecycleOwner(local, session, { readNow: () => NOW });
    await expect(waking.restore()).rejects.toThrow(KeyringFormatError);
    expect(session.values[UNLOCK_SESSION_STORAGE_KEY]).toBeUndefined();
  });

  it("restores only a session bound to the current persistent bundle", async () => {
    const local = new LocalStorage(await record());
    const session = new SessionStorage();
    const first = new KeyringLifecycleOwner(local, session, { readNow: () => NOW });
    await first.unlockWithPassword({
      passwordBytes: PASSWORD.slice(),
      context: CONTEXT,
      policy: POLICY,
    });

    const waking = new KeyringLifecycleOwner(local, session, { readNow: () => NOW });
    await expect(waking.restore()).resolves.toBe(true);
    await expect(waking.isUnlocked()).resolves.toBe(true);

    local.value = await record(fill(32, 0xaa));
    const mismatched = new KeyringLifecycleOwner(local, session, { readNow: () => NOW });
    await expect(mismatched.restore()).resolves.toBe(false);
    expect(session.values[UNLOCK_SESSION_STORAGE_KEY]).toBeUndefined();
  });
});
