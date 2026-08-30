import {
  KeyringExpiredError,
  KeyringLockedError,
  startUnlockSession,
  type KeyringUnwrapKey,
} from "@warden/core";
import { describe, expect, it } from "vitest";

import {
  UNLOCK_SESSION_STORAGE_KEY,
  UnlockSessionFormatError,
  UnlockSessionOwner,
  UnlockSessionStorageError,
  type UnlockSessionStorageArea,
} from "../src/background/unlock-session.js";

const fill = (length: number, value: number): Uint8Array => new Uint8Array(length).fill(value);
const T0 = 1_700_000_000_000;
const POLICY = { idleTimeoutMs: 15 * 60_000, hardTimeoutMs: 8 * 60 * 60_000 };
const ACCOUNT = fill(32, 0x41);
const key = (): KeyringUnwrapKey => ({ kdf: "argon2id-password", bytes: fill(32, 0x72) });

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

class MemorySessionStorage implements UnlockSessionStorageArea {
  value: unknown;
  readonly log: string[] = [];
  setCalls = 0;
  removeCalls = 0;
  setGate: Gate | undefined;
  removeGate: Gate | undefined;
  rejectSet = false;
  rejectRemove = false;
  corruptSet = false;
  private setEnteredResolve: (() => void) | undefined;
  private removeEnteredResolve: (() => void) | undefined;
  private readonly setWaiters: Array<{ target: number; resolve: () => void }> = [];
  private readonly removeWaiters: Array<{ target: number; resolve: () => void }> = [];
  setEntered = new Promise<void>((resolve) => {
    this.setEnteredResolve = resolve;
  });
  removeEntered = new Promise<void>((resolve) => {
    this.removeEnteredResolve = resolve;
  });

  waitForNextSet(): Promise<void> {
    const target = this.setCalls + 1;
    return new Promise<void>((resolve) => {
      this.setWaiters.push({ target, resolve });
    });
  }

  waitForNextRemove(): Promise<void> {
    const target = this.removeCalls + 1;
    return new Promise<void>((resolve) => {
      this.removeWaiters.push({ target, resolve });
    });
  }

  async get(keyName: string): Promise<Record<string, unknown>> {
    this.log.push("get");
    return this.value === undefined ? {} : { [keyName]: structuredClone(this.value) };
  }

  async set(items: Record<string, unknown>): Promise<void> {
    this.log.push("set:start");
    this.setCalls++;
    this.setEnteredResolve?.();
    for (let index = this.setWaiters.length - 1; index >= 0; index--) {
      const waiter = this.setWaiters[index]!;
      if (this.setCalls >= waiter.target) {
        this.setWaiters.splice(index, 1);
        waiter.resolve();
      }
    }
    await this.setGate?.promise;
    if (this.rejectSet) throw new Error("set failed");
    this.value = structuredClone(items[UNLOCK_SESSION_STORAGE_KEY]);
    if (this.corruptSet) {
      const record = this.value as { unwrapKey: number[] };
      record.unwrapKey[0] = record.unwrapKey[0]! ^ 0xff;
    }
    this.log.push("set:end");
  }

  async remove(_keyName: string): Promise<void> {
    this.log.push("remove:start");
    this.removeCalls++;
    this.removeEnteredResolve?.();
    for (let index = this.removeWaiters.length - 1; index >= 0; index--) {
      const waiter = this.removeWaiters[index]!;
      if (this.removeCalls >= waiter.target) {
        this.removeWaiters.splice(index, 1);
        waiter.resolve();
      }
    }
    await this.removeGate?.promise;
    if (this.rejectRemove) throw new Error("remove failed");
    this.value = undefined;
    this.log.push("remove:end");
  }
}

function owner(storage = new MemorySessionStorage(), readNow = () => T0 + 1) {
  return { storage, owner: new UnlockSessionOwner(storage, { readNow }) };
}

describe("MV3 unlock session ownership", () => {
  it("persists one strict JSON record and consumes the caller-owned unwrap key", async () => {
    const state = owner();
    const unwrapKey = key();
    await state.owner.unlock({
      account: ACCOUNT,
      unwrapKey,
      deadlines: startUnlockSession(T0, POLICY),
    });
    expect(await state.owner.isUnlocked()).toBe(true);
    expect(Array.from(unwrapKey.bytes)).toEqual(new Array(32).fill(0));
    expect(state.storage.value).toEqual({
      version: 1,
      account: Array.from(ACCOUNT),
      kdf: "argon2id-password",
      unwrapKey: new Array(32).fill(0x72),
      idleExpiresAt: T0 + POLICY.idleTimeoutMs,
      hardExpiresAt: T0 + POLICY.hardTimeoutMs,
    });
  });

  it("reuses one signal for the session and gives each key use an isolated key copy", async () => {
    const state = owner();
    await state.owner.unlock({
      account: ACCOUNT,
      unwrapKey: key(),
      deadlines: startUnlockSession(T0, POLICY),
    });
    const signals: AbortSignal[] = [];
    const borrowed: Uint8Array[] = [];
    for (let index = 0; index < 2; index++) {
      await state.owner.useBytes("sign", async (lease) => {
        signals.push(lease.unlock.signal);
        borrowed.push(lease.unwrapKey.bytes);
        expect(Array.from(lease.account)).toEqual(Array.from(ACCOUNT));
        return Uint8Array.of(index + 1);
      });
    }
    expect(signals[0]).toBe(signals[1]);
    expect(borrowed[0]).not.toBe(borrowed[1]);
    for (const bytes of borrowed) expect(Array.from(bytes)).toEqual(new Array(32).fill(0));
  });

  it("aborts and zeroes an in-flight lease synchronously before storage removal settles", async () => {
    const state = owner();
    await state.owner.unlock({
      account: ACCOUNT,
      unwrapKey: key(),
      deadlines: startUnlockSession(T0, POLICY),
    });
    const taskGate = gate();
    const removeGate = gate();
    state.storage.removeGate = removeGate;
    const removalEntered = state.storage.waitForNextRemove();
    let leaseSignal: AbortSignal | undefined;
    let leaseKey: Uint8Array | undefined;
    const lateOutput = fill(64, 0x99);
    let entered!: () => void;
    const taskEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const pending = state.owner.useBytes("sign", async (lease) => {
      leaseSignal = lease.unlock.signal;
      leaseKey = lease.unwrapKey.bytes;
      entered();
      await taskGate.promise;
      return lateOutput;
    });
    await taskEntered;

    const locking = state.owner.lock();
    expect(leaseSignal!.aborted).toBe(true);
    expect(Array.from(leaseKey!)).toEqual(new Array(32).fill(0));
    expect(await state.owner.isUnlocked()).toBe(false);
    taskGate.release();
    await expect(pending).rejects.toThrow(KeyringLockedError);
    expect(Array.from(lateOutput)).toEqual(new Array(64).fill(0));
    await removalEntered;
    removeGate.release();
    await locking;
    expect(state.storage.value).toBeUndefined();
  });

  it("serializes lock removal after a pending unlock write so stale material cannot win the race", async () => {
    const state = owner();
    const setGate = gate();
    state.storage.setGate = setGate;
    const activating = state.owner.unlock({
      account: ACCOUNT,
      unwrapKey: key(),
      deadlines: startUnlockSession(T0, POLICY),
    });
    await state.storage.setEntered;
    const locking = state.owner.lock();
    expect(state.storage.log.filter((entry) => entry === "remove:start")).toHaveLength(1);
    setGate.release();
    await expect(activating).rejects.toThrow(KeyringLockedError);
    await locking;
    expect(state.storage.log.slice(-3)).toEqual(["set:end", "remove:start", "remove:end"]);
    expect(state.storage.value).toBeUndefined();
  });

  it("does not expose a session until its storage replacement commits", async () => {
    const state = owner();
    const setGate = gate();
    state.storage.setGate = setGate;
    const activating = state.owner.unlock({
      account: ACCOUNT,
      unwrapKey: key(),
      deadlines: startUnlockSession(T0, POLICY),
    });
    await state.storage.setEntered;

    expect(await state.owner.isUnlocked()).toBe(false);
    await expect(state.owner.useBytes("sign", async () => Uint8Array.of(1))).rejects.toThrow(
      KeyringLockedError,
    );
    setGate.release();
    await activating;
    expect(await state.owner.isUnlocked()).toBe(true);
  });

  it("removes an activation that expires while its storage replacement is pending", async () => {
    let now = T0 + 1;
    const state = owner(undefined, () => now);
    const setGate = gate();
    state.storage.setGate = setGate;
    const deadlines = startUnlockSession(T0, POLICY);
    const activating = state.owner.unlock({ account: ACCOUNT, unwrapKey: key(), deadlines });
    await state.storage.setEntered;
    const removalEntered = state.storage.waitForNextRemove();
    now = deadlines.idleExpiresAt;
    setGate.release();

    await removalEntered;
    await expect(activating).rejects.toThrow(KeyringExpiredError);
    expect(state.storage.value).toBeUndefined();
    expect(await state.owner.isUnlocked()).toBe(false);
  });

  it("restores a live session after worker death and rejects it at the absolute idle boundary", async () => {
    let now = T0 + 1;
    const storage = new MemorySessionStorage();
    const first = new UnlockSessionOwner(storage, { readNow: () => now });
    const deadlines = startUnlockSession(T0, POLICY);
    await first.unlock({ account: ACCOUNT, unwrapKey: key(), deadlines });

    const afterWorkerDeath = new UnlockSessionOwner(storage, { readNow: () => now });
    expect(await afterWorkerDeath.restore()).toBe(true);
    expect(await afterWorkerDeath.useBytes("decrypt", async () => Uint8Array.of(7))).toEqual(
      Uint8Array.of(7),
    );
    now = deadlines.idleExpiresAt;
    await expect(afterWorkerDeath.useBytes("decrypt", async () => Uint8Array.of(8))).rejects.toThrow(
      KeyringExpiredError,
    );
    expect(storage.value).toBeUndefined();
  });

  it("refuses and removes malformed or ambiguous stored records", async () => {
    const state = owner();
    state.storage.value = {
      version: 1,
      account: new Array(32).fill(1),
      kdf: "argon2id-password",
      unwrapKey: new Array(32).fill(2),
      idleExpiresAt: T0 + 100,
      hardExpiresAt: T0 + 200,
      approved: true,
    };
    await expect(state.owner.restore()).rejects.toThrow(UnlockSessionFormatError);
    expect(await state.owner.isUnlocked()).toBe(false);
    expect(state.storage.value).toBeUndefined();
  });

  it("slides only idle time and persists the new absolute deadline", async () => {
    let now = T0 + 1;
    const state = owner(undefined, () => now);
    const deadlines = startUnlockSession(T0, POLICY);
    await state.owner.unlock({ account: ACCOUNT, unwrapKey: key(), deadlines });
    now = T0 + 60_000;
    await state.owner.touch(POLICY);
    expect(state.storage.value).toMatchObject({
      idleExpiresAt: now + POLICY.idleTimeoutMs,
      hardExpiresAt: deadlines.hardExpiresAt,
    });
  });

  it("does not revive a session that expires while a touch write is pending", async () => {
    let now = T0 + 1;
    const state = owner(undefined, () => now);
    const deadlines = startUnlockSession(T0, POLICY);
    await state.owner.unlock({ account: ACCOUNT, unwrapKey: key(), deadlines });
    const setGate = gate();
    state.storage.setGate = setGate;
    const setEntered = state.storage.waitForNextSet();
    now = T0 + 60_000;
    const touching = state.owner.touch(POLICY);
    await setEntered;
    const removalEntered = state.storage.waitForNextRemove();
    now = deadlines.idleExpiresAt;
    setGate.release();

    await removalEntered;
    await expect(touching).rejects.toThrow(KeyringExpiredError);
    expect(state.storage.value).toBeUndefined();
    expect(await state.owner.isUnlocked()).toBe(false);
  });

  it("invalidates an expired session when readiness is inspected", async () => {
    let now = T0 + 1;
    const state = owner(undefined, () => now);
    const deadlines = startUnlockSession(T0, POLICY);
    await state.owner.unlock({ account: ACCOUNT, unwrapKey: key(), deadlines });
    now = deadlines.idleExpiresAt;

    expect(await state.owner.isUnlocked()).toBe(false);
    expect(state.storage.value).toBeUndefined();
    await expect(state.owner.useBytes("sign", async () => Uint8Array.of(1))).rejects.toThrow(
      KeyringLockedError,
    );
  });

  it("zeroes a rejected output before an expired-session removal settles", async () => {
    let now = T0 + 1;
    const state = owner(undefined, () => now);
    const deadlines = startUnlockSession(T0, POLICY);
    await state.owner.unlock({ account: ACCOUNT, unwrapKey: key(), deadlines });
    const removeGate = gate();
    state.storage.removeGate = removeGate;
    const removalEntered = state.storage.waitForNextRemove();
    const output = fill(64, 0x99);

    const pending = state.owner.useBytes("decrypt", async () => {
      now = deadlines.idleExpiresAt;
      return output;
    });
    await removalEntered;
    expect(Array.from(output)).toEqual(new Array(64).fill(0));
    removeGate.release();
    await expect(pending).rejects.toThrow(KeyringExpiredError);
  });

  it("stays locally locked and typed-fail-closed when Chrome cannot remove session storage", async () => {
    const state = owner();
    await state.owner.unlock({
      account: ACCOUNT,
      unwrapKey: key(),
      deadlines: startUnlockSession(T0, POLICY),
    });
    state.storage.rejectRemove = true;
    await expect(state.owner.lock()).rejects.toThrow(UnlockSessionStorageError);
    expect(await state.owner.isUnlocked()).toBe(false);
    await expect(state.owner.useBytes("sign", async () => Uint8Array.of(1))).rejects.toThrow(
      KeyringLockedError,
    );
  });

  it("zeroes the caller key and leaves no active session when persistence fails", async () => {
    const state = owner();
    state.storage.rejectSet = true;
    const unwrapKey = key();
    await expect(
      state.owner.unlock({
        account: ACCOUNT,
        unwrapKey,
        deadlines: startUnlockSession(T0, POLICY),
      }),
    ).rejects.toThrow(UnlockSessionStorageError);
    expect(Array.from(unwrapKey.bytes)).toEqual(new Array(32).fill(0));
    expect(await state.owner.isUnlocked()).toBe(false);
  });

  it("rejects, removes, and locks after a mismatched storage readback", async () => {
    const state = owner();
    state.storage.corruptSet = true;
    await expect(
      state.owner.unlock({
        account: ACCOUNT,
        unwrapKey: key(),
        deadlines: startUnlockSession(T0, POLICY),
      }),
    ).rejects.toThrow(UnlockSessionStorageError);
    expect(state.storage.value).toBeUndefined();
    expect(await state.owner.isUnlocked()).toBe(false);
    await expect(state.owner.useBytes("sign", async () => Uint8Array.of(1))).rejects.toThrow(
      KeyringLockedError,
    );
  });
});
