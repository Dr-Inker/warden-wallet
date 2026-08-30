import { describe, expect, it } from "vitest";

import {
  KeyringLockedError,
  deriveUnwrapKeyFromPasswordBytes,
  deriveUnwrapKeyFromPasswordBytesAsync,
  type Argon2idParams,
} from "../src/keyring/index.js";

const fill = (length: number, value: number): Uint8Array =>
  new Uint8Array(length).fill(value);

const SALT = fill(16, 0x53);
const FAST: Argon2idParams = {
  memoryKiB: 64,
  timeCost: 1,
  parallelism: 1,
};

describe("cooperative Argon2id password derivation", () => {
  it("produces exactly the synchronous RFC implementation's key", async () => {
    const expected = deriveUnwrapKeyFromPasswordBytes(
      new TextEncoder().encode("async equivalence password"),
      SALT,
      FAST,
    );
    const actual = await deriveUnwrapKeyFromPasswordBytesAsync(
      new TextEncoder().encode("async equivalence password"),
      SALT,
      FAST,
    );

    expect(actual.kdf).toBe("argon2id-password");
    expect(actual.bytes).toEqual(expected.bytes);
  });

  it("yields to a host task, observes revocation, and wipes caller bytes", async () => {
    // Four MiB is deliberately large enough to cross the production time slice,
    // but small enough to keep this contract cheap in the repository gate. A
    // Promise/microtask-only yield cannot run this timer and will finish instead.
    const cancellable: Argon2idParams = {
      memoryKiB: 4 * 1024,
      timeCost: 1,
      parallelism: 1,
    };
    const password = new TextEncoder().encode("cancel this derivation");
    const controller = new AbortController();
    let hostTaskRan = false;
    const cancellation = new Promise<void>((resolve) => {
      setTimeout(() => {
        hostTaskRan = true;
        controller.abort();
        resolve();
      }, 0);
    });

    await expect(
      deriveUnwrapKeyFromPasswordBytesAsync(password, SALT, cancellable, {
        signal: controller.signal,
      }),
    ).rejects.toThrow(KeyringLockedError);
    await cancellation;

    expect(hostTaskRan).toBe(true);
    expect(password).toEqual(new Uint8Array(password.length));
  });

  it("rejects an already-revoked derivation before allocating Argon2 memory", async () => {
    const password = new TextEncoder().encode("already revoked");
    const controller = new AbortController();
    controller.abort();

    await expect(
      deriveUnwrapKeyFromPasswordBytesAsync(password, SALT, {
        memoryKiB: 128 * 1024,
        timeCost: 10,
        parallelism: 4,
      }, {
        signal: controller.signal,
      }),
    ).rejects.toThrow(KeyringLockedError);
    expect(password).toEqual(new Uint8Array(password.length));
  });
});
