import { describe, it, expect } from "vitest";
import {
  MAX_UNLOCK_TIMEOUT_MS,
  assertUnlockCheck,
  assertUnlocked,
  effectiveExpiresAt,
  evaluateUnlock,
  isUnlocked,
  snapshotUnlockCheck,
  startUnlockSession,
  touchUnlockSession,
  zeroizeUnwrapMaterial,
  type UnlockPolicy,
} from "../src/keyring/deadlines.js";
import { KeyringExpiredError, KeyringFormatError } from "../src/keyring/errors.js";

// Absolute wall-clock unlock deadlines (WRD-KEY-03).
//
// Every function under test takes `now` as a parameter and never reads the clock, so
// "the worker slept for four hours" is an ordinary argument rather than a fake timer.
// That is the point of the design, and it is why these are deterministic assertions.

const T0 = 1_700_000_000_000; // a fixed epoch-ms instant; nothing here depends on the real clock
const POLICY: UnlockPolicy = { idleTimeoutMs: 5 * 60_000, hardTimeoutMs: 60 * 60_000 };

describe("starting a session turns durations into ABSOLUTE instants", () => {
  it("stores epoch-ms deadlines, not remaining durations", () => {
    const d = startUnlockSession(T0, POLICY);
    expect(d.idleExpiresAt).toBe(T0 + POLICY.idleTimeoutMs);
    expect(d.hardExpiresAt).toBe(T0 + POLICY.hardTimeoutMs);
    expect(effectiveExpiresAt(d)).toBe(T0 + POLICY.idleTimeoutMs);
  });

  it("clamps the idle deadline to the hard ceiling when the policy inverts them", () => {
    const d = startUnlockSession(T0, { idleTimeoutMs: 60_000, hardTimeoutMs: 10_000 });
    expect(d.hardExpiresAt).toBe(T0 + 10_000);
    expect(d.idleExpiresAt).toBe(T0 + 10_000); // never promises past the ceiling
  });

  it("validates the policy instead of coercing it", () => {
    const bad: UnlockPolicy[] = [
      { idleTimeoutMs: 0, hardTimeoutMs: 1000 },
      { idleTimeoutMs: -1, hardTimeoutMs: 1000 },
      { idleTimeoutMs: 1.5, hardTimeoutMs: 1000 },
      { idleTimeoutMs: 1000, hardTimeoutMs: MAX_UNLOCK_TIMEOUT_MS + 1 },
      { idleTimeoutMs: Number.NaN, hardTimeoutMs: 1000 },
      { idleTimeoutMs: Number.POSITIVE_INFINITY, hardTimeoutMs: 1000 },
    ];
    for (const p of bad) expect(() => startUnlockSession(T0, p)).toThrow(KeyringFormatError);
    expect(() => startUnlockSession(Number.NaN, POLICY)).toThrow(KeyringFormatError);
  });
});

describe("the idle boundary is closed, in the safe direction", () => {
  const d = startUnlockSession(T0, POLICY);

  it("is live one millisecond before the idle deadline", () => {
    const r = evaluateUnlock(d, d.idleExpiresAt - 1);
    expect(r.state).toBe("live");
    if (r.state === "live") expect(r.remainingMs).toBe(1);
  });

  it("is EXPIRED exactly AT the idle deadline", () => {
    const r = evaluateUnlock(d, d.idleExpiresAt);
    expect(r.state).toBe("expired");
    if (r.state === "expired") {
      expect(r.reason).toBe("idle");
      expect(r.mustClearSessionMaterial).toBe(true);
    }
    expect(isUnlocked(d, d.idleExpiresAt)).toBe(false);
    expect(() => assertUnlocked(d, d.idleExpiresAt, "sign")).toThrow(KeyringExpiredError);
  });
});

describe("the hard boundary cannot be slid, however much activity there is", () => {
  it("expires at the hard deadline even under continuous touching", () => {
    const policy: UnlockPolicy = { idleTimeoutMs: 60_000, hardTimeoutMs: 5 * 60_000 };
    let d = startUnlockSession(T0, policy);
    // Touch every 30s — always inside the idle budget — right up to the ceiling.
    for (let t = T0 + 30_000; t < T0 + policy.hardTimeoutMs; t += 30_000) {
      d = touchUnlockSession(d, t, policy);
      expect(d.hardExpiresAt).toBe(T0 + policy.hardTimeoutMs); // never moves
      expect(d.idleExpiresAt).toBeLessThanOrEqual(d.hardExpiresAt); // never overshoots it
    }
    const r = evaluateUnlock(d, T0 + policy.hardTimeoutMs);
    expect(r.state).toBe("expired");
    if (r.state === "expired") expect(r.reason).toBe("hard");
  });

  it("reports `hard` when both deadlines have passed", () => {
    const d = startUnlockSession(T0, POLICY);
    const r = evaluateUnlock(d, T0 + 10 * 60 * 60_000);
    expect(r.state).toBe("expired");
    if (r.state === "expired") expect(r.reason).toBe("hard");
  });

  it("is live one millisecond before the hard deadline", () => {
    const policy: UnlockPolicy = { idleTimeoutMs: 60 * 60_000, hardTimeoutMs: 60_000 };
    const d = startUnlockSession(T0, policy);
    expect(evaluateUnlock(d, d.hardExpiresAt - 1).state).toBe("live");
    expect(evaluateUnlock(d, d.hardExpiresAt).state).toBe("expired");
  });
});

describe("MV3: the clock advances while the worker is asleep", () => {
  it("expires across a suspension in which nothing ran and no alarm fired", () => {
    const d = startUnlockSession(T0, POLICY);
    // Last thing before suspension: still live.
    expect(evaluateUnlock(d, T0 + 1000).state).toBe("live");

    // ---- the service worker is suspended here. No timer runs. No alarm fires. ----
    // A countdown or a `setTimeout` would simply have stopped; an absolute deadline
    // does not care that nothing executed in the interval.

    const wake = T0 + 4 * 60 * 60_000; // four hours later
    const r = evaluateUnlock(d, wake);
    expect(r.state).toBe("expired");
    if (r.state === "expired") expect(r.mustClearSessionMaterial).toBe(true);
    expect(() => assertUnlocked(d, wake, "sign")).toThrow(KeyringExpiredError);
  });

  it("survives a suspension SHORTER than the idle budget and stays live on wake", () => {
    const d = startUnlockSession(T0, POLICY);
    expect(evaluateUnlock(d, T0 + POLICY.idleTimeoutMs - 1).state).toBe("live");
  });

  it("refuses to resurrect an expired session via a touch after wake", () => {
    const d = startUnlockSession(T0, POLICY);
    const wake = T0 + POLICY.idleTimeoutMs + 1;
    expect(() => touchUnlockSession(d, wake, POLICY)).toThrow(KeyringExpiredError);
    // …and the original deadlines are unchanged, because touch never mutates.
    expect(d.idleExpiresAt).toBe(T0 + POLICY.idleTimeoutMs);
  });

  it("rejects a key use after expiry even though no alarm ever fired", () => {
    // Stated as its own case because it is the invariant's actual claim: alarms are a
    // wake-up aid. Nothing in this file schedules or consults one, and expiry still holds.
    const d = startUnlockSession(T0, POLICY);
    let threw: unknown;
    try {
      assertUnlocked(d, T0 + POLICY.hardTimeoutMs + 1, "decrypt");
    } catch (e) {
      threw = e;
    }
    expect(threw).toBeInstanceOf(KeyringExpiredError);
    expect((threw as KeyringExpiredError).reason).toBe("hard");
  });
});

describe("async key uses receive a live clock authority, never a sampled instant", () => {
  it("re-reads the clock on every check and closes exactly at the boundary", () => {
    const deadlines = startUnlockSession(T0, POLICY);
    let now = T0 + 1;
    const unlock = snapshotUnlockCheck({ deadlines, readNow: () => now });
    expect(() => assertUnlockCheck(unlock, "decrypt")).not.toThrow();
    now = deadlines.idleExpiresAt;
    expect(() => assertUnlockCheck(unlock, "decrypt")).toThrow(KeyringExpiredError);
  });

  it("rejects the obsolete frozen-number shape instead of silently reusing it", () => {
    const deadlines = startUnlockSession(T0, POLICY);
    expect(() =>
      snapshotUnlockCheck({
        deadlines,
        readNow: (T0 + 1) as unknown as () => number,
      }),
    ).toThrow(KeyringFormatError);
  });

  it("fails closed with a typed error when the clock reader itself throws", () => {
    const deadlines = startUnlockSession(T0, POLICY);
    const unlock = snapshotUnlockCheck({
      deadlines,
      readNow: () => {
        throw new Error("clock transport failed");
      },
    });
    expect(() => assertUnlockCheck(unlock, "decrypt")).toThrow(KeyringFormatError);
  });

  it("snapshots deadline values and reader identity before suspension", () => {
    const deadlines = startUnlockSession(T0, POLICY) as {
      idleExpiresAt: number;
      hardExpiresAt: number;
    };
    let now = T0 + 1;
    const source = { deadlines, readNow: () => now };
    const unlock = snapshotUnlockCheck(source)!;
    deadlines.idleExpiresAt = T0 + 1;
    source.readNow = () => T0 + POLICY.hardTimeoutMs;
    expect(() => assertUnlockCheck(unlock, "decrypt")).not.toThrow();
    now = unlock.deadlines.idleExpiresAt;
    expect(() => assertUnlockCheck(unlock, "decrypt")).toThrow(KeyringExpiredError);
  });
});

describe("touch slides only the idle deadline", () => {
  it("extends idle from `now`, not from the old deadline", () => {
    const d0 = startUnlockSession(T0, POLICY);
    const d1 = touchUnlockSession(d0, T0 + 60_000, POLICY);
    expect(d1.idleExpiresAt).toBe(T0 + 60_000 + POLICY.idleTimeoutMs);
    expect(d1.hardExpiresAt).toBe(d0.hardExpiresAt);
  });

  it("clamps a slide that would cross the hard ceiling", () => {
    const policy: UnlockPolicy = { idleTimeoutMs: 60_000, hardTimeoutMs: 90_000 };
    const d = touchUnlockSession(startUnlockSession(T0, policy), T0 + 60_000 - 1, policy);
    expect(d.idleExpiresAt).toBe(T0 + 90_000);
  });
});

describe("best-effort zeroization", () => {
  it("overwrites the buffer it is given (and claims nothing more)", () => {
    const secret = Uint8Array.from([1, 2, 3, 4, 5]);
    zeroizeUnwrapMaterial(secret);
    expect(Array.from(secret)).toEqual([0, 0, 0, 0, 0]);
    // It cannot reach an engine-made copy, and this test does not pretend it can.
    // See the honest caveat in `deadlines.ts`.
  });
});
