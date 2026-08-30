//! Absolute unlock deadlines — invariant `WRD-KEY-03`.
//!
//! ## The rule
//!
//! An unlocked keyring carries TWO absolute wall-clock instants, both epoch
//! milliseconds:
//!
//!   * `idleExpiresAt` — slides forward on user activity, but never past the hard one.
//!   * `hardExpiresAt` — fixed at unlock. Nothing slides it. It is the ceiling.
//!
//! Both are **absolute**, never "a duration plus a timer". This is the whole point of
//! the invariant. Under MV3 the service worker is suspended and revived at the
//! browser's discretion; a `setTimeout` that would have fired at T does not fire, and
//! a countdown that was decrementing simply stops. Wall-clock instants survive that,
//! because the check is `now >= deadline`, evaluated whenever someone actually asks —
//! not when a timer remembers to.
//!
//! **Alarms are a wake-up aid, never the authority.** `chrome.alarms` (C1) exists to
//! give the worker a chance to *proactively* clear material; it is not consulted here
//! and it is not required for expiry to take effect. A key use at an expired instant
//! is refused whether or not any alarm ever fired — the tests assert exactly that.
//!
//! ## Pure by construction
//!
//! Nothing in this module reads the clock implicitly. Pure policy functions take
//! `now` as a number. Async key-use APIs instead take an {@link UnlockCheck} whose
//! `readNow` callback is invoked before key use and again after every suspension
//! boundary. The same check carries an `AbortSignal` owned by the unlocked session,
//! so an explicit lock can revoke work that began while the deadline was still live.
//! A service worker supplies `Date.now` plus its session signal; a test supplies a
//! controlled reader/controller. They execute the identical code path, so "what
//! happens after a four-hour suspension" and "what if lock wins the race" are
//! deterministic assertions rather than hopes. A captured number is deliberately
//! not accepted by the async API: it would go stale at the first `await`.
//!
//! ## Boundary and clock semantics, stated rather than implied
//!
//!   * `now === deadline` is **EXPIRED**. Fail closed at the boundary.
//!   * `hard` outranks `idle` when both have passed, because it is the reason the
//!     session can never be resumed.
//!   * A refresh never resurrects: {@link touchUnlockSession} on an already-expired
//!     session throws instead of extending it.
//!   * Wall-clock is not monotonic. A backwards NTP step lengthens a live session by
//!     the size of the step, and a forwards step shortens it. The invariant asks for
//!     wall-clock deadlines and this implements them honestly; a monotonic clock is
//!     not available across an MV3 suspension, so a bounded backwards-jump residual
//!     is accepted rather than papered over. `MAX_UNLOCK_TIMEOUT_MS` bounds the blast
//!     radius of a misconfiguration but not of a clock step.
//!
//! ## What is NOT here (C1)
//!
//! The invariant also says expiry "clears all session unlock material". This module
//! reports {@link UnlockEvaluation.mustClearSessionMaterial} and offers
//! {@link zeroizeUnwrapMaterial} for buffers a caller holds, but the actual clearing
//! of `chrome.storage.session`, in-memory key references, pending ceremonies and
//! hardware transports is **C1 and unimplemented**. Nothing here creates or owns the
//! session controller either. C1 must create ONE controller per unlocked session,
//! pass that same signal to every key use, and synchronously abort it before clearing
//! the rest of the session on lock/account change. A fresh per-call signal defeats
//! revocation completely.
//!
//! Nor does a returned `Uint8Array` become magically revocable. Each async layer
//! re-checks before releasing its result to its caller, but the final consumer must
//! re-check this same authority immediately before sign/decrypt/export and must own
//! clearing any material it retains. WebCrypto has no `AbortSignal` parameter, and a
//! synchronous Argon2 call cannot process an event-loop abort until it returns.

import {
  KeyringExpiredError,
  KeyringFormatError,
  KeyringLockedError,
  type UnlockExpiryReason,
} from "./errors.js";

/**
 * Upper bound on any configured timeout: 30 days. A sanity rail, not a policy —
 * it exists so a units mistake (seconds read as milliseconds, or a `0` that became
 * `Infinity`) cannot mint an effectively immortal session.
 */
export const MAX_UNLOCK_TIMEOUT_MS = 30 * 24 * 60 * 60 * 1000;

/** Unlock timeouts, as durations. Turned into absolute instants at unlock time. */
export interface UnlockPolicy {
  /** Inactivity budget. Slides forward on {@link touchUnlockSession}. */
  readonly idleTimeoutMs: number;
  /** Total session budget from unlock. Never slides. */
  readonly hardTimeoutMs: number;
}

/** The two absolute deadlines of a live unlock session, in epoch milliseconds. */
export interface UnlockDeadlines {
  readonly idleExpiresAt: number;
  readonly hardExpiresAt: number;
}

/**
 * Live deadline authority for an asynchronous key use. `readNow` MUST read the
 * current epoch-millisecond clock on every call; it is a callback, rather than a
 * sampled number, so an operation cannot carry one preflight instant across an
 * `await` and accidentally return secret material after expiry. `signal` is the
 * stable, session-owned in-process revocation authority for explicit
 * lock/account-change races. It MUST NOT be a fresh per-call signal. WebCrypto itself
 * is not abortable; each caller suppresses a result if the signal fired before its
 * final check.
 */
export interface UnlockCheck {
  readonly deadlines: UnlockDeadlines;
  readonly readNow: () => number;
  readonly signal: AbortSignal;
}

/** The result of checking a session against an instant. */
export type UnlockEvaluation =
  | {
      readonly state: "live";
      /** Milliseconds until the FIRST of the two deadlines. */
      readonly remainingMs: number;
      /** `min(idleExpiresAt, hardExpiresAt)` — the instant that actually governs. */
      readonly effectiveExpiresAt: number;
    }
  | {
      readonly state: "expired";
      readonly reason: UnlockExpiryReason;
      /** Always true. The caller MUST clear session unlock material (C1 owns the clearing). */
      readonly mustClearSessionMaterial: true;
    };

function assertInstant(value: number, name: string): void {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new KeyringFormatError(`${name} must be a finite number of epoch milliseconds, got ${value}`);
  }
}

function assertDeadline(value: number, name: string): void {
  assertInstant(value, name);
  if (!Number.isInteger(value)) throw new KeyringFormatError(`${name} must be an integer, got ${value}`);
  if (value < 0 || value > Number.MAX_SAFE_INTEGER) {
    throw new KeyringFormatError(`${name} is out of range: ${value}`);
  }
}

/** Validate a policy completely: positive, integral, and inside the sanity bound. */
export function assertValidUnlockPolicy(policy: UnlockPolicy): void {
  for (const [name, value] of [
    ["idleTimeoutMs", policy.idleTimeoutMs],
    ["hardTimeoutMs", policy.hardTimeoutMs],
  ] as const) {
    if (!Number.isInteger(value)) throw new KeyringFormatError(`${name} must be an integer, got ${value}`);
    if (value <= 0) throw new KeyringFormatError(`${name} must be positive, got ${value}`);
    if (value > MAX_UNLOCK_TIMEOUT_MS) {
      throw new KeyringFormatError(`${name} of ${value} ms exceeds the ${MAX_UNLOCK_TIMEOUT_MS} ms cap`);
    }
  }
}

/** Validate a deadline pair. */
export function assertValidUnlockDeadlines(deadlines: UnlockDeadlines): void {
  if (typeof deadlines !== "object" || deadlines === null) {
    throw new KeyringFormatError("unlock deadlines must be an object");
  }
  assertDeadline(deadlines.idleExpiresAt, "idleExpiresAt");
  assertDeadline(deadlines.hardExpiresAt, "hardExpiresAt");
}

function assertAbortSignal(signal: AbortSignal): void {
  if (
    typeof signal !== "object" ||
    signal === null ||
    typeof signal.aborted !== "boolean" ||
    typeof signal.addEventListener !== "function" ||
    typeof signal.removeEventListener !== "function"
  ) {
    throw new KeyringFormatError("unlock check signal must be an AbortSignal");
  }
}

/**
 * Validate and snapshot caller-owned deadline authority before an async operation.
 * Numeric deadlines and the reader function identity are captured once so a caller
 * cannot swap either while WebCrypto is pending. The reader's own live clock state
 * intentionally remains dynamic.
 */
export function snapshotUnlockCheck(unlock: UnlockCheck | undefined): UnlockCheck | undefined {
  if (unlock === undefined) return undefined;
  if (typeof unlock !== "object" || unlock === null) {
    throw new KeyringFormatError("unlock check must be an object");
  }
  const sourceDeadlines = unlock.deadlines;
  const sourceReadNow = unlock.readNow;
  const signal = unlock.signal;
  assertValidUnlockDeadlines(sourceDeadlines);
  if (typeof sourceReadNow !== "function") {
    throw new KeyringFormatError("unlock check readNow must be a function");
  }
  assertAbortSignal(signal);
  const deadlines = Object.freeze({
    idleExpiresAt: sourceDeadlines.idleExpiresAt,
    hardExpiresAt: sourceDeadlines.hardExpiresAt,
  });
  const readNow = sourceReadNow.bind(unlock);
  return Object.freeze({ deadlines, readNow, signal });
}

/**
 * Convert a policy into absolute deadlines at the instant of unlock. The idle
 * deadline is clamped to the hard one immediately, so `idleExpiresAt` is never a
 * promise the hard ceiling would not honour (this matters when a policy configures a
 * hard budget shorter than the idle one).
 */
export function startUnlockSession(now: number, policy: UnlockPolicy): UnlockDeadlines {
  assertInstant(now, "now");
  assertValidUnlockPolicy(policy);
  const hardExpiresAt = Math.floor(now) + policy.hardTimeoutMs;
  const idleExpiresAt = Math.min(Math.floor(now) + policy.idleTimeoutMs, hardExpiresAt);
  const deadlines = { idleExpiresAt, hardExpiresAt };
  assertValidUnlockDeadlines(deadlines);
  return deadlines;
}

/** `min(idleExpiresAt, hardExpiresAt)` — the deadline that actually governs. */
export function effectiveExpiresAt(deadlines: UnlockDeadlines): number {
  assertValidUnlockDeadlines(deadlines);
  return Math.min(deadlines.idleExpiresAt, deadlines.hardExpiresAt);
}

/**
 * Check a session against an instant. Pure; the caller supplies `now`. `now` at or
 * past a deadline is expired — the boundary is closed, in the safe direction.
 */
export function evaluateUnlock(deadlines: UnlockDeadlines, now: number): UnlockEvaluation {
  assertValidUnlockDeadlines(deadlines);
  assertInstant(now, "now");
  if (now >= deadlines.hardExpiresAt) {
    return { state: "expired", reason: "hard", mustClearSessionMaterial: true };
  }
  if (now >= deadlines.idleExpiresAt) {
    return { state: "expired", reason: "idle", mustClearSessionMaterial: true };
  }
  const effective = Math.min(deadlines.idleExpiresAt, deadlines.hardExpiresAt);
  return { state: "live", remainingMs: effective - now, effectiveExpiresAt: effective };
}

/** True iff the session is live at `now`. */
export function isUnlocked(deadlines: UnlockDeadlines, now: number): boolean {
  return evaluateUnlock(deadlines, now).state === "live";
}

/**
 * Throw {@link KeyringExpiredError} unless the session is live at `now`. This is the
 * gate `WRD-KEY-03` means by "checked on every key use": call it synchronously
 * immediately before the key use, and AGAIN after any `await` that could have
 * suspended the worker — the second call is not redundant, because `now` moved.
 */
export function assertUnlocked(deadlines: UnlockDeadlines, now: number, operation: string): void {
  const result = evaluateUnlock(deadlines, now);
  if (result.state === "expired") throw new KeyringExpiredError(result.reason, operation);
}

/** Read a captured live clock and fail closed unless the session is live now. */
export function assertUnlockCheck(unlock: UnlockCheck | undefined, operation: string): void {
  if (unlock === undefined) return;
  if (typeof unlock !== "object" || unlock === null || typeof unlock.readNow !== "function") {
    throw new KeyringFormatError("unlock check must contain a readNow function");
  }
  const signal = unlock.signal;
  assertAbortSignal(signal);
  if (signal.aborted) throw new KeyringLockedError(operation);
  let now: number;
  try {
    now = unlock.readNow();
  } catch {
    throw new KeyringFormatError("unlock check readNow failed");
  }
  // A clock provider is ordinary caller code. If it synchronously triggered lock,
  // the revocation wins rather than allowing the stale pre-read signal state.
  if (signal.aborted) throw new KeyringLockedError(operation);
  assertUnlocked(unlock.deadlines, now, operation);
}

/**
 * Register best-effort cleanup for JS-owned secret copies when the owning unlocked
 * session is aborted. The callback runs at most once. This cannot cancel WebCrypto
 * or erase bytes the browser already copied internally; it only shortens the lifetime
 * of buffers this process still owns. The returned function MUST run in `finally`.
 */
export function registerUnlockAbortCleanup(
  unlock: UnlockCheck | undefined,
  cleanup: () => void,
): () => void {
  if (unlock === undefined) return () => undefined;
  const signal = unlock.signal;
  assertAbortSignal(signal);
  if (typeof cleanup !== "function") {
    throw new KeyringFormatError("unlock abort cleanup must be a function");
  }
  let active = true;
  let cleaned = false;
  const onAbort = (): void => {
    if (!active || cleaned) return;
    cleaned = true;
    cleanup();
  };
  signal.addEventListener("abort", onAbort, { once: true });
  // Adding a listener after abort does not replay the event. Close that race by
  // checking the sticky state immediately after registration.
  if (signal.aborted) onAbort();
  return () => {
    if (!active) return;
    active = false;
    signal.removeEventListener("abort", onAbort);
  };
}

/**
 * Slide the idle deadline forward on activity, clamped to the hard ceiling. Refuses
 * to act on an expired session: an expired session is gone, and a "touch" that could
 * revive one would turn the idle deadline into a suggestion.
 */
export function touchUnlockSession(
  deadlines: UnlockDeadlines,
  now: number,
  policy: UnlockPolicy,
): UnlockDeadlines {
  assertValidUnlockPolicy(policy);
  assertUnlocked(deadlines, now, "touch");
  return {
    idleExpiresAt: Math.min(Math.floor(now) + policy.idleTimeoutMs, deadlines.hardExpiresAt),
    hardExpiresAt: deadlines.hardExpiresAt,
  };
}

/**
 * Overwrite a secret buffer with zeroes. **Best effort, and deliberately not
 * described as more.** It zeroes THIS `Uint8Array`; it cannot reach a copy the JS
 * engine made when the value was passed around, a string the bytes came from (JS
 * strings are immutable and may be interned), or a page the GC already moved. It is
 * worth doing — it shortens the window in which a heap snapshot contains the secret —
 * and it is not a guarantee. The plan says not to overstate this, so: not stated.
 */
export function zeroizeUnwrapMaterial(bytes: Uint8Array): void {
  bytes.fill(0);
}
