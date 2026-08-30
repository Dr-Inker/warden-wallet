//! Unwrap-key derivation — invariant `WRD-KEY-02` ("no retained password; no
//! equality-check auth") and the derivation half of C2's two unlock paths.
//!
//! Two paths produce the SAME shape of KEK, and both must be able to recover the
//! same random DEK and payload ciphertext through `bundle.ts`, because the plan is
//! explicit that PRF is an optimization only:
//!
//!   1. **Argon2id over a password** — always available, the fallback that must never
//!      stop working.
//!   2. **HKDF-SHA256 over a WebAuthn PRF secret** — faster, hardware-bound, and
//!      allowed only after a real-device compatibility matrix demonstrates it.
//!
//! ## What "no equality check" means here
//!
//! There is no `verifyPassword()` in this module and there must never be one. A
//! re-authentication is performed by DERIVING a KEK and letting the authenticated
//! DEK wrap accept or reject it (`bundle.ts`). Comparing a stored password, a stored
//! hash, or a stored derived key against a candidate would replace a cryptographic
//! authentication with a branch — the exact substitution `WRD-KEY-02` forbids, and
//! the exact branch a fault-injection or a tampered-storage attacker aims at.
//!
//! ## What "no retained password" means here
//!
//! This module holds no module-level state of any kind: no cache, no memo, no last
//! salt. It returns a derived key and keeps nothing. Both byte-oriented password
//! APIs zero the caller's password buffer before returning. Production async paths
//! should use {@link deriveUnwrapKeyFromPasswordBytesAsync}; the synchronous form is
//! retained for vectors and low-level compatibility only.
//!
//! The string overload cannot do that. **JS strings are immutable and may be interned
//! or copied by the engine, so a password that ever existed as a `string` cannot be
//! erased from the heap by any code in this process.** That is a property of the
//! platform, not a gap in this file, and the plan explicitly says not to overstate
//! zeroing. The only real mitigations are architectural: read the password into a
//! buffer where possible, never store it, never re-prompt from a cached copy, and
//! drop every reference immediately after derivation.
//!
//! ## Parameters are UNVERIFIED
//!
//! C2 requires benchmarking Argon2id on the slowest supported desktop class and
//! choosing the cost floor from MEASURED latency. That benchmark has not been run.
//! {@link PROVISIONAL_ARGON2ID_PARAMS} is therefore a labelled placeholder, not a
//! floor, and {@link Argon2idParams} is always an explicit argument — nothing in this
//! module silently inherits a PBKDF2 or legacy-wallet cost. Do not cite the
//! provisional numbers as a measured minimum anywhere.
//!
//! ## Not here (C1)
//!
//! Obtaining a PRF secret requires a WebAuthn assertion with the `prf` extension in
//! an extension context. That is C1 and UNIMPLEMENTED; this module takes the PRF
//! output as an argument and does the derivation half only.

import { argon2id, argon2idAsync } from "@noble/hashes/argon2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { KeyringFormatError, KeyringLockedError } from "./errors.js";
import { keyringPrfInfo, type KeyringContext } from "./aad.js";
import { zeroizeUnwrapMaterial } from "./deadlines.js";

/** Which derivation produced an unwrap key. Recorded for diagnostics; never a bypass. */
export type KeyringKdfLabel = "argon2id-password" | "webauthn-prf-hkdf";

/** Length of every unwrap key, in bytes (AES-256). */
export const UNWRAP_KEY_BYTES = 32;
/** Minimum Argon2id salt length, in bytes. RFC 9106 recommends 16. */
export const MIN_ARGON2ID_SALT_BYTES = 16;
/**
 * Resource-exhaustion ceilings for metadata read from persistent storage.
 * These are safety caps, NOT password-hardening floors: the measured product
 * floor remains open. Raising a ceiling requires a format/policy review.
 */
export const MAX_ARGON2ID_MEMORY_KIB = 128 * 1024;
export const MAX_ARGON2ID_TIME_COST = 10;
export const MAX_ARGON2ID_PARALLELISM = 16;
/** Length of the WebAuthn PRF secret the CTAP2 `hmac-secret` construction yields. */
export const WEBAUTHN_PRF_OUTPUT_BYTES = 32;
/** Maximum synchronous work budget before the async Argon2 driver yields to the host. */
export const ARGON2ID_ASYNC_TICK_MS = 10;

/** A derived key that can unwrap a keyring envelope. Always exactly 32 bytes. */
export interface KeyringUnwrapKey {
  readonly kdf: KeyringKdfLabel;
  readonly bytes: Uint8Array;
}

/**
 * Argon2id cost parameters. Explicit on every call — there is no ambient default
 * anywhere in this package.
 */
export interface Argon2idParams {
  /** Memory cost in KiB (`m`). */
  readonly memoryKiB: number;
  /** Time cost / iterations (`t`). */
  readonly timeCost: number;
  /** Parallelism / lanes (`p`). */
  readonly parallelism: number;
}

/** Optional revocation authority for a host-responsive password derivation. */
export interface Argon2idDerivationControl {
  readonly signal?: AbortSignal;
}

interface PrioritizedHostScheduler {
  postTask<T>(
    callback: () => T | PromiseLike<T>,
    options: {
      readonly priority: "background";
      readonly signal?: AbortSignal;
    },
  ): Promise<Awaited<T>>;
}

/**
 * **PROVISIONAL — UNVERIFIED, pending the C2 benchmark.**
 *
 * 64 MiB / t=3 / p=4 is the RFC 9106 "second recommended option" shape, chosen here
 * only so that tests and callers have something concrete to pass. It is **not** a
 * measured floor: C2 requires running Argon2id on the slowest supported desktop
 * class, recording memory/time/parallelism plus observed latency, choosing the floor
 * from that data and amending the spec. Until that happens, treat these numbers as a
 * placeholder and cite no security claim from them.
 */
export const PROVISIONAL_ARGON2ID_PARAMS: Argon2idParams = {
  memoryKiB: 64 * 1024,
  timeCost: 3,
  parallelism: 4,
};

/** Validate Argon2id parameters explicitly. No coercion, no rounding, no defaults. */
export function assertValidArgon2idParams(params: Argon2idParams): void {
  if (typeof params !== "object" || params === null) {
    throw new KeyringFormatError("argon2id params must be an object");
  }
  const rows: ReadonlyArray<readonly [string, number, number, number]> = [
    // [name, value, minimum, maximum]
    ["memoryKiB", params.memoryKiB, 8, MAX_ARGON2ID_MEMORY_KIB],
    ["timeCost", params.timeCost, 1, MAX_ARGON2ID_TIME_COST],
    ["parallelism", params.parallelism, 1, MAX_ARGON2ID_PARALLELISM],
  ];
  for (const [name, value, min, max] of rows) {
    if (!Number.isInteger(value)) throw new KeyringFormatError(`argon2id ${name} must be an integer, got ${value}`);
    if (value < min) throw new KeyringFormatError(`argon2id ${name} must be at least ${min}, got ${value}`);
    if (value > max) throw new KeyringFormatError(`argon2id ${name} must be at most ${max}, got ${value}`);
  }
  // RFC 9106: m must be at least 8*p KiB, else the lane layout is degenerate.
  if (params.memoryKiB < 8 * params.parallelism) {
    throw new KeyringFormatError(`argon2id memoryKiB must be at least 8*parallelism (${8 * params.parallelism})`);
  }
}

function assertSalt(salt: Uint8Array): void {
  if (!(salt instanceof Uint8Array)) throw new KeyringFormatError("salt must be a Uint8Array");
  if (salt.length < MIN_ARGON2ID_SALT_BYTES) {
    throw new KeyringFormatError(`salt must be at least ${MIN_ARGON2ID_SALT_BYTES} bytes, got ${salt.length}`);
  }
}

function snapshotDerivationSignal(
  control: Argon2idDerivationControl | undefined,
): AbortSignal | undefined {
  if (control === undefined) return undefined;
  if (typeof control !== "object" || control === null) {
    throw new KeyringFormatError("argon2id derivation control must be an object");
  }
  const signal = control.signal;
  if (signal === undefined) return undefined;
  if (
    typeof signal !== "object" ||
    signal === null ||
    typeof signal.aborted !== "boolean" ||
    typeof signal.addEventListener !== "function" ||
    typeof signal.removeEventListener !== "function"
  ) {
    throw new KeyringFormatError("argon2id derivation signal must be an AbortSignal");
  }
  return signal;
}

function prioritizedHostScheduler(): PrioritizedHostScheduler | undefined {
  const candidate = (globalThis as { readonly scheduler?: unknown }).scheduler;
  if (
    typeof candidate !== "object" ||
    candidate === null ||
    typeof (candidate as { readonly postTask?: unknown }).postTask !== "function"
  ) {
    return undefined;
  }
  return candidate as PrioritizedHostScheduler;
}

/**
 * Derive an unwrap key from password BYTES. **Zeroes `passwordBytes` before
 * returning** — pass a buffer you own and do not reuse it afterwards. Best effort,
 * with the honest caveats in this file's header.
 *
 * Throws rather than truncating on any invalid parameter; nothing here is silently
 * clamped.
 */
export function deriveUnwrapKeyFromPasswordBytes(
  passwordBytes: Uint8Array,
  salt: Uint8Array,
  params: Argon2idParams,
): KeyringUnwrapKey {
  if (!(passwordBytes instanceof Uint8Array)) throw new KeyringFormatError("passwordBytes must be a Uint8Array");
  // Every remaining check lives INSIDE the try, so that a rejected salt or a rejected
  // cost parameter still leaves the caller's password buffer zeroed. A validation path
  // that skips the wipe is exactly how a password survives a failed unlock attempt.
  try {
    if (passwordBytes.length === 0) throw new KeyringFormatError("refusing to derive from an empty password");
    assertSalt(salt);
    assertValidArgon2idParams(params);
    const bytes = argon2id(passwordBytes, salt, {
      m: params.memoryKiB,
      t: params.timeCost,
      p: params.parallelism,
      dkLen: UNWRAP_KEY_BYTES,
    });
    if (bytes.length !== UNWRAP_KEY_BYTES) {
      throw new KeyringFormatError(`argon2id returned ${bytes.length} bytes, expected ${UNWRAP_KEY_BYTES}`);
    }
    return { kdf: "argon2id-password", bytes };
  } finally {
    // Runs on the success path AND on any throw: a failed derivation must not leave
    // the password sitting in the caller's buffer either.
    zeroizeUnwrapMaterial(passwordBytes);
  }
}

/**
 * Host-responsive Argon2id derivation for production password paths.
 *
 * `@noble/hashes` 2.4 yields at least once per
 * {@link ARGON2ID_ASYNC_TICK_MS} synchronous-work window. In browsers with the
 * Prioritized Task Scheduling API, this wrapper starts the KDF as a `background`
 * task and passes the revocation signal to that task. Noble's internal
 * `scheduler.yield()` calls then inherit both properties: ordinary extension work
 * can run ahead of the continuation, and abort rejection invokes Noble's matrix
 * cleanup before unwinding. Without `scheduler.postTask`, Noble's timer fallback
 * still yields to host tasks, but its already-initialized computation is not
 * signal-cancellable; this wrapper wipes the caller-owned password promptly and
 * suppresses the eventual output instead. An already-aborted signal is rejected
 * before Argon2 allocates in either case.
 */
export async function deriveUnwrapKeyFromPasswordBytesAsync(
  passwordBytes: Uint8Array,
  salt: Uint8Array,
  params: Argon2idParams,
  control?: Argon2idDerivationControl,
): Promise<KeyringUnwrapKey> {
  if (!(passwordBytes instanceof Uint8Array)) {
    throw new KeyringFormatError("passwordBytes must be a Uint8Array");
  }
  let derivedBytes: Uint8Array | undefined;
  let removeAbortCleanup = (): void => undefined;
  try {
    if (passwordBytes.length === 0) {
      throw new KeyringFormatError("refusing to derive from an empty password");
    }
    assertSalt(salt);
    assertValidArgon2idParams(params);
    const signal = snapshotDerivationSignal(control);
    if (signal?.aborted) throw new KeyringLockedError("derive password unwrap key");

    if (signal !== undefined) {
      let active = true;
      const onAbort = (): void => {
        if (active) zeroizeUnwrapMaterial(passwordBytes);
      };
      signal.addEventListener("abort", onAbort, { once: true });
      // AbortSignal is sticky but does not replay an abort to a late listener.
      if (signal.aborted) onAbort();
      removeAbortCleanup = () => {
        if (!active) return;
        active = false;
        signal.removeEventListener("abort", onAbort);
      };
      if (signal.aborted) throw new KeyringLockedError("derive password unwrap key");
    }

    const derive = () => argon2idAsync(passwordBytes, salt, {
      m: params.memoryKiB,
      t: params.timeCost,
      p: params.parallelism,
      dkLen: UNWRAP_KEY_BYTES,
      asyncTick: ARGON2ID_ASYNC_TICK_MS,
    });
    const scheduler = prioritizedHostScheduler();
    try {
      derivedBytes = scheduler === undefined
        ? await derive()
        : await scheduler.postTask(derive, {
            priority: "background",
            ...(signal === undefined ? {} : { signal }),
          });
    } catch (error) {
      if (signal?.aborted) throw new KeyringLockedError("derive password unwrap key");
      throw error;
    }
    if (signal?.aborted) {
      zeroizeUnwrapMaterial(derivedBytes);
      derivedBytes = undefined;
      throw new KeyringLockedError("derive password unwrap key");
    }
    if (derivedBytes.length !== UNWRAP_KEY_BYTES) {
      zeroizeUnwrapMaterial(derivedBytes);
      derivedBytes = undefined;
      throw new KeyringFormatError(
        `argon2id returned an unexpected output length; expected ${UNWRAP_KEY_BYTES}`,
      );
    }
    return { kdf: "argon2id-password", bytes: derivedBytes };
  } finally {
    removeAbortCleanup();
    zeroizeUnwrapMaterial(passwordBytes);
  }
}

/**
 * Derive an unwrap key from a password STRING. Convenience for the realistic case
 * where the platform hands you a `string` (a DOM input value). The UTF-8 buffer this
 * function creates is zeroed; **the string itself cannot be**, for the platform
 * reasons documented in this file's header. Drop your reference to it immediately.
 */
export function deriveUnwrapKeyFromPassword(
  password: string,
  salt: Uint8Array,
  params: Argon2idParams,
): KeyringUnwrapKey {
  if (typeof password !== "string") throw new KeyringFormatError("password must be a string");
  if (password.length === 0) throw new KeyringFormatError("refusing to derive from an empty password");
  const bytes = new TextEncoder().encode(password);
  return deriveUnwrapKeyFromPasswordBytes(bytes, salt, params);
}

/**
 * Derive an unwrap key from a WebAuthn PRF secret via HKDF-SHA256.
 *
 * The raw PRF output is not used directly: HKDF gives domain separation and a clean
 * extract/expand, so the same authenticator secret used for another purpose cannot
 * yield this key. `info` binds the account, origin, key kind, genesis hash and
 * program id ({@link keyringPrfInfo}) — deliberately NOT the schema or envelope
 * version, so a format revision re-encodes the envelope without changing the key the
 * passkey derives.
 *
 * `prfSalt` is the per-account random salt stored beside the envelope; it is not
 * secret, and it exists so that rotating the unwrap key does not require a new
 * passkey.
 *
 * Acquiring `prfOutput` (a WebAuthn assertion carrying the `prf` extension) is C1 and
 * is NOT implemented anywhere in this package.
 */
export function deriveUnwrapKeyFromPrf(
  prfOutput: Uint8Array,
  prfSalt: Uint8Array,
  info: Uint8Array,
): KeyringUnwrapKey {
  if (!(prfOutput instanceof Uint8Array)) throw new KeyringFormatError("prfOutput must be a Uint8Array");
  if (prfOutput.length !== WEBAUTHN_PRF_OUTPUT_BYTES) {
    throw new KeyringFormatError(
      `prfOutput must be exactly ${WEBAUTHN_PRF_OUTPUT_BYTES} bytes, got ${prfOutput.length}`,
    );
  }
  assertSalt(prfSalt);
  if (!(info instanceof Uint8Array) || info.length === 0) {
    throw new KeyringFormatError("info must be a non-empty Uint8Array");
  }
  const bytes = hkdf(sha256, prfOutput, prfSalt, info, UNWRAP_KEY_BYTES);
  if (bytes.length !== UNWRAP_KEY_BYTES) {
    throw new KeyringFormatError(`hkdf returned ${bytes.length} bytes, expected ${UNWRAP_KEY_BYTES}`);
  }
  return { kdf: "webauthn-prf-hkdf", bytes };
}

/**
 * {@link deriveUnwrapKeyFromPrf} with the canonical context-bound `info`. The usual
 * entry point once C1 can produce a PRF secret.
 */
export function deriveUnwrapKeyFromPrfForContext(
  prfOutput: Uint8Array,
  prfSalt: Uint8Array,
  context: KeyringContext,
): KeyringUnwrapKey {
  return deriveUnwrapKeyFromPrf(prfOutput, prfSalt, keyringPrfInfo(context));
}

/** Zero an unwrap key's bytes. Best effort — see {@link zeroizeUnwrapMaterial}. */
export function zeroizeUnwrapKey(key: KeyringUnwrapKey): void {
  zeroizeUnwrapMaterial(key.bytes);
}
