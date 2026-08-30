//! Typed, fail-closed errors intentionally surfaced by the keyring core. Validation,
//! authentication, deadline/clock, and missing-WebCrypto failures use these classes;
//! callers must still treat an unexpected platform exception as a hard failure, never
//! as authorization (same discipline as `webauthn/assertion.ts`).
//!
//! The split matters for what a caller may LEARN from a failure:
//!
//!   * `KeyringFormatError` — structural: a length, a field, an unknown envelope
//!     version. Safe to describe, because it says nothing about key material.
//!   * `KeyringAuthError` — the AEAD rejected. DELIBERATELY uniform: wrong unwrap
//!     key, tampered ciphertext, tampered tag, wrong account, wrong origin, wrong
//!     key kind, and a cross-cluster replay all surface as the SAME message. AES-GCM
//!     gives us that indistinguishability for free and we must not throw it away by
//!     pre-checking context fields against a stored copy and reporting which one
//!     differed — that would turn the envelope into a context oracle.
//!   * `KeyringExpiredError` — an unlock deadline had passed at a live clock reading
//!     (WRD-KEY-03). Carries which deadline, because that is a UX fact, not a secret.
//!   * `KeyringLockedError` — the owning unlock session was explicitly revoked while
//!     work was pending. The browser may finish WebCrypto internally; its result is
//!     suppressed when revocation precedes the operation's final check, and
//!     JS-owned secret copies are cleared best effort.
//!   * `KeyringCryptoUnavailableError` — no WebCrypto. Fail closed; never fall back
//!     to a JS AES implementation.

/** Structural rejection: malformed input, bad length, unknown envelope version. */
export class KeyringFormatError extends Error {
  constructor(message: string) {
    super(`keyring: ${message}`);
    this.name = "KeyringFormatError";
  }
}

/**
 * AEAD authentication failed. The message is intentionally CONSTANT — the caller
 * must not be able to distinguish "wrong password" from "wrong cluster" from
 * "flipped a ciphertext bit" from this error.
 */
export class KeyringAuthError extends Error {
  constructor() {
    super("keyring: envelope failed authentication");
    this.name = "KeyringAuthError";
  }
}

/** Which absolute deadline had already passed. `hard` wins when both have. */
export type UnlockExpiryReason = "idle" | "hard";

/** An unlock deadline had passed at the latest live clock reading (WRD-KEY-03). */
export class KeyringExpiredError extends Error {
  readonly reason: UnlockExpiryReason;
  constructor(reason: UnlockExpiryReason, operation: string) {
    super(`keyring: ${reason} unlock deadline has passed; ${operation} refused`);
    this.name = "KeyringExpiredError";
    this.reason = reason;
  }
}

/** The owning unlock session was explicitly aborted before this operation released its result. */
export class KeyringLockedError extends Error {
  constructor(operation: string) {
    super(`keyring: unlock session was locked or revoked; ${operation} refused`);
    this.name = "KeyringLockedError";
  }
}

/** `globalThis.crypto.subtle` is missing. Fail closed — never substitute JS AES. */
export class KeyringCryptoUnavailableError extends Error {
  constructor(message: string) {
    super(`keyring: ${message}`);
    this.name = "KeyringCryptoUnavailableError";
  }
}
