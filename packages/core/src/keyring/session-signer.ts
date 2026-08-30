//! Plaintext schema for the encrypted Ed25519 session signer.
//!
//! The envelope AAD already binds `keyKind = "session-signer"` and this
//! schema version, so v1 is deliberately only the 32-byte Ed25519 seed. The
//! Solana client expands that seed to its 64-byte `(seed || public key)`
//! representation when signing. Persisting the redundant public half would
//! create a consistency field that every consumer must remember to validate.
//!
//! These helpers copy on both sides. Callers still own zeroization of every
//! secret copy; JavaScript zeroization remains best effort.

import { KeyringFormatError } from "./errors.js";

/** Plaintext-layout version bound into {@link KeyringContext.schemaVersion}. */
export const SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION = 1;
/** Ed25519 seed width used by Solana's `Keypair.fromSeed`. */
export const SESSION_SIGNER_SEED_BYTES = 32;

function copySeed(value: unknown, name: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new KeyringFormatError(`${name} must be a Uint8Array`);
  }
  if (value.length !== SESSION_SIGNER_SEED_BYTES) {
    throw new KeyringFormatError(
      `${name} must be exactly ${SESSION_SIGNER_SEED_BYTES} bytes, got ${value.length}`,
    );
  }
  return value.slice();
}

/** Encode schema v1: the exact seed bytes, with no padding or implicit fields. */
export function encodeSessionSignerPayload(seed: Uint8Array): Uint8Array {
  return copySeed(seed, "session-signer seed");
}

/** Strictly decode schema v1 and return an isolated caller-owned seed copy. */
export function decodeSessionSignerPayload(plaintext: Uint8Array): Uint8Array {
  return copySeed(plaintext, "session-signer plaintext");
}
