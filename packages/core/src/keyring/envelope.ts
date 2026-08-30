//! The versioned AES-256-GCM envelope component used by the C2 keyring core.
//! `bundle.ts` is the intended persistent record: it stores one payload envelope
//! plus password and PRF wraps of the same random DEK. This module remains public
//! for strict component encoding and independent interoperability tests; C1 must not
//! revive the obsolete design of persisting two separately encrypted payloads.
//!
//! ## Wire format (v1)
//!
//! ```text
//! envelope := u16be(version) ‖ u8(nonceLen) ‖ nonce ‖ u32be(ctLen) ‖ ciphertext‖tag
//! ```
//!
//! Everything is explicitly length-delimited and the decoder refuses trailing bytes,
//! so a truncated or padded record is a `KeyringFormatError`, not a silent partial read.
//! `version` is checked against {@link SUPPORTED_KEYRING_ENVELOPE_VERSIONS} BEFORE any
//! other work, so an unknown version can never reach the AEAD.
//!
//! The header lives outside the AEAD (it has to — you must parse it to decrypt), so on
//! its own it is attacker-mutable in storage. That is why `version` is ALSO a bound
//! field of the AAD (`aad.ts`): rolling the stored version back to an older, weaker
//! format, or forward to confuse a future reader, changes the AAD and fails
//! authentication. The nonce is likewise covered — GCM authenticates its own IV.
//!
//! ## Nonces
//!
//! 96-bit (12-byte) random nonces from `crypto.getRandomValues`, freshly drawn on
//! every seal. 96 bits is the only IV length for which GCM uses the value directly
//! rather than hashing it, and it is what every interoperable implementation expects.
//! There is DELIBERATELY no way to inject a nonce through this API — not even for
//! tests — because a nonce-injection hook is exactly the footgun that turns "nonce
//! uniqueness is mandatory" into a comment. The tests prove per-seal randomness by
//! sealing twice, and prove interoperability by driving `crypto.subtle` directly.
//! Random 96-bit nonces carry the usual birthday bound (keep re-seals under ~2^32 per
//! unwrap key for a 2^-32 collision probability); a keyring re-seals on unlock-policy
//! changes and key rotations, i.e. a handful of times per install, so the bound is not
//! close. If a future design ever re-seals per operation, this must become a counter.
//!
//! ## What is NOT here (C1, deliberately not stubbed)
//!
//! `chrome.storage.session` placement of unlock material, MV3 service-worker
//! suspension handling, the CSP that forbids remote code and generic `eval`, and the
//! WebAuthn PRF assertion that produces a PRF secret are all C1 work and are
//! UNIMPLEMENTED. This module imports no extension API and takes no position on where
//! its output is stored. Nothing here should be read as enforcing those clauses.

import {
  KEYRING_AES_KEY_BYTES,
  KEYRING_NONCE_BYTES,
  KEYRING_TAG_BYTES,
  MAX_KEYRING_CIPHERTEXT_BYTES,
  openAead,
  sealAead,
} from "./aead.js";
import { KeyringFormatError } from "./errors.js";
import { encodeKeyringAad, type KeyringContext } from "./aad.js";
import { assertUnlocked, type UnlockDeadlines } from "./deadlines.js";
import type { KeyringUnwrapKey } from "./derive.js";

/** The current envelope format version. */
export const KEYRING_ENVELOPE_VERSION_1 = 1;
/** Every version this build can open. An envelope outside this set is rejected outright. */
export const SUPPORTED_KEYRING_ENVELOPE_VERSIONS: readonly number[] = [KEYRING_ENVELOPE_VERSION_1];
/** Unwrap-key length in bytes. AES-256 only; a 128-bit key is refused. */
export const KEYRING_UNWRAP_KEY_BYTES = KEYRING_AES_KEY_BYTES;
export { KEYRING_NONCE_BYTES, KEYRING_TAG_BYTES, MAX_KEYRING_CIPHERTEXT_BYTES } from "./aead.js";

/** A parsed keyring envelope. `ciphertext` is the GCM output, i.e. `ct ‖ tag`. */
export interface KeyringEnvelope {
  readonly version: number;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

/**
 * An unlock-deadline check to run before touching key material (WRD-KEY-03). `now`
 * is supplied by the caller — this module never reads the clock, so a wake handler
 * and a test drive the exact same code path.
 */
export interface UnlockCheck {
  readonly deadlines: UnlockDeadlines;
  readonly now: number;
}

/** Serialize one envelope component to its canonical bytes. */
export function encodeKeyringEnvelope(envelope: KeyringEnvelope): Uint8Array {
  const { version, nonce, ciphertext } = envelope;
  if (!Number.isInteger(version) || version < 0 || version > 0xffff) {
    throw new KeyringFormatError(`envelope version must be a u16, got ${version}`);
  }
  if (nonce.length !== KEYRING_NONCE_BYTES) {
    throw new KeyringFormatError(`nonce must be exactly ${KEYRING_NONCE_BYTES} bytes, got ${nonce.length}`);
  }
  if (ciphertext.length < KEYRING_TAG_BYTES) {
    throw new KeyringFormatError(`ciphertext must carry at least the ${KEYRING_TAG_BYTES}-byte tag`);
  }
  if (ciphertext.length > MAX_KEYRING_CIPHERTEXT_BYTES) {
    throw new KeyringFormatError(`ciphertext of ${ciphertext.length} bytes exceeds the cap`);
  }
  const out = new Uint8Array(2 + 1 + nonce.length + 4 + ciphertext.length);
  let o = 0;
  out[o++] = (version >>> 8) & 0xff;
  out[o++] = version & 0xff;
  out[o++] = nonce.length;
  out.set(nonce, o);
  o += nonce.length;
  const ctLen = ciphertext.length;
  out[o++] = (ctLen >>> 24) & 0xff;
  out[o++] = (ctLen >>> 16) & 0xff;
  out[o++] = (ctLen >>> 8) & 0xff;
  out[o++] = ctLen & 0xff;
  out.set(ciphertext, o);
  return out;
}

/**
 * Parse stored bytes into an envelope. STRICT: the version is validated first (an
 * unknown version is refused before any length is trusted), every length is checked
 * explicitly, and trailing bytes are an error rather than something to ignore.
 */
export function decodeKeyringEnvelope(bytes: Uint8Array): KeyringEnvelope {
  if (!(bytes instanceof Uint8Array)) throw new KeyringFormatError("envelope must be a Uint8Array");
  if (bytes.length < 3) throw new KeyringFormatError("envelope truncated: no header");
  const version = (bytes[0]! << 8) | bytes[1]!;
  if (!SUPPORTED_KEYRING_ENVELOPE_VERSIONS.includes(version)) {
    throw new KeyringFormatError(`unknown envelope version ${version}`);
  }
  const nonceLen = bytes[2]!;
  if (nonceLen !== KEYRING_NONCE_BYTES) {
    throw new KeyringFormatError(`v${version} requires a ${KEYRING_NONCE_BYTES}-byte nonce, got ${nonceLen}`);
  }
  if (bytes.length < 3 + nonceLen + 4) throw new KeyringFormatError("envelope truncated: no ciphertext length");
  const nonce = bytes.slice(3, 3 + nonceLen);
  let p = 3 + nonceLen;
  const ctLen = bytes[p]! * 0x100_0000 + bytes[p + 1]! * 0x1_0000 + bytes[p + 2]! * 0x100 + bytes[p + 3]!;
  p += 4;
  if (ctLen < KEYRING_TAG_BYTES) {
    throw new KeyringFormatError(`ciphertext length ${ctLen} is below the ${KEYRING_TAG_BYTES}-byte tag`);
  }
  if (ctLen > MAX_KEYRING_CIPHERTEXT_BYTES) {
    throw new KeyringFormatError(`ciphertext length ${ctLen} exceeds the cap`);
  }
  if (p + ctLen !== bytes.length) {
    throw new KeyringFormatError("envelope length does not match its ciphertext length (truncated or trailing bytes)");
  }
  return { version, nonce, ciphertext: bytes.slice(p, p + ctLen) };
}

/** Arguments to {@link sealKeyringEnvelope}. */
export interface SealParams {
  /** The secret to protect. Must be non-empty — an empty plaintext is treated as a caller bug. */
  readonly plaintext: Uint8Array;
  /** The 32-byte unwrap key from `derive.ts`. */
  readonly unwrapKey: KeyringUnwrapKey;
  /** The context this envelope is bound to. */
  readonly context: KeyringContext;
  /** Format version to write. Defaults to the current one. */
  readonly version?: number;
  /**
   * Optional unlock-deadline check. Supply it whenever a session already exists —
   * re-sealing is a key use, and WRD-KEY-03 requires a check on every key use.
   */
  readonly unlock?: UnlockCheck;
}

/**
 * Seal `plaintext` under a FRESH random nonce, authenticating the canonical AAD for
 * `context` and the format version. Returns the envelope; the caller serializes it
 * with {@link encodeKeyringEnvelope}.
 */
export async function sealKeyringEnvelope(params: SealParams): Promise<KeyringEnvelope> {
  const version = params.version ?? KEYRING_ENVELOPE_VERSION_1;
  if (!SUPPORTED_KEYRING_ENVELOPE_VERSIONS.includes(version)) {
    throw new KeyringFormatError(`refusing to seal at unsupported version ${version}`);
  }
  if (params.unlock !== undefined) {
    assertUnlocked(params.unlock.deadlines, params.unlock.now, "seal");
  }
  if (!(params.plaintext instanceof Uint8Array)) throw new KeyringFormatError("plaintext must be a Uint8Array");
  if (params.plaintext.length === 0) {
    // Fail closed: an empty plaintext here is almost always a buffer that was
    // already zeroized, and sealing it would silently destroy the keyring.
    throw new KeyringFormatError("refusing to seal an empty plaintext");
  }
  if (params.plaintext.length + KEYRING_TAG_BYTES > MAX_KEYRING_CIPHERTEXT_BYTES) {
    throw new KeyringFormatError(`plaintext of ${params.plaintext.length} bytes exceeds the envelope cap`);
  }
  const aad = encodeKeyringAad(params.context, version);
  const sealed = await sealAead({
    plaintext: params.plaintext,
    keyBytes: params.unwrapKey.bytes,
    keyName: "unwrap key",
    aad,
  });
  return { version, ...sealed };
}

/** Arguments to {@link openKeyringEnvelope}. */
export interface OpenParams {
  /** The envelope, either already parsed or as the raw bytes storage held. */
  readonly envelope: KeyringEnvelope | Uint8Array;
  /** The 32-byte unwrap key from `derive.ts`. */
  readonly unwrapKey: KeyringUnwrapKey;
  /** The context the caller believes it is in. A mismatch fails authentication. */
  readonly context: KeyringContext;
  /**
   * Optional unlock-deadline check (WRD-KEY-03). Omitted ONLY for the first open of
   * an unlock ceremony, where no session exists yet by definition; every later key
   * use — and every use after a service-worker wake — must pass it.
   */
  readonly unlock?: UnlockCheck;
}

/**
 * Authenticate and decrypt an envelope in `context`. Rejects — with an
 * indistinguishable {@link KeyringAuthError} — a wrong unwrap key, a tampered
 * ciphertext or tag, a tampered nonce, and ANY context mismatch: wrong account,
 * wrong origin, wrong key kind, wrong schema version, wrong Warden program id, and
 * (the WRDF-0023 case) an envelope transplanted to a different cluster, where the
 * SmartAccount address is identical but the genesis hash is not.
 *
 * Structural problems — an unknown format version, a bad length — surface earlier as
 * a {@link KeyringFormatError}, before any key is imported.
 */
export async function openKeyringEnvelope(params: OpenParams): Promise<Uint8Array> {
  const envelope =
    params.envelope instanceof Uint8Array ? decodeKeyringEnvelope(params.envelope) : params.envelope;
  if (!SUPPORTED_KEYRING_ENVELOPE_VERSIONS.includes(envelope.version)) {
    throw new KeyringFormatError(`unknown envelope version ${envelope.version}`);
  }
  if (envelope.nonce.length !== KEYRING_NONCE_BYTES) {
    throw new KeyringFormatError(`nonce must be exactly ${KEYRING_NONCE_BYTES} bytes, got ${envelope.nonce.length}`);
  }
  if (envelope.ciphertext.length < KEYRING_TAG_BYTES) {
    throw new KeyringFormatError("ciphertext is shorter than the authentication tag");
  }
  if (params.unlock !== undefined) {
    assertUnlocked(params.unlock.deadlines, params.unlock.now, "open");
  }
  // The AAD is REBUILT from the caller's context and the envelope's own version —
  // never read out of the envelope. That is what makes a transplanted envelope fail:
  // the attacker controls the stored bytes, but not the context we rebuild from.
  const aad = encodeKeyringAad(params.context, envelope.version);
  return openAead({
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    keyBytes: params.unwrapKey.bytes,
    keyName: "unwrap key",
    aad,
  });
}
