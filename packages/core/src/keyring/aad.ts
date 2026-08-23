//! Canonical, **injective** additional-authenticated-data (AAD) for the Warden
//! keyring envelope — the half of invariant `WRD-KEY-04` that decides *which
//! context* an envelope is allowed to decrypt in.
//!
//! ## What is bound, and why each field is load-bearing
//!
//! | field           | why it is in the AAD                                                     |
//! |-----------------|--------------------------------------------------------------------------|
//! | `account`       | one envelope must not unwrap another SmartAccount's material              |
//! | `origin`        | the FULL extension origin — a different extension id must not unwrap it   |
//! | `keyKind`       | a session-signer envelope must not be opened as a recovery-secret one     |
//! | `schemaVersion` | a plaintext-layout change must not be reinterpretable under the old layout|
//! | `genesisHash`   | canonical cluster identity — see the cross-cluster note below (WRDF-0023) |
//! | `programId`     | ditto: the Warden program the account belongs to                          |
//!
//! **The cross-cluster case is not theoretical (WRDF-0023).** A Warden SmartAccount
//! PDA is *not network-qualified*: its seeds carry no cluster identity, so the same
//! `program id + root + salt` yields the SAME address on devnet and on mainnet. With
//! an account-only AAD, an envelope lifted from a devnet profile authenticates and
//! decrypts against a mainnet account of the same address — the "replayed-context
//! rejects" promise of `WRD-KEY-04` would be vacuous. Binding the genesis hash and
//! the program id closes it.
//!
//! **What is deliberately NOT bound: any per-release build hash.** A normal
//! extension update would then brick every existing envelope. The extension `origin`
//! is stable across updates; the build is not.
//!
//! ## The encoding, and why a naive concatenation is a real vulnerability
//!
//! If the AAD were `account ‖ origin ‖ keyKind ‖ …`, then the field vectors
//! `("ab", "c")` and `("a", "bc")` produce IDENTICAL bytes. An attacker who can
//! influence any variable-length field (the origin string is the obvious one) can
//! then make two genuinely different contexts authenticate the same envelope, and
//! the AAD stops being a context binding at all. That is a boundary-ambiguity /
//! canonicalization bug, the same class as a length-extension or a delimiter
//! injection.
//!
//! So the encoding is **prefix-decodable**:
//!
//! ```text
//! aad := LP(DOMAIN_TAG) ‖ u16be(envelopeVersion) ‖ u8(fieldCount) ‖ LP(f_1) ‖ … ‖ LP(f_n)
//! LP(x) := u32be(x.length) ‖ x                       // fixed-width 4-byte length prefix
//! ```
//!
//! Injectivity is not asserted, it is *exhibited*: `decodeLengthPrefixedFields` is a
//! total left inverse of `encodeLengthPrefixedFields` (a function with a left inverse
//! is injective). Every field's extent is read from its own fixed-width prefix, so no
//! field content can be mistaken for structure and there is no separator to smuggle.
//! `("ab","c")` encodes to `00000002 6162 00000001 63` and `("a","bc")` to
//! `00000001 61 00000002 6263` — different byte strings, as required.
//!
//! The `DOMAIN_TAG` gives cross-protocol separation: the C5 recovery envelope binds a
//! similar field set (`WRD-EXP-01`) and must never share an AAD space with this one.
//! `envelopeVersion` sits INSIDE the AAD as well as in the envelope header, so the
//! header's version bytes — which live outside the AEAD and are attacker-mutable in
//! storage — cannot be rolled back or bumped without failing authentication.
//!
//! Origin strings are bound as their EXACT UTF-8 bytes. This module deliberately does
//! not canonicalize (lowercase, strip a trailing slash, …): a normalizer is one more
//! place where two distinct origins could be made to collide. The caller must supply
//! one stable spelling; a mismatched spelling fails closed, which is the safe direction.

import { KeyringFormatError } from "./errors.js";

/** Domain-separation tag for the keyring-envelope AAD. Never reuse it elsewhere. */
export const KEYRING_AAD_DOMAIN = "warden/keyring-envelope/aad";
/**
 * Domain tag for the info string of the PRF unwrap-key derivation. Separate from
 * the AAD tag on purpose: the two are different cryptographic roles.
 */
export const KEYRING_PRF_INFO_DOMAIN = "warden/keyring-unwrap/prf";
/** Width of every length prefix, in bytes. Fixed — never varint, never inferred. */
export const LENGTH_PREFIX_BYTES = 4;
/** Number of context fields the keyring AAD binds. Pinned so an arity change cannot alias. */
export const KEYRING_AAD_FIELD_COUNT = 6;
/** Hard cap on any single encoded field. Prevents an absurd origin from being sealed at all. */
export const MAX_AAD_FIELD_BYTES = 4096;
/** A Solana pubkey / genesis hash, in bytes. Every 32-byte field is checked against it. */
export const PUBKEY_BYTES = 32;
/** Longest extension origin we accept, in UTF-8 bytes. `chrome-extension://<32 chars>` is 51. */
export const MAX_ORIGIN_BYTES = 512;

/**
 * The closed set of key kinds a keyring envelope may protect. Closed on purpose:
 * an open string here would let a caller invent a kind and, with a variable-length
 * neighbour, reopen the boundary question the length prefixes exist to settle.
 * Adding a member is backward compatible — the kind is per-envelope, not global.
 */
export const KEYRING_KEY_KINDS = ["session-signer", "approval-capability", "recovery-secret"] as const;

/** One of {@link KEYRING_KEY_KINDS}. */
export type KeyringKeyKind = (typeof KEYRING_KEY_KINDS)[number];

/**
 * The context an envelope is cryptographically bound to. All six fields are
 * mandatory; there is no "optional binding", because an optional binding is a
 * binding an attacker can choose to omit.
 */
export interface KeyringContext {
  /** SmartAccount pubkey, exactly 32 bytes. */
  readonly account: Uint8Array;
  /** FULL extension origin, e.g. `chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi`. */
  readonly origin: string;
  /** Which key this envelope protects. */
  readonly keyKind: KeyringKeyKind;
  /** Layout version of the PLAINTEXT inside the envelope (distinct from the envelope version). */
  readonly schemaVersion: number;
  /** Canonical cluster identity: the cluster's genesis hash, exactly 32 bytes (WRDF-0023). */
  readonly genesisHash: Uint8Array;
  /** The Warden program id the account belongs to, exactly 32 bytes (WRDF-0023). */
  readonly programId: Uint8Array;
}

const TEXT_ENCODER = /* @__PURE__ */ new TextEncoder();
const TEXT_DECODER = /* @__PURE__ */ new TextDecoder("utf-8", { fatal: true });

function u16be(n: number, name: string): [number, number] {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) {
    throw new KeyringFormatError(`${name} must be a u16 (0..65535), got ${n}`);
  }
  return [(n >>> 8) & 0xff, n & 0xff];
}

function u32beBytes(n: number, name: string): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
    throw new KeyringFormatError(`${name} must be a u32 (0..4294967295), got ${n}`);
  }
  return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

/**
 * Encode a domain tag, a version, and an ordered field vector into the canonical
 * prefix-decodable form documented at the top of this file. Injective in
 * `(domain, version, fields)` — see {@link decodeLengthPrefixedFields}, its left inverse.
 */
export function encodeLengthPrefixedFields(
  domain: string,
  version: number,
  fields: readonly Uint8Array[],
): Uint8Array {
  const domainBytes = TEXT_ENCODER.encode(domain);
  if (domainBytes.length === 0) throw new KeyringFormatError("domain tag must not be empty");
  if (domainBytes.length > MAX_AAD_FIELD_BYTES) throw new KeyringFormatError("domain tag too long");
  if (fields.length > 0xff) throw new KeyringFormatError(`field count must fit a u8, got ${fields.length}`);

  const out: number[] = [];
  const pushLp = (bytes: Uint8Array): void => {
    if (bytes.length > MAX_AAD_FIELD_BYTES) {
      throw new KeyringFormatError(`field of ${bytes.length} bytes exceeds the ${MAX_AAD_FIELD_BYTES}-byte cap`);
    }
    for (const b of u32beBytes(bytes.length, "field length")) out.push(b);
    for (const b of bytes) out.push(b);
  };

  pushLp(domainBytes);
  for (const b of u16be(version, "version")) out.push(b);
  out.push(fields.length);
  for (const f of fields) pushLp(f);
  return Uint8Array.from(out);
}

/**
 * The total left inverse of {@link encodeLengthPrefixedFields}. Its EXISTENCE is the
 * injectivity proof; the tests exercise it as such. It is a verification and
 * diagnostic aid — the seal/open path never needs to decode an AAD, it rebuilds one.
 * Strict: trailing bytes, a truncated field, or a length prefix that overruns the
 * buffer are all rejected.
 */
export function decodeLengthPrefixedFields(bytes: Uint8Array): {
  domain: string;
  version: number;
  fields: Uint8Array[];
} {
  let pos = 0;
  const need = (n: number): void => {
    if (pos + n > bytes.length) throw new KeyringFormatError("truncated: read past end");
  };
  const readU8 = (): number => {
    need(1);
    return bytes[pos++]!;
  };
  const readLp = (): Uint8Array => {
    need(LENGTH_PREFIX_BYTES);
    let len = 0;
    for (let i = 0; i < LENGTH_PREFIX_BYTES; i++) len = len * 0x100 + bytes[pos + i]!;
    pos += LENGTH_PREFIX_BYTES;
    if (len > MAX_AAD_FIELD_BYTES) throw new KeyringFormatError(`field length ${len} exceeds the cap`);
    need(len);
    const out = bytes.slice(pos, pos + len);
    pos += len;
    return out;
  };

  const domainBytes = readLp();
  let domain: string;
  try {
    domain = TEXT_DECODER.decode(domainBytes);
  } catch {
    throw new KeyringFormatError("domain tag is not valid UTF-8");
  }
  need(2);
  const version = (bytes[pos]! << 8) | bytes[pos + 1]!;
  pos += 2;
  const count = readU8();
  const fields: Uint8Array[] = [];
  for (let i = 0; i < count; i++) fields.push(readLp());
  if (pos !== bytes.length) throw new KeyringFormatError("trailing bytes after the last field");
  return { domain, version, fields };
}

/**
 * Validate a {@link KeyringContext} completely — every length checked explicitly,
 * nothing truncated, nothing defaulted. Throws `KeyringFormatError` on the first
 * violation. Called by every encode path, so a malformed context can never reach
 * the AEAD.
 */
export function assertValidKeyringContext(context: KeyringContext): void {
  const fixed: ReadonlyArray<readonly [string, Uint8Array]> = [
    ["account", context.account],
    ["genesisHash", context.genesisHash],
    ["programId", context.programId],
  ];
  for (const [name, value] of fixed) {
    if (!(value instanceof Uint8Array)) throw new KeyringFormatError(`${name} must be a Uint8Array`);
    if (value.length !== PUBKEY_BYTES) {
      throw new KeyringFormatError(`${name} must be exactly ${PUBKEY_BYTES} bytes, got ${value.length}`);
    }
  }
  if (typeof context.origin !== "string" || context.origin.length === 0) {
    throw new KeyringFormatError("origin must be a non-empty string");
  }
  // Control characters would never appear in a real extension origin and are a
  // classic confusable/log-injection vector, so refuse them rather than bind them.
  if (/[\u0000-\u001f\u007f]/.test(context.origin)) {
    throw new KeyringFormatError("origin must not contain control characters");
  }
  const originBytes = TEXT_ENCODER.encode(context.origin);
  if (originBytes.length > MAX_ORIGIN_BYTES) {
    throw new KeyringFormatError(`origin is ${originBytes.length} bytes, over the ${MAX_ORIGIN_BYTES}-byte cap`);
  }
  if (!(KEYRING_KEY_KINDS as readonly string[]).includes(context.keyKind)) {
    throw new KeyringFormatError(`unknown key kind ${JSON.stringify(context.keyKind)}`);
  }
  if (!Number.isInteger(context.schemaVersion) || context.schemaVersion < 0 || context.schemaVersion > 0xffff_ffff) {
    throw new KeyringFormatError(`schemaVersion must be a u32, got ${context.schemaVersion}`);
  }
}

/**
 * Build the canonical AAD bytes for `context` under `envelopeVersion`. This is the
 * ONLY AAD the seal/open path may use; both directions rebuild it from the context
 * they were handed, so a context mismatch of any kind surfaces as an AEAD failure
 * rather than as a comparison this code could get wrong.
 */
export function encodeKeyringAad(context: KeyringContext, envelopeVersion: number): Uint8Array {
  assertValidKeyringContext(context);
  return encodeLengthPrefixedFields(KEYRING_AAD_DOMAIN, envelopeVersion, [
    context.account,
    TEXT_ENCODER.encode(context.origin),
    TEXT_ENCODER.encode(context.keyKind),
    u32beBytes(context.schemaVersion, "schemaVersion"),
    context.genesisHash,
    context.programId,
  ]);
}

/**
 * Left inverse of {@link encodeKeyringAad}: recovers `(context, envelopeVersion)`
 * from canonical AAD bytes, or throws. Exists to make the injectivity property
 * mechanically checkable (and to debug a mismatch offline); it is NOT on the
 * seal/open path.
 */
export function decodeKeyringAad(bytes: Uint8Array): { context: KeyringContext; envelopeVersion: number } {
  const { domain, version, fields } = decodeLengthPrefixedFields(bytes);
  if (domain !== KEYRING_AAD_DOMAIN) {
    throw new KeyringFormatError(`wrong AAD domain ${JSON.stringify(domain)}`);
  }
  if (fields.length !== KEYRING_AAD_FIELD_COUNT) {
    throw new KeyringFormatError(`expected ${KEYRING_AAD_FIELD_COUNT} AAD fields, got ${fields.length}`);
  }
  const [account, originBytes, keyKindBytes, schemaBytes, genesisHash, programId] = fields as [
    Uint8Array,
    Uint8Array,
    Uint8Array,
    Uint8Array,
    Uint8Array,
    Uint8Array,
  ];
  if (schemaBytes.length !== 4) {
    throw new KeyringFormatError(`schemaVersion field must be 4 bytes, got ${schemaBytes.length}`);
  }
  let origin: string;
  let keyKind: string;
  try {
    origin = TEXT_DECODER.decode(originBytes);
    keyKind = TEXT_DECODER.decode(keyKindBytes);
  } catch {
    throw new KeyringFormatError("origin or key kind is not valid UTF-8");
  }
  const schemaVersion =
    schemaBytes[0]! * 0x100_0000 + schemaBytes[1]! * 0x1_0000 + schemaBytes[2]! * 0x100 + schemaBytes[3]!;
  const context: KeyringContext = {
    account,
    origin,
    keyKind: keyKind as KeyringKeyKind,
    schemaVersion,
    genesisHash,
    programId,
  };
  assertValidKeyringContext(context);
  return { context, envelopeVersion: version };
}

/**
 * The HKDF `info` string for a PRF-derived unwrap key. Uses the SAME injective
 * encoder but its own domain tag, and deliberately OMITS `schemaVersion` and the
 * envelope version: those change with format revisions, and a format revision must
 * not change the key a passkey derives (that would brick unlock, not just re-encode).
 */
export function keyringPrfInfo(context: KeyringContext): Uint8Array {
  assertValidKeyringContext(context);
  return encodeLengthPrefixedFields(KEYRING_PRF_INFO_DOMAIN, 1, [
    context.account,
    TEXT_ENCODER.encode(context.origin),
    TEXT_ENCODER.encode(context.keyKind),
    context.genesisHash,
    context.programId,
  ]);
}
