//! Persistent C2 keyring record.
//!
//! `chrome.storage` stores JSON-serializable property values and does not preserve a
//! `Uint8Array` as bytes. Consequently the storage representation here is ONE
//! canonical base64url string containing ONE strict binary record. Salts, KDF cost
//! parameters, PRF enrollment metadata, and the encrypted bundle cannot be written
//! as independently tearable properties by a conforming caller.
//!
//! This is a format and crypto-orchestration boundary, not a claim that Chrome has
//! documented transactional or durable-write semantics. The still-unbuilt extension
//! adapter must store the returned string under one `storage.local` key, restrict
//! `storage.local` to `TRUSTED_CONTEXTS`, serialize competing writers, and verify
//! errors/readback. It must never put this record in `storage.sync` or place plaintext
//! unlock material in persistent storage.
//!
//! ## Wire format (v1)
//!
//! ```text
//! record := u16be(version=1)
//!           || u8(flags)                         // bit 0: PRF metadata/wrap present
//!           || u32be(argonMemoryKiB)
//!           || u32be(argonTimeCost)
//!           || u32be(argonParallelism)
//!           || passwordSalt[16]
//!           || if flags&1: prfInput[32] || prfHkdfSalt[16]
//!           || LP32(bundle)
//! ```
//!
//! The bytes before `LP32(bundle)` are also supplied to `bundle.ts` as an external
//! authenticated binding. Therefore a PRF unlock rejects tampered password salt/cost
//! metadata, and password unlock rejects tampered PRF metadata. An unused fallback
//! cannot be silently poisoned.
//!
//! PRF metadata is optional because WebAuthn PRF support is not universal and the
//! real-device compatibility matrix remains UNVERIFIED. Password unlock is mandatory.
//! `prf.input` is the value the extension supplies as WebAuthn `prf.eval.first`;
//! `prf.hkdfSalt` is independently random and feeds the HKDF extraction step.

import type { KeyringContext } from "./aad.js";
import { randomKeyringBytes } from "./aead.js";
import {
  KEYRING_BUNDLE_VERSION_1,
  MAX_KEYRING_BUNDLE_BYTES,
  decodeKeyringBundle,
  encodeKeyringBundle,
  openKeyringBundle,
  sealKeyringBundle,
  type KeyringBundle,
} from "./bundle.js";
import {
  assertValidArgon2idParams,
  deriveUnwrapKeyFromPasswordBytes,
  deriveUnwrapKeyFromPrfForContext,
  zeroizeUnwrapKey,
  type Argon2idParams,
  type KeyringUnwrapKey,
} from "./derive.js";
import {
  assertUnlockCheck,
  snapshotUnlockCheck,
  type UnlockCheck,
} from "./deadlines.js";
import { KeyringAuthError, KeyringFormatError } from "./errors.js";

export const KEYRING_RECORD_VERSION_1 = 1;
export const SUPPORTED_KEYRING_RECORD_VERSIONS: readonly number[] = [KEYRING_RECORD_VERSION_1];
export const KEYRING_PASSWORD_SALT_BYTES = 16;
export const KEYRING_PRF_INPUT_BYTES = 32;
export const KEYRING_PRF_HKDF_SALT_BYTES = 16;
export const KEYRING_RECORD_STORAGE_PREFIX = "warden-keyring:";

const KEYRING_RECORD_FLAG_PRF = 1;
const KEYRING_RECORD_KNOWN_FLAGS = KEYRING_RECORD_FLAG_PRF;
const RECORD_BASE_METADATA_BYTES = 2 + 1 + 3 * 4 + KEYRING_PASSWORD_SALT_BYTES;
const RECORD_PRF_METADATA_BYTES = KEYRING_PRF_INPUT_BYTES + KEYRING_PRF_HKDF_SALT_BYTES;
const RECORD_MAX_METADATA_BYTES = RECORD_BASE_METADATA_BYTES + RECORD_PRF_METADATA_BYTES;
const LENGTH_BYTES = 4;
/** Bound checked before allocating or decoding an attacker-controlled storage value. */
export const MAX_KEYRING_RECORD_BYTES = RECORD_MAX_METADATA_BYTES + LENGTH_BYTES + MAX_KEYRING_BUNDLE_BYTES;
export const MAX_KEYRING_RECORD_STORAGE_CHARS = Math.ceil((MAX_KEYRING_RECORD_BYTES * 4) / 3);

export interface KeyringRecordPrfMetadata {
  /** Random WebAuthn `prf.eval.first` input. Public, exact 32 bytes in v1. */
  readonly input: Uint8Array;
  /** Independent public HKDF salt. Exact 16 bytes in v1. */
  readonly hkdfSalt: Uint8Array;
}

export interface KeyringRecordMetadata {
  readonly version: number;
  readonly argon2id: {
    readonly params: Argon2idParams;
    readonly salt: Uint8Array;
  };
  /** Null when PRF has not been enrolled for this record. */
  readonly prf: KeyringRecordPrfMetadata | null;
}

export interface KeyringRecord {
  readonly metadata: KeyringRecordMetadata;
  readonly bundle: KeyringBundle;
}

function assertRecordVersion(version: number): void {
  if (!SUPPORTED_KEYRING_RECORD_VERSIONS.includes(version)) {
    throw new KeyringFormatError(`unknown record version ${version}`);
  }
}

function assertExactBytes(value: unknown, length: number, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) throw new KeyringFormatError(`${name} must be a Uint8Array`);
  if (value.length !== length) {
    throw new KeyringFormatError(`${name} must be exactly ${length} bytes, got ${value.length}`);
  }
}

function canonicalMetadata(value: unknown): KeyringRecordMetadata {
  if (typeof value !== "object" || value === null || value instanceof Uint8Array) {
    throw new KeyringFormatError("record metadata must be an object");
  }
  const metadata = value as Partial<KeyringRecordMetadata>;
  if (typeof metadata.version !== "number") throw new KeyringFormatError("record version must be a number");
  assertRecordVersion(metadata.version);
  if (typeof metadata.argon2id !== "object" || metadata.argon2id === null) {
    throw new KeyringFormatError("argon2id metadata must be an object");
  }
  const params = metadata.argon2id.params;
  if (typeof params !== "object" || params === null) {
    throw new KeyringFormatError("argon2id params must be an object");
  }
  assertValidArgon2idParams(params);
  assertExactBytes(metadata.argon2id.salt, KEYRING_PASSWORD_SALT_BYTES, "password salt");

  let prf: KeyringRecordPrfMetadata | null;
  if (metadata.prf === null) {
    prf = null;
  } else {
    if (typeof metadata.prf !== "object" || metadata.prf === undefined) {
      throw new KeyringFormatError("PRF metadata must be an object or null");
    }
    assertExactBytes(metadata.prf.input, KEYRING_PRF_INPUT_BYTES, "PRF input");
    assertExactBytes(metadata.prf.hkdfSalt, KEYRING_PRF_HKDF_SALT_BYTES, "PRF HKDF salt");
    prf = { input: metadata.prf.input.slice(), hkdfSalt: metadata.prf.hkdfSalt.slice() };
  }

  return {
    version: metadata.version,
    argon2id: {
      params: {
        memoryKiB: params.memoryKiB,
        timeCost: params.timeCost,
        parallelism: params.parallelism,
      },
      salt: metadata.argon2id.salt.slice(),
    },
    prf,
  };
}

function writeU32(out: Uint8Array, offset: number, value: number): void {
  out[offset] = (value >>> 24) & 0xff;
  out[offset + 1] = (value >>> 16) & 0xff;
  out[offset + 2] = (value >>> 8) & 0xff;
  out[offset + 3] = value & 0xff;
}

function metadataBytes(value: KeyringRecordMetadata): Uint8Array {
  const metadata = canonicalMetadata(value);
  const hasPrf = metadata.prf !== null;
  const out = new Uint8Array(RECORD_BASE_METADATA_BYTES + (hasPrf ? RECORD_PRF_METADATA_BYTES : 0));
  let offset = 0;
  out[offset++] = (metadata.version >>> 8) & 0xff;
  out[offset++] = metadata.version & 0xff;
  out[offset++] = hasPrf ? KEYRING_RECORD_FLAG_PRF : 0;
  writeU32(out, offset, metadata.argon2id.params.memoryKiB);
  offset += 4;
  writeU32(out, offset, metadata.argon2id.params.timeCost);
  offset += 4;
  writeU32(out, offset, metadata.argon2id.params.parallelism);
  offset += 4;
  out.set(metadata.argon2id.salt, offset);
  offset += KEYRING_PASSWORD_SALT_BYTES;
  if (metadata.prf !== null) {
    out.set(metadata.prf.input, offset);
    offset += KEYRING_PRF_INPUT_BYTES;
    out.set(metadata.prf.hkdfSalt, offset);
  }
  return out;
}

/** Canonical bytes authenticated by every bundle component. */
export function encodeKeyringRecordMetadata(metadata: KeyringRecordMetadata): Uint8Array {
  return metadataBytes(metadata);
}

function assertPrfShape(metadata: KeyringRecordMetadata, bundle: KeyringBundle): void {
  if ((metadata.prf === null) !== (bundle.prfWrap === null)) {
    throw new KeyringFormatError("PRF metadata and wrap must either both be present or both be absent");
  }
}

/** Serialize the exact one-record binary representation. */
export function encodeKeyringRecord(record: KeyringRecord): Uint8Array {
  if (typeof record !== "object" || record === null || record instanceof Uint8Array) {
    throw new KeyringFormatError("record must be an object");
  }
  const metadata = canonicalMetadata(record.metadata);
  const bundleBytes = encodeKeyringBundle(record.bundle);
  const bundle = decodeKeyringBundle(bundleBytes);
  assertPrfShape(metadata, bundle);
  const header = metadataBytes(metadata);
  const out = new Uint8Array(header.length + LENGTH_BYTES + bundleBytes.length);
  out.set(header, 0);
  writeU32(out, header.length, bundleBytes.length);
  out.set(bundleBytes, header.length + LENGTH_BYTES);
  if (out.length > MAX_KEYRING_RECORD_BYTES) {
    throw new KeyringFormatError(`record of ${out.length} bytes exceeds the cap`);
  }
  return out;
}

function readU32(bytes: Uint8Array, offset: number): number {
  return (
    bytes[offset]! * 0x100_0000 +
    bytes[offset + 1]! * 0x1_0000 +
    bytes[offset + 2]! * 0x100 +
    bytes[offset + 3]!
  );
}

/** Strict parser: unknown version/flags and cost ceilings are checked before bundle lengths. */
export function decodeKeyringRecord(bytes: Uint8Array): KeyringRecord {
  if (!(bytes instanceof Uint8Array)) throw new KeyringFormatError("record bytes must be a Uint8Array");
  if (bytes.length < 2) throw new KeyringFormatError("record truncated: no version");
  const version = (bytes[0]! << 8) | bytes[1]!;
  assertRecordVersion(version);
  if (bytes.length > MAX_KEYRING_RECORD_BYTES) {
    throw new KeyringFormatError(`record of ${bytes.length} bytes exceeds the cap`);
  }
  if (bytes.length < 3) throw new KeyringFormatError("record truncated: no flags");
  const flags = bytes[2]!;
  if ((flags & ~KEYRING_RECORD_KNOWN_FLAGS) !== 0) {
    throw new KeyringFormatError(`unknown record flags 0x${flags.toString(16)}`);
  }
  const hasPrf = (flags & KEYRING_RECORD_FLAG_PRF) !== 0;
  const metadataLength = RECORD_BASE_METADATA_BYTES + (hasPrf ? RECORD_PRF_METADATA_BYTES : 0);
  if (bytes.length < metadataLength + LENGTH_BYTES) {
    throw new KeyringFormatError("record truncated in KDF metadata or bundle length");
  }
  const params: Argon2idParams = {
    memoryKiB: readU32(bytes, 3),
    timeCost: readU32(bytes, 7),
    parallelism: readU32(bytes, 11),
  };
  // Attacker-controlled resource costs are rejected before derivation/allocation.
  assertValidArgon2idParams(params);
  let offset = 15;
  const salt = bytes.slice(offset, offset + KEYRING_PASSWORD_SALT_BYTES);
  offset += KEYRING_PASSWORD_SALT_BYTES;
  let prf: KeyringRecordPrfMetadata | null = null;
  if (hasPrf) {
    const input = bytes.slice(offset, offset + KEYRING_PRF_INPUT_BYTES);
    offset += KEYRING_PRF_INPUT_BYTES;
    const hkdfSalt = bytes.slice(offset, offset + KEYRING_PRF_HKDF_SALT_BYTES);
    offset += KEYRING_PRF_HKDF_SALT_BYTES;
    prf = { input, hkdfSalt };
  }
  const bundleLength = readU32(bytes, offset);
  offset += LENGTH_BYTES;
  if (bundleLength === 0) throw new KeyringFormatError("record bundle is empty");
  if (bundleLength > MAX_KEYRING_BUNDLE_BYTES) {
    throw new KeyringFormatError(`record bundle length ${bundleLength} exceeds the cap`);
  }
  if (offset + bundleLength > bytes.length) throw new KeyringFormatError("record bundle is truncated");
  if (offset + bundleLength < bytes.length) throw new KeyringFormatError("trailing bytes after record bundle");
  const bundle = decodeKeyringBundle(bytes.slice(offset, offset + bundleLength));
  if (bundle.version !== KEYRING_BUNDLE_VERSION_1) {
    throw new KeyringFormatError(`record v${version} requires bundle v${KEYRING_BUNDLE_VERSION_1}`);
  }
  const metadata: KeyringRecordMetadata = { version, argon2id: { params, salt }, prf };
  assertPrfShape(metadata, bundle);
  return { metadata, bundle };
}

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function encodeBase64Url(bytes: Uint8Array): string {
  let output = "";
  let offset = 0;
  for (; offset + 3 <= bytes.length; offset += 3) {
    const value = bytes[offset]! * 0x1_0000 + bytes[offset + 1]! * 0x100 + bytes[offset + 2]!;
    output += B64URL[(value >>> 18) & 0x3f];
    output += B64URL[(value >>> 12) & 0x3f];
    output += B64URL[(value >>> 6) & 0x3f];
    output += B64URL[value & 0x3f];
  }
  const remaining = bytes.length - offset;
  if (remaining === 1) {
    const value = bytes[offset]! << 16;
    output += B64URL[(value >>> 18) & 0x3f];
    output += B64URL[(value >>> 12) & 0x3f];
  } else if (remaining === 2) {
    const value = (bytes[offset]! << 16) | (bytes[offset + 1]! << 8);
    output += B64URL[(value >>> 18) & 0x3f];
    output += B64URL[(value >>> 12) & 0x3f];
    output += B64URL[(value >>> 6) & 0x3f];
  }
  return output;
}

function decodeBase64Url(value: string): Uint8Array {
  if (value.length === 0) throw new KeyringFormatError("storage payload must not be empty");
  if (value.length > MAX_KEYRING_RECORD_STORAGE_CHARS) {
    throw new KeyringFormatError(`storage payload of ${value.length} characters exceeds the cap`);
  }
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new KeyringFormatError("storage payload contains padding or a non-base64url alphabet character");
  }
  const remainder = value.length % 4;
  if (remainder === 1) throw new KeyringFormatError("storage payload has an impossible base64url length");
  const code = (index: number): number => B64URL.indexOf(value[index]!);
  if (remainder === 2 && (code(value.length - 1) & 0x0f) !== 0) {
    throw new KeyringFormatError("storage payload has non-canonical base64url tail bits");
  }
  if (remainder === 3 && (code(value.length - 1) & 0x03) !== 0) {
    throw new KeyringFormatError("storage payload has non-canonical base64url tail bits");
  }

  const output = new Uint8Array(Math.floor((value.length * 6) / 8));
  let inputOffset = 0;
  let outputOffset = 0;
  for (; inputOffset + 4 <= value.length; inputOffset += 4) {
    const bits =
      code(inputOffset) * 0x4_0000 +
      code(inputOffset + 1) * 0x1_000 +
      code(inputOffset + 2) * 0x40 +
      code(inputOffset + 3);
    output[outputOffset++] = (bits >>> 16) & 0xff;
    output[outputOffset++] = (bits >>> 8) & 0xff;
    output[outputOffset++] = bits & 0xff;
  }
  if (remainder === 2) {
    const bits = code(inputOffset) * 0x40 + code(inputOffset + 1);
    output[outputOffset] = (bits >>> 4) & 0xff;
  } else if (remainder === 3) {
    const bits = code(inputOffset) * 0x1_000 + code(inputOffset + 1) * 0x40 + code(inputOffset + 2);
    output[outputOffset++] = (bits >>> 10) & 0xff;
    output[outputOffset] = (bits >>> 2) & 0xff;
  }
  return output;
}

/** JSON-safe, single-property Chrome storage value. */
export function encodeKeyringRecordStorageValue(record: KeyringRecord): string {
  return KEYRING_RECORD_STORAGE_PREFIX + encodeBase64Url(encodeKeyringRecord(record));
}

/** Decode only the canonical string form; objects/typed arrays fail closed. */
export function decodeKeyringRecordStorageValue(value: unknown): KeyringRecord {
  if (typeof value !== "string") throw new KeyringFormatError("stored keyring record must be a string");
  if (!value.startsWith(KEYRING_RECORD_STORAGE_PREFIX)) {
    throw new KeyringFormatError("stored keyring record has the wrong prefix");
  }
  if (value.length > KEYRING_RECORD_STORAGE_PREFIX.length + MAX_KEYRING_RECORD_STORAGE_CHARS) {
    throw new KeyringFormatError(`storage payload of ${value.length - KEYRING_RECORD_STORAGE_PREFIX.length} characters exceeds the cap`);
  }
  return decodeKeyringRecord(decodeBase64Url(value.slice(KEYRING_RECORD_STORAGE_PREFIX.length)));
}

export interface PrepareKeyringRecordMetadataParams {
  readonly argon2idParams: Argon2idParams;
  readonly enablePrf: boolean;
}

/**
 * Generate the public setup values before the WebAuthn assertion. When PRF is
 * enabled, pass the returned `prf.input` as `prf.eval.first`, then provide the
 * resulting 32-byte output to {@link sealKeyringRecord}.
 */
export function prepareKeyringRecordMetadata(
  params: PrepareKeyringRecordMetadataParams,
): KeyringRecordMetadata {
  if (typeof params !== "object" || params === null) {
    throw new KeyringFormatError("record setup params must be an object");
  }
  assertValidArgon2idParams(params.argon2idParams);
  if (typeof params.enablePrf !== "boolean") throw new KeyringFormatError("enablePrf must be a boolean");
  return {
    version: KEYRING_RECORD_VERSION_1,
    argon2id: {
      params: { ...params.argon2idParams },
      salt: randomKeyringBytes(KEYRING_PASSWORD_SALT_BYTES, "an Argon2id salt"),
    },
    prf: params.enablePrf
      ? {
          input: randomKeyringBytes(KEYRING_PRF_INPUT_BYTES, "a WebAuthn PRF input"),
          hkdfSalt: randomKeyringBytes(KEYRING_PRF_HKDF_SALT_BYTES, "a PRF HKDF salt"),
        }
      : null,
  };
}

export interface SealKeyringRecordParams {
  readonly metadata: KeyringRecordMetadata;
  /** Caller-owned secret buffer; overwritten in `finally` on success or failure. */
  readonly plaintext: Uint8Array;
  /** Caller-owned password buffer; overwritten in `finally` on success or failure. */
  readonly passwordBytes: Uint8Array;
  /** Required iff metadata enrolled PRF; caller-owned and overwritten in `finally`. */
  readonly prfOutput?: Uint8Array;
  readonly context: KeyringContext;
  readonly unlock?: UnlockCheck;
}

/** Derive enrolled KEKs, seal one bundle, and return a canonical persistent record. */
export async function sealKeyringRecord(params: SealKeyringRecordParams): Promise<KeyringRecord> {
  const passwordBytes = params.passwordBytes;
  const prfOutput = params.prfOutput;
  const plaintext = params.plaintext;
  let passwordKey: KeyringUnwrapKey | undefined;
  let prfKey: KeyringUnwrapKey | undefined;
  try {
    if (!(passwordBytes instanceof Uint8Array)) throw new KeyringFormatError("passwordBytes must be a Uint8Array");
    if (!(plaintext instanceof Uint8Array)) throw new KeyringFormatError("plaintext must be a Uint8Array");
    if (prfOutput !== undefined && !(prfOutput instanceof Uint8Array)) {
      throw new KeyringFormatError("prfOutput must be a Uint8Array");
    }
    const unlock = snapshotUnlockCheck(params.unlock);
    assertUnlockCheck(unlock, "seal record");
    const metadata = canonicalMetadata(params.metadata);
    if (metadata.prf === null && prfOutput !== undefined) {
      throw new KeyringFormatError("PRF output supplied for a password-only record");
    }
    if (metadata.prf !== null && prfOutput === undefined) {
      throw new KeyringFormatError("PRF output is required by enrolled PRF metadata");
    }
    const recordBinding = metadataBytes(metadata);
    passwordKey = deriveUnwrapKeyFromPasswordBytes(
      passwordBytes,
      metadata.argon2id.salt,
      metadata.argon2id.params,
    );
    assertUnlockCheck(unlock, "seal record");
    if (metadata.prf !== null) {
      prfKey = deriveUnwrapKeyFromPrfForContext(prfOutput!, metadata.prf.hkdfSalt, params.context);
      assertUnlockCheck(unlock, "seal record");
    }
    const bundle = await sealKeyringBundle({
      plaintext,
      passwordKey,
      prfKey,
      context: params.context,
      recordBinding,
      unlock,
    });
    assertUnlockCheck(unlock, "seal record");
    assertPrfShape(metadata, bundle);
    return { metadata, bundle };
  } finally {
    if (passwordBytes instanceof Uint8Array) passwordBytes.fill(0);
    if (prfOutput instanceof Uint8Array) prfOutput.fill(0);
    if (plaintext instanceof Uint8Array) plaintext.fill(0);
    if (passwordKey !== undefined) zeroizeUnwrapKey(passwordKey);
    if (prfKey !== undefined) zeroizeUnwrapKey(prfKey);
  }
}

export type KeyringRecordInput = KeyringRecord | Uint8Array | string;

function canonicalRecord(input: KeyringRecordInput): KeyringRecord {
  if (typeof input === "string") return decodeKeyringRecordStorageValue(input);
  if (input instanceof Uint8Array) return decodeKeyringRecord(input);
  return decodeKeyringRecord(encodeKeyringRecord(input));
}

export interface OpenKeyringRecordWithPasswordParams {
  readonly record: KeyringRecordInput;
  /** Caller-owned; overwritten on every exit path. */
  readonly passwordBytes: Uint8Array;
  readonly context: KeyringContext;
  readonly unlock?: UnlockCheck;
}

/** Cryptographic password re-authentication: derive, unwrap, decrypt; never compare. */
export async function openKeyringRecordWithPasswordBytes(
  params: OpenKeyringRecordWithPasswordParams,
): Promise<Uint8Array> {
  const passwordBytes = params.passwordBytes;
  let passwordKey: KeyringUnwrapKey | undefined;
  try {
    if (!(passwordBytes instanceof Uint8Array)) throw new KeyringFormatError("passwordBytes must be a Uint8Array");
    const unlock = snapshotUnlockCheck(params.unlock);
    assertUnlockCheck(unlock, "open record with password");
    const record = canonicalRecord(params.record);
    const recordBinding = metadataBytes(record.metadata);
    passwordKey = deriveUnwrapKeyFromPasswordBytes(
      passwordBytes,
      record.metadata.argon2id.salt,
      record.metadata.argon2id.params,
    );
    assertUnlockCheck(unlock, "open record with password");
    const plaintext = await openKeyringBundle({
      bundle: record.bundle,
      unwrapKey: passwordKey,
      context: params.context,
      recordBinding,
      unlock,
    });
    try {
      assertUnlockCheck(unlock, "open record with password");
      return plaintext;
    } catch (error) {
      plaintext.fill(0);
      throw error;
    }
  } finally {
    if (passwordBytes instanceof Uint8Array) passwordBytes.fill(0);
    if (passwordKey !== undefined) zeroizeUnwrapKey(passwordKey);
  }
}

export interface OpenKeyringRecordWithPrfParams {
  readonly record: KeyringRecordInput;
  /** Exact 32-byte WebAuthn result; caller-owned and overwritten on every exit. */
  readonly prfOutput: Uint8Array;
  readonly context: KeyringContext;
  readonly unlock?: UnlockCheck;
}

/** Open through an enrolled PRF path; absence is a uniform authentication failure. */
export async function openKeyringRecordWithPrfBytes(
  params: OpenKeyringRecordWithPrfParams,
): Promise<Uint8Array> {
  const prfOutput = params.prfOutput;
  let prfKey: KeyringUnwrapKey | undefined;
  try {
    if (!(prfOutput instanceof Uint8Array)) throw new KeyringFormatError("prfOutput must be a Uint8Array");
    const unlock = snapshotUnlockCheck(params.unlock);
    assertUnlockCheck(unlock, "open record with PRF");
    const record = canonicalRecord(params.record);
    if (record.metadata.prf === null) throw new KeyringAuthError();
    const recordBinding = metadataBytes(record.metadata);
    prfKey = deriveUnwrapKeyFromPrfForContext(
      prfOutput,
      record.metadata.prf.hkdfSalt,
      params.context,
    );
    assertUnlockCheck(unlock, "open record with PRF");
    const plaintext = await openKeyringBundle({
      bundle: record.bundle,
      unwrapKey: prfKey,
      context: params.context,
      recordBinding,
      unlock,
    });
    try {
      assertUnlockCheck(unlock, "open record with PRF");
      return plaintext;
    } catch (error) {
      plaintext.fill(0);
      throw error;
    }
  } finally {
    if (prfOutput instanceof Uint8Array) prfOutput.fill(0);
    if (prfKey !== undefined) zeroizeUnwrapKey(prfKey);
  }
}
