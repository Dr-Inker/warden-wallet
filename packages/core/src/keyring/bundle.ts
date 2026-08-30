//! Versioned KEK/DEK keyring bundle for C2.
//!
//! One fresh random 256-bit data-encryption key (DEK) encrypts the keyring payload
//! exactly once. The DEK is then encrypted independently by the password-derived
//! key-encryption key (KEK) and, when the credential supports it, the
//! WebAuthn-PRF-derived KEK. PRF is therefore an optional optimization, not a
//! prerequisite or a second vault: password unlock always recovers the DEK, while
//! an enrolled PRF path recovers that same DEK and opens the same ciphertext.
//!
//! The bundle is authenticated as one unit. Each DEK wrap binds its position/KDF,
//! bundle id, bundle version, component version, and full Warden context. The
//! payload additionally binds the exact encoded bytes of every wrap slot (the PRF
//! slot is an authenticated empty value when PRF is absent). Tampering or splicing
//! even an unused fallback consequently makes every enrolled unlock path fail closed
//! instead of leaving a poisoned fallback dormant until it is needed. A caller may
//! also bind canonical outer-record metadata; `record.ts` always does.
//!
//! ## Wire format (v1)
//!
//! ```text
//! bundle := u16be(version) || u8(bundleIdLen) || bundleId
//!           || LP32(payloadEnvelope)
//!           || LP32(passwordDekWrap)
//!           || LP32(prfDekWrap)        // zero length when PRF is not enrolled
//! LP32(x) := u32be(x.length) || x
//! ```
//!
//! Each non-empty component is a strict v1 `KeyringEnvelope`; only the PRF slot may
//! be empty. Unknown versions are rejected before component lengths are read, every
//! component length is bounded, and trailing bytes are refused.
//!
//! The raw DEK necessarily exists briefly as bytes: WebCrypto `wrapKey()` first
//! exports the wrapped key and therefore cannot wrap a non-extractable key. This
//! implementation keeps the byte lifetime inside one function and overwrites the
//! buffer in `finally`. As elsewhere in this package, JavaScript zeroing is best
//! effort, not a claim that VM or WebCrypto-internal copies are erased.

import {
  KEYRING_AES_KEY_BYTES,
  KEYRING_NONCE_BYTES,
  KEYRING_TAG_BYTES,
  MAX_KEYRING_CIPHERTEXT_BYTES,
  assertAes256KeyBytes,
  openAead,
  randomKeyringBytes,
  sealAead,
} from "./aead.js";
import {
  assertValidKeyringContext,
  encodeKeyringAad,
  encodeLengthPrefixedFields,
  MAX_AAD_FIELD_BYTES,
  type KeyringContext,
} from "./aad.js";
import { assertUnlocked } from "./deadlines.js";
import type { KeyringKdfLabel, KeyringUnwrapKey } from "./derive.js";
import {
  KEYRING_ENVELOPE_VERSION_1,
  decodeKeyringEnvelope,
  encodeKeyringEnvelope,
  type KeyringEnvelope,
  type UnlockCheck,
} from "./envelope.js";
import { KeyringAuthError, KeyringFormatError } from "./errors.js";

/** Current persistent bundle format. */
export const KEYRING_BUNDLE_VERSION_1 = 1;
export const SUPPORTED_KEYRING_BUNDLE_VERSIONS: readonly number[] = [KEYRING_BUNDLE_VERSION_1];
/** Random per-bundle identifier. 128 bits prevents cross-record aliasing. */
export const KEYRING_BUNDLE_ID_BYTES = 16;
/** One AES-256 data-encryption key. */
export const KEYRING_DEK_BYTES = KEYRING_AES_KEY_BYTES;
/** A wrapped DEK is 32 ciphertext bytes plus one 16-byte GCM tag. */
export const KEYRING_WRAPPED_DEK_BYTES = KEYRING_DEK_BYTES + KEYRING_TAG_BYTES;

/** Domain tags are public format constants and must never be reused for another role. */
export const KEYRING_BUNDLE_WRAP_AAD_DOMAIN = "warden/keyring-bundle/wrap/aad";
export const KEYRING_BUNDLE_PAYLOAD_AAD_DOMAIN = "warden/keyring-bundle/payload/aad";

const TEXT_ENCODER = /* @__PURE__ */ new TextEncoder();
const BUNDLE_COMPONENT_COUNT = 3;
const BUNDLE_FIXED_HEADER_BYTES = 2 + 1 + KEYRING_BUNDLE_ID_BYTES;
const ENVELOPE_FIXED_HEADER_BYTES = 2 + 1 + KEYRING_NONCE_BYTES + 4;
const MAX_ENCODED_ENVELOPE_BYTES = ENVELOPE_FIXED_HEADER_BYTES + MAX_KEYRING_CIPHERTEXT_BYTES;
/** Parser allocation/length cap, derived from the three bounded envelopes. */
export const MAX_KEYRING_BUNDLE_BYTES =
  BUNDLE_FIXED_HEADER_BYTES + BUNDLE_COMPONENT_COUNT * (4 + MAX_ENCODED_ENVELOPE_BYTES);

export interface KeyringBundle {
  readonly version: number;
  readonly bundleId: Uint8Array;
  readonly payload: KeyringEnvelope;
  readonly passwordWrap: KeyringEnvelope;
  /** Null when this credential/device has no usable WebAuthn PRF path. */
  readonly prfWrap: KeyringEnvelope | null;
}

function u16be(value: number): Uint8Array {
  return Uint8Array.of((value >>> 8) & 0xff, value & 0xff);
}

function writeU32be(out: Uint8Array, offset: number, value: number): void {
  out[offset] = (value >>> 24) & 0xff;
  out[offset + 1] = (value >>> 16) & 0xff;
  out[offset + 2] = (value >>> 8) & 0xff;
  out[offset + 3] = value & 0xff;
}

function assertBundleVersion(version: number): void {
  if (!SUPPORTED_KEYRING_BUNDLE_VERSIONS.includes(version)) {
    throw new KeyringFormatError(`unknown bundle version ${version}`);
  }
}

function assertBundleId(bundleId: Uint8Array): void {
  if (!(bundleId instanceof Uint8Array)) throw new KeyringFormatError("bundle id must be a Uint8Array");
  if (bundleId.length !== KEYRING_BUNDLE_ID_BYTES) {
    throw new KeyringFormatError(
      `bundle id must be exactly ${KEYRING_BUNDLE_ID_BYTES} bytes, got ${bundleId.length}`,
    );
  }
}

function assertComponentEnvelope(value: unknown, role: "payload" | "password wrap" | "PRF wrap"): asserts value is KeyringEnvelope {
  if (typeof value !== "object" || value === null) {
    throw new KeyringFormatError(`${role} envelope must be an object`);
  }
  const envelope = value as Partial<KeyringEnvelope>;
  if (envelope.version !== KEYRING_ENVELOPE_VERSION_1) {
    throw new KeyringFormatError(`${role} requires envelope version ${KEYRING_ENVELOPE_VERSION_1}`);
  }
  if (!(envelope.nonce instanceof Uint8Array)) {
    throw new KeyringFormatError(`${role} nonce must be a Uint8Array`);
  }
  if (!(envelope.ciphertext instanceof Uint8Array)) {
    throw new KeyringFormatError(`${role} ciphertext must be a Uint8Array`);
  }
  // Exercise the canonical envelope validator as well as the bundle-specific rules.
  encodeKeyringEnvelope(envelope as KeyringEnvelope);
  if (role === "payload" && envelope.ciphertext.length <= KEYRING_TAG_BYTES) {
    throw new KeyringFormatError("payload ciphertext must protect a non-empty plaintext");
  }
  if (role !== "payload" && envelope.ciphertext.length !== KEYRING_WRAPPED_DEK_BYTES) {
    throw new KeyringFormatError(
      `${role} ciphertext must be exactly ${KEYRING_WRAPPED_DEK_BYTES} bytes, got ${envelope.ciphertext.length}`,
    );
  }
}

function assertKeyringBundle(value: unknown): asserts value is KeyringBundle {
  if (typeof value !== "object" || value === null || value instanceof Uint8Array) {
    throw new KeyringFormatError("bundle must be an object or encoded Uint8Array");
  }
  const bundle = value as Partial<KeyringBundle>;
  if (typeof bundle.version !== "number") throw new KeyringFormatError("bundle version must be a number");
  assertBundleVersion(bundle.version);
  assertBundleId(bundle.bundleId as Uint8Array);
  assertComponentEnvelope(bundle.payload, "payload");
  assertComponentEnvelope(bundle.passwordWrap, "password wrap");
  if (bundle.prfWrap !== null) assertComponentEnvelope(bundle.prfWrap, "PRF wrap");
}

function copyRecordBinding(binding: Uint8Array | undefined): Uint8Array | undefined {
  if (binding === undefined) return undefined;
  if (!(binding instanceof Uint8Array)) throw new KeyringFormatError("record binding must be a Uint8Array");
  if (binding.length === 0) throw new KeyringFormatError("record binding must not be empty");
  if (binding.length > MAX_AAD_FIELD_BYTES) {
    throw new KeyringFormatError(
      `record binding of ${binding.length} bytes exceeds the ${MAX_AAD_FIELD_BYTES}-byte cap`,
    );
  }
  return binding.slice();
}

function assertUnwrapKey(key: KeyringUnwrapKey, expected?: KeyringKdfLabel): void {
  if (typeof key !== "object" || key === null) throw new KeyringFormatError("unwrap key must be an object");
  const known = key.kdf === "argon2id-password" || key.kdf === "webauthn-prf-hkdf";
  if (!known) throw new KeyringFormatError(`unknown unwrap-key KDF ${JSON.stringify(key.kdf)}`);
  if (expected !== undefined && key.kdf !== expected) {
    throw new KeyringFormatError(`expected ${expected} key, got ${key.kdf}`);
  }
  assertAes256KeyBytes(key.bytes, "unwrap key");
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

function wrapAad(
  context: KeyringContext,
  bundleVersion: number,
  bundleId: Uint8Array,
  kdf: KeyringKdfLabel,
  envelopeVersion: number,
  recordBinding?: Uint8Array,
): Uint8Array {
  const fields = [
    encodeKeyringAad(context, bundleVersion),
    bundleId,
    TEXT_ENCODER.encode(kdf),
    u16be(envelopeVersion),
  ];
  if (recordBinding !== undefined) fields.push(recordBinding);
  return encodeLengthPrefixedFields(KEYRING_BUNDLE_WRAP_AAD_DOMAIN, bundleVersion, fields);
}

function payloadAad(
  context: KeyringContext,
  bundleVersion: number,
  bundleId: Uint8Array,
  payloadVersion: number,
  passwordWrap: KeyringEnvelope,
  prfWrap: KeyringEnvelope | null,
  recordBinding?: Uint8Array,
): Uint8Array {
  const fields = [
    encodeKeyringAad(context, bundleVersion),
    bundleId,
    u16be(payloadVersion),
    encodeKeyringEnvelope(passwordWrap),
    prfWrap === null ? new Uint8Array(0) : encodeKeyringEnvelope(prfWrap),
  ];
  if (recordBinding !== undefined) fields.push(recordBinding);
  return encodeLengthPrefixedFields(KEYRING_BUNDLE_PAYLOAD_AAD_DOMAIN, bundleVersion, fields);
}

/** Serialize the exact persistent representation. */
export function encodeKeyringBundle(bundle: KeyringBundle): Uint8Array {
  assertKeyringBundle(bundle);
  const components = [
    encodeKeyringEnvelope(bundle.payload),
    encodeKeyringEnvelope(bundle.passwordWrap),
    bundle.prfWrap === null ? new Uint8Array(0) : encodeKeyringEnvelope(bundle.prfWrap),
  ];
  const length = BUNDLE_FIXED_HEADER_BYTES + components.reduce((total, bytes) => total + 4 + bytes.length, 0);
  if (length > MAX_KEYRING_BUNDLE_BYTES) throw new KeyringFormatError(`bundle of ${length} bytes exceeds the cap`);

  const out = new Uint8Array(length);
  let offset = 0;
  out[offset++] = (bundle.version >>> 8) & 0xff;
  out[offset++] = bundle.version & 0xff;
  out[offset++] = bundle.bundleId.length;
  out.set(bundle.bundleId, offset);
  offset += bundle.bundleId.length;
  for (const component of components) {
    writeU32be(out, offset, component.length);
    offset += 4;
    out.set(component, offset);
    offset += component.length;
  }
  return out;
}

/** Strictly parse the persistent bundle representation. */
export function decodeKeyringBundle(bytes: Uint8Array): KeyringBundle {
  if (!(bytes instanceof Uint8Array)) throw new KeyringFormatError("bundle bytes must be a Uint8Array");
  if (bytes.length < 2) throw new KeyringFormatError("bundle truncated: no version");
  const version = (bytes[0]! << 8) | bytes[1]!;
  // Version is deliberately checked before trusting the id or component lengths.
  assertBundleVersion(version);
  if (bytes.length > MAX_KEYRING_BUNDLE_BYTES) {
    throw new KeyringFormatError(`bundle of ${bytes.length} bytes exceeds the cap`);
  }
  if (bytes.length < 3) throw new KeyringFormatError("bundle truncated: no bundle id length");
  const idLength = bytes[2]!;
  if (idLength !== KEYRING_BUNDLE_ID_BYTES) {
    throw new KeyringFormatError(`v${version} requires a ${KEYRING_BUNDLE_ID_BYTES}-byte bundle id, got ${idLength}`);
  }
  let offset = 3;
  if (offset + idLength > bytes.length) throw new KeyringFormatError("bundle truncated in bundle id");
  const bundleId = bytes.slice(offset, offset + idLength);
  offset += idLength;

  const components: Array<KeyringEnvelope | null> = [];
  for (let index = 0; index < BUNDLE_COMPONENT_COUNT; index++) {
    if (offset + 4 > bytes.length) throw new KeyringFormatError("bundle truncated before component length");
    const length =
      bytes[offset]! * 0x100_0000 +
      bytes[offset + 1]! * 0x1_0000 +
      bytes[offset + 2]! * 0x100 +
      bytes[offset + 3]!;
    offset += 4;
    if (length === 0) {
      if (index !== 2) throw new KeyringFormatError(`bundle component ${index} is empty`);
      components.push(null);
      continue;
    }
    if (length > MAX_ENCODED_ENVELOPE_BYTES) {
      throw new KeyringFormatError(`bundle component ${index} length ${length} exceeds the cap`);
    }
    if (offset + length > bytes.length) throw new KeyringFormatError(`bundle component ${index} is truncated`);
    components.push(decodeKeyringEnvelope(bytes.slice(offset, offset + length)));
    offset += length;
  }
  if (offset !== bytes.length) throw new KeyringFormatError("trailing bytes after bundle components");

  const [payload, passwordWrap, prfWrap] = components as [
    KeyringEnvelope,
    KeyringEnvelope,
    KeyringEnvelope | null,
  ];
  const bundle = { version, bundleId, payload, passwordWrap, prfWrap };
  assertKeyringBundle(bundle);
  return bundle;
}

export interface SealKeyringBundleParams {
  readonly plaintext: Uint8Array;
  readonly passwordKey: KeyringUnwrapKey;
  /** Omit when PRF is unavailable; password fallback remains fully functional. */
  readonly prfKey?: KeyringUnwrapKey;
  readonly context: KeyringContext;
  /** Canonical outer-record metadata authenticated by every enrolled path. */
  readonly recordBinding?: Uint8Array;
  readonly version?: number;
  readonly unlock?: UnlockCheck;
}

/** Seal one payload under a random DEK and wrap that DEK by both unlock paths. */
export async function sealKeyringBundle(params: SealKeyringBundleParams): Promise<KeyringBundle> {
  const version = params.version ?? KEYRING_BUNDLE_VERSION_1;
  assertBundleVersion(version);
  // Validate before drawing a DEK or performing either wrap. Invalid caller input
  // must not cause needless secret generation or expensive crypto work.
  if (!(params.plaintext instanceof Uint8Array)) throw new KeyringFormatError("plaintext must be a Uint8Array");
  if (params.plaintext.length === 0) throw new KeyringFormatError("refusing to seal an empty plaintext");
  if (params.plaintext.length + KEYRING_TAG_BYTES > MAX_KEYRING_CIPHERTEXT_BYTES) {
    throw new KeyringFormatError(`plaintext of ${params.plaintext.length} bytes exceeds the envelope cap`);
  }
  assertUnwrapKey(params.passwordKey, "argon2id-password");
  if (params.prfKey !== undefined) assertUnwrapKey(params.prfKey, "webauthn-prf-hkdf");
  if (params.prfKey !== undefined && equalBytes(params.passwordKey.bytes, params.prfKey.bytes)) {
    throw new KeyringFormatError("password and PRF paths must use independent key material");
  }
  assertValidKeyringContext(params.context);
  const recordBinding = copyRecordBinding(params.recordBinding);
  if (params.unlock !== undefined) assertUnlocked(params.unlock.deadlines, params.unlock.now, "seal bundle");

  // Snapshot every mutable caller-owned buffer before the first await. A lock
  // handler may zero the caller's session keys as soon as this async API returns;
  // without snapshots that race can persist a bundle assembled from mixed states.
  const passwordKeyBytes = params.passwordKey.bytes.slice();
  const prfKeyBytes = params.prfKey?.bytes.slice();
  const plaintext = params.plaintext.slice();
  const context: KeyringContext = {
    ...params.context,
    account: params.context.account.slice(),
    genesisHash: params.context.genesisHash.slice(),
    programId: params.context.programId.slice(),
  };
  let dek: Uint8Array | undefined;
  try {
    const bundleId = randomKeyringBytes(KEYRING_BUNDLE_ID_BYTES, "a bundle id");
    dek = randomKeyringBytes(KEYRING_DEK_BYTES, "a data-encryption key");
    const passwordBody = await sealAead({
      plaintext: dek,
      keyBytes: passwordKeyBytes,
      keyName: "password unwrap key",
      aad: wrapAad(
        context,
        version,
        bundleId,
        "argon2id-password",
        KEYRING_ENVELOPE_VERSION_1,
        recordBinding,
      ),
    });
    const passwordWrap: KeyringEnvelope = {
      version: KEYRING_ENVELOPE_VERSION_1,
      ...passwordBody,
    };

    let prfWrap: KeyringEnvelope | null = null;
    if (prfKeyBytes !== undefined) {
      const prfBody = await sealAead({
        plaintext: dek,
        keyBytes: prfKeyBytes,
        keyName: "PRF unwrap key",
        aad: wrapAad(
          context,
          version,
          bundleId,
          "webauthn-prf-hkdf",
          KEYRING_ENVELOPE_VERSION_1,
          recordBinding,
        ),
      });
      prfWrap = { version: KEYRING_ENVELOPE_VERSION_1, ...prfBody };
    }

    const payloadBody = await sealAead({
      plaintext,
      keyBytes: dek,
      keyName: "data-encryption key",
      aad: payloadAad(
        context,
        version,
        bundleId,
        KEYRING_ENVELOPE_VERSION_1,
        passwordWrap,
        prfWrap,
        recordBinding,
      ),
    });
    return {
      version,
      bundleId,
      payload: { version: KEYRING_ENVELOPE_VERSION_1, ...payloadBody },
      passwordWrap,
      prfWrap,
    };
  } finally {
    passwordKeyBytes.fill(0);
    prfKeyBytes?.fill(0);
    plaintext.fill(0);
    dek?.fill(0);
  }
}

export interface OpenKeyringBundleParams {
  readonly bundle: KeyringBundle | Uint8Array;
  readonly unwrapKey: KeyringUnwrapKey;
  readonly context: KeyringContext;
  /** Must be the exact canonical outer-record metadata used at seal time. */
  readonly recordBinding?: Uint8Array;
  readonly unlock?: UnlockCheck;
}

/** Recover the DEK through the selected labelled path, then open the one payload. */
export async function openKeyringBundle(params: OpenKeyringBundleParams): Promise<Uint8Array> {
  const parsed = params.bundle instanceof Uint8Array ? decodeKeyringBundle(params.bundle) : params.bundle;
  assertKeyringBundle(parsed);
  assertUnwrapKey(params.unwrapKey);
  assertValidKeyringContext(params.context);
  const recordBinding = copyRecordBinding(params.recordBinding);
  if (params.unlock !== undefined) assertUnlocked(params.unlock.deadlines, params.unlock.now, "open bundle");

  // Canonicalize/copy all caller-owned mutable bytes before awaiting WebCrypto.
  // A concurrent storage refresh or lock must not make one authentication attempt
  // observe a mixture of two records.
  const bundle = decodeKeyringBundle(encodeKeyringBundle(parsed));
  const unwrapKeyBytes = params.unwrapKey.bytes.slice();
  const kdf = params.unwrapKey.kdf;
  const context: KeyringContext = {
    ...params.context,
    account: params.context.account.slice(),
    genesisHash: params.context.genesisHash.slice(),
    programId: params.context.programId.slice(),
  };
  let dek: Uint8Array | undefined;
  try {
    const selected = kdf === "argon2id-password" ? bundle.passwordWrap : bundle.prfWrap;
    if (selected === null) throw new KeyringAuthError();
    dek = await openAead({
      nonce: selected.nonce,
      ciphertext: selected.ciphertext,
      keyBytes: unwrapKeyBytes,
      keyName: "unwrap key",
      aad: wrapAad(context, bundle.version, bundle.bundleId, kdf, selected.version, recordBinding),
    });
    if (dek.length !== KEYRING_DEK_BYTES) {
      throw new KeyringFormatError(`wrapped data-encryption key must be ${KEYRING_DEK_BYTES} bytes`);
    }
    return await openAead({
      nonce: bundle.payload.nonce,
      ciphertext: bundle.payload.ciphertext,
      keyBytes: dek,
      keyName: "data-encryption key",
      aad: payloadAad(
        context,
        bundle.version,
        bundle.bundleId,
        bundle.payload.version,
        bundle.passwordWrap,
        bundle.prfWrap,
        recordBinding,
      ),
    });
  } finally {
    unwrapKeyBytes.fill(0);
    dek?.fill(0);
  }
}
