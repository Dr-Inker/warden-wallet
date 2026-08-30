//! Internal AES-256-GCM operations shared by the legacy single-key envelope and
//! the KEK/DEK bundle. This module is intentionally not exported from the package
//! root: callers should use `envelope.ts` or `bundle.ts`, whose AAD builders bind
//! the ciphertext to a Warden context and format.

import {
  KeyringAuthError,
  KeyringCryptoUnavailableError,
  KeyringFormatError,
} from "./errors.js";

/** GCM nonce length in bytes. 12 is mandatory here, not a default. */
export const KEYRING_NONCE_BYTES = 12;
/** GCM tag length in bytes (128 bits). Passed explicitly to WebCrypto. */
export const KEYRING_TAG_BYTES = 16;
/** AES-256 key length in bytes. */
export const KEYRING_AES_KEY_BYTES = 32;
/** Sanity cap on one ciphertext. A keyring is small. */
export const MAX_KEYRING_CIPHERTEXT_BYTES = 64 * 1024;

export interface AeadEnvelopeBody {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

function subtle(): SubtleCrypto {
  const crypto = globalThis.crypto;
  if (crypto === undefined || crypto.subtle === undefined) {
    throw new KeyringCryptoUnavailableError("WebCrypto (crypto.subtle) is unavailable; refusing to continue");
  }
  return crypto.subtle;
}

/** Draw bytes from the platform CSPRNG. There is deliberately no injectable RNG. */
export function randomKeyringBytes(length: number, purpose: string): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw new KeyringFormatError(`random byte length must be a positive integer, got ${length}`);
  }
  const crypto = globalThis.crypto;
  if (crypto === undefined || typeof crypto.getRandomValues !== "function") {
    throw new KeyringCryptoUnavailableError(`crypto.getRandomValues is unavailable; refusing to generate ${purpose}`);
  }
  return crypto.getRandomValues(new Uint8Array(length));
}

export function assertAes256KeyBytes(bytes: Uint8Array, name: string): void {
  if (!(bytes instanceof Uint8Array)) throw new KeyringFormatError(`${name} bytes must be a Uint8Array`);
  if (bytes.length !== KEYRING_AES_KEY_BYTES) {
    throw new KeyringFormatError(
      `${name} must be exactly ${KEYRING_AES_KEY_BYTES} bytes (AES-256), got ${bytes.length}`,
    );
  }
}

function assertAad(aad: Uint8Array): void {
  if (!(aad instanceof Uint8Array) || aad.length === 0) {
    throw new KeyringFormatError("AEAD additional data must be a non-empty Uint8Array");
  }
}

/** Import raw bytes as a non-extractable AES-GCM key. */
async function importAesKey(
  keyBytes: Uint8Array,
  keyName: string,
  usage: "encrypt" | "decrypt",
): Promise<CryptoKey> {
  assertAes256KeyBytes(keyBytes, keyName);
  return subtle().importKey("raw", keyBytes as unknown as BufferSource, { name: "AES-GCM" }, false, [usage]);
}

export interface SealAeadParams {
  readonly plaintext: Uint8Array;
  readonly keyBytes: Uint8Array;
  readonly keyName: string;
  readonly aad: Uint8Array;
}

/** AES-256-GCM seal with a fresh, non-injectable 96-bit nonce. */
export async function sealAead(params: SealAeadParams): Promise<AeadEnvelopeBody> {
  if (!(params.plaintext instanceof Uint8Array)) throw new KeyringFormatError("plaintext must be a Uint8Array");
  if (params.plaintext.length === 0) throw new KeyringFormatError("refusing to seal an empty plaintext");
  if (params.plaintext.length + KEYRING_TAG_BYTES > MAX_KEYRING_CIPHERTEXT_BYTES) {
    throw new KeyringFormatError(`plaintext of ${params.plaintext.length} bytes exceeds the envelope cap`);
  }
  assertAad(params.aad);
  assertAes256KeyBytes(params.keyBytes, params.keyName);
  const plaintext = params.plaintext.slice();
  const keyBytes = params.keyBytes.slice();
  const aad = params.aad.slice();
  try {
    const key = await importAesKey(keyBytes, params.keyName, "encrypt");
    const nonce = randomKeyringBytes(KEYRING_NONCE_BYTES, "a nonce");
    const ciphertext = new Uint8Array(
      await subtle().encrypt(
        {
          name: "AES-GCM",
          iv: nonce as unknown as BufferSource,
          additionalData: aad as unknown as BufferSource,
          tagLength: KEYRING_TAG_BYTES * 8,
        },
        key,
        plaintext as unknown as BufferSource,
      ),
    );
    return { nonce, ciphertext };
  } finally {
    plaintext.fill(0);
    keyBytes.fill(0);
  }
}

export interface OpenAeadParams extends AeadEnvelopeBody {
  readonly keyBytes: Uint8Array;
  readonly keyName: string;
  readonly aad: Uint8Array;
}

/** Authenticate and decrypt, collapsing every AEAD rejection to one error. */
export async function openAead(params: OpenAeadParams): Promise<Uint8Array> {
  if (!(params.nonce instanceof Uint8Array) || params.nonce.length !== KEYRING_NONCE_BYTES) {
    const length = params.nonce instanceof Uint8Array ? params.nonce.length : "non-byte value";
    throw new KeyringFormatError(`nonce must be exactly ${KEYRING_NONCE_BYTES} bytes, got ${length}`);
  }
  if (!(params.ciphertext instanceof Uint8Array)) {
    throw new KeyringFormatError("ciphertext must be a Uint8Array");
  }
  if (params.ciphertext.length < KEYRING_TAG_BYTES) {
    throw new KeyringFormatError("ciphertext is shorter than the authentication tag");
  }
  if (params.ciphertext.length > MAX_KEYRING_CIPHERTEXT_BYTES) {
    throw new KeyringFormatError(`ciphertext of ${params.ciphertext.length} bytes exceeds the cap`);
  }
  assertAad(params.aad);
  assertAes256KeyBytes(params.keyBytes, params.keyName);
  const nonce = params.nonce.slice();
  const ciphertext = params.ciphertext.slice();
  const keyBytes = params.keyBytes.slice();
  const aad = params.aad.slice();
  try {
    const key = await importAesKey(keyBytes, params.keyName, "decrypt");
    try {
      const plaintext = await subtle().decrypt(
        {
          name: "AES-GCM",
          iv: nonce as unknown as BufferSource,
          additionalData: aad as unknown as BufferSource,
          tagLength: KEYRING_TAG_BYTES * 8,
        },
        key,
        ciphertext as unknown as BufferSource,
      );
      return new Uint8Array(plaintext);
    } catch {
      throw new KeyringAuthError();
    }
  } finally {
    keyBytes.fill(0);
  }
}
