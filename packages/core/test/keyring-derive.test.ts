import { describe, it, expect } from "vitest";
import { argon2id } from "@noble/hashes/argon2";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import {
  MIN_ARGON2ID_SALT_BYTES,
  PROVISIONAL_ARGON2ID_PARAMS,
  UNWRAP_KEY_BYTES,
  assertValidArgon2idParams,
  deriveUnwrapKeyFromPassword,
  deriveUnwrapKeyFromPasswordBytes,
  deriveUnwrapKeyFromPrf,
  deriveUnwrapKeyFromPrfForContext,
  zeroizeUnwrapKey,
  type Argon2idParams,
} from "../src/keyring/derive.js";
import { keyringPrfInfo, type KeyringContext } from "../src/keyring/aad.js";
import { KeyringAuthError, KeyringFormatError } from "../src/keyring/errors.js";
import { openKeyringEnvelope, sealKeyringEnvelope } from "../src/keyring/envelope.js";
import { openKeyringBundle, sealKeyringBundle } from "../src/keyring/bundle.js";

// Unwrap-key derivation (WRD-KEY-02) — both unlock paths must recover the SAME DEK
// and payload ciphertext, because PRF is only an optimization and Argon2id must work.
//
// Cost parameters here are deliberately tiny: these tests pin the PLUMBING (that our
// wrapper passes exactly the parameters it was handed, with no silent substitution),
// not the cost floor. The real floor is a MEASUREMENT that C2 has not taken yet — see
// PROVISIONAL_ARGON2ID_PARAMS.

const hex = (b: Uint8Array): string => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const fill = (n: number, v: number): Uint8Array => new Uint8Array(n).fill(v);

/** Fast, test-only cost. NOT a security parameter. */
const FAST: Argon2idParams = { memoryKiB: 64, timeCost: 1, parallelism: 1 };
const SALT = fill(16, 0x33);

const CTX: KeyringContext = {
  account: fill(32, 0xa1),
  origin: "chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi",
  keyKind: "session-signer",
  schemaVersion: 1,
  genesisHash: fill(32, 0x5e),
  programId: fill(32, 0x77),
};

describe("Argon2id, pinned against the library rather than against ourselves", () => {
  it("matches the RFC 9106 §5.3 Argon2id reference vector", () => {
    // Independence at the bottom of the stack: this is a published vector, computed by
    // nobody in this repo. It pins @noble/hashes' Argon2id itself, so the wrapper test
    // below inherits a meaningful base.
    const tag = argon2id(fill(32, 0x01), fill(16, 0x02), {
      t: 3,
      m: 32,
      p: 4,
      version: 0x13,
      key: fill(8, 0x03),
      personalization: fill(12, 0x04),
      dkLen: 32,
    });
    expect(hex(tag)).toBe("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
  });

  it("passes the caller's parameters through verbatim — no substitution, no defaults", () => {
    const key = deriveUnwrapKeyFromPassword("correct horse battery staple", SALT, FAST);
    const direct = argon2id(new TextEncoder().encode("correct horse battery staple"), SALT, {
      m: FAST.memoryKiB,
      t: FAST.timeCost,
      p: FAST.parallelism,
      dkLen: UNWRAP_KEY_BYTES,
    });
    expect(hex(key.bytes)).toBe(hex(direct));
    expect(key.bytes.length).toBe(UNWRAP_KEY_BYTES);
    expect(key.kdf).toBe("argon2id-password");
  });

  it("is deterministic in (password, salt, params) and sensitive to each", () => {
    const base = deriveUnwrapKeyFromPassword("pw", SALT, FAST);
    expect(hex(deriveUnwrapKeyFromPassword("pw", SALT, FAST).bytes)).toBe(hex(base.bytes));
    expect(hex(deriveUnwrapKeyFromPassword("pW", SALT, FAST).bytes)).not.toBe(hex(base.bytes));
    expect(hex(deriveUnwrapKeyFromPassword("pw", fill(16, 0x34), FAST).bytes)).not.toBe(hex(base.bytes));
    expect(hex(deriveUnwrapKeyFromPassword("pw", SALT, { ...FAST, timeCost: 2 }).bytes)).not.toBe(hex(base.bytes));
  });

  it("declares its provisional parameters as UNVERIFIED, and still validates them", () => {
    // The constant exists so callers have something concrete to pass; it is NOT a
    // measured floor and nothing in this suite treats it as one.
    expect(() => assertValidArgon2idParams(PROVISIONAL_ARGON2ID_PARAMS)).not.toThrow();
    expect(PROVISIONAL_ARGON2ID_PARAMS.memoryKiB).toBe(64 * 1024);
    expect(PROVISIONAL_ARGON2ID_PARAMS.timeCost).toBe(3);
    expect(PROVISIONAL_ARGON2ID_PARAMS.parallelism).toBe(4);
  });

  it("rejects invalid parameters and short salts rather than clamping them", () => {
    const bad: Argon2idParams[] = [
      { memoryKiB: 64, timeCost: 0, parallelism: 1 },
      { memoryKiB: 4, timeCost: 1, parallelism: 1 },
      { memoryKiB: 64, timeCost: 1, parallelism: 0 },
      { memoryKiB: 8, timeCost: 1, parallelism: 4 }, // m < 8*p
      { memoryKiB: 64.5, timeCost: 1, parallelism: 1 },
    ];
    for (const p of bad) expect(() => assertValidArgon2idParams(p)).toThrow(KeyringFormatError);
    expect(() => deriveUnwrapKeyFromPassword("pw", fill(MIN_ARGON2ID_SALT_BYTES - 1, 1), FAST)).toThrow(
      /salt must be at least 16 bytes/,
    );
    expect(() => deriveUnwrapKeyFromPassword("", SALT, FAST)).toThrow(/empty password/);
  });
});

describe("WRD-KEY-02: nothing retains the password, and nothing compares one", () => {
  it("zeroes the caller's password buffer before returning", () => {
    const pw = new TextEncoder().encode("hunter2hunter2");
    const copy = pw.slice();
    const key = deriveUnwrapKeyFromPasswordBytes(pw, SALT, FAST);
    expect(Array.from(pw)).toEqual(new Array(copy.length).fill(0));
    // The derivation still produced the right key from the pre-zeroed contents.
    expect(hex(key.bytes)).toBe(hex(argon2id(copy, SALT, { m: 64, t: 1, p: 1, dkLen: 32 })));
  });

  it("zeroes the password buffer even when the derivation throws", () => {
    const pw = new TextEncoder().encode("hunter2");
    expect(() => deriveUnwrapKeyFromPasswordBytes(pw, fill(4, 0), FAST)).toThrow(KeyringFormatError);
    expect(Array.from(pw)).toEqual(new Array(pw.length).fill(0));
  });

  it("exposes NO password verification function — re-auth is a derive-and-decrypt", async () => {
    // The module surface is the evidence: there is no verifyPassword/checkPassword, so
    // there is nothing for a caller to substitute for a cryptographic authentication.
    const mod = await import("../src/keyring/derive.js");
    const names = Object.keys(mod).map((n) => n.toLowerCase());
    for (const forbidden of ["verify", "check", "compare", "equals", "matches"]) {
      expect(names.some((n) => n.includes(forbidden))).toBe(false);
    }
  });

  it("authenticates a wrong password through the AEAD, not through a comparison", async () => {
    const right = deriveUnwrapKeyFromPassword("right-password", SALT, FAST);
    const wrong = deriveUnwrapKeyFromPassword("wrong-password", SALT, FAST);
    const env = await sealKeyringEnvelope({ plaintext: fill(48, 0x9a), unwrapKey: right, context: CTX });
    expect(hex(await openKeyringEnvelope({ envelope: env, unwrapKey: right, context: CTX }))).toBe(hex(fill(48, 0x9a)));
    await expect(openKeyringEnvelope({ envelope: env, unwrapKey: wrong, context: CTX })).rejects.toThrow(
      KeyringAuthError,
    );
  });

  it("zeroizes a derived key on request (best effort — see the module doc)", () => {
    const key = deriveUnwrapKeyFromPassword("pw", SALT, FAST);
    zeroizeUnwrapKey(key);
    expect(Array.from(key.bytes)).toEqual(new Array(UNWRAP_KEY_BYTES).fill(0));
  });
});

describe("PRF path (interface level; acquiring the PRF secret is C1 and unimplemented)", () => {
  const PRF = fill(32, 0x6d);
  const PRF_SALT = fill(16, 0x44);

  it("derives exactly HKDF-SHA256(prf, salt, info) — pinned against a direct library call", () => {
    const key = deriveUnwrapKeyFromPrfForContext(PRF, PRF_SALT, CTX);
    const direct = hkdf(sha256, PRF, PRF_SALT, keyringPrfInfo(CTX), UNWRAP_KEY_BYTES);
    expect(hex(key.bytes)).toBe(hex(direct));
    expect(key.kdf).toBe("webauthn-prf-hkdf");
    expect(key.bytes.length).toBe(UNWRAP_KEY_BYTES);
  });

  it("does NOT hand back the raw PRF output as the unwrap key", () => {
    expect(hex(deriveUnwrapKeyFromPrfForContext(PRF, PRF_SALT, CTX).bytes)).not.toBe(hex(PRF));
  });

  it("binds the context: a different account, origin, key kind, cluster or program gives a different key", () => {
    const base = hex(deriveUnwrapKeyFromPrfForContext(PRF, PRF_SALT, CTX).bytes);
    const variants: KeyringContext[] = [
      { ...CTX, account: fill(32, 0xa2) },
      { ...CTX, origin: CTX.origin + "/" },
      { ...CTX, keyKind: "recovery-secret" },
      { ...CTX, genesisHash: fill(32, 0x5f) },
      { ...CTX, programId: fill(32, 0x78) },
    ];
    const all = new Set([base, ...variants.map((c) => hex(deriveUnwrapKeyFromPrfForContext(PRF, PRF_SALT, c).bytes))]);
    expect(all.size).toBe(variants.length + 1);
    // A schema bump must NOT move the key — that would brick unlock on a format revision.
    expect(hex(deriveUnwrapKeyFromPrfForContext(PRF, PRF_SALT, { ...CTX, schemaVersion: 7 }).bytes)).toBe(base);
  });

  it("validates PRF input lengths explicitly", () => {
    expect(() => deriveUnwrapKeyFromPrf(fill(31, 1), PRF_SALT, keyringPrfInfo(CTX))).toThrow(/exactly 32 bytes/);
    expect(() => deriveUnwrapKeyFromPrf(fill(64, 1), PRF_SALT, keyringPrfInfo(CTX))).toThrow(/exactly 32 bytes/);
    expect(() => deriveUnwrapKeyFromPrf(PRF, fill(8, 1), keyringPrfInfo(CTX))).toThrow(/salt must be at least/);
    expect(() => deriveUnwrapKeyFromPrf(PRF, PRF_SALT, new Uint8Array(0))).toThrow(/non-empty/);
  });
});

describe("both unlock paths recover the SAME bundle payload (PRF is never the only way)", () => {
  it("independently derived password and PRF KEKs unwrap one payload ciphertext", async () => {
    const prfKey = deriveUnwrapKeyFromPrfForContext(fill(32, 0x6d), fill(16, 0x44), CTX);
    const pwKey = deriveUnwrapKeyFromPassword("pw", SALT, FAST);
    const secret = fill(64, 0xc3);

    const bundle = await sealKeyringBundle({ plaintext: secret, passwordKey: pwKey, prfKey, context: CTX });
    const payloadCiphertext = hex(bundle.payload.ciphertext);
    expect(hex(await openKeyringBundle({ bundle, unwrapKey: pwKey, context: CTX }))).toBe(hex(secret));
    expect(hex(await openKeyringBundle({ bundle, unwrapKey: prfKey, context: CTX }))).toBe(hex(secret));
    expect(hex(bundle.payload.ciphertext)).toBe(payloadCiphertext);
  });
});
