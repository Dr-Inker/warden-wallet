import { describe, it, expect, vi } from "vitest";
import {
  KEYRING_ENVELOPE_VERSION_1,
  KEYRING_NONCE_BYTES,
  KEYRING_TAG_BYTES,
  decodeKeyringEnvelope,
  encodeKeyringEnvelope,
  openKeyringEnvelope,
  sealKeyringEnvelope,
} from "../src/keyring/envelope.js";
import type { KeyringContext } from "../src/keyring/aad.js";
import { encodeKeyringAad } from "../src/keyring/aad.js";
import {
  KeyringAuthError,
  KeyringExpiredError,
  KeyringFormatError,
  KeyringLockedError,
} from "../src/keyring/errors.js";
import { startUnlockSession } from "../src/keyring/deadlines.js";
import type { KeyringUnwrapKey } from "../src/keyring/derive.js";

// Versioned AEAD keyring envelope (WRD-KEY-04).
//
// TESTING RULE, from the plan and followed literally: "Do not derive expected
// ciphertext from the implementation under test." So the AAD below is re-implemented
// LONGHAND from the format documented in `keyring/aad.ts`, the ciphertext for the
// acceptance vectors is produced by calling `crypto.subtle.encrypt` DIRECTLY, and the
// envelope bytes are assembled by hand. `open(seal(x)) === x` appears exactly once,
// labelled — on its own it is self-consistent and proves almost nothing: an
// implementation that XORed with a constant would pass it.

const fill = (n: number, v: number): Uint8Array => new Uint8Array(n).fill(v);
const hex = (b: Uint8Array): string => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");

const CTX: KeyringContext = {
  account: fill(32, 0xa1),
  origin: "chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi",
  keyKind: "session-signer",
  schemaVersion: 1,
  genesisHash: fill(32, 0x5e),
  programId: fill(32, 0x77),
};
const PLAINTEXT = new TextEncoder().encode("ed25519-session-secret:0123456789abcdef");

// --- INDEPENDENT re-implementations (written from the doc, never by calling src) -------

/** Length-prefixed canonical AAD, rebuilt by hand. */
function refAad(ctx: KeyringContext, envelopeVersion: number): Uint8Array {
  const te = new TextEncoder();
  const out: number[] = [];
  const lp = (b: Uint8Array): void => {
    out.push((b.length >>> 24) & 0xff, (b.length >>> 16) & 0xff, (b.length >>> 8) & 0xff, b.length & 0xff);
    for (const x of b) out.push(x);
  };
  const u32 = (n: number): Uint8Array =>
    Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  lp(te.encode("warden/keyring-envelope/aad"));
  out.push((envelopeVersion >>> 8) & 0xff, envelopeVersion & 0xff);
  out.push(6);
  lp(ctx.account);
  lp(te.encode(ctx.origin));
  lp(te.encode(ctx.keyKind));
  lp(u32(ctx.schemaVersion));
  lp(ctx.genesisHash);
  lp(ctx.programId);
  return Uint8Array.from(out);
}

/** Envelope wire bytes, assembled by hand from the documented layout. */
function refEnvelopeBytes(version: number, nonce: Uint8Array, ct: Uint8Array): Uint8Array {
  const out: number[] = [];
  out.push((version >>> 8) & 0xff, version & 0xff);
  out.push(nonce.length);
  for (const b of nonce) out.push(b);
  out.push((ct.length >>> 24) & 0xff, (ct.length >>> 16) & 0xff, (ct.length >>> 8) & 0xff, ct.length & 0xff);
  for (const b of ct) out.push(b);
  return Uint8Array.from(out);
}

async function rawKey(bytes: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey("raw", bytes as unknown as BufferSource, { name: "AES-GCM" }, false, usages);
}

/** Encrypt with raw WebCrypto — the independent oracle for the acceptance vectors. */
async function rawEncrypt(keyBytes: Uint8Array, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array): Promise<Uint8Array> {
  const k = await rawKey(keyBytes, ["encrypt"]);
  return new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce as unknown as BufferSource, additionalData: aad as unknown as BufferSource, tagLength: 128 },
      k,
      pt as unknown as BufferSource,
    ),
  );
}

/** Decrypt with raw WebCrypto — proves OUR seal is interoperable, not merely self-consistent. */
async function rawDecrypt(keyBytes: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array): Promise<Uint8Array> {
  const k = await rawKey(keyBytes, ["decrypt"]);
  return new Uint8Array(
    await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce as unknown as BufferSource, additionalData: aad as unknown as BufferSource, tagLength: 128 },
      k,
      ct as unknown as BufferSource,
    ),
  );
}

const KEY_BYTES = fill(32, 0x2b);
const KEY: KeyringUnwrapKey = { kdf: "argon2id-password", bytes: KEY_BYTES };
const NONCE = fill(KEYRING_NONCE_BYTES, 0x11);

/** A hand-built, independently-encrypted envelope in `ctx`. */
async function independentEnvelope(ctx: KeyringContext = CTX, version = 1, pt = PLAINTEXT): Promise<Uint8Array> {
  const ct = await rawEncrypt(KEY_BYTES, NONCE, refAad(ctx, version), pt);
  return refEnvelopeBytes(version, NONCE, ct);
}

// --- The independence checks themselves ------------------------------------------------

describe("AAD independence pin", () => {
  it("the longhand AAD equals what the implementation builds (so the vectors below are meaningful)", () => {
    expect(hex(refAad(CTX, 1))).toBe(hex(encodeKeyringAad(CTX, 1)));
    expect(hex(refAad(CTX, 2))).toBe(hex(encodeKeyringAad(CTX, 2)));
  });
});

describe("envelope interoperability, both directions", () => {
  it("ACCEPTS a ciphertext produced independently by crypto.subtle with a hand-built AAD", async () => {
    const bytes = await independentEnvelope();
    const out = await openKeyringEnvelope({ envelope: bytes, unwrapKey: KEY, context: CTX });
    expect(hex(out)).toBe(hex(PLAINTEXT));
  });

  it("produces a ciphertext raw crypto.subtle can decrypt with the hand-built AAD", async () => {
    const env = await sealKeyringEnvelope({ plaintext: PLAINTEXT, unwrapKey: KEY, context: CTX });
    const out = await rawDecrypt(KEY_BYTES, env.nonce, refAad(CTX, env.version), env.ciphertext);
    expect(hex(out)).toBe(hex(PLAINTEXT));
  });

  it("round-trips through its own seal/open — a WEAK check, kept only for completeness", async () => {
    // Self-consistency proves almost nothing on its own (a constant-XOR "cipher" would
    // pass it too). The two vectors above are the ones that carry the weight.
    const env = await sealKeyringEnvelope({ plaintext: PLAINTEXT, unwrapKey: KEY, context: CTX });
    expect(hex(await openKeyringEnvelope({ envelope: env, unwrapKey: KEY, context: CTX }))).toBe(hex(PLAINTEXT));
    // …and through the serialized form storage actually holds.
    const bytes = encodeKeyringEnvelope(env);
    expect(hex(await openKeyringEnvelope({ envelope: bytes, unwrapKey: KEY, context: CTX }))).toBe(hex(PLAINTEXT));
  });
});

describe("nonces are fresh per seal", () => {
  it("gives a different nonce AND a different ciphertext for identical plaintext + key + context", async () => {
    const seals = await Promise.all(
      Array.from({ length: 8 }, () => sealKeyringEnvelope({ plaintext: PLAINTEXT, unwrapKey: KEY, context: CTX })),
    );
    const nonces = new Set(seals.map((e) => hex(e.nonce)));
    expect(nonces.size).toBe(seals.length);
    expect(new Set(seals.map((e) => hex(e.ciphertext))).size).toBe(seals.length);
    for (const e of seals) expect(e.nonce.length).toBe(KEYRING_NONCE_BYTES);
    // There is no API to inject a nonce, deliberately — so this is the only way to
    // observe the randomness, and that is the right trade.
  });
});

describe("tampering rejects (indistinguishably)", () => {
  it("rejects a one-bit flip anywhere in the ciphertext body", async () => {
    const bytes = await independentEnvelope();
    const bodyStart = 3 + KEYRING_NONCE_BYTES + 4;
    const bodyEnd = bytes.length - KEYRING_TAG_BYTES;
    for (const i of [bodyStart, bodyStart + 1, bodyEnd - 1]) {
      const t = bytes.slice();
      t[i] = t[i]! ^ 0x01;
      await expect(openKeyringEnvelope({ envelope: t, unwrapKey: KEY, context: CTX })).rejects.toThrow(KeyringAuthError);
    }
  });

  it("rejects a one-bit flip in the authentication TAG", async () => {
    const bytes = await independentEnvelope();
    for (const i of [bytes.length - KEYRING_TAG_BYTES, bytes.length - 1]) {
      const t = bytes.slice();
      t[i] = t[i]! ^ 0x80;
      await expect(openKeyringEnvelope({ envelope: t, unwrapKey: KEY, context: CTX })).rejects.toThrow(KeyringAuthError);
    }
  });

  it("rejects a one-bit flip in the AAD used at seal time", async () => {
    // A true AAD-corruption vector: seal independently under a CORRUPTED AAD, then ask
    // our open() — which rebuilds the clean AAD from the context — to accept it.
    const aad = refAad(CTX, 1);
    for (const i of [0, 5, aad.length - 1]) {
      const bad = aad.slice();
      bad[i] = bad[i]! ^ 0x01;
      const ct = await rawEncrypt(KEY_BYTES, NONCE, bad, PLAINTEXT);
      const bytes = refEnvelopeBytes(1, NONCE, ct);
      await expect(openKeyringEnvelope({ envelope: bytes, unwrapKey: KEY, context: CTX })).rejects.toThrow(
        KeyringAuthError,
      );
    }
  });

  it("rejects a flipped nonce (GCM authenticates its own IV)", async () => {
    const bytes = await independentEnvelope();
    const t = bytes.slice();
    t[3] = t[3]! ^ 0x01;
    await expect(openKeyringEnvelope({ envelope: t, unwrapKey: KEY, context: CTX })).rejects.toThrow(KeyringAuthError);
  });

  it("rejects a wrong unwrap key", async () => {
    const bytes = await independentEnvelope();
    const wrong: KeyringUnwrapKey = { kdf: "argon2id-password", bytes: fill(32, 0x2c) };
    await expect(openKeyringEnvelope({ envelope: bytes, unwrapKey: wrong, context: CTX })).rejects.toThrow(
      KeyringAuthError,
    );
  });

  it("reports every authentication failure with the SAME message (no context oracle)", async () => {
    const bytes = await independentEnvelope();
    const messages = new Set<string>();
    const attempts: Array<{ unwrapKey: KeyringUnwrapKey; context: KeyringContext }> = [
      { unwrapKey: { kdf: "argon2id-password", bytes: fill(32, 0x2c) }, context: CTX },
      { unwrapKey: KEY, context: { ...CTX, account: fill(32, 0xa2) } },
      { unwrapKey: KEY, context: { ...CTX, genesisHash: fill(32, 0x5f) } },
    ];
    for (const a of attempts) {
      await openKeyringEnvelope({ envelope: bytes, ...a }).catch((e: unknown) => {
        messages.add((e as Error).message);
      });
    }
    expect(messages.size).toBe(1);
  });
});

describe("context binding — a mismatch on ANY bound field rejects", () => {
  const wrongContexts: Array<[string, KeyringContext]> = [
    ["wrong account", { ...CTX, account: fill(32, 0xa2) }],
    ["wrong origin (different extension id)", { ...CTX, origin: "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }],
    ["wrong origin (trailing slash)", { ...CTX, origin: CTX.origin + "/" }],
    ["wrong key kind", { ...CTX, keyKind: "recovery-secret" }],
    ["wrong schema version", { ...CTX, schemaVersion: 2 }],
    ["wrong Warden program id", { ...CTX, programId: fill(32, 0x78) }],
  ];
  for (const [name, ctx] of wrongContexts) {
    it(`rejects ${name}`, async () => {
      const bytes = await independentEnvelope();
      await expect(openKeyringEnvelope({ envelope: bytes, unwrapKey: KEY, context: ctx })).rejects.toThrow(
        KeyringAuthError,
      );
    });
  }

  it("REJECTS A CROSS-CLUSTER REPLAY: identical account, different genesis hash (WRDF-0023)", async () => {
    // The finding this vector exists for: a Warden SmartAccount PDA is not
    // network-qualified, so the same program id + root + salt yields the SAME address
    // on devnet and mainnet. Everything below is byte-identical to the sealing context
    // EXCEPT the cluster's genesis hash — which is exactly the shape an envelope lifted
    // from one profile and dropped into another has.
    const devnet = { ...CTX, genesisHash: fill(32, 0x5e) };
    const mainnet = { ...CTX, genesisHash: fill(32, 0x99) };
    expect(hex(devnet.account)).toBe(hex(mainnet.account)); // same address, as the finding says
    expect(hex(devnet.programId)).toBe(hex(mainnet.programId));

    const sealedOnDevnet = await independentEnvelope(devnet);
    // Sanity: it really does open on the cluster it was sealed for.
    expect(hex(await openKeyringEnvelope({ envelope: sealedOnDevnet, unwrapKey: KEY, context: devnet }))).toBe(
      hex(PLAINTEXT),
    );
    // The transplant fails, which is the whole point.
    await expect(openKeyringEnvelope({ envelope: sealedOnDevnet, unwrapKey: KEY, context: mainnet })).rejects.toThrow(
      KeyringAuthError,
    );
  });

  it("binds the envelope VERSION, so the out-of-AEAD header bytes cannot be rolled", async () => {
    // Header bytes live outside the AEAD by necessity. Sealing under an AAD built for
    // version 2 while the header claims version 1 must fail — that is what proves the
    // version is authenticated rather than merely parsed.
    const ct = await rawEncrypt(KEY_BYTES, NONCE, refAad(CTX, 2), PLAINTEXT);
    const bytes = refEnvelopeBytes(1, NONCE, ct);
    await expect(openKeyringEnvelope({ envelope: bytes, unwrapKey: KEY, context: CTX })).rejects.toThrow(
      KeyringAuthError,
    );
  });
});

describe("malformed and unknown-version envelopes reject structurally", () => {
  it("rejects an unknown version before touching any key material", async () => {
    for (const version of [0, 2, 0xffff]) {
      const bytes = refEnvelopeBytes(version, NONCE, fill(32, 0));
      expect(() => decodeKeyringEnvelope(bytes)).toThrow(/unknown envelope version/);
      await expect(openKeyringEnvelope({ envelope: bytes, unwrapKey: KEY, context: CTX })).rejects.toThrow(
        KeyringFormatError,
      );
    }
  });

  it("rejects truncation, trailing bytes, a wrong nonce length, and a sub-tag ciphertext", async () => {
    const good = await independentEnvelope();
    expect(() => decodeKeyringEnvelope(good.subarray(0, 2))).toThrow(KeyringFormatError);
    expect(() => decodeKeyringEnvelope(good.subarray(0, good.length - 1))).toThrow(KeyringFormatError);
    expect(() => decodeKeyringEnvelope(Uint8Array.from([...good, 0x00]))).toThrow(KeyringFormatError);
    expect(() => decodeKeyringEnvelope(refEnvelopeBytes(1, fill(8, 0), fill(32, 0)))).toThrow(
      /requires a 12-byte nonce/,
    );
    expect(() => decodeKeyringEnvelope(refEnvelopeBytes(1, NONCE, fill(KEYRING_TAG_BYTES - 1, 0)))).toThrow(
      /below the 16-byte tag/,
    );
    expect(() => decodeKeyringEnvelope(new Uint8Array(0))).toThrow(KeyringFormatError);
  });

  it("refuses to seal an empty plaintext, an unsupported version, or a non-256-bit key", async () => {
    await expect(
      sealKeyringEnvelope({ plaintext: new Uint8Array(0), unwrapKey: KEY, context: CTX }),
    ).rejects.toThrow(/empty plaintext/);
    await expect(
      sealKeyringEnvelope({ plaintext: PLAINTEXT, unwrapKey: KEY, context: CTX, version: 2 }),
    ).rejects.toThrow(/unsupported version/);
    await expect(
      sealKeyringEnvelope({
        plaintext: PLAINTEXT,
        unwrapKey: { kdf: "argon2id-password", bytes: fill(16, 1) },
        context: CTX,
      }),
    ).rejects.toThrow(/exactly 32 bytes/);
  });

  it("encode/decode of the wire form is a strict round-trip", async () => {
    const env = await sealKeyringEnvelope({ plaintext: PLAINTEXT, unwrapKey: KEY, context: CTX });
    const back = decodeKeyringEnvelope(encodeKeyringEnvelope(env));
    expect(back.version).toBe(KEYRING_ENVELOPE_VERSION_1);
    expect(hex(back.nonce)).toBe(hex(env.nonce));
    expect(hex(back.ciphertext)).toBe(hex(env.ciphertext));
  });
});

describe("a key use past an unlock deadline is refused (WRD-KEY-03 at the key-use site)", () => {
  it("refuses to open an otherwise-valid envelope after expiry — no alarm involved", async () => {
    const bytes = await independentEnvelope();
    const t0 = 1_700_000_000_000;
    const deadlines = startUnlockSession(t0, { idleTimeoutMs: 60_000, hardTimeoutMs: 3_600_000 });

    // Live: the same envelope opens fine.
    expect(
      hex(
        await openKeyringEnvelope({
          envelope: bytes,
          unwrapKey: KEY,
          context: CTX,
          unlock: { deadlines, readNow: () => t0 + 1, signal: new AbortController().signal },
        }),
      ),
    ).toBe(hex(PLAINTEXT));

    // Expired: refused. Nothing scheduled a timer, nothing fired an alarm, and no
    // cleanup ran — the deadline check alone is the authority.
    await expect(
      openKeyringEnvelope({
        envelope: bytes,
        unwrapKey: KEY,
        context: CTX,
        unlock: { deadlines, readNow: () => t0 + 60_000, signal: new AbortController().signal },
      }),
    ).rejects.toThrow(KeyringExpiredError);
  });

  it("refuses to re-seal past a deadline too", async () => {
    const t0 = 1_700_000_000_000;
    const deadlines = startUnlockSession(t0, { idleTimeoutMs: 60_000, hardTimeoutMs: 3_600_000 });
    await expect(
      sealKeyringEnvelope({
        plaintext: PLAINTEXT,
        unwrapKey: KEY,
        context: CTX,
        unlock: {
          deadlines,
          readNow: () => t0 + 3_600_000,
          signal: new AbortController().signal,
        },
      }),
    ).rejects.toThrow(KeyringExpiredError);
  });

  it("re-reads wall clock after key import and refuses to decrypt after expiry", async () => {
    const bytes = await independentEnvelope();
    const t0 = 1_700_000_000_000;
    const deadlines = startUnlockSession(t0, { idleTimeoutMs: 100, hardTimeoutMs: 500 });
    let now = t0 + 1;
    const subtle = globalThis.crypto.subtle;
    const originalImportKey = subtle.importKey;
    const importSpy = vi.spyOn(subtle, "importKey").mockImplementation(
      (async (...args: unknown[]) => {
        const key = (await Reflect.apply(originalImportKey, subtle, args)) as CryptoKey;
        now = deadlines.idleExpiresAt;
        return key;
      }) as typeof subtle.importKey,
    );
    const decryptSpy = vi.spyOn(subtle, "decrypt");
    try {
      await expect(
        openKeyringEnvelope({
          envelope: bytes,
          unwrapKey: KEY,
          context: CTX,
          unlock: { deadlines, readNow: () => now, signal: new AbortController().signal },
        }),
      ).rejects.toThrow(KeyringExpiredError);
      expect(importSpy).toHaveBeenCalledTimes(1);
      expect(decryptSpy).not.toHaveBeenCalled();
    } finally {
      decryptSpy.mockRestore();
      importSpy.mockRestore();
    }
  });

  it("suppresses and zeroes plaintext when expiry crosses the decrypt await", async () => {
    const bytes = await independentEnvelope();
    const t0 = 1_700_000_000_000;
    const deadlines = startUnlockSession(t0, { idleTimeoutMs: 100, hardTimeoutMs: 500 });
    let now = t0 + 1;
    let decryptedBuffer: ArrayBuffer | undefined;
    const subtle = globalThis.crypto.subtle;
    const originalDecrypt = subtle.decrypt;
    const decryptSpy = vi.spyOn(subtle, "decrypt").mockImplementation(
      (async (...args: unknown[]) => {
        decryptedBuffer = (await Reflect.apply(originalDecrypt, subtle, args)) as ArrayBuffer;
        now = deadlines.idleExpiresAt;
        return decryptedBuffer;
      }) as typeof subtle.decrypt,
    );
    try {
      await expect(
        openKeyringEnvelope({
          envelope: bytes,
          unwrapKey: KEY,
          context: CTX,
          unlock: { deadlines, readNow: () => now, signal: new AbortController().signal },
        }),
      ).rejects.toThrow(KeyringExpiredError);
      expect(decryptSpy).toHaveBeenCalledTimes(1);
      expect(decryptedBuffer).toBeDefined();
      expect(Array.from(new Uint8Array(decryptedBuffer!))).toEqual(new Array(PLAINTEXT.length).fill(0));
    } finally {
      decryptSpy.mockRestore();
    }
  });

  it("suppresses a sealed result when expiry crosses the encrypt await", async () => {
    const t0 = 1_700_000_000_000;
    const deadlines = startUnlockSession(t0, { idleTimeoutMs: 100, hardTimeoutMs: 500 });
    let now = t0 + 1;
    const subtle = globalThis.crypto.subtle;
    const originalEncrypt = subtle.encrypt;
    const encryptSpy = vi.spyOn(subtle, "encrypt").mockImplementation(
      (async (...args: unknown[]) => {
        const ciphertext = (await Reflect.apply(originalEncrypt, subtle, args)) as ArrayBuffer;
        now = deadlines.idleExpiresAt;
        return ciphertext;
      }) as typeof subtle.encrypt,
    );
    try {
      await expect(
        sealKeyringEnvelope({
          plaintext: PLAINTEXT,
          unwrapKey: KEY,
          context: CTX,
          unlock: { deadlines, readNow: () => now, signal: new AbortController().signal },
        }),
      ).rejects.toThrow(KeyringExpiredError);
      expect(encryptSpy).toHaveBeenCalledTimes(1);
    } finally {
      encryptSpy.mockRestore();
    }
  });

  it("suppresses and zeroes plaintext when manual lock aborts during decrypt", async () => {
    const bytes = await independentEnvelope();
    const t0 = 1_700_000_000_000;
    const deadlines = startUnlockSession(t0, { idleTimeoutMs: 100, hardTimeoutMs: 500 });
    const controller = new AbortController();
    let decryptedBuffer: ArrayBuffer | undefined;
    const subtle = globalThis.crypto.subtle;
    const originalDecrypt = subtle.decrypt;
    const decryptSpy = vi.spyOn(subtle, "decrypt").mockImplementation(
      (async (...args: unknown[]) => {
        decryptedBuffer = (await Reflect.apply(originalDecrypt, subtle, args)) as ArrayBuffer;
        controller.abort();
        return decryptedBuffer;
      }) as typeof subtle.decrypt,
    );
    try {
      await expect(
        openKeyringEnvelope({
          envelope: bytes,
          unwrapKey: KEY,
          context: CTX,
          unlock: {
            deadlines,
            readNow: () => t0 + 1,
            signal: controller.signal,
          },
        }),
      ).rejects.toThrow(KeyringLockedError);
      expect(decryptSpy).toHaveBeenCalledTimes(1);
      expect(decryptedBuffer).toBeDefined();
      expect(Array.from(new Uint8Array(decryptedBuffer!))).toEqual(new Array(PLAINTEXT.length).fill(0));
    } finally {
      decryptSpy.mockRestore();
    }
  });
});

describe("caller-owned byte buffers are snapshotted across WebCrypto awaits", () => {
  it("seals the plaintext and key state present when the operation starts", async () => {
    const plaintext = PLAINTEXT.slice();
    const unwrapKey: KeyringUnwrapKey = { ...KEY, bytes: KEY.bytes.slice() };
    const pending = sealKeyringEnvelope({ plaintext, unwrapKey, context: CTX });
    plaintext.fill(0);
    unwrapKey.bytes.fill(0);

    const envelope = await pending;
    expect(hex(await openKeyringEnvelope({ envelope, unwrapKey: KEY, context: CTX }))).toBe(hex(PLAINTEXT));
  });

  it("opens the envelope and key state present when the operation starts", async () => {
    const envelope = decodeKeyringEnvelope(await independentEnvelope());
    const unwrapKey: KeyringUnwrapKey = { ...KEY, bytes: KEY.bytes.slice() };
    const pending = openKeyringEnvelope({ envelope, unwrapKey, context: CTX });
    envelope.nonce.fill(0);
    envelope.ciphertext.fill(0);
    unwrapKey.bytes.fill(0);

    expect(hex(await pending)).toBe(hex(PLAINTEXT));
  });
});
