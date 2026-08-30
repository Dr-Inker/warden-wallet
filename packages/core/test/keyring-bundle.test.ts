import { describe, expect, it } from "vitest";

import type { KeyringContext } from "../src/keyring/aad.js";
import type { KeyringUnwrapKey } from "../src/keyring/derive.js";
import { startUnlockSession } from "../src/keyring/deadlines.js";
import { KeyringAuthError, KeyringExpiredError, KeyringFormatError } from "../src/keyring/errors.js";
import {
  KEYRING_BUNDLE_ID_BYTES,
  KEYRING_BUNDLE_VERSION_1,
  decodeKeyringBundle,
  encodeKeyringBundle,
  openKeyringBundle,
  sealKeyringBundle,
  type KeyringBundle,
} from "../src/keyring/bundle.js";

const fill = (n: number, value: number): Uint8Array => new Uint8Array(n).fill(value);
const hex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");

const CONTEXT: KeyringContext = {
  account: fill(32, 0x11),
  origin: "chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi",
  keyKind: "session-signer",
  schemaVersion: 1,
  genesisHash: fill(32, 0x22),
  programId: fill(32, 0x33),
};

const PASSWORD_KEY: KeyringUnwrapKey = {
  kdf: "argon2id-password",
  bytes: fill(32, 0x44),
};
const PRF_KEY: KeyringUnwrapKey = {
  kdf: "webauthn-prf-hkdf",
  bytes: fill(32, 0x55),
};
const SECRET = new TextEncoder().encode("one ciphertext, two independently authenticated unlock paths");

// Independent reference implementation. It deliberately does not call any bundle
// AAD or envelope encoder from src: otherwise the expected bytes would be derived
// from the code under test and the vector would certify only self-consistency.
function refFields(domain: string, version: number, fields: readonly Uint8Array[]): Uint8Array {
  const out: number[] = [];
  const lp = (bytes: Uint8Array): void => {
    out.push(
      (bytes.length >>> 24) & 0xff,
      (bytes.length >>> 16) & 0xff,
      (bytes.length >>> 8) & 0xff,
      bytes.length & 0xff,
      ...bytes,
    );
  };
  lp(new TextEncoder().encode(domain));
  out.push((version >>> 8) & 0xff, version & 0xff, fields.length);
  for (const field of fields) lp(field);
  return Uint8Array.from(out);
}

function refU16(value: number): Uint8Array {
  return Uint8Array.of((value >>> 8) & 0xff, value & 0xff);
}

function refU32(value: number): Uint8Array {
  return Uint8Array.of(
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  );
}

function refContextAad(context: KeyringContext, bundleVersion: number): Uint8Array {
  const text = new TextEncoder();
  return refFields("warden/keyring-envelope/aad", bundleVersion, [
    context.account,
    text.encode(context.origin),
    text.encode(context.keyKind),
    refU32(context.schemaVersion),
    context.genesisHash,
    context.programId,
  ]);
}

function refEnvelopeBytes(envelope: KeyringBundle["payload"]): Uint8Array {
  return Uint8Array.from([
    (envelope.version >>> 8) & 0xff,
    envelope.version & 0xff,
    envelope.nonce.length,
    ...envelope.nonce,
    ...refU32(envelope.ciphertext.length),
    ...envelope.ciphertext,
  ]);
}

function refWrapAad(
  context: KeyringContext,
  bundleVersion: number,
  bundleId: Uint8Array,
  kdf: KeyringUnwrapKey["kdf"],
  envelopeVersion: number,
): Uint8Array {
  return refFields("warden/keyring-bundle/wrap/aad", bundleVersion, [
    refContextAad(context, bundleVersion),
    bundleId,
    new TextEncoder().encode(kdf),
    refU16(envelopeVersion),
  ]);
}

function refPayloadAad(bundle: KeyringBundle, context: KeyringContext): Uint8Array {
  return refFields("warden/keyring-bundle/payload/aad", bundle.version, [
    refContextAad(context, bundle.version),
    bundle.bundleId,
    refU16(bundle.payload.version),
    refEnvelopeBytes(bundle.passwordWrap),
    refEnvelopeBytes(bundle.prfWrap),
  ]);
}

async function rawEncrypt(
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes as unknown as BufferSource,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );
  return new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce as unknown as BufferSource,
        additionalData: aad as unknown as BufferSource,
        tagLength: 128,
      },
      key,
      plaintext as unknown as BufferSource,
    ),
  );
}

async function rawDecrypt(
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes as unknown as BufferSource,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce as unknown as BufferSource,
        additionalData: aad as unknown as BufferSource,
        tagLength: 128,
      },
      key,
      ciphertext as unknown as BufferSource,
    ),
  );
}

async function independentBundle(): Promise<KeyringBundle> {
  const version = 1;
  const bundleId = fill(16, 0x71);
  const dek = fill(32, 0x82);
  const passwordNonce = fill(12, 0x91);
  const prfNonce = fill(12, 0x92);
  const payloadNonce = fill(12, 0x93);
  const passwordWrap = {
    version: 1,
    nonce: passwordNonce,
    ciphertext: await rawEncrypt(
      PASSWORD_KEY.bytes,
      passwordNonce,
      refWrapAad(CONTEXT, version, bundleId, PASSWORD_KEY.kdf, 1),
      dek,
    ),
  };
  const prfWrap = {
    version: 1,
    nonce: prfNonce,
    ciphertext: await rawEncrypt(
      PRF_KEY.bytes,
      prfNonce,
      refWrapAad(CONTEXT, version, bundleId, PRF_KEY.kdf, 1),
      dek,
    ),
  };
  const skeleton: KeyringBundle = {
    version,
    bundleId,
    payload: { version: 1, nonce: payloadNonce, ciphertext: fill(17, 0) },
    passwordWrap,
    prfWrap,
  };
  return {
    ...skeleton,
    payload: {
      version: 1,
      nonce: payloadNonce,
      ciphertext: await rawEncrypt(dek, payloadNonce, refPayloadAad(skeleton, CONTEXT), SECRET),
    },
  };
}

function refBundleBytes(bundle: KeyringBundle): Uint8Array {
  const components = [bundle.payload, bundle.passwordWrap, bundle.prfWrap].map(refEnvelopeBytes);
  return Uint8Array.from([
    (bundle.version >>> 8) & 0xff,
    bundle.version & 0xff,
    bundle.bundleId.length,
    ...bundle.bundleId,
    ...components.flatMap((component) => [...refU32(component.length), ...component]),
  ]);
}

function cloneBundle(bundle: KeyringBundle): KeyringBundle {
  return {
    version: bundle.version,
    bundleId: bundle.bundleId.slice(),
    payload: {
      version: bundle.payload.version,
      nonce: bundle.payload.nonce.slice(),
      ciphertext: bundle.payload.ciphertext.slice(),
    },
    passwordWrap: {
      version: bundle.passwordWrap.version,
      nonce: bundle.passwordWrap.nonce.slice(),
      ciphertext: bundle.passwordWrap.ciphertext.slice(),
    },
    prfWrap: {
      version: bundle.prfWrap.version,
      nonce: bundle.prfWrap.nonce.slice(),
      ciphertext: bundle.prfWrap.ciphertext.slice(),
    },
  };
}

describe("C2 KEK/DEK bundle: one payload ciphertext, two unlock paths", () => {
  it("accepts a bundle encrypted by independent raw WebCrypto through BOTH paths", async () => {
    const bundle = await independentBundle();
    expect(hex(await openKeyringBundle({ bundle, unwrapKey: PASSWORD_KEY, context: CONTEXT }))).toBe(hex(SECRET));
    expect(hex(await openKeyringBundle({ bundle, unwrapKey: PRF_KEY, context: CONTEXT }))).toBe(hex(SECRET));
  });

  it("produces wraps and a payload that independent raw WebCrypto can open", async () => {
    const bundle = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    const passwordDek = await rawDecrypt(
      PASSWORD_KEY.bytes,
      bundle.passwordWrap.nonce,
      refWrapAad(CONTEXT, bundle.version, bundle.bundleId, PASSWORD_KEY.kdf, bundle.passwordWrap.version),
      bundle.passwordWrap.ciphertext,
    );
    const prfDek = await rawDecrypt(
      PRF_KEY.bytes,
      bundle.prfWrap.nonce,
      refWrapAad(CONTEXT, bundle.version, bundle.bundleId, PRF_KEY.kdf, bundle.prfWrap.version),
      bundle.prfWrap.ciphertext,
    );
    expect(hex(passwordDek)).toBe(hex(prfDek));
    expect(
      hex(
        await rawDecrypt(
          passwordDek,
          bundle.payload.nonce,
          refPayloadAad(bundle, CONTEXT),
          bundle.payload.ciphertext,
        ),
      ),
    ).toBe(hex(SECRET));
  });

  it("opens the exact same payload through either the password KEK or the PRF KEK", async () => {
    const bundle = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });

    expect(bundle.bundleId.length).toBe(KEYRING_BUNDLE_ID_BYTES);
    expect(bundle.version).toBe(KEYRING_BUNDLE_VERSION_1);
    const payloadBefore = hex(bundle.payload.ciphertext);

    const fromPassword = await openKeyringBundle({ bundle, unwrapKey: PASSWORD_KEY, context: CONTEXT });
    const fromPrf = await openKeyringBundle({ bundle, unwrapKey: PRF_KEY, context: CONTEXT });

    expect(hex(fromPassword)).toBe(hex(SECRET));
    expect(hex(fromPrf)).toBe(hex(SECRET));
    expect(hex(bundle.payload.ciphertext)).toBe(payloadBefore);
    expect(hex(bundle.passwordWrap.ciphertext)).not.toBe(hex(bundle.prfWrap.ciphertext));
  });

  it("uses fresh bundle ids, payload nonces, and wrap nonces on every seal", async () => {
    const first = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    const second = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });

    expect(hex(first.bundleId)).not.toBe(hex(second.bundleId));
    expect(hex(first.payload.nonce)).not.toBe(hex(second.payload.nonce));
    expect(hex(first.passwordWrap.nonce)).not.toBe(hex(second.passwordWrap.nonce));
    expect(hex(first.prfWrap.nonce)).not.toBe(hex(second.prfWrap.nonce));
  });

  it("snapshots caller-owned key, plaintext, and context bytes before the first async suspension", async () => {
    const passwordKey: KeyringUnwrapKey = { ...PASSWORD_KEY, bytes: PASSWORD_KEY.bytes.slice() };
    const prfKey: KeyringUnwrapKey = { ...PRF_KEY, bytes: PRF_KEY.bytes.slice() };
    const plaintext = SECRET.slice();
    const context: KeyringContext = {
      ...CONTEXT,
      account: CONTEXT.account.slice(),
      genesisHash: CONTEXT.genesisHash.slice(),
      programId: CONTEXT.programId.slice(),
    };

    const pending = sealKeyringBundle({ plaintext, passwordKey, prfKey, context });
    // A lock handler is allowed to zero caller-owned session buffers as soon as the
    // async API returns. That must not create a half-old/half-zero persistent record.
    plaintext.fill(0);
    passwordKey.bytes.fill(0);
    prfKey.bytes.fill(0);
    context.account.fill(0);
    context.genesisHash.fill(0);
    context.programId.fill(0);

    const bundle = await pending;
    expect(hex(await openKeyringBundle({ bundle, unwrapKey: PASSWORD_KEY, context: CONTEXT }))).toBe(hex(SECRET));
    expect(hex(await openKeyringBundle({ bundle, unwrapKey: PRF_KEY, context: CONTEXT }))).toBe(hex(SECRET));
  });

  it("opens one canonical snapshot when caller-owned bundle, key, and context bytes change mid-flight", async () => {
    const original = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    const bundle = cloneBundle(original);
    const unwrapKey: KeyringUnwrapKey = { ...PASSWORD_KEY, bytes: PASSWORD_KEY.bytes.slice() };
    const context: KeyringContext = {
      ...CONTEXT,
      account: CONTEXT.account.slice(),
      genesisHash: CONTEXT.genesisHash.slice(),
      programId: CONTEXT.programId.slice(),
    };

    const pending = openKeyringBundle({ bundle, unwrapKey, context });
    bundle.bundleId.fill(0);
    bundle.payload.nonce.fill(0);
    bundle.payload.ciphertext.fill(0);
    bundle.passwordWrap.nonce.fill(0);
    bundle.passwordWrap.ciphertext.fill(0);
    bundle.prfWrap.nonce.fill(0);
    bundle.prfWrap.ciphertext.fill(0);
    unwrapKey.bytes.fill(0);
    context.account.fill(0);
    context.genesisHash.fill(0);
    context.programId.fill(0);

    expect(hex(await pending)).toBe(hex(SECRET));
  });

  it("refuses a fake fallback where both labelled paths use identical key bytes", async () => {
    await expect(
      sealKeyringBundle({
        plaintext: SECRET,
        passwordKey: PASSWORD_KEY,
        prfKey: { kdf: "webauthn-prf-hkdf", bytes: PASSWORD_KEY.bytes.slice() },
        context: CONTEXT,
      }),
    ).rejects.toThrow(/independent/);
  });

  it("rejects a wrong password through AEAD rather than a password comparison", async () => {
    const bundle = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    const wrong: KeyringUnwrapKey = { kdf: "argon2id-password", bytes: fill(32, 0x45) };
    await expect(openKeyringBundle({ bundle, unwrapKey: wrong, context: CONTEXT })).rejects.toThrow(
      KeyringAuthError,
    );
  });

  it("refuses empty payloads, swapped setup labels, and unsupported versions", async () => {
    await expect(
      sealKeyringBundle({ plaintext: new Uint8Array(0), passwordKey: PASSWORD_KEY, prfKey: PRF_KEY, context: CONTEXT }),
    ).rejects.toThrow(/empty plaintext/);
    await expect(
      sealKeyringBundle({ plaintext: SECRET, passwordKey: PRF_KEY, prfKey: PASSWORD_KEY, context: CONTEXT }),
    ).rejects.toThrow(/expected argon2id-password/);
    await expect(
      sealKeyringBundle({ plaintext: SECRET, passwordKey: PASSWORD_KEY, prfKey: PRF_KEY, context: CONTEXT, version: 2 }),
    ).rejects.toThrow(/unknown bundle version 2/);
  });

  it("enforces an existing unlock deadline before sealing or opening", async () => {
    const deadlines = startUnlockSession(1_000, { idleTimeoutMs: 100, hardTimeoutMs: 500 });
    const bundle = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    await expect(
      sealKeyringBundle({
        plaintext: SECRET,
        passwordKey: PASSWORD_KEY,
        prfKey: PRF_KEY,
        context: CONTEXT,
        unlock: { deadlines, now: 1_100 },
      }),
    ).rejects.toThrow(KeyringExpiredError);
    await expect(
      openKeyringBundle({ bundle, unwrapKey: PASSWORD_KEY, context: CONTEXT, unlock: { deadlines, now: 1_100 } }),
    ).rejects.toThrow(KeyringExpiredError);
  });
});

describe("the bundle is one authenticated unit, including the unused wrap", () => {
  it("tampering the UNUSED PRF wrap makes password unlock fail closed", async () => {
    const bundle = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    const tampered = cloneBundle(bundle);
    tampered.prfWrap.ciphertext[0] ^= 0x01;

    await expect(openKeyringBundle({ bundle: tampered, unwrapKey: PASSWORD_KEY, context: CONTEXT })).rejects.toThrow(
      KeyringAuthError,
    );
  });

  it("tampering the UNUSED password wrap makes PRF unlock fail closed", async () => {
    const bundle = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    const tampered = cloneBundle(bundle);
    tampered.passwordWrap.ciphertext[tampered.passwordWrap.ciphertext.length - 1] ^= 0x80;

    await expect(openKeyringBundle({ bundle: tampered, unwrapKey: PRF_KEY, context: CONTEXT })).rejects.toThrow(
      KeyringAuthError,
    );
  });

  it("rejects a wrap spliced from a different bundle through BOTH unlock paths", async () => {
    const first = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    const second = await sealKeyringBundle({
      plaintext: new TextEncoder().encode("different secret"),
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    const spliced = { ...cloneBundle(first), prfWrap: cloneBundle(second).prfWrap };

    await expect(openKeyringBundle({ bundle: spliced, unwrapKey: PASSWORD_KEY, context: CONTEXT })).rejects.toThrow(
      KeyringAuthError,
    );
    await expect(openKeyringBundle({ bundle: spliced, unwrapKey: PRF_KEY, context: CONTEXT })).rejects.toThrow(
      KeyringAuthError,
    );
  });

  it("rejects swapping the password and PRF wrap positions", async () => {
    const original = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    const cloned = cloneBundle(original);
    const swapped = { ...cloned, passwordWrap: cloned.prfWrap, prfWrap: cloned.passwordWrap };

    await expect(openKeyringBundle({ bundle: swapped, unwrapKey: PASSWORD_KEY, context: CONTEXT })).rejects.toThrow(
      KeyringAuthError,
    );
    await expect(openKeyringBundle({ bundle: swapped, unwrapKey: PRF_KEY, context: CONTEXT })).rejects.toThrow(
      KeyringAuthError,
    );
  });
});

describe("bundle context and wire-format binding", () => {
  it("authenticates bundle and component versions instead of merely parsing their headers", async () => {
    const original = await independentBundle();
    const dek = fill(32, 0x82);
    const wrongWrapVersionAad: KeyringBundle = {
      ...cloneBundle(original),
      passwordWrap: {
        ...original.passwordWrap,
        ciphertext: await rawEncrypt(
          PASSWORD_KEY.bytes,
          original.passwordWrap.nonce,
          refWrapAad(CONTEXT, 2, original.bundleId, PASSWORD_KEY.kdf, original.passwordWrap.version),
          dek,
        ),
      },
    };
    await expect(
      openKeyringBundle({ bundle: wrongWrapVersionAad, unwrapKey: PASSWORD_KEY, context: CONTEXT }),
    ).rejects.toThrow(KeyringAuthError);

    const wrongPayloadVersionAad = cloneBundle(original);
    const claimedV2 = { ...wrongPayloadVersionAad, version: 2 };
    const payloadSealedAsV2: KeyringBundle = {
      ...wrongPayloadVersionAad,
      payload: {
        ...wrongPayloadVersionAad.payload,
        ciphertext: await rawEncrypt(
          dek,
          wrongPayloadVersionAad.payload.nonce,
          refPayloadAad(claimedV2, CONTEXT),
          SECRET,
        ),
      },
    };
    await expect(
      openKeyringBundle({ bundle: payloadSealedAsV2, unwrapKey: PASSWORD_KEY, context: CONTEXT }),
    ).rejects.toThrow(KeyringAuthError);
  });

  it("rejects a cross-cluster transplant even when the SmartAccount address is identical", async () => {
    const devnet = { ...CONTEXT, genesisHash: fill(32, 0x66) };
    const mainnet = { ...CONTEXT, genesisHash: fill(32, 0x77) };
    const bundle = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: devnet,
    });

    expect(hex(devnet.account)).toBe(hex(mainnet.account));
    await expect(openKeyringBundle({ bundle, unwrapKey: PASSWORD_KEY, context: mainnet })).rejects.toThrow(
      KeyringAuthError,
    );
    await expect(openKeyringBundle({ bundle, unwrapKey: PRF_KEY, context: mainnet })).rejects.toThrow(
      KeyringAuthError,
    );
  });

  it("strictly round-trips the persistent binary form", async () => {
    const bundle = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    const bytes = encodeKeyringBundle(bundle);
    const decoded = decodeKeyringBundle(bytes);

    expect(hex(encodeKeyringBundle(decoded))).toBe(hex(bytes));
    expect(hex(await openKeyringBundle({ bundle: bytes, unwrapKey: PASSWORD_KEY, context: CONTEXT }))).toBe(
      hex(SECRET),
    );
  });

  it("matches a hand-built persistent wire encoding and decodes those bytes", async () => {
    const bundle = await independentBundle();
    const expected = refBundleBytes(bundle);
    expect(hex(encodeKeyringBundle(bundle))).toBe(hex(expected));
    expect(hex(encodeKeyringBundle(decodeKeyringBundle(expected)))).toBe(hex(expected));
  });

  it("rejects unknown versions before trusting component lengths", async () => {
    const bundle = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    const bytes = encodeKeyringBundle(bundle);
    bytes[0] = 0;
    bytes[1] = 2;
    expect(() => decodeKeyringBundle(bytes)).toThrow(/unknown bundle version 2/);
  });

  it("rejects a wrong id length, truncation, trailing bytes, and component-length lies", async () => {
    const bundle = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    const bytes = encodeKeyringBundle(bundle);

    const wrongIdLength = bytes.slice();
    wrongIdLength[2] = KEYRING_BUNDLE_ID_BYTES - 1;
    expect(() => decodeKeyringBundle(wrongIdLength)).toThrow(/bundle id/);
    expect(() => decodeKeyringBundle(bytes.subarray(0, bytes.length - 1))).toThrow(KeyringFormatError);
    expect(() => decodeKeyringBundle(Uint8Array.from([...bytes, 0]))).toThrow(/trailing/);

    const componentLengthOffset = 3 + KEYRING_BUNDLE_ID_BYTES;
    const lied = bytes.slice();
    lied[componentLengthOffset + 3] ^= 0x01;
    expect(() => decodeKeyringBundle(lied)).toThrow(KeyringFormatError);
  });

  it("rejects a runtime-invented KDF label instead of choosing a default wrap", async () => {
    const bundle = await sealKeyringBundle({
      plaintext: SECRET,
      passwordKey: PASSWORD_KEY,
      prfKey: PRF_KEY,
      context: CONTEXT,
    });
    const invented = { kdf: "legacy-pbkdf2", bytes: fill(32, 0x44) } as unknown as KeyringUnwrapKey;
    await expect(openKeyringBundle({ bundle, unwrapKey: invented, context: CONTEXT })).rejects.toThrow(
      KeyringFormatError,
    );
  });
});
