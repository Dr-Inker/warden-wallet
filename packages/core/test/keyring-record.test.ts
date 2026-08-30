import { describe, expect, it, vi } from "vitest";

import type { KeyringContext } from "../src/keyring/aad.js";
import type { Argon2idParams } from "../src/keyring/derive.js";
import { startUnlockSession } from "../src/keyring/deadlines.js";
import {
  KeyringAuthError,
  KeyringExpiredError,
  KeyringFormatError,
  KeyringLockedError,
} from "../src/keyring/errors.js";
import type { KeyringBundle } from "../src/keyring/bundle.js";
import {
  KEYRING_PASSWORD_SALT_BYTES,
  KEYRING_PRF_HKDF_SALT_BYTES,
  KEYRING_PRF_INPUT_BYTES,
  KEYRING_RECORD_STORAGE_PREFIX,
  KEYRING_RECORD_VERSION_1,
  KEYRING_RECORD_VERSION_2,
  MAX_KEYRING_RECORD_STORAGE_CHARS,
  decodeKeyringRecord,
  decodeKeyringRecordStorageValue,
  encodeKeyringRecord,
  encodeKeyringRecordStorageValue,
  openKeyringRecordWithPasswordBytes,
  openKeyringRecordWithPrfBytes,
  prepareKeyringRecordMetadata,
  sealKeyringRecord,
  type KeyringRecord,
  type KeyringRecordMetadata,
} from "../src/keyring/record.js";

const fill = (length: number, value: number): Uint8Array => new Uint8Array(length).fill(value);
const hex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
const password = (): Uint8Array => new TextEncoder().encode("correct horse battery staple");

/** Fast test-only cost, never a product floor. */
const FAST: Argon2idParams = { memoryKiB: 64, timeCost: 1, parallelism: 1 };
const CONTEXT: KeyringContext = {
  account: fill(32, 0x11),
  origin: "chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi",
  keyKind: "session-signer",
  schemaVersion: 1,
  genesisHash: fill(32, 0x22),
  programId: fill(32, 0x33),
};
const SECRET = new TextEncoder().encode("persistent keyring payload");
const PRF_OUTPUT = fill(32, 0x7a);

function cloneMetadata(metadata: KeyringRecordMetadata): KeyringRecordMetadata {
  const common = {
    version: metadata.version,
    argon2id: {
      params: { ...metadata.argon2id.params },
      salt: metadata.argon2id.salt.slice(),
    },
    prf:
      metadata.prf === null
        ? null
        : {
            input: metadata.prf.input.slice(),
            hkdfSalt: metadata.prf.hkdfSalt.slice(),
          },
  };
  return metadata.version === KEYRING_RECORD_VERSION_1
    ? { ...common, version: KEYRING_RECORD_VERSION_1 }
    : {
        ...common,
        version: KEYRING_RECORD_VERSION_2,
        context: {
          ...metadata.context,
          account: metadata.context.account.slice(),
          genesisHash: metadata.context.genesisHash.slice(),
          programId: metadata.context.programId.slice(),
        },
      };
}

function prepared(enablePrf: boolean) {
  return prepareKeyringRecordMetadata({
    argon2idParams: FAST,
    enablePrf,
    context: CONTEXT,
  });
}

async function dualRecord(): Promise<KeyringRecord> {
  return sealKeyringRecord({
    metadata: prepared(true),
    plaintext: SECRET.slice(),
    passwordBytes: password(),
    prfOutput: PRF_OUTPUT.slice(),
  });
}

function u32(value: number): number[] {
  return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
}

function refEnvelope(envelope: KeyringBundle["payload"]): number[] {
  return [
    (envelope.version >>> 8) & 0xff,
    envelope.version & 0xff,
    envelope.nonce.length,
    ...envelope.nonce,
    ...u32(envelope.ciphertext.length),
    ...envelope.ciphertext,
  ];
}

function refBundle(bundle: KeyringBundle): Uint8Array {
  const components = [
    Uint8Array.from(refEnvelope(bundle.payload)),
    Uint8Array.from(refEnvelope(bundle.passwordWrap)),
    bundle.prfWrap === null ? new Uint8Array(0) : Uint8Array.from(refEnvelope(bundle.prfWrap)),
  ];
  return Uint8Array.from([
    (bundle.version >>> 8) & 0xff,
    bundle.version & 0xff,
    bundle.bundleId.length,
    ...bundle.bundleId,
    ...components.flatMap((component) => [...u32(component.length), ...component]),
  ]);
}

function fixtureRecord(withPrf: boolean): KeyringRecord {
  const envelope = (nonceByte: number, ciphertextLength: number, ciphertextByte: number) => ({
    version: 1,
    nonce: fill(12, nonceByte),
    ciphertext: fill(ciphertextLength, ciphertextByte),
  });
  return {
    metadata: {
      version: 1,
      argon2id: { params: FAST, salt: fill(16, 0x41) },
      prf: withPrf ? { input: fill(32, 0x42), hkdfSalt: fill(16, 0x43) } : null,
    },
    bundle: {
      version: 1,
      bundleId: fill(16, 0x44),
      payload: envelope(0x45, 17, 0x46),
      passwordWrap: envelope(0x47, 48, 0x48),
      prfWrap: withPrf ? envelope(0x49, 48, 0x4a) : null,
    },
  };
}

describe("C2 persistent record metadata and storage representation", () => {
  it("generates fresh fixed-width salts/PRF inputs without an injectable RNG", () => {
    expect(KEYRING_RECORD_VERSION_1).toBe(1);
    expect(KEYRING_RECORD_VERSION_2).toBe(2);
    expect(KEYRING_PASSWORD_SALT_BYTES).toBe(16);
    expect(KEYRING_PRF_INPUT_BYTES).toBe(32);
    expect(KEYRING_PRF_HKDF_SALT_BYTES).toBe(16);

    const first = prepared(true);
    const second = prepared(true);
    expect(first.argon2id.salt.length).toBe(KEYRING_PASSWORD_SALT_BYTES);
    expect(first.prf?.input.length).toBe(KEYRING_PRF_INPUT_BYTES);
    expect(first.prf?.hkdfSalt.length).toBe(KEYRING_PRF_HKDF_SALT_BYTES);
    expect(hex(first.argon2id.salt)).not.toBe(hex(second.argon2id.salt));
    expect(hex(first.prf!.input)).not.toBe(hex(second.prf!.input));
    expect(hex(first.prf!.hkdfSalt)).not.toBe(hex(second.prf!.hkdfSalt));
  });

  it("serializes the whole record as one canonical JSON-safe string", async () => {
    const record = await dualRecord();
    const value = encodeKeyringRecordStorageValue(record);
    expect(typeof value).toBe("string");
    expect(value.startsWith(KEYRING_RECORD_STORAGE_PREFIX)).toBe(true);
    expect(value).not.toContain("=");

    const decoded = decodeKeyringRecordStorageValue(value);
    expect(hex(encodeKeyringRecord(decoded))).toBe(hex(encodeKeyringRecord(record)));
    const passwordBytes = password();
    expect(hex(await openKeyringRecordWithPasswordBytes({ record: value, passwordBytes }))).toBe(
      hex(SECRET),
    );
    expect(Array.from(passwordBytes)).toEqual(new Array(passwordBytes.length).fill(0));
    const prfOutput = PRF_OUTPUT.slice();
    expect(
      hex(
        await openKeyringRecordWithPrfBytes({
          record: value,
          prfOutput,
        }),
      ),
    ).toBe(hex(SECRET));
    expect(Array.from(prfOutput)).toEqual(new Array(prfOutput.length).fill(0));
  });

  it("matches the platform's independent base64url encoder exactly", () => {
    const record = fixtureRecord(true);
    const bytes = encodeKeyringRecord(record);
    const expected = Buffer.from(bytes).toString("base64url");
    expect(encodeKeyringRecordStorageValue(record)).toBe(KEYRING_RECORD_STORAGE_PREFIX + expected);
  });

  it("matches a hand-built binary wire encoding rather than a production-derived expectation", () => {
    const record = fixtureRecord(true);
    const bundle = refBundle(record.bundle);
    const expected = Uint8Array.from([
      0,
      1, // record version
      1, // flags: PRF present
      ...u32(FAST.memoryKiB),
      ...u32(FAST.timeCost),
      ...u32(FAST.parallelism),
      ...fill(16, 0x41),
      ...fill(32, 0x42),
      ...fill(16, 0x43),
      ...u32(bundle.length),
      ...bundle,
    ]);
    expect(hex(encodeKeyringRecord(record))).toBe(hex(expected));
    expect(hex(encodeKeyringRecord(decodeKeyringRecord(expected)))).toBe(hex(expected));
  });

  it("supports a password-only record when WebAuthn PRF is unavailable", async () => {
    const metadata = prepared(false);
    const record = await sealKeyringRecord({
      metadata,
      plaintext: SECRET.slice(),
      passwordBytes: password(),
    });
    expect(record.metadata.prf).toBeNull();
    expect(record.bundle.prfWrap).toBeNull();
    expect(
      hex(await openKeyringRecordWithPasswordBytes({ record, passwordBytes: password() })),
    ).toBe(hex(SECRET));
    await expect(
      openKeyringRecordWithPrfBytes({ record, prfOutput: PRF_OUTPUT.slice() }),
    ).rejects.toThrow(KeyringAuthError);
  });

  it("keeps record v1 available only through an explicit legacy context", async () => {
    const record = await sealKeyringRecord({
      metadata: {
        version: KEYRING_RECORD_VERSION_1,
        argon2id: {
          params: FAST,
          salt: fill(KEYRING_PASSWORD_SALT_BYTES, 0x81),
        },
        prf: null,
      },
      plaintext: SECRET.slice(),
      passwordBytes: password(),
      context: CONTEXT,
    });

    await expect(
      openKeyringRecordWithPasswordBytes({
        record,
        passwordBytes: password(),
      }),
    ).rejects.toThrow(/record v1 requires an explicit legacy context/);
    await expect(
      openKeyringRecordWithPasswordBytes({
        record,
        passwordBytes: password(),
        context: CONTEXT,
      }),
    ).resolves.toEqual(SECRET);
  });

  it("zeroes caller-owned password, PRF output, and plaintext buffers on success", async () => {
    const passwordBytes = password();
    const prfOutput = PRF_OUTPUT.slice();
    const plaintext = SECRET.slice();
    await sealKeyringRecord({
      metadata: prepared(true),
      plaintext,
      passwordBytes,
      prfOutput,
    });
    expect(Array.from(passwordBytes)).toEqual(new Array(passwordBytes.length).fill(0));
    expect(Array.from(prfOutput)).toEqual(new Array(prfOutput.length).fill(0));
    expect(Array.from(plaintext)).toEqual(new Array(plaintext.length).fill(0));
  });
});

describe("outer metadata is authenticated, including an unused fallback", () => {
  it("makes PRF unlock reject a tampered password salt or Argon2 parameter", async () => {
    const record = await dualRecord();
    const saltTamper = cloneMetadata(record.metadata);
    saltTamper.argon2id.salt[0] ^= 1;
    const paramsTamper = cloneMetadata(record.metadata);
    paramsTamper.argon2id.params = { ...paramsTamper.argon2id.params, timeCost: 2 };

    for (const metadata of [saltTamper, paramsTamper]) {
      await expect(
        openKeyringRecordWithPrfBytes({
          record: { metadata, bundle: record.bundle },
          prfOutput: PRF_OUTPUT.slice(),
        }),
      ).rejects.toThrow(KeyringAuthError);
    }
  });

  it("makes password unlock reject a tampered PRF input or HKDF salt", async () => {
    const record = await dualRecord();
    const inputTamper = cloneMetadata(record.metadata);
    inputTamper.prf!.input[0] ^= 1;
    const saltTamper = cloneMetadata(record.metadata);
    saltTamper.prf!.hkdfSalt[0] ^= 1;

    for (const metadata of [inputTamper, saltTamper]) {
      await expect(
        openKeyringRecordWithPasswordBytes({
          record: { metadata, bundle: record.bundle },
          passwordBytes: password(),
        }),
      ).rejects.toThrow(KeyringAuthError);
    }
  });

  it("rejects a bundle spliced under another valid record header through both paths", async () => {
    const first = await dualRecord();
    const second = await dualRecord();
    const spliced: KeyringRecord = { metadata: first.metadata, bundle: second.bundle };

    await expect(
      openKeyringRecordWithPasswordBytes({ record: spliced, passwordBytes: password() }),
    ).rejects.toThrow(KeyringAuthError);
    await expect(
      openKeyringRecordWithPrfBytes({
        record: spliced,
        prfOutput: PRF_OUTPUT.slice(),
      }),
    ).rejects.toThrow(KeyringAuthError);
  });

  it("snapshots prepared metadata before the async seal can observe caller mutation", async () => {
    const metadata = prepared(true);
    const expected = cloneMetadata(metadata);
    const pending = sealKeyringRecord({
      metadata,
      plaintext: SECRET.slice(),
      passwordBytes: password(),
      prfOutput: PRF_OUTPUT.slice(),
    });
    metadata.argon2id.salt.fill(0);
    metadata.prf!.input.fill(0);
    metadata.prf!.hkdfSalt.fill(0);
    const record = await pending;
    expect(hex(record.metadata.argon2id.salt)).toBe(hex(expected.argon2id.salt));
    expect(hex(record.metadata.prf!.input)).toBe(hex(expected.prf!.input));
    expect(
      hex(await openKeyringRecordWithPasswordBytes({ record, passwordBytes: password() })),
    ).toBe(hex(SECRET));
  });
});

describe("record orchestration cannot carry a stale clock sample across derivation", () => {
  it("re-checks after synchronous Argon2id and wipes all caller-owned secrets on expiry", async () => {
    const deadlines = startUnlockSession(1_000, { idleTimeoutMs: 100, hardTimeoutMs: 500 });
    let reads = 0;
    const unlock = {
      deadlines,
      readNow: () => (reads++ === 0 ? 1_001 : deadlines.idleExpiresAt),
      signal: new AbortController().signal,
    };
    const passwordBytes = password();
    const plaintext = SECRET.slice();
    await expect(
      sealKeyringRecord({
        metadata: prepared(false),
        plaintext,
        passwordBytes,
        unlock,
      }),
    ).rejects.toThrow(KeyringExpiredError);
    expect(reads).toBe(2);
    expect(Array.from(passwordBytes)).toEqual(new Array(passwordBytes.length).fill(0));
    expect(Array.from(plaintext)).toEqual(new Array(plaintext.length).fill(0));

    const record = await sealKeyringRecord({
      metadata: prepared(false),
      plaintext: SECRET.slice(),
      passwordBytes: password(),
    });
    reads = 0;
    const unlockPassword = password();
    await expect(
      openKeyringRecordWithPasswordBytes({
        record,
        passwordBytes: unlockPassword,
        unlock,
      }),
    ).rejects.toThrow(KeyringExpiredError);
    expect(reads).toBe(2);
    expect(Array.from(unlockPassword)).toEqual(new Array(unlockPassword.length).fill(0));
  });

  it("lock zeroes JS-owned secrets before a stalled WebCrypto operation settles", async () => {
    const deadlines = startUnlockSession(1_000, { idleTimeoutMs: 100, hardTimeoutMs: 500 });
    const controller = new AbortController();
    const passwordBytes = password();
    const plaintext = SECRET.slice();
    const subtle = globalThis.crypto.subtle;
    const originalEncrypt = subtle.encrypt;
    let capturedAeadPlaintext: Uint8Array | undefined;
    let enterEncrypt!: () => void;
    const encryptEntered = new Promise<void>((resolve) => {
      enterEncrypt = resolve;
    });
    let releaseEncrypt!: () => void;
    const encryptGate = new Promise<void>((resolve) => {
      releaseEncrypt = resolve;
    });
    const encryptSpy = vi.spyOn(subtle, "encrypt").mockImplementation(
      (async (...args: unknown[]) => {
        const input = args[2] as BufferSource;
        capturedAeadPlaintext = ArrayBuffer.isView(input)
          ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
          : new Uint8Array(input);
        // Start the real operation first. WebCrypto has copied its input before its
        // Promise is returned; the artificial gate stalls only our observable result.
        const platformResult = Reflect.apply(originalEncrypt, subtle, args) as Promise<ArrayBuffer>;
        enterEncrypt();
        await encryptGate;
        return platformResult;
      }) as typeof subtle.encrypt,
    );
    let pending: Promise<KeyringRecord> | undefined;
    let settled = false;
    try {
      pending = sealKeyringRecord({
        metadata: prepared(false),
        plaintext,
        passwordBytes,
        unlock: {
          deadlines,
          readNow: () => 1_001,
          signal: controller.signal,
        },
      });
      void pending.then(
        () => {
          settled = true;
        },
        () => {
          settled = true;
        },
      );
      await encryptEntered;
      controller.abort();

      expect(settled).toBe(false);
      expect(Array.from(passwordBytes)).toEqual(new Array(passwordBytes.length).fill(0));
      expect(Array.from(plaintext)).toEqual(new Array(plaintext.length).fill(0));
      expect(capturedAeadPlaintext).toBeDefined();
      expect(Array.from(capturedAeadPlaintext!)).toEqual(
        new Array(capturedAeadPlaintext!.length).fill(0),
      );

      releaseEncrypt();
      await expect(pending).rejects.toThrow(KeyringLockedError);
    } finally {
      releaseEncrypt();
      await pending?.catch(() => undefined);
      encryptSpy.mockRestore();
    }
  });
});

describe("strict persistent parser and storage codec", () => {
  it("rejects unknown versions and flags before trusting the bundle length", () => {
    expect(() => decodeKeyringRecord(Uint8Array.of(0, 3, 0xff, 0xff, 0xff, 0xff))).toThrow(/unknown record version/);
    const bytes = encodeKeyringRecord(fixtureRecord(true));
    bytes[2] = 0x80;
    expect(() => decodeKeyringRecord(bytes)).toThrow(/unknown record flags/);
  });

  it("rejects attacker-sized KDF costs before any Argon2 allocation", () => {
    const bytes = encodeKeyringRecord(fixtureRecord(true));
    bytes.set([0xff, 0xff, 0xff, 0xff], 3);
    expect(() => decodeKeyringRecord(bytes)).toThrow(/memoryKiB must be at most/);
  });

  it("rejects truncation, trailing bytes, and bundle-length lies", () => {
    const bytes = encodeKeyringRecord(fixtureRecord(true));
    for (let cut = 0; cut < bytes.length; cut++) {
      expect(() => decodeKeyringRecord(bytes.slice(0, cut))).toThrow(KeyringFormatError);
    }
    expect(() => decodeKeyringRecord(Uint8Array.from([...bytes, 0]))).toThrow(/trailing|length/);
    const lied = bytes.slice();
    const bundleLengthOffset = 2 + 1 + 12 + 16 + 32 + 16;
    lied.set([0, 0, 0, 1], bundleLengthOffset);
    expect(() => decodeKeyringRecord(lied)).toThrow(/trailing|length|bundle/);
  });

  it("rejects a PRF metadata/wrap presence mismatch", () => {
    const dual = fixtureRecord(true);
    expect(() => encodeKeyringRecord({ ...dual, metadata: { ...dual.metadata, prf: null } })).toThrow(
      /PRF metadata and wrap must either both be present or both be absent/,
    );
    const passwordOnly = fixtureRecord(false);
    expect(() =>
      encodeKeyringRecord({
        ...passwordOnly,
        metadata: { ...passwordOnly.metadata, prf: { input: fill(32, 1), hkdfSalt: fill(16, 2) } },
      }),
    ).toThrow(/PRF metadata and wrap must either both be present or both be absent/);
  });

  it("rejects non-string Chrome values, wrong prefixes, padding, alphabet errors, and non-canonical tails", () => {
    expect(() => decodeKeyringRecordStorageValue({})).toThrow(/must be a string/);
    expect(() => decodeKeyringRecordStorageValue(new Uint8Array(4))).toThrow(/must be a string/);
    expect(() => decodeKeyringRecordStorageValue("wrong:AAAA")).toThrow(/prefix/);
    expect(() => decodeKeyringRecordStorageValue(KEYRING_RECORD_STORAGE_PREFIX + "AA==")).toThrow(/padding|alphabet/);
    expect(() => decodeKeyringRecordStorageValue(KEYRING_RECORD_STORAGE_PREFIX + "AA*")).toThrow(/alphabet/);
    expect(() => decodeKeyringRecordStorageValue(KEYRING_RECORD_STORAGE_PREFIX + "A")).toThrow(/length/);
    expect(() => decodeKeyringRecordStorageValue(KEYRING_RECORD_STORAGE_PREFIX + "AB")).toThrow(/non-canonical/);
    expect(() =>
      decodeKeyringRecordStorageValue(
        KEYRING_RECORD_STORAGE_PREFIX + "A".repeat(MAX_KEYRING_RECORD_STORAGE_CHARS + 1),
      ),
    ).toThrow(/exceeds the cap/);
  });

  it("zeroes secret inputs even when record validation fails before derivation", async () => {
    const metadata = prepared(true);
    metadata.argon2id.salt = fill(3, 0);
    const passwordBytes = password();
    const prfOutput = PRF_OUTPUT.slice();
    const plaintext = SECRET.slice();
    await expect(
      sealKeyringRecord({ metadata, passwordBytes, prfOutput, plaintext }),
    ).rejects.toThrow(KeyringFormatError);
    expect(Array.from(passwordBytes)).toEqual(new Array(passwordBytes.length).fill(0));
    expect(Array.from(prfOutput)).toEqual(new Array(prfOutput.length).fill(0));
    expect(Array.from(plaintext)).toEqual(new Array(plaintext.length).fill(0));
  });
});
