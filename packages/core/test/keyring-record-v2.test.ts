import { describe, expect, it } from "vitest";

import {
  KEYRING_RECORD_VERSION_2,
  MAX_KEYRING_RECORD_CONTEXT_BYTES,
  KeyringAuthError,
  KeyringFormatError,
  decodeKeyringRecordStorageValue,
  decodeKeyringRecord,
  encodeKeyringRecord,
  encodeKeyringRecordStorageValue,
  encodeSessionSignerPayload,
  getKeyringRecordContext,
  openKeyringRecordWithPasswordBytes,
  prepareKeyringRecordMetadata,
  sealKeyringRecord,
  type KeyringContext,
} from "../src/keyring/index.js";

const fill = (length: number, value: number): Uint8Array =>
  new Uint8Array(length).fill(value);
const password = (): Uint8Array =>
  new TextEncoder().encode("self-contained record password");
const CONTEXT: KeyringContext = {
  account: fill(32, 0x11),
  origin: "chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi",
  keyKind: "session-signer",
  schemaVersion: 1,
  genesisHash: fill(32, 0x22),
  programId: fill(32, 0x33),
};
const FAST = { memoryKiB: 64, timeCost: 1, parallelism: 1 } as const;

async function selfContainedRecord(context: KeyringContext = CONTEXT) {
  return sealKeyringRecord({
    metadata: prepareKeyringRecordMetadata({
      argon2idParams: FAST,
      enablePrf: false,
      context,
    }),
    plaintext: encodeSessionSignerPayload(fill(32, 0x44)),
    passwordBytes: password(),
  });
}

describe("self-contained keyring record v2", () => {
  it("persists a copy-owned complete context and opens without caller-resupplied context", async () => {
    const mutableContext = {
      ...CONTEXT,
      account: CONTEXT.account.slice(),
      genesisHash: CONTEXT.genesisHash.slice(),
      programId: CONTEXT.programId.slice(),
    };
    const pending = selfContainedRecord(mutableContext);
    mutableContext.account.fill(0);
    mutableContext.genesisHash.fill(0);
    mutableContext.programId.fill(0);
    const stored = encodeKeyringRecordStorageValue(await pending);
    const decoded = decodeKeyringRecordStorageValue(stored);

    expect(decoded.metadata.version).toBe(KEYRING_RECORD_VERSION_2);
    const first = getKeyringRecordContext(decoded);
    expect(first).toEqual(CONTEXT);
    first.account.fill(0);
    first.genesisHash.fill(0);
    first.programId.fill(0);
    expect(getKeyringRecordContext(decoded)).toEqual(CONTEXT);

    await expect(
      openKeyringRecordWithPasswordBytes({ record: stored, passwordBytes: password() }),
    ).resolves.toEqual(encodeSessionSignerPayload(fill(32, 0x44)));
  });

  it("refuses a caller-supplied context for v2 instead of reopening context selection", async () => {
    const record = await selfContainedRecord();
    const supplied = {
      ...CONTEXT,
      account: fill(32, 0x99),
    };
    const secret = password();

    await expect(
      openKeyringRecordWithPasswordBytes({
        record,
        passwordBytes: secret,
        context: supplied,
      }),
    ).rejects.toThrow(KeyringFormatError);
    expect(secret).toEqual(new Uint8Array(secret.length));
  });

  it("authenticates the persisted context so one-bit metadata tampering cannot relocate a record", async () => {
    const record = await selfContainedRecord();
    const decoded = decodeKeyringRecordStorageValue(
      encodeKeyringRecordStorageValue(record),
    );
    if (decoded.metadata.version !== KEYRING_RECORD_VERSION_2) {
      throw new Error("test fixture did not produce v2");
    }
    const tamperedAccount = decoded.metadata.context.account.slice();
    tamperedAccount[0] ^= 1;
    const tampered = {
      ...decoded,
      metadata: {
        ...decoded.metadata,
        context: { ...decoded.metadata.context, account: tamperedAccount },
      },
    };

    await expect(
      openKeyringRecordWithPasswordBytes({
        record: tampered,
        passwordBytes: password(),
      }),
    ).rejects.toThrow(KeyringAuthError);
  });

  it("strictly bounds the embedded context before trusting its bytes or bundle length", async () => {
    const bytes = encodeKeyringRecord(await selfContainedRecord());
    // Hand-pinned from record-v2's wire contract: version + flags + three u32
    // costs + 16-byte salt. This expectation does not call the production parser.
    const contextLengthOffset = 2 + 1 + 3 * 4 + 16;
    const contextOffset = contextLengthOffset + 4;

    const empty = bytes.slice();
    empty.fill(0, contextLengthOffset, contextOffset);
    expect(() => decodeKeyringRecord(empty)).toThrow(/context is empty/);

    const oversized = bytes.slice();
    const tooLarge = MAX_KEYRING_RECORD_CONTEXT_BYTES + 1;
    oversized.set([
      (tooLarge >>> 24) & 0xff,
      (tooLarge >>> 16) & 0xff,
      (tooLarge >>> 8) & 0xff,
      tooLarge & 0xff,
    ], contextLengthOffset);
    expect(() => decodeKeyringRecord(oversized)).toThrow(/context length.*exceeds/);

    const wrongEnvelopeVersion = bytes.slice();
    const domainLength =
      wrongEnvelopeVersion[contextOffset]! * 0x100_0000 +
      wrongEnvelopeVersion[contextOffset + 1]! * 0x1_0000 +
      wrongEnvelopeVersion[contextOffset + 2]! * 0x100 +
      wrongEnvelopeVersion[contextOffset + 3]!;
    const embeddedVersionOffset = contextOffset + 4 + domainLength;
    wrongEnvelopeVersion.set([0, 2], embeddedVersionOffset);
    expect(() => decodeKeyringRecord(wrongEnvelopeVersion)).toThrow(
      /record v2 context requires bundle v1/,
    );

    for (let cut = contextLengthOffset; cut < bytes.length; cut++) {
      expect(() => decodeKeyringRecord(bytes.slice(0, cut))).toThrow(KeyringFormatError);
    }
  });
});
