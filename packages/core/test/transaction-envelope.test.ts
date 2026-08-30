import { VersionedTransaction } from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import {
  TransactionEnvelopeError,
  parseSerializedTransactionEnvelope,
  type TransactionEnvelopeErrorCode,
} from "../src/transaction/envelope.js";

// Hand-pinned wire fields, not produced through web3 or the parser under test.
const LEGACY_TX_HEX = [
  "01",
  "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
  "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
  "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
  "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
  "01000103",
  "1111111111111111111111111111111111111111111111111111111111111111",
  "2222222222222222222222222222222222222222222222222222222222222222",
  "3333333333333333333333333333333333333333333333333333333333333333",
  "4444444444444444444444444444444444444444444444444444444444444444",
  "010202000103aabbcc",
].join("");
const V0_TX_HEX = [
  "01",
  "b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5",
  "b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5",
  "b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5",
  "b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5",
  "8001000103",
  "5151515151515151515151515151515151515151515151515151515151515151",
  "5252525252525252525252525252525252525252525252525252525252525252",
  "5353535353535353535353535353535353535353535353535353535353535353",
  "5454545454545454545454545454545454545454545454545454545454545454",
  "010202000102dead00",
].join("");

const LEGACY_MESSAGE_OFFSET = 1 + 64;
const LEGACY_FIRST_KEY_OFFSET = LEGACY_MESSAGE_OFFSET + 4;
const LEGACY_PROGRAM_INDEX_OFFSET = LEGACY_MESSAGE_OFFSET + 133;
const LEGACY_FIRST_ACCOUNT_INDEX_OFFSET = LEGACY_MESSAGE_OFFSET + 135;
const LEGACY_DATA_LENGTH_OFFSET = LEGACY_MESSAGE_OFFSET + 137;
const V0_MESSAGE_OFFSET = 1 + 64;

function fromHex(value: string): Uint8Array {
  if (value.length % 2 !== 0) throw new Error("test fixture hex is odd-length");
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index++) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

function fill(length: number, value: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function expectError(
  transaction: Uint8Array,
  code: TransactionEnvelopeErrorCode,
  requiredSigner?: Uint8Array,
): void {
  try {
    parseSerializedTransactionEnvelope(transaction, requiredSigner);
  } catch (error) {
    expect(error).toBeInstanceOf(TransactionEnvelopeError);
    expect((error as TransactionEnvelopeError).code).toBe(code);
    return;
  }
  throw new Error(`expected transaction envelope error ${code}`);
}

describe("strict serialized Solana transaction envelope", () => {
  it("parses an independently literal legacy transaction and pins every wire fact", () => {
    const transaction = fromHex(LEGACY_TX_HEX);
    const envelope = parseSerializedTransactionEnvelope(transaction, fill(32, 0x11));

    expect(transaction).toHaveLength(206);
    expect(envelope.version).toBe("legacy");
    expect(envelope.header).toEqual({
      numRequiredSignatures: 1,
      numReadonlySignedAccounts: 0,
      numReadonlyUnsignedAccounts: 1,
    });
    expect(envelope.transactionBytes).toEqual(transaction);
    expect(envelope.messageBytes).toEqual(transaction.slice(LEGACY_MESSAGE_OFFSET));
    expect(envelope.signatures).toEqual([fill(64, 0xa5)]);
    expect(envelope.staticAccountKeys).toEqual([
      fill(32, 0x11),
      fill(32, 0x22),
      fill(32, 0x33),
    ]);
    expect(envelope.requiredSignerKeys).toEqual([fill(32, 0x11)]);
    expect(envelope.recentBlockhash).toEqual(fill(32, 0x44));
    expect(envelope.instructions).toEqual([
      {
        programIdIndex: 2,
        accountKeyIndexes: new Uint8Array([0, 1]),
        data: new Uint8Array([0xaa, 0xbb, 0xcc]),
      },
    ]);
    expect(Object.isFrozen(envelope)).toBe(true);
    expect(Object.isFrozen(envelope.header)).toBe(true);

    // Differential oracle only: the implementation under test does not call web3.
    const web3 = VersionedTransaction.deserialize(transaction);
    expect(web3.version).toBe("legacy");
    expect(web3.serialize()).toEqual(transaction);
  });

  it("parses a lookup-free v0 transaction and agrees with web3 byte-for-byte", () => {
    const transaction = fromHex(V0_TX_HEX);
    const envelope = parseSerializedTransactionEnvelope(transaction, fill(32, 0x51));

    expect(transaction).toHaveLength(207);
    expect(envelope.version).toBe(0);
    expect(envelope.header).toEqual({
      numRequiredSignatures: 1,
      numReadonlySignedAccounts: 0,
      numReadonlyUnsignedAccounts: 1,
    });
    expect(envelope.staticAccountKeys).toEqual([
      fill(32, 0x51),
      fill(32, 0x52),
      fill(32, 0x53),
    ]);
    expect(envelope.recentBlockhash).toEqual(fill(32, 0x54));
    expect(envelope.instructions).toEqual([
      {
        programIdIndex: 2,
        accountKeyIndexes: new Uint8Array([0, 1]),
        data: new Uint8Array([0xde, 0xad]),
      },
    ]);

    const web3 = VersionedTransaction.deserialize(transaction);
    expect(web3.version).toBe(0);
    expect(web3.serialize()).toEqual(transaction);
  });

  it("copy-owns caller input and every byte-bearing read", () => {
    const transaction = fromHex(LEGACY_TX_HEX);
    const envelope = parseSerializedTransactionEnvelope(transaction);
    transaction.fill(0);

    expect(envelope.transactionBytes).toEqual(fromHex(LEGACY_TX_HEX));
    const transactionRead = envelope.transactionBytes;
    const messageRead = envelope.messageBytes;
    const signaturesRead = envelope.signatures;
    const keysRead = envelope.staticAccountKeys;
    const signerKeysRead = envelope.requiredSignerKeys;
    const blockhashRead = envelope.recentBlockhash;
    const instructionsRead = envelope.instructions;
    transactionRead.fill(0);
    messageRead.fill(0);
    signaturesRead[0]!.fill(0);
    keysRead[0]!.fill(0);
    signerKeysRead[0]!.fill(0);
    blockhashRead.fill(0);
    instructionsRead[0]!.accountKeyIndexes.fill(0xff);
    instructionsRead[0]!.data.fill(0);

    expect(envelope.transactionBytes).toEqual(fromHex(LEGACY_TX_HEX));
    expect(envelope.signatures[0]).toEqual(fill(64, 0xa5));
    expect(envelope.staticAccountKeys[0]).toEqual(fill(32, 0x11));
    expect(envelope.requiredSignerKeys[0]).toEqual(fill(32, 0x11));
    expect(envelope.recentBlockhash).toEqual(fill(32, 0x44));
    expect(envelope.instructions[0]).toEqual({
      programIdIndex: 2,
      accountKeyIndexes: new Uint8Array([0, 1]),
      data: new Uint8Array([0xaa, 0xbb, 0xcc]),
    });
  });

  it("rejects wrong input types, empty/oversize values, truncation, and trailing bytes", () => {
    expectError([] as unknown as Uint8Array, "INVALID_TYPE");
    expectError(new Uint8Array(), "INVALID_SIZE");
    expectError(new Uint8Array(1_233), "INVALID_SIZE");
    expectError(fromHex(LEGACY_TX_HEX).slice(0, 64), "TRUNCATED");
    expectError(
      concat(fromHex(LEGACY_TX_HEX), new Uint8Array([0])),
      "TRAILING_BYTES",
    );
  });

  it("enforces canonical Solana ShortU16 encodings instead of web3's permissive decoder", () => {
    const transaction = fromHex(LEGACY_TX_HEX);
    expectError(
      concat(new Uint8Array([0x81, 0x00]), transaction.slice(1)),
      "NON_CANONICAL_SHORTVEC",
    );
    expectError(new Uint8Array([0x80, 0x80, 0x04]), "SHORTVEC_OVERFLOW");
    expectError(new Uint8Array([0x80, 0x80, 0x80]), "SHORTVEC_OVERFLOW");
    // 65,535 is a canonical three-byte ShortU16; it reaches the bounded-read
    // failure instead of being mislabeled as an encoding overflow.
    expectError(new Uint8Array([0xff, 0xff, 0x03]), "TRUNCATED");
    expectError(
      concat(
        transaction.slice(0, LEGACY_MESSAGE_OFFSET + 3),
        new Uint8Array([0x83, 0x00]),
        transaction.slice(LEGACY_MESSAGE_OFFSET + 4),
      ),
      "NON_CANONICAL_SHORTVEC",
    );
  });

  it("accepts the canonical two-byte ShortU16 boundary and rejects its alias", () => {
    const transaction = fromHex(LEGACY_TX_HEX);
    const data = fill(128, 0x6d);
    const canonical = concat(
      transaction.slice(0, LEGACY_DATA_LENGTH_OFFSET),
      new Uint8Array([0x80, 0x01]),
      data,
    );
    const envelope = parseSerializedTransactionEnvelope(canonical);
    expect(envelope.instructions[0]!.data).toEqual(data);
    expect(VersionedTransaction.deserialize(canonical).serialize()).toEqual(canonical);

    const alias = concat(
      transaction.slice(0, LEGACY_DATA_LENGTH_OFFSET),
      new Uint8Array([0x80, 0x81, 0x00]),
      data,
    );
    expectError(alias, "NON_CANONICAL_SHORTVEC");
  });

  it("rejects every proper prefix of both accepted golden transactions", () => {
    for (const transaction of [fromHex(LEGACY_TX_HEX), fromHex(V0_TX_HEX)]) {
      for (let length = 0; length < transaction.length; length++) {
        expect(() =>
          parseSerializedTransactionEnvelope(transaction.slice(0, length)),
        ).toThrow(TransactionEnvelopeError);
      }
    }
  });

  it("rejects unsupported message versions and any unresolved address lookup table", () => {
    const unknownVersion = fromHex(V0_TX_HEX);
    unknownVersion[V0_MESSAGE_OFFSET] = 0x81;
    expectError(unknownVersion, "UNSUPPORTED_VERSION");

    const v0 = fromHex(V0_TX_HEX);
    const lookupTransaction = concat(
      v0.slice(0, -1),
      new Uint8Array([1]),
      fill(32, 0x61),
      new Uint8Array([1, 7, 0]),
    );
    expectError(lookupTransaction, "ADDRESS_LOOKUPS_UNSUPPORTED");
  });

  it("mirrors runtime signature/header/account-key sanitization", () => {
    const signatureMismatch = fromHex(LEGACY_TX_HEX);
    signatureMismatch[LEGACY_MESSAGE_OFFSET] = 2;
    expectError(signatureMismatch, "SIGNATURE_COUNT_MISMATCH");

    const noSignaturesMessage = fromHex(LEGACY_TX_HEX).slice(
      LEGACY_MESSAGE_OFFSET,
    );
    noSignaturesMessage[0] = 0;
    expectError(
      concat(new Uint8Array([0]), noSignaturesMessage),
      "INVALID_HEADER",
    );

    const readonlyPayer = fromHex(LEGACY_TX_HEX);
    readonlyPayer[LEGACY_MESSAGE_OFFSET + 1] = 1;
    expectError(readonlyPayer, "INVALID_HEADER");

    const overlappingHeader = fromHex(LEGACY_TX_HEX);
    overlappingHeader[LEGACY_MESSAGE_OFFSET + 2] = 3;
    expectError(overlappingHeader, "INVALID_HEADER");

    const duplicateKey = fromHex(LEGACY_TX_HEX);
    duplicateKey.set(
      duplicateKey.slice(LEGACY_FIRST_KEY_OFFSET, LEGACY_FIRST_KEY_OFFSET + 32),
      LEGACY_FIRST_KEY_OFFSET + 32,
    );
    expectError(duplicateKey, "DUPLICATE_ACCOUNT_KEY");
  });

  it("rejects payer/program aliasing and every out-of-range compiled index", () => {
    const payerAsProgram = fromHex(LEGACY_TX_HEX);
    payerAsProgram[LEGACY_PROGRAM_INDEX_OFFSET] = 0;
    expectError(payerAsProgram, "INVALID_INSTRUCTION_INDEX");

    const missingProgram = fromHex(LEGACY_TX_HEX);
    missingProgram[LEGACY_PROGRAM_INDEX_OFFSET] = 3;
    expectError(missingProgram, "INVALID_INSTRUCTION_INDEX");

    const missingAccount = fromHex(LEGACY_TX_HEX);
    missingAccount[LEGACY_FIRST_ACCOUNT_INDEX_OFFSET] = 3;
    expectError(missingAccount, "INVALID_INSTRUCTION_INDEX");
  });

  it("binds an optional requested wallet account to the actual required-signer set", () => {
    const transaction = fromHex(LEGACY_TX_HEX);
    expect(
      parseSerializedTransactionEnvelope(transaction, fill(32, 0x11)).requiredSignerKeys,
    ).toEqual([fill(32, 0x11)]);
    expectError(transaction, "REQUESTED_SIGNER_MISSING", fill(32, 0x22));
    expectError(transaction, "REQUESTED_SIGNER_INVALID", fill(31, 0x11));
  });
});
