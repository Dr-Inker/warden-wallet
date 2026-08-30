//! Strict, browser-safe parsing for the serialized Solana transaction bytes a
//! Wallet Standard caller supplies. This boundary authenticates wire shape only:
//! it does NOT claim that an instruction is safe, policy-compliant, simulated,
//! or ready to sign. Those semantic decisions belong to the later C4 decoder.
//!
//! The parser is intentionally independent of `@solana/web3.js`. The SDK's
//! current deserializers consume compact lengths by shifting an array and do not
//! prove strict ShortU16 form or end-of-input. Here every vector length is a
//! canonical Solana ShortU16, every read is bounded by the 1,232-byte packet,
//! and trailing bytes are fatal. Legacy and lookup-free v0 are the only accepted
//! message shapes. A v0 lookup is refused until Warden has a trusted,
//! cluster-bound lookup resolver; signing before those accounts are known would
//! make local instruction review fictitious.

import { MAX_TX_BYTES } from "../constants.js";

const SIGNATURE_BYTES = 64;
const PUBLIC_KEY_BYTES = 32;
const VERSION_PREFIX_MASK = 0x7f;
const VERSIONED_FLAG = 0x80;
const MAX_ACCOUNT_KEYS = 256;

export type SupportedTransactionVersion = "legacy" | 0;

export type TransactionEnvelopeErrorCode =
  | "INVALID_TYPE"
  | "INVALID_SIZE"
  | "TRUNCATED"
  | "NON_CANONICAL_SHORTVEC"
  | "SHORTVEC_OVERFLOW"
  | "UNSUPPORTED_VERSION"
  | "SIGNATURE_COUNT_MISMATCH"
  | "INVALID_HEADER"
  | "DUPLICATE_ACCOUNT_KEY"
  | "INVALID_INSTRUCTION_INDEX"
  | "INVALID_ADDRESS_LOOKUP"
  | "ADDRESS_LOOKUPS_UNSUPPORTED"
  | "TRAILING_BYTES"
  | "REQUESTED_SIGNER_INVALID"
  | "REQUESTED_SIGNER_MISSING";

export class TransactionEnvelopeError extends Error {
  readonly code: TransactionEnvelopeErrorCode;

  constructor(code: TransactionEnvelopeErrorCode, message: string) {
    super(`transaction envelope: ${message}`);
    this.name = "TransactionEnvelopeError";
    this.code = code;
  }
}

export interface TransactionMessageHeader {
  readonly numRequiredSignatures: number;
  readonly numReadonlySignedAccounts: number;
  readonly numReadonlyUnsignedAccounts: number;
}

export interface TransactionCompiledInstruction {
  readonly programIdIndex: number;
  readonly accountKeyIndexes: Uint8Array;
  readonly data: Uint8Array;
}

/**
 * Parsed facts from one exact serialized transaction. Every byte-bearing getter
 * returns a new owned copy. JavaScript cannot freeze non-empty Uint8Arrays, so
 * copy isolation—not a misleading shallow freeze—is the immutability contract.
 */
export interface SolanaTransactionEnvelope {
  readonly version: SupportedTransactionVersion;
  readonly header: TransactionMessageHeader;
  readonly transactionBytes: Uint8Array;
  readonly messageBytes: Uint8Array;
  readonly signatures: readonly Uint8Array[];
  readonly staticAccountKeys: readonly Uint8Array[];
  readonly requiredSignerKeys: readonly Uint8Array[];
  readonly recentBlockhash: Uint8Array;
  readonly instructions: readonly TransactionCompiledInstruction[];
}

interface ParsedEnvelopeData {
  readonly version: SupportedTransactionVersion;
  readonly header: TransactionMessageHeader;
  readonly transactionBytes: Uint8Array;
  readonly messageBytes: Uint8Array;
  readonly signatures: readonly Uint8Array[];
  readonly staticAccountKeys: readonly Uint8Array[];
  readonly recentBlockhash: Uint8Array;
  readonly instructions: readonly TransactionCompiledInstruction[];
}

function fail(code: TransactionEnvelopeErrorCode, message: string): never {
  throw new TransactionEnvelopeError(code, message);
}

class WireReader {
  readonly #bytes: Uint8Array;
  #offset = 0;

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  get offset(): number {
    return this.#offset;
  }

  get remaining(): number {
    return this.#bytes.length - this.#offset;
  }

  readU8(label: string): number {
    if (this.#offset >= this.#bytes.length) {
      fail("TRUNCATED", `${label} is truncated at byte ${this.#offset}`);
    }
    return this.#bytes[this.#offset++]!;
  }

  readBytes(length: number, label: string): Uint8Array {
    if (length > this.remaining) {
      fail(
        "TRUNCATED",
        `${label} needs ${length} bytes but only ${this.remaining} remain`,
      );
    }
    const start = this.#offset;
    this.#offset += length;
    return this.#bytes.slice(start, this.#offset);
  }

  /** Solana's strict one-to-three-byte ShortU16, including alias rejection. */
  readShortU16(label: string): number {
    let value = 0;
    for (let byteIndex = 0; byteIndex < 3; byteIndex++) {
      const byte = this.readU8(`${label} length`);
      if (byteIndex !== 0 && byte === 0) {
        fail(
          "NON_CANONICAL_SHORTVEC",
          `${label} length uses an alias ShortU16 encoding`,
        );
      }
      if (byteIndex === 2) {
        if ((byte & VERSIONED_FLAG) !== 0) {
          fail("SHORTVEC_OVERFLOW", `${label} length continues past three bytes`);
        }
        if ((byte & 0x7c) !== 0) {
          fail("SHORTVEC_OVERFLOW", `${label} length exceeds u16`);
        }
      }
      value |= (byte & VERSION_PREFIX_MASK) << (byteIndex * 7);
      if ((byte & VERSIONED_FLAG) === 0) return value;
    }
    fail("SHORTVEC_OVERFLOW", `${label} length is malformed`);
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function assertDistinctStaticKeys(keys: readonly Uint8Array[]): void {
  // The runtime ultimately rejects duplicate loaded accounts with
  // AccountLoadedTwice. O(n^2) is bounded by the u8 account-index space and the
  // much tighter packet cap, and avoids a string/Buffer dependency in browsers.
  for (let left = 0; left < keys.length; left++) {
    for (let right = left + 1; right < keys.length; right++) {
      if (bytesEqual(keys[left]!, keys[right]!)) {
        fail(
          "DUPLICATE_ACCOUNT_KEY",
          `static account keys ${left} and ${right} are identical`,
        );
      }
    }
  }
}

function snapshotByteArrays(values: readonly Uint8Array[]): readonly Uint8Array[] {
  return Object.freeze(values.map((value) => value.slice()));
}

function snapshotInstructions(
  values: readonly TransactionCompiledInstruction[],
): readonly TransactionCompiledInstruction[] {
  return Object.freeze(
    values.map((value) =>
      Object.freeze({
        programIdIndex: value.programIdIndex,
        accountKeyIndexes: value.accountKeyIndexes.slice(),
        data: value.data.slice(),
      }),
    ),
  );
}

class ParsedSolanaTransactionEnvelope implements SolanaTransactionEnvelope {
  readonly version: SupportedTransactionVersion;
  readonly header: TransactionMessageHeader;
  readonly #transactionBytes: Uint8Array;
  readonly #messageBytes: Uint8Array;
  readonly #signatures: readonly Uint8Array[];
  readonly #staticAccountKeys: readonly Uint8Array[];
  readonly #recentBlockhash: Uint8Array;
  readonly #instructions: readonly TransactionCompiledInstruction[];

  constructor(data: ParsedEnvelopeData) {
    this.version = data.version;
    this.header = Object.freeze({ ...data.header });
    this.#transactionBytes = data.transactionBytes.slice();
    this.#messageBytes = data.messageBytes.slice();
    this.#signatures = snapshotByteArrays(data.signatures);
    this.#staticAccountKeys = snapshotByteArrays(data.staticAccountKeys);
    this.#recentBlockhash = data.recentBlockhash.slice();
    this.#instructions = snapshotInstructions(data.instructions);
    Object.freeze(this);
  }

  get transactionBytes(): Uint8Array {
    return this.#transactionBytes.slice();
  }

  get messageBytes(): Uint8Array {
    return this.#messageBytes.slice();
  }

  get signatures(): readonly Uint8Array[] {
    return snapshotByteArrays(this.#signatures);
  }

  get staticAccountKeys(): readonly Uint8Array[] {
    return snapshotByteArrays(this.#staticAccountKeys);
  }

  get requiredSignerKeys(): readonly Uint8Array[] {
    return snapshotByteArrays(
      this.#staticAccountKeys.slice(0, this.header.numRequiredSignatures),
    );
  }

  get recentBlockhash(): Uint8Array {
    return this.#recentBlockhash.slice();
  }

  get instructions(): readonly TransactionCompiledInstruction[] {
    return snapshotInstructions(this.#instructions);
  }
}

function readRepeatedBytes(
  reader: WireReader,
  count: number,
  width: number,
  label: string,
): Uint8Array[] {
  if (count * width > reader.remaining) {
    fail(
      "TRUNCATED",
      `${label} need ${count * width} bytes but only ${reader.remaining} remain`,
    );
  }
  const values: Uint8Array[] = [];
  for (let index = 0; index < count; index++) {
    values.push(reader.readBytes(width, `${label}[${index}]`));
  }
  return values;
}

function validateHeader(
  header: TransactionMessageHeader,
  signatureCount: number,
  staticAccountCount: number,
): void {
  if (signatureCount !== header.numRequiredSignatures) {
    fail(
      "SIGNATURE_COUNT_MISMATCH",
      `${signatureCount} signatures do not match ${header.numRequiredSignatures} required signers`,
    );
  }
  if (staticAccountCount > MAX_ACCOUNT_KEYS) {
    fail("INVALID_HEADER", `static account count ${staticAccountCount} exceeds 256`);
  }
  if (
    header.numReadonlySignedAccounts >= header.numRequiredSignatures ||
    header.numRequiredSignatures + header.numReadonlyUnsignedAccounts >
      staticAccountCount
  ) {
    fail(
      "INVALID_HEADER",
      "header overlaps signer/read-only regions or has no writable fee payer",
    );
  }
}

function validateInstructionIndexes(
  instructions: readonly TransactionCompiledInstruction[],
  staticAccountCount: number,
  totalAccountCount: number,
): void {
  for (let instructionIndex = 0; instructionIndex < instructions.length; instructionIndex++) {
    const instruction = instructions[instructionIndex]!;
    if (
      instruction.programIdIndex === 0 ||
      instruction.programIdIndex >= staticAccountCount
    ) {
      fail(
        "INVALID_INSTRUCTION_INDEX",
        `instruction ${instructionIndex} program index ${instruction.programIdIndex} is not a non-payer static account`,
      );
    }
    for (const accountIndex of instruction.accountKeyIndexes) {
      if (accountIndex >= totalAccountCount) {
        fail(
          "INVALID_INSTRUCTION_INDEX",
          `instruction ${instructionIndex} account index ${accountIndex} is out of range`,
        );
      }
    }
  }
}

/**
 * Parse one exact Wallet Standard serialized transaction. If `requiredSigner`
 * is supplied, it must be a 32-byte key present in the message's actual required
 * signer prefix; a page-selected account label is never accepted on faith.
 */
export function parseSerializedTransactionEnvelope(
  serializedTransaction: Uint8Array,
  requiredSigner?: Uint8Array,
): SolanaTransactionEnvelope {
  if (!(serializedTransaction instanceof Uint8Array)) {
    fail("INVALID_TYPE", "serialized transaction must be a Uint8Array");
  }
  if (
    serializedTransaction.length === 0 ||
    serializedTransaction.length > MAX_TX_BYTES
  ) {
    fail(
      "INVALID_SIZE",
      `serialized transaction must contain 1 to ${MAX_TX_BYTES} bytes`,
    );
  }
  let ownedRequiredSigner: Uint8Array | undefined;
  if (requiredSigner !== undefined) {
    if (!(requiredSigner instanceof Uint8Array) || requiredSigner.length !== PUBLIC_KEY_BYTES) {
      fail(
        "REQUESTED_SIGNER_INVALID",
        `required signer must contain exactly ${PUBLIC_KEY_BYTES} bytes`,
      );
    }
    ownedRequiredSigner = requiredSigner.slice();
  }

  const transactionBytes = serializedTransaction.slice();
  const reader = new WireReader(transactionBytes);
  const signatureCount = reader.readShortU16("signature vector");
  const signatures = readRepeatedBytes(
    reader,
    signatureCount,
    SIGNATURE_BYTES,
    "signatures",
  );

  const messageOffset = reader.offset;
  const prefix = reader.readU8("message prefix");
  let version: SupportedTransactionVersion;
  let numRequiredSignatures: number;
  if ((prefix & VERSIONED_FLAG) === 0) {
    version = "legacy";
    numRequiredSignatures = prefix;
  } else {
    const wireVersion = prefix & VERSION_PREFIX_MASK;
    if (wireVersion !== 0) {
      fail("UNSUPPORTED_VERSION", `message version ${wireVersion} is unsupported`);
    }
    version = 0;
    numRequiredSignatures = reader.readU8("required signature count");
  }

  const header = Object.freeze({
    numRequiredSignatures,
    numReadonlySignedAccounts: reader.readU8("read-only signed account count"),
    numReadonlyUnsignedAccounts: reader.readU8(
      "read-only unsigned account count",
    ),
  });
  const staticAccountCount = reader.readShortU16("static account vector");
  validateHeader(header, signatureCount, staticAccountCount);
  const staticAccountKeys = readRepeatedBytes(
    reader,
    staticAccountCount,
    PUBLIC_KEY_BYTES,
    "static account keys",
  );
  assertDistinctStaticKeys(staticAccountKeys);

  if (
    ownedRequiredSigner !== undefined &&
    !staticAccountKeys
      .slice(0, numRequiredSignatures)
      .some((key) => bytesEqual(key, ownedRequiredSigner!))
  ) {
    fail(
      "REQUESTED_SIGNER_MISSING",
      "requested wallet account is not an actual required signer",
    );
  }

  const recentBlockhash = reader.readBytes(PUBLIC_KEY_BYTES, "recent blockhash");
  const instructionCount = reader.readShortU16("instruction vector");
  if (instructionCount * 3 > reader.remaining) {
    fail(
      "TRUNCATED",
      `${instructionCount} instructions cannot fit in ${reader.remaining} remaining bytes`,
    );
  }
  const instructions: TransactionCompiledInstruction[] = [];
  for (let index = 0; index < instructionCount; index++) {
    const programIdIndex = reader.readU8(`instruction ${index} program index`);
    const accountIndexCount = reader.readShortU16(
      `instruction ${index} account-index vector`,
    );
    const accountKeyIndexes = reader.readBytes(
      accountIndexCount,
      `instruction ${index} account indexes`,
    );
    const dataLength = reader.readShortU16(`instruction ${index} data vector`);
    const data = reader.readBytes(dataLength, `instruction ${index} data`);
    instructions.push({ programIdIndex, accountKeyIndexes, data });
  }

  let lookupCount = 0;
  let dynamicAccountCount = 0;
  if (version === 0) {
    lookupCount = reader.readShortU16("address lookup vector");
    for (let index = 0; index < lookupCount; index++) {
      reader.readBytes(PUBLIC_KEY_BYTES, `address lookup ${index} table key`);
      const writableCount = reader.readShortU16(
        `address lookup ${index} writable-index vector`,
      );
      reader.readBytes(
        writableCount,
        `address lookup ${index} writable indexes`,
      );
      const readonlyCount = reader.readShortU16(
        `address lookup ${index} read-only-index vector`,
      );
      reader.readBytes(
        readonlyCount,
        `address lookup ${index} read-only indexes`,
      );
      if (writableCount + readonlyCount === 0) {
        fail(
          "INVALID_ADDRESS_LOOKUP",
          `address lookup ${index} loads no accounts`,
        );
      }
      dynamicAccountCount += writableCount + readonlyCount;
    }
  }

  if (reader.remaining !== 0) {
    fail(
      "TRAILING_BYTES",
      `${reader.remaining} unconsumed byte${reader.remaining === 1 ? "" : "s"} remain`,
    );
  }
  const totalAccountCount = staticAccountCount + dynamicAccountCount;
  if (totalAccountCount > MAX_ACCOUNT_KEYS) {
    fail(
      "INVALID_ADDRESS_LOOKUP",
      `static and looked-up accounts total ${totalAccountCount}, exceeding 256`,
    );
  }
  validateInstructionIndexes(
    instructions,
    staticAccountCount,
    totalAccountCount,
  );
  if (lookupCount !== 0) {
    fail(
      "ADDRESS_LOOKUPS_UNSUPPORTED",
      "v0 address lookup tables require trusted cluster-bound resolution",
    );
  }

  return new ParsedSolanaTransactionEnvelope({
    version,
    header,
    transactionBytes,
    messageBytes: transactionBytes.slice(messageOffset),
    signatures,
    staticAccountKeys,
    recentBlockhash,
    instructions,
  });
}
