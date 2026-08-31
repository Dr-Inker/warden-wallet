import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";

import {
  createPendingApprovalRecord,
  digestApprovalMessage,
} from "../src/approval/record.js";
import {
  parseSerializedTransactionEnvelope,
  TransactionEnvelopeError,
} from "../src/transaction/envelope.js";
import {
  SessionTransactionBuildError,
  prepareSessionTransaction,
  type SessionTransactionBuildErrorCode,
} from "../src/transaction/session-transaction.js";

const fill = (value: number): Uint8Array => new Uint8Array(32).fill(value);
const key = (value: number): PublicKey => new PublicKey(fill(value));
const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length && left.every((value, index) => value === right[index]);
const isZero = (value: Uint8Array): boolean => value.every((byte) => byte === 0);
const readU32le = (value: Uint8Array, offset: number): number =>
  (value[offset]! |
    (value[offset + 1]! << 8) |
    (value[offset + 2]! << 16) |
    (value[offset + 3]! << 24)) >>> 0;

const SMART_KEYPAIR = Keypair.fromSeed(fill(0x11));
const SESSION_KEYPAIR = Keypair.fromSeed(fill(0x22));
const SMART_ACCOUNT = SMART_KEYPAIR.publicKey;
const SESSION_SIGNER = SESSION_KEYPAIR.publicKey;
const SESSION_ACCOUNT = key(0x33);
const REGISTRY = key(0x44);
const WARDEN_PROGRAM = new PublicKey(
  "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2",
);
const TARGET_PROGRAM = key(0x55);
const DESTINATION = key(0x66);
const SOURCE_BLOCKHASH = fill(0x77);
const FINAL_BLOCKHASH = fill(0x88);
const EXECUTE_DISCRIMINATOR = Uint8Array.of(
  130,
  221,
  242,
  154,
  13,
  193,
  189,
  29,
);

type SourceVersion = "legacy" | 0;

function ordinaryInstruction(data = Uint8Array.of(7, 8, 9)): TransactionInstruction {
  return new TransactionInstruction({
    programId: TARGET_PROGRAM,
    keys: [
      { pubkey: DESTINATION, isSigner: false, isWritable: true },
    ],
    data: Buffer.from(data),
  });
}

function sourceTransaction(
  instructions: TransactionInstruction[],
  version: SourceVersion = 0,
): VersionedTransaction {
  const message = new TransactionMessage({
    payerKey: SMART_ACCOUNT,
    recentBlockhash: new PublicKey(SOURCE_BLOCKHASH).toBase58(),
    instructions,
  });
  return new VersionedTransaction(
    version === 0
      ? message.compileToV0Message()
      : message.compileToLegacyMessage(),
  );
}

function prepare(
  transaction: Uint8Array,
  overrides: Partial<Parameters<typeof prepareSessionTransaction>[1]> = {},
) {
  return prepareSessionTransaction(transaction, {
    smartAccount: SMART_ACCOUNT,
    sessionSigner: SESSION_SIGNER,
    sessionAccount: SESSION_ACCOUNT,
    registry: REGISTRY,
    wardenProgram: WARDEN_PROGRAM,
    recentBlockhash: FINAL_BLOCKHASH,
    ...overrides,
  });
}

function captureBuildError(
  run: () => unknown,
  code: SessionTransactionBuildErrorCode,
): SessionTransactionBuildError {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(SessionTransactionBuildError);
    expect((error as SessionTransactionBuildError).code).toBe(code);
    return error as SessionTransactionBuildError;
  }
  throw new Error(`expected ${code}`);
}

describe("prepareSessionTransaction", () => {
  it("publishes rewriting separately from the web3-independent parser subpath", () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(import.meta.dirname, "../package.json"), "utf8"),
    ) as { exports: Record<string, { import: string; types: string }> };
    expect(packageJson.exports["./transaction"]).toEqual({
      types: "./dist/transaction/index.d.ts",
      import: "./dist/transaction/index.js",
    });
    expect(packageJson.exports["./transaction/session"]).toEqual({
      types: "./dist/transaction/session-transaction.d.ts",
      import: "./dist/transaction/session-transaction.js",
    });
    const parserIndex = readFileSync(
      resolve(import.meta.dirname, "../src/transaction/index.ts"),
      "utf8",
    );
    expect(parserIndex).toContain('export * from "./envelope.js"');
    expect(parserIndex).not.toContain("session-transaction");
  });

  it.each<SourceVersion>(["legacy", 0])(
    "rewrites a strict %s dApp envelope into one lookup-free v0 session message",
    (version) => {
      const source = sourceTransaction([ordinaryInstruction()], version).serialize();
      const prepared = prepare(source);
      const unsigned = prepared.unsignedTransactionBytes;
      const envelope = parseSerializedTransactionEnvelope(
        unsigned,
        SESSION_SIGNER.toBytes(),
      );

      expect(envelope.version).toBe(0);
      expect(envelope.header.numRequiredSignatures).toBe(1);
      expect(envelope.requiredSignerKeys).toEqual([SESSION_SIGNER.toBytes()]);
      expect(envelope.signatures).toHaveLength(1);
      expect(isZero(envelope.signatures[0]!)).toBe(true);
      expect(envelope.recentBlockhash).toEqual(FINAL_BLOCKHASH);
      expect(envelope.recentBlockhash).not.toEqual(SOURCE_BLOCKHASH);
      expect(envelope.messageBytes).toEqual(prepared.messageBytes);
      expect(unsigned.length).toBeLessThanOrEqual(1_232);
      expect(unsigned).not.toEqual(source);

      const decoded = VersionedTransaction.deserialize(unsigned);
      expect(decoded.message.serialize()).toEqual(prepared.messageBytes);
      const decompiled = TransactionMessage.decompile(decoded.message);
      expect(decompiled.payerKey.equals(SESSION_SIGNER)).toBe(true);
      expect(decompiled.recentBlockhash).toBe(
        new PublicKey(FINAL_BLOCKHASH).toBase58(),
      );
      expect(decompiled.instructions).toHaveLength(3);

      const execute = decompiled.instructions.at(-1)!;
      expect(execute.programId.equals(WARDEN_PROGRAM)).toBe(true);
      expect(new Uint8Array(execute.data.subarray(0, 8))).toEqual(
        EXECUTE_DISCRIMINATOR,
      );
      expect(execute.data[8]).toBe(0); // root: Option::None (session path)
      expect(execute.data[9]).toBe(1); // payload: Option::Some
      expect(readU32le(execute.data, 10)).toBe(prepared.payload.length);
      expect(new Uint8Array(execute.data.subarray(14))).toEqual(prepared.payload);
      expect(execute.keys.map((meta) => meta.pubkey.toBase58())).toEqual([
        SMART_ACCOUNT,
        SESSION_SIGNER,
        SESSION_ACCOUNT,
        WARDEN_PROGRAM,
        WARDEN_PROGRAM,
        REGISTRY,
        WARDEN_PROGRAM,
        TARGET_PROGRAM,
        DESTINATION,
      ].map((publicKey) => publicKey.toBase58()));
      expect(execute.keys.map((meta) => [meta.isSigner, meta.isWritable])).toEqual([
        [false, true], // SmartAccount is mutated by execute, but signs only via PDA seeds.
        [true, true], // Session delegate is also the final fee payer.
        [false, true], // SessionKey cap state.
        [false, false],
        [false, false],
        [false, false], // Registry is authorization input, not mutated.
        [false, false],
        [false, false], // Inner program id.
        [false, true], // Inner writable destination.
      ]);
      expect(prepared.sourceVersion).toBe(version);
      expect(prepared.transactionByteLength).toBe(unsigned.length);
      expect(prepared.messageByteLength).toBe(prepared.messageBytes.length);
    },
  );

  it("copy-owns source, blockhash, and every byte-bearing result", () => {
    const source = sourceTransaction([ordinaryInstruction()]).serialize();
    const sourceSnapshot = source.slice();
    const finalBlockhash = FINAL_BLOCKHASH.slice();
    const prepared = prepareSessionTransaction(source, {
      smartAccount: SMART_ACCOUNT,
      sessionSigner: SESSION_SIGNER,
      sessionAccount: SESSION_ACCOUNT,
      registry: REGISTRY,
      wardenProgram: WARDEN_PROGRAM,
      recentBlockhash: finalBlockhash,
    });

    source.fill(0xff);
    finalBlockhash.fill(0xff);
    const firstMessage = prepared.messageBytes;
    const firstTransaction = prepared.unsignedTransactionBytes;
    const firstPayload = prepared.payload;
    const firstHash = prepared.accountsHash;
    firstMessage.fill(0);
    firstTransaction.fill(0);
    firstPayload.fill(0);
    firstHash.fill(0);

    const reparsed = parseSerializedTransactionEnvelope(
      prepared.unsignedTransactionBytes,
      SESSION_SIGNER.toBytes(),
    );
    expect(reparsed.messageBytes).toEqual(prepared.messageBytes);
    expect(reparsed.recentBlockhash).toEqual(FINAL_BLOCKHASH);
    expect(prepared.sourceTransactionBytes).toEqual(sourceSnapshot);
    expect(prepared.payload.some((byte) => byte !== 0)).toBe(true);
    expect(prepared.accountsHash.some((byte) => byte !== 0)).toBe(true);
  });

  it("binds approval to immutable signing bytes, not mutable signature slots", () => {
    const prepared = prepare(
      sourceTransaction([ordinaryInstruction()]).serialize(),
    );
    const record = createPendingApprovalRecord({
      id: "req_0123456789abcdef0123456789abcdef",
      origin: "https://example.test",
      tabId: 7,
      frameId: 0,
      documentId: "document-1",
      account: SMART_ACCOUNT.toBytes(),
      method: "solana:signTransaction",
      chain: "solana:devnet",
      genesisHash: fill(0x99),
      programId: WARDEN_PROGRAM.toBytes(),
      rawMessage: prepared.messageBytes,
      policyVersion: 3,
      createdAt: 1_000,
      expiresAt: 61_000,
    });
    const unsigned = prepared.unsignedTransactionBytes;
    const signed = VersionedTransaction.deserialize(unsigned);
    signed.sign([SESSION_KEYPAIR]);

    expect(signed.message.serialize()).toEqual(record.rawMessage);
    expect(signed.serialize()).not.toEqual(unsigned);
    expect(isZero(signed.signatures[0]!)).toBe(false);
    expect(digestApprovalMessage(signed.message.serialize())).toEqual(
      record.messageDigest,
    );
    expect(bytesEqual(record.rawMessage, unsigned)).toBe(false);
    expect(ed25519.verify(
      signed.signatures[0]!,
      record.rawMessage,
      SESSION_SIGNER.toBytes(),
    )).toBe(true);
    const changedMessage = record.rawMessage.slice();
    changedMessage[changedMessage.length - 1]! ^= 1;
    expect(ed25519.verify(
      signed.signatures[0]!,
      changedMessage,
      SESSION_SIGNER.toBytes(),
    )).toBe(false);
  });

  it("rejects any incoming signature and any additional required signer", () => {
    const alreadySigned = sourceTransaction([ordinaryInstruction()]);
    alreadySigned.sign([SMART_KEYPAIR]);
    captureBuildError(
      () => prepare(alreadySigned.serialize()),
      "SOURCE_SIGNATURE_PRESENT",
    );

    const cosigner = Keypair.fromSeed(fill(0xaa)).publicKey;
    const withCosigner = ordinaryInstruction();
    withCosigner.keys.push({
      pubkey: cosigner,
      isSigner: true,
      isWritable: false,
    });
    captureBuildError(
      () => prepare(sourceTransaction([withCosigner]).serialize()),
      "SOURCE_SIGNER_SET_UNSUPPORTED",
    );
  });

  it("rejects a mismatched advertised account and aliasing PDA/session authority", () => {
    captureBuildError(
      () => prepare(
        sourceTransaction([ordinaryInstruction()]).serialize(),
        { smartAccount: key(0xab) },
      ),
      "SOURCE_SIGNER_MISMATCH",
    );
    captureBuildError(
      () => prepare(
        sourceTransaction([ordinaryInstruction()]).serialize(),
        { sessionSigner: SMART_ACCOUNT },
      ),
      "INVALID_AUTHORITY",
    );
  });

  it("rejects empty, durable-nonce, and Instructions-sysvar source shapes", () => {
    captureBuildError(
      () => prepare(sourceTransaction([]).serialize()),
      "SOURCE_INSTRUCTIONS_EMPTY",
    );

    const nonceAdvance = SystemProgram.nonceAdvance({
      noncePubkey: key(0xbb),
      authorizedPubkey: SMART_ACCOUNT,
    });
    captureBuildError(
      () => prepare(
        sourceTransaction([nonceAdvance, ordinaryInstruction()]).serialize(),
      ),
      "SOURCE_DURABLE_NONCE_UNSUPPORTED",
    );

    const introspective = ordinaryInstruction();
    introspective.keys.push({
      pubkey: SYSVAR_INSTRUCTIONS_PUBKEY,
      isSigner: false,
      isWritable: false,
    });
    captureBuildError(
      () => prepare(sourceTransaction([introspective]).serialize()),
      "SOURCE_INSTRUCTIONS_SYSVAR_UNSUPPORTED",
    );

    captureBuildError(
      () => prepare(sourceTransaction([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 250_000 }),
      ]).serialize()),
      "SOURCE_INSTRUCTIONS_EMPTY",
    );
  });

  it("preserves the strict parser failure as the cause of a malformed source", () => {
    const valid = sourceTransaction([ordinaryInstruction()]).serialize();
    const trailing = new Uint8Array(valid.length + 1);
    trailing.set(valid);
    const error = captureBuildError(
      () => prepare(trailing),
      "SOURCE_ENVELOPE_INVALID",
    );
    expect(error.cause).toBeInstanceOf(TransactionEnvelopeError);
    expect((error.cause as TransactionEnvelopeError).code).toBe("TRAILING_BYTES");
  });

  it("rejects source semantics the generic execute wrapper cannot preserve", () => {
    const transfer = SystemProgram.transfer({
      fromPubkey: SMART_ACCOUNT,
      toPubkey: DESTINATION,
      lamports: 1,
    });
    const error = captureBuildError(
      () => prepare(sourceTransaction([transfer]).serialize()),
      "SOURCE_WRAP_UNSUPPORTED",
    );
    expect(error.cause).toBeInstanceOf(Error);
    expect((error.cause as Error).message).toMatch(/SmartAccount PDA writable/);
  });

  it("requires an explicit nonzero 32-byte final blockhash", () => {
    const source = sourceTransaction([ordinaryInstruction()]).serialize();
    captureBuildError(
      () => prepare(source, { recentBlockhash: new Uint8Array(31) }),
      "INVALID_RECENT_BLOCKHASH",
    );
    captureBuildError(
      () => prepare(source, { recentBlockhash: new Uint8Array(32) }),
      "INVALID_RECENT_BLOCKHASH",
    );
  });

  it("rejects a source that fits but whose wrapped packet exceeds 1,232 bytes", () => {
    const source = sourceTransaction([
      ordinaryInstruction(new Uint8Array(900).fill(0xcd)),
    ]).serialize();
    expect(source.length).toBeLessThanOrEqual(1_232);
    captureBuildError(
      () => prepare(source),
      "FINAL_TRANSACTION_TOO_LARGE",
    );
  });
});
