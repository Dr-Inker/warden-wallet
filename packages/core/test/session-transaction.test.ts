import { describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { createPublicKey, verify as verifySignature } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  ComputeBudgetProgram,
  AddressLookupTableAccount,
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
  SessionTransactionSignError,
  prepareSessionTransaction,
  signApprovedSessionMessage,
  type SessionTransactionBuildErrorCode,
  type SessionTransactionSignErrorCode,
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

function captureSignError(
  run: () => unknown,
  code: SessionTransactionSignErrorCode,
): SessionTransactionSignError {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(SessionTransactionSignError);
    expect((error as SessionTransactionSignError).code).toBe(code);
    return error as SessionTransactionSignError;
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

  it("rewrites in a browser runtime with no Node Buffer global", () => {
    const source = sourceTransaction([ordinaryInstruction()]).serialize();
    vi.stubGlobal("Buffer", undefined);
    try {
      const prepared = prepare(source);
      expect(prepared.messageBytes.length).toBeGreaterThan(0);
      expect(prepared.unsignedTransactionBytes.length).toBeLessThanOrEqual(1_232);
    } finally {
      vi.unstubAllGlobals();
    }
  });

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

describe("signApprovedSessionMessage", () => {
  function approvedMessage(): {
    readonly prepared: ReturnType<typeof prepare>;
    readonly rawMessage: Uint8Array;
    readonly messageDigest: Uint8Array;
  } {
    const prepared = prepare(
      sourceTransaction([ordinaryInstruction()]).serialize(),
    );
    const record = createPendingApprovalRecord({
      id: "req_fedcba9876543210fedcba9876543210",
      origin: "https://signing.example.test",
      tabId: 9,
      frameId: 0,
      documentId: "document-signing-1",
      account: SMART_ACCOUNT.toBytes(),
      method: "solana:signTransaction",
      chain: "solana:devnet",
      genesisHash: fill(0x99),
      programId: WARDEN_PROGRAM.toBytes(),
      rawMessage: prepared.messageBytes,
      policyVersion: 4,
      createdAt: 2_000,
      expiresAt: 62_000,
    });
    return {
      prepared,
      rawMessage: record.rawMessage,
      messageDigest: record.messageDigest,
    };
  }

  it("signs exactly the approved message and changes only its signature slot", () => {
    const approval = approvedMessage();
    const seed = fill(0x22);
    const seedSnapshot = seed.slice();
    const messageSnapshot = approval.rawMessage.slice();
    const signed = signApprovedSessionMessage(approval.rawMessage, seed);
    const transactionBytes = signed.transactionBytes;
    const envelope = parseSerializedTransactionEnvelope(
      transactionBytes,
      SESSION_SIGNER.toBytes(),
    );

    expect(seed).toEqual(seedSnapshot);
    expect(approval.rawMessage).toEqual(messageSnapshot);
    expect(envelope.version).toBe(0);
    expect(envelope.header.numRequiredSignatures).toBe(1);
    expect(envelope.requiredSignerKeys).toEqual([SESSION_SIGNER.toBytes()]);
    expect(envelope.messageBytes).toEqual(approval.rawMessage);
    expect(envelope.recentBlockhash).toEqual(FINAL_BLOCKHASH);
    expect(envelope.signatures).toHaveLength(1);
    expect(envelope.signatures[0]).toEqual(signed.signature);
    expect(isZero(envelope.signatures[0]!)).toBe(false);
    expect(signed.messageBytes).toEqual(approval.rawMessage);
    expect(signed.sessionSigner).toEqual(SESSION_SIGNER.toBytes());
    expect(signed.recentBlockhash).toEqual(FINAL_BLOCKHASH);
    expect(signed.messageByteLength).toBe(approval.rawMessage.length);
    expect(signed.transactionByteLength).toBe(transactionBytes.length);
    expect(Object.isFrozen(signed)).toBe(true);
    expect(digestApprovalMessage(signed.messageBytes)).toEqual(
      approval.messageDigest,
    );
    expect(ed25519.verify(
      signed.signature,
      approval.rawMessage,
      SESSION_SIGNER.toBytes(),
    )).toBe(true);
    expect(ed25519.verify(
      signed.signature,
      approval.prepared.unsignedTransactionBytes,
      SESSION_SIGNER.toBytes(),
    )).toBe(false);
    const nodePublicKey = createPublicKey({
      key: Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(SESSION_SIGNER.toBytes()),
      ]),
      format: "der",
      type: "spki",
    });
    expect(verifySignature(
      null,
      Buffer.from(approval.rawMessage),
      nodePublicKey,
      Buffer.from(signed.signature),
    )).toBe(true);
    const changedMessage = approval.rawMessage.slice();
    changedMessage[changedMessage.length - 1]! ^= 1;
    expect(verifySignature(
      null,
      Buffer.from(changedMessage),
      nodePublicKey,
      Buffer.from(signed.signature),
    )).toBe(false);

    const unsigned = approval.prepared.unsignedTransactionBytes;
    expect(transactionBytes).toHaveLength(unsigned.length);
    expect(transactionBytes[0]).toBe(unsigned[0]);
    expect(transactionBytes.subarray(65)).toEqual(unsigned.subarray(65));
    expect(transactionBytes.subarray(1, 65)).toEqual(signed.signature);
    expect(transactionBytes.subarray(1, 65)).not.toEqual(
      unsigned.subarray(1, 65),
    );

    const sdkTransaction = VersionedTransaction.deserialize(transactionBytes);
    expect(sdkTransaction.message.serialize()).toEqual(approval.rawMessage);
    expect(sdkTransaction.signatures).toEqual([signed.signature]);
    expect(sdkTransaction.serialize()).toEqual(transactionBytes);
  });

  it("copy-isolates every returned signing artefact", () => {
    const approval = approvedMessage();
    const signed = signApprovedSessionMessage(approval.rawMessage, fill(0x22));
    const originalTransaction = signed.transactionBytes;
    const originalMessage = signed.messageBytes;
    const originalSignature = signed.signature;
    const originalSigner = signed.sessionSigner;
    const originalBlockhash = signed.recentBlockhash;

    signed.transactionBytes.fill(0);
    signed.messageBytes.fill(0);
    signed.signature.fill(0);
    signed.sessionSigner.fill(0);
    signed.recentBlockhash.fill(0);

    expect(signed.transactionBytes).toEqual(originalTransaction);
    expect(signed.messageBytes).toEqual(originalMessage);
    expect(signed.signature).toEqual(originalSignature);
    expect(signed.sessionSigner).toEqual(originalSigner);
    expect(signed.recentBlockhash).toEqual(originalBlockhash);
  });

  it("refuses a seed whose derived public key is not the approved sole signer", () => {
    const approval = approvedMessage();
    const error = captureSignError(
      () => signApprovedSessionMessage(approval.rawMessage, fill(0x23)),
      "SESSION_SIGNER_MISMATCH",
    );
    expect(error.cause).toBeInstanceOf(TransactionEnvelopeError);
  });

  it("rejects malformed input, legacy messages, extra signers, and zero blockhashes", () => {
    const approval = approvedMessage();
    captureSignError(
      () => signApprovedSessionMessage(
        new Uint8Array([...approval.rawMessage, 0]),
        fill(0x22),
      ),
      "INVALID_APPROVED_MESSAGE",
    );
    captureSignError(
      () => signApprovedSessionMessage(
        approval.prepared.unsignedTransactionBytes,
        fill(0x22),
      ),
      "INVALID_APPROVED_MESSAGE",
    );
    captureSignError(
      () => signApprovedSessionMessage(approval.rawMessage, new Uint8Array(31)),
      "INVALID_SESSION_SEED",
    );

    const legacy = new TransactionMessage({
      payerKey: SESSION_SIGNER,
      recentBlockhash: new PublicKey(FINAL_BLOCKHASH).toBase58(),
      instructions: [ordinaryInstruction()],
    }).compileToLegacyMessage().serialize();
    captureSignError(
      () => signApprovedSessionMessage(legacy, fill(0x22)),
      "APPROVED_MESSAGE_VERSION_UNSUPPORTED",
    );

    const cosignerInstruction = ordinaryInstruction();
    cosignerInstruction.keys.push({
      pubkey: key(0xaa),
      isSigner: true,
      isWritable: false,
    });
    const withCosigner = new TransactionMessage({
      payerKey: SESSION_SIGNER,
      recentBlockhash: new PublicKey(FINAL_BLOCKHASH).toBase58(),
      instructions: [cosignerInstruction],
    }).compileToV0Message().serialize();
    captureSignError(
      () => signApprovedSessionMessage(withCosigner, fill(0x22)),
      "APPROVED_SIGNER_SET_UNSUPPORTED",
    );

    const zeroBlockhash = new TransactionMessage({
      payerKey: SESSION_SIGNER,
      recentBlockhash: PublicKey.default.toBase58(),
      instructions: [ordinaryInstruction()],
    }).compileToV0Message().serialize();
    captureSignError(
      () => signApprovedSessionMessage(zeroBlockhash, fill(0x22)),
      "APPROVED_BLOCKHASH_INVALID",
    );
  });

  it("refuses v0 address-table lookups because their account roles are unresolved", () => {
    const lookup = new AddressLookupTableAccount({
      key: key(0xbb),
      state: {
        deactivationSlot: 0xffff_ffff_ffff_ffffn,
        lastExtendedSlot: 1,
        lastExtendedSlotStartIndex: 0,
        authority: undefined,
        addresses: [DESTINATION],
      },
    });
    const message = new TransactionMessage({
      payerKey: SESSION_SIGNER,
      recentBlockhash: new PublicKey(FINAL_BLOCKHASH).toBase58(),
      instructions: [ordinaryInstruction()],
    }).compileToV0Message([lookup]).serialize();

    captureSignError(
      () => signApprovedSessionMessage(message, fill(0x22)),
      "APPROVED_MESSAGE_LOOKUPS_UNSUPPORTED",
    );
  });
});
