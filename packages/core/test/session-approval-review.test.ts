import {
  ComputeBudgetProgram,
  PublicKey,
  TransactionInstruction,
  TransactionMessage,
} from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import {
  createPendingApprovalRecord,
  resolveApprovalRecord,
} from "../src/approval/record.js";
import {
  SessionIntentError,
  decodeSessionApprovalReview,
} from "../src/transaction/session-intent.js";

const fill = (value: number): Uint8Array => new Uint8Array(32).fill(value);
const WARDEN_PROGRAM = new PublicKey(
  "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2",
);
const OWNER_SEED = fill(0x11);
const SESSION_SIGNER = new PublicKey(fill(0x22));
const GENESIS_HASH = fill(0x99);
const BLOCKHASH = fill(0x88);
const [SMART_ACCOUNT] = PublicKey.findProgramAddressSync(
  [new TextEncoder().encode("account"), OWNER_SEED],
  WARDEN_PROGRAM,
);
const [SESSION_ACCOUNT] = PublicKey.findProgramAddressSync(
  [
    new TextEncoder().encode("session"),
    SMART_ACCOUNT.toBytes(),
    SESSION_SIGNER.toBytes(),
  ],
  WARDEN_PROGRAM,
);
const [REGISTRY] = PublicKey.findProgramAddressSync(
  [new TextEncoder().encode("registry")],
  WARDEN_PROGRAM,
);
const MEMO_PROGRAM = new PublicKey(
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
);
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
const GOLDEN_MESSAGE_HEX =
  "80010004072222222222222222222222222222222222222222222222222222222222222222" +
  "d6c617f8f9b6efa8f53b8e3519b87ce86c0d4b8bf97da710769c395d7a6225f97016a12" +
  "f469df2029c389bc4a61caf34c1e8f290b01d1971bd12853c70b6a49b0306466fe521173" +
  "2ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000017b5f72e2c074fa855520" +
  "6db7ccf465c1db513c725913ca7ce685f135f8bd51bb58ca5e9f58c81171d832ad015248" +
  "304e438e6b9a0ab891f53c5286275046f7054a535a992921064d24e87160da387c7c35b5" +
  "ddbc92bb81e41fa8404105448d888888888888888888888888888888888888888888888888" +
  "88888888888888880303000502c02709000300050100000200040801000204040504062b82" +
  "ddf29a0dc1bd1d00011d000000010200180077617264656e2072656c656173652063616e64" +
  "696461746500";

function goldenMessage(): Uint8Array {
  return Uint8Array.from(Buffer.from(GOLDEN_MESSAGE_HEX, "hex"));
}

function writeU16le(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
}

function writeU32le(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

interface MessageOptions {
  readonly memo?: Uint8Array;
  readonly units?: number;
  readonly heapBytes?: number;
  readonly executeProgram?: PublicKey;
  readonly instructionOrder?: readonly ("units" | "heap" | "execute")[];
}

function builtMessage(options: MessageOptions = {}): Uint8Array {
  const memo = options.memo ?? new TextEncoder().encode("warden release candidate");
  const payload = new Uint8Array(5 + memo.length);
  payload[0] = 1;
  payload[1] = 2;
  payload[2] = 0;
  writeU16le(payload, 3, memo.length);
  payload.set(memo, 5);
  const executeData = new Uint8Array(14 + payload.length);
  executeData.set(EXECUTE_DISCRIMINATOR, 0);
  executeData[8] = 0;
  executeData[9] = 1;
  writeU32le(executeData, 10, payload.length);
  executeData.set(payload, 14);
  const instructions = {
    units: ComputeBudgetProgram.setComputeUnitLimit({
      units: options.units ?? 600_000,
    }),
    heap: ComputeBudgetProgram.requestHeapFrame({
      bytes: options.heapBytes ?? 128 * 1_024,
    }),
    execute: new TransactionInstruction({
      programId: options.executeProgram ?? WARDEN_PROGRAM,
      keys: [
        { pubkey: SMART_ACCOUNT, isSigner: false, isWritable: true },
        { pubkey: SESSION_SIGNER, isSigner: true, isWritable: true },
        { pubkey: SESSION_ACCOUNT, isSigner: false, isWritable: true },
        { pubkey: WARDEN_PROGRAM, isSigner: false, isWritable: false },
        { pubkey: WARDEN_PROGRAM, isSigner: false, isWritable: false },
        { pubkey: REGISTRY, isSigner: false, isWritable: false },
        { pubkey: WARDEN_PROGRAM, isSigner: false, isWritable: false },
        { pubkey: MEMO_PROGRAM, isSigner: false, isWritable: false },
      ],
      data: Buffer.from(executeData),
    }),
  };
  return new TransactionMessage({
    payerKey: SESSION_SIGNER,
    recentBlockhash: new PublicKey(BLOCKHASH).toBase58(),
    instructions: (options.instructionOrder ?? ["units", "heap", "execute"])
      .map((name) => instructions[name]),
  }).compileToV0Message().serialize();
}

function pendingRecord(overrides: Record<string, unknown> = {}) {
  return createPendingApprovalRecord({
    id: `req_${"ab".repeat(16)}`,
    origin: "https://dapp.example",
    tabId: 7,
    frameId: 0,
    documentId: "document-approval-review",
    account: SMART_ACCOUNT.toBytes(),
    method: "solana:signTransaction",
    chain: "solana:devnet",
    genesisHash: GENESIS_HASH,
    programId: WARDEN_PROGRAM.toBytes(),
    rawMessage: goldenMessage(),
    policyVersion: 1,
    createdAt: 1_900_000_000_000,
    expiresAt: 1_900_000_060_000,
    ...overrides,
  });
}

describe("durable session approval review projection", () => {
  it("reparses one exact pending record into frozen primitive-only rendering facts", () => {
    const record = pendingRecord();
    expect(Buffer.from(builtMessage()).toString("hex")).toBe(GOLDEN_MESSAGE_HEX);
    const callerBytes = {
      account: record.account.slice(),
      genesisHash: record.genesisHash.slice(),
      programId: record.programId.slice(),
      rawMessage: record.rawMessage.slice(),
      messageDigest: record.messageDigest.slice(),
    };
    const review = decodeSessionApprovalReview(record);

    expect(review).toEqual({
      kind: "memo-v1",
      requestId: record.id,
      origin: "https://dapp.example",
      method: "solana:signTransaction",
      chain: "solana:devnet",
      genesisHash: new PublicKey(GENESIS_HASH).toBase58(),
      account: SMART_ACCOUNT.toBase58(),
      sessionSigner: SESSION_SIGNER.toBase58(),
      sessionAccount: SESSION_ACCOUNT.toBase58(),
      registry: REGISTRY.toBase58(),
      wardenProgram: WARDEN_PROGRAM.toBase58(),
      memoProgram: MEMO_PROGRAM.toBase58(),
      recentBlockhash: new PublicKey(BLOCKHASH).toBase58(),
      memo: "warden release candidate",
      memoByteLength: 24,
      computeUnitLimit: 600_000,
      heapFrameBytes: 128 * 1_024,
      messageByteLength: 333,
      messageDigest: Buffer.from(record.messageDigest).toString("hex"),
      policyVersion: 1,
      createdAt: 1_900_000_000_000,
      expiresAt: 1_900_000_060_000,
    });
    expect(Object.isFrozen(review)).toBe(true);
    expect(Object.values(review).every((value) => !(value instanceof Uint8Array))).toBe(true);
    expect(record).toMatchObject(callerBytes);
  });

  it.each([
    ["terminal record", () => resolveApprovalRecord(pendingRecord(), "rejected", 1_900_000_001_000)],
    ["send method", () => pendingRecord({ method: "solana:signAndSendTransaction" })],
    ["wrong account binding", () => pendingRecord({ account: fill(0x44) })],
    ["wrong Warden program", () => pendingRecord({ programId: fill(0x55) })],
    [
      "digest-authenticated but unsupported message",
      () => {
        const message = goldenMessage();
        message[message.length - 2] = 0x01;
        return pendingRecord({ rawMessage: message });
      },
    ],
  ])("refuses a %s", (_label, create) => {
    expect(() => decodeSessionApprovalReview(create())).toThrow(SessionIntentError);
  });

  it.each([
    [
      "excessive compute limit",
      { units: 1_400_001 },
      "COMPUTE_BUDGET_INVALID",
    ],
    [
      "wrong heap frame",
      { heapBytes: 64 * 1_024 },
      "COMPUTE_BUDGET_INVALID",
    ],
    [
      "reordered compute instructions",
      { instructionOrder: ["heap", "units", "execute"] as const },
      "COMPUTE_BUDGET_INVALID",
    ],
    [
      "extra execute instruction",
      { instructionOrder: ["units", "heap", "execute", "execute"] as const },
      "MESSAGE_SHAPE_UNSUPPORTED",
    ],
    [
      "different outer program",
      { executeProgram: MEMO_PROGRAM },
      "MESSAGE_SHAPE_UNSUPPORTED",
    ],
    [
      "control byte in memo",
      { memo: Uint8Array.of(0x41, 0x0a) },
      "MEMO_INVALID",
    ],
  ])("refuses a digest-authenticated %s", (_label, options, code) => {
    let error: unknown;
    try {
      decodeSessionApprovalReview(pendingRecord({
        rawMessage: builtMessage(options),
      }));
    } catch (value) {
      error = value;
    }
    expect(error).toBeInstanceOf(SessionIntentError);
    expect((error as SessionIntentError).code).toBe(code);
  });
});
