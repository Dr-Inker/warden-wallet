import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  ComputeBudgetProgram,
  PublicKey,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import type { SessionAuthoritySnapshot } from "../src/transaction/session-approval-coordinator.js";
import { prepareSessionTransaction } from "../src/transaction/session-transaction.js";
import {
  DeterministicSessionIntentGate,
  SessionIntentError,
  decodeSessionIntent,
  encodeSessionAuthorizationState,
  type SessionIntentErrorCode,
} from "../src/transaction/session-intent.js";

const fill = (value: number): Uint8Array => new Uint8Array(32).fill(value);
const writeU16le = (bytes: Uint8Array, offset: number, value: number): void => {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
};
const writeU32le = (bytes: Uint8Array, offset: number, value: number): void => {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
};
const writeU64le = (bytes: Uint8Array, offset: number, value: bigint): void => {
  let remaining = value;
  for (let index = 0; index < 8; index++) {
    bytes[offset + index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
};

const WARDEN_PROGRAM = new PublicKey(
  "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2",
);
const MEMO_PROGRAM = new PublicKey(
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
);
const SMART_DISCRIMINATOR = Uint8Array.of(
  186, 83, 247, 224, 59, 95, 223, 112,
);
const SESSION_DISCRIMINATOR = Uint8Array.of(
  93, 186, 163, 139, 160, 255, 81, 112,
);
const REGISTRY_DISCRIMINATOR = Uint8Array.of(
  47, 174, 110, 246, 184, 182, 252, 218,
);
const EXECUTE_DISCRIMINATOR = Uint8Array.of(
  130, 221, 242, 154, 13, 193, 189, 29,
);
const AUTH_MAGIC = Uint8Array.of(87, 82, 68, 65, 85, 84, 72, 1); // WRDAUTH + v1
const OWNER_SEED = fill(0x11);
const SESSION_SIGNER = new PublicKey(fill(0x22));
const GENESIS_HASH = fill(0x99);
const BLOCKHASH = fill(0x88);
const ACCOUNT_GENERATION = 7n;
const POLICY_VERSION = 1;
const SESSION_EXPIRY = 2_000_000_000;
const MEMO_TEXT = "warden release candidate";
const MEMO_BYTES = new TextEncoder().encode(MEMO_TEXT);
const SMART_DATA_LEN = 4_120;
const SESSION_DATA_LEN = 751;
const REGISTRY_DATA_LEN = 3_480;
const AUTH_STATE_LEN = 8 + 33 + SMART_DATA_LEN + 33 + SESSION_DATA_LEN + 33 + REGISTRY_DATA_LEN;
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

const [SMART_ACCOUNT, SMART_BUMP] = PublicKey.findProgramAddressSync(
  [new TextEncoder().encode("account"), OWNER_SEED],
  WARDEN_PROGRAM,
);
const [SESSION_ACCOUNT, SESSION_BUMP] = PublicKey.findProgramAddressSync(
  [
    new TextEncoder().encode("session"),
    SMART_ACCOUNT.toBytes(),
    SESSION_SIGNER.toBytes(),
  ],
  WARDEN_PROGRAM,
);
const [REGISTRY, REGISTRY_BUMP] = PublicKey.findProgramAddressSync(
  [new TextEncoder().encode("registry")],
  WARDEN_PROGRAM,
);

function findAlternateProgramAddress(
  seeds: readonly Uint8Array[],
  canonicalBump: number,
): readonly [PublicKey, number] {
  for (let bump = canonicalBump - 1; bump >= 0; bump--) {
    try {
      return [
        PublicKey.createProgramAddressSync(
          [...seeds, Uint8Array.of(bump)],
          WARDEN_PROGRAM,
        ),
        bump,
      ];
    } catch {
      // Keep searching: roughly half of candidate bumps are on-curve.
    }
  }
  throw new Error("test fixture could not find an alternate valid PDA bump");
}

interface FixtureOptions {
  readonly smart?: (bytes: Uint8Array) => void;
  readonly session?: (bytes: Uint8Array) => void;
  readonly registry?: (bytes: Uint8Array) => void;
  readonly authorization?: (bytes: Uint8Array) => void;
  readonly message?: MessageOptions;
}

interface MessageOptions {
  readonly memo?: Uint8Array;
  readonly payload?: Uint8Array;
  readonly executeData?: Uint8Array;
  readonly executeKeys?: readonly {
    readonly pubkey: PublicKey;
    readonly isSigner: boolean;
    readonly isWritable: boolean;
  }[];
  readonly units?: number;
  readonly heapBytes?: number;
  readonly unitInstruction?: TransactionInstruction;
  readonly heapInstruction?: TransactionInstruction;
  readonly payerKey?: PublicKey;
  readonly blockhash?: Uint8Array;
  readonly executeProgram?: PublicKey;
  readonly instructionOrder?: readonly ("units" | "heap" | "execute")[];
}

function smartData(): Uint8Array {
  const bytes = new Uint8Array(SMART_DATA_LEN);
  bytes.set(SMART_DISCRIMINATOR, 0);
  bytes[8] = 1;
  bytes[9] = SMART_BUMP;
  bytes.set(OWNER_SEED, 14);
  bytes.set(GENESIS_HASH, 175);
  bytes.set(REGISTRY.toBytes(), 239);
  writeU64le(bytes, 528, ACCOUNT_GENERATION);
  writeU64le(bytes, 536, 3n); // a used root nonce is valid session state
  writeU32le(bytes, 560, POLICY_VERSION);
  writeU16le(bytes, 1_936, 1 << 1); // current policy permits session execute
  return bytes;
}

function sessionData(): Uint8Array {
  const bytes = new Uint8Array(SESSION_DATA_LEN);
  bytes.set(SESSION_DISCRIMINATOR, 0);
  bytes[8] = 1;
  bytes[9] = SESSION_BUMP;
  bytes.set(SMART_ACCOUNT.toBytes(), 10);
  bytes.set(SESSION_SIGNER.toBytes(), 42);
  bytes[74] = 0;
  writeU64le(bytes, 75, BigInt(SESSION_EXPIRY));
  writeU16le(bytes, 83, 1 << 1);
  writeU64le(bytes, 85, ACCOUNT_GENERATION);
  writeU16le(bytes, 669, 1);
  return bytes;
}

function registryData(): Uint8Array {
  const bytes = new Uint8Array(REGISTRY_DATA_LEN);
  bytes.set(REGISTRY_DISCRIMINATOR, 0);
  bytes[8] = 1;
  bytes[9] = REGISTRY_BUMP;
  writeU16le(bytes, 80, 1);
  bytes.set(MEMO_PROGRAM.toBytes(), 88);
  bytes[88 + 40] = 0; // tagless program
  bytes[88 + 41] = 0; // no account-role rule
  writeU64le(bytes, 3_160, 1n); // entry zero is in list one
  bytes[3_224] = 1; // list one was allocated
  return bytes;
}

function handAuthorizationState(
  smart: Uint8Array,
  session: Uint8Array,
  registry: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(AUTH_STATE_LEN);
  out.set(AUTH_MAGIC, 0);
  let offset = AUTH_MAGIC.length;
  for (const data of [smart, session, registry]) {
    out.set(WARDEN_PROGRAM.toBytes(), offset);
    offset += 32;
    out[offset++] = 0;
    out.set(data, offset);
    offset += data.length;
  }
  expect(offset).toBe(out.length);
  return out;
}

function inlinePayload(memo = MEMO_BYTES): Uint8Array {
  const payload = new Uint8Array(5 + memo.length);
  payload[0] = 1; // one inner instruction
  payload[1] = 2; // logical[2] = first remaining account = Memo program
  payload[2] = 0; // Memo receives no signer accounts
  writeU16le(payload, 3, memo.length);
  payload.set(memo, 5);
  return payload;
}

function inlineExecute(payload: Uint8Array): Uint8Array {
  const data = new Uint8Array(14 + payload.length);
  data.set(EXECUTE_DISCRIMINATOR, 0);
  data[8] = 0; // root None: session path
  data[9] = 1; // inline payload Some
  writeU32le(data, 10, payload.length);
  data.set(payload, 14);
  return data;
}

function canonicalExecuteKeys(): {
  pubkey: PublicKey;
  isSigner: boolean;
  isWritable: boolean;
}[] {
  return [
    { pubkey: SMART_ACCOUNT, isSigner: false, isWritable: true },
    { pubkey: SESSION_SIGNER, isSigner: true, isWritable: true },
    { pubkey: SESSION_ACCOUNT, isSigner: false, isWritable: true },
    { pubkey: WARDEN_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: WARDEN_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: REGISTRY, isSigner: false, isWritable: false },
    { pubkey: WARDEN_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: MEMO_PROGRAM, isSigner: false, isWritable: false },
  ];
}

function finalMessage(options: MessageOptions = {}): Uint8Array {
  const payload = options.payload ?? inlinePayload(options.memo);
  const executeData = options.executeData ?? inlineExecute(payload);
  const executeKeys = options.executeKeys ?? canonicalExecuteKeys();
  const instructions = {
    units: options.unitInstruction ?? ComputeBudgetProgram.setComputeUnitLimit({
      units: options.units ?? 600_000,
    }),
    heap: options.heapInstruction ?? ComputeBudgetProgram.requestHeapFrame({
      bytes: options.heapBytes ?? 128 * 1_024,
    }),
    execute: new TransactionInstruction({
      programId: options.executeProgram ?? WARDEN_PROGRAM,
      keys: [...executeKeys],
      data: Buffer.from(executeData),
    }),
  };
  const order = options.instructionOrder ?? ["units", "heap", "execute"];
  return new TransactionMessage({
    payerKey: options.payerKey ?? SESSION_SIGNER,
    recentBlockhash: new PublicKey(options.blockhash ?? BLOCKHASH).toBase58(),
    instructions: order.map((name) => instructions[name]),
  }).compileToV0Message().serialize();
}

function fixture(options: FixtureOptions = {}): {
  readonly messageBytes: Uint8Array;
  readonly authority: SessionAuthoritySnapshot;
  readonly smart: Uint8Array;
  readonly session: Uint8Array;
  readonly registry: Uint8Array;
} {
  const smart = smartData();
  const session = sessionData();
  const registry = registryData();
  options.smart?.(smart);
  options.session?.(session);
  options.registry?.(registry);
  const authorizationState = handAuthorizationState(smart, session, registry);
  options.authorization?.(authorizationState);
  return {
    messageBytes: finalMessage(options.message),
    authority: {
      chain: "solana:devnet",
      genesisHash: GENESIS_HASH.slice(),
      smartAccount: SMART_ACCOUNT,
      sessionSigner: SESSION_SIGNER,
      sessionAccount: SESSION_ACCOUNT,
      registry: REGISTRY,
      wardenProgram: WARDEN_PROGRAM,
      accountGeneration: ACCOUNT_GENERATION,
      policyVersion: POLICY_VERSION,
      authorizationState,
      contextSlot: 42,
    },
    smart,
    session,
    registry,
  };
}

function captureError(
  run: () => unknown,
  code: SessionIntentErrorCode,
): SessionIntentError {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(SessionIntentError);
    expect((error as SessionIntentError).code).toBe(code);
    return error as SessionIntentError;
  }
  throw new Error(`expected ${code}`);
}

describe("deterministic session intent", () => {
  it("publishes the gate as a separate opt-in subpath", () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(import.meta.dirname, "../package.json"), "utf8"),
    ) as { exports: Record<string, { import: string; types: string }> };
    expect(packageJson.exports["./transaction/session-intent"]).toEqual({
      types: "./dist/transaction/session-intent.d.ts",
      import: "./dist/transaction/session-intent.js",
    });
    const parserIndex = readFileSync(
      resolve(import.meta.dirname, "../src/transaction/index.ts"),
      "utf8",
    );
    expect(parserIndex).not.toContain("session-intent");
  });

  it("encodes the fixed-width authority packet exactly and copy-owns inputs", () => {
    const smart = smartData();
    const session = sessionData();
    const registry = registryData();
    const expected = handAuthorizationState(smart, session, registry);
    const encoded = encodeSessionAuthorizationState({
      smartAccount: { owner: WARDEN_PROGRAM, executable: false, data: smart },
      session: { owner: WARDEN_PROGRAM, executable: false, data: session },
      registry: { owner: WARDEN_PROGRAM, executable: false, data: registry },
    });
    expect(encoded).toEqual(expected);
    expect(encoded).toHaveLength(AUTH_STATE_LEN);
    smart.fill(0xff);
    session.fill(0xff);
    registry.fill(0xff);
    expect(encoded).toEqual(expected);
  });

  it("pins an exact lookup-free v0 message vector independent of the decoder", () => {
    const message = finalMessage();
    expect(message).toHaveLength(333);
    expect(Buffer.from(message).toString("hex")).toBe(GOLDEN_MESSAGE_HEX);
  });

  it("accepts the exact message emitted by the production session builder", () => {
    const sourceMessage = new TransactionMessage({
      payerKey: SMART_ACCOUNT,
      recentBlockhash: new PublicKey(fill(0x77)).toBase58(),
      instructions: [
        ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
        ComputeBudgetProgram.requestHeapFrame({ bytes: 128 * 1_024 }),
        new TransactionInstruction({
          programId: MEMO_PROGRAM,
          keys: [],
          data: Buffer.from(MEMO_BYTES),
        }),
      ],
    }).compileToV0Message();
    const prepared = prepareSessionTransaction(
      new VersionedTransaction(sourceMessage).serialize(),
      {
        smartAccount: SMART_ACCOUNT,
        sessionSigner: SESSION_SIGNER,
        sessionAccount: SESSION_ACCOUNT,
        registry: REGISTRY,
        wardenProgram: WARDEN_PROGRAM,
        recentBlockhash: BLOCKHASH,
      },
    );

    expect(prepared.messageBytes).toEqual(finalMessage());
    expect(Buffer.from(prepared.messageBytes).toString("hex")).toBe(
      GOLDEN_MESSAGE_HEX,
    );
    expect(
      decodeSessionIntent({
        messageBytes: prepared.messageBytes,
        authority: fixture().authority,
        nowUnixSeconds: 1_900_000_000,
      }).memo,
    ).toBe(MEMO_TEXT);
  });

  it("rejects noncanonical encoder inputs before producing a packet", () => {
    const smart = smartData();
    captureError(
      () => encodeSessionAuthorizationState({
        smartAccount: {
          owner: WARDEN_PROGRAM,
          executable: false,
          data: smart.slice(1),
        },
        session: {
          owner: WARDEN_PROGRAM,
          executable: false,
          data: sessionData(),
        },
        registry: {
          owner: WARDEN_PROGRAM,
          executable: false,
          data: registryData(),
        },
      }),
      "INVALID_INPUT",
    );
  });

  it("decodes one exact printable-ASCII Memo message into frozen primitives", () => {
    const input = fixture();
    const intent = decodeSessionIntent({
      ...input,
      nowUnixSeconds: 1_900_000_000,
    });
    expect(intent).toEqual({
      kind: "memo-v1",
      chain: "solana:devnet",
      genesisHash: new PublicKey(GENESIS_HASH).toBase58(),
      smartAccount: SMART_ACCOUNT.toBase58(),
      sessionSigner: SESSION_SIGNER.toBase58(),
      sessionAccount: SESSION_ACCOUNT.toBase58(),
      registry: REGISTRY.toBase58(),
      wardenProgram: WARDEN_PROGRAM.toBase58(),
      programId: MEMO_PROGRAM.toBase58(),
      recentBlockhash: new PublicKey(BLOCKHASH).toBase58(),
      memo: MEMO_TEXT,
      memoByteLength: MEMO_BYTES.length,
      computeUnitLimit: 600_000,
      heapFrameBytes: 128 * 1_024,
      messageByteLength: input.messageBytes.length,
      accountGeneration: ACCOUNT_GENERATION.toString(10),
      policyVersion: POLICY_VERSION,
      sessionExpiryUnixSeconds: SESSION_EXPIRY,
      programAllowlistId: 1,
      contextSlot: 42,
    });
    expect(Object.isFrozen(intent)).toBe(true);
  });

  it("does not mutate inputs and returns no byte-bearing aliases", () => {
    const input = fixture();
    const messageBefore = input.messageBytes.slice();
    const stateBefore = input.authority.authorizationState.slice();
    const intent = decodeSessionIntent({
      ...input,
      nowUnixSeconds: 1_900_000_000,
    });
    expect(input.messageBytes).toEqual(messageBefore);
    expect(input.authority.authorizationState).toEqual(stateBefore);
    input.messageBytes.fill(0);
    input.authority.authorizationState.fill(0);
    expect(intent.memo).toBe(MEMO_TEXT);
    expect(intent.recentBlockhash).toBe(new PublicKey(BLOCKHASH).toBase58());
    expect(Object.values(intent).every((value) => !(value instanceof Uint8Array))).toBe(true);
  });

  it("snapshots messageBytes from a hostile getter exactly once", () => {
    const input = fixture();
    let reads = 0;
    const hostileInput = {
      get messageBytes(): Uint8Array {
        reads++;
        return reads === 1 ? input.messageBytes : new Uint8Array();
      },
      authority: input.authority,
      nowUnixSeconds: 1_900_000_000,
    };

    expect(decodeSessionIntent(hostileInput).memo).toBe(MEMO_TEXT);
    expect(reads).toBe(1);
  });

  it("snapshots authorizationState from a hostile getter exactly once", () => {
    const input = fixture();
    let reads = 0;
    const authority = {
      ...input.authority,
      get authorizationState(): Uint8Array {
        reads++;
        return reads === 1
          ? input.authority.authorizationState
          : new Uint8Array();
      },
    };

    expect(decodeSessionIntent({
      messageBytes: input.messageBytes,
      authority,
      nowUnixSeconds: 1_900_000_000,
    }).memo).toBe(MEMO_TEXT);
    expect(reads).toBe(1);
  });

  it("provides a synchronous coordinator gate with an injected clock", () => {
    let clockReads = 0;
    const gate = new DeterministicSessionIntentGate({
      readUnixSeconds() {
        clockReads++;
        return 1_900_000_000;
      },
    });
    expect(gate.assertAllowed(fixture())).toBeUndefined();
    expect(clockReads).toBe(1);
  });

  it.each([
    ["wrong magic", (bytes: Uint8Array) => { bytes[0] ^= 1; }],
    ["wrong packet version", (bytes: Uint8Array) => { bytes[7] = 2; }],
    ["noncanonical SmartAccount executable flag", (bytes: Uint8Array) => { bytes[40] = 2; }],
    ["noncanonical SessionKey executable flag", (bytes: Uint8Array) => { bytes[4_193] = 2; }],
    ["noncanonical Registry executable flag", (bytes: Uint8Array) => { bytes[4_977] = 2; }],
  ])("rejects authority framing: %s", (_name, mutate) => {
    const input = fixture({ authorization: mutate });
    captureError(
      () => decodeSessionIntent({ ...input, nowUnixSeconds: 1_900_000_000 }),
      "AUTHORIZATION_STATE_INVALID",
    );
  });

  it("rejects a truncated authority packet", () => {
    const input = fixture();
    captureError(
      () => decodeSessionIntent({
        messageBytes: input.messageBytes,
        authority: {
          ...input.authority,
          authorizationState: input.authority.authorizationState.slice(1),
        },
        nowUnixSeconds: 1_900_000_000,
      }),
      "AUTHORIZATION_STATE_INVALID",
    );
  });

  it.each([
    ["negative clock", -1],
    ["fractional clock", 1_900_000_000.5],
  ])("rejects invalid decoder input: %s", (_name, nowUnixSeconds) => {
    const input = fixture();
    captureError(
      () => decodeSessionIntent({ ...input, nowUnixSeconds }),
      "INVALID_INPUT",
    );
  });

  it.each([
    ["empty message", new Uint8Array()],
    ["oversized message", new Uint8Array(1_168)],
  ])("bounds message bytes before envelope allocation: %s", (_name, messageBytes) => {
    const input = fixture();
    captureError(
      () => decodeSessionIntent({
        authority: input.authority,
        messageBytes,
        nowUnixSeconds: 1_900_000_000,
      }),
      "MESSAGE_INVALID",
    );
  });

  it.each<[
    string,
    FixtureOptions,
    SessionIntentErrorCode,
  ]>([
    ["wrong SmartAccount owner", { authorization: (bytes) => { bytes[8] ^= 1; } }, "AUTHORITY_MISMATCH"],
    ["executable SmartAccount", { authorization: (bytes) => { bytes[40] = 1; } }, "AUTHORITY_NOT_USABLE"],
    ["wrong SmartAccount discriminator", { smart: (bytes) => { bytes[0] ^= 1; } }, "AUTHORITY_NOT_USABLE"],
    ["future SmartAccount version", { smart: (bytes) => { bytes[8] = 2; } }, "AUTHORITY_NOT_USABLE"],
    ["wrong SmartAccount PDA bump", { smart: (bytes) => { bytes[9] ^= 1; } }, "AUTHORITY_MISMATCH"],
    ["frozen SmartAccount", { smart: (bytes) => { bytes[12] = 1; } }, "AUTHORITY_NOT_USABLE"],
    ["stale freeze timestamp", { smart: (bytes) => { bytes[552] = 1; } }, "AUTHORITY_NOT_USABLE"],
    ["wrong cluster tag", { smart: (bytes) => { bytes[175] ^= 1; } }, "AUTHORITY_MISMATCH"],
    ["wrong registry pointer", { smart: (bytes) => { bytes[239] ^= 1; } }, "AUTHORITY_MISMATCH"],
    ["wrong account generation", { smart: (bytes) => { bytes[528] ^= 1; } }, "AUTHORITY_MISMATCH"],
    ["wrong policy version", { smart: (bytes) => { bytes[560] ^= 1; } }, "AUTHORITY_MISMATCH"],
    ["future policy op bit", { smart: (bytes) => { writeU16le(bytes, 1_936, 0x82); } }, "AUTHORITY_NOT_USABLE"],
    ["nonzero SmartAccount reserved byte", { smart: (bytes) => { bytes[271] = 1; } }, "AUTHORITY_NOT_USABLE"],
    ["wrong SessionKey owner", { authorization: (bytes) => { bytes[4_161] ^= 1; } }, "AUTHORITY_MISMATCH"],
    ["executable SessionKey", { authorization: (bytes) => { bytes[4_193] = 1; } }, "AUTHORITY_NOT_USABLE"],
    ["wrong SessionKey discriminator", { session: (bytes) => { bytes[0] ^= 1; } }, "AUTHORITY_NOT_USABLE"],
    ["future SessionKey version", { session: (bytes) => { bytes[8] = 2; } }, "AUTHORITY_NOT_USABLE"],
    ["wrong SessionKey PDA bump", { session: (bytes) => { bytes[9] ^= 1; } }, "AUTHORITY_MISMATCH"],
    ["wrong SessionKey SmartAccount", { session: (bytes) => { bytes[10] ^= 1; } }, "AUTHORITY_MISMATCH"],
    ["wrong SessionKey signer", { session: (bytes) => { bytes[42] ^= 1; } }, "AUTHORITY_MISMATCH"],
    ["future SessionKey kind", { session: (bytes) => { bytes[74] = 1; } }, "AUTHORITY_NOT_USABLE"],
    ["expired session", { session: (bytes) => { writeU64le(bytes, 75, 1_800_000_000n); } }, "AUTHORITY_NOT_USABLE"],
    ["execute op absent", { session: (bytes) => { writeU16le(bytes, 83, 1); } }, "AUTHORITY_NOT_USABLE"],
    ["future op bit set", { session: (bytes) => { writeU16le(bytes, 83, 0x82); } }, "AUTHORITY_NOT_USABLE"],
    ["wrong SessionKey generation", { session: (bytes) => { bytes[85] ^= 1; } }, "AUTHORITY_MISMATCH"],
    ["zero allowlist id", { session: (bytes) => { writeU16le(bytes, 669, 0); } }, "AUTHORITY_NOT_USABLE"],
    ["nonzero SessionKey reserved byte", { session: (bytes) => { bytes[687] = 1; } }, "AUTHORITY_NOT_USABLE"],
    ["wrong Registry owner", { authorization: (bytes) => { bytes[4_945] ^= 1; } }, "AUTHORITY_MISMATCH"],
    ["executable Registry", { authorization: (bytes) => { bytes[4_977] = 1; } }, "AUTHORITY_NOT_USABLE"],
    ["wrong Registry discriminator", { registry: (bytes) => { bytes[0] ^= 1; } }, "AUTHORITY_NOT_USABLE"],
    ["future Registry version", { registry: (bytes) => { bytes[8] = 2; } }, "AUTHORITY_NOT_USABLE"],
    ["wrong Registry PDA bump", { registry: (bytes) => { bytes[9] ^= 1; } }, "AUTHORITY_MISMATCH"],
    ["nonzero Registry padding", { registry: (bytes) => { bytes[10] = 1; } }, "AUTHORITY_NOT_USABLE"],
    ["nonzero unused Registry entry", { registry: (bytes) => { bytes[136] = 1; } }, "AUTHORITY_NOT_USABLE"],
    ["Registry list bit past n_entries", { registry: (bytes) => { writeU64le(bytes, 3_160, 3n); } }, "AUTHORITY_NOT_USABLE"],
    ["registry list absent", { registry: (bytes) => {
      writeU64le(bytes, 3_160, 0n);
      bytes[3_224] = 0;
    } }, "REGISTRY_DENIED"],
    ["Memo entry has role rules", { registry: (bytes) => { bytes[129] = 1; } }, "REGISTRY_DENIED"],
    ["ambiguous Memo entries", { registry: (bytes) => {
      writeU16le(bytes, 80, 2);
      bytes.set(MEMO_PROGRAM.toBytes(), 136);
      writeU64le(bytes, 3_160, 3n);
    } }, "REGISTRY_DENIED"],
  ])("fails closed on %s", (_name, options, code) => {
    const input = fixture(options);
    captureError(
      () => decodeSessionIntent({ ...input, nowUnixSeconds: 1_900_000_000 }),
      code,
    );
  });

  it("rejects a self-described future policy version", () => {
    const input = fixture({ smart: (bytes) => { writeU32le(bytes, 560, 2); } });
    captureError(
      () => decodeSessionIntent({
        messageBytes: input.messageBytes,
        authority: { ...input.authority, policyVersion: 2 },
        nowUnixSeconds: 1_900_000_000,
      }),
      "AUTHORITY_NOT_USABLE",
    );
  });

  it("pins the resolver to the shipped Warden program id", () => {
    const input = fixture();
    captureError(
      () => decodeSessionIntent({
        messageBytes: input.messageBytes,
        authority: { ...input.authority, wardenProgram: MEMO_PROGRAM },
        nowUnixSeconds: 1_900_000_000,
      }),
      "AUTHORITY_MISMATCH",
    );
  });

  it("rejects a valid but noncanonical SmartAccount PDA bump", () => {
    const [alternateSmartAccount, alternateSmartBump] =
      findAlternateProgramAddress(
        [new TextEncoder().encode("account"), OWNER_SEED],
        SMART_BUMP,
      );
    const [alternateSessionAccount, alternateSessionBump] =
      PublicKey.findProgramAddressSync(
        [
          new TextEncoder().encode("session"),
          alternateSmartAccount.toBytes(),
          SESSION_SIGNER.toBytes(),
        ],
        WARDEN_PROGRAM,
      );
    const smart = smartData();
    smart[9] = alternateSmartBump;
    const session = sessionData();
    session[9] = alternateSessionBump;
    session.set(alternateSmartAccount.toBytes(), 10);
    const registry = registryData();
    const authority: SessionAuthoritySnapshot = {
      ...fixture().authority,
      smartAccount: alternateSmartAccount,
      sessionAccount: alternateSessionAccount,
      authorizationState: handAuthorizationState(smart, session, registry),
    };
    const executeKeys = canonicalExecuteKeys();
    executeKeys[0] = {
      pubkey: alternateSmartAccount,
      isSigner: false,
      isWritable: true,
    };
    executeKeys[2] = {
      pubkey: alternateSessionAccount,
      isSigner: false,
      isWritable: true,
    };

    captureError(
      () => decodeSessionIntent({
        authority,
        messageBytes: finalMessage({ executeKeys }),
        nowUnixSeconds: 1_900_000_000,
      }),
      "AUTHORITY_MISMATCH",
    );
  });

  it.each<[
    string,
    MessageOptions,
    SessionIntentErrorCode,
  ]>([
    ["reordered budget instructions", { instructionOrder: ["heap", "units", "execute"] }, "COMPUTE_BUDGET_INVALID"],
    ["duplicate unit-limit instruction", { instructionOrder: ["units", "units", "execute"] }, "COMPUTE_BUDGET_INVALID"],
    ["priority-fee instruction", {
      unitInstruction: ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 }),
    }, "COMPUTE_BUDGET_INVALID"],
    ["compute limit below the measured floor", { units: 119_999 }, "COMPUTE_BUDGET_INVALID"],
    ["compute limit above the runtime ceiling", { units: 1_400_001 }, "COMPUTE_BUDGET_INVALID"],
    ["noncanonical heap frame", { heapBytes: 64 * 1_024 }, "COMPUTE_BUDGET_INVALID"],
    ["extra top-level instruction", { instructionOrder: ["units", "heap", "execute", "execute"] }, "MESSAGE_SHAPE_UNSUPPORTED"],
    ["zero recent blockhash", { blockhash: new Uint8Array(32) }, "MESSAGE_INVALID"],
    ["different fee payer", { payerKey: new PublicKey(fill(0x77)) }, "MESSAGE_INVALID"],
    ["different outer program", { executeProgram: MEMO_PROGRAM }, "MESSAGE_SHAPE_UNSUPPORTED"],
    ["readonly SmartAccount", { executeKeys: (() => {
      const keys = canonicalExecuteKeys();
      keys[0] = { ...keys[0]!, isWritable: false };
      return keys;
    })() }, "MESSAGE_SHAPE_UNSUPPORTED"],
    ["root authorization variant", { executeData: (() => {
      const bytes = inlineExecute(inlinePayload());
      bytes[8] = 1;
      return bytes;
    })() }, "EXECUTE_LAYOUT_INVALID"],
    ["staged payload variant", { executeData: (() => {
      const bytes = inlineExecute(inlinePayload());
      bytes[9] = 0;
      return bytes;
    })() }, "EXECUTE_LAYOUT_INVALID"],
    ["wrong execute payload length", { executeData: (() => {
      const bytes = inlineExecute(inlinePayload());
      bytes[10] = bytes[10]! + 1;
      return bytes;
    })() }, "EXECUTE_LAYOUT_INVALID"],
    ["execute trailing byte", { executeData: (() => {
      const canonical = inlineExecute(inlinePayload());
      const bytes = new Uint8Array(canonical.length + 1);
      bytes.set(canonical);
      return bytes;
    })() }, "EXECUTE_LAYOUT_INVALID"],
    ["malformed inner payload", { payload: Uint8Array.of(1, 2, 0, 2, 0, 0x41) }, "EXECUTE_PAYLOAD_INVALID"],
    ["payload trailing byte", { payload: Uint8Array.of(1, 2, 0, 1, 0, 0x41, 0) }, "EXECUTE_PAYLOAD_INVALID"],
    ["multiple inner instructions", { payload: Uint8Array.of(
      2,
      2, 0, 1, 0, 0x41,
      2, 0, 1, 0, 0x42,
    ) }, "EXECUTE_PAYLOAD_INVALID"],
    ["different logical program", { payload: Uint8Array.of(1, 3, 0, 1, 0, 0x41) }, "INSTRUCTION_UNSUPPORTED"],
    ["inner account reference", { payload: Uint8Array.of(1, 2, 1, 0, 0, 0, 0) }, "INSTRUCTION_UNSUPPORTED"],
    ["empty Memo", { memo: new Uint8Array() }, "MEMO_INVALID"],
    ["control byte in Memo", { memo: Uint8Array.of(0x41, 0x0a) }, "MEMO_INVALID"],
    ["non-ASCII Memo", { memo: Uint8Array.of(0xc3, 0xa9) }, "MEMO_INVALID"],
    ["oversized Memo", { memo: new Uint8Array(257).fill(0x41) }, "MEMO_INVALID"],
  ])("rejects unsupported message shape: %s", (_name, message, code) => {
    const input = fixture({ message });
    captureError(
      () => decodeSessionIntent({ ...input, nowUnixSeconds: 1_900_000_000 }),
      code,
    );
  });
});
