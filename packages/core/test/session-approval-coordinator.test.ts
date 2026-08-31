import { ed25519 } from "@noble/curves/ed25519.js";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  Keypair,
  PublicKey,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import { BPF_UPGRADEABLE_LOADER } from "../src/deploy/config.js";
import {
  approvalDigestsEqual,
  createPendingApprovalRecord,
  resolveApprovalRecord,
  snapshotApprovalRecord,
  type ApprovalCreateParams,
  type ApprovalRecord,
} from "../src/approval/record.js";
import {
  completeApprovalSigningAttempt,
  createApprovalSigningAttempt,
  failApprovalSigningAttempt,
  retryApprovalSigningAttempt,
  snapshotApprovalSigningOutcome,
  snapshotApprovalSigningRecord,
  type ApprovalSigningFailureCode,
  type ApprovalSigningOutcome,
  type ApprovalSigningRecord,
} from "../src/approval/signing-outcome.js";
import { parseSerializedTransactionEnvelope } from "../src/transaction/envelope.js";
import {
  SESSION_APPROVAL_COMMITMENT,
  SessionApprovalCoordinator,
  SessionApprovalCoordinatorError,
  type SessionApprovalAuthorityResolver,
  type SessionApprovalBlockhashClient,
  type SessionApprovalIntentGate,
  type SessionApprovalKeyring,
  type SessionApprovalOwner,
  type SessionAuthoritySnapshot,
} from "../src/transaction/session-approval-coordinator.js";

const fill = (value: number): Uint8Array => new Uint8Array(32).fill(value);
const key = (value: number): PublicKey => new PublicKey(fill(value));
const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length && left.every((value, index) => value === right[index]);

const SMART_SEED = fill(0x11);
const SESSION_SEED = fill(0x22);
const SMART_ACCOUNT = Keypair.fromSeed(SMART_SEED).publicKey;
const SESSION_SIGNER = Keypair.fromSeed(SESSION_SEED).publicKey;
const SESSION_ACCOUNT = key(0x33);
const REGISTRY = key(0x44);
const WARDEN_PROGRAM = new PublicKey(
  "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2",
);
const TARGET_PROGRAM = key(0x55);
const DESTINATION = key(0x66);
const SOURCE_BLOCKHASH = fill(0x77);
const FINAL_BLOCKHASH = fill(0x88);
const GENESIS_HASH = fill(0x99);
const WARDEN_PROGRAM_DATA = PublicKey.findProgramAddressSync(
  [WARDEN_PROGRAM.toBytes()],
  BPF_UPGRADEABLE_LOADER,
)[0];
const WARDEN_PROGRAM_DATA_SLOT = 123n;
const WARDEN_UPGRADE_AUTHORITY = key(0xaa);
const WARDEN_CODE_HASH = fill(0xab);
const WARDEN_PROGRAM_DATA_HASH = fill(0xac);
const OBSERVED_TIME = 1_900_000_000;

function sourceTransaction(): Uint8Array {
  const instruction = new TransactionInstruction({
    programId: TARGET_PROGRAM,
    keys: [{ pubkey: DESTINATION, isSigner: false, isWritable: true }],
    data: Buffer.from([7, 8, 9]),
  });
  const message = new TransactionMessage({
    payerKey: SMART_ACCOUNT,
    recentBlockhash: new PublicKey(SOURCE_BLOCKHASH).toBase58(),
    instructions: [instruction],
  }).compileToV0Message();
  return new VersionedTransaction(message).serialize();
}

function authority(
  overrides: Partial<SessionAuthoritySnapshot> = {},
): SessionAuthoritySnapshot {
  return {
    chain: "solana:devnet",
    genesisHash: GENESIS_HASH,
    smartAccount: SMART_ACCOUNT,
    sessionSigner: SESSION_SIGNER,
    sessionAccount: SESSION_ACCOUNT,
    registry: REGISTRY,
    wardenProgram: WARDEN_PROGRAM,
    wardenProgramData: WARDEN_PROGRAM_DATA,
    wardenProgramDataSlot: WARDEN_PROGRAM_DATA_SLOT,
    wardenUpgradeAuthority: WARDEN_UPGRADE_AUTHORITY,
    wardenCodeHash: WARDEN_CODE_HASH,
    wardenProgramDataHash: WARDEN_PROGRAM_DATA_HASH,
    accountGeneration: 7n,
    policyVersion: 9,
    authorizationState: Uint8Array.of(1, 2, 3, 4),
    observedUnixTimestamp: OBSERVED_TIME,
    contextSlot: 10,
    ...overrides,
  };
}

function request(source = sourceTransaction()) {
  return {
    origin: "https://dapp.example",
    tabId: 2,
    frameId: 0,
    documentId: "document-0123456789",
    requestedAccount: SMART_ACCOUNT.toBytes(),
    method: "solana:signTransaction" as const,
    chain: "solana:devnet" as const,
    sourceTransactionBytes: source,
  };
}

class MemoryApprovalOwner implements SessionApprovalOwner {
  readonly records = new Map<string, ApprovalRecord>();
  readonly outcomes = new Map<string, ApprovalSigningOutcome>();
  readonly events: string[];
  now = 1_001;
  claimThenThrow = false;
  completeThenThrow = false;
  failThenThrow = false;
  readFailures = 0;
  readSigningFailures = 0;
  afterCompleteCommit: (() => void) | undefined;

  constructor(events: string[]) {
    this.events = events;
  }

  async create(params: ApprovalCreateParams): Promise<ApprovalRecord> {
    this.events.push("approval:create");
    if (this.records.has(params.id)) throw new Error("duplicate approval id");
    const record = createPendingApprovalRecord(params);
    this.records.set(record.id, snapshotApprovalRecord(record));
    return snapshotApprovalRecord(record);
  }

  async read(id: string): Promise<ApprovalRecord | null> {
    this.events.push("approval:read");
    if (this.readFailures > 0) {
      this.readFailures--;
      throw new Error("transient approval read failure");
    }
    const record = this.records.get(id);
    return record === undefined ? null : snapshotApprovalRecord(record);
  }

  async readSigning(
    id: string,
    expectedDigest: Uint8Array,
  ): Promise<ApprovalSigningRecord | null> {
    this.events.push("approval:signing-read");
    if (this.readSigningFailures > 0) {
      this.readSigningFailures--;
      throw new Error("transient signing read failure");
    }
    const record = this.records.get(id);
    const outcome = this.outcomes.get(id);
    if (record === undefined || outcome === undefined) return null;
    if (!approvalDigestsEqual(record.messageDigest, expectedDigest)) {
      throw new Error("approval signing digest mismatch");
    }
    return snapshotApprovalSigningRecord({ approval: record, outcome });
  }

  async claimForSigning(
    id: string,
    expectedDigest: Uint8Array,
    attemptId: string,
  ): Promise<ApprovalSigningRecord> {
    this.events.push("approval:claim");
    let current = this.records.get(id);
    if (current === undefined) {
      throw new Error("approval claim refused");
    }
    if (!approvalDigestsEqual(current.messageDigest, expectedDigest)) {
      if (current.state === "pending") {
        const invalidated = resolveApprovalRecord(current, "invalidated", this.now++);
        this.records.set(id, invalidated);
      }
      throw new Error("approval digest mismatch");
    }
    let outcome = this.outcomes.get(id);
    if (current.state === "pending") {
      const resolvedAt = this.now++;
      current = resolveApprovalRecord(current, "approved", resolvedAt);
      outcome = createApprovalSigningAttempt({
        id,
        messageDigest: expectedDigest,
        attemptId,
        attemptNumber: 1,
        startedAt: resolvedAt,
      });
      this.records.set(id, current);
      this.outcomes.set(id, outcome);
    } else if (current.state === "approved" && outcome?.state === "failed") {
      outcome = retryApprovalSigningAttempt(outcome, attemptId, this.now++);
      this.outcomes.set(id, outcome);
    } else if (
      current.state !== "approved" ||
      outcome === undefined ||
      (outcome.state === "signing" && outcome.attemptId !== attemptId)
    ) {
      throw new Error("approval claim refused");
    }
    if (this.claimThenThrow) {
      this.claimThenThrow = false;
      throw new Error("claim acknowledgement lost");
    }
    return snapshotApprovalSigningRecord({ approval: current, outcome });
  }

  async completeSigning(
    id: string,
    expectedDigest: Uint8Array,
    attemptId: string,
    transactionBytes: Uint8Array,
  ): Promise<ApprovalSigningRecord> {
    this.events.push("approval:complete");
    const record = this.records.get(id);
    const outcome = this.outcomes.get(id);
    if (
      record?.state !== "approved" ||
      outcome === undefined ||
      !approvalDigestsEqual(record.messageDigest, expectedDigest)
    ) {
      throw new Error("approval completion refused");
    }
    if (outcome.state === "signed") {
      if (
        outcome.attemptId !== attemptId ||
        outcome.transactionBytes === null ||
        !bytesEqual(outcome.transactionBytes, transactionBytes)
      ) {
        throw new Error("approval completion conflict");
      }
      return snapshotApprovalSigningRecord({ approval: record, outcome });
    }
    if (outcome.state !== "signing" || outcome.attemptId !== attemptId) {
      throw new Error("approval completion stale");
    }
    const completed = completeApprovalSigningAttempt(
      outcome,
      transactionBytes,
      this.now++,
    );
    this.outcomes.set(id, completed);
    this.afterCompleteCommit?.();
    if (this.completeThenThrow) {
      this.completeThenThrow = false;
      throw new Error("completion acknowledgement lost");
    }
    return snapshotApprovalSigningRecord({ approval: record, outcome: completed });
  }

  async failSigning(
    id: string,
    expectedDigest: Uint8Array,
    attemptId: string,
    failureCode: ApprovalSigningFailureCode,
  ): Promise<ApprovalSigningRecord> {
    this.events.push(`approval:fail:${failureCode}`);
    const record = this.records.get(id);
    const outcome = this.outcomes.get(id);
    if (
      record?.state !== "approved" ||
      outcome?.state !== "signing" ||
      outcome.attemptId !== attemptId ||
      !approvalDigestsEqual(record.messageDigest, expectedDigest)
    ) {
      throw new Error("approval failure refused");
    }
    const failed = failApprovalSigningAttempt(
      outcome,
      failureCode,
      this.now++,
    );
    this.outcomes.set(id, failed);
    if (this.failThenThrow) {
      this.failThenThrow = false;
      throw new Error("failure acknowledgement lost");
    }
    return snapshotApprovalSigningRecord({ approval: record, outcome: failed });
  }

  async reject(id: string): Promise<ApprovalRecord> {
    this.events.push("approval:reject");
    return this.resolve(id, "rejected");
  }

  async cancel(id: string): Promise<ApprovalRecord> {
    this.events.push("approval:cancel");
    return this.resolve(id, "cancelled");
  }

  private resolve(
    id: string,
    state: "rejected" | "cancelled",
  ): ApprovalRecord {
    const current = this.records.get(id);
    if (current === undefined || current.state !== "pending") {
      throw new Error(`approval ${state} refused`);
    }
    const resolved = resolveApprovalRecord(current, state, this.now++);
    this.records.set(id, resolved);
    return snapshotApprovalRecord(resolved);
  }
}

interface HarnessOptions {
  readonly resolve?: (
    call: number,
    minContextSlot: number,
  ) => SessionAuthoritySnapshot | Promise<SessionAuthoritySnapshot>;
  readonly valid?: boolean | ((call: number) => boolean);
  readonly latestBlockhash?: Uint8Array;
  readonly validityContextSlot?: number;
  readonly forceValidityContextSlot?: number;
  readonly gate?: SessionApprovalIntentGate;
  readonly lease?: Partial<{
    account: Uint8Array;
    genesisHash: Uint8Array;
    programId: Uint8Array;
    seed: Uint8Array;
  }>;
  readonly mutateKeyringResult?: (result: Uint8Array) => void;
  readonly claimThenThrow?: boolean;
  readonly completeThenThrow?: boolean;
  readonly failThenThrow?: boolean;
  readonly afterCompleteCommit?: () => void;
}

function harness(options: HarnessOptions = {}) {
  const events: string[] = [];
  const intentMessages: Uint8Array[] = [];
  const owner = new MemoryApprovalOwner(events);
  owner.claimThenThrow = options.claimThenThrow ?? false;
  owner.completeThenThrow = options.completeThenThrow ?? false;
  owner.failThenThrow = options.failThenThrow ?? false;
  owner.afterCompleteCommit = options.afterCompleteCommit;
  let resolveCalls = 0;
  let validityCalls = 0;
  const resolver: SessionApprovalAuthorityResolver = {
    async resolve(input) {
      resolveCalls++;
      events.push(`authority:${resolveCalls}:${input.minContextSlot}`);
      expect(input.commitment).toBe(SESSION_APPROVAL_COMMITMENT);
      const resolved = options.resolve === undefined
        ? authority({ contextSlot: Math.max(input.minContextSlot, resolveCalls * 10) })
        : await options.resolve(resolveCalls, input.minContextSlot);
      return resolved;
    },
  };
  const blockhash: SessionApprovalBlockhashClient = {
    async getLatestBlockhash(input) {
      events.push(`blockhash:latest:${input.minContextSlot}`);
      expect(input.commitment).toBe(SESSION_APPROVAL_COMMITMENT);
      expect(input.chain).toBe("solana:devnet");
      expect(input.genesisHash).toEqual(GENESIS_HASH);
      return {
        blockhash: options.latestBlockhash ?? FINAL_BLOCKHASH,
        lastValidBlockHeight: 500,
        contextSlot: Math.max(input.minContextSlot, 20),
      };
    },
    async isBlockhashValid(input) {
      validityCalls++;
      events.push(`blockhash:valid:${input.minContextSlot}`);
      expect(input.commitment).toBe(SESSION_APPROVAL_COMMITMENT);
      expect(input.chain).toBe("solana:devnet");
      expect(input.genesisHash).toEqual(GENESIS_HASH);
      expect(input.blockhash).toEqual(FINAL_BLOCKHASH);
      return {
        valid: typeof options.valid === "function"
          ? options.valid(validityCalls)
          : options.valid ?? true,
        contextSlot: options.forceValidityContextSlot ?? Math.max(
          input.minContextSlot,
          options.validityContextSlot ?? 50,
        ),
      };
    },
  };
  const gate = options.gate ?? {
    assertAllowed(input) {
      events.push(`intent:${input.authority.contextSlot}`);
      intentMessages.push(input.messageBytes.slice());
      const unsigned = new Uint8Array(65 + input.messageBytes.length);
      unsigned[0] = 1;
      unsigned.set(input.messageBytes, 65);
      const parsed = parseSerializedTransactionEnvelope(
        unsigned,
        input.authority.sessionSigner.toBytes(),
      );
      expect(parsed.messageBytes).toEqual(input.messageBytes);
    },
  };
  const keyring: SessionApprovalKeyring = {
    async useSessionSignerBytes(operation, use) {
      events.push(`keyring:start:${operation}`);
      const result = await use({
        account: options.lease?.account ?? SMART_ACCOUNT.toBytes(),
        genesisHash: options.lease?.genesisHash ?? GENESIS_HASH,
        programId: options.lease?.programId ?? WARDEN_PROGRAM.toBytes(),
        seed: options.lease?.seed ?? SESSION_SEED,
      });
      options.mutateKeyringResult?.(result);
      events.push("keyring:end");
      return result;
    },
  };
  const coordinator = new SessionApprovalCoordinator(
    { authority: resolver, blockhash, intent: gate, approvals: owner, keyring },
    { readNow: () => 1_000, approvalTtlMs: 60_000 },
  );
  return {
    coordinator,
    events,
    intentMessages,
    owner,
    get resolveCalls() {
      return resolveCalls;
    },
  };
}

async function captureError(
  run: Promise<unknown>,
  code: SessionApprovalCoordinatorError["code"],
): Promise<SessionApprovalCoordinatorError> {
  try {
    await run;
  } catch (error) {
    expect(error).toBeInstanceOf(SessionApprovalCoordinatorError);
    expect((error as SessionApprovalCoordinatorError).code).toBe(code);
    return error as SessionApprovalCoordinatorError;
  }
  throw new Error(`expected coordinator error ${code}`);
}

describe("session approval coordinator", () => {
  it("publishes a separate opt-in coordinator subpath without widening the parser boundary", async () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(import.meta.dirname, "../package.json"), "utf8"),
    ) as { exports: Record<string, { import: string; types: string }> };
    expect(packageJson.exports["./transaction/session-approval"]).toEqual({
      types: "./dist/transaction/session-approval-coordinator.d.ts",
      import: "./dist/transaction/session-approval-coordinator.js",
    });
    const parser = await import("../src/transaction/index.js");
    expect("SessionApprovalCoordinator" in parser).toBe(false);
  });

  it("orders authority, exact-message approval, CAS, contextual lease, validity, and signing", async () => {
    const { coordinator, events, intentMessages, owner } = harness();
    const source = sourceTransaction();
    const prepared = await coordinator.prepare(request(source));
    source.fill(0xff);

    const pending = owner.records.get(prepared.id)!;
    expect(pending.state).toBe("pending");
    expect(pending.rawMessage).not.toEqual(source);
    expect(pending.messageDigest).toEqual(prepared.messageDigest);
    expect(pending.account).toEqual(SMART_ACCOUNT.toBytes());
    expect(pending.genesisHash).toEqual(GENESIS_HASH);
    expect(pending.programId).toEqual(WARDEN_PROGRAM.toBytes());
    expect(prepared.blockhash).toEqual(FINAL_BLOCKHASH);
    expect(prepared.lastValidBlockHeight).toBe(500);

    const signed = await coordinator.approve(prepared.id, prepared.messageDigest);
    const envelope = parseSerializedTransactionEnvelope(
      signed.transactionBytes,
      SESSION_SIGNER.toBytes(),
    );
    expect(envelope.messageBytes).toEqual(pending.rawMessage);
    expect(envelope.recentBlockhash).toEqual(FINAL_BLOCKHASH);
    expect(signed.messageDigest).toEqual(pending.messageDigest);
    expect(ed25519.verify(
      envelope.signatures[0]!,
      envelope.messageBytes,
      SESSION_SIGNER.toBytes(),
    )).toBe(true);
    expect(owner.records.get(prepared.id)?.state).toBe("approved");
    expect(intentMessages).toHaveLength(4);
    expect(intentMessages.every((message) => bytesEqual(message, pending.rawMessage)))
      .toBe(true);
    expect(events).toEqual([
      "authority:1:0",
      "blockhash:latest:10",
      "authority:2:20",
      "intent:20",
      "approval:create",
      "approval:read",
      "authority:3:20",
      "intent:30",
      "approval:claim",
      "authority:4:30",
      "blockhash:valid:40",
      "authority:5:50",
      "intent:50",
      "keyring:start:sign approved session transaction",
      "authority:6:50",
      "intent:60",
      "keyring:end",
      "approval:complete",
    ]);

    const expectedTransaction = signed.transactionBytes;
    const expectedSignature = signed.signature;
    const eventsBeforeReplay = [...events];
    prepared.messageDigest.fill(0);
    signed.transactionBytes.fill(0);
    signed.signature.fill(0);
    expect(owner.records.get(prepared.id)?.messageDigest).toEqual(
      pending.messageDigest,
    );
    const replayed = await coordinator.approve(prepared.id, pending.messageDigest);
    expect(replayed.transactionBytes).toEqual(expectedTransaction);
    expect(replayed.signature).toEqual(expectedSignature);
    expect(events).toEqual([...eventsBeforeReplay, "approval:signing-read"]);
    replayed.transactionBytes.fill(0);
    expect(owner.outcomes.get(prepared.id)?.transactionBytes).toEqual(
      expectedTransaction,
    );
  });

  it("persists a failed attempt and retries it under a fresh CAS token", async () => {
    const test = harness({ valid: (call) => call > 1 });
    const prepared = await test.coordinator.prepare(request());

    await captureError(
      test.coordinator.approve(prepared.id, prepared.messageDigest),
      "BLOCKHASH_INVALID",
    );
    const failed = snapshotApprovalSigningOutcome(
      test.owner.outcomes.get(prepared.id),
    );
    expect(failed.state).toBe("failed");
    expect(failed.failureCode).toBe("blockhash-invalid");
    expect(failed.attemptNumber).toBe(1);
    expect(test.events).toContain("approval:fail:blockhash-invalid");

    const signed = await test.coordinator.approve(
      prepared.id,
      prepared.messageDigest,
    );
    const completed = test.owner.outcomes.get(prepared.id)!;
    expect(completed.state).toBe("signed");
    expect(completed.attemptNumber).toBe(2);
    expect(completed.attemptId).not.toBe(failed.attemptId);
    expect(completed.transactionBytes).toEqual(signed.transactionBytes);
    expect(test.events.filter((event) => event === "approval:claim")).toHaveLength(2);
    expect(test.events.filter((event) => event === "approval:complete"))
      .toHaveLength(1);
  });

  it("recovers a committed claim after its acknowledgement is lost", async () => {
    const test = harness({ claimThenThrow: true });
    const prepared = await test.coordinator.prepare(request());

    const signed = await test.coordinator.approve(
      prepared.id,
      prepared.messageDigest,
    );
    expect(signed.transactionBytes.length).toBeGreaterThan(0);
    expect(test.owner.outcomes.get(prepared.id)?.state).toBe("signed");
    expect(test.events.filter((event) => event === "approval:claim")).toHaveLength(1);
    expect(test.events.filter((event) => event === "approval:signing-read"))
      .toHaveLength(1);
    expect(test.events.some((event) => event.startsWith("approval:fail:")))
      .toBe(false);
  });

  it("recovers a committed completion after its acknowledgement is lost", async () => {
    const test = harness({ completeThenThrow: true });
    const prepared = await test.coordinator.prepare(request());

    const signed = await test.coordinator.approve(
      prepared.id,
      prepared.messageDigest,
    );
    const durable = test.owner.outcomes.get(prepared.id)!;
    expect(durable.state).toBe("signed");
    expect(durable.transactionBytes).toEqual(signed.transactionBytes);
    expect(test.events.slice(-2)).toEqual([
      "approval:complete",
      "approval:signing-read",
    ]);
    expect(test.events.some((event) => event.startsWith("approval:fail:")))
      .toBe(false);
  });

  it("recovers a committed failure after its acknowledgement is lost", async () => {
    const test = harness({ valid: (call) => call > 1, failThenThrow: true });
    const prepared = await test.coordinator.prepare(request());

    await captureError(
      test.coordinator.approve(prepared.id, prepared.messageDigest),
      "BLOCKHASH_INVALID",
    );
    expect(test.owner.outcomes.get(prepared.id)).toMatchObject({
      state: "failed",
      failureCode: "blockhash-invalid",
      attemptNumber: 1,
    });

    const signed = await test.coordinator.approve(
      prepared.id,
      prepared.messageDigest,
    );
    expect(signed.transactionBytes.length).toBeGreaterThan(0);
    expect(test.owner.outcomes.get(prepared.id)).toMatchObject({
      state: "signed",
      attemptNumber: 2,
    });
    expect(test.events.filter((event) => event === "approval:signing-read"))
      .toHaveLength(2);
  });

  it("retains the sole authority capsule across uncertain durable reads", async () => {
    const pendingRead = harness();
    const pending = await pendingRead.coordinator.prepare(request());
    pendingRead.owner.readFailures = 1;
    await captureError(
      pendingRead.coordinator.approve(pending.id, pending.messageDigest),
      "APPROVAL_RECORD_MISMATCH",
    );
    await expect(pendingRead.coordinator.approve(
      pending.id,
      pending.messageDigest,
    )).resolves.toBeDefined();

    const failedRead = harness({ valid: (call) => call > 1 });
    const failed = await failedRead.coordinator.prepare(request());
    await captureError(
      failedRead.coordinator.approve(failed.id, failed.messageDigest),
      "BLOCKHASH_INVALID",
    );
    failedRead.owner.readSigningFailures = 1;
    await captureError(
      failedRead.coordinator.approve(failed.id, failed.messageDigest),
      "APPROVAL_RECORD_MISMATCH",
    );
    await expect(failedRead.coordinator.approve(
      failed.id,
      failed.messageDigest,
    )).resolves.toBeDefined();
  });

  it("releases no signed bytes when disposal races durable completion", async () => {
    let dispose = (): void => {};
    const test = harness({ afterCompleteCommit: () => dispose() });
    dispose = () => test.coordinator.dispose();
    const prepared = await test.coordinator.prepare(request());

    await captureError(
      test.coordinator.approve(prepared.id, prepared.messageDigest),
      "DISPOSED",
    );
    expect(test.owner.outcomes.get(prepared.id)?.state).toBe("signed");
    expect(test.events.some((event) => event.startsWith("approval:fail:")))
      .toBe(false);
  });

  it("rejects sign-and-send before authority/RPC work because no durable result owner exists", async () => {
    const test = harness();
    const unsupported = {
      ...request(),
      method: "solana:signAndSendTransaction",
    } as unknown as Parameters<SessionApprovalCoordinator["prepare"]>[0];
    await captureError(test.coordinator.prepare(unsupported), "UNSUPPORTED_METHOD");
    expect(test.resolveCalls).toBe(0);
    expect(test.owner.records.size).toBe(0);
    expect(test.events).toEqual([]);
  });

  it.each([
    ["smart account", { smartAccount: key(0xa1) }, "AUTHORITY_INVALID"],
    ["chain", { chain: "solana:mainnet" as const }, "AUTHORITY_INVALID"],
    ["genesis", { genesisHash: fill(0xa2) }, "AUTHORITY_CHANGED"],
    ["session signer", { sessionSigner: key(0xa3) }, "AUTHORITY_CHANGED"],
    ["session account", { sessionAccount: key(0xa4) }, "AUTHORITY_CHANGED"],
    ["registry", { registry: key(0xa5) }, "AUTHORITY_CHANGED"],
    ["program", { wardenProgram: key(0xa6) }, "AUTHORITY_CHANGED"],
    ["program data", { wardenProgramData: key(0xa7) }, "AUTHORITY_CHANGED"],
    ["program data slot", { wardenProgramDataSlot: 124n }, "AUTHORITY_CHANGED"],
    ["upgrade authority", { wardenUpgradeAuthority: key(0xa8) }, "AUTHORITY_CHANGED"],
    ["code hash", { wardenCodeHash: fill(0xa9) }, "AUTHORITY_CHANGED"],
    ["program data hash", { wardenProgramDataHash: fill(0xaa) }, "AUTHORITY_CHANGED"],
    ["generation", { accountGeneration: 8n }, "AUTHORITY_CHANGED"],
    ["policy", { policyVersion: 10 }, "AUTHORITY_CHANGED"],
    ["authorization state", { authorizationState: Uint8Array.of(9) }, "AUTHORITY_CHANGED"],
    ["Clock regression", { observedUnixTimestamp: OBSERVED_TIME - 1 }, "AUTHORITY_CHANGED"],
  ] satisfies ReadonlyArray<readonly [
    string,
    Partial<SessionAuthoritySnapshot>,
    SessionApprovalCoordinatorError["code"],
  ]>) (
    "refuses %s drift between initial authority and blockhash-bound preparation",
    async (_name, drift, expectedCode) => {
      const test = harness({
        resolve(call, minContextSlot) {
          return authority({
            contextSlot: Math.max(minContextSlot, call * 10),
            ...(call === 2 ? drift : {}),
          });
        },
      });
      await captureError(test.coordinator.prepare(request()), expectedCode);
      expect(test.owner.records.size).toBe(0);
      expect(test.events).not.toContain("approval:create");
    },
  );

  it("permits forward Clock observations and gives each intent check the latest snapshot", async () => {
    const observed: number[] = [];
    const test = harness({
      resolve(call, minContextSlot) {
        return authority({
          contextSlot: Math.max(minContextSlot, call * 10),
          observedUnixTimestamp: OBSERVED_TIME + call,
        });
      },
      gate: {
        assertAllowed(input) {
          observed.push(input.authority.observedUnixTimestamp);
        },
      },
    });

    const prepared = await test.coordinator.prepare(request());
    await test.coordinator.approve(prepared.id, prepared.messageDigest);
    expect(observed).toEqual([
      OBSERVED_TIME + 2,
      OBSERVED_TIME + 3,
      OBSERVED_TIME + 5,
      OBSERVED_TIME + 6,
    ]);
  });

  it("rejects a Clock regression from the immediately preceding observation", async () => {
    const test = harness({
      resolve(call, minContextSlot) {
        const observedUnixTimestamp = call === 3
          ? OBSERVED_TIME + 10
          : call === 4
            ? OBSERVED_TIME + 5
            : OBSERVED_TIME;
        return authority({
          contextSlot: Math.max(minContextSlot, call * 10),
          observedUnixTimestamp,
        });
      },
    });

    const prepared = await test.coordinator.prepare(request());
    await captureError(
      test.coordinator.approve(prepared.id, prepared.messageDigest),
      "AUTHORITY_CHANGED",
    );
    expect(test.owner.records.get(prepared.id)?.state).toBe("approved");
    expect(test.owner.outcomes.get(prepared.id)?.state).toBe("failed");
    expect(test.owner.outcomes.get(prepared.id)?.failureCode)
      .toBe("authority-check-failed");
    expect(test.events.some((event) => event.startsWith("keyring:"))).toBe(false);
  });

  it("cancels before claim when current authority or policy changed", async () => {
    const test = harness({
      resolve(call, minContextSlot) {
        return authority({
          contextSlot: Math.max(minContextSlot, call * 10),
          ...(call === 3 ? { policyVersion: 10 } : {}),
        });
      },
    });
    const prepared = await test.coordinator.prepare(request());
    await captureError(
      test.coordinator.approve(prepared.id, prepared.messageDigest),
      "AUTHORITY_CHANGED",
    );
    expect(test.owner.records.get(prepared.id)?.state).toBe("cancelled");
    expect(test.events).not.toContain("approval:claim");
    expect(test.events.some((event) => event.startsWith("keyring:"))).toBe(false);
  });

  it.each([
    ["after claim", 4],
    ["after validity response", 5],
    ["inside the key lease", 6],
  ])("releases no signature when authority changes %s", async (_name, driftCall) => {
    const test = harness({
      resolve(call, minContextSlot) {
        return authority({
          contextSlot: Math.max(minContextSlot, call * 10),
          ...(call === driftCall
            ? { authorizationState: Uint8Array.of(1, 2, 3, 5) }
            : {}),
        });
      },
    });
    const prepared = await test.coordinator.prepare(request());
    await captureError(
      test.coordinator.approve(prepared.id, prepared.messageDigest),
      "AUTHORITY_CHANGED",
    );
    expect(test.owner.records.get(prepared.id)?.state).toBe("approved");
    expect(test.owner.outcomes.get(prepared.id)?.state).toBe("failed");
    expect(test.owner.outcomes.get(prepared.id)?.failureCode)
      .toBe("authority-check-failed");
    expect(test.events).not.toContain("keyring:end");
  });

  it("consumes a claimed attempt when the exact approved blockhash is invalid and never refreshes it", async () => {
    const test = harness({ valid: false });
    const prepared = await test.coordinator.prepare(request());
    await captureError(
      test.coordinator.approve(prepared.id, prepared.messageDigest),
      "BLOCKHASH_INVALID",
    );
    expect(test.owner.records.get(prepared.id)?.state).toBe("approved");
    expect(test.owner.outcomes.get(prepared.id)?.state).toBe("failed");
    expect(test.owner.outcomes.get(prepared.id)?.failureCode)
      .toBe("blockhash-invalid");
    expect(test.events.filter((event) => event.startsWith("blockhash:latest")))
      .toHaveLength(1);
    expect(test.events.filter((event) => event.startsWith("blockhash:valid")))
      .toHaveLength(1);
    expect(test.events.some((event) => event.startsWith("keyring:"))).toBe(false);
  });

  it("rejects regressing authority and validity contexts instead of accepting stale observations", async () => {
    const authorityRegression = harness({
      resolve(call, minContextSlot) {
        return authority({
          contextSlot: call === 2 ? minContextSlot - 1 : Math.max(minContextSlot, 10),
        });
      },
    });
    await captureError(
      authorityRegression.coordinator.prepare(request()),
      "AUTHORITY_INVALID",
    );
    expect(authorityRegression.owner.records.size).toBe(0);

    const validityRegression = harness({ forceValidityContextSlot: 1 });
    const prepared = await validityRegression.coordinator.prepare(request());
    await captureError(
      validityRegression.coordinator.approve(prepared.id, prepared.messageDigest),
      "BLOCKHASH_INVALID",
    );
    expect(validityRegression.owner.records.get(prepared.id)?.state).toBe("approved");
    expect(validityRegression.owner.outcomes.get(prepared.id)?.failureCode)
      .toBe("blockhash-invalid");
    expect(validityRegression.resolveCalls).toBe(4);
  });

  it("atomically invalidates a UI digest mismatch before authority or key use", async () => {
    const test = harness();
    const prepared = await test.coordinator.prepare(request());
    const wrong = prepared.messageDigest;
    wrong[0] ^= 0xff;
    await captureError(
      test.coordinator.approve(prepared.id, wrong),
      "APPROVAL_DIGEST_MISMATCH",
    );
    expect(test.owner.records.get(prepared.id)?.state).toBe("invalidated");
    expect(test.resolveCalls).toBe(2);
    expect(test.events.at(-1)).toBe("approval:claim");
  });

  it("drops a capsule when trusted storage metadata no longer matches its exact binding", async () => {
    const test = harness();
    const prepared = await test.coordinator.prepare(request());
    const current = test.owner.records.get(prepared.id)!;
    test.owner.records.set(prepared.id, createPendingApprovalRecord({
      ...current,
      origin: "https://other.example",
    }));

    await captureError(
      test.coordinator.approve(prepared.id, prepared.messageDigest),
      "APPROVAL_RECORD_MISMATCH",
    );
    expect(test.events).not.toContain("approval:claim");
    expect(test.events.some((event) => event.startsWith("keyring:"))).toBe(false);
    await captureError(
      test.coordinator.approve(prepared.id, prepared.messageDigest),
      "APPROVAL_NOT_ACTIVE",
    );
  });

  it.each([
    ["account", { account: fill(0xa1) }],
    ["genesis", { genesisHash: fill(0xa2) }],
    ["program", { programId: fill(0xa3) }],
  ])("matches the keyring's authenticated %s context after claim", async (_name, lease) => {
    const test = harness({ lease });
    const prepared = await test.coordinator.prepare(request());
    await captureError(
      test.coordinator.approve(prepared.id, prepared.messageDigest),
      "KEYRING_CONTEXT_MISMATCH",
    );
    expect(test.owner.records.get(prepared.id)?.state).toBe("approved");
    expect(test.owner.outcomes.get(prepared.id)?.failureCode)
      .toBe("keyring-context-mismatch");
    expect(test.resolveCalls).toBe(5);
    expect(test.events).not.toContain("keyring:end");
  });

  it("blocks an async or throwing intent gate instead of treating it as a verdict", async () => {
    const asyncGate = {
      assertAllowed: (() => Promise.resolve()) as unknown as SessionApprovalIntentGate["assertAllowed"],
    };
    const asyncTest = harness({ gate: asyncGate });
    await captureError(asyncTest.coordinator.prepare(request()), "INTENT_BLOCKED");
    expect(asyncTest.owner.records.size).toBe(0);

    const throwingTest = harness({
      gate: {
        assertAllowed() {
          throw new Error("unknown program");
        },
      },
    });
    const error = await captureError(
      throwingTest.coordinator.prepare(request()),
      "INTENT_BLOCKED",
    );
    expect(error.cause).toEqual(new Error("unknown program"));
    expect(throwingTest.owner.records.size).toBe(0);
  });

  it("rejects a signature mutated by the keyring boundary after the exact finalizer returns", async () => {
    const test = harness({
      mutateKeyringResult(result) {
        result[1] ^= 0xff;
      },
    });
    const prepared = await test.coordinator.prepare(request());
    await captureError(
      test.coordinator.approve(prepared.id, prepared.messageDigest),
      "SIGNED_RESULT_INVALID",
    );
    expect(test.owner.records.get(prepared.id)?.state).toBe("approved");
    expect(test.owner.outcomes.get(prepared.id)?.failureCode)
      .toBe("signed-result-invalid");
  });

  it("lets a concurrent cancellation win before claim and never enters the keyring", async () => {
    let release!: () => void;
    let entered!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    const started = new Promise<void>((resolve) => { entered = resolve; });
    const test = harness({
      async resolve(call, minContextSlot) {
        if (call === 3) {
          entered();
          await blocked;
        }
        return authority({ contextSlot: Math.max(minContextSlot, call * 10) });
      },
    });
    const prepared = await test.coordinator.prepare(request());
    const signing = test.coordinator.approve(prepared.id, prepared.messageDigest);
    await started;
    await test.coordinator.cancel(prepared.id);
    release();
    await captureError(signing, "APPROVAL_CLAIM_FAILED");
    expect(test.owner.records.get(prepared.id)?.state).toBe("cancelled");
    expect(test.events.some((event) => event.startsWith("keyring:"))).toBe(false);
  });

  it("allows only one of two concurrent approve calls to reach the atomic claim", async () => {
    let release!: () => void;
    let entered!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    const started = new Promise<void>((resolve) => { entered = resolve; });
    const test = harness({
      async resolve(call, minContextSlot) {
        if (call === 3) {
          entered();
          await blocked;
        }
        return authority({ contextSlot: Math.max(minContextSlot, call * 10) });
      },
    });
    const prepared = await test.coordinator.prepare(request());
    const first = test.coordinator.approve(prepared.id, prepared.messageDigest);
    await started;
    await captureError(
      test.coordinator.approve(prepared.id, prepared.messageDigest),
      "APPROVAL_NOT_ACTIVE",
    );
    release();
    await expect(first).resolves.toBeDefined();
    expect(test.events.filter((event) => event === "approval:claim")).toHaveLength(1);
    expect(test.events.filter((event) => event === "keyring:end")).toHaveLength(1);
  });

  it("copy-owns resolver, RPC, result, and gate buffers", async () => {
    const mutableGenesis = GENESIS_HASH.slice();
    const mutableState = Uint8Array.of(1, 2, 3, 4);
    const mutableBlockhash = FINAL_BLOCKHASH.slice();
    const test = harness({
      latestBlockhash: mutableBlockhash,
      gate: {
        assertAllowed(input) {
          const unsigned = new Uint8Array(65 + input.messageBytes.length);
          unsigned[0] = 1;
          unsigned.set(input.messageBytes, 65);
          expect(parseSerializedTransactionEnvelope(
            unsigned,
            input.authority.sessionSigner.toBytes(),
          ).recentBlockhash).toEqual(FINAL_BLOCKHASH);
          input.messageBytes.fill(0);
          input.authority.genesisHash.fill(0);
          input.authority.authorizationState.fill(0);
        },
      },
      resolve(call, minContextSlot) {
        return authority({
          genesisHash: mutableGenesis,
          authorizationState: mutableState,
          contextSlot: Math.max(minContextSlot, call * 10),
        });
      },
    });
    const prepared = await test.coordinator.prepare(request());
    mutableGenesis.fill(0);
    mutableState.fill(0);
    mutableBlockhash.fill(0);
    expect(prepared.blockhash).toEqual(FINAL_BLOCKHASH);
    expect(test.owner.records.get(prepared.id)?.genesisHash).toEqual(GENESIS_HASH);
    expect(test.owner.records.get(prepared.id)?.rawMessage.every((byte) => byte === 0))
      .toBe(false);
  });
});
