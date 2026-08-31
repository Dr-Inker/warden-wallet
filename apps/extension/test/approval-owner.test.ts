import { describe, expect, it } from "vitest";

import {
  approvalDigestsEqual,
  completeApprovalSigningAttempt,
  createPendingApprovalRecord,
  createApprovalSigningAttempt,
  failApprovalSigningAttempt,
  resolveApprovalRecord,
  retryApprovalSigningAttempt,
  snapshotApprovalSigningOutcome,
  snapshotApprovalRecord,
  type ApprovalCreateParams,
  type ApprovalRecord,
  type ApprovalSigningFailureCode,
  type ApprovalSigningOutcome,
  type ApprovalTerminalState,
} from "@warden/core/approval";
import {
  ApprovalOwner,
  type ApprovalRecordRepository,
  type ApprovalTransition,
} from "../src/background/approval-owner.js";

const fill = (length: number, value: number): Uint8Array =>
  new Uint8Array(length).fill(value);

function input(idByte = "ab"): ApprovalCreateParams {
  return {
    id: `req_${idByte.repeat(16)}`,
    origin: "https://dapp.example",
    tabId: 2,
    frameId: 0,
    documentId: "document-0123456789",
    account: fill(32, 0x11),
    method: "solana:signTransaction",
    chain: "solana:devnet",
    genesisHash: fill(32, 0x22),
    programId: fill(32, 0x33),
    rawMessage: new Uint8Array([1, 2, 3]),
    policyVersion: 9,
    createdAt: 1_000,
    expiresAt: 2_000,
  };
}

class MemoryApprovalRepository implements ApprovalRecordRepository {
  readonly records = new Map<string, ApprovalRecord>();
  readonly outcomes = new Map<string, ApprovalSigningOutcome>();
  readonly transitions: ApprovalTransition[] = [];
  invalidatedAt: number | undefined;

  async create(record: ApprovalRecord, now: number): Promise<ApprovalRecord> {
    if (now >= record.expiresAt || this.records.has(record.id)) {
      throw new Error("create refused");
    }
    const snapshot = snapshotApprovalRecord(record);
    this.records.set(record.id, snapshot);
    return snapshotApprovalRecord(snapshot);
  }

  async read(id: string, _now: number): Promise<ApprovalRecord | null> {
    const record = this.records.get(id);
    return record === undefined ? null : snapshotApprovalRecord(record);
  }

  async readSigning(input: {
    readonly id: string;
    readonly expectedDigest: Uint8Array;
  }) {
    const record = this.records.get(input.id);
    const outcome = this.outcomes.get(input.id);
    if (record === undefined || outcome === undefined) return null;
    if (!approvalDigestsEqual(record.messageDigest, input.expectedDigest)) {
      throw new Error("digest mismatch");
    }
    return {
      approval: snapshotApprovalRecord(record),
      outcome: snapshotApprovalSigningOutcome(outcome),
    };
  }

  async claimSigning(input: {
    readonly id: string;
    readonly expectedDigest: Uint8Array;
    readonly attemptId: string;
    readonly now: number;
  }) {
    let record = this.records.get(input.id);
    if (record === undefined) throw new Error("missing");
    if (!approvalDigestsEqual(record.messageDigest, input.expectedDigest)) {
      throw new Error("digest mismatch");
    }
    let outcome = this.outcomes.get(input.id);
    if (record.state === "pending") {
      record = resolveApprovalRecord(record, "approved", input.now);
      outcome = createApprovalSigningAttempt({
        id: input.id,
        messageDigest: input.expectedDigest,
        attemptId: input.attemptId,
        attemptNumber: 1,
        startedAt: input.now,
      });
      this.records.set(input.id, record);
      this.outcomes.set(input.id, outcome);
    } else if (record.state === "approved" && outcome?.state === "failed") {
      outcome = retryApprovalSigningAttempt(outcome, input.attemptId, input.now);
      this.outcomes.set(input.id, outcome);
    } else if (
      record.state !== "approved" ||
      outcome === undefined ||
      (outcome.state === "signing" && outcome.attemptId !== input.attemptId)
    ) {
      throw new Error("claim refused");
    }
    return {
      approval: snapshotApprovalRecord(record),
      outcome: snapshotApprovalSigningOutcome(outcome),
    };
  }

  async completeSigning(input: {
    readonly id: string;
    readonly expectedDigest: Uint8Array;
    readonly attemptId: string;
    readonly transactionBytes: Uint8Array;
    readonly now: number;
  }) {
    const record = this.records.get(input.id);
    const outcome = this.outcomes.get(input.id);
    if (
      record?.state !== "approved" ||
      outcome?.state !== "signing" ||
      outcome.attemptId !== input.attemptId ||
      !approvalDigestsEqual(record.messageDigest, input.expectedDigest)
    ) {
      throw new Error("completion refused");
    }
    const completed = completeApprovalSigningAttempt(
      outcome,
      input.transactionBytes,
      input.now,
    );
    this.outcomes.set(input.id, completed);
    return {
      approval: snapshotApprovalRecord(record),
      outcome: snapshotApprovalSigningOutcome(completed),
    };
  }

  async failSigning(input: {
    readonly id: string;
    readonly expectedDigest: Uint8Array;
    readonly attemptId: string;
    readonly failureCode: ApprovalSigningFailureCode;
    readonly now: number;
  }) {
    const record = this.records.get(input.id);
    const outcome = this.outcomes.get(input.id);
    if (
      record?.state !== "approved" ||
      outcome?.state !== "signing" ||
      outcome.attemptId !== input.attemptId ||
      !approvalDigestsEqual(record.messageDigest, input.expectedDigest)
    ) {
      throw new Error("failure refused");
    }
    const failed = failApprovalSigningAttempt(outcome, input.failureCode, input.now);
    this.outcomes.set(input.id, failed);
    return {
      approval: snapshotApprovalRecord(record),
      outcome: snapshotApprovalSigningOutcome(failed),
    };
  }

  async transition(transition: ApprovalTransition): Promise<ApprovalRecord> {
    this.transitions.push({ ...transition });
    const current = this.records.get(transition.id);
    if (current === undefined || current.state !== "pending") {
      throw new Error("transition refused");
    }
    const resolved = resolveApprovalRecord(
      current,
      transition.state as ApprovalTerminalState,
      transition.now,
    );
    this.records.set(current.id, resolved);
    return snapshotApprovalRecord(resolved);
  }

  async invalidatePending(now: number): Promise<number> {
    this.invalidatedAt = now;
    let count = 0;
    for (const [id, record] of this.records) {
      if (record.state === "pending") {
        this.records.set(id, resolveApprovalRecord(record, "cancelled", now));
        count++;
      } else if (record.state === "approved") {
        const outcome = this.outcomes.get(id);
        if (outcome?.state === "signing") {
          this.outcomes.set(
            id,
            failApprovalSigningAttempt(outcome, "worker-restarted", now),
          );
          count++;
        }
      }
    }
    return count;
  }

  close(): void {}
}

describe("approval owner", () => {
  it("creates from copied bytes and uses its live clock on every repository operation", async () => {
    let now = 1_100;
    const repository = new MemoryApprovalRepository();
    const owner = new ApprovalOwner(repository, { readNow: () => now });
    const params = input();
    const created = await owner.create(params);
    params.rawMessage.fill(0xff);

    expect(created.rawMessage).toEqual(new Uint8Array([1, 2, 3]));
    now = 1_200;
    const view = await owner.read(created.id);
    expect(view?.rawMessage).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("durably claims and completes one exact attempt, then replays its owned bytes", async () => {
    let now = 1_100;
    const repository = new MemoryApprovalRepository();
    const owner = new ApprovalOwner(repository, { readNow: () => now });
    const first = await owner.create(input("ab"));
    now = 1_200;
    const attemptId = `attempt_${"11".repeat(16)}`;
    const claimed = await owner.claimForSigning(
      first.id,
      first.messageDigest,
      attemptId,
    );
    now = 1_300;
    const completed = await owner.completeSigning(
      first.id,
      first.messageDigest,
      attemptId,
      Uint8Array.of(1, 2, 3, 4),
    );
    completed.outcome.transactionBytes!.fill(0);
    const replay = await owner.readSigning(first.id, first.messageDigest);
    const reclaimed = await owner.claimForSigning(
      first.id,
      first.messageDigest,
      `attempt_${"22".repeat(16)}`,
    );

    expect(claimed.approval.state).toBe("approved");
    expect(claimed.outcome.state).toBe("signing");
    expect(replay?.outcome.state).toBe("signed");
    expect(replay?.outcome.transactionBytes).toEqual(Uint8Array.of(1, 2, 3, 4));
    expect(reclaimed.outcome.state).toBe("signed");
    expect(reclaimed.outcome.attemptId).toBe(attemptId);
  });

  it("persists a closed failure, retries with a fresh token, and rejects a stale finisher", async () => {
    let now = 1_100;
    const repository = new MemoryApprovalRepository();
    const owner = new ApprovalOwner(repository, { readNow: () => now });
    const created = await owner.create(input("cd"));
    const firstAttempt = `attempt_${"33".repeat(16)}`;
    const secondAttempt = `attempt_${"44".repeat(16)}`;

    now = 1_200;
    await owner.claimForSigning(created.id, created.messageDigest, firstAttempt);
    now = 1_250;
    const failed = await owner.failSigning(
      created.id,
      created.messageDigest,
      firstAttempt,
      "blockhash-invalid",
    );
    now = 1_300;
    const retry = await owner.claimForSigning(
      created.id,
      created.messageDigest,
      secondAttempt,
    );

    expect(failed.outcome).toMatchObject({
      state: "failed",
      failureCode: "blockhash-invalid",
      attemptNumber: 1,
    });
    expect(retry.outcome).toMatchObject({
      state: "signing",
      attemptId: secondAttempt,
      attemptNumber: 2,
    });
    await expect(owner.completeSigning(
      created.id,
      created.messageDigest,
      firstAttempt,
      Uint8Array.of(9),
    )).rejects.toThrow("completion refused");
  });

  it("cancels pending records and marks orphaned signing attempts failed at worker startup", async () => {
    const repository = new MemoryApprovalRepository();
    repository.records.set(
      input().id,
      createPendingApprovalRecord(input()),
    );
    const owner = new ApprovalOwner(repository, { readNow: () => 1_500 });
    const claimedInput = input("ef");
    const claimed = createPendingApprovalRecord(claimedInput);
    repository.records.set(
      claimed.id,
      resolveApprovalRecord(claimed, "approved", 1_200),
    );
    repository.outcomes.set(claimed.id, createApprovalSigningAttempt({
      id: claimed.id,
      messageDigest: claimed.messageDigest,
      attemptId: `attempt_${"55".repeat(16)}`,
      attemptNumber: 1,
      startedAt: 1_200,
    }));

    await expect(owner.invalidateAfterWorkerRestart()).resolves.toBe(2);
    expect(repository.invalidatedAt).toBe(1_500);
    expect(repository.records.get(input().id)?.state).toBe("cancelled");
    expect(repository.outcomes.get(claimed.id)).toMatchObject({
      state: "failed",
      failureCode: "worker-restarted",
    });
  });
});
