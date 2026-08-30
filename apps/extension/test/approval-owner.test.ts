import { describe, expect, it } from "vitest";

import {
  createPendingApprovalRecord,
  resolveApprovalRecord,
  snapshotApprovalRecord,
  type ApprovalCreateParams,
  type ApprovalRecord,
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

  async transition(transition: ApprovalTransition): Promise<ApprovalRecord> {
    this.transitions.push({
      ...transition,
      expectedDigest: transition.expectedDigest?.slice(),
    });
    const current = this.records.get(transition.id);
    if (current === undefined || current.state !== "pending") {
      throw new Error("transition refused");
    }
    if (transition.expectedDigest !== undefined) {
      expect(transition.expectedDigest).toEqual(current.messageDigest);
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
      if (record.state !== "pending") continue;
      this.records.set(id, resolveApprovalRecord(record, "cancelled", now));
      count++;
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

  it("claims one exact digest for signing and makes rejection a distinct terminal choice", async () => {
    let now = 1_100;
    const repository = new MemoryApprovalRepository();
    const owner = new ApprovalOwner(repository, { readNow: () => now });
    const first = await owner.create(input("ab"));
    const second = await owner.create(input("cd"));

    now = 1_200;
    const claimed = await owner.claimForSigning(first.id, first.messageDigest);
    now = 1_300;
    const rejected = await owner.reject(second.id);

    expect(claimed.state).toBe("approved");
    expect(rejected.state).toBe("rejected");
    expect(repository.transitions).toEqual([
      {
        id: first.id,
        state: "approved",
        now: 1_200,
        expectedDigest: first.messageDigest,
      },
      { id: second.id, state: "rejected", now: 1_300 },
    ]);
  });

  it("invalidates every pending record at worker startup instead of restoring dead Ports", async () => {
    const repository = new MemoryApprovalRepository();
    repository.records.set(
      input().id,
      createPendingApprovalRecord(input()),
    );
    const owner = new ApprovalOwner(repository, { readNow: () => 1_500 });

    await expect(owner.invalidateAfterWorkerRestart()).resolves.toBe(1);
    expect(repository.invalidatedAt).toBe(1_500);
    expect(repository.records.get(input().id)?.state).toBe("cancelled");
  });
});
