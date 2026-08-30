import { describe, expect, it } from "vitest";

import {
  APPROVAL_DIGEST_BYTES,
  APPROVAL_MAX_TTL_MS,
  ApprovalRecordFormatError,
  createPendingApprovalRecord,
  resolveApprovalRecord,
  snapshotApprovalRecord,
} from "../src/approval/index.js";

const fill = (length: number, value: number): Uint8Array =>
  new Uint8Array(length).fill(value);

function pendingInput() {
  return {
    id: `req_${"ab".repeat(16)}`,
    origin: "https://dapp.example",
    tabId: 19,
    frameId: 4,
    documentId: "123e4567-e89b-12d3-a456-426614174000",
    account: fill(32, 0x11),
    method: "solana:signTransaction" as const,
    chain: "solana:devnet" as const,
    genesisHash: fill(32, 0x22),
    programId: fill(32, 0x33),
    rawMessage: new Uint8Array([0x61, 0x62, 0x63]),
    policyVersion: 7,
    createdAt: 1_000,
    expiresAt: 1_000 + APPROVAL_MAX_TTL_MS,
  };
}

describe("immutable approval record", () => {
  it("binds every authority field and pins SHA-256 with an independent vector", () => {
    const input = pendingInput();
    const record = createPendingApprovalRecord(input);

    expect(record).toMatchObject({
      version: 1,
      id: input.id,
      origin: input.origin,
      tabId: input.tabId,
      frameId: input.frameId,
      documentId: input.documentId,
      method: input.method,
      chain: input.chain,
      policyVersion: input.policyVersion,
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
      state: "pending",
      resolvedAt: null,
    });
    expect(record.messageDigest).toHaveLength(APPROVAL_DIGEST_BYTES);
    expect(Buffer.from(record.messageDigest).toString("hex")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(Object.isFrozen(record)).toBe(true);
  });

  it("owns all byte fields and never aliases caller or reader buffers", () => {
    const input = pendingInput();
    const record = createPendingApprovalRecord(input);
    input.account.fill(0xff);
    input.genesisHash.fill(0xff);
    input.programId.fill(0xff);
    input.rawMessage.fill(0xff);

    expect(record.account).toEqual(fill(32, 0x11));
    expect(record.genesisHash).toEqual(fill(32, 0x22));
    expect(record.programId).toEqual(fill(32, 0x33));
    expect(record.rawMessage).toEqual(new Uint8Array([0x61, 0x62, 0x63]));

    const second = snapshotApprovalRecord(record);
    second.rawMessage[0] = 0;
    second.messageDigest[0] = 0;
    expect(record.rawMessage).toEqual(new Uint8Array([0x61, 0x62, 0x63]));
    expect(Buffer.from(record.messageDigest).toString("hex")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("permits exactly one pending-to-terminal transition without changing the binding", () => {
    const pending = createPendingApprovalRecord(pendingInput());
    const approved = resolveApprovalRecord(pending, "approved", 1_500);

    expect(approved.state).toBe("approved");
    expect(approved.resolvedAt).toBe(1_500);
    expect(approved.rawMessage).toEqual(pending.rawMessage);
    expect(approved.messageDigest).toEqual(pending.messageDigest);
    expect(() => resolveApprovalRecord(approved, "rejected", 1_600)).toThrow(
      ApprovalRecordFormatError,
    );
  });

  it("fails closed on ambiguous origins, lifetime inflation, unknown fields, and digest tamper", () => {
    const valid = createPendingApprovalRecord(pendingInput());
    const cases: unknown[] = [
      { ...pendingInput(), id: "page_selected_id" },
      { ...pendingInput(), origin: "https://dapp.example/path" },
      { ...pendingInput(), origin: "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      { ...pendingInput(), account: fill(31, 1) },
      { ...pendingInput(), rawMessage: new Uint8Array(0) },
      {
        ...pendingInput(),
        expiresAt: pendingInput().createdAt + APPROVAL_MAX_TTL_MS + 1,
      },
      { ...valid, unknown: true },
      { ...valid, state: "pending", resolvedAt: 1_001 },
      {
        ...valid,
        messageDigest: new Uint8Array(valid.messageDigest).fill(0),
      },
    ];

    for (const value of cases) {
      expect(() => snapshotApprovalRecord(value)).toThrow(ApprovalRecordFormatError);
    }
  });
});
