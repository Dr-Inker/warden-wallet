import { describe, expect, it } from "vitest";

import {
  ApprovalSigningOutcomeFormatError,
  completeApprovalSigningAttempt,
  createApprovalSigningAttempt,
  failApprovalSigningAttempt,
  retryApprovalSigningAttempt,
  snapshotApprovalSigningOutcome,
} from "../src/approval/signing-outcome.js";

const digest = (value = 0x11): Uint8Array => new Uint8Array(32).fill(value);
const transaction = (): Uint8Array => Uint8Array.of(1, 2, 3);

function attempt() {
  return createApprovalSigningAttempt({
    id: `req_${"ab".repeat(16)}`,
    messageDigest: digest(),
    attemptId: `attempt_${"cd".repeat(16)}`,
    attemptNumber: 1,
    startedAt: 1_100,
  });
}

describe("durable approval signing outcome", () => {
  it("copy-owns one exact signing attempt binding", () => {
    const messageDigest = digest();
    const created = createApprovalSigningAttempt({
      id: `req_${"ab".repeat(16)}`,
      messageDigest,
      attemptId: `attempt_${"cd".repeat(16)}`,
      attemptNumber: 1,
      startedAt: 1_100,
    });
    messageDigest.fill(0xff);

    expect(created).toMatchObject({
      version: 1,
      id: `req_${"ab".repeat(16)}`,
      attemptId: `attempt_${"cd".repeat(16)}`,
      attemptNumber: 1,
      state: "signing",
      startedAt: 1_100,
      resolvedAt: null,
      transactionBytes: null,
      transactionDigest: null,
      failureCode: null,
    });
    expect(created.messageDigest).toEqual(digest());
    expect(Object.isFrozen(created)).toBe(true);
  });

  it("authenticates and copy-owns a completed signed result with an independent digest", () => {
    const bytes = transaction();
    const signed = completeApprovalSigningAttempt(attempt(), bytes, 1_200);
    bytes.fill(0xff);

    expect(signed.state).toBe("signed");
    expect(signed.resolvedAt).toBe(1_200);
    expect(signed.transactionBytes).toEqual(transaction());
    expect(Buffer.from(signed.transactionDigest!).toString("hex")).toBe(
      "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
    );

    const copy = snapshotApprovalSigningOutcome(signed);
    copy.messageDigest.fill(0);
    copy.transactionBytes!.fill(0);
    copy.transactionDigest!.fill(0);
    expect(signed.messageDigest).toEqual(digest());
    expect(signed.transactionBytes).toEqual(transaction());
  });

  it("records only a closed failure code and creates a fresh numbered retry token", () => {
    const failed = failApprovalSigningAttempt(
      attempt(),
      "blockhash-invalid",
      1_150,
    );
    expect(failed).toMatchObject({
      state: "failed",
      failureCode: "blockhash-invalid",
      resolvedAt: 1_150,
      transactionBytes: null,
      transactionDigest: null,
    });

    const retried = retryApprovalSigningAttempt(
      failed,
      `attempt_${"ef".repeat(16)}`,
      1_160,
    );
    expect(retried).toMatchObject({
      attemptId: `attempt_${"ef".repeat(16)}`,
      attemptNumber: 2,
      state: "signing",
      startedAt: 1_160,
      resolvedAt: null,
      failureCode: null,
    });
    expect(() => completeApprovalSigningAttempt(failed, transaction(), 1_200))
      .toThrow(ApprovalSigningOutcomeFormatError);
    expect(() => failApprovalSigningAttempt(retried, "not-a-code" as never, 1_200))
      .toThrow(ApprovalSigningOutcomeFormatError);
  });

  it("rejects ambiguous shapes, accessors, custom prototypes, and state/digest tamper", () => {
    const signing = attempt();
    const signed = completeApprovalSigningAttempt(signing, transaction(), 1_200);
    const extra = { ...signing, extra: true };
    const symbol = { ...signing } as Record<PropertyKey, unknown>;
    symbol[Symbol("hidden")] = true;
    const accessor = { ...signing };
    Object.defineProperty(accessor, "state", { enumerable: true, get: () => "signing" });
    const custom = Object.assign(Object.create({ inherited: true }), signing);
    const tamperedDigest = {
      ...signed,
      transactionDigest: digest(0xff),
    };
    const impossibleSigned = {
      ...signed,
      failureCode: "signing-failed",
    };

    for (const value of [extra, symbol, accessor, custom, tamperedDigest, impossibleSigned]) {
      expect(() => snapshotApprovalSigningOutcome(value)).toThrow(
        ApprovalSigningOutcomeFormatError,
      );
    }
  });

  it("rejects malformed identities, counters, clocks, and impossible nullable fields", () => {
    const signing = attempt();
    const cases: unknown[] = [
      { ...signing, id: "page-id" },
      { ...signing, attemptId: "attempt-page" },
      { ...signing, messageDigest: digest().subarray(1) },
      { ...signing, attemptNumber: 0 },
      { ...signing, attemptNumber: 0x1_0000_0000 },
      { ...signing, startedAt: -1 },
      { ...signing, resolvedAt: 1_200 },
      { ...signing, transactionBytes: transaction() },
      { ...signing, transactionDigest: digest() },
      { ...signing, failureCode: "signing-failed" },
      {
        ...failApprovalSigningAttempt(signing, "signing-failed", 1_200),
        resolvedAt: 1_099,
      },
    ];
    for (const value of cases) {
      expect(() => snapshotApprovalSigningOutcome(value)).toThrow(
        ApprovalSigningOutcomeFormatError,
      );
    }
  });
});
