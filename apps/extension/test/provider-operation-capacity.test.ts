import { describe, expect, it } from "vitest";

import {
  MAX_PREPARING_PROVIDER_OPERATIONS,
  MAX_TOTAL_PROVIDER_OPERATIONS,
  PROVIDER_OPERATION_RETENTION_MS,
  ProviderOperationCapacityError,
  ProviderOperationOriginCapacityError,
  isProviderOperationRetentionExpired,
  providerOperationCapacityRefusal,
} from "../src/background/provider-operation-store.js";
import {
  MAX_PROVIDER_OPERATIONS_PER_ORIGIN,
  isProviderOriginCapacityRefusal,
} from "../src/background/provider-origin-capacity.js";
import type { ProviderOperationRecord } from "../src/background/provider-operation.js";

const ORIGIN = "https://dapp.example";

function counts(overrides: Partial<{
  preparingCount: number;
  totalCount: number;
  originCount: number;
  origin: string;
}> = {}) {
  return {
    preparingCount: 0,
    totalCount: 0,
    originCount: 0,
    origin: ORIGIN,
    ...overrides,
  };
}

function row(overrides: Partial<ProviderOperationRecord> = {}): ProviderOperationRecord {
  return {
    version: 1,
    key: `op_${"ab".repeat(32)}`,
    extensionId: "a".repeat(32),
    origin: ORIGIN,
    tabId: 7,
    frameId: 0,
    documentId: "123e4567-e89b-12d3-a456-426614174000",
    correlationId: "request_0123456789abcdef",
    method: "solana:signTransaction",
    requestDigest: new Uint8Array(32).fill(0x11),
    createdAt: 1_000,
    expiresAt: 61_000,
    state: "bound",
    approvalId: `req_${"22".repeat(16)}`,
    approvalDigest: new Uint8Array(32).fill(0x33),
    failureCode: null,
    resolvedAt: null,
    ...overrides,
  } as ProviderOperationRecord;
}

describe("C14 journal capacity admission (audit finding X-2)", () => {
  it("admits a claim while every count is beneath its bound", () => {
    expect(providerOperationCapacityRefusal(counts())).toBeNull();
    expect(providerOperationCapacityRefusal(counts({
      preparingCount: MAX_PREPARING_PROVIDER_OPERATIONS - 1,
      totalCount: MAX_TOTAL_PROVIDER_OPERATIONS - 1,
      originCount: MAX_PROVIDER_OPERATIONS_PER_ORIGIN - 1,
    }))).toBeNull();
  });

  it("reports global exhaustion as global exhaustion, ahead of the origin share", () => {
    const preparing = providerOperationCapacityRefusal(counts({
      preparingCount: MAX_PREPARING_PROVIDER_OPERATIONS,
      totalCount: MAX_TOTAL_PROVIDER_OPERATIONS,
      originCount: MAX_PROVIDER_OPERATIONS_PER_ORIGIN,
    }));
    expect(preparing).toBeInstanceOf(ProviderOperationCapacityError);
    expect(preparing).not.toBeInstanceOf(ProviderOperationOriginCapacityError);
    expect(preparing?.message).toContain("32 operations may be preparing");

    const total = providerOperationCapacityRefusal(counts({
      totalCount: MAX_TOTAL_PROVIDER_OPERATIONS,
      originCount: MAX_PROVIDER_OPERATIONS_PER_ORIGIN,
    }));
    expect(total).not.toBeInstanceOf(ProviderOperationOriginCapacityError);
    expect(total?.message).toContain("128 operations may be retained");
  });

  it("refuses one origin's excess with a distinguishable origin-scoped error", () => {
    const refusal = providerOperationCapacityRefusal(counts({
      totalCount: MAX_PROVIDER_OPERATIONS_PER_ORIGIN,
      originCount: MAX_PROVIDER_OPERATIONS_PER_ORIGIN,
      origin: "https://hostile.example",
    }));

    expect(refusal).toBeInstanceOf(ProviderOperationOriginCapacityError);
    // Still a capacity error, so existing handlers keep working.
    expect(refusal).toBeInstanceOf(ProviderOperationCapacityError);
    expect(isProviderOriginCapacityRefusal(refusal)).toBe(true);
    expect(refusal?.message).toBe(
      "provider operation store: provider origin capacity: " +
        "origin https://hostile.example may hold at most 16 retained operations",
    );
    expect((refusal as ProviderOperationOriginCapacityError).origin)
      .toBe("https://hostile.example");
    expect(MAX_PROVIDER_OPERATIONS_PER_ORIGIN).toBe(16);
    expect(MAX_PROVIDER_OPERATIONS_PER_ORIGIN * 8)
      .toBe(MAX_TOTAL_PROVIDER_OPERATIONS);
  });

  it("serves a second origin while the first has exhausted its share", () => {
    // The hostile origin holds its whole share; the victim origin holds none.
    // Both see the same global totals, and only the hostile one is refused.
    const globalTotal = MAX_PROVIDER_OPERATIONS_PER_ORIGIN;
    expect(providerOperationCapacityRefusal(counts({
      totalCount: globalTotal,
      originCount: MAX_PROVIDER_OPERATIONS_PER_ORIGIN,
      origin: "https://hostile.example",
    }))).toBeInstanceOf(ProviderOperationOriginCapacityError);
    expect(providerOperationCapacityRefusal(counts({
      totalCount: globalTotal,
      originCount: 0,
      origin: "https://victim.example",
    }))).toBeNull();
  });

  it("frees a terminal row only once its retention window has fully elapsed", () => {
    const bound = row({ expiresAt: 61_000 });
    expect(isProviderOperationRetentionExpired(bound, 61_000)).toBe(false);
    expect(isProviderOperationRetentionExpired(
      bound,
      61_000 + PROVIDER_OPERATION_RETENTION_MS - 1,
    )).toBe(false);
    expect(isProviderOperationRetentionExpired(
      bound,
      61_000 + PROVIDER_OPERATION_RETENTION_MS,
    )).toBe(true);

    const failed = row({
      state: "failed",
      approvalId: null,
      approvalDigest: null,
      failureCode: "worker-restarted",
      resolvedAt: 5_000,
    });
    expect(isProviderOperationRetentionExpired(failed, 5_000)).toBe(false);
    expect(isProviderOperationRetentionExpired(
      failed,
      5_000 + PROVIDER_OPERATION_RETENTION_MS,
    )).toBe(true);

    // A preparing row is never retention-eligible; it must fail first.
    const preparing = row({
      state: "preparing",
      approvalId: null,
      approvalDigest: null,
    });
    expect(isProviderOperationRetentionExpired(
      preparing,
      Number.MAX_SAFE_INTEGER,
    )).toBe(false);
    expect(PROVIDER_OPERATION_RETENTION_MS).toBe(10 * 60 * 1_000);
  });
});
