import { describe, expect, it } from "vitest";

import {
  MAX_PROVIDER_MESSAGE_BYTES,
  MAX_TRANSACTION_BYTES,
  parseProviderRequest,
  ProviderMessageFormatError,
} from "../src/background/provider-message.js";

const CORRELATION_ID = "request_0123456789abcdef";
const ACCOUNT_ADDRESS = "11111111111111111111111111111111";

function request(
  method: string,
  params: Record<string, unknown>,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    version: 1,
    type: "request",
    correlationId: CORRELATION_ID,
    method,
    params,
    ...overrides,
  };
}

describe("closed provider request schema", () => {
  it("normalizes standard:connect without granting account authority", () => {
    const parsed = parseProviderRequest(request("standard:connect", {}));
    expect(parsed).toEqual({
      version: 1,
      type: "request",
      correlationId: CORRELATION_ID,
      method: "standard:connect",
      params: { silent: false },
    });
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.params)).toBe(true);
  });

  it("accepts the exact silent-connect and disconnect shapes", () => {
    expect(
      parseProviderRequest(request("standard:connect", { silent: true })),
    ).toMatchObject({ method: "standard:connect", params: { silent: true } });
    expect(parseProviderRequest(request("standard:disconnect", {}))).toEqual({
      version: 1,
      type: "request",
      correlationId: CORRELATION_ID,
      method: "standard:disconnect",
      params: {},
    });
  });

  it("copies and freezes one signTransaction input with closed options", () => {
    const transaction = [1, 2, 3, 255];
    const parsed = parseProviderRequest(
      request("solana:signTransaction", {
        accountAddress: ACCOUNT_ADDRESS,
        transaction,
        chain: "solana:devnet",
        options: { preflightCommitment: "confirmed", minContextSlot: 42 },
      }),
    );

    expect(parsed).toEqual({
      version: 1,
      type: "request",
      correlationId: CORRELATION_ID,
      method: "solana:signTransaction",
      params: {
        requestedAccountAddress: ACCOUNT_ADDRESS,
        transaction: [1, 2, 3, 255],
        chain: "solana:devnet",
        options: { preflightCommitment: "confirmed", minContextSlot: 42 },
      },
    });
    if (parsed.method !== "solana:signTransaction") {
      throw new Error("parser returned the wrong method discriminator");
    }
    transaction[0] = 99;
    expect(parsed.params.transaction[0]).toBe(1);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.params)).toBe(true);
    expect(Object.isFrozen(parsed.params.transaction)).toBe(true);
    expect(Object.isFrozen(parsed.params.options)).toBe(true);
  });

  it("normalizes omitted signTransaction chain and options without inventing authority", () => {
    expect(
      parseProviderRequest(
        request("solana:signTransaction", {
          accountAddress: ACCOUNT_ADDRESS,
          transaction: [1],
        }),
      ),
    ).toMatchObject({
      method: "solana:signTransaction",
      params: {
        requestedAccountAddress: ACCOUNT_ADDRESS,
        chain: null,
        options: { preflightCommitment: null, minContextSlot: null },
      },
    });
  });

  it("accepts one exact signAndSendTransaction input and standard send options", () => {
    const parsed = parseProviderRequest(
      request("solana:signAndSendTransaction", {
        accountAddress: ACCOUNT_ADDRESS,
        transaction: [9, 8, 7],
        chain: "solana:mainnet",
        options: {
          preflightCommitment: "processed",
          minContextSlot: 7,
          commitment: "finalized",
          skipPreflight: false,
          maxRetries: 3,
        },
      }),
    );

    expect(parsed).toMatchObject({
      method: "solana:signAndSendTransaction",
      params: {
        requestedAccountAddress: ACCOUNT_ADDRESS,
        transaction: [9, 8, 7],
        chain: "solana:mainnet",
        options: {
          preflightCommitment: "processed",
          minContextSlot: 7,
          commitment: "finalized",
          skipPreflight: false,
          maxRetries: 3,
        },
      },
    });
  });

  it("accepts the exact 1232-byte transaction boundary", () => {
    const parsed = parseProviderRequest(
      request("solana:signTransaction", {
        accountAddress: ACCOUNT_ADDRESS,
        transaction: Array.from({ length: MAX_TRANSACTION_BYTES }, () => 255),
      }),
    );
    if (parsed.method !== "solana:signTransaction") {
      throw new Error("parser returned the wrong method discriminator");
    }
    expect(parsed.params.transaction).toHaveLength(1_232);
  });

  it.each([
    "solana:mainnet",
    "solana:devnet",
    "solana:testnet",
    "solana:localnet",
  ])("accepts the exact supported chain %s", (chain) => {
    expect(
      parseProviderRequest(
        request("solana:signAndSendTransaction", {
          accountAddress: ACCOUNT_ADDRESS,
          transaction: [1],
          chain,
        }),
      ),
    ).toMatchObject({ method: "solana:signAndSendTransaction", params: { chain } });
  });

  it.each(["solana:signMessage", "solana:signIn", "standard:events", "warden:unlock"])(
    "rejects unsupported or non-request method %s",
    (method) => {
      expect(() => parseProviderRequest(request(method, {}))).toThrow(
        ProviderMessageFormatError,
      );
    },
  );

  it.each(["$ctx", "origin", "tabId", "frameId", "approved", "policy"])(
    "rejects page-supplied authority field %s at the envelope",
    (field) => {
      expect(() =>
        parseProviderRequest(request("standard:connect", {}, { [field]: "forged" })),
      ).toThrow(ProviderMessageFormatError);
    },
  );

  it.each(["$ctx", "origin", "tabId", "frameId", "approved", "policy"])(
    "rejects page-supplied authority field %s inside params",
    (field) => {
      expect(() =>
        parseProviderRequest(
          request("solana:signTransaction", {
            accountAddress: ACCOUNT_ADDRESS,
            transaction: [1],
            [field]: "forged",
          }),
        ),
      ).toThrow(ProviderMessageFormatError);
    },
  );

  it.each([
    ["null", null],
    ["array", []],
    ["wrong version", request("standard:connect", {}, { version: 2 })],
    ["string version", request("standard:connect", {}, { version: "1" })],
    ["wrong type", request("standard:connect", {}, { type: "response" })],
    ["short correlation id", request("standard:connect", {}, { correlationId: "short" })],
    [
      "punctuated correlation id",
      request("standard:connect", {}, { correlationId: "request/0123456789abcdef" }),
    ],
    ["non-object params", request("standard:connect", [] as unknown as Record<string, unknown>)],
  ])("rejects malformed envelope: %s", (_label, value) => {
    expect(() => parseProviderRequest(value)).toThrow(ProviderMessageFormatError);
  });

  it("rejects cyclic and globally oversized inputs before schema dispatch", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => parseProviderRequest(cyclic)).toThrow(
      "invalid provider request: request is not JSON serializable",
    );

    expect(() =>
      parseProviderRequest(
        request("standard:connect", {}, { padding: "x".repeat(MAX_PROVIDER_MESSAGE_BYTES) }),
      ),
    ).toThrow(
      `invalid provider request: request exceeds the ${MAX_PROVIDER_MESSAGE_BYTES}-byte limit`,
    );
  });

  it.each([
    ["unknown connect field", { silent: false, account: ACCOUNT_ADDRESS }],
    ["non-boolean silent", { silent: "false" }],
    ["disconnect field", { silent: false }],
  ])("rejects ambiguous standard params: %s", (label, params) => {
    const method = label === "disconnect field" ? "standard:disconnect" : "standard:connect";
    expect(() => parseProviderRequest(request(method, params))).toThrow(
      ProviderMessageFormatError,
    );
  });

  it.each([
    ["empty", []],
    ["too large", Array.from({ length: MAX_TRANSACTION_BYTES + 1 }, () => 1)],
    ["negative byte", [0, -1]],
    ["large byte", [0, 256]],
    ["fractional byte", [0, 1.5]],
    ["string byte", [0, "1"]],
    ["typed array", new Uint8Array([1, 2])],
    ["JSON object", { 0: 1, 1: 2 }],
  ])("rejects malformed transaction bytes: %s", (_label, transaction) => {
    expect(() =>
      parseProviderRequest(
        request("solana:signTransaction", {
          accountAddress: ACCOUNT_ADDRESS,
          transaction,
        }),
      ),
    ).toThrow(ProviderMessageFormatError);
  });

  it("rejects sparse transaction arrays instead of letting Array.every skip holes", () => {
    const transaction = new Array<number>(2);
    transaction[1] = 1;
    expect(() =>
      parseProviderRequest(
        request("solana:signTransaction", {
          accountAddress: ACCOUNT_ADDRESS,
          transaction,
        }),
      ),
    ).toThrow(ProviderMessageFormatError);
  });

  it.each([
    ["missing", undefined],
    ["too short", "1111111111111111111111111111111"],
    ["too long", "1".repeat(45)],
    ["non-base58", "O".repeat(32)],
    ["non-string", 123],
  ])("rejects malformed requested account address: %s", (_label, accountAddress) => {
    expect(() =>
      parseProviderRequest(
        request("solana:signTransaction", { accountAddress, transaction: [1] }),
      ),
    ).toThrow(ProviderMessageFormatError);
  });

  it.each(["solana:mainnet-beta", "ethereum:1", "solana:unknown", 1])(
    "rejects unsupported or malformed chain %j",
    (chain) => {
      expect(() =>
        parseProviderRequest(
          request("solana:signAndSendTransaction", {
            accountAddress: ACCOUNT_ADDRESS,
            transaction: [1],
            chain,
          }),
        ),
      ).toThrow(ProviderMessageFormatError);
    },
  );

  it("requires chain for signAndSendTransaction", () => {
    expect(() =>
      parseProviderRequest(
        request("solana:signAndSendTransaction", {
          accountAddress: ACCOUNT_ADDRESS,
          transaction: [1],
        }),
      ),
    ).toThrow(ProviderMessageFormatError);
  });

  it.each([
    ["unknown option", { unexpected: true }],
    ["bad preflight commitment", { preflightCommitment: "safe" }],
    ["negative min slot", { minContextSlot: -1 }],
    ["fractional min slot", { minContextSlot: 1.5 }],
    ["unsafe min slot", { minContextSlot: Number.MAX_SAFE_INTEGER + 1 }],
  ])("rejects malformed signTransaction options: %s", (_label, options) => {
    expect(() =>
      parseProviderRequest(
        request("solana:signTransaction", {
          accountAddress: ACCOUNT_ADDRESS,
          transaction: [1],
          options,
        }),
      ),
    ).toThrow(ProviderMessageFormatError);
  });

  it("rejects an explicitly undefined options field that JSON transport would erase", () => {
    expect(() =>
      parseProviderRequest(
        request("solana:signTransaction", {
          accountAddress: ACCOUNT_ADDRESS,
          transaction: [1],
          options: undefined,
        }),
      ),
    ).toThrow(ProviderMessageFormatError);
  });

  it.each([
    ["bad commitment", { commitment: "safe" }],
    ["non-boolean skip", { skipPreflight: "false" }],
    ["negative retries", { maxRetries: -1 }],
    ["fractional retries", { maxRetries: 1.5 }],
    ["unsafe retries", { maxRetries: Number.MAX_SAFE_INTEGER + 1 }],
  ])("rejects malformed signAndSend options: %s", (_label, options) => {
    expect(() =>
      parseProviderRequest(
        request("solana:signAndSendTransaction", {
          accountAddress: ACCOUNT_ADDRESS,
          transaction: [1],
          chain: "solana:devnet",
          options,
        }),
      ),
    ).toThrow(ProviderMessageFormatError);
  });
});
