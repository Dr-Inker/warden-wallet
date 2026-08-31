import { describe, expect, it } from "vitest";

import {
  APPROVAL_UI_PORT_NAME,
  ApprovalUiProtocolError,
  createApprovalReviewResponse,
  createApprovalUnavailableResponse,
  createApprovalRejectedResponse,
  parseApprovalUiRequest,
  parseApprovalUiResponse,
  type ApprovalReviewDetails,
} from "../src/approval-protocol.js";

const REQUEST_ID = `req_${"ab".repeat(16)}`;
const CORRELATION_ID = "approval_request_0123456789abcdef";
const PUBLIC_KEY = "1".repeat(32);

const review: ApprovalReviewDetails = Object.freeze({
  kind: "memo-v1",
  requestId: REQUEST_ID,
  origin: "https://dapp.example",
  method: "solana:signTransaction",
  chain: "solana:devnet",
  genesisHash: PUBLIC_KEY,
  account: PUBLIC_KEY,
  sessionSigner: PUBLIC_KEY,
  sessionAccount: PUBLIC_KEY,
  registry: PUBLIC_KEY,
  wardenProgram: PUBLIC_KEY,
  memoProgram: PUBLIC_KEY,
  recentBlockhash: PUBLIC_KEY,
  memo: "Review this exact memo",
  memoByteLength: 22,
  computeUnitLimit: 600_000,
  heapFrameBytes: 131_072,
  messageByteLength: 333,
  messageDigest: "11".repeat(32),
  policyVersion: 1,
  createdAt: 1_900_000_000_000,
  expiresAt: 1_900_000_060_000,
});

function request(
  method: "approval:getReview" | "approval:reject" = "approval:getReview",
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    version: 1,
    type: "request",
    correlationId: CORRELATION_ID,
    method,
    params: { requestId: REQUEST_ID },
    ...overrides,
  };
}

describe("closed approval UI protocol", () => {
  it("uses one versioned channel and accepts only review or rejection for one exact id", () => {
    expect(APPROVAL_UI_PORT_NAME).toBe("warden:approval-ui:v1");
    expect(parseApprovalUiRequest(request())).toEqual({
      version: 1,
      type: "request",
      correlationId: CORRELATION_ID,
      method: "approval:getReview",
      params: { requestId: REQUEST_ID },
    });
    expect(parseApprovalUiRequest(request("approval:reject"))).toMatchObject({
      method: "approval:reject",
      params: { requestId: REQUEST_ID },
    });
  });

  it.each([
    ["approve method", request("approval:getReview", { method: "approval:approve" })],
    ["sign method", request("approval:getReview", { method: "approval:sign" })],
    ["page-selected account", request("approval:getReview", {
      params: { requestId: REQUEST_ID, account: "attacker" },
    })],
    ["malformed request id", request("approval:getReview", {
      params: { requestId: "req_short" },
    })],
    ["extra top-level field", request("approval:getReview", { authority: "page" })],
    ["unknown version", request("approval:getReview", { version: 2 })],
  ])("rejects %s", (_label, value) => {
    expect(() => parseApprovalUiRequest(value)).toThrow(ApprovalUiProtocolError);
  });

  it("round-trips exact primitive-only review, rejection, and unavailable responses", () => {
    const reviewResponse = createApprovalReviewResponse(CORRELATION_ID, review);
    const rejectedResponse = createApprovalRejectedResponse(
      CORRELATION_ID,
      REQUEST_ID,
    );
    const unavailableResponse = createApprovalUnavailableResponse(CORRELATION_ID);

    expect(parseApprovalUiResponse(reviewResponse)).toEqual(reviewResponse);
    expect(parseApprovalUiResponse(rejectedResponse)).toEqual(rejectedResponse);
    expect(parseApprovalUiResponse(unavailableResponse)).toEqual(unavailableResponse);
    expect(JSON.stringify(reviewResponse)).not.toContain("rawMessage");
    expect(JSON.stringify(reviewResponse)).not.toContain("authorizationState");
    expect(Object.values(reviewResponse.result.review).every(
      (value) => !(value instanceof Uint8Array),
    )).toBe(true);
  });

  it.each([
    ["review with extra field", {
      ...createApprovalReviewResponse(CORRELATION_ID, review),
      result: { status: "pending", review: { ...review, rawMessage: [1, 2, 3] } },
    }],
    ["review with mismatched request id", {
      ...createApprovalReviewResponse(CORRELATION_ID, review),
      result: {
        status: "pending",
        requestId: REQUEST_ID,
        review: { ...review, requestId: `req_${"cd".repeat(16)}` },
      },
    }],
    ["invented approved response", {
      version: 1,
      type: "response",
      correlationId: CORRELATION_ID,
      ok: true,
      result: { status: "approved", requestId: REQUEST_ID },
    }],
  ])("rejects an inbound %s", (_label, value) => {
    expect(() => parseApprovalUiResponse(value)).toThrow(ApprovalUiProtocolError);
  });

  it("requires every displayed public key to canonically encode exactly 32 bytes", () => {
    expect(() => createApprovalReviewResponse(CORRELATION_ID, {
      ...review,
      account: "2".repeat(32),
    })).toThrow(ApprovalUiProtocolError);
  });

  it("normalizes hostile response introspection failures to a protocol error", () => {
    const poison = new Proxy({}, {
      ownKeys() {
        throw new Error("hostile ownKeys trap");
      },
    });
    expect(() => parseApprovalUiResponse(poison)).toThrow(ApprovalUiProtocolError);

    const response = {
      ...createApprovalReviewResponse(CORRELATION_ID, review),
      result: poison,
    };
    expect(() => parseApprovalUiResponse(response)).toThrow(ApprovalUiProtocolError);
  });
});
