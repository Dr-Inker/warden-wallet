import { describe, expect, it } from "vitest";

import {
  PAGE_PROVIDER_RECEIPT_TYPE,
  PROVIDER_TRANSPORT_CANCEL_TYPE,
  PROVIDER_TRANSPORT_RECEIPT_TYPE,
  PROVIDER_TRANSPORT_REQUEST_TYPE,
  PROVIDER_TRANSPORT_SETTLED_TYPE,
  PROVIDER_TRANSPORT_TERMINAL_TYPE,
  createPageProviderReceiptEnvelope,
  createProviderTransportCancelEnvelope,
  createProviderTransportReceiptEnvelope,
  createProviderTransportRequestEnvelope,
  createProviderTransportSettledEnvelope,
  createProviderTransportTerminalEnvelope,
  providerTransportReceiptIdFromOperationKey,
  readPageProviderReceiptEnvelope,
  readProviderTransportCancelEnvelope,
  readProviderTransportReceiptEnvelope,
  readProviderTransportRequestEnvelope,
  readProviderTransportSettledEnvelope,
  readProviderTransportTerminalEnvelope,
} from "../src/provider-delivery-protocol.js";

const CORRELATION_ID = "delivery_protocol_01234567";
const EXPIRES_AT = 123_456;
const OPERATION_KEY = `op_${"ab".repeat(32)}`;
const RECEIPT_ID = `delivery_${"ab".repeat(32)}`;
const REQUEST = Object.freeze({ correlationId: CORRELATION_ID });
const TERMINAL = Object.freeze({ correlationId: CORRELATION_ID, ok: false });

describe("C22 closed provider delivery protocol", () => {
  it("constructs and reads the exact immutable request/terminal/receipt/settled sequence", () => {
    const request = createProviderTransportRequestEnvelope(EXPIRES_AT, REQUEST);
    const terminal = createProviderTransportTerminalEnvelope(
      CORRELATION_ID,
      RECEIPT_ID,
      EXPIRES_AT,
      TERMINAL,
    );
    const receipt = createProviderTransportReceiptEnvelope(
      CORRELATION_ID,
      RECEIPT_ID,
      EXPIRES_AT,
    );
    const settled = createProviderTransportSettledEnvelope(
      CORRELATION_ID,
      RECEIPT_ID,
      EXPIRES_AT,
    );

    expect(request).toEqual({
      version: 1,
      type: PROVIDER_TRANSPORT_REQUEST_TYPE,
      expiresAt: EXPIRES_AT,
      payload: REQUEST,
    });
    expect(terminal).toEqual({
      version: 1,
      type: PROVIDER_TRANSPORT_TERMINAL_TYPE,
      correlationId: CORRELATION_ID,
      receiptId: RECEIPT_ID,
      expiresAt: EXPIRES_AT,
      payload: TERMINAL,
    });
    expect(receipt.type).toBe(PROVIDER_TRANSPORT_RECEIPT_TYPE);
    expect(settled.type).toBe(PROVIDER_TRANSPORT_SETTLED_TYPE);
    expect(readProviderTransportRequestEnvelope(request)).toEqual(request);
    expect(readProviderTransportTerminalEnvelope(terminal)).toEqual(terminal);
    expect(readProviderTransportReceiptEnvelope(receipt)).toEqual(receipt);
    expect(readProviderTransportSettledEnvelope(settled)).toEqual(settled);
    expect(Object.isFrozen(request)).toBe(true);
    expect(Object.isFrozen(terminal)).toBe(true);
  });

  it("binds cancellation to the same immutable request and absolute deadline", () => {
    const cancel = createProviderTransportCancelEnvelope(EXPIRES_AT, REQUEST);
    expect(cancel).toEqual({
      version: 1,
      type: PROVIDER_TRANSPORT_CANCEL_TYPE,
      expiresAt: EXPIRES_AT,
      payload: REQUEST,
    });
    expect(readProviderTransportCancelEnvelope(cancel)).toEqual(cancel);
  });

  it("derives one deterministic opaque receipt id from the operation identity", () => {
    expect(providerTransportReceiptIdFromOperationKey(OPERATION_KEY)).toBe(RECEIPT_ID);
    expect(() => providerTransportReceiptIdFromOperationKey("op_not-a-digest")).toThrow();
  });

  it("wraps only an exact receipt for the page-to-content acknowledgment", () => {
    const receipt = createProviderTransportReceiptEnvelope(
      CORRELATION_ID,
      RECEIPT_ID,
      EXPIRES_AT,
    );
    const page = createPageProviderReceiptEnvelope(receipt);
    expect(page).toEqual({
      version: 1,
      type: PAGE_PROVIDER_RECEIPT_TYPE,
      payload: receipt,
    });
    expect(readPageProviderReceiptEnvelope(page)).toEqual(page);
  });

  it("rejects unknown fields, accessors, malformed ids, and unsafe deadlines", () => {
    const valid = createProviderTransportReceiptEnvelope(
      CORRELATION_ID,
      RECEIPT_ID,
      EXPIRES_AT,
    );
    expect(readProviderTransportReceiptEnvelope({ ...valid, secret: true })).toBeNull();
    expect(readProviderTransportReceiptEnvelope({ ...valid, receiptId: "delivery_bad" })).toBeNull();
    expect(readProviderTransportReceiptEnvelope({ ...valid, expiresAt: Number.MAX_SAFE_INTEGER + 1 })).toBeNull();
    expect(readProviderTransportReceiptEnvelope(Object.create({ ...valid }))).toBeNull();
    expect(readProviderTransportReceiptEnvelope(Object.defineProperty(
      { ...valid },
      "receiptId",
      { enumerable: true, get: () => RECEIPT_ID },
    ))).toBeNull();

    const revoked = Proxy.revocable(valid, {});
    revoked.revoke();
    expect(() => readProviderTransportReceiptEnvelope(revoked.proxy)).not.toThrow();
    expect(readProviderTransportReceiptEnvelope(revoked.proxy)).toBeNull();
  });
});
