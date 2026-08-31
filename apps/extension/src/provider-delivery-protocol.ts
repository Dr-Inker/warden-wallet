//! Still-unreachable C22 delivery/settlement wire language.
//!
//! Chrome Port and Window sends are enqueue operations. These exact envelopes
//! keep the initiating absolute deadline immutable across worker generations
//! and distinguish terminal enqueue, page receipt, and background settlement.
//! Payload schemas remain owned by their existing request/terminal parsers.

export const PROVIDER_TRANSPORT_REQUEST_TYPE =
  "warden:provider:transport-request" as const;
export const PROVIDER_TRANSPORT_TERMINAL_TYPE =
  "warden:provider:transport-terminal" as const;
export const PROVIDER_TRANSPORT_RECEIPT_TYPE =
  "warden:provider:transport-receipt" as const;
export const PROVIDER_TRANSPORT_SETTLED_TYPE =
  "warden:provider:transport-settled" as const;
export const PROVIDER_TRANSPORT_CANCEL_TYPE =
  "warden:provider:transport-cancel" as const;
export const PAGE_PROVIDER_RECEIPT_TYPE =
  "warden:provider:receipt" as const;

const CORRELATION_ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
const OPERATION_KEY_PATTERN = /^op_[0-9a-f]{64}$/;
const RECEIPT_ID_PATTERN = /^delivery_[0-9a-f]{64}$/;

export interface ProviderTransportRequestEnvelope {
  readonly version: 1;
  readonly type: typeof PROVIDER_TRANSPORT_REQUEST_TYPE;
  readonly expiresAt: number;
  readonly payload: unknown;
}

export interface ProviderTransportTerminalEnvelope {
  readonly version: 1;
  readonly type: typeof PROVIDER_TRANSPORT_TERMINAL_TYPE;
  readonly correlationId: string;
  readonly receiptId: string;
  readonly expiresAt: number;
  readonly payload: unknown;
}

export interface ProviderTransportReceiptEnvelope {
  readonly version: 1;
  readonly type: typeof PROVIDER_TRANSPORT_RECEIPT_TYPE;
  readonly correlationId: string;
  readonly receiptId: string;
  readonly expiresAt: number;
}

export interface ProviderTransportSettledEnvelope {
  readonly version: 1;
  readonly type: typeof PROVIDER_TRANSPORT_SETTLED_TYPE;
  readonly correlationId: string;
  readonly receiptId: string;
  readonly expiresAt: number;
}

export interface ProviderTransportCancelEnvelope {
  readonly version: 1;
  readonly type: typeof PROVIDER_TRANSPORT_CANCEL_TYPE;
  readonly expiresAt: number;
  readonly payload: unknown;
}

export interface PageProviderReceiptEnvelope {
  readonly version: 1;
  readonly type: typeof PAGE_PROVIDER_RECEIPT_TYPE;
  readonly payload: ProviderTransportReceiptEnvelope;
}

export class ProviderDeliveryProtocolError extends Error {
  constructor(message: string) {
    super(`provider delivery protocol: ${message}`);
    this.name = "ProviderDeliveryProtocolError";
  }
}

function closedDataRecord(
  value: unknown,
  fields: readonly string[],
): Record<string, unknown> | null {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return null;
    }
    const keys = Reflect.ownKeys(value);
    const prototype = Object.getPrototypeOf(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    if (
      keys.length !== fields.length ||
      keys.some((key) => typeof key !== "string" || !fields.includes(key)) ||
      fields.some((field) => !Object.hasOwn(descriptors, field))
    ) {
      return null;
    }
    const result: Record<string, unknown> = {};
    for (const field of fields) {
      const descriptor = descriptors[field];
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        descriptor.enumerable !== true
      ) {
        return null;
      }
      result[field] = descriptor.value;
    }
    return result;
  } catch {
    return null;
  }
}

function requireDeadline(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new ProviderDeliveryProtocolError(
      "expiresAt must be a non-negative safe integer",
    );
  }
  return value as number;
}

function requireCorrelationId(value: unknown): string {
  if (typeof value !== "string" || !CORRELATION_ID_PATTERN.test(value)) {
    throw new ProviderDeliveryProtocolError("correlationId is malformed");
  }
  return value;
}

function requireReceiptId(value: unknown): string {
  if (typeof value !== "string" || !RECEIPT_ID_PATTERN.test(value)) {
    throw new ProviderDeliveryProtocolError("receiptId is malformed");
  }
  return value;
}

function readIdentityEnvelope(
  value: unknown,
  type: typeof PROVIDER_TRANSPORT_RECEIPT_TYPE |
    typeof PROVIDER_TRANSPORT_SETTLED_TYPE,
): ProviderTransportReceiptEnvelope | ProviderTransportSettledEnvelope | null {
  const record = closedDataRecord(
    value,
    ["version", "type", "correlationId", "receiptId", "expiresAt"],
  );
  if (record === null || record.version !== 1 || record.type !== type) return null;
  try {
    return Object.freeze({
      version: 1,
      type,
      correlationId: requireCorrelationId(record.correlationId),
      receiptId: requireReceiptId(record.receiptId),
      expiresAt: requireDeadline(record.expiresAt),
    });
  } catch {
    return null;
  }
}

export function providerTransportReceiptIdFromOperationKey(key: string): string {
  if (typeof key !== "string" || !OPERATION_KEY_PATTERN.test(key)) {
    throw new ProviderDeliveryProtocolError("operation key is malformed");
  }
  return `delivery_${key.slice(3)}`;
}

export function createProviderTransportRequestEnvelope(
  expiresAtValue: number,
  payload: unknown,
): ProviderTransportRequestEnvelope {
  return Object.freeze({
    version: 1,
    type: PROVIDER_TRANSPORT_REQUEST_TYPE,
    expiresAt: requireDeadline(expiresAtValue),
    payload,
  });
}

export function readProviderTransportRequestEnvelope(
  value: unknown,
): ProviderTransportRequestEnvelope | null {
  const record = closedDataRecord(value, ["version", "type", "expiresAt", "payload"]);
  if (
    record === null ||
    record.version !== 1 ||
    record.type !== PROVIDER_TRANSPORT_REQUEST_TYPE
  ) {
    return null;
  }
  try {
    return createProviderTransportRequestEnvelope(
      requireDeadline(record.expiresAt),
      record.payload,
    );
  } catch {
    return null;
  }
}

export function createProviderTransportTerminalEnvelope(
  correlationIdValue: string,
  receiptIdValue: string,
  expiresAtValue: number,
  payload: unknown,
): ProviderTransportTerminalEnvelope {
  return Object.freeze({
    version: 1,
    type: PROVIDER_TRANSPORT_TERMINAL_TYPE,
    correlationId: requireCorrelationId(correlationIdValue),
    receiptId: requireReceiptId(receiptIdValue),
    expiresAt: requireDeadline(expiresAtValue),
    payload,
  });
}

export function readProviderTransportTerminalEnvelope(
  value: unknown,
): ProviderTransportTerminalEnvelope | null {
  const record = closedDataRecord(
    value,
    ["version", "type", "correlationId", "receiptId", "expiresAt", "payload"],
  );
  if (
    record === null ||
    record.version !== 1 ||
    record.type !== PROVIDER_TRANSPORT_TERMINAL_TYPE
  ) {
    return null;
  }
  try {
    return createProviderTransportTerminalEnvelope(
      requireCorrelationId(record.correlationId),
      requireReceiptId(record.receiptId),
      requireDeadline(record.expiresAt),
      record.payload,
    );
  } catch {
    return null;
  }
}

export function createProviderTransportReceiptEnvelope(
  correlationIdValue: string,
  receiptIdValue: string,
  expiresAtValue: number,
): ProviderTransportReceiptEnvelope {
  return Object.freeze({
    version: 1,
    type: PROVIDER_TRANSPORT_RECEIPT_TYPE,
    correlationId: requireCorrelationId(correlationIdValue),
    receiptId: requireReceiptId(receiptIdValue),
    expiresAt: requireDeadline(expiresAtValue),
  });
}

export function readProviderTransportReceiptEnvelope(
  value: unknown,
): ProviderTransportReceiptEnvelope | null {
  return readIdentityEnvelope(
    value,
    PROVIDER_TRANSPORT_RECEIPT_TYPE,
  ) as ProviderTransportReceiptEnvelope | null;
}

export function createProviderTransportSettledEnvelope(
  correlationIdValue: string,
  receiptIdValue: string,
  expiresAtValue: number,
): ProviderTransportSettledEnvelope {
  return Object.freeze({
    version: 1,
    type: PROVIDER_TRANSPORT_SETTLED_TYPE,
    correlationId: requireCorrelationId(correlationIdValue),
    receiptId: requireReceiptId(receiptIdValue),
    expiresAt: requireDeadline(expiresAtValue),
  });
}

export function readProviderTransportSettledEnvelope(
  value: unknown,
): ProviderTransportSettledEnvelope | null {
  return readIdentityEnvelope(
    value,
    PROVIDER_TRANSPORT_SETTLED_TYPE,
  ) as ProviderTransportSettledEnvelope | null;
}

export function createProviderTransportCancelEnvelope(
  expiresAtValue: number,
  payload: unknown,
): ProviderTransportCancelEnvelope {
  return Object.freeze({
    version: 1,
    type: PROVIDER_TRANSPORT_CANCEL_TYPE,
    expiresAt: requireDeadline(expiresAtValue),
    payload,
  });
}

export function readProviderTransportCancelEnvelope(
  value: unknown,
): ProviderTransportCancelEnvelope | null {
  const record = closedDataRecord(value, ["version", "type", "expiresAt", "payload"]);
  if (
    record === null ||
    record.version !== 1 ||
    record.type !== PROVIDER_TRANSPORT_CANCEL_TYPE
  ) {
    return null;
  }
  try {
    return createProviderTransportCancelEnvelope(
      requireDeadline(record.expiresAt),
      record.payload,
    );
  } catch {
    return null;
  }
}

export function createPageProviderReceiptEnvelope(
  payload: ProviderTransportReceiptEnvelope,
): PageProviderReceiptEnvelope {
  const receipt = readProviderTransportReceiptEnvelope(payload);
  if (receipt === null) {
    throw new ProviderDeliveryProtocolError("page receipt payload is malformed");
  }
  return Object.freeze({
    version: 1,
    type: PAGE_PROVIDER_RECEIPT_TYPE,
    payload: receipt,
  });
}

export function readPageProviderReceiptEnvelope(
  value: unknown,
): PageProviderReceiptEnvelope | null {
  const record = closedDataRecord(value, ["version", "type", "payload"]);
  if (
    record === null ||
    record.version !== 1 ||
    record.type !== PAGE_PROVIDER_RECEIPT_TYPE
  ) {
    return null;
  }
  const payload = readProviderTransportReceiptEnvelope(record.payload);
  if (payload === null) return null;
  return Object.freeze({
    version: 1,
    type: PAGE_PROVIDER_RECEIPT_TYPE,
    payload,
  });
}
