//! Still-unreachable C14/C19 provider terminal language.
//!
//! This module is intentionally separate from the page/content protocol. The
//! emitted content bridge continues to accept only WARDEN_METHOD_UNAVAILABLE;
//! importing this file there requires a later explicit trust-boundary review.

import { MAX_TX_BYTES } from "@warden/core/constants";

const CORRELATION_ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;

const TERMINAL_FAILURE_MESSAGES = Object.freeze({
  WARDEN_USER_REJECTED: "User rejected the request",
  WARDEN_REQUEST_CANCELLED: "Provider request was cancelled",
  WARDEN_REQUEST_EXPIRED: "Provider request expired",
  WARDEN_REQUEST_FAILED: "Provider request failed",
} as const);

export type ProviderTerminalFailureCode = keyof typeof TERMINAL_FAILURE_MESSAGES;

export interface ProviderSignedTransactionResponse {
  readonly version: 1;
  readonly type: "response";
  readonly correlationId: string;
  readonly ok: true;
  readonly result: Readonly<{
    readonly signedTransaction: readonly number[];
  }>;
}

export interface ProviderTerminalFailureResponse {
  readonly version: 1;
  readonly type: "response";
  readonly correlationId: string;
  readonly ok: false;
  readonly error: Readonly<{
    readonly code: ProviderTerminalFailureCode;
    readonly message: (typeof TERMINAL_FAILURE_MESSAGES)[ProviderTerminalFailureCode];
  }>;
}

export type ProviderTerminalResponse =
  | ProviderSignedTransactionResponse
  | ProviderTerminalFailureResponse;

export class ProviderTerminalProtocolError extends Error {
  constructor(message: string) {
    super(`provider terminal protocol: ${message}`);
    this.name = "ProviderTerminalProtocolError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactFields(
  value: Record<string, unknown>,
  fields: readonly string[],
): boolean {
  try {
    const keys = Reflect.ownKeys(value);
    return keys.length === fields.length &&
      keys.every((key) => typeof key === "string" && fields.includes(key)) &&
      fields.every((field) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, field);
        return descriptor !== undefined &&
          "value" in descriptor &&
          descriptor.enumerable === true;
      });
  } catch {
    return false;
  }
}

function isDenseTransaction(value: unknown): value is readonly number[] {
  try {
    if (!Array.isArray(value) || value.length === 0 || value.length > MAX_TX_BYTES) {
      return false;
    }
    for (let index = 0; index < value.length; index++) {
      if (!Object.hasOwn(value, index)) return false;
      const byte = value[index];
      if (!Number.isInteger(byte) || byte < 0 || byte > 255) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function isTerminalFailureCode(
  value: unknown,
): value is ProviderTerminalFailureCode {
  return typeof value === "string" && Object.hasOwn(TERMINAL_FAILURE_MESSAGES, value);
}

export function providerTerminalFailureMessage(
  code: ProviderTerminalFailureCode,
): (typeof TERMINAL_FAILURE_MESSAGES)[ProviderTerminalFailureCode] {
  if (!isTerminalFailureCode(code)) {
    throw new ProviderTerminalProtocolError("terminal failure code is unsupported");
  }
  return TERMINAL_FAILURE_MESSAGES[code];
}

export function isSignedTransactionProviderResponse(
  value: unknown,
): value is ProviderSignedTransactionResponse {
  try {
    if (
      !isRecord(value) ||
      !exactFields(value, ["version", "type", "correlationId", "ok", "result"]) ||
      value.version !== 1 ||
      value.type !== "response" ||
      typeof value.correlationId !== "string" ||
      !CORRELATION_ID_PATTERN.test(value.correlationId) ||
      value.ok !== true ||
      !isRecord(value.result) ||
      !exactFields(value.result, ["signedTransaction"]) ||
      !isDenseTransaction(value.result.signedTransaction)
    ) {
      return false;
    }
    return true;
  } catch {
    // Validators at the page boundary must be total even for revoked or
    // adversarial proxies supplied by same-realm tests.
    return false;
  }
}

export function isProviderTerminalFailureResponse(
  value: unknown,
): value is ProviderTerminalFailureResponse {
  try {
    if (
      !isRecord(value) ||
      !exactFields(value, ["version", "type", "correlationId", "ok", "error"]) ||
      value.version !== 1 ||
      value.type !== "response" ||
      typeof value.correlationId !== "string" ||
      !CORRELATION_ID_PATTERN.test(value.correlationId) ||
      value.ok !== false ||
      !isRecord(value.error) ||
      !exactFields(value.error, ["code", "message"]) ||
      !isTerminalFailureCode(value.error.code) ||
      value.error.message !== TERMINAL_FAILURE_MESSAGES[value.error.code]
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

export function createSignedTransactionProviderResponse(
  correlationId: string,
  transactionBytes: Uint8Array,
): ProviderSignedTransactionResponse {
  if (
    typeof correlationId !== "string" ||
    !CORRELATION_ID_PATTERN.test(correlationId)
  ) {
    throw new ProviderTerminalProtocolError("correlation id is malformed");
  }
  if (
    !(transactionBytes instanceof Uint8Array) ||
    transactionBytes.length === 0 ||
    transactionBytes.length > MAX_TX_BYTES
  ) {
    throw new ProviderTerminalProtocolError("signed transaction bytes are malformed");
  }
  return Object.freeze({
    version: 1,
    type: "response",
    correlationId,
    ok: true,
    result: Object.freeze({
      signedTransaction: Object.freeze(Array.from(transactionBytes)),
    }),
  });
}

export function createProviderTerminalFailureResponse(
  correlationId: string,
  code: ProviderTerminalFailureCode,
): ProviderTerminalFailureResponse {
  if (
    typeof correlationId !== "string" ||
    !CORRELATION_ID_PATTERN.test(correlationId)
  ) {
    throw new ProviderTerminalProtocolError("correlation id is malformed");
  }
  const message = providerTerminalFailureMessage(code);
  return Object.freeze({
    version: 1,
    type: "response",
    correlationId,
    ok: false,
    error: Object.freeze({ code, message }),
  });
}
