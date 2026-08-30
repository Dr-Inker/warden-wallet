export const PROVIDER_PORT_NAME = "warden:provider:v1";
export const PAGE_PROVIDER_REQUEST_TYPE = "warden:provider:request";
export const PAGE_PROVIDER_RESPONSE_TYPE = "warden:provider:response";
export const MAX_PROVIDER_REQUESTS_PER_DOCUMENT = 1_024;

const CORRELATION_ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
const UNAVAILABLE_CODE = "WARDEN_METHOD_UNAVAILABLE";
const UNAVAILABLE_MESSAGE = "Warden provider methods are not enabled";

export interface PageProviderRequestEnvelope {
  readonly version: 1;
  readonly type: typeof PAGE_PROVIDER_REQUEST_TYPE;
  readonly payload: unknown;
}

export interface PageProviderResponseEnvelope {
  readonly version: 1;
  readonly type: typeof PAGE_PROVIDER_RESPONSE_TYPE;
  readonly payload: ProviderUnavailableResponse;
}

export interface ProviderUnavailableResponse {
  readonly version: 1;
  readonly type: "response";
  readonly correlationId: string;
  readonly ok: false;
  readonly error: Readonly<{
    code: typeof UNAVAILABLE_CODE;
    message: typeof UNAVAILABLE_MESSAGE;
  }>;
}

export class ProviderProtocolError extends Error {
  constructor(message: string) {
    super(`provider protocol: ${message}`);
    this.name = "ProviderProtocolError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactOwnFields(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  try {
    const fields = Object.keys(value);
    return (
      fields.length === expected.length &&
      expected.every((field) => Object.hasOwn(value, field)) &&
      fields.every((field) => expected.includes(field))
    );
  } catch {
    return false;
  }
}

/**
 * Recognize only Warden's page-to-content transport wrapper. The payload stays
 * opaque and untrusted here; the background owns provider-schema validation.
 */
export function readPageProviderRequestEnvelope(
  value: unknown,
): PageProviderRequestEnvelope | null {
  if (
    !isRecord(value) ||
    !hasExactOwnFields(value, ["version", "type", "payload"]) ||
    value.version !== 1 ||
    value.type !== PAGE_PROVIDER_REQUEST_TYPE
  ) {
    return null;
  }
  return value as unknown as PageProviderRequestEnvelope;
}

/**
 * The zero-authority background currently has exactly one response language.
 * Rejecting every other shape prevents a future accidental background payload
 * from being copied into a hostile page without an explicit protocol change.
 */
export function isProviderUnavailableResponse(
  value: unknown,
): value is ProviderUnavailableResponse {
  if (
    !isRecord(value) ||
    !hasExactOwnFields(value, ["version", "type", "correlationId", "ok", "error"]) ||
    value.version !== 1 ||
    value.type !== "response" ||
    typeof value.correlationId !== "string" ||
    !CORRELATION_ID_PATTERN.test(value.correlationId) ||
    value.ok !== false ||
    !isRecord(value.error) ||
    !hasExactOwnFields(value.error, ["code", "message"]) ||
    value.error.code !== UNAVAILABLE_CODE ||
    value.error.message !== UNAVAILABLE_MESSAGE
  ) {
    return false;
  }
  return true;
}

export function createUnavailableProviderResponse(
  correlationId: string,
): ProviderUnavailableResponse {
  if (!CORRELATION_ID_PATTERN.test(correlationId)) {
    throw new ProviderProtocolError("cannot create a response for a malformed correlation id");
  }
  return Object.freeze({
    version: 1,
    type: "response",
    correlationId,
    ok: false,
    error: Object.freeze({
      code: UNAVAILABLE_CODE,
      message: UNAVAILABLE_MESSAGE,
    }),
  });
}

export function createPageProviderResponseEnvelope(
  payload: ProviderUnavailableResponse,
): PageProviderResponseEnvelope {
  return Object.freeze({
    version: 1,
    type: PAGE_PROVIDER_RESPONSE_TYPE,
    payload,
  });
}
