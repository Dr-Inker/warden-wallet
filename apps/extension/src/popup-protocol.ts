export const POPUP_PORT_NAME = "warden:popup:v1";
export const MAX_POPUP_REQUESTS_PER_PORT = 16;

const CORRELATION_ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
const POPUP_METHOD = "popup:getBoundaryStatus";
const UNAVAILABLE_CODE = "WARDEN_POPUP_UNAVAILABLE";
const UNAVAILABLE_MESSAGE = "Warden popup methods are not enabled";

export interface PopupBoundaryStatusRequest {
  readonly version: 1;
  readonly type: "request";
  readonly correlationId: string;
  readonly method: typeof POPUP_METHOD;
  readonly params: Readonly<Record<never, never>>;
}

export interface PopupUnavailableResponse {
  readonly version: 1;
  readonly type: "response";
  readonly correlationId: string;
  readonly ok: false;
  readonly error: Readonly<{
    code: typeof UNAVAILABLE_CODE;
    message: typeof UNAVAILABLE_MESSAGE;
  }>;
}

export class PopupProtocolError extends Error {
  constructor(message: string) {
    super(`popup protocol: ${message}`);
    this.name = "PopupProtocolError";
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

function hasValidCorrelationId(value: unknown): value is string {
  return typeof value === "string" && CORRELATION_ID_PATTERN.test(value);
}

/**
 * Parse the popup's separate, deliberately powerless request language. It has
 * no account, origin, approval, storage, key, RPC, or provider fields.
 */
export function parsePopupRequest(value: unknown): PopupBoundaryStatusRequest {
  if (
    !isRecord(value) ||
    !hasExactOwnFields(value, [
      "version",
      "type",
      "correlationId",
      "method",
      "params",
    ]) ||
    value.version !== 1 ||
    value.type !== "request" ||
    !hasValidCorrelationId(value.correlationId) ||
    value.method !== POPUP_METHOD ||
    !isRecord(value.params) ||
    !hasExactOwnFields(value.params, [])
  ) {
    throw new PopupProtocolError("invalid request");
  }

  return Object.freeze({
    version: 1,
    type: "request",
    correlationId: value.correlationId,
    method: POPUP_METHOD,
    params: Object.freeze({}),
  });
}

export function createUnavailablePopupResponse(
  correlationId: string,
): PopupUnavailableResponse {
  if (!hasValidCorrelationId(correlationId)) {
    throw new PopupProtocolError(
      "cannot create a response for a malformed correlation id",
    );
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

export function isPopupUnavailableResponse(
  value: unknown,
): value is PopupUnavailableResponse {
  return (
    isRecord(value) &&
    hasExactOwnFields(value, ["version", "type", "correlationId", "ok", "error"]) &&
    value.version === 1 &&
    value.type === "response" &&
    hasValidCorrelationId(value.correlationId) &&
    value.ok === false &&
    isRecord(value.error) &&
    hasExactOwnFields(value.error, ["code", "message"]) &&
    value.error.code === UNAVAILABLE_CODE &&
    value.error.message === UNAVAILABLE_MESSAGE
  );
}
