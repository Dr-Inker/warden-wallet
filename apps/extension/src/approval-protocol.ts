export const APPROVAL_UI_PORT_NAME = "warden:approval-ui:v1";

const CORRELATION_ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
const REQUEST_ID_PATTERN = /^req_[0-9a-f]{32}$/;
const BASE58_PUBLIC_KEY_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;
const REVIEW_METHOD = "approval:getReview";
const APPROVE_METHOD = "approval:approve";
const REJECT_METHOD = "approval:reject";
const UNAVAILABLE_CODE = "WARDEN_APPROVAL_UNAVAILABLE";
const UNAVAILABLE_MESSAGE = "Approval request is unavailable";
const MAX_APPROVAL_TTL_MS = 10 * 60 * 1_000;
const MAX_JAVASCRIPT_DATE_MS = 8_640_000_000_000_000;

const REQUEST_FIELDS = [
  "correlationId",
  "method",
  "params",
  "type",
  "version",
] as const;
const PARAM_FIELDS = ["requestId"] as const;
const RESPONSE_FIELDS = ["correlationId", "ok", "result", "type", "version"] as const;
const ERROR_RESPONSE_FIELDS = ["correlationId", "error", "ok", "type", "version"] as const;
const ERROR_FIELDS = ["code", "message"] as const;
const REVIEW_RESULT_FIELDS = ["canApprove", "requestId", "review", "status"] as const;
const APPROVED_RESULT_FIELDS = ["requestId", "status"] as const;
const REJECTED_RESULT_FIELDS = ["requestId", "status"] as const;
const REVIEW_FIELDS = [
  "account",
  "chain",
  "computeUnitLimit",
  "createdAt",
  "expiresAt",
  "genesisHash",
  "heapFrameBytes",
  "kind",
  "memo",
  "memoByteLength",
  "memoProgram",
  "messageByteLength",
  "messageDigest",
  "method",
  "origin",
  "policyVersion",
  "recentBlockhash",
  "registry",
  "requestId",
  "sessionAccount",
  "sessionSigner",
  "wardenProgram",
] as const;

export type ApprovalUiMethod =
  | typeof REVIEW_METHOD
  | typeof APPROVE_METHOD
  | typeof REJECT_METHOD;

export interface ApprovalUiRequest {
  readonly version: 1;
  readonly type: "request";
  readonly correlationId: string;
  readonly method: ApprovalUiMethod;
  readonly params: Readonly<{ readonly requestId: string }>;
}

export interface ApprovalReviewDetails {
  readonly kind: "memo-v1";
  readonly requestId: string;
  readonly origin: string;
  readonly method: "solana:signTransaction";
  readonly chain:
    | "solana:mainnet"
    | "solana:devnet"
    | "solana:testnet"
    | "solana:localnet";
  readonly genesisHash: string;
  readonly account: string;
  readonly sessionSigner: string;
  readonly sessionAccount: string;
  readonly registry: string;
  readonly wardenProgram: string;
  readonly memoProgram: string;
  readonly recentBlockhash: string;
  readonly memo: string;
  readonly memoByteLength: number;
  readonly computeUnitLimit: number;
  readonly heapFrameBytes: number;
  readonly messageByteLength: number;
  readonly messageDigest: string;
  readonly policyVersion: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface ApprovalReviewResponse {
  readonly version: 1;
  readonly type: "response";
  readonly correlationId: string;
  readonly ok: true;
  readonly result: Readonly<{
    readonly status: "pending";
    readonly requestId: string;
    readonly canApprove: boolean;
    readonly review: ApprovalReviewDetails;
  }>;
}

export interface ApprovalApprovedResponse {
  readonly version: 1;
  readonly type: "response";
  readonly correlationId: string;
  readonly ok: true;
  readonly result: Readonly<{
    readonly status: "approved";
    readonly requestId: string;
  }>;
}

export interface ApprovalRejectedResponse {
  readonly version: 1;
  readonly type: "response";
  readonly correlationId: string;
  readonly ok: true;
  readonly result: Readonly<{
    readonly status: "rejected";
    readonly requestId: string;
  }>;
}

export interface ApprovalUnavailableResponse {
  readonly version: 1;
  readonly type: "response";
  readonly correlationId: string;
  readonly ok: false;
  readonly error: Readonly<{
    readonly code: typeof UNAVAILABLE_CODE;
    readonly message: typeof UNAVAILABLE_MESSAGE;
  }>;
}

export type ApprovalUiResponse =
  | ApprovalReviewResponse
  | ApprovalApprovedResponse
  | ApprovalRejectedResponse
  | ApprovalUnavailableResponse;

export class ApprovalUiProtocolError extends Error {
  constructor(message: string) {
    super(`approval UI protocol: ${message}`);
    this.name = "ApprovalUiProtocolError";
  }
}

function invalid(message: string): never {
  throw new ApprovalUiProtocolError(message);
}

function exactDataRecord(
  value: unknown,
  fields: readonly string[],
  name: string,
): Readonly<Record<string, unknown>> {
  let keys: readonly PropertyKey[];
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      invalid(`${name} must be an object`);
    }
    keys = Reflect.ownKeys(value);
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch (error) {
    if (error instanceof ApprovalUiProtocolError) throw error;
    invalid(`${name} shape could not be inspected`);
  }
  if (prototype !== Object.prototype && prototype !== null) {
    invalid(`${name} has a custom prototype`);
  }
  const stringKeys = keys.filter((key): key is string => typeof key === "string").sort();
  const expected = [...fields].sort();
  if (
    keys.length !== expected.length ||
    stringKeys.length !== expected.length ||
    expected.some((field, index) => stringKeys[index] !== field)
  ) {
    invalid(`${name} has missing or unknown fields`);
  }
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const field of expected) {
    const descriptor = descriptors[field];
    if (descriptor === undefined || !("value" in descriptor)) {
      invalid(`${name}.${field} must be an own data property`);
    }
    result[field] = descriptor.value;
  }
  return result;
}

function correlationId(value: unknown): string {
  if (typeof value !== "string" || !CORRELATION_ID_PATTERN.test(value)) {
    invalid("correlation id is malformed");
  }
  return value;
}

function ownDataProperty(value: unknown, field: string, name: string): unknown {
  let descriptor: PropertyDescriptor | undefined;
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      invalid(`${name} must be an object`);
    }
    descriptor = Object.getOwnPropertyDescriptor(value, field);
  } catch (error) {
    if (error instanceof ApprovalUiProtocolError) throw error;
    invalid(`${name} shape could not be inspected`);
  }
  if (descriptor === undefined || !("value" in descriptor)) {
    invalid(`${name}.${field} must be an own data property`);
  }
  return descriptor.value;
}

export function parseApprovalRequestId(value: unknown): string {
  if (typeof value !== "string" || !REQUEST_ID_PATTERN.test(value)) {
    invalid("request id is malformed");
  }
  return value;
}

function safeInteger(
  value: unknown,
  name: string,
  minimum = 0,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < minimum ||
    (value as number) > maximum
  ) {
    invalid(`${name} is outside its supported integer range`);
  }
  return value as number;
}

function publicKey(value: unknown, name: string): string {
  if (typeof value !== "string" || !BASE58_PUBLIC_KEY_PATTERN.test(value)) {
    invalid(`${name} is not a canonical bounded base58 public key`);
  }
  let decoded = 0n;
  for (const character of value) {
    decoded = decoded * 58n + BigInt(BASE58_ALPHABET.indexOf(character));
  }
  let significantBytes = 0;
  for (let remaining = decoded; remaining > 0n; remaining >>= 8n) {
    significantBytes++;
  }
  let leadingZeroBytes = 0;
  while (value[leadingZeroBytes] === "1") leadingZeroBytes++;
  if (leadingZeroBytes + significantBytes !== 32) {
    invalid(`${name} does not encode exactly 32 bytes`);
  }
  return value;
}

function origin(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 2_048 ||
    CONTROL_CHARACTER_PATTERN.test(value)
  ) {
    invalid("origin is malformed");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    invalid("origin is malformed");
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.origin !== value ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    invalid("origin is not one canonical HTTP(S) origin");
  }
  return value;
}

function reviewDetails(value: unknown): ApprovalReviewDetails {
  const raw = exactDataRecord(value, REVIEW_FIELDS, "review");
  if (raw.kind !== "memo-v1") invalid("review kind is unsupported");
  const requestId = parseApprovalRequestId(raw.requestId);
  const reviewOrigin = origin(raw.origin);
  if (raw.method !== "solana:signTransaction") {
    invalid("review method is unsupported");
  }
  if (
    raw.chain !== "solana:mainnet" &&
    raw.chain !== "solana:devnet" &&
    raw.chain !== "solana:testnet" &&
    raw.chain !== "solana:localnet"
  ) {
    invalid("review chain is unsupported");
  }
  const memo = raw.memo;
  if (
    typeof memo !== "string" ||
    memo.length === 0 ||
    memo.length > 256 ||
    /[^\x20-\x7e]/.test(memo)
  ) {
    invalid("review memo is not bounded printable ASCII");
  }
  const memoByteLength = safeInteger(raw.memoByteLength, "memoByteLength", 1, 256);
  if (memoByteLength !== memo.length) invalid("memoByteLength does not match memo");
  const createdAt = safeInteger(
    raw.createdAt,
    "createdAt",
    0,
    MAX_JAVASCRIPT_DATE_MS,
  );
  const expiresAt = safeInteger(
    raw.expiresAt,
    "expiresAt",
    0,
    MAX_JAVASCRIPT_DATE_MS,
  );
  if (
    expiresAt <= createdAt ||
    expiresAt - createdAt > MAX_APPROVAL_TTL_MS
  ) {
    invalid("review lifetime is invalid");
  }
  if (typeof raw.messageDigest !== "string" || !DIGEST_PATTERN.test(raw.messageDigest)) {
    invalid("message digest is malformed");
  }

  return Object.freeze({
    kind: "memo-v1",
    requestId,
    origin: reviewOrigin,
    method: "solana:signTransaction",
    chain: raw.chain,
    genesisHash: publicKey(raw.genesisHash, "genesisHash"),
    account: publicKey(raw.account, "account"),
    sessionSigner: publicKey(raw.sessionSigner, "sessionSigner"),
    sessionAccount: publicKey(raw.sessionAccount, "sessionAccount"),
    registry: publicKey(raw.registry, "registry"),
    wardenProgram: publicKey(raw.wardenProgram, "wardenProgram"),
    memoProgram: publicKey(raw.memoProgram, "memoProgram"),
    recentBlockhash: publicKey(raw.recentBlockhash, "recentBlockhash"),
    memo,
    memoByteLength,
    computeUnitLimit: safeInteger(
      raw.computeUnitLimit,
      "computeUnitLimit",
      120_000,
      1_400_000,
    ),
    heapFrameBytes: safeInteger(
      raw.heapFrameBytes,
      "heapFrameBytes",
      128 * 1_024,
      128 * 1_024,
    ),
    messageByteLength: safeInteger(raw.messageByteLength, "messageByteLength", 1, 1_167),
    messageDigest: raw.messageDigest,
    policyVersion: safeInteger(raw.policyVersion, "policyVersion", 0, 0xffff_ffff),
    createdAt,
    expiresAt,
  });
}

export function parseApprovalUiRequest(value: unknown): ApprovalUiRequest {
  const raw = exactDataRecord(value, REQUEST_FIELDS, "request");
  if (raw.version !== 1 || raw.type !== "request") invalid("request envelope is invalid");
  const id = correlationId(raw.correlationId);
  if (
    raw.method !== REVIEW_METHOD &&
    raw.method !== APPROVE_METHOD &&
    raw.method !== REJECT_METHOD
  ) {
    invalid("request method is unsupported");
  }
  const params = exactDataRecord(raw.params, PARAM_FIELDS, "request params");
  return Object.freeze({
    version: 1,
    type: "request",
    correlationId: id,
    method: raw.method,
    params: Object.freeze({ requestId: parseApprovalRequestId(params.requestId) }),
  });
}

export function createApprovalReviewResponse(
  correlationIdValue: string,
  reviewValue: ApprovalReviewDetails,
  canApproveValue = false,
): ApprovalReviewResponse {
  const id = correlationId(correlationIdValue);
  const review = reviewDetails(reviewValue);
  if (typeof canApproveValue !== "boolean") {
    invalid("review approval capability must be boolean");
  }
  return Object.freeze({
    version: 1,
    type: "response",
    correlationId: id,
    ok: true,
    result: Object.freeze({
      status: "pending",
      requestId: review.requestId,
      canApprove: canApproveValue,
      review,
    }),
  });
}

export function createApprovalApprovedResponse(
  correlationIdValue: string,
  requestIdValue: string,
): ApprovalApprovedResponse {
  return Object.freeze({
    version: 1,
    type: "response",
    correlationId: correlationId(correlationIdValue),
    ok: true,
    result: Object.freeze({
      status: "approved",
      requestId: parseApprovalRequestId(requestIdValue),
    }),
  });
}

export function createApprovalRejectedResponse(
  correlationIdValue: string,
  requestIdValue: string,
): ApprovalRejectedResponse {
  return Object.freeze({
    version: 1,
    type: "response",
    correlationId: correlationId(correlationIdValue),
    ok: true,
    result: Object.freeze({
      status: "rejected",
      requestId: parseApprovalRequestId(requestIdValue),
    }),
  });
}

export function createApprovalUnavailableResponse(
  correlationIdValue: string,
): ApprovalUnavailableResponse {
  return Object.freeze({
    version: 1,
    type: "response",
    correlationId: correlationId(correlationIdValue),
    ok: false,
    error: Object.freeze({
      code: UNAVAILABLE_CODE,
      message: UNAVAILABLE_MESSAGE,
    }),
  });
}

export function parseApprovalUiResponse(value: unknown): ApprovalUiResponse {
  const ok = ownDataProperty(value, "ok", "response");

  if (ok === false) {
    const raw = exactDataRecord(value, ERROR_RESPONSE_FIELDS, "response");
    if (raw.version !== 1 || raw.type !== "response" || raw.ok !== false) {
      invalid("unavailable response envelope is invalid");
    }
    const error = exactDataRecord(raw.error, ERROR_FIELDS, "response error");
    if (error.code !== UNAVAILABLE_CODE || error.message !== UNAVAILABLE_MESSAGE) {
      invalid("unavailable response error is invalid");
    }
    return createApprovalUnavailableResponse(correlationId(raw.correlationId));
  }
  if (ok !== true) invalid("response.ok is invalid");

  const raw = exactDataRecord(value, RESPONSE_FIELDS, "response");
  if (raw.version !== 1 || raw.type !== "response" || raw.ok !== true) {
    invalid("success response envelope is invalid");
  }
  const id = correlationId(raw.correlationId);
  const resultStatus = ownDataProperty(raw.result, "status", "response result");
  if (resultStatus === "pending") {
    const result = exactDataRecord(raw.result, REVIEW_RESULT_FIELDS, "review result");
    const requestId = parseApprovalRequestId(result.requestId);
    if (typeof result.canApprove !== "boolean") {
      invalid("review approval capability must be boolean");
    }
    const review = reviewDetails(result.review);
    if (review.requestId !== requestId) invalid("review request id does not match result");
    return createApprovalReviewResponse(id, review, result.canApprove);
  }
  if (resultStatus === "approved") {
    const result = exactDataRecord(raw.result, APPROVED_RESULT_FIELDS, "approved result");
    return createApprovalApprovedResponse(id, parseApprovalRequestId(result.requestId));
  }
  if (resultStatus === "rejected") {
    const result = exactDataRecord(raw.result, REJECTED_RESULT_FIELDS, "rejected result");
    return createApprovalRejectedResponse(id, parseApprovalRequestId(result.requestId));
  }
  invalid("response status is unsupported");
}
