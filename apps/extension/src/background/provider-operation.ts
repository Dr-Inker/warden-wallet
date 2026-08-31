//! Still-unreachable C14 durable provider-operation identity and journal owner.
//!
//! A page correlation id is not trusted as authority, but when it is joined to
//! browser-owned document provenance and the exact closed provider request it
//! becomes an idempotency identity. The journal claim must commit before an
//! approval is prepared. While the bounded journal row is retained, an
//! interrupted `preparing` claim is never retried: liveness may fail, but a
//! reconnect cannot mint a second approval/signature.

import { APPROVAL_DIGEST_BYTES } from "@warden/core/approval";

import type { OwnedProviderRequest } from "./provider-port.js";
import { MAX_PROVIDER_REQUEST_TTL_MS } from "./provider-port.js";
import { MAX_TRANSACTION_BYTES } from "./provider-message.js";

export const PROVIDER_OPERATION_VERSION = 1 as const;
export const PROVIDER_OPERATION_DIGEST_BYTES = 32;
export const PROVIDER_OPERATION_KEY_PREFIX = "op_";

const PROVIDER_OPERATION_KEY_PATTERN = /^op_[0-9a-f]{64}$/;
const APPROVAL_ID_PATTERN = /^req_[0-9a-f]{32}$/;
const CORRELATION_ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
const ACCOUNT_ADDRESS_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const EXTENSION_ID_PATTERN = /^[a-p]{32}$/;
const DOCUMENT_ID_PATTERN = /^[\x21-\x7e]{1,128}$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;
const CHAINS: ReadonlySet<string> = new Set([
  "solana:mainnet",
  "solana:devnet",
  "solana:testnet",
  "solana:localnet",
]);
const COMMITMENTS: ReadonlySet<string> = new Set([
  "processed",
  "confirmed",
  "finalized",
]);

const IDENTITY_FIELDS = [
  "correlationId",
  "documentId",
  "extensionId",
  "frameId",
  "key",
  "method",
  "origin",
  "requestDigest",
  "tabId",
] as const;
const RECORD_FIELDS = [
  "approvalDigest",
  "approvalId",
  "correlationId",
  "createdAt",
  "documentId",
  "expiresAt",
  "extensionId",
  "failureCode",
  "frameId",
  "key",
  "method",
  "origin",
  "requestDigest",
  "resolvedAt",
  "state",
  "tabId",
  "version",
] as const;

export type ProviderOperationState = "preparing" | "bound" | "failed";
export type ProviderOperationFailureCode =
  | "preparation-failed"
  | "request-cancelled"
  | "worker-restarted"
  | "expired";

const FAILURE_CODES: ReadonlySet<string> = new Set([
  "preparation-failed",
  "request-cancelled",
  "worker-restarted",
  "expired",
]);

export interface ProviderOperationIdentity {
  readonly key: string;
  readonly extensionId: string;
  readonly origin: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly correlationId: string;
  readonly method: "solana:signTransaction";
  readonly requestDigest: Uint8Array;
}

export interface ProviderOperationRecord extends ProviderOperationIdentity {
  readonly version: typeof PROVIDER_OPERATION_VERSION;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly state: ProviderOperationState;
  readonly approvalId: string | null;
  readonly approvalDigest: Uint8Array | null;
  readonly failureCode: ProviderOperationFailureCode | null;
  readonly resolvedAt: number | null;
}

export interface ProviderOperationClaim {
  readonly created: boolean;
  readonly record: ProviderOperationRecord;
}

export interface ProviderOperationRepository {
  claim(input: {
    readonly identity: ProviderOperationIdentity;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly now: number;
  }): Promise<ProviderOperationClaim>;
  read(input: {
    readonly key: string;
    readonly now: number;
  }): Promise<ProviderOperationRecord | null>;
  bind(input: {
    readonly key: string;
    readonly expectedRequestDigest: Uint8Array;
    readonly approvalId: string;
    readonly approvalDigest: Uint8Array;
    readonly now: number;
  }): Promise<ProviderOperationRecord>;
  fail(input: {
    readonly key: string;
    readonly expectedRequestDigest: Uint8Array;
    readonly failureCode: ProviderOperationFailureCode;
    readonly now: number;
  }): Promise<ProviderOperationRecord>;
  invalidatePreparing(now: number): Promise<number>;
  close(): void;
}

export interface ProviderOperationDigestSource {
  digest(bytes: Uint8Array): Promise<Uint8Array>;
}

export interface ProviderOperationRequestLease {
  readonly owned: OwnedProviderRequest;
  assertActive(): void;
}

export interface ProviderOperationPreparation {
  readonly id: string;
  readonly messageDigest: Uint8Array;
}

export interface ProviderOperationResolution {
  /** True only for the caller that invoked the preparation callback. */
  readonly created: boolean;
  readonly record: ProviderOperationRecord;
}

export interface ProviderOperationOwnerOptions {
  readonly readNow?: () => number;
  readonly digestSource?: ProviderOperationDigestSource;
}

export class ProviderOperationStateError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`provider operation: ${message}`, options);
    this.name = "ProviderOperationStateError";
  }
}

function stateError(message: string, cause?: unknown): never {
  throw new ProviderOperationStateError(
    message,
    cause === undefined ? {} : { cause },
  );
}

function closedDataRecord(
  value: unknown,
  fields: readonly string[],
  name: string,
): Record<string, unknown> {
  let keys: readonly PropertyKey[];
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    if (
      typeof value !== "object" ||
      value === null ||
      Array.isArray(value) ||
      value instanceof Uint8Array
    ) {
      stateError(`${name} must be an object`);
    }
    keys = Reflect.ownKeys(value);
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch (error) {
    if (error instanceof ProviderOperationStateError) throw error;
    stateError(`${name} shape could not be inspected`, error);
  }
  const stringKeys = keys
    .filter((key): key is string => typeof key === "string")
    .sort();
  if (
    prototype !== Object.prototype &&
    prototype !== null
  ) {
    stateError(`${name} must have a plain prototype`);
  }
  if (
    keys.length !== fields.length ||
    stringKeys.length !== fields.length ||
    stringKeys.some((field, index) => field !== fields[index])
  ) {
    stateError(`${name} has missing or unknown fields`);
  }
  const record: Record<string, unknown> = {};
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      stateError(`${name}.${field} must be an enumerable own data property`);
    }
    record[field] = descriptor.value;
  }
  return record;
}

function requireSafeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    stateError(`${name} must be a non-negative safe integer`);
  }
  return value as number;
}

function requireKey(value: unknown): string {
  if (typeof value !== "string" || !PROVIDER_OPERATION_KEY_PATTERN.test(value)) {
    stateError("key must be a SHA-256 provider operation key");
  }
  return value;
}

function requireBytes(value: unknown, length: number, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    stateError(`${name} must contain exactly ${length} bytes`);
  }
  return value.slice();
}

function requireApprovalId(value: unknown): string {
  if (typeof value !== "string" || !APPROVAL_ID_PATTERN.test(value)) {
    stateError("approvalId must be a background-minted approval id");
  }
  return value;
}

function requireOrigin(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 2_048 ||
    CONTROL_CHARACTER_PATTERN.test(value)
  ) {
    stateError("origin is malformed");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (error) {
    stateError("origin is malformed", error);
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.origin !== value ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    stateError("origin must be a canonical HTTP(S) origin");
  }
  return value;
}

function requireIdentityFields(record: Record<string, unknown>): ProviderOperationIdentity {
  const key = requireKey(record.key);
  if (
    typeof record.extensionId !== "string" ||
    !EXTENSION_ID_PATTERN.test(record.extensionId)
  ) {
    stateError("extensionId is malformed");
  }
  const origin = requireOrigin(record.origin);
  const tabId = requireSafeInteger(record.tabId, "tabId");
  const frameId = requireSafeInteger(record.frameId, "frameId");
  if (
    typeof record.documentId !== "string" ||
    !DOCUMENT_ID_PATTERN.test(record.documentId)
  ) {
    stateError("documentId is malformed");
  }
  if (
    typeof record.correlationId !== "string" ||
    !CORRELATION_ID_PATTERN.test(record.correlationId)
  ) {
    stateError("correlationId is malformed");
  }
  if (record.method !== "solana:signTransaction") {
    stateError("method is unsupported");
  }
  const requestDigest = requireBytes(
    record.requestDigest,
    PROVIDER_OPERATION_DIGEST_BYTES,
    "requestDigest",
  );
  return Object.freeze({
    key,
    extensionId: record.extensionId,
    origin,
    tabId,
    frameId,
    documentId: record.documentId,
    correlationId: record.correlationId,
    method: "solana:signTransaction",
    requestDigest,
  });
}

export function snapshotProviderOperationIdentity(
  value: unknown,
): ProviderOperationIdentity {
  return requireIdentityFields(closedDataRecord(
    value,
    IDENTITY_FIELDS,
    "identity",
  ));
}

export function snapshotProviderOperation(value: unknown): ProviderOperationRecord {
  const record = closedDataRecord(value, RECORD_FIELDS, "record");
  if (record.version !== PROVIDER_OPERATION_VERSION) {
    stateError(`version must be ${PROVIDER_OPERATION_VERSION}`);
  }
  const identity = requireIdentityFields(record);
  const createdAt = requireSafeInteger(record.createdAt, "createdAt");
  const expiresAt = requireSafeInteger(record.expiresAt, "expiresAt");
  if (
    expiresAt <= createdAt ||
    expiresAt - createdAt > MAX_PROVIDER_REQUEST_TTL_MS
  ) {
    identity.requestDigest.fill(0);
    stateError(`expiresAt must be within ${MAX_PROVIDER_REQUEST_TTL_MS}ms of createdAt`);
  }
  if (
    record.state !== "preparing" &&
    record.state !== "bound" &&
    record.state !== "failed"
  ) {
    identity.requestDigest.fill(0);
    stateError("state is unsupported");
  }

  let approvalId: string | null = null;
  let approvalDigest: Uint8Array | null = null;
  let failureCode: ProviderOperationFailureCode | null = null;
  let resolvedAt: number | null = null;
  try {
    if (record.state === "preparing") {
      if (
        record.approvalId !== null ||
        record.approvalDigest !== null ||
        record.failureCode !== null ||
        record.resolvedAt !== null
      ) {
        stateError("preparing record must have no terminal fields");
      }
    } else {
      resolvedAt = requireSafeInteger(record.resolvedAt, "resolvedAt");
      if (resolvedAt < createdAt) stateError("resolvedAt precedes createdAt");
      if (record.state === "bound") {
        if (resolvedAt >= expiresAt) stateError("bound record resolved at or after expiry");
        approvalId = requireApprovalId(record.approvalId);
        approvalDigest = requireBytes(
          record.approvalDigest,
          APPROVAL_DIGEST_BYTES,
          "approvalDigest",
        );
        if (record.failureCode !== null) {
          stateError("bound record must not have a failureCode");
        }
      } else {
        if (record.approvalId !== null || record.approvalDigest !== null) {
          stateError("failed record must not have an approval binding");
        }
        if (
          typeof record.failureCode !== "string" ||
          !FAILURE_CODES.has(record.failureCode)
        ) {
          stateError("failed record has an unsupported failureCode");
        }
        failureCode = record.failureCode as ProviderOperationFailureCode;
        if (failureCode === "expired" && resolvedAt < expiresAt) {
          stateError("expired record resolved before expiry");
        }
      }
    }

    return Object.freeze({
      version: PROVIDER_OPERATION_VERSION,
      ...identity,
      createdAt,
      expiresAt,
      state: record.state,
      approvalId,
      approvalDigest,
      failureCode,
      resolvedAt,
    });
  } catch (error) {
    approvalDigest?.fill(0);
    identity.requestDigest.fill(0);
    throw error;
  }
}

function identityObject(identity: ProviderOperationIdentity): ProviderOperationIdentity {
  return {
    key: identity.key,
    extensionId: identity.extensionId,
    origin: identity.origin,
    tabId: identity.tabId,
    frameId: identity.frameId,
    documentId: identity.documentId,
    correlationId: identity.correlationId,
    method: identity.method,
    requestDigest: identity.requestDigest,
  };
}

export function providerOperationIdentitiesEqual(
  leftValue: ProviderOperationIdentity,
  rightValue: ProviderOperationIdentity,
): boolean {
  let left: ProviderOperationIdentity | undefined;
  let right: ProviderOperationIdentity | undefined;
  try {
    left = snapshotProviderOperationIdentity(identityObject(leftValue));
    right = snapshotProviderOperationIdentity(identityObject(rightValue));
    return left.key === right.key &&
      left.extensionId === right.extensionId &&
      left.origin === right.origin &&
      left.tabId === right.tabId &&
      left.frameId === right.frameId &&
      left.documentId === right.documentId &&
      left.correlationId === right.correlationId &&
      left.method === right.method &&
      bytesEqual(left.requestDigest, right.requestDigest);
  } catch {
    return false;
  } finally {
    left?.requestDigest.fill(0);
    right?.requestDigest.fill(0);
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function bytesToHex(bytes: Uint8Array): string {
  let encoded = "";
  for (const byte of bytes) encoded += byte.toString(16).padStart(2, "0");
  return encoded;
}

const DEFAULT_DIGEST_SOURCE: ProviderOperationDigestSource = Object.freeze({
  async digest(bytes: Uint8Array): Promise<Uint8Array> {
    const cryptoObject = globalThis.crypto;
    if (
      typeof cryptoObject !== "object" ||
      cryptoObject === null ||
      typeof cryptoObject.subtle !== "object" ||
      cryptoObject.subtle === null ||
      typeof cryptoObject.subtle.digest !== "function"
    ) {
      stateError("Web Crypto SHA-256 is unavailable");
    }
    let result: ArrayBuffer;
    try {
      result = await cryptoObject.subtle.digest("SHA-256", bytes.slice());
    } catch (error) {
      stateError("Web Crypto SHA-256 failed", error);
    }
    return new Uint8Array(result);
  },
});

function requireDigestSource(value: unknown): ProviderOperationDigestSource {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as Partial<ProviderOperationDigestSource>).digest !== "function"
  ) {
    stateError("digestSource must provide digest()");
  }
  const source = value as ProviderOperationDigestSource;
  return Object.freeze({ digest: source.digest.bind(source) });
}

async function digest(
  source: ProviderOperationDigestSource,
  bytes: Uint8Array,
): Promise<Uint8Array> {
  let value: unknown;
  try {
    value = await source.digest(bytes.slice());
  } catch (error) {
    if (error instanceof ProviderOperationStateError) throw error;
    stateError("digest source failed", error);
  }
  return requireBytes(value, PROVIDER_OPERATION_DIGEST_BYTES, "SHA-256 digest");
}

function requireOwnedProviderRequest(value: unknown): {
  readonly extensionId: string;
  readonly origin: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly correlationId: string;
  readonly requestedAccountAddress: string;
  readonly transaction: readonly number[];
  readonly chain: string | null;
  readonly preflightCommitment: string | null;
  readonly minContextSlot: number | null;
} {
  if (typeof value !== "object" || value === null) {
    stateError("owned provider request must be an object");
  }
  const owned = value as Partial<OwnedProviderRequest>;
  const provenance = owned.provenance;
  const request = owned.request;
  if (
    typeof provenance !== "object" ||
    provenance === null ||
    provenance.kind !== "provider" ||
    typeof request !== "object" ||
    request === null ||
    request.method !== "solana:signTransaction"
  ) {
    stateError("only a parsed signTransaction provider request is supported");
  }
  if (!EXTENSION_ID_PATTERN.test(provenance.extensionId)) {
    stateError("provider extensionId is malformed");
  }
  const origin = requireOrigin(provenance.origin);
  const tabId = requireSafeInteger(provenance.tabId, "provider tabId");
  const frameId = requireSafeInteger(provenance.frameId, "provider frameId");
  if (!DOCUMENT_ID_PATTERN.test(provenance.documentId)) {
    stateError("provider documentId is malformed");
  }
  if (!CORRELATION_ID_PATTERN.test(request.correlationId)) {
    stateError("provider correlationId is malformed");
  }
  const params = request.params;
  if (
    typeof params !== "object" ||
    params === null ||
    !ACCOUNT_ADDRESS_PATTERN.test(params.requestedAccountAddress)
  ) {
    stateError("requested account address is malformed");
  }
  if (params.chain !== null && !CHAINS.has(params.chain)) {
    stateError("provider chain is malformed");
  }
  const options = params.options;
  if (
    typeof options !== "object" ||
    options === null ||
    (options.preflightCommitment !== null &&
      !COMMITMENTS.has(options.preflightCommitment)) ||
    (options.minContextSlot !== null &&
      (!Number.isSafeInteger(options.minContextSlot) || options.minContextSlot < 0))
  ) {
    stateError("provider signTransaction options are malformed");
  }
  if (
    !Array.isArray(params.transaction) ||
    params.transaction.length === 0 ||
    params.transaction.length > MAX_TRANSACTION_BYTES
  ) {
    stateError("provider transaction is malformed");
  }
  const transaction = new Array<number>(params.transaction.length);
  for (let index = 0; index < params.transaction.length; index++) {
    if (!Object.hasOwn(params.transaction, index)) {
      stateError("provider transaction must be dense");
    }
    const byte = params.transaction[index];
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      stateError(`provider transaction[${index}] is not a byte`);
    }
    transaction[index] = byte;
  }
  return Object.freeze({
    extensionId: provenance.extensionId,
    origin,
    tabId,
    frameId,
    documentId: provenance.documentId,
    correlationId: request.correlationId,
    requestedAccountAddress: params.requestedAccountAddress,
    transaction: Object.freeze(transaction),
    chain: params.chain,
    preflightCommitment: options.preflightCommitment,
    minContextSlot: options.minContextSlot,
  });
}

/**
 * Derive a stable key across background request-id/time reminting. Every page
 * request field and every browser-owned provenance field is length-delimited by
 * a fixed JSON tuple before SHA-256; no page field is treated as authority.
 */
export async function deriveProviderOperationIdentity(
  ownedValue: OwnedProviderRequest,
  digestSourceValue: ProviderOperationDigestSource = DEFAULT_DIGEST_SOURCE,
): Promise<ProviderOperationIdentity> {
  const owned = requireOwnedProviderRequest(ownedValue);
  const source = requireDigestSource(digestSourceValue);
  const encoder = new TextEncoder();
  let requestBytes: Uint8Array | undefined;
  let requestDigest: Uint8Array | undefined;
  let keyBytes: Uint8Array | undefined;
  let keyDigest: Uint8Array | undefined;
  try {
    requestBytes = encoder.encode(JSON.stringify([
      "warden-provider-request",
      1,
      owned.correlationId,
      "solana:signTransaction",
      owned.requestedAccountAddress,
      owned.chain,
      owned.preflightCommitment,
      owned.minContextSlot,
      owned.transaction,
    ]));
    requestDigest = await digest(source, requestBytes);
    keyBytes = encoder.encode(JSON.stringify([
      "warden-provider-operation",
      1,
      owned.extensionId,
      owned.origin,
      owned.tabId,
      owned.frameId,
      owned.documentId,
      bytesToHex(requestDigest),
    ]));
    keyDigest = await digest(source, keyBytes);
    return snapshotProviderOperationIdentity({
      key: `${PROVIDER_OPERATION_KEY_PREFIX}${bytesToHex(keyDigest)}`,
      extensionId: owned.extensionId,
      origin: owned.origin,
      tabId: owned.tabId,
      frameId: owned.frameId,
      documentId: owned.documentId,
      correlationId: owned.correlationId,
      method: "solana:signTransaction",
      requestDigest,
    });
  } finally {
    requestBytes?.fill(0);
    requestDigest?.fill(0);
    keyBytes?.fill(0);
    keyDigest?.fill(0);
  }
}

export function createPreparingProviderOperation(input: {
  readonly identity: ProviderOperationIdentity;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly now: number;
}): ProviderOperationRecord {
  if (typeof input !== "object" || input === null) {
    stateError("creation input must be an object");
  }
  const identity = snapshotProviderOperationIdentity(identityObject(input.identity));
  const createdAt = requireSafeInteger(input.createdAt, "createdAt");
  const expiresAt = requireSafeInteger(input.expiresAt, "expiresAt");
  const now = requireSafeInteger(input.now, "now");
  try {
    if (
      expiresAt <= createdAt ||
      expiresAt - createdAt > MAX_PROVIDER_REQUEST_TTL_MS
    ) {
      stateError("operation lifetime is malformed");
    }
    if (now < createdAt) stateError("clock precedes operation creation");
    if (now >= expiresAt) stateError("operation is already expired");
    return snapshotProviderOperation({
      version: PROVIDER_OPERATION_VERSION,
      ...identityObject(identity),
      createdAt,
      expiresAt,
      state: "preparing",
      approvalId: null,
      approvalDigest: null,
      failureCode: null,
      resolvedAt: null,
    });
  } finally {
    identity.requestDigest.fill(0);
  }
}

export function bindProviderOperation(
  value: ProviderOperationRecord,
  input: {
    readonly key: string;
    readonly expectedRequestDigest: Uint8Array;
    readonly approvalId: string;
    readonly approvalDigest: Uint8Array;
    readonly now: number;
  },
): ProviderOperationRecord {
  const current = snapshotProviderOperation(value);
  const key = requireKey(input.key);
  const expectedRequestDigest = requireBytes(
    input.expectedRequestDigest,
    PROVIDER_OPERATION_DIGEST_BYTES,
    "expectedRequestDigest",
  );
  const approvalId = requireApprovalId(input.approvalId);
  const approvalDigest = requireBytes(
    input.approvalDigest,
    APPROVAL_DIGEST_BYTES,
    "approvalDigest",
  );
  const now = requireSafeInteger(input.now, "now");
  try {
    if (
      current.key !== key ||
      !bytesEqual(current.requestDigest, expectedRequestDigest)
    ) {
      stateError("operation binding identity differs from the durable claim");
    }
    if (current.state === "bound") {
      if (
        current.approvalId === approvalId &&
        current.approvalDigest !== null &&
        bytesEqual(current.approvalDigest, approvalDigest)
      ) {
        return snapshotProviderOperation(current);
      }
      stateError("operation is already bound to a different approval");
    }
    if (current.state !== "preparing") {
      stateError("failed operation cannot be bound");
    }
    if (now < current.createdAt) stateError("clock precedes operation creation");
    if (now >= current.expiresAt) stateError("operation expired before binding");
    return snapshotProviderOperation({
      ...current,
      state: "bound",
      approvalId,
      approvalDigest,
      failureCode: null,
      resolvedAt: now,
    });
  } finally {
    current.requestDigest.fill(0);
    current.approvalDigest?.fill(0);
    expectedRequestDigest.fill(0);
    approvalDigest.fill(0);
  }
}

export function failProviderOperation(
  value: ProviderOperationRecord,
  failureCodeValue: ProviderOperationFailureCode,
  nowValue: number,
): ProviderOperationRecord {
  const current = snapshotProviderOperation(value);
  const now = requireSafeInteger(nowValue, "now");
  if (
    typeof failureCodeValue !== "string" ||
    !FAILURE_CODES.has(failureCodeValue)
  ) {
    current.requestDigest.fill(0);
    current.approvalDigest?.fill(0);
    stateError("failureCode is unsupported");
  }
  try {
    if (current.state === "failed") {
      if (current.failureCode === failureCodeValue) {
        return snapshotProviderOperation(current);
      }
      stateError("operation already failed with a different code");
    }
    if (current.state !== "preparing") {
      stateError("bound operation cannot be failed");
    }
    if (now < current.createdAt) stateError("clock precedes operation creation");
    if (failureCodeValue === "expired" && now < current.expiresAt) {
      stateError("operation cannot expire before its deadline");
    }
    return snapshotProviderOperation({
      ...current,
      state: "failed",
      approvalId: null,
      approvalDigest: null,
      failureCode: failureCodeValue,
      resolvedAt: now,
    });
  } finally {
    current.requestDigest.fill(0);
    current.approvalDigest?.fill(0);
  }
}

function requireRepository(value: unknown): ProviderOperationRepository {
  if (typeof value !== "object" || value === null) {
    stateError("repository must be an object");
  }
  const repository = value as Partial<ProviderOperationRepository>;
  for (const method of [
    "claim",
    "read",
    "bind",
    "fail",
    "invalidatePreparing",
    "close",
  ] as const) {
    if (typeof repository[method] !== "function") {
      stateError(`repository must provide ${method}()`);
    }
  }
  return Object.freeze({
    claim: repository.claim!.bind(value),
    read: repository.read!.bind(value),
    bind: repository.bind!.bind(value),
    fail: repository.fail!.bind(value),
    invalidatePreparing: repository.invalidatePreparing!.bind(value),
    close: repository.close!.bind(value),
  });
}

function requireClock(value: unknown): () => number {
  if (typeof value !== "function") stateError("readNow must be a function");
  return value as () => number;
}

function requirePreparation(value: unknown): ProviderOperationPreparation {
  if (typeof value !== "object" || value === null) {
    stateError("preparation result must be an object");
  }
  const preparation = value as Partial<ProviderOperationPreparation>;
  return Object.freeze({
    id: requireApprovalId(preparation.id),
    messageDigest: requireBytes(
      preparation.messageDigest,
      APPROVAL_DIGEST_BYTES,
      "preparation messageDigest",
    ),
  });
}

function bindRequestLease(value: unknown): {
  readonly owned: OwnedProviderRequest;
  readonly assertActive: () => void;
} {
  if (typeof value !== "object" || value === null) {
    stateError("request lease must be an object");
  }
  const lease = value as Partial<ProviderOperationRequestLease>;
  if (typeof lease.owned !== "object" || lease.owned === null) {
    stateError("request lease has no owned request");
  }
  if (typeof lease.assertActive !== "function") {
    stateError("request lease must provide assertActive()");
  }
  return Object.freeze({
    owned: lease.owned as OwnedProviderRequest,
    assertActive: lease.assertActive.bind(value),
  });
}

function exactBoundRecord(
  value: unknown,
  identity: ProviderOperationIdentity,
  preparation: ProviderOperationPreparation,
): ProviderOperationRecord | null {
  if (value === null) return null;
  let record: ProviderOperationRecord | undefined;
  try {
    record = snapshotProviderOperation(value);
    if (
      record.state !== "bound" ||
      !providerOperationIdentitiesEqual(record, identity) ||
      record.approvalId !== preparation.id ||
      record.approvalDigest === null ||
      !bytesEqual(record.approvalDigest, preparation.messageDigest)
    ) {
      return null;
    }
    const result = snapshotProviderOperation(record);
    return result;
  } finally {
    record?.requestDigest.fill(0);
    record?.approvalDigest?.fill(0);
  }
}

/**
 * Owns claim-before-prepare and bind-after-prepare ordering. The callback must
 * stop after durable approval creation; opening a window or signing before this
 * method returns would violate the journal-before-action contract.
 */
export class ProviderOperationOwner {
  readonly #repository: ProviderOperationRepository;
  readonly #readNow: () => number;
  readonly #digestSource: ProviderOperationDigestSource;

  constructor(
    repositoryValue: ProviderOperationRepository,
    options: ProviderOperationOwnerOptions = {},
  ) {
    this.#repository = requireRepository(repositoryValue);
    this.#readNow = requireClock(options.readNow ?? Date.now);
    this.#digestSource = requireDigestSource(
      options.digestSource ?? DEFAULT_DIGEST_SOURCE,
    );
  }

  #currentTime(): number {
    let value: unknown;
    try {
      value = this.#readNow();
    } catch (error) {
      stateError("clock read failed", error);
    }
    return requireSafeInteger(value, "clock");
  }

  async prepare(
    leaseValue: ProviderOperationRequestLease,
    prepareValue: () => Promise<ProviderOperationPreparation>,
  ): Promise<ProviderOperationResolution> {
    const lease = bindRequestLease(leaseValue);
    if (typeof prepareValue !== "function") {
      stateError("prepare callback must be a function");
    }
    lease.assertActive();
    const identity = await deriveProviderOperationIdentity(
      lease.owned,
      this.#digestSource,
    );
    lease.assertActive();
    let claimRecord: ProviderOperationRecord | undefined;
    let preparation: ProviderOperationPreparation | undefined;
    let bound: ProviderOperationRecord | undefined;
    try {
      const claim = await this.#repository.claim({
        identity,
        createdAt: lease.owned.createdAt,
        expiresAt: lease.owned.expiresAt,
        now: this.#currentTime(),
      });
      if (
        typeof claim !== "object" ||
        claim === null ||
        typeof claim.created !== "boolean"
      ) {
        stateError("repository returned a malformed claim");
      }
      claimRecord = snapshotProviderOperation(claim.record);
      if (!providerOperationIdentitiesEqual(claimRecord, identity)) {
        stateError("durable claim identity differs from the browser request");
      }
      if (
        claim.created &&
        (claimRecord.createdAt !== lease.owned.createdAt ||
          claimRecord.expiresAt !== lease.owned.expiresAt)
      ) {
        stateError("new durable claim changed the request lifetime");
      }
      if (!claim.created) {
        if (claimRecord.state === "bound") {
          lease.assertActive();
          return Object.freeze({
            created: false,
            record: snapshotProviderOperation(claimRecord),
          });
        }
        if (claimRecord.state === "preparing") {
          stateError("operation is already being prepared or was interrupted");
        }
        stateError(`operation previously failed as ${claimRecord.failureCode}`);
      }
      if (claimRecord.state !== "preparing") {
        stateError("new durable claim is not preparing");
      }

      try {
        // A Port may disconnect while the durable claim transaction is in
        // flight. Recheck before the callback can create an approval.
        lease.assertActive();
        preparation = requirePreparation(await prepareValue());
      } catch (error) {
        const failureCode: ProviderOperationFailureCode = lease.owned.signal.aborted
          ? "request-cancelled"
          : "preparation-failed";
        try {
          const failed = await this.#repository.fail({
            key: identity.key,
            expectedRequestDigest: identity.requestDigest,
            failureCode,
            now: this.#currentTime(),
          });
          failed.requestDigest.fill(0);
          failed.approvalDigest?.fill(0);
        } catch (persistenceError) {
          stateError(
            "preparation failed and durable failure recording is unproven",
            new AggregateError([error, persistenceError]),
          );
        }
        throw error;
      }

      try {
        bound = snapshotProviderOperation(await this.#repository.bind({
          key: identity.key,
          expectedRequestDigest: identity.requestDigest,
          approvalId: preparation.id,
          approvalDigest: preparation.messageDigest,
          now: this.#currentTime(),
        }));
      } catch (error) {
        let observed: ProviderOperationRecord | null = null;
        try {
          observed = exactBoundRecord(
            await this.#repository.read({
              key: identity.key,
              now: this.#currentTime(),
            }),
            identity,
            preparation,
          );
        } catch {
          // The bind error below remains authoritative; no second preparation
          // is allowed while the durable claim is uncertain.
        }
        if (observed === null) {
          stateError("durable approval binding is unproven", error);
        }
        bound = observed;
      }
      if (
        !providerOperationIdentitiesEqual(bound, identity) ||
        bound.state !== "bound" ||
        bound.approvalId !== preparation.id ||
        bound.approvalDigest === null ||
        !bytesEqual(bound.approvalDigest, preparation.messageDigest)
      ) {
        stateError("repository bound a different provider operation");
      }

      // A disconnect here cannot erase the durable mapping. The caller may
      // cancel the exact approval, and a retry will observe that same row.
      lease.assertActive();
      return Object.freeze({
        created: true,
        record: snapshotProviderOperation(bound),
      });
    } finally {
      // Once the callback returned an approval locator, no later failure path
      // rewrites an uncertain mapping as generic failure: the row may already
      // be durably bound and must remain the sole replay locator.
      identity.requestDigest.fill(0);
      claimRecord?.requestDigest.fill(0);
      claimRecord?.approvalDigest?.fill(0);
      preparation?.messageDigest.fill(0);
      bound?.requestDigest.fill(0);
      bound?.approvalDigest?.fill(0);
    }
  }

  invalidateAfterWorkerRestart(): Promise<number> {
    return this.#repository.invalidatePreparing(this.#currentTime());
  }

  close(): void {
    this.#repository.close();
  }
}
