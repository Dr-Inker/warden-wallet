//! Browser-safe C3 approval record domain. The record binds only trusted,
//! background-resolved fields; it deliberately contains no UI labels, route
//! parameters, simulation verdicts, RPC response, or page-selected authority.
//!
//! Byte arrays are always copy-owned. JavaScript cannot freeze a non-empty
//! Uint8Array, so callers receive isolated buffers rather than a false claim of
//! element immutability. Persistent owners must snapshot again at every trust
//! boundary and verify the digest before a terminal transition.

import { sha256 } from "@noble/hashes/sha2.js";

import { MAX_TX_BYTES } from "../constants.js";

export const APPROVAL_RECORD_VERSION = 1 as const;
export const APPROVAL_DIGEST_BYTES = 32;
export const APPROVAL_AUTHORITY_BYTES = 32;
export const APPROVAL_MAX_TTL_MS = 10 * 60 * 1_000;

const MAX_ORIGIN_CHARACTERS = 2_048;
const MAX_DOCUMENT_ID_CHARACTERS = 256;
const APPROVAL_ID_PATTERN = /^req_[0-9a-f]{32}$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;

export type ApprovalMethod =
  | "solana:signTransaction"
  | "solana:signAndSendTransaction";

export type ApprovalChain =
  | "solana:mainnet"
  | "solana:devnet"
  | "solana:testnet"
  | "solana:localnet";

export type ApprovalTerminalState =
  | "approved"
  | "rejected"
  | "cancelled"
  | "expired"
  | "invalidated";

export type ApprovalState = "pending" | ApprovalTerminalState;

export interface ApprovalCreateParams {
  /** Background-minted 128-bit identity; never a page correlation id. */
  readonly id: string;
  /** Browser-owned canonical HTTP(S) origin. */
  readonly origin: string;
  readonly tabId: number;
  readonly frameId: number;
  /** Browser-owned document identity for the originating Port. */
  readonly documentId: string;
  /** Authoritatively resolved SmartAccount public key. */
  readonly account: Uint8Array;
  readonly method: ApprovalMethod;
  /** Explicit resolved chain; nullable page selectors never reach this record. */
  readonly chain: ApprovalChain;
  readonly genesisHash: Uint8Array;
  readonly programId: Uint8Array;
  /** Exact serialized transaction/message bytes that a future signer may consume. */
  readonly rawMessage: Uint8Array;
  readonly policyVersion: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface ApprovalRecord extends ApprovalCreateParams {
  readonly version: typeof APPROVAL_RECORD_VERSION;
  readonly messageDigest: Uint8Array;
  readonly state: ApprovalState;
  readonly resolvedAt: number | null;
}

export class ApprovalRecordFormatError extends Error {
  constructor(message: string) {
    super(`approval record: ${message}`);
    this.name = "ApprovalRecordFormatError";
  }
}

const RECORD_FIELDS = [
  "account",
  "chain",
  "createdAt",
  "documentId",
  "expiresAt",
  "frameId",
  "genesisHash",
  "id",
  "messageDigest",
  "method",
  "origin",
  "policyVersion",
  "programId",
  "rawMessage",
  "resolvedAt",
  "state",
  "tabId",
  "version",
] as const;

const METHODS: ReadonlySet<string> = new Set([
  "solana:signTransaction",
  "solana:signAndSendTransaction",
]);
const CHAINS: ReadonlySet<string> = new Set([
  "solana:mainnet",
  "solana:devnet",
  "solana:testnet",
  "solana:localnet",
]);
const STATES: ReadonlySet<string> = new Set([
  "pending",
  "approved",
  "rejected",
  "cancelled",
  "expired",
  "invalidated",
]);

function invalid(message: string): never {
  throw new ApprovalRecordFormatError(message);
}

function requireRecord(value: unknown): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    value instanceof Uint8Array
  ) {
    invalid("value must be an object");
  }
  const record = value as Record<string, unknown>;
  const fields = Object.keys(record).sort();
  if (
    fields.length !== RECORD_FIELDS.length ||
    fields.some((field, index) => field !== RECORD_FIELDS[index])
  ) {
    invalid("value has missing or unknown fields");
  }
  return record;
}

function requireSafeNonNegativeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    invalid(`${name} must be a non-negative safe integer`);
  }
  return value as number;
}

function requireBytes(value: unknown, length: number, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    invalid(`${name} must contain exactly ${length} bytes`);
  }
  return value.slice();
}

function requireRawMessage(value: unknown): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    value.length === 0 ||
    value.length > MAX_TX_BYTES
  ) {
    invalid(`rawMessage must contain 1 to ${MAX_TX_BYTES} bytes`);
  }
  return value.slice();
}

function requireOrigin(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_ORIGIN_CHARACTERS ||
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
    invalid("origin must be a canonical HTTP(S) origin");
  }
  return value;
}

function requireDocumentId(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_DOCUMENT_ID_CHARACTERS ||
    CONTROL_CHARACTER_PATTERN.test(value)
  ) {
    invalid("documentId is malformed");
  }
  return value;
}

function requireId(value: unknown): string {
  if (typeof value !== "string" || !APPROVAL_ID_PATTERN.test(value)) {
    invalid("id must be a background-minted 128-bit request id");
  }
  return value;
}

function requireMethod(value: unknown): ApprovalMethod {
  if (typeof value !== "string" || !METHODS.has(value)) {
    invalid("method is unsupported");
  }
  return value as ApprovalMethod;
}

function requireChain(value: unknown): ApprovalChain {
  if (typeof value !== "string" || !CHAINS.has(value)) {
    invalid("chain is unsupported");
  }
  return value as ApprovalChain;
}

function requireState(value: unknown): ApprovalState {
  if (typeof value !== "string" || !STATES.has(value)) {
    invalid("state is unsupported");
  }
  return value as ApprovalState;
}

/** Synchronous so an IndexedDB read-modify-write transaction can recheck it. */
export function digestApprovalMessage(rawMessage: Uint8Array): Uint8Array {
  const owned = requireRawMessage(rawMessage);
  try {
    return sha256(owned);
  } finally {
    owned.fill(0);
  }
}

export function approvalDigestsEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (
    !(left instanceof Uint8Array) ||
    !(right instanceof Uint8Array) ||
    left.length !== APPROVAL_DIGEST_BYTES ||
    right.length !== APPROVAL_DIGEST_BYTES
  ) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < APPROVAL_DIGEST_BYTES; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

/** Strictly validate, integrity-check, and copy-own a stored approval record. */
export function snapshotApprovalRecord(value: unknown): ApprovalRecord {
  const record = requireRecord(value);
  if (record.version !== APPROVAL_RECORD_VERSION) {
    invalid(`version must be ${APPROVAL_RECORD_VERSION}`);
  }
  const id = requireId(record.id);
  const origin = requireOrigin(record.origin);
  const tabId = requireSafeNonNegativeInteger(record.tabId, "tabId");
  const frameId = requireSafeNonNegativeInteger(record.frameId, "frameId");
  const documentId = requireDocumentId(record.documentId);
  const account = requireBytes(
    record.account,
    APPROVAL_AUTHORITY_BYTES,
    "account",
  );
  const method = requireMethod(record.method);
  const chain = requireChain(record.chain);
  const genesisHash = requireBytes(
    record.genesisHash,
    APPROVAL_AUTHORITY_BYTES,
    "genesisHash",
  );
  const programId = requireBytes(
    record.programId,
    APPROVAL_AUTHORITY_BYTES,
    "programId",
  );
  const rawMessage = requireRawMessage(record.rawMessage);
  const messageDigest = requireBytes(
    record.messageDigest,
    APPROVAL_DIGEST_BYTES,
    "messageDigest",
  );
  const policyVersion = requireSafeNonNegativeInteger(
    record.policyVersion,
    "policyVersion",
  );
  const createdAt = requireSafeNonNegativeInteger(record.createdAt, "createdAt");
  const expiresAt = requireSafeNonNegativeInteger(record.expiresAt, "expiresAt");
  if (
    expiresAt <= createdAt ||
    expiresAt - createdAt > APPROVAL_MAX_TTL_MS
  ) {
    invalid(`expiresAt must be within ${APPROVAL_MAX_TTL_MS}ms of createdAt`);
  }
  const state = requireState(record.state);
  let resolvedAt: number | null;
  if (state === "pending") {
    if (record.resolvedAt !== null) invalid("pending record must not have resolvedAt");
    resolvedAt = null;
  } else {
    resolvedAt = requireSafeNonNegativeInteger(record.resolvedAt, "resolvedAt");
    if (resolvedAt < createdAt) invalid("resolvedAt precedes createdAt");
    if (state === "expired") {
      if (resolvedAt < expiresAt) invalid("expired record resolved before expiry");
    } else if (resolvedAt >= expiresAt) {
      invalid("non-expiry terminal state resolved at or after expiry");
    }
  }

  const computedDigest = sha256(rawMessage);
  const digestMatches = approvalDigestsEqual(messageDigest, computedDigest);
  computedDigest.fill(0);
  if (!digestMatches) {
    account.fill(0);
    genesisHash.fill(0);
    programId.fill(0);
    rawMessage.fill(0);
    messageDigest.fill(0);
    invalid("messageDigest does not authenticate rawMessage");
  }

  return Object.freeze({
    version: APPROVAL_RECORD_VERSION,
    id,
    origin,
    tabId,
    frameId,
    documentId,
    account,
    method,
    chain,
    genesisHash,
    programId,
    rawMessage,
    messageDigest,
    policyVersion,
    createdAt,
    expiresAt,
    state,
    resolvedAt,
  });
}

export function createPendingApprovalRecord(
  params: ApprovalCreateParams,
): ApprovalRecord {
  if (typeof params !== "object" || params === null) {
    invalid("creation parameters must be an object");
  }
  const rawMessage = params.rawMessage instanceof Uint8Array
    ? params.rawMessage.slice()
    : params.rawMessage;
  const messageDigest = rawMessage instanceof Uint8Array
    ? digestApprovalMessage(rawMessage)
    : new Uint8Array(0);
  try {
    return snapshotApprovalRecord({
      version: APPROVAL_RECORD_VERSION,
      id: params.id,
      origin: params.origin,
      tabId: params.tabId,
      frameId: params.frameId,
      documentId: params.documentId,
      account: params.account,
      method: params.method,
      chain: params.chain,
      genesisHash: params.genesisHash,
      programId: params.programId,
      rawMessage,
      messageDigest,
      policyVersion: params.policyVersion,
      createdAt: params.createdAt,
      expiresAt: params.expiresAt,
      state: "pending",
      resolvedAt: null,
    });
  } finally {
    if (rawMessage instanceof Uint8Array) rawMessage.fill(0);
    messageDigest.fill(0);
  }
}

export function resolveApprovalRecord(
  value: ApprovalRecord,
  state: ApprovalTerminalState,
  resolvedAt: number,
): ApprovalRecord {
  if (!STATES.has(state)) {
    invalid("terminal state is unsupported");
  }
  const current = snapshotApprovalRecord(value);
  try {
    if (current.state !== "pending") {
      invalid("record has already reached a terminal state");
    }
    return snapshotApprovalRecord({
      ...current,
      state,
      resolvedAt,
    });
  } finally {
    current.account.fill(0);
    current.genesisHash.fill(0);
    current.programId.fill(0);
    current.rawMessage.fill(0);
    current.messageDigest.fill(0);
  }
}
