//! Durable, browser-safe ownership for one approval signing attempt.
//!
//! The approval record remains the human decision and exact-message binding.
//! This separate record says whether an attempt is currently owned, completed
//! with exact signed bytes, or failed with a closed machine-readable reason.
//! An attempt id is a CAS token: an older worker may not complete or fail a
//! newer retry. No raw exception text is persisted.

import { sha256 } from "@noble/hashes/sha2.js";

import { MAX_TX_BYTES } from "../constants.js";
import {
  APPROVAL_DIGEST_BYTES,
  approvalDigestsEqual,
  snapshotApprovalRecord,
  type ApprovalRecord,
} from "./record.js";

export const APPROVAL_SIGNING_OUTCOME_VERSION = 1 as const;
export const APPROVAL_SIGNING_ATTEMPT_ID_BYTES = 16;

const APPROVAL_ID_PATTERN = /^req_[0-9a-f]{32}$/;
const ATTEMPT_ID_PATTERN = /^attempt_[0-9a-f]{32}$/;
const U32_MAX = 0xffff_ffff;

export type ApprovalSigningOutcomeState = "signing" | "signed" | "failed";

export type ApprovalSigningFailureCode =
  | "approval-record-mismatch"
  | "authority-check-failed"
  | "blockhash-invalid"
  | "blockhash-unavailable"
  | "coordinator-disposed"
  | "intent-blocked"
  | "keyring-context-mismatch"
  | "signed-result-invalid"
  | "signing-failed"
  | "worker-restarted";

export interface ApprovalSigningAttemptParams {
  readonly id: string;
  readonly messageDigest: Uint8Array;
  /** Background-minted 128-bit CAS token for exactly this attempt. */
  readonly attemptId: string;
  readonly attemptNumber: number;
  readonly startedAt: number;
}

export interface ApprovalSigningOutcome extends ApprovalSigningAttemptParams {
  readonly version: typeof APPROVAL_SIGNING_OUTCOME_VERSION;
  readonly state: ApprovalSigningOutcomeState;
  readonly resolvedAt: number | null;
  readonly transactionBytes: Uint8Array | null;
  readonly transactionDigest: Uint8Array | null;
  readonly failureCode: ApprovalSigningFailureCode | null;
}

export interface ApprovalSigningRecord {
  readonly approval: ApprovalRecord;
  readonly outcome: ApprovalSigningOutcome;
}

export class ApprovalSigningOutcomeFormatError extends Error {
  constructor(message: string) {
    super(`approval signing outcome: ${message}`);
    this.name = "ApprovalSigningOutcomeFormatError";
  }
}

const OUTCOME_FIELDS = [
  "attemptId",
  "attemptNumber",
  "failureCode",
  "id",
  "messageDigest",
  "resolvedAt",
  "startedAt",
  "state",
  "transactionBytes",
  "transactionDigest",
  "version",
] as const;

const FAILURE_CODES: ReadonlySet<string> = new Set([
  "approval-record-mismatch",
  "authority-check-failed",
  "blockhash-invalid",
  "blockhash-unavailable",
  "coordinator-disposed",
  "intent-blocked",
  "keyring-context-mismatch",
  "signed-result-invalid",
  "signing-failed",
  "worker-restarted",
]);

function invalid(message: string): never {
  throw new ApprovalSigningOutcomeFormatError(message);
}

function exactDataRecord(
  value: unknown,
  fields: readonly string[],
  label: string,
): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    value instanceof Uint8Array
  ) {
    invalid(`${label} must be an object`);
  }
  let keys: readonly PropertyKey[];
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    keys = Reflect.ownKeys(value);
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    invalid(`${label} shape could not be inspected`);
  }
  if (prototype !== Object.prototype && prototype !== null) {
    invalid(`${label} must have a plain or null prototype`);
  }
  const stringKeys = keys.filter((key): key is string => typeof key === "string").sort();
  if (
    stringKeys.length !== keys.length ||
    stringKeys.length !== fields.length ||
    stringKeys.some((field, index) => field !== fields[index])
  ) {
    invalid(`${label} has missing, unknown, or symbolic fields`);
  }
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (descriptor === undefined || !("value" in descriptor)) {
      invalid(`${label}.${field} must be an own data property`);
    }
    snapshot[field] = descriptor.value;
  }
  return snapshot;
}

function requireSafeNonNegativeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    invalid(`${name} must be a non-negative safe integer`);
  }
  return value as number;
}

function requireAttemptNumber(value: unknown): number {
  const attemptNumber = requireSafeNonNegativeInteger(value, "attemptNumber");
  if (attemptNumber === 0 || attemptNumber > U32_MAX) {
    invalid("attemptNumber must be between 1 and u32::MAX");
  }
  return attemptNumber;
}

function requireId(value: unknown): string {
  if (typeof value !== "string" || !APPROVAL_ID_PATTERN.test(value)) {
    invalid("id must be a background-minted 128-bit request id");
  }
  return value;
}

function requireAttemptId(value: unknown): string {
  if (typeof value !== "string" || !ATTEMPT_ID_PATTERN.test(value)) {
    invalid("attemptId must be a background-minted 128-bit attempt id");
  }
  return value;
}

function requireDigest(value: unknown, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== APPROVAL_DIGEST_BYTES) {
    invalid(`${name} must contain exactly ${APPROVAL_DIGEST_BYTES} bytes`);
  }
  return value.slice();
}

function requireTransaction(value: unknown): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    value.length === 0 ||
    value.length > MAX_TX_BYTES
  ) {
    invalid(`transactionBytes must contain 1 to ${MAX_TX_BYTES} bytes`);
  }
  return value.slice();
}

function requireState(value: unknown): ApprovalSigningOutcomeState {
  if (value !== "signing" && value !== "signed" && value !== "failed") {
    invalid("state is unsupported");
  }
  return value;
}

function requireFailureCode(value: unknown): ApprovalSigningFailureCode {
  if (typeof value !== "string" || !FAILURE_CODES.has(value)) {
    invalid("failureCode is unsupported");
  }
  return value as ApprovalSigningFailureCode;
}

/** Validate an untrusted failure code before any persistence transaction starts. */
export function parseApprovalSigningFailureCode(
  value: unknown,
): ApprovalSigningFailureCode {
  return requireFailureCode(value);
}

function clearOutcome(value: ApprovalSigningOutcome | undefined): void {
  value?.messageDigest.fill(0);
  value?.transactionBytes?.fill(0);
  value?.transactionDigest?.fill(0);
}

function clearApproval(value: ApprovalRecord | undefined): void {
  value?.account.fill(0);
  value?.genesisHash.fill(0);
  value?.programId.fill(0);
  value?.rawMessage.fill(0);
  value?.messageDigest.fill(0);
}

/** Strictly validate, integrity-check, and copy-own a persisted outcome. */
export function snapshotApprovalSigningOutcome(
  value: unknown,
): ApprovalSigningOutcome {
  const record = exactDataRecord(value, OUTCOME_FIELDS, "value");
  if (record.version !== APPROVAL_SIGNING_OUTCOME_VERSION) {
    invalid(`version must be ${APPROVAL_SIGNING_OUTCOME_VERSION}`);
  }
  const id = requireId(record.id);
  const messageDigest = requireDigest(record.messageDigest, "messageDigest");
  const attemptId = requireAttemptId(record.attemptId);
  const attemptNumber = requireAttemptNumber(record.attemptNumber);
  const state = requireState(record.state);
  const startedAt = requireSafeNonNegativeInteger(record.startedAt, "startedAt");

  let resolvedAt: number | null;
  let transactionBytes: Uint8Array | null;
  let transactionDigest: Uint8Array | null;
  let failureCode: ApprovalSigningFailureCode | null;
  if (state === "signing") {
    if (
      record.resolvedAt !== null ||
      record.transactionBytes !== null ||
      record.transactionDigest !== null ||
      record.failureCode !== null
    ) {
      messageDigest.fill(0);
      invalid("signing state must not carry a resolution");
    }
    resolvedAt = null;
    transactionBytes = null;
    transactionDigest = null;
    failureCode = null;
  } else {
    resolvedAt = requireSafeNonNegativeInteger(record.resolvedAt, "resolvedAt");
    if (resolvedAt < startedAt) {
      messageDigest.fill(0);
      invalid("resolvedAt precedes startedAt");
    }
    if (state === "signed") {
      if (record.failureCode !== null) {
        messageDigest.fill(0);
        invalid("signed state must not carry failureCode");
      }
      transactionBytes = requireTransaction(record.transactionBytes);
      transactionDigest = requireDigest(
        record.transactionDigest,
        "transactionDigest",
      );
      const computedDigest = sha256(transactionBytes);
      const digestMatches = approvalDigestsEqual(
        transactionDigest,
        computedDigest,
      );
      computedDigest.fill(0);
      if (!digestMatches) {
        messageDigest.fill(0);
        transactionBytes.fill(0);
        transactionDigest.fill(0);
        invalid("transactionDigest does not authenticate transactionBytes");
      }
      failureCode = null;
    } else {
      if (record.transactionBytes !== null || record.transactionDigest !== null) {
        messageDigest.fill(0);
        invalid("failed state must not carry transaction bytes");
      }
      transactionBytes = null;
      transactionDigest = null;
      failureCode = requireFailureCode(record.failureCode);
    }
  }

  return Object.freeze({
    version: APPROVAL_SIGNING_OUTCOME_VERSION,
    id,
    messageDigest,
    attemptId,
    attemptNumber,
    state,
    startedAt,
    resolvedAt,
    transactionBytes,
    transactionDigest,
    failureCode,
  });
}

/** Validate and copy-own the atomic approval/outcome pair returned by storage. */
export function snapshotApprovalSigningRecord(
  value: unknown,
): ApprovalSigningRecord {
  const record = exactDataRecord(value, ["approval", "outcome"], "signing record");
  let approval: ApprovalRecord | undefined;
  let outcome: ApprovalSigningOutcome | undefined;
  try {
    approval = snapshotApprovalRecord(record.approval);
    outcome = snapshotApprovalSigningOutcome(record.outcome);
    if (
      approval.state !== "approved" ||
      approval.resolvedAt === null ||
      approval.id !== outcome.id ||
      !approvalDigestsEqual(approval.messageDigest, outcome.messageDigest) ||
      outcome.startedAt < approval.resolvedAt
    ) {
      invalid("approval and outcome do not describe one exact claimed binding");
    }
    return Object.freeze({
      approval: snapshotApprovalRecord(approval),
      outcome: snapshotApprovalSigningOutcome(outcome),
    });
  } finally {
    clearApproval(approval);
    clearOutcome(outcome);
  }
}

export function createApprovalSigningAttempt(
  paramsValue: ApprovalSigningAttemptParams,
): ApprovalSigningOutcome {
  const params = exactDataRecord(
    paramsValue,
    ["attemptId", "attemptNumber", "id", "messageDigest", "startedAt"],
    "creation parameters",
  );
  return snapshotApprovalSigningOutcome({
    version: APPROVAL_SIGNING_OUTCOME_VERSION,
    id: params.id,
    messageDigest: params.messageDigest,
    attemptId: params.attemptId,
    attemptNumber: params.attemptNumber,
    state: "signing",
    startedAt: params.startedAt,
    resolvedAt: null,
    transactionBytes: null,
    transactionDigest: null,
    failureCode: null,
  });
}

export function completeApprovalSigningAttempt(
  value: ApprovalSigningOutcome,
  transactionValue: Uint8Array,
  resolvedAtValue: number,
): ApprovalSigningOutcome {
  const current = snapshotApprovalSigningOutcome(value);
  let transactionBytes: Uint8Array | undefined;
  let transactionDigest: Uint8Array | undefined;
  try {
    if (current.state !== "signing") {
      invalid("only a signing attempt can be completed");
    }
    const resolvedAt = requireSafeNonNegativeInteger(resolvedAtValue, "resolvedAt");
    if (resolvedAt < current.startedAt) invalid("resolvedAt precedes startedAt");
    transactionBytes = requireTransaction(transactionValue);
    transactionDigest = sha256(transactionBytes);
    return snapshotApprovalSigningOutcome({
      ...current,
      state: "signed",
      resolvedAt,
      transactionBytes,
      transactionDigest,
      failureCode: null,
    });
  } finally {
    clearOutcome(current);
    transactionBytes?.fill(0);
    transactionDigest?.fill(0);
  }
}

export function failApprovalSigningAttempt(
  value: ApprovalSigningOutcome,
  failureCodeValue: ApprovalSigningFailureCode,
  resolvedAtValue: number,
): ApprovalSigningOutcome {
  const current = snapshotApprovalSigningOutcome(value);
  try {
    if (current.state !== "signing") {
      invalid("only a signing attempt can fail");
    }
    const failureCode = requireFailureCode(failureCodeValue);
    const resolvedAt = requireSafeNonNegativeInteger(resolvedAtValue, "resolvedAt");
    if (resolvedAt < current.startedAt) invalid("resolvedAt precedes startedAt");
    return snapshotApprovalSigningOutcome({
      ...current,
      state: "failed",
      resolvedAt,
      transactionBytes: null,
      transactionDigest: null,
      failureCode,
    });
  } finally {
    clearOutcome(current);
  }
}

export function retryApprovalSigningAttempt(
  value: ApprovalSigningOutcome,
  attemptIdValue: string,
  startedAtValue: number,
): ApprovalSigningOutcome {
  const current = snapshotApprovalSigningOutcome(value);
  try {
    if (current.state !== "failed" || current.resolvedAt === null) {
      invalid("only a failed attempt can be retried");
    }
    if (current.attemptNumber === U32_MAX) invalid("attemptNumber is exhausted");
    const attemptId = requireAttemptId(attemptIdValue);
    if (attemptId === current.attemptId) invalid("retry must use a fresh attemptId");
    const startedAt = requireSafeNonNegativeInteger(startedAtValue, "startedAt");
    if (startedAt < current.resolvedAt) {
      invalid("retry startedAt precedes the prior resolution");
    }
    return createApprovalSigningAttempt({
      id: current.id,
      messageDigest: current.messageDigest,
      attemptId,
      attemptNumber: current.attemptNumber + 1,
      startedAt,
    });
  } finally {
    clearOutcome(current);
  }
}
