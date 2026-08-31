//! Still-unreachable C3 session approval orchestration domain.
//!
//! This module deliberately owns ordering, not transport. It has no provider
//! route, approval page, RPC implementation, account registry, semantic
//! decoder, sender, or result store. Those capabilities are injected so the
//! only successful path is mechanically forced through: authoritative state,
//! one final blockhash, exact-message construction, a synchronous local intent
//! verdict, immutable approval creation, current-state revalidation, atomic
//! digest claim, AAD-contextual key use, exact blockhash validity, one last
//! state/verdict check, and exact-byte signing.

import { ed25519 } from "@noble/curves/ed25519.js";
import { PublicKey } from "@solana/web3.js";

import {
  APPROVAL_DIGEST_BYTES,
  APPROVAL_MAX_TTL_MS,
  approvalDigestsEqual,
  digestApprovalMessage,
  snapshotApprovalRecord,
  type ApprovalChain,
  type ApprovalCreateParams,
  type ApprovalRecord,
} from "../approval/record.js";
import { MAX_TX_BYTES } from "../constants.js";
import { parseSerializedTransactionEnvelope } from "./envelope.js";
import {
  prepareSessionTransaction,
  signApprovedSessionMessage,
} from "./session-transaction.js";

export const SESSION_APPROVAL_COMMITMENT = "confirmed" as const;
export const SESSION_APPROVAL_DEFAULT_TTL_MS = 60_000;
export const SESSION_APPROVAL_MAX_ACTIVE = 32;

const MAX_AUTHORIZATION_STATE_BYTES = 64 * 1_024;
const U32_MAX = 0xffff_ffff;
const U64_MAX = 0xffff_ffff_ffff_ffffn;
const APPROVAL_ID_PATTERN = /^req_[0-9a-f]{32}$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;
const CHAINS: ReadonlySet<string> = new Set([
  "solana:mainnet",
  "solana:devnet",
  "solana:testnet",
  "solana:localnet",
]);

export type SessionApprovalCoordinatorErrorCode =
  | "INVALID_DEPENDENCY"
  | "INVALID_REQUEST"
  | "UNSUPPORTED_METHOD"
  | "CAPACITY_EXCEEDED"
  | "DISPOSED"
  | "AUTHORITY_UNAVAILABLE"
  | "AUTHORITY_INVALID"
  | "AUTHORITY_CHANGED"
  | "BLOCKHASH_UNAVAILABLE"
  | "BLOCKHASH_INVALID"
  | "INTENT_BLOCKED"
  | "APPROVAL_CREATE_FAILED"
  | "APPROVAL_NOT_ACTIVE"
  | "APPROVAL_RECORD_MISMATCH"
  | "APPROVAL_DIGEST_MISMATCH"
  | "APPROVAL_CLAIM_FAILED"
  | "APPROVAL_RESOLUTION_FAILED"
  | "KEYRING_CONTEXT_MISMATCH"
  | "SIGNING_FAILED"
  | "SIGNED_RESULT_INVALID";

export class SessionApprovalCoordinatorError extends Error {
  readonly code: SessionApprovalCoordinatorErrorCode;

  constructor(
    code: SessionApprovalCoordinatorErrorCode,
    message: string,
    options: ErrorOptions = {},
  ) {
    super(`session approval coordinator: ${message}`, options);
    this.name = "SessionApprovalCoordinatorError";
    this.code = code;
  }
}

export interface SessionApprovalRequest {
  /** Browser-owned canonical HTTP(S) origin. */
  readonly origin: string;
  readonly tabId: number;
  readonly frameId: number;
  /** Browser-owned document identity for the live provider Port. */
  readonly documentId: string;
  /** Untrusted selector; the resolver must prove it is currently selectable. */
  readonly requestedAccount: Uint8Array;
  readonly method: "solana:signTransaction";
  readonly chain: ApprovalChain;
  /** Incoming unsigned dApp transaction, not the eventual approval object. */
  readonly sourceTransactionBytes: Uint8Array;
}

export interface SessionAuthoritySelection {
  readonly account: Uint8Array;
  readonly chain: ApprovalChain;
}

/**
 * One canonical observation of every input that can affect authorization.
 *
 * `authorizationState` is a deterministic, canonical encoding of the complete
 * account/session/registry state used by the resolver and local intent gate.
 * It must change when any authority-bearing byte changes. The coordinator
 * compares it exactly at every observation; a hash or lossy summary supplied by
 * an RPC server is not an acceptable implementation of this contract.
 */
export interface SessionAuthoritySnapshot {
  readonly chain: ApprovalChain;
  readonly genesisHash: Uint8Array;
  readonly smartAccount: PublicKey;
  readonly sessionSigner: PublicKey;
  readonly sessionAccount: PublicKey;
  readonly registry: PublicKey;
  readonly wardenProgram: PublicKey;
  /** Canonical Upgradeable Loader ProgramData PDA for `wardenProgram`. */
  readonly wardenProgramData: PublicKey;
  /** Loader-recorded deployment/upgrade slot, pinned by the resolver. */
  readonly wardenProgramDataSlot: bigint;
  /** Exact pinned ProgramData upgrade authority. */
  readonly wardenUpgradeAuthority: PublicKey;
  /** Release artifact hash over the deployed code region. */
  readonly wardenCodeHash: Uint8Array;
  /** Full raw ProgramData account hash, including metadata and allocation. */
  readonly wardenProgramDataHash: Uint8Array;
  readonly accountGeneration: bigint;
  readonly policyVersion: number;
  readonly authorizationState: Uint8Array;
  /** Clock sysvar `unix_timestamp` from the same bank snapshot as the accounts. */
  readonly observedUnixTimestamp: number;
  readonly contextSlot: number;
}

export interface SessionApprovalAuthorityResolver {
  resolve(input: {
    readonly selection: SessionAuthoritySelection;
    readonly commitment: typeof SESSION_APPROVAL_COMMITMENT;
    readonly minContextSlot: number;
  }): Promise<SessionAuthoritySnapshot>;
}

export interface SessionApprovalBlockhashClient {
  getLatestBlockhash(input: {
    readonly chain: ApprovalChain;
    readonly genesisHash: Uint8Array;
    readonly commitment: typeof SESSION_APPROVAL_COMMITMENT;
    readonly minContextSlot: number;
  }): Promise<{
    readonly blockhash: Uint8Array;
    readonly lastValidBlockHeight: number;
    readonly contextSlot: number;
  }>;

  isBlockhashValid(input: {
    readonly chain: ApprovalChain;
    readonly genesisHash: Uint8Array;
    readonly blockhash: Uint8Array;
    readonly commitment: typeof SESSION_APPROVAL_COMMITMENT;
    readonly minContextSlot: number;
  }): Promise<{
    readonly valid: boolean;
    readonly contextSlot: number;
  }>;
}

/**
 * Privileged, deterministic local decoder/policy gate. It must return
 * synchronously and return no value; throw to block. The coordinator supplies
 * isolated exact-message and authority copies and repeats the verdict at the
 * final no-await-before-sign boundary.
 */
export interface SessionApprovalIntentGate {
  assertAllowed(input: {
    readonly messageBytes: Uint8Array;
    readonly authority: SessionAuthoritySnapshot;
  }): void;
}

/** Structural subset implemented by the extension's transactional owner. */
export interface SessionApprovalOwner {
  create(params: ApprovalCreateParams): Promise<ApprovalRecord>;
  read(id: string): Promise<ApprovalRecord | null>;
  claimForSigning(id: string, expectedDigest: Uint8Array): Promise<ApprovalRecord>;
  reject(id: string): Promise<ApprovalRecord>;
  cancel(id: string): Promise<ApprovalRecord>;
}

export interface SessionApprovalSignerLease {
  readonly account: Uint8Array;
  readonly genesisHash: Uint8Array;
  readonly programId: Uint8Array;
  readonly seed: Uint8Array;
}

/** Structural subset implemented by the extension's keyring lifecycle owner. */
export interface SessionApprovalKeyring {
  useSessionSignerBytes(
    operation: string,
    use: (lease: SessionApprovalSignerLease) => Promise<Uint8Array>,
  ): Promise<Uint8Array>;
}

export interface PreparedSessionApproval {
  readonly id: string;
  readonly messageDigest: Uint8Array;
  readonly account: Uint8Array;
  readonly chain: ApprovalChain;
  readonly blockhash: Uint8Array;
  readonly lastValidBlockHeight: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface SignedSessionApproval {
  readonly id: string;
  readonly messageDigest: Uint8Array;
  readonly transactionBytes: Uint8Array;
  readonly signature: Uint8Array;
}

interface CoordinatorDependencies {
  readonly authority: SessionApprovalAuthorityResolver;
  readonly blockhash: SessionApprovalBlockhashClient;
  readonly intent: SessionApprovalIntentGate;
  readonly approvals: SessionApprovalOwner;
  readonly keyring: SessionApprovalKeyring;
}

interface CoordinatorOptions {
  readonly readNow?: () => number;
  readonly approvalTtlMs?: number;
}

interface SnapshotRequest {
  readonly origin: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly requestedAccount: Uint8Array;
  readonly method: "solana:signTransaction";
  readonly chain: ApprovalChain;
  readonly sourceTransactionBytes: Uint8Array;
}

interface BlockhashSnapshot {
  readonly blockhash: Uint8Array;
  readonly lastValidBlockHeight: number;
  readonly contextSlot: number;
}

interface ValiditySnapshot {
  readonly valid: boolean;
  readonly contextSlot: number;
}

interface ApprovalCapsule {
  readonly approval: ApprovalRecord;
  readonly selection: SessionAuthoritySelection;
  readonly authority: SessionAuthoritySnapshot;
  readonly blockhash: BlockhashSnapshot;
}

class PreparedSessionApprovalValue implements PreparedSessionApproval {
  readonly id: string;
  readonly chain: ApprovalChain;
  readonly lastValidBlockHeight: number;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly #messageDigest: Uint8Array;
  readonly #account: Uint8Array;
  readonly #blockhash: Uint8Array;

  constructor(capsule: ApprovalCapsule) {
    this.id = capsule.approval.id;
    this.chain = capsule.approval.chain;
    this.lastValidBlockHeight = capsule.blockhash.lastValidBlockHeight;
    this.createdAt = capsule.approval.createdAt;
    this.expiresAt = capsule.approval.expiresAt;
    this.#messageDigest = capsule.approval.messageDigest.slice();
    this.#account = capsule.approval.account.slice();
    this.#blockhash = capsule.blockhash.blockhash.slice();
    Object.freeze(this);
  }

  get messageDigest(): Uint8Array {
    return this.#messageDigest.slice();
  }

  get account(): Uint8Array {
    return this.#account.slice();
  }

  get blockhash(): Uint8Array {
    return this.#blockhash.slice();
  }
}

class SignedSessionApprovalValue implements SignedSessionApproval {
  readonly id: string;
  readonly #messageDigest: Uint8Array;
  readonly #transactionBytes: Uint8Array;
  readonly #signature: Uint8Array;

  constructor(
    id: string,
    messageDigest: Uint8Array,
    transactionBytes: Uint8Array,
    signature: Uint8Array,
  ) {
    this.id = id;
    this.#messageDigest = messageDigest.slice();
    this.#transactionBytes = transactionBytes.slice();
    this.#signature = signature.slice();
    Object.freeze(this);
  }

  get messageDigest(): Uint8Array {
    return this.#messageDigest.slice();
  }

  get transactionBytes(): Uint8Array {
    return this.#transactionBytes.slice();
  }

  get signature(): Uint8Array {
    return this.#signature.slice();
  }
}

function fail(
  code: SessionApprovalCoordinatorErrorCode,
  message: string,
  cause?: unknown,
): never {
  throw new SessionApprovalCoordinatorError(
    code,
    message,
    cause === undefined ? {} : { cause },
  );
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function allZero(value: Uint8Array): boolean {
  let combined = 0;
  for (const byte of value) combined |= byte;
  return combined === 0;
}

function requireObject(
  value: unknown,
  code: SessionApprovalCoordinatorErrorCode,
  name: string,
): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    value instanceof Uint8Array
  ) {
    fail(code, `${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireBytes(
  value: unknown,
  length: number,
  name: string,
  code: SessionApprovalCoordinatorErrorCode,
): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(code, `${name} must contain exactly ${length} bytes`);
  }
  return value.slice();
}

function requireBoundedBytes(
  value: unknown,
  minimum: number,
  maximum: number,
  name: string,
  code: SessionApprovalCoordinatorErrorCode,
): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    value.length < minimum ||
    value.length > maximum
  ) {
    fail(code, `${name} must contain ${minimum} to ${maximum} bytes`);
  }
  return value.slice();
}

function requireSafeNonNegativeInteger(
  value: unknown,
  name: string,
  code: SessionApprovalCoordinatorErrorCode,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    fail(code, `${name} must be a non-negative safe integer`);
  }
  return value as number;
}

function requireU32(
  value: unknown,
  name: string,
  code: SessionApprovalCoordinatorErrorCode,
): number {
  const integer = requireSafeNonNegativeInteger(value, name, code);
  if (integer > U32_MAX) fail(code, `${name} exceeds u32`);
  return integer;
}

function requireU64Bigint(
  value: unknown,
  name: string,
  code: SessionApprovalCoordinatorErrorCode,
): bigint {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX) {
    fail(code, `${name} must be a u64 bigint`);
  }
  return value;
}

function requirePublicKey(
  value: unknown,
  name: string,
  code: SessionApprovalCoordinatorErrorCode,
): PublicKey {
  if (!(value instanceof PublicKey)) fail(code, `${name} must be a PublicKey`);
  try {
    return new PublicKey(value.toBytes());
  } catch (error) {
    fail(code, `${name} could not be copied`, error);
  }
}

function requireChain(
  value: unknown,
  name: string,
  code: SessionApprovalCoordinatorErrorCode,
): ApprovalChain {
  if (typeof value !== "string" || !CHAINS.has(value)) {
    fail(code, `${name} is unsupported`);
  }
  return value as ApprovalChain;
}

function snapshotRequest(value: unknown): SnapshotRequest {
  const request = requireObject(value, "INVALID_REQUEST", "request");
  if (typeof request.origin !== "string") {
    fail("INVALID_REQUEST", "origin must be a string");
  }
  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(request.origin);
  } catch (error) {
    fail("INVALID_REQUEST", "origin is malformed", error);
  }
  if (
    request.origin.length === 0 ||
    request.origin.length > 2_048 ||
    CONTROL_CHARACTER_PATTERN.test(request.origin) ||
    (parsedOrigin.protocol !== "https:" && parsedOrigin.protocol !== "http:") ||
    parsedOrigin.origin !== request.origin ||
    parsedOrigin.username !== "" ||
    parsedOrigin.password !== ""
  ) {
    fail("INVALID_REQUEST", "origin must be a canonical HTTP(S) origin");
  }
  const tabId = requireSafeNonNegativeInteger(
    request.tabId,
    "tabId",
    "INVALID_REQUEST",
  );
  const frameId = requireSafeNonNegativeInteger(
    request.frameId,
    "frameId",
    "INVALID_REQUEST",
  );
  if (
    typeof request.documentId !== "string" ||
    request.documentId.length === 0 ||
    request.documentId.length > 256 ||
    CONTROL_CHARACTER_PATTERN.test(request.documentId)
  ) {
    fail("INVALID_REQUEST", "documentId is malformed");
  }
  const requestedAccount = requireBytes(
    request.requestedAccount,
    32,
    "requestedAccount",
    "INVALID_REQUEST",
  );
  if (request.method !== "solana:signTransaction") {
    requestedAccount.fill(0);
    fail(
      "UNSUPPORTED_METHOD",
      "only solana:signTransaction is supported; sign-and-send needs durable result ownership",
    );
  }
  const chain = requireChain(request.chain, "chain", "INVALID_REQUEST");
  const sourceTransactionBytes = requireBoundedBytes(
    request.sourceTransactionBytes,
    1,
    MAX_TX_BYTES,
    "sourceTransactionBytes",
    "INVALID_REQUEST",
  );
  return Object.freeze({
    origin: request.origin,
    tabId,
    frameId,
    documentId: request.documentId,
    requestedAccount,
    method: "solana:signTransaction" as const,
    chain,
    sourceTransactionBytes,
  });
}

function clearRequest(request: SnapshotRequest | undefined): void {
  request?.requestedAccount.fill(0);
  request?.sourceTransactionBytes.fill(0);
}

function snapshotSelection(
  account: Uint8Array,
  chain: ApprovalChain,
): SessionAuthoritySelection {
  return Object.freeze({ account: account.slice(), chain });
}

function clearSelection(selection: SessionAuthoritySelection | undefined): void {
  selection?.account.fill(0);
}

function snapshotAuthority(
  value: unknown,
  selection: SessionAuthoritySelection,
  minimumContextSlot: number,
): SessionAuthoritySnapshot {
  const authority = requireObject(value, "AUTHORITY_INVALID", "authority response");
  const chain = requireChain(authority.chain, "authority chain", "AUTHORITY_INVALID");
  const genesisHash = requireBytes(
    authority.genesisHash,
    32,
    "authority genesisHash",
    "AUTHORITY_INVALID",
  );
  const smartAccount = requirePublicKey(
    authority.smartAccount,
    "authority smartAccount",
    "AUTHORITY_INVALID",
  );
  const sessionSigner = requirePublicKey(
    authority.sessionSigner,
    "authority sessionSigner",
    "AUTHORITY_INVALID",
  );
  const sessionAccount = requirePublicKey(
    authority.sessionAccount,
    "authority sessionAccount",
    "AUTHORITY_INVALID",
  );
  const registry = requirePublicKey(
    authority.registry,
    "authority registry",
    "AUTHORITY_INVALID",
  );
  const wardenProgram = requirePublicKey(
    authority.wardenProgram,
    "authority wardenProgram",
    "AUTHORITY_INVALID",
  );
  const wardenProgramData = requirePublicKey(
    authority.wardenProgramData,
    "authority wardenProgramData",
    "AUTHORITY_INVALID",
  );
  const wardenProgramDataSlot = requireU64Bigint(
    authority.wardenProgramDataSlot,
    "authority wardenProgramDataSlot",
    "AUTHORITY_INVALID",
  );
  const wardenUpgradeAuthority = requirePublicKey(
    authority.wardenUpgradeAuthority,
    "authority wardenUpgradeAuthority",
    "AUTHORITY_INVALID",
  );
  const wardenCodeHash = requireBytes(
    authority.wardenCodeHash,
    32,
    "authority wardenCodeHash",
    "AUTHORITY_INVALID",
  );
  const wardenProgramDataHash = requireBytes(
    authority.wardenProgramDataHash,
    32,
    "authority wardenProgramDataHash",
    "AUTHORITY_INVALID",
  );
  const accountGeneration = requireU64Bigint(
    authority.accountGeneration,
    "authority accountGeneration",
    "AUTHORITY_INVALID",
  );
  const policyVersion = requireU32(
    authority.policyVersion,
    "authority policyVersion",
    "AUTHORITY_INVALID",
  );
  const authorizationState = requireBoundedBytes(
    authority.authorizationState,
    1,
    MAX_AUTHORIZATION_STATE_BYTES,
    "authority authorizationState",
    "AUTHORITY_INVALID",
  );
  const observedUnixTimestamp = requireSafeNonNegativeInteger(
    authority.observedUnixTimestamp,
    "authority observedUnixTimestamp",
    "AUTHORITY_INVALID",
  );
  const contextSlot = requireSafeNonNegativeInteger(
    authority.contextSlot,
    "authority contextSlot",
    "AUTHORITY_INVALID",
  );
  if (contextSlot < minimumContextSlot) {
    genesisHash.fill(0);
    wardenCodeHash.fill(0);
    wardenProgramDataHash.fill(0);
    authorizationState.fill(0);
    fail("AUTHORITY_INVALID", "authority context regressed below minContextSlot");
  }
  if (
    chain !== selection.chain ||
    !bytesEqual(smartAccount.toBytes(), selection.account)
  ) {
    genesisHash.fill(0);
    wardenCodeHash.fill(0);
    wardenProgramDataHash.fill(0);
    authorizationState.fill(0);
    fail("AUTHORITY_INVALID", "authority did not resolve the requested selection");
  }
  if (allZero(genesisHash)) {
    genesisHash.fill(0);
    wardenCodeHash.fill(0);
    wardenProgramDataHash.fill(0);
    authorizationState.fill(0);
    fail("AUTHORITY_INVALID", "authority genesisHash must not be all zero");
  }
  if (allZero(wardenCodeHash) || allZero(wardenProgramDataHash)) {
    genesisHash.fill(0);
    wardenCodeHash.fill(0);
    wardenProgramDataHash.fill(0);
    authorizationState.fill(0);
    fail("AUTHORITY_INVALID", "authority program identity hashes must not be all zero");
  }
  return Object.freeze({
    chain,
    genesisHash,
    smartAccount,
    sessionSigner,
    sessionAccount,
    registry,
    wardenProgram,
    wardenProgramData,
    wardenProgramDataSlot,
    wardenUpgradeAuthority,
    wardenCodeHash,
    wardenProgramDataHash,
    accountGeneration,
    policyVersion,
    authorizationState,
    observedUnixTimestamp,
    contextSlot,
  });
}

function cloneAuthority(value: SessionAuthoritySnapshot): SessionAuthoritySnapshot {
  return Object.freeze({
    chain: value.chain,
    genesisHash: value.genesisHash.slice(),
    smartAccount: new PublicKey(value.smartAccount.toBytes()),
    sessionSigner: new PublicKey(value.sessionSigner.toBytes()),
    sessionAccount: new PublicKey(value.sessionAccount.toBytes()),
    registry: new PublicKey(value.registry.toBytes()),
    wardenProgram: new PublicKey(value.wardenProgram.toBytes()),
    wardenProgramData: new PublicKey(value.wardenProgramData.toBytes()),
    wardenProgramDataSlot: value.wardenProgramDataSlot,
    wardenUpgradeAuthority: new PublicKey(value.wardenUpgradeAuthority.toBytes()),
    wardenCodeHash: value.wardenCodeHash.slice(),
    wardenProgramDataHash: value.wardenProgramDataHash.slice(),
    accountGeneration: value.accountGeneration,
    policyVersion: value.policyVersion,
    authorizationState: value.authorizationState.slice(),
    observedUnixTimestamp: value.observedUnixTimestamp,
    contextSlot: value.contextSlot,
  });
}

function clearAuthority(value: SessionAuthoritySnapshot | undefined): void {
  value?.genesisHash.fill(0);
  value?.wardenCodeHash.fill(0);
  value?.wardenProgramDataHash.fill(0);
  value?.authorizationState.fill(0);
}

function authoritiesEqual(
  expected: SessionAuthoritySnapshot,
  actual: SessionAuthoritySnapshot,
): boolean {
  return (
    expected.chain === actual.chain &&
    bytesEqual(expected.genesisHash, actual.genesisHash) &&
    expected.smartAccount.equals(actual.smartAccount) &&
    expected.sessionSigner.equals(actual.sessionSigner) &&
    expected.sessionAccount.equals(actual.sessionAccount) &&
    expected.registry.equals(actual.registry) &&
    expected.wardenProgram.equals(actual.wardenProgram) &&
    expected.wardenProgramData.equals(actual.wardenProgramData) &&
    expected.wardenProgramDataSlot === actual.wardenProgramDataSlot &&
    expected.wardenUpgradeAuthority.equals(actual.wardenUpgradeAuthority) &&
    bytesEqual(expected.wardenCodeHash, actual.wardenCodeHash) &&
    bytesEqual(expected.wardenProgramDataHash, actual.wardenProgramDataHash) &&
    expected.accountGeneration === actual.accountGeneration &&
    expected.policyVersion === actual.policyVersion &&
    bytesEqual(expected.authorizationState, actual.authorizationState)
  );
}

function assertAuthorityUnchanged(
  expected: SessionAuthoritySnapshot,
  actual: SessionAuthoritySnapshot,
): void {
  if (!authoritiesEqual(expected, actual)) {
    fail("AUTHORITY_CHANGED", "authoritative account/session/registry state changed");
  }
  if (actual.observedUnixTimestamp < expected.observedUnixTimestamp) {
    fail("AUTHORITY_CHANGED", "authoritative Clock timestamp regressed");
  }
}

function snapshotLatestBlockhash(
  value: unknown,
  minimumContextSlot: number,
): BlockhashSnapshot {
  const response = requireObject(
    value,
    "BLOCKHASH_INVALID",
    "latest blockhash response",
  );
  const blockhash = requireBytes(
    response.blockhash,
    32,
    "latest blockhash",
    "BLOCKHASH_INVALID",
  );
  const lastValidBlockHeight = requireSafeNonNegativeInteger(
    response.lastValidBlockHeight,
    "lastValidBlockHeight",
    "BLOCKHASH_INVALID",
  );
  const contextSlot = requireSafeNonNegativeInteger(
    response.contextSlot,
    "latest blockhash contextSlot",
    "BLOCKHASH_INVALID",
  );
  if (contextSlot < minimumContextSlot || allZero(blockhash)) {
    blockhash.fill(0);
    fail(
      "BLOCKHASH_INVALID",
      contextSlot < minimumContextSlot
        ? "latest blockhash context regressed below minContextSlot"
        : "latest blockhash must not be all zero",
    );
  }
  return Object.freeze({ blockhash, lastValidBlockHeight, contextSlot });
}

function snapshotValidity(
  value: unknown,
  minimumContextSlot: number,
): ValiditySnapshot {
  const response = requireObject(
    value,
    "BLOCKHASH_INVALID",
    "blockhash validity response",
  );
  if (typeof response.valid !== "boolean") {
    fail("BLOCKHASH_INVALID", "blockhash validity must be boolean");
  }
  const contextSlot = requireSafeNonNegativeInteger(
    response.contextSlot,
    "blockhash validity contextSlot",
    "BLOCKHASH_INVALID",
  );
  if (contextSlot < minimumContextSlot) {
    fail("BLOCKHASH_INVALID", "blockhash validity context regressed below minContextSlot");
  }
  return Object.freeze({ valid: response.valid, contextSlot });
}

function clearBlockhash(value: BlockhashSnapshot | undefined): void {
  value?.blockhash.fill(0);
}

function recordBindingEqual(left: ApprovalRecord, right: ApprovalRecord): boolean {
  return (
    left.version === right.version &&
    left.id === right.id &&
    left.origin === right.origin &&
    left.tabId === right.tabId &&
    left.frameId === right.frameId &&
    left.documentId === right.documentId &&
    bytesEqual(left.account, right.account) &&
    left.method === right.method &&
    left.chain === right.chain &&
    bytesEqual(left.genesisHash, right.genesisHash) &&
    bytesEqual(left.programId, right.programId) &&
    bytesEqual(left.rawMessage, right.rawMessage) &&
    approvalDigestsEqual(left.messageDigest, right.messageDigest) &&
    left.policyVersion === right.policyVersion &&
    left.createdAt === right.createdAt &&
    left.expiresAt === right.expiresAt
  );
}

function clearApproval(record: ApprovalRecord | undefined): void {
  record?.account.fill(0);
  record?.genesisHash.fill(0);
  record?.programId.fill(0);
  record?.rawMessage.fill(0);
  record?.messageDigest.fill(0);
}

function snapshotOwnerRecord(
  value: unknown,
  code: SessionApprovalCoordinatorErrorCode,
  label: string,
): ApprovalRecord {
  try {
    return snapshotApprovalRecord(value);
  } catch (error) {
    fail(code, `${label} is malformed`, error);
  }
}

function clearCapsule(capsule: ApprovalCapsule | undefined): void {
  if (capsule === undefined) return;
  clearApproval(capsule.approval);
  clearSelection(capsule.selection);
  clearAuthority(capsule.authority);
  clearBlockhash(capsule.blockhash);
}

function requireApprovalId(value: unknown): string {
  if (typeof value !== "string" || !APPROVAL_ID_PATTERN.test(value)) {
    fail("APPROVAL_NOT_ACTIVE", "approval id is malformed or inactive");
  }
  return value;
}

function requireExpectedDigest(value: unknown): Uint8Array {
  return requireBytes(
    value,
    APPROVAL_DIGEST_BYTES,
    "expected approval digest",
    "APPROVAL_DIGEST_MISMATCH",
  );
}

function mintApprovalId(): string {
  const bytes = new Uint8Array(16);
  try {
    const cryptoObject = globalThis.crypto;
    if (
      typeof cryptoObject !== "object" ||
      cryptoObject === null ||
      typeof cryptoObject.getRandomValues !== "function"
    ) {
      fail("APPROVAL_CREATE_FAILED", "cryptographic request-id generation is unavailable");
    }
    cryptoObject.getRandomValues(bytes);
    let hex = "";
    for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
    return `req_${hex}`;
  } catch (error) {
    if (error instanceof SessionApprovalCoordinatorError) throw error;
    fail("APPROVAL_CREATE_FAILED", "cryptographic request-id generation failed", error);
  } finally {
    bytes.fill(0);
  }
}

function requireDependencies(value: unknown): CoordinatorDependencies {
  const dependencies = requireObject(
    value,
    "INVALID_DEPENDENCY",
    "dependencies",
  );
  const requirements = {
    authority: ["resolve"],
    blockhash: ["getLatestBlockhash", "isBlockhashValid"],
    intent: ["assertAllowed"],
    approvals: ["create", "read", "claimForSigning", "reject", "cancel"],
    keyring: ["useSessionSignerBytes"],
  } as const;
  for (const [owner, methods] of Object.entries(requirements)) {
    const dependency = dependencies[owner];
    if (typeof dependency !== "object" || dependency === null) {
      fail("INVALID_DEPENDENCY", `${owner} dependency must be an object`);
    }
    for (const method of methods) {
      if (typeof (dependency as Record<string, unknown>)[method] !== "function") {
        fail("INVALID_DEPENDENCY", `${owner} dependency must provide ${method}()`);
      }
    }
  }
  return value as CoordinatorDependencies;
}

/**
 * Internal coordinator. Constructing this class adds no route; a future
 * extension composition must still supply real authoritative resolver, local
 * decoder, RPC, approval UI/owner, and contextual keyring implementations.
 */
export class SessionApprovalCoordinator {
  readonly #authority: SessionApprovalAuthorityResolver;
  readonly #blockhash: SessionApprovalBlockhashClient;
  readonly #intent: SessionApprovalIntentGate;
  readonly #approvals: SessionApprovalOwner;
  readonly #keyring: SessionApprovalKeyring;
  readonly #readNow: () => number;
  readonly #approvalTtlMs: number;
  readonly #capsules = new Map<string, ApprovalCapsule>();
  readonly #activeSigning = new Set<string>();
  #activePreparations = 0;
  #disposed = false;

  constructor(
    dependenciesValue: CoordinatorDependencies,
    options: CoordinatorOptions = {},
  ) {
    const dependencies = requireDependencies(dependenciesValue);
    if (options.readNow !== undefined && typeof options.readNow !== "function") {
      fail("INVALID_DEPENDENCY", "readNow must be a function");
    }
    const approvalTtlMs = options.approvalTtlMs ?? SESSION_APPROVAL_DEFAULT_TTL_MS;
    if (
      !Number.isSafeInteger(approvalTtlMs) ||
      approvalTtlMs <= 0 ||
      approvalTtlMs > APPROVAL_MAX_TTL_MS
    ) {
      fail(
        "INVALID_DEPENDENCY",
        `approvalTtlMs must be between 1 and ${APPROVAL_MAX_TTL_MS}`,
      );
    }
    this.#authority = dependencies.authority;
    this.#blockhash = dependencies.blockhash;
    this.#intent = dependencies.intent;
    this.#approvals = dependencies.approvals;
    this.#keyring = dependencies.keyring;
    this.#readNow = options.readNow ?? Date.now;
    this.#approvalTtlMs = approvalTtlMs;
  }

  #assertUsable(): void {
    if (this.#disposed) fail("DISPOSED", "coordinator is disposed");
  }

  #currentTime(): number {
    let now: unknown;
    try {
      now = this.#readNow();
    } catch (error) {
      fail("APPROVAL_CREATE_FAILED", "clock read failed", error);
    }
    return requireSafeNonNegativeInteger(
      now,
      "clock",
      "APPROVAL_CREATE_FAILED",
    );
  }

  async #pruneInactiveCapsules(): Promise<void> {
    for (const [id, capsule] of [...this.#capsules]) {
      let record: ApprovalRecord | null;
      try {
        record = await this.#approvals.read(id);
      } catch {
        // A transient storage error cannot justify discarding an approval's
        // sole in-memory authority capsule. Capacity fails closed instead.
        continue;
      }
      if (this.#capsules.get(id) !== capsule) {
        clearApproval(record ?? undefined);
        continue;
      }
      let current: ApprovalRecord | undefined;
      try {
        current = record === null
          ? undefined
          : snapshotOwnerRecord(record, "APPROVAL_RECORD_MISMATCH", "stored approval");
        if (
          current === undefined ||
          current.state !== "pending" ||
          !recordBindingEqual(current, capsule.approval)
        ) {
          this.#capsules.delete(id);
          clearCapsule(capsule);
        }
      } catch {
        this.#capsules.delete(id);
        clearCapsule(capsule);
      } finally {
        clearApproval(current);
        clearApproval(record ?? undefined);
      }
    }
  }

  async #resolveAuthority(
    selection: SessionAuthoritySelection,
    minimumContextSlot: number,
  ): Promise<SessionAuthoritySnapshot> {
    const inputSelection = snapshotSelection(selection.account, selection.chain);
    let response: SessionAuthoritySnapshot;
    try {
      response = await this.#authority.resolve({
        selection: inputSelection,
        commitment: SESSION_APPROVAL_COMMITMENT,
        minContextSlot: minimumContextSlot,
      });
    } catch (error) {
      if (error instanceof SessionApprovalCoordinatorError) throw error;
      fail("AUTHORITY_UNAVAILABLE", "authority resolution failed", error);
    } finally {
      clearSelection(inputSelection);
    }
    return snapshotAuthority(response, selection, minimumContextSlot);
  }

  async #latestBlockhash(
    authority: SessionAuthoritySnapshot,
  ): Promise<BlockhashSnapshot> {
    const genesisHash = authority.genesisHash.slice();
    let response: Awaited<ReturnType<SessionApprovalBlockhashClient["getLatestBlockhash"]>>;
    try {
      response = await this.#blockhash.getLatestBlockhash({
        chain: authority.chain,
        genesisHash,
        commitment: SESSION_APPROVAL_COMMITMENT,
        minContextSlot: authority.contextSlot,
      });
    } catch (error) {
      if (error instanceof SessionApprovalCoordinatorError) throw error;
      fail("BLOCKHASH_UNAVAILABLE", "latest blockhash request failed", error);
    } finally {
      genesisHash.fill(0);
    }
    return snapshotLatestBlockhash(response, authority.contextSlot);
  }

  async #blockhashValidity(
    authority: SessionAuthoritySnapshot,
    blockhash: BlockhashSnapshot,
  ): Promise<ValiditySnapshot> {
    const genesisHash = authority.genesisHash.slice();
    const blockhashBytes = blockhash.blockhash.slice();
    let response: Awaited<ReturnType<SessionApprovalBlockhashClient["isBlockhashValid"]>>;
    try {
      response = await this.#blockhash.isBlockhashValid({
        chain: authority.chain,
        genesisHash,
        blockhash: blockhashBytes,
        commitment: SESSION_APPROVAL_COMMITMENT,
        minContextSlot: authority.contextSlot,
      });
    } catch (error) {
      if (error instanceof SessionApprovalCoordinatorError) throw error;
      fail("BLOCKHASH_UNAVAILABLE", "blockhash validity request failed", error);
    } finally {
      genesisHash.fill(0);
      blockhashBytes.fill(0);
    }
    return snapshotValidity(response, authority.contextSlot);
  }

  #assertIntentAllowed(
    messageValue: Uint8Array,
    authorityValue: SessionAuthoritySnapshot,
  ): void {
    const messageBytes = messageValue.slice();
    const authority = cloneAuthority(authorityValue);
    try {
      let result: unknown;
      try {
        result = (this.#intent.assertAllowed as (input: {
          readonly messageBytes: Uint8Array;
          readonly authority: SessionAuthoritySnapshot;
        }) => unknown)({ messageBytes, authority });
      } catch (error) {
        fail("INTENT_BLOCKED", "local intent decoder or policy gate blocked", error);
      }
      if (result !== undefined) {
        if (result instanceof Promise) void result.catch(() => undefined);
        fail(
          "INTENT_BLOCKED",
          "local intent gate must complete synchronously and return no value",
        );
      }
    } finally {
      messageBytes.fill(0);
      clearAuthority(authority);
    }
  }

  async prepare(requestValue: SessionApprovalRequest): Promise<PreparedSessionApproval> {
    this.#assertUsable();
    const request = snapshotRequest(requestValue);
    let selection: SessionAuthoritySelection | undefined;
    let initialAuthority: SessionAuthoritySnapshot | undefined;
    let currentAuthority: SessionAuthoritySnapshot | undefined;
    let latest: BlockhashSnapshot | undefined;
    let messageBytes: Uint8Array | undefined;
    let created: ApprovalRecord | undefined;
    let stored = false;
    let reserved = false;

    try {
      await this.#pruneInactiveCapsules();
      this.#assertUsable();
      if (
        this.#capsules.size +
          this.#activeSigning.size +
          this.#activePreparations >=
        SESSION_APPROVAL_MAX_ACTIVE
      ) {
        fail("CAPACITY_EXCEEDED", "too many active session approvals");
      }
      this.#activePreparations++;
      reserved = true;

      selection = snapshotSelection(request.requestedAccount, request.chain);
      initialAuthority = await this.#resolveAuthority(selection, 0);
      this.#assertUsable();
      latest = await this.#latestBlockhash(initialAuthority);
      this.#assertUsable();
      currentAuthority = await this.#resolveAuthority(
        selection,
        latest.contextSlot,
      );
      this.#assertUsable();
      assertAuthorityUnchanged(initialAuthority, currentAuthority);

      const prepared = prepareSessionTransaction(request.sourceTransactionBytes, {
        smartAccount: currentAuthority.smartAccount,
        sessionSigner: currentAuthority.sessionSigner,
        sessionAccount: currentAuthority.sessionAccount,
        registry: currentAuthority.registry,
        wardenProgram: currentAuthority.wardenProgram,
        recentBlockhash: latest.blockhash,
      });
      messageBytes = prepared.messageBytes;
      this.#assertIntentAllowed(messageBytes, currentAuthority);
      this.#assertUsable();

      const createdAt = this.#currentTime();
      const expiresAt = createdAt + this.#approvalTtlMs;
      if (!Number.isSafeInteger(expiresAt)) {
        fail("APPROVAL_CREATE_FAILED", "approval expiry exceeds safe integer range");
      }
      const params: ApprovalCreateParams = {
        id: mintApprovalId(),
        origin: request.origin,
        tabId: request.tabId,
        frameId: request.frameId,
        documentId: request.documentId,
        account: currentAuthority.smartAccount.toBytes(),
        method: request.method,
        chain: currentAuthority.chain,
        genesisHash: currentAuthority.genesisHash,
        programId: currentAuthority.wardenProgram.toBytes(),
        rawMessage: messageBytes,
        policyVersion: currentAuthority.policyVersion,
        createdAt,
        expiresAt,
      };
      let ownerCreated: ApprovalRecord;
      try {
        ownerCreated = await this.#approvals.create(params);
      } catch (error) {
        fail("APPROVAL_CREATE_FAILED", "approval owner refused creation", error);
      }
      created = snapshotOwnerRecord(
        ownerCreated,
        "APPROVAL_RECORD_MISMATCH",
        "created approval",
      );
      clearApproval(ownerCreated);
      if (
        created.state !== "pending" ||
        created.resolvedAt !== null ||
        created.id !== params.id ||
        created.origin !== params.origin ||
        created.tabId !== params.tabId ||
        created.frameId !== params.frameId ||
        created.documentId !== params.documentId ||
        !bytesEqual(created.account, params.account) ||
        created.method !== params.method ||
        created.chain !== params.chain ||
        !bytesEqual(created.genesisHash, params.genesisHash) ||
        !bytesEqual(created.programId, params.programId) ||
        !bytesEqual(created.rawMessage, params.rawMessage) ||
        created.policyVersion !== params.policyVersion ||
        created.createdAt !== params.createdAt ||
        created.expiresAt !== params.expiresAt
      ) {
        fail(
          "APPROVAL_RECORD_MISMATCH",
          "approval owner changed the exact prepared binding",
        );
      }
      this.#assertUsable();

      const capsule: ApprovalCapsule = Object.freeze({
        approval: snapshotApprovalRecord(created),
        selection: snapshotSelection(selection.account, selection.chain),
        authority: cloneAuthority(currentAuthority),
        blockhash: Object.freeze({
          blockhash: latest.blockhash.slice(),
          lastValidBlockHeight: latest.lastValidBlockHeight,
          contextSlot: latest.contextSlot,
        }),
      });
      if (this.#capsules.has(created.id)) {
        clearCapsule(capsule);
        fail("APPROVAL_CREATE_FAILED", "approval id collision escaped persistence");
      }
      this.#capsules.set(created.id, capsule);
      stored = true;
      return new PreparedSessionApprovalValue(capsule);
    } catch (error) {
      if (created !== undefined && !stored) {
        try {
          await this.#approvals.cancel(created.id);
        } catch (cleanupError) {
          if (error instanceof SessionApprovalCoordinatorError) {
            throw new SessionApprovalCoordinatorError(error.code, error.message.replace(
              "session approval coordinator: ",
              "",
            ), {
              cause: new AggregateError(
                [error, cleanupError],
                "approval preparation failed and cancellation also failed",
              ),
            });
          }
          throw new AggregateError(
            [error, cleanupError],
            "approval preparation failed and cancellation also failed",
          );
        }
      }
      throw error;
    } finally {
      if (reserved) this.#activePreparations--;
      clearRequest(request);
      clearSelection(selection);
      clearAuthority(initialAuthority);
      clearAuthority(currentAuthority);
      clearBlockhash(latest);
      messageBytes?.fill(0);
      clearApproval(created);
    }
  }

  async #cancelAfterPreclaimFailure(
    id: string,
    error: unknown,
  ): Promise<never> {
    try {
      const cancelled = await this.#approvals.cancel(id);
      clearApproval(cancelled);
    } catch (cleanupError) {
      if (error instanceof SessionApprovalCoordinatorError) {
        throw new SessionApprovalCoordinatorError(
          error.code,
          error.message.replace("session approval coordinator: ", ""),
          {
            cause: new AggregateError(
              [error, cleanupError],
              "approval failed before claim and cancellation also failed",
            ),
          },
        );
      }
      fail(
        "APPROVAL_RESOLUTION_FAILED",
        "approval failed before claim and cancellation also failed",
        new AggregateError([error, cleanupError]),
      );
    }
    throw error;
  }

  async approve(
    idValue: string,
    expectedDigestValue: Uint8Array,
  ): Promise<SignedSessionApproval> {
    this.#assertUsable();
    const id = requireApprovalId(idValue);
    const expectedDigest = requireExpectedDigest(expectedDigestValue);
    const capsule = this.#capsules.get(id);
    if (capsule === undefined || this.#activeSigning.has(id)) {
      expectedDigest.fill(0);
      fail("APPROVAL_NOT_ACTIVE", "approval has no active worker-owned capsule");
    }
    this.#capsules.delete(id);
    this.#activeSigning.add(id);

    let pending: ApprovalRecord | undefined;
    let preclaimAuthority: SessionAuthoritySnapshot | undefined;
    let claimed: ApprovalRecord | undefined;
    let postclaimAuthority: SessionAuthoritySnapshot | undefined;
    let postValidityAuthority: SessionAuthoritySnapshot | undefined;
    let signedBytes: Uint8Array | undefined;
    let shouldCancelPending = false;
    let claimStarted = false;
    try {
      let ownerRecord: ApprovalRecord | null;
      try {
        ownerRecord = await this.#approvals.read(id);
      } catch (error) {
        fail("APPROVAL_RECORD_MISMATCH", "approval read failed", error);
      }
      if (ownerRecord === null) {
        fail("APPROVAL_NOT_ACTIVE", "approval record is absent");
      }
      pending = snapshotOwnerRecord(
        ownerRecord,
        "APPROVAL_RECORD_MISMATCH",
        "pending approval",
      );
      clearApproval(ownerRecord);
      if (
        pending.state !== "pending" ||
        pending.resolvedAt !== null ||
        !recordBindingEqual(pending, capsule.approval)
      ) {
        fail(
          "APPROVAL_RECORD_MISMATCH",
          "stored approval no longer matches the worker-owned exact binding",
        );
      }
      shouldCancelPending = true;

      if (!approvalDigestsEqual(expectedDigest, pending.messageDigest)) {
        claimStarted = true;
        shouldCancelPending = false;
        try {
          const unexpected = await this.#approvals.claimForSigning(id, expectedDigest);
          clearApproval(unexpected);
        } catch (error) {
          fail(
            "APPROVAL_DIGEST_MISMATCH",
            "UI digest did not match and the atomic claim invalidated the attempt",
            error,
          );
        }
        fail(
          "APPROVAL_DIGEST_MISMATCH",
          "approval owner accepted a mismatched UI digest",
        );
      }

      preclaimAuthority = await this.#resolveAuthority(
        capsule.selection,
        Math.max(capsule.authority.contextSlot, capsule.blockhash.contextSlot),
      );
      this.#assertUsable();
      assertAuthorityUnchanged(capsule.authority, preclaimAuthority);
      this.#assertIntentAllowed(pending.rawMessage, preclaimAuthority);
      this.#assertUsable();

      claimStarted = true;
      shouldCancelPending = false;
      let ownerClaimed: ApprovalRecord;
      try {
        ownerClaimed = await this.#approvals.claimForSigning(
          id,
          pending.messageDigest,
        );
      } catch (error) {
        fail("APPROVAL_CLAIM_FAILED", "atomic approval claim failed", error);
      }
      claimed = snapshotOwnerRecord(
        ownerClaimed,
        "APPROVAL_RECORD_MISMATCH",
        "claimed approval",
      );
      clearApproval(ownerClaimed);
      if (
        claimed.state !== "approved" ||
        claimed.resolvedAt === null ||
        !recordBindingEqual(claimed, pending)
      ) {
        fail(
          "APPROVAL_RECORD_MISMATCH",
          "atomic claim changed or failed to approve the exact binding",
        );
      }

      // Do network-bound validity work before borrowing plaintext key bytes.
      // A final monotonic authority observation still occurs inside the lease,
      // immediately before the synchronous decoder/signing boundary.
      postclaimAuthority = await this.#resolveAuthority(
        capsule.selection,
        preclaimAuthority.contextSlot,
      );
      this.#assertUsable();
      assertAuthorityUnchanged(preclaimAuthority, postclaimAuthority);
      const validity = await this.#blockhashValidity(
        postclaimAuthority,
        capsule.blockhash,
      );
      this.#assertUsable();
      if (!validity.valid) {
        fail(
          "BLOCKHASH_INVALID",
          "the exact approved blockhash is no longer valid",
        );
      }
      postValidityAuthority = await this.#resolveAuthority(
        capsule.selection,
        validity.contextSlot,
      );
      this.#assertUsable();
      assertAuthorityUnchanged(postclaimAuthority, postValidityAuthority);
      this.#assertIntentAllowed(claimed.rawMessage, postValidityAuthority);
      this.#assertUsable();

      try {
        signedBytes = await this.#keyring.useSessionSignerBytes(
          "sign approved session transaction",
          async (leaseValue) => {
            const lease = requireObject(
              leaseValue,
              "KEYRING_CONTEXT_MISMATCH",
              "session signer lease",
            );
            const leaseAccount = requireBytes(
              lease.account,
              32,
              "lease account",
              "KEYRING_CONTEXT_MISMATCH",
            );
            const leaseGenesis = requireBytes(
              lease.genesisHash,
              32,
              "lease genesisHash",
              "KEYRING_CONTEXT_MISMATCH",
            );
            const leaseProgram = requireBytes(
              lease.programId,
              32,
              "lease programId",
              "KEYRING_CONTEXT_MISMATCH",
            );
            try {
              if (
                !bytesEqual(leaseAccount, claimed!.account) ||
                !bytesEqual(leaseGenesis, claimed!.genesisHash) ||
                !bytesEqual(leaseProgram, claimed!.programId)
              ) {
                fail(
                  "KEYRING_CONTEXT_MISMATCH",
                  "leased keyring account/genesis/program does not match the claimed approval",
                );
              }
            } finally {
              leaseAccount.fill(0);
              leaseGenesis.fill(0);
              leaseProgram.fill(0);
            }

            if (!(lease.seed instanceof Uint8Array) || lease.seed.length !== 32) {
              fail(
                "KEYRING_CONTEXT_MISMATCH",
                "leased session signer seed must contain exactly 32 bytes",
              );
            }

            let finalAuthority: SessionAuthoritySnapshot | undefined;
            try {
              finalAuthority = await this.#resolveAuthority(
                capsule.selection,
                postValidityAuthority!.contextSlot,
              );
              this.#assertUsable();
              assertAuthorityUnchanged(postValidityAuthority!, finalAuthority);
              this.#assertIntentAllowed(claimed!.rawMessage, finalAuthority);
              this.#assertUsable();

              // No suspension is permitted between this final state/verdict
              // observation and exact-message signing.
              const signed = signApprovedSessionMessage(
                claimed!.rawMessage,
                lease.seed,
              );
              if (
                !bytesEqual(signed.messageBytes, claimed!.rawMessage) ||
                !bytesEqual(signed.sessionSigner, finalAuthority.sessionSigner.toBytes()) ||
                !bytesEqual(signed.recentBlockhash, capsule.blockhash.blockhash)
              ) {
                fail(
                  "SIGNED_RESULT_INVALID",
                  "exact finalizer output drifted from claimed authority/message/blockhash",
                );
              }
              return signed.transactionBytes;
            } finally {
              clearAuthority(finalAuthority);
            }
          },
        );
      } catch (error) {
        if (error instanceof SessionApprovalCoordinatorError) throw error;
        fail("SIGNING_FAILED", "contextual keyring use or signing failed", error);
      }

      if (!(signedBytes instanceof Uint8Array)) {
        fail("SIGNED_RESULT_INVALID", "keyring returned a non-byte signing result");
      }
      let envelope;
      try {
        envelope = parseSerializedTransactionEnvelope(
          signedBytes,
          capsule.authority.sessionSigner.toBytes(),
        );
      } catch (error) {
        fail("SIGNED_RESULT_INVALID", "signed result failed strict reparsing", error);
      }
      const recomputedDigest = digestApprovalMessage(envelope.messageBytes);
      try {
        if (
          envelope.version !== 0 ||
          envelope.signatures.length !== 1 ||
          allZero(envelope.signatures[0]!) ||
          !bytesEqual(envelope.messageBytes, claimed.rawMessage) ||
          !approvalDigestsEqual(recomputedDigest, claimed.messageDigest) ||
          !bytesEqual(envelope.recentBlockhash, capsule.blockhash.blockhash) ||
          !ed25519.verify(
            envelope.signatures[0]!,
            envelope.messageBytes,
            capsule.authority.sessionSigner.toBytes(),
          )
        ) {
          fail(
            "SIGNED_RESULT_INVALID",
            "signed result does not authenticate the claimed exact binding",
          );
        }
        return new SignedSessionApprovalValue(
          id,
          claimed.messageDigest,
          signedBytes,
          envelope.signatures[0]!,
        );
      } finally {
        recomputedDigest.fill(0);
      }
    } catch (error) {
      if (shouldCancelPending && !claimStarted) {
        return this.#cancelAfterPreclaimFailure(id, error);
      }
      throw error;
    } finally {
      this.#activeSigning.delete(id);
      expectedDigest.fill(0);
      clearApproval(pending);
      clearAuthority(preclaimAuthority);
      clearApproval(claimed);
      clearAuthority(postclaimAuthority);
      clearAuthority(postValidityAuthority);
      signedBytes?.fill(0);
      clearCapsule(capsule);
    }
  }

  async reject(idValue: string): Promise<ApprovalRecord> {
    this.#assertUsable();
    const id = requireApprovalId(idValue);
    const capsule = this.#capsules.get(id);
    this.#capsules.delete(id);
    clearCapsule(capsule);
    try {
      const record = await this.#approvals.reject(id);
      return snapshotOwnerRecord(
        record,
        "APPROVAL_RESOLUTION_FAILED",
        "rejected approval",
      );
    } catch (error) {
      if (error instanceof SessionApprovalCoordinatorError) throw error;
      fail("APPROVAL_RESOLUTION_FAILED", "approval rejection failed", error);
    }
  }

  async cancel(idValue: string): Promise<ApprovalRecord> {
    this.#assertUsable();
    const id = requireApprovalId(idValue);
    const capsule = this.#capsules.get(id);
    this.#capsules.delete(id);
    clearCapsule(capsule);
    try {
      const record = await this.#approvals.cancel(id);
      return snapshotOwnerRecord(
        record,
        "APPROVAL_RESOLUTION_FAILED",
        "cancelled approval",
      );
    } catch (error) {
      if (error instanceof SessionApprovalCoordinatorError) throw error;
      fail("APPROVAL_RESOLUTION_FAILED", "approval cancellation failed", error);
    }
  }

  /** Drop in-memory authority capsules. Startup invalidation owns persistence. */
  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    for (const capsule of this.#capsules.values()) clearCapsule(capsule);
    this.#capsules.clear();
  }
}
