//! Deterministic, fail-closed local intent decoding for the still-opt-in
//! session approval path.
//!
//! This first decoder version deliberately recognizes one narrow consequence:
//! a lookup-free v0 Warden `execute` carrying exactly one account-less,
//! printable-ASCII Memo instruction. It does not call RPC, simulate, guess at
//! unknown programs, or treat malformed/unsupported bytes as benign. Asset
//! instructions remain blocked until the authority resolver can provide the
//! transaction-specific account state needed to describe their real owners,
//! mints, balances, and destinations.

import { PublicKey } from "@solana/web3.js";

import {
  MAX_REGISTRY_ENTRIES,
  MAX_REGISTRY_LISTS,
  REGISTRY_DATA_LEN,
  decodeRegistry,
} from "../deploy/accounts.js";
import { MAX_TX_BYTES } from "../constants.js";
import { decodeExecutePayload } from "../execute/payload.js";
import { parseSerializedTransactionEnvelope } from "./envelope.js";
import type {
  SessionApprovalIntentGate,
  SessionAuthoritySnapshot,
} from "./session-approval-coordinator.js";

const PUBLIC_KEY_BYTES = 32;
const SMART_ACCOUNT_DATA_BYTES = 4_120;
const SESSION_ACCOUNT_DATA_BYTES = 751;
const AUTHORIZATION_STATE_MAGIC = Uint8Array.of(
  87,
  82,
  68,
  65,
  85,
  84,
  72,
  1,
); // ASCII "WRDAUTH" || format version 1.
const AUTHORIZATION_ACCOUNT_PREFIX_BYTES = PUBLIC_KEY_BYTES + 1;
const AUTHORIZATION_STATE_BYTES =
  AUTHORIZATION_STATE_MAGIC.length +
  AUTHORIZATION_ACCOUNT_PREFIX_BYTES +
  SMART_ACCOUNT_DATA_BYTES +
  AUTHORIZATION_ACCOUNT_PREFIX_BYTES +
  SESSION_ACCOUNT_DATA_BYTES +
  AUTHORIZATION_ACCOUNT_PREFIX_BYTES +
  REGISTRY_DATA_LEN;

const SMART_ACCOUNT_DISCRIMINATOR = Uint8Array.of(
  186,
  83,
  247,
  224,
  59,
  95,
  223,
  112,
);
const SESSION_ACCOUNT_DISCRIMINATOR = Uint8Array.of(
  93,
  186,
  163,
  139,
  160,
  255,
  81,
  112,
);
const EXECUTE_DISCRIMINATOR = Uint8Array.of(
  130,
  221,
  242,
  154,
  13,
  193,
  189,
  29,
);
const ACCOUNT_SEED = Uint8Array.of(97, 99, 99, 111, 117, 110, 116);
const SESSION_SEED = Uint8Array.of(115, 101, 115, 115, 105, 111, 110);
const REGISTRY_SEED = Uint8Array.of(114, 101, 103, 105, 115, 116, 114, 121);
const COMPUTE_BUDGET_PROGRAM = new PublicKey(
  "ComputeBudget111111111111111111111111111111",
);
const MEMO_PROGRAM = new PublicKey(
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
);
// Independent literal from the shipped Warden IDL/program declaration. The
// resolver does not get to redefine which executable this decoder understands.
const CANONICAL_WARDEN_PROGRAM = new PublicKey(
  "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2",
);

const COMPUTE_SET_UNIT_LIMIT = 2;
const COMPUTE_REQUEST_HEAP_FRAME = 1;
const MIN_COMPUTE_UNIT_LIMIT = 120_000;
const MAX_COMPUTE_UNIT_LIMIT = 1_400_000;
const MEMO_HEAP_FRAME_BYTES = 128 * 1_024;
const MAX_MEMO_BYTES = 256;
const OP_EXECUTE = 1 << 1;
const KNOWN_SESSION_OPS = 0x0f;
const U32_MAX = 0xffff_ffff;
const U64_MAX = 0xffff_ffff_ffff_ffffn;
const I64_SIGN_BIT = 0x8000_0000_0000_0000n;
const I64_MODULUS = 0x1_0000_0000_0000_0000n;
const CHAINS: ReadonlySet<string> = new Set([
  "solana:mainnet",
  "solana:devnet",
  "solana:testnet",
  "solana:localnet",
]);

export type SessionIntentErrorCode =
  | "INVALID_INPUT"
  | "AUTHORIZATION_STATE_INVALID"
  | "AUTHORITY_MISMATCH"
  | "AUTHORITY_NOT_USABLE"
  | "MESSAGE_INVALID"
  | "MESSAGE_SHAPE_UNSUPPORTED"
  | "COMPUTE_BUDGET_INVALID"
  | "EXECUTE_LAYOUT_INVALID"
  | "EXECUTE_PAYLOAD_INVALID"
  | "REGISTRY_DENIED"
  | "INSTRUCTION_UNSUPPORTED"
  | "MEMO_INVALID";

export class SessionIntentError extends Error {
  readonly code: SessionIntentErrorCode;

  constructor(
    code: SessionIntentErrorCode,
    message: string,
    options: ErrorOptions = {},
  ) {
    super(`session intent: ${message}`, options);
    this.name = "SessionIntentError";
    this.code = code;
  }
}

export interface SessionAuthorizationAccount {
  readonly owner: PublicKey;
  readonly executable: boolean;
  readonly data: Uint8Array;
}

export interface SessionAuthorizationStateInput {
  readonly smartAccount: SessionAuthorizationAccount;
  readonly session: SessionAuthorizationAccount;
  readonly registry: SessionAuthorizationAccount;
}

export interface SessionIntentDecodeInput {
  readonly messageBytes: Uint8Array;
  readonly authority: SessionAuthoritySnapshot;
  readonly nowUnixSeconds: number;
}

/** Primitive-only rendering facts for the one intent this decoder recognizes. */
export interface SessionMemoIntent {
  readonly kind: "memo-v1";
  readonly chain: SessionAuthoritySnapshot["chain"];
  readonly genesisHash: string;
  readonly smartAccount: string;
  readonly sessionSigner: string;
  readonly sessionAccount: string;
  readonly registry: string;
  readonly wardenProgram: string;
  readonly programId: string;
  readonly recentBlockhash: string;
  readonly memo: string;
  readonly memoByteLength: number;
  readonly computeUnitLimit: number;
  readonly heapFrameBytes: number;
  readonly messageByteLength: number;
  readonly accountGeneration: string;
  readonly policyVersion: number;
  readonly sessionExpiryUnixSeconds: number;
  readonly programAllowlistId: number;
  readonly contextSlot: number;
}

export interface DeterministicSessionIntentGateOptions {
  readonly readUnixSeconds?: () => number;
}

interface OwnedAuthorizationAccount {
  readonly owner: PublicKey;
  readonly executable: boolean;
  readonly data: Uint8Array;
}

interface ParsedAuthorizationState {
  readonly smartAccount: OwnedAuthorizationAccount;
  readonly session: OwnedAuthorizationAccount;
  readonly registry: OwnedAuthorizationAccount;
}

interface OwnedAuthority {
  readonly chain: SessionAuthoritySnapshot["chain"];
  readonly genesisHash: Uint8Array;
  readonly smartAccount: PublicKey;
  readonly sessionSigner: PublicKey;
  readonly sessionAccount: PublicKey;
  readonly registry: PublicKey;
  readonly wardenProgram: PublicKey;
  readonly accountGeneration: bigint;
  readonly policyVersion: number;
  readonly authorizationState: Uint8Array;
  readonly contextSlot: number;
}

interface ValidatedSessionState {
  readonly expiryUnixSeconds: number;
  readonly allowlistId: number;
}

interface ValidatedRegistryState {
  readonly entries: ReturnType<typeof decodeRegistry>["entries"];
  readonly lists: ReturnType<typeof decodeRegistry>["lists"];
}

function fail(
  code: SessionIntentErrorCode,
  message: string,
  cause?: unknown,
): never {
  throw new SessionIntentError(
    code,
    message,
    cause === undefined ? {} : { cause },
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function allZero(bytes: Uint8Array): boolean {
  for (const byte of bytes) {
    if (byte !== 0) return false;
  }
  return true;
}

function requireZeroRange(
  bytes: Uint8Array,
  start: number,
  end: number,
  label: string,
): void {
  for (let offset = start; offset < end; offset++) {
    if (bytes[offset] !== 0) {
      fail("AUTHORITY_NOT_USABLE", `${label} contains nonzero reserved bytes`);
    }
  }
}

function readU16le(bytes: Uint8Array, offset: number): number {
  return bytes[offset]! | (bytes[offset + 1]! << 8);
}

function readU32le(bytes: Uint8Array, offset: number): number {
  return (
    bytes[offset]! |
    (bytes[offset + 1]! << 8) |
    (bytes[offset + 2]! << 16) |
    (bytes[offset + 3]! << 24)
  ) >>> 0;
}

function readU64le(bytes: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let index = 7; index >= 0; index--) {
    value = (value << 8n) | BigInt(bytes[offset + index]!);
  }
  return value;
}

function readI64le(bytes: Uint8Array, offset: number): bigint {
  const value = readU64le(bytes, offset);
  return (value & I64_SIGN_BIT) === 0n ? value : value - I64_MODULUS;
}

function requireSafeInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    fail("INVALID_INPUT", `${label} must be a safe integer`);
  }
  return value;
}

function requireU32(value: unknown, label: string): number {
  const number = requireSafeInteger(value, label);
  if (number < 0 || number > U32_MAX) {
    fail("INVALID_INPUT", `${label} must be a u32`);
  }
  return number;
}

function requirePublicKey(value: unknown, label: string): PublicKey {
  if (!(value instanceof PublicKey)) {
    fail("INVALID_INPUT", `${label} must be a PublicKey`);
  }
  return new PublicKey(value.toBytes());
}

function requireBytes(value: unknown, length: number, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail("INVALID_INPUT", `${label} must contain exactly ${length} bytes`);
  }
  return value.slice();
}

function snapshotAuthorizationAccount(
  value: unknown,
  dataLength: number,
  label: string,
): OwnedAuthorizationAccount {
  if (!isObject(value)) {
    fail("INVALID_INPUT", `${label} must be an account object`);
  }
  const ownerValue = value.owner;
  const executableValue = value.executable;
  const dataValue = value.data;
  if (typeof executableValue !== "boolean") {
    fail("INVALID_INPUT", `${label}.executable must be a boolean`);
  }
  return {
    owner: requirePublicKey(ownerValue, `${label}.owner`),
    executable: executableValue,
    data: requireBytes(dataValue, dataLength, `${label}.data`),
  };
}

/**
 * Encode the complete raw SmartAccount/SessionKey/Registry observation used by
 * the resolver. The packet is fixed-width and versioned; every account owner,
 * executable bit, and data byte participates in the coordinator's exact
 * equality checks. This function canonicalizes framing, not account validity.
 */
export function encodeSessionAuthorizationState(
  input: SessionAuthorizationStateInput,
): Uint8Array {
  if (!isObject(input)) {
    fail("INVALID_INPUT", "authorization input must be an object");
  }
  const smartAccountValue = input.smartAccount;
  const sessionValue = input.session;
  const registryValue = input.registry;
  const accounts = [
    snapshotAuthorizationAccount(
      smartAccountValue,
      SMART_ACCOUNT_DATA_BYTES,
      "smartAccount",
    ),
    snapshotAuthorizationAccount(
      sessionValue,
      SESSION_ACCOUNT_DATA_BYTES,
      "session",
    ),
    snapshotAuthorizationAccount(
      registryValue,
      REGISTRY_DATA_LEN,
      "registry",
    ),
  ];
  const out = new Uint8Array(AUTHORIZATION_STATE_BYTES);
  out.set(AUTHORIZATION_STATE_MAGIC, 0);
  let offset = AUTHORIZATION_STATE_MAGIC.length;
  for (const account of accounts) {
    out.set(account.owner.toBytes(), offset);
    offset += PUBLIC_KEY_BYTES;
    out[offset++] = account.executable ? 1 : 0;
    out.set(account.data, offset);
    offset += account.data.length;
  }
  return out;
}

function snapshotAuthority(value: unknown): OwnedAuthority {
  if (!isObject(value)) {
    fail("INVALID_INPUT", "authority must be an object");
  }
  const chainValue = value.chain;
  const genesisHashValue = value.genesisHash;
  const smartAccountValue = value.smartAccount;
  const sessionSignerValue = value.sessionSigner;
  const sessionAccountValue = value.sessionAccount;
  const registryValue = value.registry;
  const wardenProgramValue = value.wardenProgram;
  const accountGenerationValue = value.accountGeneration;
  const policyVersionValue = value.policyVersion;
  const authorizationStateValue = value.authorizationState;
  const contextSlotValue = value.contextSlot;
  if (typeof chainValue !== "string" || !CHAINS.has(chainValue)) {
    fail("INVALID_INPUT", "authority.chain is unsupported");
  }
  const genesisHash = requireBytes(
    genesisHashValue,
    PUBLIC_KEY_BYTES,
    "authority.genesisHash",
  );
  if (allZero(genesisHash)) {
    fail("INVALID_INPUT", "authority.genesisHash must not be all zero");
  }
  if (
    typeof accountGenerationValue !== "bigint" ||
    accountGenerationValue < 0n ||
    accountGenerationValue > U64_MAX
  ) {
    fail("INVALID_INPUT", "authority.accountGeneration must be a u64 bigint");
  }
  const contextSlot = requireSafeInteger(
    contextSlotValue,
    "authority.contextSlot",
  );
  if (contextSlot < 0) {
    fail("INVALID_INPUT", "authority.contextSlot must not be negative");
  }
  if (!(authorizationStateValue instanceof Uint8Array)) {
    fail("INVALID_INPUT", "authority.authorizationState must be a Uint8Array");
  }
  if (authorizationStateValue.length !== AUTHORIZATION_STATE_BYTES) {
    fail(
      "AUTHORIZATION_STATE_INVALID",
      `authorization packet length ${authorizationStateValue.length} is not ${AUTHORIZATION_STATE_BYTES}`,
    );
  }
  const wardenProgram = requirePublicKey(
    wardenProgramValue,
    "authority.wardenProgram",
  );
  if (!wardenProgram.equals(CANONICAL_WARDEN_PROGRAM)) {
    fail(
      "AUTHORITY_MISMATCH",
      "authority.wardenProgram is not the shipped Warden program",
    );
  }
  return {
    chain: chainValue as OwnedAuthority["chain"],
    genesisHash,
    smartAccount: requirePublicKey(
      smartAccountValue,
      "authority.smartAccount",
    ),
    sessionSigner: requirePublicKey(
      sessionSignerValue,
      "authority.sessionSigner",
    ),
    sessionAccount: requirePublicKey(
      sessionAccountValue,
      "authority.sessionAccount",
    ),
    registry: requirePublicKey(registryValue, "authority.registry"),
    wardenProgram,
    accountGeneration: accountGenerationValue,
    policyVersion: requireU32(policyVersionValue, "authority.policyVersion"),
    authorizationState: authorizationStateValue.slice(),
    contextSlot,
  };
}

function readAuthorizationAccount(
  packet: Uint8Array,
  offset: number,
  dataLength: number,
): { readonly account: OwnedAuthorizationAccount; readonly nextOffset: number } {
  const owner = new PublicKey(packet.slice(offset, offset + PUBLIC_KEY_BYTES));
  offset += PUBLIC_KEY_BYTES;
  const executable = packet[offset++];
  if (executable !== 0 && executable !== 1) {
    fail(
      "AUTHORIZATION_STATE_INVALID",
      "account executable flag is not canonical",
    );
  }
  const data = packet.slice(offset, offset + dataLength);
  return {
    account: { owner, executable: executable === 1, data },
    nextOffset: offset + dataLength,
  };
}

function parseAuthorizationState(packet: Uint8Array): ParsedAuthorizationState {
  if (packet.length !== AUTHORIZATION_STATE_BYTES) {
    fail(
      "AUTHORIZATION_STATE_INVALID",
      `authorization packet length ${packet.length} is not ${AUTHORIZATION_STATE_BYTES}`,
    );
  }
  if (
    !bytesEqual(
      packet.slice(0, AUTHORIZATION_STATE_MAGIC.length),
      AUTHORIZATION_STATE_MAGIC,
    )
  ) {
    fail(
      "AUTHORIZATION_STATE_INVALID",
      "authorization packet magic or version is unsupported",
    );
  }
  let offset = AUTHORIZATION_STATE_MAGIC.length;
  const smart = readAuthorizationAccount(
    packet,
    offset,
    SMART_ACCOUNT_DATA_BYTES,
  );
  offset = smart.nextOffset;
  const session = readAuthorizationAccount(
    packet,
    offset,
    SESSION_ACCOUNT_DATA_BYTES,
  );
  offset = session.nextOffset;
  const registry = readAuthorizationAccount(
    packet,
    offset,
    REGISTRY_DATA_LEN,
  );
  offset = registry.nextOffset;
  if (offset !== packet.length) {
    fail(
      "AUTHORIZATION_STATE_INVALID",
      "authorization packet framing did not consume every byte",
    );
  }
  return {
    smartAccount: smart.account,
    session: session.account,
    registry: registry.account,
  };
}

function requireDiscriminator(
  data: Uint8Array,
  expected: Uint8Array,
  label: string,
): void {
  if (!bytesEqual(data.slice(0, expected.length), expected)) {
    fail("AUTHORITY_NOT_USABLE", `${label} discriminator is unsupported`);
  }
}

function assertCanonicalPda(
  actual: PublicKey,
  seeds: readonly Uint8Array[],
  bump: number,
  program: PublicKey,
  label: string,
): void {
  let expected: PublicKey;
  let canonicalBump: number;
  try {
    [expected, canonicalBump] = PublicKey.findProgramAddressSync(
      [...seeds],
      program,
    );
  } catch (error) {
    fail("AUTHORITY_MISMATCH", `${label} PDA seeds are invalid`, error);
  }
  if (bump !== canonicalBump || !actual.equals(expected)) {
    fail("AUTHORITY_MISMATCH", `${label} address or bump is not canonical`);
  }
}

function assertAccountContainer(
  account: OwnedAuthorizationAccount,
  authority: OwnedAuthority,
  label: string,
): void {
  if (!account.owner.equals(authority.wardenProgram)) {
    fail("AUTHORITY_MISMATCH", `${label} owner is not the Warden program`);
  }
  if (account.executable) {
    fail("AUTHORITY_NOT_USABLE", `${label} is unexpectedly executable`);
  }
}

function validateSmartAccount(
  account: OwnedAuthorizationAccount,
  authority: OwnedAuthority,
): void {
  assertAccountContainer(account, authority, "SmartAccount");
  const data = account.data;
  requireDiscriminator(data, SMART_ACCOUNT_DISCRIMINATOR, "SmartAccount");
  if (data[8] !== 1) {
    fail("AUTHORITY_NOT_USABLE", "SmartAccount version is unsupported");
  }
  assertCanonicalPda(
    authority.smartAccount,
    [ACCOUNT_SEED, data.slice(14, 46)],
    data[9]!,
    authority.wardenProgram,
    "SmartAccount",
  );
  if (data[12] !== 0) {
    fail("AUTHORITY_NOT_USABLE", "SmartAccount is frozen");
  }
  if (data[13] !== 0 || readI64le(data, 544) !== 0n || readI64le(data, 552) !== 0n) {
    fail(
      "AUTHORITY_NOT_USABLE",
      "unfrozen SmartAccount carries noncanonical freeze state",
    );
  }
  if (!bytesEqual(data.slice(175, 207), authority.genesisHash)) {
    fail("AUTHORITY_MISMATCH", "SmartAccount cluster tag changed");
  }
  if (!bytesEqual(data.slice(239, 271), authority.registry.toBytes())) {
    fail("AUTHORITY_MISMATCH", "SmartAccount registry changed");
  }
  if (readU64le(data, 528) !== authority.accountGeneration) {
    fail("AUTHORITY_MISMATCH", "SmartAccount generation changed");
  }
  if (readU32le(data, 560) !== authority.policyVersion) {
    fail("AUTHORITY_MISMATCH", "SmartAccount policy version changed");
  }
  if (authority.policyVersion !== 1) {
    fail("AUTHORITY_NOT_USABLE", "SmartAccount policy version is unsupported");
  }
  const policyOps = readU16le(data, 1_936);
  if (
    (policyOps & ~KNOWN_SESSION_OPS) !== 0 ||
    (policyOps & OP_EXECUTE) === 0
  ) {
    fail(
      "AUTHORITY_NOT_USABLE",
      "SmartAccount policy does not safely permit session execute",
    );
  }
  requireZeroRange(data, 271, 527, "SmartAccount");
  requireZeroRange(data, 527, 528, "SmartAccount alignment padding");
  requireZeroRange(data, 564, 568, "SmartAccount policy version padding");
  requireZeroRange(data, 1_938, 1_944, "SmartAccount policy ceiling padding");
  requireZeroRange(data, 1_944, 2_008, "SmartAccount policy");
}

function requireSafeI64Number(value: bigint, label: string): number {
  if (
    value < BigInt(Number.MIN_SAFE_INTEGER) ||
    value > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    fail("AUTHORITY_NOT_USABLE", `${label} is outside the safe integer range`);
  }
  return Number(value);
}

function validateSessionAccount(
  account: OwnedAuthorizationAccount,
  authority: OwnedAuthority,
  nowUnixSeconds: number,
): ValidatedSessionState {
  assertAccountContainer(account, authority, "SessionKey");
  const data = account.data;
  requireDiscriminator(data, SESSION_ACCOUNT_DISCRIMINATOR, "SessionKey");
  if (data[8] !== 1) {
    fail("AUTHORITY_NOT_USABLE", "SessionKey version is unsupported");
  }
  if (!bytesEqual(data.slice(10, 42), authority.smartAccount.toBytes())) {
    fail("AUTHORITY_MISMATCH", "SessionKey SmartAccount changed");
  }
  if (!bytesEqual(data.slice(42, 74), authority.sessionSigner.toBytes())) {
    fail("AUTHORITY_MISMATCH", "SessionKey signer changed");
  }
  assertCanonicalPda(
    authority.sessionAccount,
    [
      SESSION_SEED,
      authority.smartAccount.toBytes(),
      authority.sessionSigner.toBytes(),
    ],
    data[9]!,
    authority.wardenProgram,
    "SessionKey",
  );
  if (data[74] !== 0) {
    fail("AUTHORITY_NOT_USABLE", "SessionKey kind is unsupported");
  }
  const expiryUnixSeconds = requireSafeI64Number(
    readI64le(data, 75),
    "SessionKey expiry",
  );
  if (nowUnixSeconds >= expiryUnixSeconds) {
    fail("AUTHORITY_NOT_USABLE", "SessionKey is expired");
  }
  const ops = readU16le(data, 83);
  if ((ops & ~KNOWN_SESSION_OPS) !== 0 || (ops & OP_EXECUTE) === 0) {
    fail("AUTHORITY_NOT_USABLE", "SessionKey does not safely permit execute");
  }
  if (readU64le(data, 85) !== authority.accountGeneration) {
    fail("AUTHORITY_MISMATCH", "SessionKey generation changed");
  }
  const allowlistId = readU16le(data, 669);
  if (allowlistId < 1 || allowlistId > MAX_REGISTRY_LISTS) {
    fail("AUTHORITY_NOT_USABLE", "SessionKey allowlist id is not usable");
  }
  requireZeroRange(data, 687, 751, "SessionKey");
  return { expiryUnixSeconds, allowlistId };
}

function validateRegistryAccount(
  account: OwnedAuthorizationAccount,
  authority: OwnedAuthority,
  allowlistId: number,
): ValidatedRegistryState {
  assertAccountContainer(account, authority, "Registry");
  let decoded: ReturnType<typeof decodeRegistry>;
  try {
    decoded = decodeRegistry(account.data);
  } catch (error) {
    fail("AUTHORITY_NOT_USABLE", "Registry account bytes are invalid", error);
  }
  if (decoded.version !== 1) {
    fail("AUTHORITY_NOT_USABLE", "Registry version is unsupported");
  }
  assertCanonicalPda(
    authority.registry,
    [REGISTRY_SEED],
    decoded.bump,
    authority.wardenProgram,
    "Registry",
  );
  requireZeroRange(account.data, 10, 16, "Registry header padding");
  requireZeroRange(account.data, 82, 88, "Registry entry padding");
  requireZeroRange(account.data, 3_225, REGISTRY_DATA_LEN, "Registry");

  for (let index = 0; index < decoded.nEntries; index++) {
    const base = 88 + index * 48;
    const entry = decoded.entries[index]!;
    requireZeroRange(
      account.data,
      base + 32 + entry.discLen,
      base + 40,
      `Registry entry ${index} selector`,
    );
    requireZeroRange(
      account.data,
      base + 42,
      base + 48,
      `Registry entry ${index}`,
    );
  }
  requireZeroRange(
    account.data,
    88 + decoded.nEntries * 48,
    88 + MAX_REGISTRY_ENTRIES * 48,
    "Registry unused entries",
  );

  const usedMask = decoded.nEntries === MAX_REGISTRY_ENTRIES
    ? U64_MAX
    : (1n << BigInt(decoded.nEntries)) - 1n;
  for (let listIndex = 0; listIndex < MAX_REGISTRY_LISTS; listIndex++) {
    const mask = decoded.lists[listIndex]!;
    if ((mask & ~usedMask) !== 0n) {
      fail("AUTHORITY_NOT_USABLE", `Registry list ${listIndex + 1} names an unused entry`);
    }
    const markedAllocated =
      (decoded.allocatedLists & (1 << listIndex)) !== 0;
    if (markedAllocated !== (mask !== 0n)) {
      fail(
        "AUTHORITY_NOT_USABLE",
        `Registry list ${listIndex + 1} allocation marker is noncanonical`,
      );
    }
  }
  if ((decoded.allocatedLists & (1 << (allowlistId - 1))) === 0) {
    fail("REGISTRY_DENIED", "SessionKey allowlist was not allocated");
  }
  return {
    entries: decoded.entries,
    lists: decoded.lists,
  };
}

function assertExpectedStaticKeys(
  actual: readonly Uint8Array[],
  authority: OwnedAuthority,
): void {
  const expected = [
    authority.sessionSigner.toBytes(),
    authority.smartAccount.toBytes(),
    authority.sessionAccount.toBytes(),
    COMPUTE_BUDGET_PROGRAM.toBytes(),
    authority.wardenProgram.toBytes(),
    authority.registry.toBytes(),
    MEMO_PROGRAM.toBytes(),
  ];
  if (
    actual.length !== expected.length ||
    expected.some((key, index) => !bytesEqual(key, actual[index]!))
  ) {
    fail(
      "MESSAGE_SHAPE_UNSUPPORTED",
      "message static account set or canonical ordering is unsupported",
    );
  }
}

function requireExactIndexes(
  actual: Uint8Array,
  expected: readonly number[],
  label: string,
): void {
  if (
    actual.length !== expected.length ||
    expected.some((value, index) => actual[index] !== value)
  ) {
    fail("EXECUTE_LAYOUT_INVALID", `${label} account layout changed`);
  }
}

function decodeMemoPayload(executeData: Uint8Array): Uint8Array {
  if (
    executeData.length < 14 ||
    !bytesEqual(executeData.slice(0, 8), EXECUTE_DISCRIMINATOR) ||
    executeData[8] !== 0 ||
    executeData[9] !== 1
  ) {
    fail(
      "EXECUTE_LAYOUT_INVALID",
      "execute must use the inline SessionKey authorization shape",
    );
  }
  const payloadLength = readU32le(executeData, 10);
  if (payloadLength !== executeData.length - 14) {
    fail(
      "EXECUTE_LAYOUT_INVALID",
      "execute payload length or trailing bytes are noncanonical",
    );
  }
  let payload;
  try {
    payload = decodeExecutePayload(executeData.slice(14));
  } catch (error) {
    fail("EXECUTE_PAYLOAD_INVALID", "execute payload is malformed", error);
  }
  if (payload.ixs.length !== 1) {
    fail(
      "EXECUTE_PAYLOAD_INVALID",
      "exactly one inner instruction is supported",
    );
  }
  const instruction = payload.ixs[0]!;
  if (instruction.programIndex !== 2 || instruction.accounts.length !== 0) {
    fail(
      "INSTRUCTION_UNSUPPORTED",
      "only an account-less Memo instruction is supported",
    );
  }
  return instruction.data;
}

function decodePrintableMemo(bytes: Uint8Array): string {
  if (bytes.length === 0 || bytes.length > MAX_MEMO_BYTES) {
    fail(
      "MEMO_INVALID",
      `Memo must contain 1 to ${MAX_MEMO_BYTES} printable ASCII bytes`,
    );
  }
  let memo = "";
  for (const byte of bytes) {
    if (byte < 0x20 || byte > 0x7e) {
      fail("MEMO_INVALID", "Memo contains a non-printable or non-ASCII byte");
    }
    memo += String.fromCharCode(byte);
  }
  return memo;
}

function assertRegistryAllowsMemo(
  registry: ValidatedRegistryState,
  allowlistId: number,
  memoData: Uint8Array,
): void {
  const matching: number[] = [];
  for (let index = 0; index < registry.entries.length; index++) {
    const entry = registry.entries[index]!;
    if (!entry.programId.equals(MEMO_PROGRAM)) continue;
    if (
      entry.discLen === 0 ||
      (memoData.length >= entry.discLen &&
        bytesEqual(
          memoData.slice(0, entry.discLen),
          entry.selector.slice(0, entry.discLen),
        ))
    ) {
      matching.push(index);
    }
  }
  if (matching.length !== 1) {
    fail(
      "REGISTRY_DENIED",
      "Memo registry match is absent or ambiguous",
    );
  }
  const index = matching[0]!;
  const entry = registry.entries[index]!;
  if (entry.discLen !== 0 || entry.roleRules !== 0) {
    fail("REGISTRY_DENIED", "Memo registry entry is not the supported tagless shape");
  }
  if ((registry.lists[allowlistId - 1]! & (1n << BigInt(index))) === 0n) {
    fail("REGISTRY_DENIED", "Memo registry entry is outside the session allowlist");
  }
}

/** Decode and authorize one exact final message without RPC or asynchronous work. */
export function decodeSessionIntent(
  input: SessionIntentDecodeInput,
): SessionMemoIntent {
  if (!isObject(input)) {
    fail("INVALID_INPUT", "decoder input must be an object");
  }
  const messageValue = input.messageBytes;
  const authorityValue = input.authority;
  const nowUnixSecondsValue = input.nowUnixSeconds;
  if (!(messageValue instanceof Uint8Array)) {
    fail("INVALID_INPUT", "messageBytes must be a Uint8Array");
  }
  if (
    messageValue.length === 0 ||
    messageValue.length > MAX_TX_BYTES - 65
  ) {
    fail(
      "MESSAGE_INVALID",
      `messageBytes must contain 1 to ${MAX_TX_BYTES - 65} bytes`,
    );
  }
  const messageBytes = messageValue.slice();
  const nowUnixSeconds = requireSafeInteger(
    nowUnixSecondsValue,
    "nowUnixSeconds",
  );
  if (nowUnixSeconds < 0) {
    fail("INVALID_INPUT", "nowUnixSeconds must not be negative");
  }
  const authority = snapshotAuthority(authorityValue);
  const state = parseAuthorizationState(authority.authorizationState);
  validateSmartAccount(state.smartAccount, authority);
  const session = validateSessionAccount(
    state.session,
    authority,
    nowUnixSeconds,
  );
  const registry = validateRegistryAccount(
    state.registry,
    authority,
    session.allowlistId,
  );

  // The strict parser accepts serialized transaction envelopes. Reconstruct
  // the unique unsigned one-signature envelope around the exact approval
  // message; this adds no authority and lets the same parser prove ShortU16,
  // version, index, lookup, packet-size, and end-of-input invariants.
  const unsigned = new Uint8Array(1 + 64 + messageBytes.length);
  unsigned[0] = 1;
  unsigned.set(messageBytes, 65);
  let envelope;
  try {
    envelope = parseSerializedTransactionEnvelope(
      unsigned,
      authority.sessionSigner.toBytes(),
    );
  } catch (error) {
    fail("MESSAGE_INVALID", "message failed the strict Solana parser", error);
  }
  if (
    envelope.version !== 0 ||
    envelope.header.numRequiredSignatures !== 1 ||
    envelope.header.numReadonlySignedAccounts !== 0 ||
    envelope.header.numReadonlyUnsignedAccounts !== 4 ||
    envelope.instructions.length !== 3
  ) {
    fail(
      "MESSAGE_SHAPE_UNSUPPORTED",
      "only the canonical three-instruction session Memo v0 message is supported",
    );
  }
  assertExpectedStaticKeys(envelope.staticAccountKeys, authority);
  if (allZero(envelope.recentBlockhash)) {
    fail("MESSAGE_INVALID", "message recent blockhash must not be all zero");
  }

  const unitInstruction = envelope.instructions[0]!;
  const heapInstruction = envelope.instructions[1]!;
  const executeInstruction = envelope.instructions[2]!;
  if (
    unitInstruction.programIdIndex !== 3 ||
    unitInstruction.accountKeyIndexes.length !== 0 ||
    unitInstruction.data.length !== 5 ||
    unitInstruction.data[0] !== COMPUTE_SET_UNIT_LIMIT
  ) {
    fail(
      "COMPUTE_BUDGET_INVALID",
      "first instruction must be one SetComputeUnitLimit",
    );
  }
  const computeUnitLimit = readU32le(unitInstruction.data, 1);
  if (
    computeUnitLimit < MIN_COMPUTE_UNIT_LIMIT ||
    computeUnitLimit > MAX_COMPUTE_UNIT_LIMIT
  ) {
    fail("COMPUTE_BUDGET_INVALID", "compute-unit limit is outside the supported range");
  }
  if (
    heapInstruction.programIdIndex !== 3 ||
    heapInstruction.accountKeyIndexes.length !== 0 ||
    heapInstruction.data.length !== 5 ||
    heapInstruction.data[0] !== COMPUTE_REQUEST_HEAP_FRAME ||
    readU32le(heapInstruction.data, 1) !== MEMO_HEAP_FRAME_BYTES
  ) {
    fail(
      "COMPUTE_BUDGET_INVALID",
      `second instruction must request exactly ${MEMO_HEAP_FRAME_BYTES} heap bytes`,
    );
  }
  if (executeInstruction.programIdIndex !== 4) {
    fail("EXECUTE_LAYOUT_INVALID", "final instruction is not Warden execute");
  }
  requireExactIndexes(
    executeInstruction.accountKeyIndexes,
    [1, 0, 2, 4, 4, 5, 4, 6],
    "execute",
  );
  const memoData = decodeMemoPayload(executeInstruction.data);
  const memo = decodePrintableMemo(memoData);
  assertRegistryAllowsMemo(registry, session.allowlistId, memoData);

  return Object.freeze({
    kind: "memo-v1",
    chain: authority.chain,
    genesisHash: new PublicKey(authority.genesisHash).toBase58(),
    smartAccount: authority.smartAccount.toBase58(),
    sessionSigner: authority.sessionSigner.toBase58(),
    sessionAccount: authority.sessionAccount.toBase58(),
    registry: authority.registry.toBase58(),
    wardenProgram: authority.wardenProgram.toBase58(),
    programId: MEMO_PROGRAM.toBase58(),
    recentBlockhash: new PublicKey(envelope.recentBlockhash).toBase58(),
    memo,
    memoByteLength: memoData.length,
    computeUnitLimit,
    heapFrameBytes: MEMO_HEAP_FRAME_BYTES,
    messageByteLength: messageBytes.length,
    accountGeneration: authority.accountGeneration.toString(10),
    policyVersion: authority.policyVersion,
    sessionExpiryUnixSeconds: session.expiryUnixSeconds,
    programAllowlistId: session.allowlistId,
    contextSlot: authority.contextSlot,
  });
}

/** Synchronous adapter for SessionApprovalCoordinator's no-await intent hook. */
export class DeterministicSessionIntentGate implements SessionApprovalIntentGate {
  readonly #readUnixSeconds: () => number;

  constructor(options: DeterministicSessionIntentGateOptions = {}) {
    if (!isObject(options)) {
      fail("INVALID_INPUT", "gate options must be an object");
    }
    const readUnixSeconds = (
      options as DeterministicSessionIntentGateOptions
    ).readUnixSeconds;
    if (
      readUnixSeconds !== undefined &&
      typeof readUnixSeconds !== "function"
    ) {
      fail("INVALID_INPUT", "readUnixSeconds must be a function");
    }
    this.#readUnixSeconds =
      readUnixSeconds === undefined
        ? () => Math.floor(Date.now() / 1_000)
        : readUnixSeconds;
  }

  assertAllowed(input: {
    readonly messageBytes: Uint8Array;
    readonly authority: SessionAuthoritySnapshot;
  }): void {
    decodeSessionIntent({
      messageBytes: input.messageBytes,
      authority: input.authority,
      nowUnixSeconds: this.#readUnixSeconds(),
    });
  }
}
