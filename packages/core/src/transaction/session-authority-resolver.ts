//! Still-unreachable C5 authority resolution for session approvals.
//!
//! One `getMultipleAccounts` call observes SmartAccount, SessionKey, Registry,
//! the shipped Warden Program, its canonical ProgramData account, and the Clock
//! sysvar at one confirmed bank context. The resolver separately binds the
//! endpoint's immutable genesis hash to the selected chain. Every account is
//! owner/executable/exact-length checked before the resolver creates its owned
//! authorization snapshot, and ProgramData is pinned by canonical address,
//! loader state, deployment slot, upgrade authority, release code hash, full
//! raw hash, and exact allocation length.
//!
//! This authenticates data *relative to the configured RPC*. Genesis binding
//! catches a wrong-cluster endpoint; it cannot make a malicious endpoint honest.
//! A production composition still needs a trusted endpoint or independently
//! specified quorum. No extension/runtime route imports this module today.

import { sha256 } from "@noble/hashes/sha2.js";
import {
  PublicKey,
  SYSVAR_CLOCK_PUBKEY,
  type Connection,
} from "@solana/web3.js";

import {
  PROGRAMDATA_METADATA_LEN,
  decodeProgramAccount,
  decodeProgramDataAccount,
} from "../deploy/accounts.js";
import { BPF_UPGRADEABLE_LOADER } from "../deploy/config.js";
import type { ApprovalChain } from "../approval/record.js";
import {
  SESSION_APPROVAL_COMMITMENT,
  type SessionApprovalAuthorityResolver,
  type SessionAuthoritySelection,
  type SessionAuthoritySnapshot,
} from "./session-approval-coordinator.js";
import {
  SESSION_INTENT_EXPIRY_SAFETY_SECONDS,
  SessionIntentError,
  assertUsableSessionAuthority,
  encodeSessionAuthorizationState,
} from "./session-intent.js";

const WARDEN_PROGRAM = new PublicKey(
  "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2",
);
const SYSVAR_OWNER = new PublicKey(
  "Sysvar1111111111111111111111111111111111111",
);
const SMART_ACCOUNT_DATA_BYTES = 4_120;
const SESSION_ACCOUNT_DATA_BYTES = 751;
const REGISTRY_ACCOUNT_DATA_BYTES = 3_480;
const PROGRAM_ACCOUNT_DATA_BYTES = 36;
const CLOCK_ACCOUNT_DATA_BYTES = 40;
const MAX_SOLANA_ACCOUNT_DATA_BYTES = 10 * 1_024 * 1_024;
const U64_MAX = 0xffff_ffff_ffff_ffffn;
const I64_SIGN_BIT = 0x8000_0000_0000_0000n;
const I64_MODULUS = 0x1_0000_0000_0000_0000n;
const SESSION_SEED = new TextEncoder().encode("session");
const REGISTRY_SEED = new TextEncoder().encode("registry");

export const SESSION_AUTHORITY_ACCOUNT_COUNT = 6;
export const SESSION_AUTHORITY_CLOCK_SAFETY_SECONDS =
  SESSION_INTENT_EXPIRY_SAFETY_SECONDS;

/** Public cluster pins from Solana's `ClusterType::get_genesis_hash`. */
export const SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES = Object.freeze({
  "solana:mainnet": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
  "solana:devnet": "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
  "solana:testnet": "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
} as const);

const CHAINS: ReadonlySet<string> = new Set([
  ...Object.keys(SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES),
  "solana:localnet",
]);

export type SessionAuthorityResolverErrorCode =
  | "INVALID_CONFIG"
  | "INVALID_REQUEST"
  | "LOCALNET_GENESIS_UNPINNED"
  | "RPC_UNAVAILABLE"
  | "RPC_RESPONSE_INVALID"
  | "GENESIS_MISMATCH"
  | "ACCOUNT_MISSING"
  | "AUTHORITY_NOT_USABLE"
  | "PROGRAM_IDENTITY_MISMATCH"
  | "CLOCK_INVALID";

export class SessionAuthorityResolverError extends Error {
  readonly code: SessionAuthorityResolverErrorCode;

  constructor(
    code: SessionAuthorityResolverErrorCode,
    message: string,
    options: ErrorOptions = {},
  ) {
    super(`session authority resolver: ${message}`, options);
    this.name = "SessionAuthorityResolverError";
    this.code = code;
  }
}

export interface SessionAuthorityRpcAccount {
  readonly owner: PublicKey;
  readonly executable: boolean;
  readonly data: Uint8Array;
}

export interface SessionAuthorityRpc {
  getGenesisHash(): Promise<string>;
  getMultipleAccounts(input: {
    readonly addresses: readonly PublicKey[];
    readonly commitment: typeof SESSION_APPROVAL_COMMITMENT;
    readonly minContextSlot: number;
  }): Promise<{
    readonly contextSlot: number;
    readonly accounts: readonly (SessionAuthorityRpcAccount | null)[];
  }>;
}

export interface PinnedSessionAuthorityResolverOptions {
  readonly rpc: SessionAuthorityRpc;
  /** Public half of the currently unlocked, AAD-bound session key. */
  readonly sessionSigner: PublicKey;
  readonly expectedWardenProgramDataSlot: bigint;
  readonly expectedWardenUpgradeAuthority: PublicKey;
  /** Release code-region hash (the deploy-gate / solana-verify convention). */
  readonly expectedWardenCodeHash: Uint8Array;
  /** sha256 of every raw ProgramData byte, including metadata and padding. */
  readonly expectedWardenProgramDataHash: Uint8Array;
  /** Exact allocation makes response memory and trailing padding bounded. */
  readonly expectedWardenProgramDataBytes: number;
  /** Local validators have no stable public genesis; callers must pin one. */
  readonly localnetGenesisHash?: Uint8Array;
}

interface OwnedRpcAccount {
  readonly owner: PublicKey;
  readonly executable: boolean;
  readonly data: Uint8Array;
}

interface OwnedResolverOptions {
  readonly rpc: SessionAuthorityRpc;
  readonly sessionSigner: PublicKey;
  readonly expectedWardenProgramDataSlot: bigint;
  readonly expectedWardenUpgradeAuthority: PublicKey;
  readonly expectedWardenCodeHash: Uint8Array;
  readonly expectedWardenProgramDataHash: Uint8Array;
  readonly expectedWardenProgramDataBytes: number;
  readonly localnetGenesisHash: Uint8Array | undefined;
}

function fail(
  code: SessionAuthorityResolverErrorCode,
  message: string,
  cause?: unknown,
): never {
  throw new SessionAuthorityResolverError(
    code,
    message,
    cause === undefined ? {} : { cause },
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Uint8Array)
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

function requireBytes(
  value: unknown,
  length: number,
  label: string,
  code: SessionAuthorityResolverErrorCode,
): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(code, `${label} must contain exactly ${length} bytes`);
  }
  return value.slice();
}

function requirePublicKey(
  value: unknown,
  label: string,
  code: SessionAuthorityResolverErrorCode,
): PublicKey {
  if (!(value instanceof PublicKey)) fail(code, `${label} must be a PublicKey`);
  try {
    return new PublicKey(value.toBytes());
  } catch (error) {
    fail(code, `${label} could not be copied`, error);
  }
}

function requireSafeNonNegativeInteger(
  value: unknown,
  label: string,
  code: SessionAuthorityResolverErrorCode,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    fail(code, `${label} must be a non-negative safe integer`);
  }
  return value as number;
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
  const unsigned = readU64le(bytes, offset);
  return (unsigned & I64_SIGN_BIT) === 0n ? unsigned : unsigned - I64_MODULUS;
}

function hexToBytes(value: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    fail("PROGRAM_IDENTITY_MISMATCH", "program code hash encoding is invalid");
  }
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function snapshotOptions(value: unknown): OwnedResolverOptions {
  if (!isObject(value)) fail("INVALID_CONFIG", "options must be an object");
  const rpcValue = value.rpc;
  const sessionSignerValue = value.sessionSigner;
  const programDataSlotValue = value.expectedWardenProgramDataSlot;
  const upgradeAuthorityValue = value.expectedWardenUpgradeAuthority;
  const codeHashValue = value.expectedWardenCodeHash;
  const programDataHashValue = value.expectedWardenProgramDataHash;
  const programDataBytesValue = value.expectedWardenProgramDataBytes;
  const localnetGenesisValue = value.localnetGenesisHash;
  if (!isObject(rpcValue)) {
    fail(
      "INVALID_CONFIG",
      "rpc must provide getGenesisHash() and getMultipleAccounts()",
    );
  }
  const getGenesisHashValue = rpcValue.getGenesisHash;
  const getMultipleAccountsValue = rpcValue.getMultipleAccounts;
  if (
    typeof getGenesisHashValue !== "function" ||
    typeof getMultipleAccountsValue !== "function"
  ) {
    fail(
      "INVALID_CONFIG",
      "rpc must provide getGenesisHash() and getMultipleAccounts()",
    );
  }
  const rpc: SessionAuthorityRpc = Object.freeze({
    getGenesisHash: getGenesisHashValue.bind(rpcValue) as () => Promise<string>,
    getMultipleAccounts: getMultipleAccountsValue.bind(
      rpcValue,
    ) as SessionAuthorityRpc["getMultipleAccounts"],
  });
  if (
    typeof programDataSlotValue !== "bigint" ||
    programDataSlotValue < 0n ||
    programDataSlotValue > U64_MAX
  ) {
    fail("INVALID_CONFIG", "expectedWardenProgramDataSlot must be a u64 bigint");
  }
  const expectedWardenCodeHash = requireBytes(
    codeHashValue,
    32,
    "expectedWardenCodeHash",
    "INVALID_CONFIG",
  );
  const expectedWardenProgramDataHash = requireBytes(
    programDataHashValue,
    32,
    "expectedWardenProgramDataHash",
    "INVALID_CONFIG",
  );
  if (allZero(expectedWardenCodeHash) || allZero(expectedWardenProgramDataHash)) {
    fail("INVALID_CONFIG", "expected program identity hashes must not be zero");
  }
  const sessionSigner = requirePublicKey(
    sessionSignerValue,
    "sessionSigner",
    "INVALID_CONFIG",
  );
  const expectedWardenUpgradeAuthority = requirePublicKey(
    upgradeAuthorityValue,
    "expectedWardenUpgradeAuthority",
    "INVALID_CONFIG",
  );
  if (
    allZero(sessionSigner.toBytes()) ||
    allZero(expectedWardenUpgradeAuthority.toBytes())
  ) {
    fail("INVALID_CONFIG", "session and upgrade authority keys must not be zero");
  }
  const expectedWardenProgramDataBytes = requireSafeNonNegativeInteger(
    programDataBytesValue,
    "expectedWardenProgramDataBytes",
    "INVALID_CONFIG",
  );
  if (
    expectedWardenProgramDataBytes <= PROGRAMDATA_METADATA_LEN ||
    expectedWardenProgramDataBytes > MAX_SOLANA_ACCOUNT_DATA_BYTES
  ) {
    fail(
      "INVALID_CONFIG",
      `expectedWardenProgramDataBytes must be ${PROGRAMDATA_METADATA_LEN + 1} to ${MAX_SOLANA_ACCOUNT_DATA_BYTES}`,
    );
  }
  let localnetGenesisHash: Uint8Array | undefined;
  if (localnetGenesisValue !== undefined) {
    localnetGenesisHash = requireBytes(
      localnetGenesisValue,
      32,
      "localnetGenesisHash",
      "INVALID_CONFIG",
    );
    if (allZero(localnetGenesisHash)) {
      fail("INVALID_CONFIG", "localnetGenesisHash must not be zero");
    }
  }
  return Object.freeze({
    rpc,
    sessionSigner,
    expectedWardenProgramDataSlot: programDataSlotValue,
    expectedWardenUpgradeAuthority,
    expectedWardenCodeHash,
    expectedWardenProgramDataHash,
    expectedWardenProgramDataBytes,
    localnetGenesisHash,
  });
}

function snapshotSelection(value: unknown): SessionAuthoritySelection {
  if (!isObject(value)) fail("INVALID_REQUEST", "selection must be an object");
  const accountValue = value.account;
  const chainValue = value.chain;
  if (typeof chainValue !== "string" || !CHAINS.has(chainValue)) {
    fail("INVALID_REQUEST", "selection chain is unsupported");
  }
  const accountBytes = requireBytes(
    accountValue,
    32,
    "selection account",
    "INVALID_REQUEST",
  );
  if (allZero(accountBytes)) {
    fail("INVALID_REQUEST", "selection account must not be zero");
  }
  return Object.freeze({
    account: accountBytes,
    chain: chainValue as ApprovalChain,
  });
}

function snapshotRpcAccount(
  value: unknown,
  address: PublicKey,
  role: string,
  expectedDataBytes: number,
): OwnedRpcAccount {
  if (value === null) {
    fail("ACCOUNT_MISSING", `${role} ${address.toBase58()} does not exist`);
  }
  if (!isObject(value)) {
    fail("RPC_RESPONSE_INVALID", `${role} response is not an account object`);
  }
  const ownerValue = value.owner;
  const executableValue = value.executable;
  const dataValue = value.data;
  const owner = requirePublicKey(
    ownerValue,
    `${role} owner`,
    "RPC_RESPONSE_INVALID",
  );
  if (typeof executableValue !== "boolean") {
    fail("RPC_RESPONSE_INVALID", `${role} executable flag is not boolean`);
  }
  // The exact bound is checked before a resolver-owned allocation is made.
  const data = requireBytes(
    dataValue,
    expectedDataBytes,
    `${role} data`,
    role === "Warden Program" || role === "Warden ProgramData"
      ? "PROGRAM_IDENTITY_MISMATCH"
      : role === "Clock sysvar"
        ? "CLOCK_INVALID"
        : "AUTHORITY_NOT_USABLE",
  );
  return { owner, executable: executableValue, data };
}

function requireStateContainer(account: OwnedRpcAccount, role: string): void {
  if (!account.owner.equals(WARDEN_PROGRAM) || account.executable) {
    fail(
      "AUTHORITY_NOT_USABLE",
      `${role} is not a non-executable account owned by the shipped Warden program`,
    );
  }
}

function expectedGenesisForChain(
  chain: ApprovalChain,
  localnetGenesisHash: Uint8Array | undefined,
): Uint8Array {
  if (chain === "solana:localnet") {
    if (localnetGenesisHash === undefined) {
      fail(
        "LOCALNET_GENESIS_UNPINNED",
        "localnet selection needs an explicit genesis hash pin",
      );
    }
    return localnetGenesisHash.slice();
  }
  return new PublicKey(SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES[chain]).toBytes();
}

function parseGenesisHash(value: unknown): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    fail("RPC_RESPONSE_INVALID", "getGenesisHash did not return a string");
  }
  let parsed: PublicKey;
  try {
    parsed = new PublicKey(value);
  } catch (error) {
    fail("RPC_RESPONSE_INVALID", "getGenesisHash returned malformed base58", error);
  }
  if (parsed.toBase58() !== value) {
    fail("RPC_RESPONSE_INVALID", "getGenesisHash returned noncanonical base58");
  }
  const bytes = parsed.toBytes();
  if (allZero(bytes)) {
    fail("RPC_RESPONSE_INVALID", "getGenesisHash returned the zero hash");
  }
  return bytes;
}

/** Canonical loader-v3 ProgramData PDA: seeds `[program_id]`. */
export function deriveWardenProgramDataAddress(
  program = WARDEN_PROGRAM,
): PublicKey {
  const programCopy = requirePublicKey(
    program,
    "warden program",
    "INVALID_REQUEST",
  );
  return PublicKey.findProgramAddressSync(
    [programCopy.toBytes()],
    BPF_UPGRADEABLE_LOADER,
  )[0];
}

/**
 * Small browser-safe adapter over web3.js. It performs no retries or endpoint
 * selection; those policy decisions belong to the future trusted RPC owner.
 */
export class ConnectionSessionAuthorityRpc implements SessionAuthorityRpc {
  readonly #getGenesisHash: Connection["getGenesisHash"];
  readonly #getMultipleAccountsInfoAndContext: Connection["getMultipleAccountsInfoAndContext"];

  constructor(connection: Connection) {
    if (!isObject(connection)) {
      fail("INVALID_CONFIG", "connection does not expose the required RPC methods");
    }
    const getGenesisHashValue = connection.getGenesisHash;
    const getMultipleAccountsInfoAndContextValue =
      connection.getMultipleAccountsInfoAndContext;
    if (
      typeof getGenesisHashValue !== "function" ||
      typeof getMultipleAccountsInfoAndContextValue !== "function"
    ) {
      fail("INVALID_CONFIG", "connection does not expose the required RPC methods");
    }
    this.#getGenesisHash = getGenesisHashValue.bind(connection);
    this.#getMultipleAccountsInfoAndContext =
      getMultipleAccountsInfoAndContextValue.bind(connection);
  }

  getGenesisHash(): Promise<string> {
    return this.#getGenesisHash();
  }

  async getMultipleAccounts(input: {
    readonly addresses: readonly PublicKey[];
    readonly commitment: typeof SESSION_APPROVAL_COMMITMENT;
    readonly minContextSlot: number;
  }): Promise<{
    readonly contextSlot: number;
    readonly accounts: readonly (SessionAuthorityRpcAccount | null)[];
  }> {
    if (!isObject(input)) {
      fail("INVALID_REQUEST", "connection account request is malformed");
    }
    const addressesValue = input.addresses;
    const commitmentValue = input.commitment;
    const minContextSlotValue = input.minContextSlot;
    if (!Array.isArray(addressesValue)) {
      fail("INVALID_REQUEST", "connection account request is malformed");
    }
    if (commitmentValue !== SESSION_APPROVAL_COMMITMENT) {
      fail("INVALID_REQUEST", "connection account request commitment is unsupported");
    }
    const minContextSlot = requireSafeNonNegativeInteger(
      minContextSlotValue,
      "minContextSlot",
      "INVALID_REQUEST",
    );
    const addresses = addressesValue.map((address, index) =>
      requirePublicKey(address, `addresses[${index}]`, "INVALID_REQUEST"),
    );
    const response = await this.#getMultipleAccountsInfoAndContext(
      addresses,
      { commitment: SESSION_APPROVAL_COMMITMENT, minContextSlot },
    );
    const contextValue = response.context;
    const accountsValue = response.value;
    if (!isObject(contextValue) || !Array.isArray(accountsValue)) {
      fail("RPC_RESPONSE_INVALID", "web3 account response is malformed");
    }
    const contextSlot = requireSafeNonNegativeInteger(
      contextValue.slot,
      "web3 response context slot",
      "RPC_RESPONSE_INVALID",
    );
    if (accountsValue.length !== addresses.length) {
      fail("RPC_RESPONSE_INVALID", "web3 account response length changed");
    }
    const accounts = accountsValue.map((value, index) => {
      if (value === null) return null;
      const ownerValue = value.owner;
      const executableValue = value.executable;
      const dataValue = value.data;
      if (
        typeof executableValue !== "boolean" ||
        !(dataValue instanceof Uint8Array) ||
        dataValue.length > MAX_SOLANA_ACCOUNT_DATA_BYTES
      ) {
        fail("RPC_RESPONSE_INVALID", `web3 account ${index} is malformed`);
      }
      return {
        owner: requirePublicKey(
          ownerValue,
          `web3 account ${index} owner`,
          "RPC_RESPONSE_INVALID",
        ),
        executable: executableValue,
        data: Uint8Array.from(dataValue),
      };
    });
    return { contextSlot, accounts };
  }
}

export class PinnedSessionAuthorityResolver
  implements SessionApprovalAuthorityResolver
{
  readonly #options: OwnedResolverOptions;

  constructor(options: PinnedSessionAuthorityResolverOptions) {
    this.#options = snapshotOptions(options);
  }

  async resolve(inputValue: {
    readonly selection: SessionAuthoritySelection;
    readonly commitment: typeof SESSION_APPROVAL_COMMITMENT;
    readonly minContextSlot: number;
  }): Promise<SessionAuthoritySnapshot> {
    if (!isObject(inputValue)) fail("INVALID_REQUEST", "request must be an object");
    const selectionValue = inputValue.selection;
    const commitmentValue = inputValue.commitment;
    const minContextSlotValue = inputValue.minContextSlot;
    if (commitmentValue !== SESSION_APPROVAL_COMMITMENT) {
      fail("INVALID_REQUEST", "only confirmed commitment is supported");
    }
    const minContextSlot = requireSafeNonNegativeInteger(
      minContextSlotValue,
      "minContextSlot",
      "INVALID_REQUEST",
    );
    const selection = snapshotSelection(selectionValue);
    const expectedGenesisHash = expectedGenesisForChain(
      selection.chain,
      this.#options.localnetGenesisHash,
    );

    let genesisResponse: unknown;
    try {
      genesisResponse = await this.#options.rpc.getGenesisHash();
    } catch (error) {
      if (error instanceof SessionAuthorityResolverError) throw error;
      fail("RPC_UNAVAILABLE", "getGenesisHash failed", error);
    }
    const genesisHash = parseGenesisHash(genesisResponse);
    if (!bytesEqual(genesisHash, expectedGenesisHash)) {
      fail(
        "GENESIS_MISMATCH",
        `RPC genesis ${new PublicKey(genesisHash).toBase58()} does not match ${selection.chain}`,
      );
    }

    const smartAccount = new PublicKey(selection.account);
    const sessionSigner = new PublicKey(this.#options.sessionSigner.toBytes());
    const [sessionAccount] = PublicKey.findProgramAddressSync(
      [SESSION_SEED, smartAccount.toBytes(), sessionSigner.toBytes()],
      WARDEN_PROGRAM,
    );
    const [registry] = PublicKey.findProgramAddressSync(
      [REGISTRY_SEED],
      WARDEN_PROGRAM,
    );
    const wardenProgramData = deriveWardenProgramDataAddress(WARDEN_PROGRAM);
    const addresses = [
      smartAccount,
      sessionAccount,
      registry,
      WARDEN_PROGRAM,
      wardenProgramData,
      SYSVAR_CLOCK_PUBKEY,
    ] as const;

    let response: unknown;
    try {
      response = await this.#options.rpc.getMultipleAccounts({
        addresses: addresses.map((address) => new PublicKey(address.toBytes())),
        commitment: SESSION_APPROVAL_COMMITMENT,
        minContextSlot,
      });
    } catch (error) {
      if (error instanceof SessionAuthorityResolverError) throw error;
      fail("RPC_UNAVAILABLE", "getMultipleAccounts failed", error);
    }
    if (!isObject(response)) {
      fail("RPC_RESPONSE_INVALID", "getMultipleAccounts response is not an object");
    }
    const contextSlotValue = response.contextSlot;
    const accountsValue = response.accounts;
    const contextSlot = requireSafeNonNegativeInteger(
      contextSlotValue,
      "account response context slot",
      "RPC_RESPONSE_INVALID",
    );
    if (contextSlot < minContextSlot) {
      fail("RPC_RESPONSE_INVALID", "account response context regressed");
    }
    if (
      !Array.isArray(accountsValue) ||
      accountsValue.length !== SESSION_AUTHORITY_ACCOUNT_COUNT
    ) {
      fail(
        "RPC_RESPONSE_INVALID",
        `account response must contain ${SESSION_AUTHORITY_ACCOUNT_COUNT} ordered entries`,
      );
    }

    const smart = snapshotRpcAccount(
      accountsValue[0],
      smartAccount,
      "SmartAccount",
      SMART_ACCOUNT_DATA_BYTES,
    );
    const session = snapshotRpcAccount(
      accountsValue[1],
      sessionAccount,
      "SessionKey",
      SESSION_ACCOUNT_DATA_BYTES,
    );
    const registryAccount = snapshotRpcAccount(
      accountsValue[2],
      registry,
      "Registry",
      REGISTRY_ACCOUNT_DATA_BYTES,
    );
    const program = snapshotRpcAccount(
      accountsValue[3],
      WARDEN_PROGRAM,
      "Warden Program",
      PROGRAM_ACCOUNT_DATA_BYTES,
    );
    const programData = snapshotRpcAccount(
      accountsValue[4],
      wardenProgramData,
      "Warden ProgramData",
      this.#options.expectedWardenProgramDataBytes,
    );
    const clock = snapshotRpcAccount(
      accountsValue[5],
      SYSVAR_CLOCK_PUBKEY,
      "Clock sysvar",
      CLOCK_ACCOUNT_DATA_BYTES,
    );

    requireStateContainer(smart, "SmartAccount");
    requireStateContainer(session, "SessionKey");
    requireStateContainer(registryAccount, "Registry");

    if (
      !program.owner.equals(BPF_UPGRADEABLE_LOADER) ||
      !program.executable
    ) {
      fail(
        "PROGRAM_IDENTITY_MISMATCH",
        "Warden Program is not executable loader-v3 state",
      );
    }
    let decodedProgram: ReturnType<typeof decodeProgramAccount>;
    try {
      decodedProgram = decodeProgramAccount(program.data);
    } catch (error) {
      fail("PROGRAM_IDENTITY_MISMATCH", "Warden Program state is invalid", error);
    }
    if (!decodedProgram.programDataAddress.equals(wardenProgramData)) {
      fail(
        "PROGRAM_IDENTITY_MISMATCH",
        "Warden Program points at a substituted ProgramData account",
      );
    }

    if (
      !programData.owner.equals(BPF_UPGRADEABLE_LOADER) ||
      programData.executable
    ) {
      fail(
        "PROGRAM_IDENTITY_MISMATCH",
        "Warden ProgramData is not non-executable loader-v3 state",
      );
    }
    let decodedProgramData: ReturnType<typeof decodeProgramDataAccount>;
    try {
      decodedProgramData = decodeProgramDataAccount(programData.data);
    } catch (error) {
      fail("PROGRAM_IDENTITY_MISMATCH", "Warden ProgramData state is invalid", error);
    }
    if (
      decodedProgramData.slot !== this.#options.expectedWardenProgramDataSlot ||
      decodedProgramData.upgradeAuthority === null ||
      !decodedProgramData.upgradeAuthority.equals(
        this.#options.expectedWardenUpgradeAuthority,
      )
    ) {
      fail(
        "PROGRAM_IDENTITY_MISMATCH",
        "Warden ProgramData slot or upgrade authority differs from the release pin",
      );
    }
    const wardenCodeHash = hexToBytes(decodedProgramData.codeHashHex);
    const wardenProgramDataHash = sha256(programData.data);
    if (
      !bytesEqual(wardenCodeHash, this.#options.expectedWardenCodeHash) ||
      !bytesEqual(
        wardenProgramDataHash,
        this.#options.expectedWardenProgramDataHash,
      )
    ) {
      fail(
        "PROGRAM_IDENTITY_MISMATCH",
        "Warden code or full ProgramData hash differs from the release pin",
      );
    }

    if (!clock.owner.equals(SYSVAR_OWNER) || clock.executable) {
      fail("CLOCK_INVALID", "Clock is not a canonical non-executable sysvar");
    }
    const clockSlotValue = readU64le(clock.data, 0);
    if (clockSlotValue > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail("CLOCK_INVALID", "Clock slot is outside the safe integer range");
    }
    const clockSlot = Number(clockSlotValue);
    if (clockSlot !== contextSlot) {
      fail("CLOCK_INVALID", "Clock slot does not equal the account response context");
    }
    const timestampValue = readI64le(clock.data, 32);
    if (
      timestampValue < 0n ||
      timestampValue >
        BigInt(Number.MAX_SAFE_INTEGER - SESSION_AUTHORITY_CLOCK_SAFETY_SECONDS)
    ) {
      fail("CLOCK_INVALID", "Clock unix_timestamp is outside the usable range");
    }
    const observedUnixTimestamp = Number(timestampValue);

    const authorizationState = encodeSessionAuthorizationState({
      smartAccount: smart,
      session,
      registry: registryAccount,
    });
    const snapshot: SessionAuthoritySnapshot = Object.freeze({
      chain: selection.chain,
      genesisHash: genesisHash.slice(),
      smartAccount,
      sessionSigner,
      sessionAccount,
      registry,
      wardenProgram: new PublicKey(WARDEN_PROGRAM.toBytes()),
      wardenProgramData,
      wardenProgramDataSlot: decodedProgramData.slot,
      wardenUpgradeAuthority: new PublicKey(
        decodedProgramData.upgradeAuthority.toBytes(),
      ),
      wardenCodeHash,
      wardenProgramDataHash,
      accountGeneration: readU64le(smart.data, 528),
      policyVersion: readU32le(smart.data, 560),
      authorizationState,
      observedUnixTimestamp,
      contextSlot,
    });
    try {
      assertUsableSessionAuthority({
        authority: snapshot,
        nowUnixSeconds:
          observedUnixTimestamp + SESSION_AUTHORITY_CLOCK_SAFETY_SECONDS,
      });
    } catch (error) {
      if (error instanceof SessionIntentError) {
        fail(
          "AUTHORITY_NOT_USABLE",
          "Warden account/session/registry observation is not usable",
          error,
        );
      }
      throw error;
    }
    return snapshot;
  }
}
