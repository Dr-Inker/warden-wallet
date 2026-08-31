//! Still-unreachable C6 Connection-bound RPC and composition boundary.
//!
//! web3.js's `getLatestBlockhash()` convenience method discards the response
//! context. Session approval needs that bank slot, so this adapter uses only
//! `getLatestBlockhashAndContext()` and `isBlockhashValid()`, always at the
//! coordinator's fixed confirmed commitment and non-regressing minimum slot.
//! Every operation first rechecks the configured Connection's genesis hash.
//!
//! The factory at the bottom is deliberately opt-in. It captures one trusted
//! Connection capability set, requires every release/program pin, installs the
//! real authority resolver and deterministic intent gate, and returns the real
//! coordinator. No extension source imports this module and it adds no provider
//! route, approval page, sender, confirmation owner, or result replay.

import { PublicKey, type Connection } from "@solana/web3.js";

import type { ApprovalChain } from "../approval/record.js";
import { PROGRAMDATA_METADATA_LEN } from "../deploy/accounts.js";
import {
  SESSION_APPROVAL_COMMITMENT,
  SessionApprovalCoordinator,
  type SessionApprovalAuthorityResolver,
  type SessionApprovalBlockhashClient,
  type SessionApprovalIntentGate,
  type SessionApprovalKeyring,
  type SessionApprovalOwner,
} from "./session-approval-coordinator.js";
import {
  ConnectionSessionAuthorityRpc,
  PinnedSessionAuthorityResolver,
  SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES,
  SESSION_AUTHORITY_WARDEN_PROGRAM_ID,
} from "./session-authority-resolver.js";
import { DeterministicSessionIntentGate } from "./session-intent.js";

const HASH_BYTES = 32;
const U64_MAX = 0xffff_ffff_ffff_ffffn;
const MAX_SOLANA_ACCOUNT_DATA_BYTES = 10 * 1_024 * 1_024;
const CHAINS: ReadonlySet<string> = new Set([
  ...Object.keys(SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES),
  "solana:localnet",
]);
const WARDEN_PROGRAM = new PublicKey(SESSION_AUTHORITY_WARDEN_PROGRAM_ID);
const DETERMINISTIC_INTENT_ASSERT_ALLOWED =
  DeterministicSessionIntentGate.prototype.assertAllowed;

export type SessionApprovalRpcErrorCode =
  | "INVALID_CONFIG"
  | "INVALID_REQUEST"
  | "CHAIN_MISMATCH"
  | "GENESIS_MISMATCH"
  | "RPC_UNAVAILABLE"
  | "RPC_RESPONSE_INVALID";

export class SessionApprovalRpcError extends Error {
  readonly code: SessionApprovalRpcErrorCode;

  constructor(
    code: SessionApprovalRpcErrorCode,
    message: string,
    options: ErrorOptions = {},
  ) {
    super(`session approval RPC: ${message}`, options);
    this.name = "SessionApprovalRpcError";
    this.code = code;
  }
}

export interface ConnectionSessionApprovalBlockhashClientOptions {
  /** Explicitly trusted endpoint capability; no URL/default is selected here. */
  readonly trustedConnection: Connection;
  /** One adapter instance is permanently bound to exactly one chain. */
  readonly chain: ApprovalChain;
  /** Exact expected endpoint genesis; public chains must use canonical pins. */
  readonly genesisHash: Uint8Array;
}

export interface SessionApprovalReleasePins {
  readonly chain: ApprovalChain;
  readonly genesisHash: Uint8Array;
  /** Must equal the literal Warden program shipped by this client build. */
  readonly wardenProgram: PublicKey;
  readonly wardenProgramDataSlot: bigint;
  readonly wardenUpgradeAuthority: PublicKey;
  readonly wardenCodeHash: Uint8Array;
  readonly wardenProgramDataHash: Uint8Array;
  readonly wardenProgramDataBytes: number;
}

export interface PinnedSessionApprovalCompositionOptions {
  readonly trustedConnection: Connection;
  readonly releasePins: SessionApprovalReleasePins;
  /** Public half of the currently unlocked, AAD-bound session key. */
  readonly sessionSigner: PublicKey;
  readonly approvals: SessionApprovalOwner;
  readonly keyring: SessionApprovalKeyring;
  readonly readNow?: () => number;
  readonly approvalTtlMs?: number;
}

interface ChainIdentity {
  readonly chain: ApprovalChain;
  readonly genesisHash: Uint8Array;
}

interface BlockhashRequestSnapshot extends ChainIdentity {
  readonly minContextSlot: number;
}

interface ValidityRequestSnapshot extends BlockhashRequestSnapshot {
  readonly blockhash: Uint8Array;
}

interface BoundConnectionMethods {
  readonly getGenesisHash: Connection["getGenesisHash"];
  readonly getLatestBlockhashAndContext: Connection["getLatestBlockhashAndContext"];
  readonly isBlockhashValid: Connection["isBlockhashValid"];
}

interface OwnedReleasePins extends ChainIdentity {
  readonly wardenProgram: PublicKey;
  readonly wardenProgramDataSlot: bigint;
  readonly wardenUpgradeAuthority: PublicKey;
  readonly wardenCodeHash: Uint8Array;
  readonly wardenProgramDataHash: Uint8Array;
  readonly wardenProgramDataBytes: number;
}

function fail(
  code: SessionApprovalRpcErrorCode,
  message: string,
  cause?: unknown,
): never {
  throw new SessionApprovalRpcError(
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
  code: SessionApprovalRpcErrorCode,
): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(code, `${label} must contain exactly ${length} bytes`);
  }
  return Uint8Array.from(value);
}

function requirePublicKey(
  value: unknown,
  label: string,
  code: SessionApprovalRpcErrorCode,
): PublicKey {
  try {
    if (!(value instanceof PublicKey)) fail(code, `${label} must be a PublicKey`);
    return new PublicKey(value.toBytes());
  } catch (error) {
    if (error instanceof SessionApprovalRpcError) throw error;
    fail(code, `${label} is malformed`, error);
  }
}

function requireSafeNonNegativeInteger(
  value: unknown,
  label: string,
  code: SessionApprovalRpcErrorCode,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    fail(code, `${label} must be a non-negative safe integer`);
  }
  return value as number;
}

function parseCanonicalHash(
  value: unknown,
  label: string,
  code: SessionApprovalRpcErrorCode,
): Uint8Array {
  if (typeof value !== "string") fail(code, `${label} must be a base58 string`);
  let parsed: PublicKey;
  try {
    parsed = new PublicKey(value);
  } catch (error) {
    fail(code, `${label} is malformed base58`, error);
  }
  if (parsed.toBase58() !== value) fail(code, `${label} is noncanonical base58`);
  const bytes = parsed.toBytes();
  if (allZero(bytes)) fail(code, `${label} must not be zero`);
  return bytes;
}

function expectedPublicGenesis(chain: ApprovalChain): Uint8Array | undefined {
  if (chain === "solana:localnet") return undefined;
  const value = SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES[
    chain as keyof typeof SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES
  ];
  return value === undefined ? undefined : new PublicKey(value).toBytes();
}

function snapshotChainIdentity(
  chainValue: unknown,
  genesisValue: unknown,
  code: SessionApprovalRpcErrorCode,
): ChainIdentity {
  if (typeof chainValue !== "string" || !CHAINS.has(chainValue)) {
    fail(code, "chain is unsupported");
  }
  const chain = chainValue as ApprovalChain;
  const genesisHash = requireBytes(genesisValue, HASH_BYTES, "genesisHash", code);
  if (allZero(genesisHash)) fail(code, "genesisHash must not be zero");
  const publicPin = expectedPublicGenesis(chain);
  if (publicPin !== undefined && !bytesEqual(genesisHash, publicPin)) {
    genesisHash.fill(0);
    fail(code, `${chain} genesisHash does not equal the canonical public pin`);
  }
  return Object.freeze({ chain, genesisHash });
}

function bindBlockhashConnection(value: unknown): BoundConnectionMethods {
  if (!isObject(value)) {
    fail("INVALID_CONFIG", "trustedConnection must expose contextual RPC methods");
  }
  try {
    const getGenesisHash = value.getGenesisHash;
    const getLatestBlockhashAndContext = value.getLatestBlockhashAndContext;
    const isBlockhashValid = value.isBlockhashValid;
    if (
      typeof getGenesisHash !== "function" ||
      typeof getLatestBlockhashAndContext !== "function" ||
      typeof isBlockhashValid !== "function"
    ) {
      fail("INVALID_CONFIG", "trustedConnection must expose contextual RPC methods");
    }
    return Object.freeze({
      getGenesisHash: getGenesisHash.bind(value) as Connection["getGenesisHash"],
      getLatestBlockhashAndContext: getLatestBlockhashAndContext.bind(
        value,
      ) as Connection["getLatestBlockhashAndContext"],
      isBlockhashValid: isBlockhashValid.bind(
        value,
      ) as Connection["isBlockhashValid"],
    });
  } catch (error) {
    if (error instanceof SessionApprovalRpcError) throw error;
    fail("INVALID_CONFIG", "trustedConnection capability access failed", error);
  }
}

function snapshotClientOptions(
  value: unknown,
): { readonly identity: ChainIdentity; readonly methods: BoundConnectionMethods } {
  if (!isObject(value)) fail("INVALID_CONFIG", "options must be an object");
  try {
    const connectionValue = value.trustedConnection;
    const methods = bindBlockhashConnection(connectionValue);
    const chainValue = value.chain;
    const genesisValue = value.genesisHash;
    return Object.freeze({
      identity: snapshotChainIdentity(
        chainValue,
        genesisValue,
        "INVALID_CONFIG",
      ),
      methods,
    });
  } catch (error) {
    if (error instanceof SessionApprovalRpcError) throw error;
    fail("INVALID_CONFIG", "options access failed", error);
  }
}

function snapshotRequestFields(
  value: unknown,
  expected: ChainIdentity,
): BlockhashRequestSnapshot {
  if (!isObject(value)) fail("INVALID_REQUEST", "request must be an object");
  try {
    const chainValue = value.chain;
    if (chainValue !== expected.chain) {
      fail("CHAIN_MISMATCH", "request chain differs from the bound Connection chain");
    }
    const genesisValue = value.genesisHash;
    const genesisHash = requireBytes(
      genesisValue,
      HASH_BYTES,
      "request genesisHash",
      "INVALID_REQUEST",
    );
    if (!bytesEqual(genesisHash, expected.genesisHash)) {
      genesisHash.fill(0);
      fail("GENESIS_MISMATCH", "request genesis differs from the bound Connection genesis");
    }
    const commitmentValue = value.commitment;
    if (commitmentValue !== SESSION_APPROVAL_COMMITMENT) {
      genesisHash.fill(0);
      fail("INVALID_REQUEST", "only confirmed commitment is supported");
    }
    const minContextSlotValue = value.minContextSlot;
    const minContextSlot = requireSafeNonNegativeInteger(
      minContextSlotValue,
      "minContextSlot",
      "INVALID_REQUEST",
    );
    return Object.freeze({
      chain: expected.chain,
      genesisHash,
      minContextSlot,
    });
  } catch (error) {
    if (error instanceof SessionApprovalRpcError) throw error;
    fail("INVALID_REQUEST", "request property access failed", error);
  }
}

function snapshotLatestResponse(
  value: unknown,
  minContextSlot: number,
): {
  readonly blockhash: Uint8Array;
  readonly lastValidBlockHeight: number;
  readonly contextSlot: number;
} {
  if (!isObject(value)) fail("RPC_RESPONSE_INVALID", "latest response is malformed");
  try {
    const contextValue = value.context;
    if (!isObject(contextValue)) {
      fail("RPC_RESPONSE_INVALID", "latest response context is malformed");
    }
    const slotValue = contextValue.slot;
    const contextSlot = requireSafeNonNegativeInteger(
      slotValue,
      "latest response context slot",
      "RPC_RESPONSE_INVALID",
    );
    if (contextSlot < minContextSlot) {
      fail("RPC_RESPONSE_INVALID", "latest response context regressed below minContextSlot");
    }
    const resultValue = value.value;
    if (!isObject(resultValue)) {
      fail("RPC_RESPONSE_INVALID", "latest response value is malformed");
    }
    const blockhashValue = resultValue.blockhash;
    const blockhash = parseCanonicalHash(
      blockhashValue,
      "latest blockhash",
      "RPC_RESPONSE_INVALID",
    );
    const lastValidBlockHeightValue = resultValue.lastValidBlockHeight;
    const lastValidBlockHeight = requireSafeNonNegativeInteger(
      lastValidBlockHeightValue,
      "lastValidBlockHeight",
      "RPC_RESPONSE_INVALID",
    );
    return Object.freeze({ blockhash, lastValidBlockHeight, contextSlot });
  } catch (error) {
    if (error instanceof SessionApprovalRpcError) throw error;
    fail("RPC_RESPONSE_INVALID", "latest response property access failed", error);
  }
}

function snapshotValidityResponse(
  value: unknown,
  minContextSlot: number,
): { readonly valid: boolean; readonly contextSlot: number } {
  if (!isObject(value)) fail("RPC_RESPONSE_INVALID", "validity response is malformed");
  try {
    const contextValue = value.context;
    if (!isObject(contextValue)) {
      fail("RPC_RESPONSE_INVALID", "validity response context is malformed");
    }
    const slotValue = contextValue.slot;
    const contextSlot = requireSafeNonNegativeInteger(
      slotValue,
      "validity response context slot",
      "RPC_RESPONSE_INVALID",
    );
    if (contextSlot < minContextSlot) {
      fail("RPC_RESPONSE_INVALID", "validity response context regressed below minContextSlot");
    }
    const validityValue = value.value;
    if (typeof validityValue !== "boolean") {
      fail("RPC_RESPONSE_INVALID", "validity response value is malformed");
    }
    return Object.freeze({ valid: validityValue, contextSlot });
  } catch (error) {
    if (error instanceof SessionApprovalRpcError) throw error;
    fail("RPC_RESPONSE_INVALID", "validity response property access failed", error);
  }
}

/**
 * Exact contextual blockhash adapter over one explicitly trusted Connection.
 * It never retries, switches endpoints, refreshes an approved hash, or sends.
 */
export class ConnectionSessionApprovalBlockhashClient
  implements SessionApprovalBlockhashClient
{
  readonly #identity: ChainIdentity;
  readonly #getGenesisHash: Connection["getGenesisHash"];
  readonly #getLatestBlockhashAndContext: Connection["getLatestBlockhashAndContext"];
  readonly #isBlockhashValid: Connection["isBlockhashValid"];

  constructor(options: ConnectionSessionApprovalBlockhashClientOptions) {
    const snapshot = snapshotClientOptions(options);
    this.#identity = snapshot.identity;
    this.#getGenesisHash = snapshot.methods.getGenesisHash;
    this.#getLatestBlockhashAndContext =
      snapshot.methods.getLatestBlockhashAndContext;
    this.#isBlockhashValid = snapshot.methods.isBlockhashValid;
  }

  async #assertEndpointGenesis(): Promise<void> {
    let response: unknown;
    try {
      response = await this.#getGenesisHash();
    } catch (error) {
      fail("RPC_UNAVAILABLE", "getGenesisHash failed", error);
    }
    const actual = parseCanonicalHash(
      response,
      "endpoint genesis hash",
      "RPC_RESPONSE_INVALID",
    );
    if (!bytesEqual(actual, this.#identity.genesisHash)) {
      actual.fill(0);
      fail("GENESIS_MISMATCH", "endpoint genesis changed from the configured pin");
    }
    actual.fill(0);
  }

  async getLatestBlockhash(inputValue: {
    readonly chain: ApprovalChain;
    readonly genesisHash: Uint8Array;
    readonly commitment: typeof SESSION_APPROVAL_COMMITMENT;
    readonly minContextSlot: number;
  }): Promise<{
    readonly blockhash: Uint8Array;
    readonly lastValidBlockHeight: number;
    readonly contextSlot: number;
  }> {
    const input = snapshotRequestFields(inputValue, this.#identity);
    try {
      await this.#assertEndpointGenesis();
      let response: unknown;
      try {
        response = await this.#getLatestBlockhashAndContext({
          commitment: SESSION_APPROVAL_COMMITMENT,
          minContextSlot: input.minContextSlot,
        });
      } catch (error) {
        fail("RPC_UNAVAILABLE", "getLatestBlockhash failed", error);
      }
      return snapshotLatestResponse(response, input.minContextSlot);
    } finally {
      input.genesisHash.fill(0);
    }
  }

  async isBlockhashValid(inputValue: {
    readonly chain: ApprovalChain;
    readonly genesisHash: Uint8Array;
    readonly blockhash: Uint8Array;
    readonly commitment: typeof SESSION_APPROVAL_COMMITMENT;
    readonly minContextSlot: number;
  }): Promise<{ readonly valid: boolean; readonly contextSlot: number }> {
    const base = snapshotRequestFields(inputValue, this.#identity);
    let blockhash: Uint8Array;
    try {
      const blockhashValue = (inputValue as unknown as Record<string, unknown>)
        .blockhash;
      blockhash = requireBytes(
        blockhashValue,
        HASH_BYTES,
        "blockhash",
        "INVALID_REQUEST",
      );
      if (allZero(blockhash)) {
        blockhash.fill(0);
        fail("INVALID_REQUEST", "blockhash must not be zero");
      }
    } catch (error) {
      base.genesisHash.fill(0);
      if (error instanceof SessionApprovalRpcError) throw error;
      fail("INVALID_REQUEST", "blockhash property access failed", error);
    }
    const input: ValidityRequestSnapshot = Object.freeze({
      ...base,
      blockhash,
    });
    const blockhashString = new PublicKey(input.blockhash).toBase58();
    try {
      await this.#assertEndpointGenesis();
      let response: unknown;
      try {
        response = await this.#isBlockhashValid(blockhashString, {
          commitment: SESSION_APPROVAL_COMMITMENT,
          minContextSlot: input.minContextSlot,
        });
      } catch (error) {
        fail("RPC_UNAVAILABLE", "isBlockhashValid failed", error);
      }
      return snapshotValidityResponse(response, input.minContextSlot);
    } finally {
      input.genesisHash.fill(0);
      input.blockhash.fill(0);
    }
  }
}

// Capture the shipped implementations during module initialization. The
// composition factory exposes only frozen bound capabilities, so later edits
// to these exported class prototypes cannot redirect an active coordinator.
const PINNED_BLOCKHASH_GET_LATEST =
  ConnectionSessionApprovalBlockhashClient.prototype.getLatestBlockhash;
const PINNED_BLOCKHASH_IS_VALID =
  ConnectionSessionApprovalBlockhashClient.prototype.isBlockhashValid;

function bindInternalBlockhashClient(
  owner: ConnectionSessionApprovalBlockhashClient,
): SessionApprovalBlockhashClient {
  return Object.freeze({
    getLatestBlockhash: PINNED_BLOCKHASH_GET_LATEST.bind(owner),
    isBlockhashValid: PINNED_BLOCKHASH_IS_VALID.bind(owner),
  });
}

function createInternalIntentGate(): SessionApprovalIntentGate {
  const owner = new DeterministicSessionIntentGate();
  return Object.freeze({
    assertAllowed: DETERMINISTIC_INTENT_ASSERT_ALLOWED.bind(owner),
  });
}

function snapshotAllConnectionCapabilities(value: unknown): Connection {
  if (!isObject(value)) {
    fail("INVALID_CONFIG", "trustedConnection must expose all required RPC methods");
  }
  try {
    const getGenesisHash = value.getGenesisHash;
    const getMultipleAccountsInfoAndContext =
      value.getMultipleAccountsInfoAndContext;
    const getLatestBlockhashAndContext = value.getLatestBlockhashAndContext;
    const isBlockhashValid = value.isBlockhashValid;
    if (
      typeof getGenesisHash !== "function" ||
      typeof getMultipleAccountsInfoAndContext !== "function" ||
      typeof getLatestBlockhashAndContext !== "function" ||
      typeof isBlockhashValid !== "function"
    ) {
      fail("INVALID_CONFIG", "trustedConnection must expose all required RPC methods");
    }
    return Object.freeze({
      getGenesisHash: getGenesisHash.bind(value),
      getMultipleAccountsInfoAndContext:
        getMultipleAccountsInfoAndContext.bind(value),
      getLatestBlockhashAndContext: getLatestBlockhashAndContext.bind(value),
      isBlockhashValid: isBlockhashValid.bind(value),
    }) as unknown as Connection;
  } catch (error) {
    if (error instanceof SessionApprovalRpcError) throw error;
    fail("INVALID_CONFIG", "trustedConnection capability access failed", error);
  }
}

function snapshotReleasePins(value: unknown): OwnedReleasePins {
  if (!isObject(value)) fail("INVALID_CONFIG", "releasePins must be an object");
  try {
    const chainValue = value.chain;
    const genesisHashValue = value.genesisHash;
    const identity = snapshotChainIdentity(
      chainValue,
      genesisHashValue,
      "INVALID_CONFIG",
    );
    const wardenProgramValue = value.wardenProgram;
    const wardenProgram = requirePublicKey(
      wardenProgramValue,
      "releasePins.wardenProgram",
      "INVALID_CONFIG",
    );
    if (!wardenProgram.equals(WARDEN_PROGRAM)) {
      fail("INVALID_CONFIG", "releasePins.wardenProgram differs from the shipped literal");
    }
    const programDataSlotValue = value.wardenProgramDataSlot;
    if (
      typeof programDataSlotValue !== "bigint" ||
      programDataSlotValue < 0n ||
      programDataSlotValue > U64_MAX
    ) {
      fail("INVALID_CONFIG", "releasePins.wardenProgramDataSlot must be a u64 bigint");
    }
    const upgradeAuthorityValue = value.wardenUpgradeAuthority;
    const wardenUpgradeAuthority = requirePublicKey(
      upgradeAuthorityValue,
      "releasePins.wardenUpgradeAuthority",
      "INVALID_CONFIG",
    );
    if (allZero(wardenUpgradeAuthority.toBytes())) {
      fail("INVALID_CONFIG", "releasePins.wardenUpgradeAuthority must not be zero");
    }
    const codeHashValue = value.wardenCodeHash;
    const wardenCodeHash = requireBytes(
      codeHashValue,
      HASH_BYTES,
      "releasePins.wardenCodeHash",
      "INVALID_CONFIG",
    );
    if (allZero(wardenCodeHash)) {
      fail("INVALID_CONFIG", "releasePins.wardenCodeHash must not be zero");
    }
    const programDataHashValue = value.wardenProgramDataHash;
    const wardenProgramDataHash = requireBytes(
      programDataHashValue,
      HASH_BYTES,
      "releasePins.wardenProgramDataHash",
      "INVALID_CONFIG",
    );
    if (allZero(wardenProgramDataHash)) {
      fail("INVALID_CONFIG", "releasePins.wardenProgramDataHash must not be zero");
    }
    const programDataBytesValue = value.wardenProgramDataBytes;
    const wardenProgramDataBytes = requireSafeNonNegativeInteger(
      programDataBytesValue,
      "releasePins.wardenProgramDataBytes",
      "INVALID_CONFIG",
    );
    if (
      wardenProgramDataBytes <= PROGRAMDATA_METADATA_LEN ||
      wardenProgramDataBytes > MAX_SOLANA_ACCOUNT_DATA_BYTES
    ) {
      fail(
        "INVALID_CONFIG",
        `releasePins.wardenProgramDataBytes must be ${PROGRAMDATA_METADATA_LEN + 1} to ${MAX_SOLANA_ACCOUNT_DATA_BYTES}`,
      );
    }
    return Object.freeze({
      ...identity,
      wardenProgram,
      wardenProgramDataSlot: programDataSlotValue,
      wardenUpgradeAuthority,
      wardenCodeHash,
      wardenProgramDataHash,
      wardenProgramDataBytes,
    });
  } catch (error) {
    if (error instanceof SessionApprovalRpcError) throw error;
    fail("INVALID_CONFIG", "releasePins property access failed", error);
  }
}

function bindApprovalOwner(value: unknown): SessionApprovalOwner {
  if (!isObject(value)) fail("INVALID_CONFIG", "approvals must be an object");
  try {
    const create = value.create;
    const read = value.read;
    const claimForSigning = value.claimForSigning;
    const reject = value.reject;
    const cancel = value.cancel;
    if (
      typeof create !== "function" ||
      typeof read !== "function" ||
      typeof claimForSigning !== "function" ||
      typeof reject !== "function" ||
      typeof cancel !== "function"
    ) {
      fail("INVALID_CONFIG", "approvals does not expose the required owner methods");
    }
    return Object.freeze({
      create: create.bind(value),
      read: read.bind(value),
      claimForSigning: claimForSigning.bind(value),
      reject: reject.bind(value),
      cancel: cancel.bind(value),
    }) as SessionApprovalOwner;
  } catch (error) {
    if (error instanceof SessionApprovalRpcError) throw error;
    fail("INVALID_CONFIG", "approvals capability access failed", error);
  }
}

function bindKeyring(value: unknown): SessionApprovalKeyring {
  if (!isObject(value)) fail("INVALID_CONFIG", "keyring must be an object");
  try {
    const useSessionSignerBytes = value.useSessionSignerBytes;
    if (typeof useSessionSignerBytes !== "function") {
      fail("INVALID_CONFIG", "keyring does not expose useSessionSignerBytes()");
    }
    return Object.freeze({
      useSessionSignerBytes: useSessionSignerBytes.bind(value),
    }) as SessionApprovalKeyring;
  } catch (error) {
    if (error instanceof SessionApprovalRpcError) throw error;
    fail("INVALID_CONFIG", "keyring capability access failed", error);
  }
}

/**
 * Construct the complete, still-unreachable Memo-only approval substrate from
 * one trusted Connection and a complete release pin set. Review provenance for
 * those pins is an external release-process trust terminus; this function can
 * validate exact shape and identity but cannot prove that a human reviewed it.
 */
export function createPinnedSessionApprovalCoordinator(
  optionsValue: PinnedSessionApprovalCompositionOptions,
): SessionApprovalCoordinator {
  if (!isObject(optionsValue)) fail("INVALID_CONFIG", "options must be an object");
  try {
    const connectionValue = optionsValue.trustedConnection;
    const connection = snapshotAllConnectionCapabilities(connectionValue);
    const releasePinsValue = optionsValue.releasePins;
    const releasePins = snapshotReleasePins(releasePinsValue);
    const sessionSignerValue = optionsValue.sessionSigner;
    const sessionSigner = requirePublicKey(
      sessionSignerValue,
      "sessionSigner",
      "INVALID_CONFIG",
    );
    if (allZero(sessionSigner.toBytes())) {
      fail("INVALID_CONFIG", "sessionSigner must not be zero");
    }
    const approvalsValue = optionsValue.approvals;
    const approvals = bindApprovalOwner(approvalsValue);
    const keyringValue = optionsValue.keyring;
    const keyring = bindKeyring(keyringValue);
    const readNowValue = optionsValue.readNow;
    if (readNowValue !== undefined && typeof readNowValue !== "function") {
      fail("INVALID_CONFIG", "readNow must be a function");
    }
    const readNow =
      typeof readNowValue === "function"
        ? readNowValue.bind(optionsValue)
        : undefined;
    const approvalTtlMsValue = optionsValue.approvalTtlMs;
    const resolver = new PinnedSessionAuthorityResolver({
      rpc: new ConnectionSessionAuthorityRpc(connection),
      sessionSigner,
      expectedWardenProgramDataSlot: releasePins.wardenProgramDataSlot,
      expectedWardenUpgradeAuthority: releasePins.wardenUpgradeAuthority,
      expectedWardenCodeHash: releasePins.wardenCodeHash,
      expectedWardenProgramDataHash: releasePins.wardenProgramDataHash,
      expectedWardenProgramDataBytes: releasePins.wardenProgramDataBytes,
      localnetGenesisHash:
        releasePins.chain === "solana:localnet"
          ? releasePins.genesisHash
          : undefined,
    });
    const resolve = resolver.resolve.bind(resolver);
    const authority: SessionApprovalAuthorityResolver = Object.freeze({
      resolve(
        input: Parameters<SessionApprovalAuthorityResolver["resolve"]>[0],
      ) {
        if (input.selection.chain !== releasePins.chain) {
          fail("CHAIN_MISMATCH", "approval chain differs from releasePins.chain");
        }
        return resolve(input);
      },
    });
    const blockhash = bindInternalBlockhashClient(
      new ConnectionSessionApprovalBlockhashClient({
        trustedConnection: connection,
        chain: releasePins.chain,
        genesisHash: releasePins.genesisHash,
      }),
    );
    return new SessionApprovalCoordinator(
      {
        authority,
        blockhash,
        intent: createInternalIntentGate(),
        approvals,
        keyring,
      },
      {
        readNow,
        approvalTtlMs: approvalTtlMsValue,
      },
    );
  } catch (error) {
    if (error instanceof SessionApprovalRpcError) throw error;
    fail("INVALID_CONFIG", "composition construction failed", error);
  }
}
