//! Still-unreachable C13 authenticated account/release selection boundary.
//!
//! Page selectors never choose a release, endpoint, program, or deploy pin.
//! One trusted background composition supplies a repository-committed release
//! name and a zero-argument Connection factory. The committed release is
//! resolved before either capability is inspected. Today's empty registry
//! therefore fails before keyring access or Connection construction.

import type { ApprovalChain } from "@warden/core/approval";
import { PUBKEY_BYTES } from "@warden/core/keyring";
import type {
  SessionApprovalKeyring,
  SessionApprovalOwner,
} from "@warden/core/transaction/session-approval";
import {
  createCommittedSessionApprovalCoordinator,
  resolveCommittedSessionRelease,
} from "@warden/core/transaction/session-release";
import type { SessionApprovalReleasePins } from "@warden/core/transaction/session-rpc";
import { PublicKey, type Connection } from "@solana/web3.js";

import type {
  AuthenticatedSessionIdentity,
  KeyringLifecycle,
} from "./keyring-lifecycle.js";
import type {
  ProviderApprovalSelection,
  ProviderApprovalSelectionInput,
  ProviderApprovalSelectionResolver,
} from "./provider-approval-request.js";

const CHAINS: ReadonlySet<string> = new Set([
  "solana:mainnet",
  "solana:devnet",
  "solana:testnet",
  "solana:localnet",
]);

export type ProviderApprovalSelectionErrorCode =
  | "INVALID_CONFIG"
  | "INVALID_REQUEST"
  | "REQUEST_ABORTED"
  | "RELEASE_INVALID"
  | "RELEASE_MISMATCH"
  | "IDENTITY_INVALID"
  | "IDENTITY_CHANGED";

export class ProviderApprovalSelectionError extends Error {
  readonly code: ProviderApprovalSelectionErrorCode;

  constructor(
    code: ProviderApprovalSelectionErrorCode,
    message: string,
    options: ErrorOptions = {},
  ) {
    super(`provider approval selection: ${message}`, options);
    this.name = "ProviderApprovalSelectionError";
    this.code = code;
  }
}

/** A source-configured factory permanently bound to one reviewed RPC URL. */
export interface TrustedProviderConnectionFactory {
  create(): Connection;
}

export interface CommittedProviderApprovalSelectionResolverOptions {
  /** Repository-owned selection; a page request never supplies this name. */
  readonly releaseName: string;
  /** Zero-argument source-owned endpoint capability. */
  readonly connectionFactory: TrustedProviderConnectionFactory;
  readonly approvals: SessionApprovalOwner;
  readonly keyring: KeyringLifecycle;
  readonly readNow?: () => number;
  readonly approvalTtlMs?: number;
}

interface ReleaseIdentity {
  readonly chain: ApprovalChain;
  readonly genesisHash: Uint8Array;
  readonly programId: Uint8Array;
}

interface OwnedSessionIdentity {
  readonly account: Uint8Array;
  readonly genesisHash: Uint8Array;
  readonly programId: Uint8Array;
  readonly revocationSignal: AbortSignal;
  readonly sessionSigner: Uint8Array;
}

interface BoundKeyring {
  readonly readIdentity: (
    operation: string,
  ) => Promise<AuthenticatedSessionIdentity>;
  readonly approvalKeyring: SessionApprovalKeyring;
}

function fail(
  code: ProviderApprovalSelectionErrorCode,
  message: string,
  cause?: unknown,
): never {
  throw new ProviderApprovalSelectionError(
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

function clearIdentity(identity: OwnedSessionIdentity | undefined): void {
  identity?.account.fill(0);
  identity?.genesisHash.fill(0);
  identity?.programId.fill(0);
  identity?.sessionSigner.fill(0);
}

function copyBytes(
  value: unknown,
  name: string,
  code: ProviderApprovalSelectionErrorCode,
): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== PUBKEY_BYTES) {
    fail(code, `${name} must contain exactly ${PUBKEY_BYTES} bytes`);
  }
  return value.slice();
}

function requireAbortSignal(
  value: unknown,
  name: string,
  code: ProviderApprovalSelectionErrorCode,
): AbortSignal {
  if (
    !isObject(value) ||
    typeof value.aborted !== "boolean" ||
    typeof value.addEventListener !== "function" ||
    typeof value.removeEventListener !== "function"
  ) {
    fail(code, `${name} is malformed`);
  }
  return value as unknown as AbortSignal;
}

function snapshotRelease(pinsValue: SessionApprovalReleasePins): ReleaseIdentity {
  if (!isObject(pinsValue)) fail("RELEASE_INVALID", "committed release pins are malformed");
  let chainValue: unknown;
  let genesisValue: unknown;
  let programValue: unknown;
  try {
    chainValue = pinsValue.chain;
    genesisValue = pinsValue.genesisHash;
    programValue = pinsValue.wardenProgram;
  } catch (error) {
    fail("RELEASE_INVALID", "committed release identity access failed", error);
  }
  if (typeof chainValue !== "string" || !CHAINS.has(chainValue)) {
    fail("RELEASE_INVALID", "committed release chain is unsupported");
  }
  const genesisHash = copyBytes(
    genesisValue,
    "committed release genesis hash",
    "RELEASE_INVALID",
  );
  let programId: Uint8Array | undefined;
  try {
    if (!(programValue instanceof PublicKey)) {
      fail("RELEASE_INVALID", "committed release program must be a PublicKey");
    }
    programId = programValue.toBytes();
  } catch (error) {
    genesisHash.fill(0);
    if (error instanceof ProviderApprovalSelectionError) throw error;
    fail("RELEASE_INVALID", "committed release program is malformed", error);
  }
  if (allZero(genesisHash) || allZero(programId)) {
    genesisHash.fill(0);
    programId.fill(0);
    fail("RELEASE_INVALID", "committed release identity must not be zero");
  }
  return Object.freeze({
    chain: chainValue as ApprovalChain,
    genesisHash,
    programId,
  });
}

function snapshotIdentity(value: unknown): OwnedSessionIdentity {
  if (!isObject(value)) fail("IDENTITY_INVALID", "authenticated identity is malformed");
  let account: Uint8Array | undefined;
  let genesisHash: Uint8Array | undefined;
  let programId: Uint8Array | undefined;
  let revocationSignal: AbortSignal | undefined;
  let sessionSigner: Uint8Array | undefined;
  try {
    account = copyBytes(value.account, "authenticated account", "IDENTITY_INVALID");
    genesisHash = copyBytes(
      value.genesisHash,
      "authenticated genesis hash",
      "IDENTITY_INVALID",
    );
    programId = copyBytes(
      value.programId,
      "authenticated program id",
      "IDENTITY_INVALID",
    );
    revocationSignal = requireAbortSignal(
      value.revocationSignal,
      "authenticated revocation signal",
      "IDENTITY_INVALID",
    );
    sessionSigner = copyBytes(
      value.sessionSigner,
      "authenticated session signer",
      "IDENTITY_INVALID",
    );
    if (
      allZero(account) ||
      allZero(genesisHash) ||
      allZero(programId) ||
      allZero(sessionSigner)
    ) {
      fail("IDENTITY_INVALID", "authenticated identity fields must not be zero");
    }
    // PublicKey construction is a defensive structural check and creates no
    // secret-key expansion.
    new PublicKey(account);
    new PublicKey(genesisHash);
    new PublicKey(programId);
    new PublicKey(sessionSigner);
    return Object.freeze({
      account,
      genesisHash,
      programId,
      revocationSignal,
      sessionSigner,
    });
  } catch (error) {
    account?.fill(0);
    genesisHash?.fill(0);
    programId?.fill(0);
    sessionSigner?.fill(0);
    if (error instanceof ProviderApprovalSelectionError) throw error;
    fail("IDENTITY_INVALID", "authenticated identity is not a Solana identity", error);
  }
}

function bindKeyring(value: unknown): BoundKeyring {
  if (!isObject(value)) fail("INVALID_CONFIG", "keyring must be an object");
  try {
    const readIdentity = value.readAuthenticatedSessionIdentity;
    const useSessionSignerBytes = value.useSessionSignerBytes;
    if (typeof readIdentity !== "function") {
      fail("INVALID_CONFIG", "keyring must expose readAuthenticatedSessionIdentity()");
    }
    if (typeof useSessionSignerBytes !== "function") {
      fail("INVALID_CONFIG", "keyring must expose useSessionSignerBytes()");
    }
    return Object.freeze({
      readIdentity: readIdentity.bind(value),
      approvalKeyring: Object.freeze({
        useSessionSignerBytes: useSessionSignerBytes.bind(value),
      }),
    });
  } catch (error) {
    if (error instanceof ProviderApprovalSelectionError) throw error;
    fail("INVALID_CONFIG", "keyring capability access failed", error);
  }
}

function bindConnectionFactory(value: unknown): () => Connection {
  if (!isObject(value)) fail("INVALID_CONFIG", "Connection factory must be an object");
  try {
    const create = value.create;
    if (typeof create !== "function") {
      fail("INVALID_CONFIG", "Connection factory must expose create()");
    }
    return create.bind(value);
  } catch (error) {
    if (error instanceof ProviderApprovalSelectionError) throw error;
    fail("INVALID_CONFIG", "Connection factory capability access failed", error);
  }
}

function requestSignal(inputValue: ProviderApprovalSelectionInput): AbortSignal {
  if (!isObject(inputValue)) fail("INVALID_REQUEST", "selection input must be an object");
  let method: unknown;
  let signal: unknown;
  try {
    method = inputValue.method;
    signal = inputValue.signal;
  } catch (error) {
    fail("INVALID_REQUEST", "selection input access failed", error);
  }
  if (method !== "solana:signTransaction") {
    fail("INVALID_REQUEST", "selection method is unsupported");
  }
  return requireAbortSignal(signal, "selection signal", "INVALID_REQUEST");
}

function assertActive(signal: AbortSignal): void {
  try {
    if (signal.aborted) fail("REQUEST_ABORTED", "provider request is no longer active");
  } catch (error) {
    if (error instanceof ProviderApprovalSelectionError) throw error;
    fail("INVALID_REQUEST", "selection signal access failed", error);
  }
}

function assertReleaseMatch(
  identity: OwnedSessionIdentity,
  release: ReleaseIdentity,
): void {
  if (
    !bytesEqual(identity.genesisHash, release.genesisHash) ||
    !bytesEqual(identity.programId, release.programId)
  ) {
    fail(
      "RELEASE_MISMATCH",
      "authenticated keyring cluster or program differs from the committed release",
    );
  }
}

function assertIdentityActive(identity: OwnedSessionIdentity): void {
  try {
    if (identity.revocationSignal.aborted) {
      fail("IDENTITY_CHANGED", "authenticated unlock generation was revoked");
    }
  } catch (error) {
    if (error instanceof ProviderApprovalSelectionError) throw error;
    fail("IDENTITY_INVALID", "authenticated revocation signal access failed", error);
  }
}

function assertSameIdentity(
  first: OwnedSessionIdentity,
  second: OwnedSessionIdentity,
): void {
  if (
    !bytesEqual(first.account, second.account) ||
    !bytesEqual(first.genesisHash, second.genesisHash) ||
    !bytesEqual(first.programId, second.programId) ||
    !bytesEqual(first.sessionSigner, second.sessionSigner) ||
    first.revocationSignal !== second.revocationSignal
  ) {
    fail("IDENTITY_CHANGED", "authenticated account context changed during selection");
  }
}

/**
 * Resolve a provider selection without consulting any page-supplied selector.
 * C12 independently compares the returned account/chain with those untrusted
 * fields before it prepares an approval.
 */
export class CommittedProviderApprovalSelectionResolver
implements ProviderApprovalSelectionResolver {
  readonly #options: CommittedProviderApprovalSelectionResolverOptions;

  constructor(optionsValue: CommittedProviderApprovalSelectionResolverOptions) {
    if (!isObject(optionsValue)) fail("INVALID_CONFIG", "options must be an object");
    // Preserve lazy access: an empty committed registry must fail before any
    // Connection, keyring, approval, clock, or TTL capability is inspected.
    this.#options = optionsValue;
  }

  async resolve(
    inputValue: ProviderApprovalSelectionInput,
  ): Promise<ProviderApprovalSelection> {
    const signal = requestSignal(inputValue);
    let releaseName: string;
    try {
      releaseName = this.#options.releaseName;
    } catch (error) {
      fail("INVALID_CONFIG", "releaseName access failed", error);
    }

    // This call is intentionally first among privileged dependencies. The
    // production registry is currently empty and refuses here synchronously.
    const release = snapshotRelease(resolveCommittedSessionRelease(releaseName));
    let first: OwnedSessionIdentity | undefined;
    let second: OwnedSessionIdentity | undefined;
    try {
      assertActive(signal);
      let keyringValue: KeyringLifecycle;
      try {
        keyringValue = this.#options.keyring;
      } catch (error) {
        fail("INVALID_CONFIG", "keyring access failed", error);
      }
      const keyring = bindKeyring(keyringValue);
      first = snapshotIdentity(
        await keyring.readIdentity("select committed provider account"),
      );
      assertIdentityActive(first);
      assertReleaseMatch(first, release);
      assertActive(signal);

      let connectionFactoryValue: TrustedProviderConnectionFactory;
      try {
        connectionFactoryValue = this.#options.connectionFactory;
      } catch (error) {
        fail("INVALID_CONFIG", "Connection factory access failed", error);
      }
      const createConnection = bindConnectionFactory(connectionFactoryValue);
      let trustedConnection: Connection;
      try {
        trustedConnection = createConnection();
      } catch (error) {
        fail("INVALID_CONFIG", "trusted Connection construction failed", error);
      }
      assertActive(signal);

      let approvals: SessionApprovalOwner;
      let readNow: (() => number) | undefined;
      let approvalTtlMs: number | undefined;
      try {
        approvals = this.#options.approvals;
        const readNowValue = this.#options.readNow;
        if (readNowValue !== undefined && typeof readNowValue !== "function") {
          fail("INVALID_CONFIG", "readNow must be a function");
        }
        readNow = readNowValue?.bind(this.#options);
        approvalTtlMs = this.#options.approvalTtlMs;
      } catch (error) {
        if (error instanceof ProviderApprovalSelectionError) throw error;
        fail("INVALID_CONFIG", "approval composition access failed", error);
      }

      const coordinator = createCommittedSessionApprovalCoordinator({
        releaseName,
        trustedConnection,
        sessionSigner: new PublicKey(first.sessionSigner),
        approvals,
        keyring: keyring.approvalKeyring,
        readNow,
        approvalTtlMs,
      });
      assertActive(signal);

      // No external access or suspension occurs after this exact second read.
      // A replace/lock/re-unlock during composition either rejects inside the
      // keyring or returns different public identity and is suppressed here.
      second = snapshotIdentity(
        await keyring.readIdentity("revalidate committed provider account"),
      );
      assertSameIdentity(first, second);
      assertIdentityActive(first);
      assertIdentityActive(second);
      assertReleaseMatch(second, release);
      assertActive(signal);
      return Object.freeze({
        account: first.account.slice(),
        authoritySignal: first.revocationSignal,
        chain: release.chain,
        coordinator,
      });
    } finally {
      clearIdentity(first);
      clearIdentity(second);
      release.genesisHash.fill(0);
      release.programId.fill(0);
    }
  }
}
