//! Browser-only C23-C28 exact-byte success and restart-cut composition.
//! Never copied into the product build.
//!
//! The release pins and Connection below are deterministic test provenance, not a
//! production release assertion. The composition deliberately uses the real pinned
//! authority resolver, deterministic intent gate, durable owners, keyring lifecycle,
//! approval UI, and C12-C22 transport graph without populating the shipped release
//! registry or making the production provider reachable.

import {
  SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION,
  encodeKeyringRecordStorageValue,
  encodeSessionSignerPayload,
  prepareKeyringRecordMetadata,
  sealKeyringRecord,
  type KeyringContext,
} from "@warden/core/keyring";
import type {
  ApprovalCreateParams,
  ApprovalRecord,
  ApprovalSigningFailureCode,
  ApprovalSigningRecord,
} from "@warden/core/approval";
import type {
  SessionApprovalOwner,
  SessionApprovalSignerLease,
} from "@warden/core/transaction/session-approval";
import { decodeSessionApprovalReview } from "@warden/core/transaction/session-intent";
import {
  createPinnedSessionApprovalCoordinator,
  type SessionApprovalReleasePins,
} from "@warden/core/transaction/session-rpc";
import {
  Keypair,
  PublicKey,
  SYSVAR_CLOCK_PUBKEY,
  type Connection,
} from "@solana/web3.js";

import { ApprovalOwner } from "../src/background/approval-owner.js";
import { installApprovalReviewBoundary } from "../src/background/approval-port.js";
import {
  APPROVAL_OBJECT_STORE_NAME,
  IndexedDbApprovalRecordRepository,
} from "../src/background/approval-store.js";
import {
  installApprovalWindowOwner,
  type ApprovalWindowsApi,
} from "../src/background/approval-window.js";
import { KeyringLifecycleOwner } from "../src/background/keyring-lifecycle.js";
import { ProviderApprovalActionOwner } from "../src/background/provider-approval-action.js";
import { ProviderApprovalOperationOwner } from "../src/background/provider-approval-operation.js";
import {
  ProviderApprovalRequestOwner,
  type ProviderApprovalSelectionInput,
  type ProviderApprovalSelectionResolver,
} from "../src/background/provider-approval-request.js";
import { IndexedDbProviderOperationRepository } from "../src/background/provider-operation-store.js";
import { ProviderOperationOwner } from "../src/background/provider-operation.js";
import {
  ProviderRuntimeTransportOwner,
  type ProviderRuntimeTransportLease,
} from "../src/background/provider-runtime-transport.js";
import { ProviderSignedResultFlowOwner } from "../src/background/provider-signed-result-flow.js";
import { ProviderTerminalOutcomeOwner } from "../src/background/provider-terminal-outcome.js";
import { ProviderTerminalResultOwner } from "../src/background/provider-terminal-result.js";
import type {
  ProviderConnectEvent,
  ProviderRuntimeApi,
  ProviderRuntimePort,
} from "../src/background/provider-port.js";
import type { KeyringRecordStorageArea } from "../src/background/keyring-record-store.js";
import type { UnlockSessionStorageArea } from "../src/background/unlock-session.js";
import { APPROVAL_UI_PORT_NAME } from "../src/approval-protocol.js";
import { PROVIDER_PORT_NAME } from "../src/provider-protocol.js";
import {
  readProviderTransportSettledEnvelope,
  readProviderTransportTerminalEnvelope,
} from "../src/provider-delivery-protocol.js";
import { isSignedTransactionProviderResponse } from
  "../src/background/provider-terminal-protocol.js";

const APPROVAL_DATABASE_NAME = "warden-provider-sign-success-approvals-v1";
const OPERATION_DATABASE_NAME = "warden-provider-sign-success-operations-v1";
const KEYRING_INITIALIZED_STORAGE_KEY =
  "warden-provider-sign-success-keyring-initialized-v1";
const SIGNING_COMMIT_CHECKPOINT_STORAGE_KEY =
  "warden:test:signing-commit-request-succeeded-v1";
const TERMINAL_ENQUEUED_CHECKPOINT_STORAGE_KEY =
  "warden:test:terminal-enqueued-v1";
const SETTLEMENT_ENQUEUE_CHECKPOINT_STORAGE_KEY =
  "warden:test:before-settlement-enqueue-v1";
const WARDEN_PROGRAM = new PublicKey(
  "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2",
);
const MEMO_PROGRAM = new PublicKey(
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
);
const BPF_UPGRADEABLE_LOADER = new PublicKey(
  "BPFLoaderUpgradeab1e11111111111111111111111",
);
const SYSVAR_OWNER = new PublicKey(
  "Sysvar1111111111111111111111111111111111111",
);
const DEVNET_GENESIS_STRING =
  "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const DEVNET_GENESIS = new PublicKey(DEVNET_GENESIS_STRING).toBytes();
const OWNER_SEED = new Uint8Array(32).fill(0x11);
const SESSION_SEED = new Uint8Array(32).fill(0x22);
const SESSION_SIGNER = Keypair.fromSeed(SESSION_SEED).publicKey;
const UPGRADE_AUTHORITY = new PublicKey(new Uint8Array(32).fill(0xaa));
const PROGRAMDATA_SLOT = 123n;
const ACCOUNT_GENERATION = 7n;
const POLICY_VERSION = 1;
const SESSION_EXPIRY = 2_000_000_000;
const OBSERVED_TIME = 1_900_000_000;
const CONTEXT_SLOT = 42;
const FINAL_BLOCKHASH = new Uint8Array(32).fill(0x88);
const PROGRAM_CODE = new TextEncoder().encode(
  "warden-authority-resolver-fixture",
);
const EXPECTED_CODE_HASH = hexBytes(
  "65cdfd837999b58ee226aa6f50316acc9b3e522e7d20a50314640b3526437466",
);
const EXPECTED_PROGRAM_DATA_HASH = hexBytes(
  "3dda51c71e3d54acaf5a2180421bf03a8ceff59fafd0bfb721c23cc1aa32a96a",
);

const [SMART_ACCOUNT, SMART_BUMP] = PublicKey.findProgramAddressSync(
  [new TextEncoder().encode("account"), OWNER_SEED],
  WARDEN_PROGRAM,
);
const [SESSION_ACCOUNT, SESSION_BUMP] = PublicKey.findProgramAddressSync(
  [
    new TextEncoder().encode("session"),
    SMART_ACCOUNT.toBytes(),
    SESSION_SIGNER.toBytes(),
  ],
  WARDEN_PROGRAM,
);
const [REGISTRY, REGISTRY_BUMP] = PublicKey.findProgramAddressSync(
  [new TextEncoder().encode("registry")],
  WARDEN_PROGRAM,
);
const [PROGRAM_DATA] = PublicKey.findProgramAddressSync(
  [WARDEN_PROGRAM.toBytes()],
  BPF_UPGRADEABLE_LOADER,
);

const SMART_DISCRIMINATOR = Uint8Array.of(
  186, 83, 247, 224, 59, 95, 223, 112,
);
const SESSION_DISCRIMINATOR = Uint8Array.of(
  93, 186, 163, 139, 160, 255, 81, 112,
);
const REGISTRY_DISCRIMINATOR = Uint8Array.of(
  47, 174, 110, 246, 184, 182, 252, 218,
);

interface BrowserChrome {
  readonly runtime: ProviderRuntimeApi;
  readonly windows: ApprovalWindowsApi;
  readonly storage: {
    readonly local: KeyringRecordStorageArea;
    readonly session: UnlockSessionStorageArea;
  };
}

interface FixtureAccount {
  readonly owner: PublicKey;
  readonly executable: boolean;
  readonly data: Uint8Array;
}

interface Counters {
  approvalPortRoutes: number;
  selectionCalls: number;
  identityReads: number;
  approvalCreates: number;
  signingClaims: number;
  signingCompletions: number;
  signerLeaseUses: number;
  signerResultsProduced: number;
  providerPortRoutes: number;
  latestApprovalId: string | null;
}

type KeyringStartup = "seeded" | "restored" | "locked";
type WorkerCheckpoint =
  | "after-signature-produced"
  | "after-signing-committed"
  | "during-signing-commit"
  | "after-terminal-enqueued"
  | "before-settlement-enqueue";

interface SigningCommitCandidate {
  readonly approvalId: string;
  readonly attemptId: string;
  readonly attemptNumber: number;
  readonly transactionBytesLength: number;
}

function hexBytes(value: string): Uint8Array {
  const pairs = value.match(/../g);
  if (pairs === null || pairs.length !== 32) throw new Error("invalid hash fixture");
  return Uint8Array.from(pairs.map((pair) => Number.parseInt(pair, 16)));
}

function writeU16le(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
}

function writeU32le(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

function writeU64le(bytes: Uint8Array, offset: number, value: bigint): void {
  let remaining = value;
  for (let index = 0; index < 8; index++) {
    bytes[offset + index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
}

function smartData(): Uint8Array {
  const bytes = new Uint8Array(4_120);
  bytes.set(SMART_DISCRIMINATOR, 0);
  bytes[8] = 1;
  bytes[9] = SMART_BUMP;
  bytes.set(OWNER_SEED, 14);
  bytes.set(DEVNET_GENESIS, 175);
  bytes.set(REGISTRY.toBytes(), 239);
  writeU64le(bytes, 528, ACCOUNT_GENERATION);
  writeU64le(bytes, 536, 3n);
  writeU32le(bytes, 560, POLICY_VERSION);
  writeU16le(bytes, 1_936, 1 << 1);
  return bytes;
}

function sessionData(): Uint8Array {
  const bytes = new Uint8Array(751);
  bytes.set(SESSION_DISCRIMINATOR, 0);
  bytes[8] = 1;
  bytes[9] = SESSION_BUMP;
  bytes.set(SMART_ACCOUNT.toBytes(), 10);
  bytes.set(SESSION_SIGNER.toBytes(), 42);
  bytes[74] = 0;
  writeU64le(bytes, 75, BigInt(SESSION_EXPIRY));
  writeU16le(bytes, 83, 1 << 1);
  writeU64le(bytes, 85, ACCOUNT_GENERATION);
  writeU16le(bytes, 669, 1);
  return bytes;
}

function registryData(): Uint8Array {
  const bytes = new Uint8Array(3_480);
  bytes.set(REGISTRY_DISCRIMINATOR, 0);
  bytes[8] = 1;
  bytes[9] = REGISTRY_BUMP;
  writeU16le(bytes, 80, 1);
  bytes.set(MEMO_PROGRAM.toBytes(), 88);
  writeU64le(bytes, 3_160, 1n);
  bytes[3_224] = 1;
  return bytes;
}

function clockData(slot: number): Uint8Array {
  const bytes = new Uint8Array(40);
  writeU64le(bytes, 0, BigInt(slot));
  writeU64le(bytes, 8, BigInt(OBSERVED_TIME - 1_000));
  writeU64le(bytes, 16, 10n);
  writeU64le(bytes, 24, 11n);
  writeU64le(bytes, 32, BigInt(OBSERVED_TIME));
  return bytes;
}

function programAccountData(): Uint8Array {
  const bytes = new Uint8Array(36);
  writeU32le(bytes, 0, 2);
  bytes.set(PROGRAM_DATA.toBytes(), 4);
  return bytes;
}

function programData(): Uint8Array {
  const bytes = new Uint8Array(45 + PROGRAM_CODE.length + 16);
  writeU32le(bytes, 0, 3);
  writeU64le(bytes, 4, PROGRAMDATA_SLOT);
  bytes[12] = 1;
  bytes.set(UPGRADE_AUTHORITY.toBytes(), 13);
  bytes.set(PROGRAM_CODE, 45);
  return bytes;
}

function account(
  owner: PublicKey,
  data: Uint8Array,
  executable = false,
): FixtureAccount {
  return Object.freeze({ owner, data, executable });
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function errorText(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

function diagnosticErrorText(error: unknown, depth = 0): string {
  if (depth >= 5) return errorText(error);
  if (error instanceof AggregateError) {
    return `${errorText(error)} [${error.errors
      .map((entry) => diagnosticErrorText(entry, depth + 1))
      .join(" | ")}]`;
  }
  if (error instanceof Error && error.cause !== undefined) {
    return `${errorText(error)} <- ${diagnosticErrorText(error.cause, depth + 1)}`;
  }
  return errorText(error);
}

function newBootId(): string {
  return [...crypto.getRandomValues(new Uint8Array(16))]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

class RoutedConnectEvent implements ProviderConnectEvent {
  private listener: ((port: ProviderRuntimePort) => void) | null = null;

  addListener(listener: (port: ProviderRuntimePort) => void): void {
    if (this.listener !== null) {
      throw new Error("C23 runtime router: duplicate child listener");
    }
    this.listener = listener;
  }

  removeListener(listener: (port: ProviderRuntimePort) => void): void {
    if (this.listener === listener) this.listener = null;
  }

  emit(port: ProviderRuntimePort): void {
    this.listener?.(port);
  }
}

function safeDisconnectUnknownPort(value: unknown): void {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly disconnect?: unknown }).disconnect !== "function"
  ) {
    return;
  }
  try {
    (value as { disconnect(): void }).disconnect();
  } catch {
    // A malformed or already-dead unknown Port is closed.
  }
}

const chromeApi = (globalThis as unknown as { readonly chrome: BrowserChrome }).chrome;
const bootId = newBootId();
const counters: Counters = {
  approvalPortRoutes: 0,
  selectionCalls: 0,
  identityReads: 0,
  approvalCreates: 0,
  signingClaims: 0,
  signingCompletions: 0,
  signerLeaseUses: 0,
  signerResultsProduced: 0,
  providerPortRoutes: 0,
  latestApprovalId: null,
};
const rpcCounters = {
  genesisCalls: 0,
  accountCalls: 0,
  latestBlockhashCalls: 0,
  blockhashValidityCalls: 0,
};
const fatalErrors: string[] = [];
let readyFlag = false;
let keyringStartup: KeyringStartup = "locked";
let armedCheckpoint: WorkerCheckpoint | null = null;
let checkpointReached: WorkerCheckpoint | null = null;
let startupInvalidatedApprovals = -1;
let startupInvalidatedOperations = -1;

async function pauseAtCheckpoint(stage: WorkerCheckpoint): Promise<void> {
  if (armedCheckpoint !== stage) return;
  armedCheckpoint = null;
  checkpointReached = stage;
  await new Promise<void>(() => {
    // C24 closes the real worker target while this exact continuation is held.
  });
}

function signingCommitCandidate(value: unknown): SigningCommitCandidate | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const envelope = value as Record<string, unknown>;
  const signingValue = envelope.signing;
  if (
    typeof envelope.id !== "string" ||
    typeof signingValue !== "object" ||
    signingValue === null ||
    Array.isArray(signingValue)
  ) {
    return null;
  }
  const signing = signingValue as Record<string, unknown>;
  if (
    signing.state !== "signed" ||
    typeof signing.attemptId !== "string" ||
    !Number.isSafeInteger(signing.attemptNumber) ||
    !(signing.transactionBytes instanceof Uint8Array) ||
    signing.transactionBytes.length === 0
  ) {
    return null;
  }
  return Object.freeze({
    approvalId: envelope.id,
    attemptId: signing.attemptId,
    attemptNumber: signing.attemptNumber as number,
    transactionBytesLength: signing.transactionBytes.length,
  });
}

function installSigningCommitCheckpoint(): void {
  const prototype = IDBObjectStore.prototype;
  const descriptor = Object.getOwnPropertyDescriptor(prototype, "put");
  if (descriptor === undefined || typeof descriptor.value !== "function") {
    throw new Error("native IDBObjectStore.put is unavailable");
  }
  const nativePut = descriptor.value as (...args: unknown[]) => IDBRequest;
  const checkpointPut = function (
    this: IDBObjectStore,
    value: unknown,
    key?: IDBValidKey,
  ): IDBRequest {
    const request = Reflect.apply(
      nativePut,
      this,
      key === undefined ? [value] : [value, key],
    ) as IDBRequest;
    const candidate = this.name === APPROVAL_OBJECT_STORE_NAME
      ? signingCommitCandidate(value)
      : null;
    if (armedCheckpoint !== "during-signing-commit" || candidate === null) {
      return request;
    }
    request.addEventListener("success", () => {
      if (armedCheckpoint !== "during-signing-commit") return;
      armedCheckpoint = null;
      checkpointReached = "during-signing-commit";
      void chromeApi.storage.session.set({
        [SIGNING_COMMIT_CHECKPOINT_STORAGE_KEY]: {
          stage: "during-signing-commit",
          bootId,
          ...candidate,
          selectionCalls: counters.selectionCalls,
          approvalCreates: counters.approvalCreates,
          signingClaims: counters.signingClaims,
          signingCompletions: counters.signingCompletions,
          signerLeaseUses: counters.signerLeaseUses,
          signerResultsProduced: counters.signerResultsProduced,
          rpc: { ...rpcCounters },
        },
      });
      const holdUntil = Date.now() + 20_000;
      while (Date.now() < holdUntil) {
        // C26 closes the actual worker target before this native event returns.
      }
    }, { once: true });
    return request;
  };
  Object.defineProperty(prototype, "put", {
    ...descriptor,
    value: checkpointPut,
  });
}

installSigningCommitCheckpoint();

function instrumentProviderPort(port: ProviderRuntimePort): ProviderRuntimePort {
  const postMessage = port.postMessage.bind(port);
  const disconnect = port.disconnect.bind(port);
  let latestSignedTerminal: Readonly<{
    correlationId: string;
    receiptId: string;
    expiresAt: number;
    signedTransaction: readonly number[];
  }> | null = null;
  return Object.freeze({
    name: port.name,
    sender: port.sender,
    onMessage: port.onMessage,
    onDisconnect: port.onDisconnect,
    postMessage(message: unknown): void {
      const settled = readProviderTransportSettledEnvelope(message);
      if (
        armedCheckpoint === "before-settlement-enqueue" &&
        settled !== null
      ) {
        const terminal = latestSignedTerminal;
        if (
          terminal === null ||
          terminal.correlationId !== settled.correlationId ||
          terminal.receiptId !== settled.receiptId ||
          terminal.expiresAt !== settled.expiresAt
        ) {
          throw new Error("settlement does not match the enqueued signed terminal");
        }
        const approvalId = counters.latestApprovalId;
        if (approvalId === null) {
          throw new Error("settlement has no approval identity");
        }
        armedCheckpoint = null;
        checkpointReached = "before-settlement-enqueue";
        void chromeApi.storage.session.set({
          [SETTLEMENT_ENQUEUE_CHECKPOINT_STORAGE_KEY]: {
            stage: "before-settlement-enqueue",
            bootId,
            approvalId,
            correlationId: settled.correlationId,
            receiptId: settled.receiptId,
            expiresAt: settled.expiresAt,
            signedTransaction: [...terminal.signedTransaction],
            selectionCalls: counters.selectionCalls,
            approvalCreates: counters.approvalCreates,
            signingClaims: counters.signingClaims,
            signingCompletions: counters.signingCompletions,
            signerLeaseUses: counters.signerLeaseUses,
            signerResultsProduced: counters.signerResultsProduced,
            rpc: { ...rpcCounters },
          },
        });
        const holdUntil = Date.now() + 20_000;
        while (Date.now() < holdUntil) {
          // C28 closes the actual worker before this native enqueue starts.
        }
        postMessage(message);
        return;
      }

      const terminal = readProviderTransportTerminalEnvelope(message);
      const signed = terminal !== null &&
          isSignedTransactionProviderResponse(terminal.payload) &&
          terminal.payload.correlationId === terminal.correlationId
        ? terminal.payload
        : null;

      // This is the actual Chrome Port enqueue. The test-only hold begins only
      // after the native method returns, while the production transport owner
      // is still unable to record its posted generation or delivery proof.
      postMessage(message);
      if (terminal !== null && signed !== null) {
        latestSignedTerminal = Object.freeze({
          correlationId: terminal.correlationId,
          receiptId: terminal.receiptId,
          expiresAt: terminal.expiresAt,
          signedTransaction: Object.freeze([
            ...signed.result.signedTransaction,
          ]),
        });
      }
      if (
        armedCheckpoint !== "after-terminal-enqueued" ||
        terminal === null ||
        signed === null
      ) {
        return;
      }
      const approvalId = counters.latestApprovalId;
      if (approvalId === null) {
        throw new Error("signed terminal has no approval identity");
      }
      armedCheckpoint = null;
      checkpointReached = "after-terminal-enqueued";
      void chromeApi.storage.session.set({
        [TERMINAL_ENQUEUED_CHECKPOINT_STORAGE_KEY]: {
          stage: "after-terminal-enqueued",
          bootId,
          approvalId,
          correlationId: terminal.correlationId,
          receiptId: terminal.receiptId,
          expiresAt: terminal.expiresAt,
          signedTransaction: [...signed.result.signedTransaction],
          selectionCalls: counters.selectionCalls,
          approvalCreates: counters.approvalCreates,
          signingClaims: counters.signingClaims,
          signingCompletions: counters.signingCompletions,
          signerLeaseUses: counters.signerLeaseUses,
          signerResultsProduced: counters.signerResultsProduced,
          rpc: { ...rpcCounters },
        },
      });
      const holdUntil = Date.now() + 20_000;
      while (Date.now() < holdUntil) {
        // C27 closes the actual worker after page receipt but before settlement.
      }
    },
    disconnect,
  });
}

async function keyringWasInitialized(): Promise<boolean> {
  const stored = await chromeApi.storage.local.get(
    KEYRING_INITIALIZED_STORAGE_KEY,
  );
  const fields = Object.keys(stored);
  if (fields.length === 0) return false;
  if (
    fields.length !== 1 ||
    fields[0] !== KEYRING_INITIALIZED_STORAGE_KEY ||
    stored[KEYRING_INITIALIZED_STORAGE_KEY] !== true
  ) {
    throw new Error("C24 keyring initialization marker is malformed");
  }
  return true;
}

const programDataBytes = programData();
const fixtureAccounts = new Map<string, FixtureAccount>([
  [SMART_ACCOUNT.toBase58(), account(WARDEN_PROGRAM, smartData())],
  [SESSION_ACCOUNT.toBase58(), account(WARDEN_PROGRAM, sessionData())],
  [REGISTRY.toBase58(), account(WARDEN_PROGRAM, registryData())],
  [
    WARDEN_PROGRAM.toBase58(),
    account(BPF_UPGRADEABLE_LOADER, programAccountData(), true),
  ],
  [
    PROGRAM_DATA.toBase58(),
    account(BPF_UPGRADEABLE_LOADER, programDataBytes),
  ],
]);

const trustedConnection = {
  async getGenesisHash(): Promise<string> {
    rpcCounters.genesisCalls++;
    return DEVNET_GENESIS_STRING;
  },
  async getMultipleAccountsInfoAndContext(
    addresses: PublicKey[],
    config: { readonly commitment: "confirmed"; readonly minContextSlot: number },
  ) {
    rpcCounters.accountCalls++;
    const slot = Math.max(CONTEXT_SLOT, config.minContextSlot);
    return {
      context: { slot },
      value: addresses.map((address) => {
        const value = address.equals(SYSVAR_CLOCK_PUBKEY)
          ? account(SYSVAR_OWNER, clockData(slot))
          : fixtureAccounts.get(address.toBase58()) ?? null;
        return value === null
          ? null
          : {
              owner: new PublicKey(value.owner.toBytes()),
              executable: value.executable,
              data: value.data.slice(),
              lamports: 1,
              rentEpoch: 0,
            };
      }),
    };
  },
  async getLatestBlockhashAndContext(
    config: { readonly commitment: "confirmed"; readonly minContextSlot: number },
  ) {
    rpcCounters.latestBlockhashCalls++;
    return {
      context: { slot: config.minContextSlot + 10 },
      value: {
        blockhash: new PublicKey(FINAL_BLOCKHASH).toBase58(),
        lastValidBlockHeight: 500,
      },
    };
  },
  async isBlockhashValid(
    blockhash: string,
    config: { readonly commitment: "confirmed"; readonly minContextSlot: number },
  ) {
    rpcCounters.blockhashValidityCalls++;
    if (blockhash !== new PublicKey(FINAL_BLOCKHASH).toBase58()) {
      throw new Error("unexpected deterministic blockhash");
    }
    return {
      context: { slot: config.minContextSlot + 10 },
      value: true,
    };
  },
} as unknown as Connection;

const releasePins: SessionApprovalReleasePins = Object.freeze({
  chain: "solana:devnet",
  genesisHash: DEVNET_GENESIS.slice(),
  wardenProgram: WARDEN_PROGRAM,
  wardenProgramDataSlot: PROGRAMDATA_SLOT,
  wardenUpgradeAuthority: UPGRADE_AUTHORITY,
  wardenCodeHash: EXPECTED_CODE_HASH.slice(),
  wardenProgramDataHash: EXPECTED_PROGRAM_DATA_HASH.slice(),
  wardenProgramDataBytes: programDataBytes.length,
});

const approvalRepository = new IndexedDbApprovalRecordRepository({
  databaseName: APPROVAL_DATABASE_NAME,
});
const approvalOwner = new ApprovalOwner(approvalRepository);
const operationRepository = new IndexedDbProviderOperationRepository({
  databaseName: OPERATION_DATABASE_NAME,
});
const operationOwner = new ProviderOperationOwner(operationRepository);
const keyring = new KeyringLifecycleOwner(
  chromeApi.storage.local,
  chromeApi.storage.session,
  chromeApi.runtime.id,
);

const approvals: SessionApprovalOwner = Object.freeze({
  async create(params: ApprovalCreateParams): Promise<ApprovalRecord> {
    counters.approvalCreates++;
    const created = await approvalOwner.create(params);
    counters.latestApprovalId = created.id;
    return created;
  },
  read: approvalOwner.read.bind(approvalOwner),
  readSigning: approvalOwner.readSigning.bind(approvalOwner),
  async claimForSigning(
    id: string,
    digest: Uint8Array,
    attemptId: string,
  ): Promise<ApprovalSigningRecord> {
    counters.signingClaims++;
    return approvalOwner.claimForSigning(id, digest, attemptId);
  },
  async completeSigning(
    id: string,
    digest: Uint8Array,
    attemptId: string,
    transactionBytes: Uint8Array,
  ): Promise<ApprovalSigningRecord> {
    counters.signingCompletions++;
    const completed = await approvalOwner.completeSigning(
      id,
      digest,
      attemptId,
      transactionBytes,
    );
    await pauseAtCheckpoint("after-signing-committed");
    return completed;
  },
  failSigning(
    id: string,
    digest: Uint8Array,
    attemptId: string,
    failureCode: ApprovalSigningFailureCode,
  ): Promise<ApprovalSigningRecord> {
    return approvalOwner.failSigning(id, digest, attemptId, failureCode);
  },
  reject: approvalOwner.reject.bind(approvalOwner),
  cancel: approvalOwner.cancel.bind(approvalOwner),
});

const approvalKeyring = Object.freeze({
  useSessionSignerBytes: async (
    operation: string,
    use: (lease: SessionApprovalSignerLease) => Promise<Uint8Array>,
  ): Promise<Uint8Array> => {
    counters.signerLeaseUses++;
    const signed = await keyring.useSessionSignerBytes(operation, use);
    counters.signerResultsProduced++;
    await pauseAtCheckpoint("after-signature-produced");
    return signed;
  },
});

const startup = Promise.all([
  approvalOwner.invalidateAfterWorkerRestart(),
  operationOwner.invalidateAfterWorkerRestart(),
]);
const ready = startup.then(async ([invalidatedApprovals, invalidatedOperations]) => {
  startupInvalidatedApprovals = invalidatedApprovals;
  startupInvalidatedOperations = invalidatedOperations;
  if (await keyring.restore()) {
    keyringStartup = "restored";
    readyFlag = true;
    return;
  }
  if (await keyringWasInitialized()) {
    if (await keyring.isUnlocked()) {
      throw new Error("failed C24 keyring restore retained signer authority");
    }
    keyringStartup = "locked";
    readyFlag = true;
    return;
  }
  const context: KeyringContext = {
    account: SMART_ACCOUNT.toBytes(),
    origin: `chrome-extension://${chromeApi.runtime.id}`,
    keyKind: "session-signer",
    schemaVersion: SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION,
    genesisHash: DEVNET_GENESIS.slice(),
    programId: WARDEN_PROGRAM.toBytes(),
  };
  const password = new TextEncoder().encode("C23 browser-only password");
  try {
    const record = encodeKeyringRecordStorageValue(await sealKeyringRecord({
      metadata: prepareKeyringRecordMetadata({
        argon2idParams: { memoryKiB: 64, timeCost: 1, parallelism: 1 },
        enablePrf: false,
        context,
      }),
      plaintext: encodeSessionSignerPayload(SESSION_SEED.slice()),
      passwordBytes: password.slice(),
    }));
    await keyring.replacePersistentRecord(record);
    await keyring.unlockWithPassword({
      passwordBytes: password.slice(),
      policy: { idleTimeoutMs: 5 * 60_000, hardTimeoutMs: 10 * 60_000 },
    });
    if (!(await keyring.isUnlocked())) {
      throw new Error("test keyring did not unlock");
    }
    await chromeApi.storage.local.set({
      [KEYRING_INITIALIZED_STORAGE_KEY]: true,
    });
    if (!(await keyringWasInitialized())) {
      throw new Error("C24 keyring initialization marker was not retained");
    }
    keyringStartup = "seeded";
    readyFlag = true;
  } finally {
    password.fill(0);
  }
});
void ready.catch((error: unknown) => {
  fatalErrors.push(errorText(error));
});

const selection: ProviderApprovalSelectionResolver = Object.freeze({
  async resolve(input: ProviderApprovalSelectionInput) {
    counters.selectionCalls++;
    try {
      await ready;
      if (input.signal.aborted) throw new Error("provider selection was aborted");
      counters.identityReads++;
      const first = await keyring.readAuthenticatedSessionIdentity(
        "select C23 test release account",
      );
      try {
        if (
          !equalBytes(first.account, SMART_ACCOUNT.toBytes()) ||
          !equalBytes(first.genesisHash, DEVNET_GENESIS) ||
          !equalBytes(first.programId, WARDEN_PROGRAM.toBytes()) ||
          !equalBytes(first.sessionSigner, SESSION_SIGNER.toBytes()) ||
          first.revocationSignal.aborted
        ) {
          throw new Error("authenticated identity differs from the C23 test release");
        }
        const coordinator = createPinnedSessionApprovalCoordinator({
          trustedConnection,
          releasePins,
          sessionSigner: SESSION_SIGNER,
          approvals,
          keyring: approvalKeyring,
          approvalTtlMs: 90_000,
        });
        counters.identityReads++;
        const second = await keyring.readAuthenticatedSessionIdentity(
          "revalidate C23 test release account",
        );
        try {
          if (
            second.revocationSignal !== first.revocationSignal ||
            second.revocationSignal.aborted ||
            !equalBytes(second.account, first.account) ||
            !equalBytes(second.genesisHash, first.genesisHash) ||
            !equalBytes(second.programId, first.programId) ||
            !equalBytes(second.sessionSigner, first.sessionSigner) ||
            input.signal.aborted
          ) {
            throw new Error("authenticated identity changed during C23 selection");
          }
          return Object.freeze({
            account: first.account.slice(),
            authoritySignal: first.revocationSignal,
            chain: "solana:devnet" as const,
            coordinator,
          });
        } finally {
          second.account.fill(0);
          second.genesisHash.fill(0);
          second.programId.fill(0);
          second.sessionSigner.fill(0);
        }
      } finally {
        first.account.fill(0);
        first.genesisHash.fill(0);
        first.programId.fill(0);
        first.sessionSigner.fill(0);
      }
    } catch (error) {
      fatalErrors.push(`selection: ${errorText(error)}`);
      throw error;
    }
  },
});

const actions = new ProviderApprovalActionOwner();
const providerConnects = new RoutedConnectEvent();
const approvalConnects = new RoutedConnectEvent();
const providerRuntime: ProviderRuntimeApi = Object.freeze({
  id: chromeApi.runtime.id,
  onConnect: providerConnects,
});
const approvalRuntime: ProviderRuntimeApi = Object.freeze({
  id: chromeApi.runtime.id,
  onConnect: approvalConnects,
});
const approvalWindows = installApprovalWindowOwner(chromeApi.windows, {
  runtimeId: chromeApi.runtime.id,
  approvals,
  ready,
  onFatal: (error) => fatalErrors.push(errorText(error)),
});
installApprovalReviewBoundary(approvalRuntime, {
  approvals,
  actions,
  ready,
  projectReview: decodeSessionApprovalReview,
  onFatal: (error) => fatalErrors.push(errorText(error)),
});
const approvalRequests = new ProviderApprovalRequestOwner({
  selection,
  approvals,
  windows: approvalWindows,
  onFatal: (error) => fatalErrors.push(errorText(error)),
});
const approvalOperations = new ProviderApprovalOperationOwner({
  actions,
  approvals: approvalRequests,
  operations: operationOwner,
});
const observedApprovalOperations = Object.freeze({
  async launch(lease: ProviderRuntimeTransportLease): Promise<unknown> {
    try {
      return await approvalOperations.launch(lease);
    } catch (error) {
      fatalErrors.push(`approval launch: ${diagnosticErrorText(error)}`);
      throw error;
    }
  },
});
const signedResults = new ProviderTerminalResultOwner({
  operations: operationRepository,
  approvals,
});
const terminalOutcomes = new ProviderTerminalOutcomeOwner({
  operations: operationRepository,
  approvals,
  signed: signedResults,
});
const signedFlow = new ProviderSignedResultFlowOwner({
  approvals: observedApprovalOperations,
  results: terminalOutcomes,
});
const transport = new ProviderRuntimeTransportOwner(providerRuntime, {
  async deliver(lease: ProviderRuntimeTransportLease): Promise<unknown> {
    try {
      await ready;
      lease.assertActive();
      return await signedFlow.deliver(lease);
    } catch (error) {
      fatalErrors.push(`flow: ${errorText(error)}`);
      throw error;
    }
  },
});

// The real runtime has exactly one Port owner. Routing first prevents the
// provider and approval boundaries from disconnecting each other's valid
// channels while retaining fail-closed handling for every unknown name.
chromeApi.runtime.onConnect.addListener((port: ProviderRuntimePort): void => {
  if (port.name === PROVIDER_PORT_NAME) {
    counters.providerPortRoutes++;
    providerConnects.emit(instrumentProviderPort(port));
  } else if (port.name === APPROVAL_UI_PORT_NAME) {
    counters.approvalPortRoutes++;
    approvalConnects.emit(port);
  } else {
    safeDisconnectUnknownPort(port);
  }
});

Object.assign(globalThis, {
  __wardenProviderSignSuccessArmCheckpoint: (stage: unknown): void => {
    if (
      stage !== "after-signature-produced" &&
      stage !== "after-signing-committed" &&
      stage !== "during-signing-commit" &&
      stage !== "after-terminal-enqueued" &&
      stage !== "before-settlement-enqueue"
    ) {
      throw new Error("unsupported signing worker checkpoint");
    }
    if (armedCheckpoint !== null || checkpointReached !== null) {
      throw new Error("signing worker checkpoint is already owned");
    }
    armedCheckpoint = stage;
  },
  __wardenProviderSignSuccessStatus: async (approvalId?: string) => {
    await ready;
    const id = approvalId ?? counters.latestApprovalId;
    const approval = id === null ? null : await approvals.read(id);
    let signing: ApprovalSigningRecord | null = null;
    if (approval !== null) {
      signing = await approvals.readSigning(approval.id, approval.messageDigest);
    }
    const durableSignedTransaction = signing?.outcome.transactionBytes ?? null;
    try {
      return {
        bootId,
        ready: readyFlag,
        keyringStartup,
        checkpointReached,
        fatalErrors: [...fatalErrors],
        startupInvalidatedApprovals,
        startupInvalidatedOperations,
        keyringUnlocked: await keyring.isUnlocked(),
        providerPortRoutes: counters.providerPortRoutes,
        approvalPortRoutes: counters.approvalPortRoutes,
        selectionCalls: counters.selectionCalls,
        identityReads: counters.identityReads,
        approvalCreates: counters.approvalCreates,
        signingClaims: counters.signingClaims,
        signingCompletions: counters.signingCompletions,
        signerLeaseUses: counters.signerLeaseUses,
        signerResultsProduced: counters.signerResultsProduced,
        latestApprovalId: id,
        approvalState: approval?.state ?? null,
        signingState: signing?.outcome.state ?? null,
        signingAttemptNumber: signing?.outcome.attemptNumber ?? null,
        signingFailureCode: signing?.outcome.failureCode ?? null,
        account: SMART_ACCOUNT.toBase58(),
        sessionSigner: SESSION_SIGNER.toBase58(),
        rawMessage: approval === null ? null : [...approval.rawMessage],
        messageDigestHex: approval === null
          ? null
          : [...approval.messageDigest]
              .map((value) => value.toString(16).padStart(2, "0"))
              .join(""),
        durableSignedTransaction:
          signing?.outcome.state === "signed" && durableSignedTransaction !== null
            ? [...durableSignedTransaction]
            : null,
        rpc: { ...rpcCounters },
        activeActions: actions.activeCount,
        activeApprovalRequests: approvalRequests.activeCount,
        activeFlows: signedFlow.activeCount,
        activeDocuments: transport.activeDocumentCount,
      };
    } finally {
      approval?.account.fill(0);
      approval?.genesisHash.fill(0);
      approval?.programId.fill(0);
      approval?.rawMessage.fill(0);
      approval?.messageDigest.fill(0);
      signing?.approval.account.fill(0);
      signing?.approval.genesisHash.fill(0);
      signing?.approval.programId.fill(0);
      signing?.approval.rawMessage.fill(0);
      signing?.approval.messageDigest.fill(0);
      signing?.outcome.messageDigest.fill(0);
      signing?.outcome.transactionBytes?.fill(0);
      signing?.outcome.transactionDigest?.fill(0);
    }
  },
});
