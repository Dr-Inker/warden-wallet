import { PublicKey, type Connection } from "@solana/web3.js";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  SessionApprovalKeyring,
  SessionApprovalOwner,
} from "@warden/core/transaction/session-approval";
import type { SessionApprovalReleasePins } from "@warden/core/transaction/session-rpc";

const releaseMocks = vi.hoisted(() => ({
  resolve: vi.fn(),
  create: vi.fn(),
}));

vi.mock("@warden/core/transaction/session-release", async (importOriginal) => {
  const actual = await importOriginal<
    typeof import("@warden/core/transaction/session-release")
  >();
  return {
    ...actual,
    resolveCommittedSessionRelease: releaseMocks.resolve,
    createCommittedSessionApprovalCoordinator: releaseMocks.create,
  };
});

import {
  CommittedProviderApprovalSelectionResolver,
} from "../src/background/provider-approval-selection.js";
import type {
  AuthenticatedSessionIdentity,
  KeyringLifecycle,
} from "../src/background/keyring-lifecycle.js";

const fill = (value: number): Uint8Array => new Uint8Array(32).fill(value);
const RELEASE_NAME = "devnet-r1";
const ACCOUNT = fill(0x41);
const GENESIS = fill(0x52);
const PROGRAM = fill(0x63);
const SESSION_SIGNER = fill(0x74);
const DEFAULT_REVOCATION = new AbortController();
const PINS: SessionApprovalReleasePins = Object.freeze({
  chain: "solana:devnet",
  genesisHash: GENESIS,
  wardenProgram: new PublicKey(PROGRAM),
  wardenProgramDataSlot: 123n,
  wardenUpgradeAuthority: new PublicKey(fill(0x81)),
  wardenCodeHash: fill(0x82),
  wardenProgramDataHash: fill(0x83),
  wardenProgramDataBytes: 96,
});

function identity(
  overrides: Partial<AuthenticatedSessionIdentity> = {},
): AuthenticatedSessionIdentity {
  return Object.freeze({
    account: (overrides.account ?? ACCOUNT).slice(),
    genesisHash: (overrides.genesisHash ?? GENESIS).slice(),
    programId: (overrides.programId ?? PROGRAM).slice(),
    revocationSignal: overrides.revocationSignal ?? DEFAULT_REVOCATION.signal,
    sessionSigner: (overrides.sessionSigner ?? SESSION_SIGNER).slice(),
  });
}

function fakeKeyring(
  reads: readonly AuthenticatedSessionIdentity[],
): KeyringLifecycle & { readonly identityCalls: string[] } {
  let index = 0;
  const identityCalls: string[] = [];
  return {
    identityCalls,
    async readAuthenticatedSessionIdentity(operation: string) {
      identityCalls.push(operation);
      const value = reads[Math.min(index, reads.length - 1)];
      index++;
      if (value === undefined) throw new Error("missing fake identity");
      return identity(value);
    },
    async isUnlocked() {
      return true;
    },
    async lock() {},
    async replacePersistentRecord() {},
    async clearPersistentRecord() {},
    async unlockWithPassword() {},
    async useSessionSignerBytes() {
      throw new Error("selection must not request signer seed bytes");
    },
  };
}

function install(
  keyring: KeyringLifecycle = fakeKeyring([identity(), identity()]),
  signal = new AbortController().signal,
) {
  const coordinator = Object.freeze({
    prepare: vi.fn(),
    cancel: vi.fn(),
  });
  const connection = Object.freeze({ marker: "trusted-connection" }) as unknown as Connection;
  const connectionFactory = { create: vi.fn(() => connection) };
  const approvals = Object.freeze({ marker: "approvals" }) as unknown as SessionApprovalOwner;
  const resolver = new CommittedProviderApprovalSelectionResolver({
    releaseName: RELEASE_NAME,
    connectionFactory,
    approvals,
    keyring,
    readNow: () => 1_700_000_000_000,
    approvalTtlMs: 60_000,
  });
  const selectorReads = {
    requestedAccountAddress: 0,
    requestedChain: 0,
    rpcUrl: 0,
    releaseDocument: 0,
    programId: 0,
    deployPin: 0,
  };
  const input = {
    method: "solana:signTransaction" as const,
    get requestedAccountAddress(): string {
      selectorReads.requestedAccountAddress++;
      throw new Error("untrusted page account must not drive composition");
    },
    get requestedChain(): "solana:devnet" {
      selectorReads.requestedChain++;
      throw new Error("untrusted page chain must not drive composition");
    },
    get rpcUrl(): string {
      selectorReads.rpcUrl++;
      throw new Error("page RPC URL must not be read");
    },
    get releaseDocument(): string {
      selectorReads.releaseDocument++;
      throw new Error("page release document must not be read");
    },
    get programId(): string {
      selectorReads.programId++;
      throw new Error("page program id must not be read");
    },
    get deployPin(): string {
      selectorReads.deployPin++;
      throw new Error("page deployment pin must not be read");
    },
    signal,
  };
  releaseMocks.resolve.mockReturnValue(PINS);
  releaseMocks.create.mockReturnValue(coordinator);
  return {
    approvals,
    connection,
    connectionFactory,
    coordinator,
    input,
    keyring,
    resolver,
    selectorReads,
  };
}

describe("source-owned committed provider selection", () => {
  beforeEach(() => {
    releaseMocks.resolve.mockReset();
    releaseMocks.create.mockReset();
  });

  it("joins two stable authenticated public identities to one committed release and trusted Connection", async () => {
    const installed = install();

    const selected = await installed.resolver.resolve(installed.input);

    expect(releaseMocks.resolve).toHaveBeenCalledTimes(1);
    expect(releaseMocks.resolve).toHaveBeenCalledWith(RELEASE_NAME);
    expect(installed.connectionFactory.create).toHaveBeenCalledTimes(1);
    expect(installed.connectionFactory.create).toHaveBeenCalledWith();
    expect((installed.keyring as unknown as { identityCalls: string[] }).identityCalls).toEqual([
      "select committed provider account",
      "revalidate committed provider account",
    ]);
    expect(releaseMocks.create).toHaveBeenCalledTimes(1);
    const composition = releaseMocks.create.mock.calls[0]![0];
    expect(composition.releaseName).toBe(RELEASE_NAME);
    expect(composition.trustedConnection).toBe(installed.connection);
    expect(composition.sessionSigner).toBeInstanceOf(PublicKey);
    expect(composition.sessionSigner.toBytes()).toEqual(SESSION_SIGNER);
    expect(composition.approvals).toBe(installed.approvals);
    expect(composition.keyring).not.toBe(installed.keyring);
    expect(Object.keys(composition.keyring)).toEqual(["useSessionSignerBytes"]);
    expect(composition.readNow()).toBe(1_700_000_000_000);
    expect(composition.approvalTtlMs).toBe(60_000);
    expect(selected.account).toEqual(ACCOUNT);
    expect(selected.account).not.toBe(ACCOUNT);
    expect(selected.chain).toBe("solana:devnet");
    expect(selected.coordinator).toBe(installed.coordinator);
    expect(selected.authoritySignal).toBe(DEFAULT_REVOCATION.signal);
    expect(installed.selectorReads).toEqual({
      requestedAccountAddress: 0,
      requestedChain: 0,
      rpcUrl: 0,
      releaseDocument: 0,
      programId: 0,
      deployPin: 0,
    });
  });

  it.each([
    ["account", identity({ account: fill(0x91) })],
    ["genesis hash", identity({ genesisHash: fill(0x92) })],
    ["program id", identity({ programId: fill(0x93) })],
    ["session signer", identity({ sessionSigner: fill(0x94) })],
    [
      "unlock generation",
      identity({ revocationSignal: new AbortController().signal }),
    ],
  ])("suppresses a composed coordinator when the authenticated %s changes in flight", async (_label, changed) => {
    const keyring = fakeKeyring([identity(), changed]);
    const installed = install(keyring);

    await expect(installed.resolver.resolve(installed.input)).rejects.toMatchObject({
      name: "ProviderApprovalSelectionError",
      code: "IDENTITY_CHANGED",
    });
    expect(installed.connectionFactory.create).toHaveBeenCalledTimes(1);
    expect(releaseMocks.create).toHaveBeenCalledTimes(1);
    expect(keyring.identityCalls).toHaveLength(2);
  });

  it("refuses an already-revoked authenticated identity before composition", async () => {
    const revocation = new AbortController();
    revocation.abort();
    const keyring = fakeKeyring([
      identity({ revocationSignal: revocation.signal }),
    ]);
    const installed = install(keyring);

    await expect(installed.resolver.resolve(installed.input)).rejects.toMatchObject({
      name: "ProviderApprovalSelectionError",
      code: "IDENTITY_CHANGED",
    });
    expect(installed.connectionFactory.create).not.toHaveBeenCalled();
    expect(releaseMocks.create).not.toHaveBeenCalled();
    expect(keyring.identityCalls).toHaveLength(1);
  });

  it("suppresses composition when the stable identity generation revokes on revalidation", async () => {
    const revocation = new AbortController();
    const keyring = fakeKeyring([
      identity({ revocationSignal: revocation.signal }),
      identity({ revocationSignal: revocation.signal }),
    ]);
    const originalRead = keyring.readAuthenticatedSessionIdentity.bind(keyring);
    let reads = 0;
    keyring.readAuthenticatedSessionIdentity = async (operation: string) => {
      const value = await originalRead(operation);
      reads++;
      if (reads === 2) revocation.abort();
      return value;
    };
    const installed = install(keyring);

    await expect(installed.resolver.resolve(installed.input)).rejects.toMatchObject({
      name: "ProviderApprovalSelectionError",
      code: "IDENTITY_CHANGED",
    });
    expect(installed.connectionFactory.create).toHaveBeenCalledTimes(1);
    expect(releaseMocks.create).toHaveBeenCalledTimes(1);
    expect(keyring.identityCalls).toHaveLength(2);
  });

  it.each([
    ["genesis hash", identity({ genesisHash: fill(0xa1) })],
    ["program id", identity({ programId: fill(0xa2) })],
  ])("refuses a keyring/release %s mismatch before Connection construction", async (_label, mismatched) => {
    const keyring = fakeKeyring([mismatched]);
    const installed = install(keyring);

    await expect(installed.resolver.resolve(installed.input)).rejects.toMatchObject({
      name: "ProviderApprovalSelectionError",
      code: "RELEASE_MISMATCH",
    });
    expect(installed.connectionFactory.create).not.toHaveBeenCalled();
    expect(releaseMocks.create).not.toHaveBeenCalled();
    expect(keyring.identityCalls).toHaveLength(1);
  });

  it("stops after authenticated identity when the provider lifetime aborts", async () => {
    const controller = new AbortController();
    const keyring = fakeKeyring([identity(), identity()]);
    const originalRead = keyring.readAuthenticatedSessionIdentity.bind(keyring);
    keyring.readAuthenticatedSessionIdentity = async (operation: string) => {
      const value = await originalRead(operation);
      controller.abort();
      return value;
    };
    const installed = install(keyring, controller.signal);

    await expect(installed.resolver.resolve(installed.input)).rejects.toMatchObject({
      name: "ProviderApprovalSelectionError",
      code: "REQUEST_ABORTED",
    });
    expect(installed.connectionFactory.create).not.toHaveBeenCalled();
    expect(releaseMocks.create).not.toHaveBeenCalled();
  });
});
