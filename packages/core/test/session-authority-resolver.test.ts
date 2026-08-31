import {
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SYSVAR_CLOCK_PUBKEY,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
  type AccountInfo,
  type Connection,
} from "@solana/web3.js";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  createPendingApprovalRecord,
  resolveApprovalRecord,
  snapshotApprovalRecord,
  type ApprovalCreateParams,
  type ApprovalRecord,
} from "../src/approval/record.js";
import {
  PROGRAMDATA_METADATA_LEN,
} from "../src/deploy/accounts.js";
import { BPF_UPGRADEABLE_LOADER } from "../src/deploy/config.js";
import {
  encodeProgramAccount,
  encodeProgramData,
} from "../src/deploy/fixtures.js";
import {
  SessionApprovalCoordinator,
  type SessionApprovalBlockhashClient,
  type SessionApprovalKeyring,
  type SessionApprovalOwner,
} from "../src/transaction/session-approval-coordinator.js";
import {
  ConnectionSessionAuthorityRpc,
  PinnedSessionAuthorityResolver,
  SESSION_AUTHORITY_ACCOUNT_COUNT,
  SESSION_AUTHORITY_CLOCK_SAFETY_SECONDS,
  SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES,
  SessionAuthorityResolverError,
  deriveWardenProgramDataAddress,
  type SessionAuthorityResolverErrorCode,
  type SessionAuthorityRpc,
  type SessionAuthorityRpcAccount,
} from "../src/transaction/session-authority-resolver.js";
import {
  DeterministicSessionIntentGate,
  encodeSessionAuthorizationState,
} from "../src/transaction/session-intent.js";

const fill = (value: number): Uint8Array => new Uint8Array(32).fill(value);
const key = (value: number): PublicKey => new PublicKey(fill(value));
const writeU16le = (bytes: Uint8Array, offset: number, value: number): void => {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
};
const writeU32le = (bytes: Uint8Array, offset: number, value: number): void => {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
};
const writeU64le = (bytes: Uint8Array, offset: number, value: bigint): void => {
  let remaining = value;
  for (let index = 0; index < 8; index++) {
    bytes[offset + index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
};
const hexToBytes = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g)!.map((byte) => Number.parseInt(byte, 16)));

function readTypeScriptTree(directory: string): string {
  let source = "";
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) source += readTypeScriptTree(path);
    else if (entry.isFile() && entry.name.endsWith(".ts")) {
      source += readFileSync(path, "utf8");
    }
  }
  return source;
}

const WARDEN_PROGRAM = new PublicKey(
  "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2",
);
const MEMO_PROGRAM = new PublicKey(
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
);
const SYSVAR_OWNER = new PublicKey(
  "Sysvar1111111111111111111111111111111111111",
);
const OWNER_SEED = fill(0x11);
const SESSION_SEED = fill(0x22);
const SESSION_SIGNER = Keypair.fromSeed(SESSION_SEED).publicKey;
const UPGRADE_AUTHORITY = key(0xaa);
const ACCOUNT_GENERATION = 7n;
const POLICY_VERSION = 1;
const SESSION_EXPIRY = 2_000_000_000;
const OBSERVED_TIME = 1_900_000_000;
const PROGRAMDATA_SLOT = 123n;
const CONTEXT_SLOT = 42;
const FINAL_BLOCKHASH = fill(0x88);
const PROGRAM_CODE = new TextEncoder().encode("warden-authority-resolver-fixture");
// Independent Node/OpenSSL SHA-256 goldens, not derived by the deploy decoder.
const EXPECTED_CODE_HASH = hexToBytes(
  "65cdfd837999b58ee226aa6f50316acc9b3e522e7d20a50314640b3526437466",
);
const EXPECTED_PROGRAM_DATA_HASH = hexToBytes(
  "3dda51c71e3d54acaf5a2180421bf03a8ceff59fafd0bfb721c23cc1aa32a96a",
);
const DEVNET_GENESIS = new PublicKey(
  SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES["solana:devnet"],
).toBytes();

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
const PROGRAM_DATA = deriveWardenProgramDataAddress(WARDEN_PROGRAM);

const SMART_DISCRIMINATOR = Uint8Array.of(
  186, 83, 247, 224, 59, 95, 223, 112,
);
const SESSION_DISCRIMINATOR = Uint8Array.of(
  93, 186, 163, 139, 160, 255, 81, 112,
);
const REGISTRY_DISCRIMINATOR = Uint8Array.of(
  47, 174, 110, 246, 184, 182, 252, 218,
);

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

function clockData(slot = CONTEXT_SLOT, unixTimestamp = OBSERVED_TIME): Uint8Array {
  const bytes = new Uint8Array(40);
  writeU64le(bytes, 0, BigInt(slot));
  writeU64le(bytes, 8, BigInt(unixTimestamp - 1_000));
  writeU64le(bytes, 16, 10n);
  writeU64le(bytes, 24, 11n);
  writeU64le(bytes, 32, BigInt(unixTimestamp));
  return bytes;
}

const account = (
  owner: PublicKey,
  data: Uint8Array,
  executable = false,
): SessionAuthorityRpcAccount => ({ owner, data, executable });

interface AuthorityFixture {
  readonly rpc: MapAuthorityRpc;
  readonly resolver: PinnedSessionAuthorityResolver;
  readonly programDataBytes: Uint8Array;
  readonly expectedCodeHash: Uint8Array;
  readonly expectedProgramDataHash: Uint8Array;
}

class MapAuthorityRpc implements SessionAuthorityRpc {
  genesisHash = SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES["solana:devnet"];
  contextSlot = CONTEXT_SLOT;
  unixTimestamp = OBSERVED_TIME;
  readonly accounts = new Map<string, SessionAuthorityRpcAccount | null>();
  readonly requests: {
    addresses: string[];
    commitment: string;
    minContextSlot: number;
  }[] = [];
  responseOverride:
    | ((input: Parameters<SessionAuthorityRpc["getMultipleAccounts"]>[0]) =>
        ReturnType<SessionAuthorityRpc["getMultipleAccounts"]>)
    | undefined;

  async getGenesisHash(): Promise<string> {
    return this.genesisHash;
  }

  async getMultipleAccounts(input: {
    readonly addresses: readonly PublicKey[];
    readonly commitment: "confirmed";
    readonly minContextSlot: number;
  }): Promise<{
    readonly contextSlot: number;
    readonly accounts: readonly (SessionAuthorityRpcAccount | null)[];
  }> {
    if (this.responseOverride !== undefined) {
      return this.responseOverride(input);
    }
    const contextSlot = Math.max(this.contextSlot, input.minContextSlot);
    const clock = this.accounts.get(SYSVAR_CLOCK_PUBKEY.toBase58());
    if (clock !== null && clock !== undefined) {
      this.accounts.set(
        SYSVAR_CLOCK_PUBKEY.toBase58(),
        account(SYSVAR_OWNER, clockData(contextSlot, this.unixTimestamp)),
      );
    }
    this.requests.push({
      addresses: input.addresses.map((address) => address.toBase58()),
      commitment: input.commitment,
      minContextSlot: input.minContextSlot,
    });
    return {
      contextSlot,
      accounts: input.addresses.map(
        (address) => this.accounts.get(address.toBase58()) ?? null,
      ),
    };
  }
}

function authorityFixture(): AuthorityFixture {
  const rpc = new MapAuthorityRpc();
  const programDataBytes = encodeProgramData({
    slot: PROGRAMDATA_SLOT,
    authority: UPGRADE_AUTHORITY,
    code: PROGRAM_CODE,
    trailingZeros: 16,
  });
  const expectedCodeHash = EXPECTED_CODE_HASH.slice();
  const expectedProgramDataHash = EXPECTED_PROGRAM_DATA_HASH.slice();
  rpc.accounts.set(
    SMART_ACCOUNT.toBase58(),
    account(WARDEN_PROGRAM, smartData()),
  );
  rpc.accounts.set(
    SESSION_ACCOUNT.toBase58(),
    account(WARDEN_PROGRAM, sessionData()),
  );
  rpc.accounts.set(REGISTRY.toBase58(), account(WARDEN_PROGRAM, registryData()));
  rpc.accounts.set(
    WARDEN_PROGRAM.toBase58(),
    account(
      BPF_UPGRADEABLE_LOADER,
      encodeProgramAccount(PROGRAM_DATA),
      true,
    ),
  );
  rpc.accounts.set(
    PROGRAM_DATA.toBase58(),
    account(BPF_UPGRADEABLE_LOADER, programDataBytes),
  );
  rpc.accounts.set(
    SYSVAR_CLOCK_PUBKEY.toBase58(),
    account(SYSVAR_OWNER, clockData()),
  );
  const resolver = new PinnedSessionAuthorityResolver({
    rpc,
    sessionSigner: SESSION_SIGNER,
    expectedWardenProgramDataSlot: PROGRAMDATA_SLOT,
    expectedWardenUpgradeAuthority: UPGRADE_AUTHORITY,
    expectedWardenCodeHash: expectedCodeHash,
    expectedWardenProgramDataHash: expectedProgramDataHash,
    expectedWardenProgramDataBytes: programDataBytes.length,
  });
  return {
    rpc,
    resolver,
    programDataBytes,
    expectedCodeHash,
    expectedProgramDataHash,
  };
}

async function resolveAuthority(
  fixture = authorityFixture(),
  minContextSlot = 0,
) {
  return fixture.resolver.resolve({
    selection: {
      account: SMART_ACCOUNT.toBytes(),
      chain: "solana:devnet",
    },
    commitment: "confirmed",
    minContextSlot,
  });
}

async function captureError(
  run: () => Promise<unknown>,
  code: SessionAuthorityResolverErrorCode,
): Promise<SessionAuthorityResolverError> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(SessionAuthorityResolverError);
    expect((error as SessionAuthorityResolverError).code).toBe(code);
    return error as SessionAuthorityResolverError;
  }
  throw new Error(`expected ${code}`);
}

class MemoryApprovalOwner implements SessionApprovalOwner {
  readonly records = new Map<string, ApprovalRecord>();

  async create(params: ApprovalCreateParams): Promise<ApprovalRecord> {
    const record = createPendingApprovalRecord(params);
    this.records.set(record.id, snapshotApprovalRecord(record));
    return snapshotApprovalRecord(record);
  }

  async read(id: string): Promise<ApprovalRecord | null> {
    const record = this.records.get(id);
    return record === undefined ? null : snapshotApprovalRecord(record);
  }

  async claimForSigning(id: string, digest: Uint8Array): Promise<ApprovalRecord> {
    const record = this.records.get(id);
    if (record === undefined || record.state !== "pending") {
      throw new Error("not pending");
    }
    if (!record.messageDigest.every((byte, index) => byte === digest[index])) {
      throw new Error("digest mismatch");
    }
    const approved = resolveApprovalRecord(record, "approved", 1_900_000_000_001);
    this.records.set(id, approved);
    return snapshotApprovalRecord(approved);
  }

  async reject(id: string): Promise<ApprovalRecord> {
    return this.resolve(id, "rejected");
  }

  async cancel(id: string): Promise<ApprovalRecord> {
    return this.resolve(id, "cancelled");
  }

  private resolve(id: string, state: "rejected" | "cancelled"): ApprovalRecord {
    const record = this.records.get(id);
    if (record === undefined || record.state !== "pending") {
      throw new Error("not pending");
    }
    const resolved = resolveApprovalRecord(record, state, 1_900_000_000_001);
    this.records.set(id, resolved);
    return snapshotApprovalRecord(resolved);
  }
}

describe("pinned session authority resolver", () => {
  it("publishes the resolver only as a separate opt-in package subpath", () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(import.meta.dirname, "../package.json"), "utf8"),
    ) as { exports: Record<string, { import: string; types: string }> };
    expect(packageJson.exports["./transaction/session-authority"]).toEqual({
      types: "./dist/transaction/session-authority-resolver.d.ts",
      import: "./dist/transaction/session-authority-resolver.js",
    });
    expect(
      readFileSync(
        resolve(import.meta.dirname, "../src/transaction/index.ts"),
        "utf8",
      ),
    ).not.toContain("session-authority-resolver");
    expect(
      readTypeScriptTree(
        resolve(import.meta.dirname, "../../../apps/extension/src"),
      ),
    ).not.toContain("session-authority");
  });

  it("pins public chain labels to the canonical genesis hashes", () => {
    expect(SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES).toEqual({
      "solana:mainnet": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
      "solana:devnet": "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
      "solana:testnet": "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
    });
    expect(Object.isFrozen(SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES)).toBe(true);
  });

  it("pins the shipped program's canonical ProgramData PDA", () => {
    expect(PROGRAM_DATA.toBase58()).toBe(
      "Eb2gEx5X9TUwJ7z8hhg1SC4GHSEW72ohG7L7emve9bpf",
    );
  });

  it("resolves all authority, executable identity, and Clock facts from one snapshot", async () => {
    const fixture = authorityFixture();
    const snapshot = await resolveAuthority(fixture);
    expect(fixture.rpc.requests).toHaveLength(1);
    expect(fixture.rpc.requests[0]).toEqual({
      addresses: [
        SMART_ACCOUNT.toBase58(),
        SESSION_ACCOUNT.toBase58(),
        REGISTRY.toBase58(),
        WARDEN_PROGRAM.toBase58(),
        PROGRAM_DATA.toBase58(),
        SYSVAR_CLOCK_PUBKEY.toBase58(),
      ],
      commitment: "confirmed",
      minContextSlot: 0,
    });
    expect(SESSION_AUTHORITY_ACCOUNT_COUNT).toBe(6);
    expect(snapshot).toMatchObject({
      chain: "solana:devnet",
      smartAccount: SMART_ACCOUNT,
      sessionSigner: SESSION_SIGNER,
      sessionAccount: SESSION_ACCOUNT,
      registry: REGISTRY,
      wardenProgram: WARDEN_PROGRAM,
      wardenProgramData: PROGRAM_DATA,
      wardenProgramDataSlot: PROGRAMDATA_SLOT,
      wardenUpgradeAuthority: UPGRADE_AUTHORITY,
      accountGeneration: ACCOUNT_GENERATION,
      policyVersion: POLICY_VERSION,
      observedUnixTimestamp: OBSERVED_TIME,
      contextSlot: CONTEXT_SLOT,
    });
    expect(snapshot.genesisHash).toEqual(DEVNET_GENESIS);
    expect(snapshot.wardenCodeHash).toEqual(fixture.expectedCodeHash);
    expect(snapshot.wardenProgramDataHash).toEqual(
      fixture.expectedProgramDataHash,
    );
    expect(snapshot.authorizationState).toEqual(
      encodeSessionAuthorizationState({
        smartAccount: {
          owner: WARDEN_PROGRAM,
          executable: false,
          data: smartData(),
        },
        session: {
          owner: WARDEN_PROGRAM,
          executable: false,
          data: sessionData(),
        },
        registry: {
          owner: WARDEN_PROGRAM,
          executable: false,
          data: registryData(),
        },
      }),
    );
  });

  it("snapshots release pins and RPC capabilities at construction", async () => {
    const fixture = authorityFixture();
    fixture.expectedCodeHash.fill(0);
    fixture.expectedProgramDataHash.fill(0);
    fixture.rpc.getGenesisHash = async () =>
      SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES["solana:mainnet"];
    fixture.rpc.getMultipleAccounts = async () => ({
      contextSlot: 0,
      accounts: [],
    });

    const snapshot = await resolveAuthority(fixture);
    expect(snapshot.contextSlot).toBe(CONTEXT_SLOT);
    expect(snapshot.wardenCodeHash).not.toEqual(new Uint8Array(32));
    expect(snapshot.wardenProgramDataHash).not.toEqual(new Uint8Array(32));
  });

  it("rejects malformed release configuration before RPC", () => {
    const fixture = authorityFixture();
    const base: ConstructorParameters<typeof PinnedSessionAuthorityResolver>[0] = {
      rpc: fixture.rpc,
      sessionSigner: SESSION_SIGNER,
      expectedWardenProgramDataSlot: PROGRAMDATA_SLOT,
      expectedWardenUpgradeAuthority: UPGRADE_AUTHORITY,
      expectedWardenCodeHash: fixture.expectedCodeHash,
      expectedWardenProgramDataHash: fixture.expectedProgramDataHash,
      expectedWardenProgramDataBytes: fixture.programDataBytes.length,
    };
    const invalid = [
      { expectedWardenProgramDataSlot: -1n },
      { sessionSigner: new PublicKey(new Uint8Array(32)) },
      { expectedWardenUpgradeAuthority: new PublicKey(new Uint8Array(32)) },
      { expectedWardenCodeHash: new Uint8Array(32) },
      { expectedWardenCodeHash: new Uint8Array(31) },
      { expectedWardenProgramDataHash: new Uint8Array(32) },
      { expectedWardenProgramDataHash: new Uint8Array(33) },
      { expectedWardenProgramDataBytes: PROGRAMDATA_METADATA_LEN },
      { expectedWardenProgramDataBytes: 10 * 1_024 * 1_024 + 1 },
      { localnetGenesisHash: new Uint8Array(32) },
    ];

    for (const override of invalid) {
      let caught: unknown;
      try {
        new PinnedSessionAuthorityResolver({
          ...base,
          ...override,
        });
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(SessionAuthorityResolverError);
      expect((caught as SessionAuthorityResolverError).code).toBe(
        "INVALID_CONFIG",
      );
    }
    expect(fixture.rpc.requests).toHaveLength(0);
  });

  it("rejects malformed resolver requests before RPC", async () => {
    const fixture = authorityFixture();
    const valid = {
      selection: {
        account: SMART_ACCOUNT.toBytes(),
        chain: "solana:devnet" as const,
      },
      commitment: "confirmed" as const,
      minContextSlot: 0,
    };
    const invalid = [
      { ...valid, commitment: "finalized" },
      { ...valid, minContextSlot: -1 },
      {
        ...valid,
        selection: { ...valid.selection, account: new Uint8Array(32) },
      },
      {
        ...valid,
        selection: { ...valid.selection, chain: "solana:unknown" },
      },
    ];

    for (const request of invalid) {
      await captureError(
        () => fixture.resolver.resolve(request as never),
        "INVALID_REQUEST",
      );
    }
    expect(fixture.rpc.requests).toHaveLength(0);
  });

  it("honours minContextSlot and rejects an RPC context regression", async () => {
    const fixture = authorityFixture();
    expect((await resolveAuthority(fixture, 99)).contextSlot).toBe(99);
    fixture.rpc.responseOverride = async () => ({
      contextSlot: 98,
      accounts: [],
    });
    await captureError(() => resolveAuthority(fixture, 99), "RPC_RESPONSE_INVALID");
  });

  it("rejects a wrong, malformed, or noncanonical genesis response", async () => {
    for (const genesisHash of [
      SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES["solana:mainnet"],
      "not-base58",
      "11111111111111111111111111111111",
    ]) {
      const fixture = authorityFixture();
      fixture.rpc.genesisHash = genesisHash;
      await captureError(
        () => resolveAuthority(fixture),
        genesisHash ===
          SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES["solana:mainnet"]
          ? "GENESIS_MISMATCH"
          : "RPC_RESPONSE_INVALID",
      );
    }
  });

  it("requires an explicit genesis pin for localnet and accepts only that exact hash", async () => {
    const fixture = authorityFixture();
    await captureError(
      () =>
        fixture.resolver.resolve({
          selection: {
            account: SMART_ACCOUNT.toBytes(),
            chain: "solana:localnet",
          },
          commitment: "confirmed",
          minContextSlot: 0,
        }),
      "LOCALNET_GENESIS_UNPINNED",
    );
    const localGenesis = key(0xcc);
    fixture.rpc.genesisHash = localGenesis.toBase58();
    const resolver = new PinnedSessionAuthorityResolver({
      rpc: fixture.rpc,
      sessionSigner: SESSION_SIGNER,
      expectedWardenProgramDataSlot: PROGRAMDATA_SLOT,
      expectedWardenUpgradeAuthority: UPGRADE_AUTHORITY,
      expectedWardenCodeHash: fixture.expectedCodeHash,
      expectedWardenProgramDataHash: fixture.expectedProgramDataHash,
      expectedWardenProgramDataBytes: fixture.programDataBytes.length,
      localnetGenesisHash: localGenesis.toBytes(),
    });
    const smart = smartData();
    smart.set(localGenesis.toBytes(), 175);
    fixture.rpc.accounts.set(
      SMART_ACCOUNT.toBase58(),
      account(WARDEN_PROGRAM, smart),
    );
    const snapshot = await resolver.resolve({
      selection: {
        account: SMART_ACCOUNT.toBytes(),
        chain: "solana:localnet",
      },
      commitment: "confirmed",
      minContextSlot: 0,
    });
    expect(snapshot.genesisHash).toEqual(localGenesis.toBytes());
  });

  it("rejects every absent account in the fixed snapshot", async () => {
    for (const missing of [
      SMART_ACCOUNT,
      SESSION_ACCOUNT,
      REGISTRY,
      WARDEN_PROGRAM,
      PROGRAM_DATA,
      SYSVAR_CLOCK_PUBKEY,
    ]) {
      const fixture = authorityFixture();
      fixture.rpc.accounts.set(missing.toBase58(), null);
      const error = await captureError(
        () => resolveAuthority(fixture),
        "ACCOUNT_MISSING",
      );
      expect(error.message).toContain(missing.toBase58());
    }
  });

  it("rejects malformed Warden state containers before emitting a packet", async () => {
    const mutations: ((fixture: AuthorityFixture) => void)[] = [
      (fixture) =>
        fixture.rpc.accounts.set(
          SMART_ACCOUNT.toBase58(),
          account(key(0xdd), smartData()),
        ),
      (fixture) =>
        fixture.rpc.accounts.set(
          SESSION_ACCOUNT.toBase58(),
          account(WARDEN_PROGRAM, sessionData(), true),
        ),
      (fixture) =>
        fixture.rpc.accounts.set(
          REGISTRY.toBase58(),
          account(WARDEN_PROGRAM, registryData().slice(1)),
        ),
      (fixture) => {
        const smart = smartData();
        smart[0] ^= 0xff;
        fixture.rpc.accounts.set(
          SMART_ACCOUNT.toBase58(),
          account(WARDEN_PROGRAM, smart),
        );
      },
      (fixture) => {
        const smart = smartData();
        smart[12] = 1;
        fixture.rpc.accounts.set(
          SMART_ACCOUNT.toBase58(),
          account(WARDEN_PROGRAM, smart),
        );
      },
      (fixture) => {
        const session = sessionData();
        writeU64le(session, 75, BigInt(OBSERVED_TIME));
        fixture.rpc.accounts.set(
          SESSION_ACCOUNT.toBase58(),
          account(WARDEN_PROGRAM, session),
        );
      },
    ];
    for (const mutate of mutations) {
      const fixture = authorityFixture();
      mutate(fixture);
      await captureError(() => resolveAuthority(fixture), "AUTHORITY_NOT_USABLE");
    }
  });

  it("rejects a noncanonical or substituted Program account", async () => {
    const cases: SessionAuthorityRpcAccount[] = [
      account(BPF_UPGRADEABLE_LOADER, encodeProgramAccount(PROGRAM_DATA), false),
      account(key(0xee), encodeProgramAccount(PROGRAM_DATA), true),
      account(BPF_UPGRADEABLE_LOADER, Uint8Array.of(1, 0, 0, 0), true),
      account(
        BPF_UPGRADEABLE_LOADER,
        Uint8Array.from([...encodeProgramAccount(PROGRAM_DATA), 0]),
        true,
      ),
      account(
        BPF_UPGRADEABLE_LOADER,
        encodeProgramAccount(key(0xef)),
        true,
      ),
    ];
    for (const value of cases) {
      const fixture = authorityFixture();
      fixture.rpc.accounts.set(WARDEN_PROGRAM.toBase58(), value);
      await captureError(
        () => resolveAuthority(fixture),
        "PROGRAM_IDENTITY_MISMATCH",
      );
    }
  });

  it("rejects ProgramData owner, executable, length, slot, authority, code, and raw-byte drift", async () => {
    const mutations: ((fixture: AuthorityFixture) => void)[] = [
      (fixture) =>
        fixture.rpc.accounts.set(
          PROGRAM_DATA.toBase58(),
          account(key(0xe1), fixture.programDataBytes),
        ),
      (fixture) =>
        fixture.rpc.accounts.set(
          PROGRAM_DATA.toBase58(),
          account(BPF_UPGRADEABLE_LOADER, fixture.programDataBytes, true),
        ),
      (fixture) =>
        fixture.rpc.accounts.set(
          PROGRAM_DATA.toBase58(),
          account(
            BPF_UPGRADEABLE_LOADER,
            fixture.programDataBytes.slice(0, -1),
          ),
        ),
      (fixture) => {
        const data = fixture.programDataBytes.slice();
        writeU64le(data, 4, PROGRAMDATA_SLOT + 1n);
        fixture.rpc.accounts.set(
          PROGRAM_DATA.toBase58(),
          account(BPF_UPGRADEABLE_LOADER, data),
        );
      },
      (fixture) => {
        const data = fixture.programDataBytes.slice();
        data.set(key(0xe2).toBytes(), 13);
        fixture.rpc.accounts.set(
          PROGRAM_DATA.toBase58(),
          account(BPF_UPGRADEABLE_LOADER, data),
        );
      },
      (fixture) => {
        const data = encodeProgramData({
          slot: PROGRAMDATA_SLOT,
          authority: null,
          code: PROGRAM_CODE,
          trailingZeros: 16,
        });
        fixture.rpc.accounts.set(
          PROGRAM_DATA.toBase58(),
          account(BPF_UPGRADEABLE_LOADER, data),
        );
      },
      (fixture) => {
        const data = fixture.programDataBytes.slice();
        data[12] = 2;
        fixture.rpc.accounts.set(
          PROGRAM_DATA.toBase58(),
          account(BPF_UPGRADEABLE_LOADER, data),
        );
      },
      (fixture) => {
        const data = fixture.programDataBytes.slice();
        data[PROGRAMDATA_METADATA_LEN] ^= 0x01;
        fixture.rpc.accounts.set(
          PROGRAM_DATA.toBase58(),
          account(BPF_UPGRADEABLE_LOADER, data),
        );
      },
      (fixture) => {
        const data = fixture.programDataBytes.slice();
        data[data.length - 1] = 1;
        fixture.rpc.accounts.set(
          PROGRAM_DATA.toBase58(),
          account(BPF_UPGRADEABLE_LOADER, data),
        );
      },
    ];
    for (const mutate of mutations) {
      const fixture = authorityFixture();
      mutate(fixture);
      await captureError(
        () => resolveAuthority(fixture),
        "PROGRAM_IDENTITY_MISMATCH",
      );
    }
  });

  it("requires the Clock sysvar owner, non-executable 40-byte layout, and context slot equality", async () => {
    const cases: SessionAuthorityRpcAccount[] = [
      account(key(0xe3), clockData()),
      account(SYSVAR_OWNER, clockData(), true),
      account(SYSVAR_OWNER, clockData().slice(1)),
      account(SYSVAR_OWNER, clockData(CONTEXT_SLOT + 1)),
      account(SYSVAR_OWNER, clockData(CONTEXT_SLOT, -1)),
    ];
    for (const value of cases) {
      const fixture = authorityFixture();
      fixture.rpc.accounts.set(SYSVAR_CLOCK_PUBKEY.toBase58(), value);
      fixture.rpc.responseOverride = async (input) => ({
        contextSlot: CONTEXT_SLOT,
        accounts: input.addresses.map(
          (address) => fixture.rpc.accounts.get(address.toBase58()) ?? null,
        ),
      });
      await captureError(() => resolveAuthority(fixture), "CLOCK_INVALID");
    }
  });

  it("reads hostile response and account getters once, bounds before copy, and copy-isolates the result", async () => {
    const fixture = authorityFixture();
    const base = await fixture.rpc.getMultipleAccounts({
      addresses: [
        SMART_ACCOUNT,
        SESSION_ACCOUNT,
        REGISTRY,
        WARDEN_PROGRAM,
        PROGRAM_DATA,
        SYSVAR_CLOCK_PUBKEY,
      ],
      commitment: "confirmed",
      minContextSlot: 0,
    });
    let accountsReads = 0;
    let contextReads = 0;
    let smartDataReads = 0;
    const mutableSmart = smartData();
    const hostileSmart = {
      get owner() {
        return WARDEN_PROGRAM;
      },
      get executable() {
        return false;
      },
      get data() {
        smartDataReads++;
        return smartDataReads === 1 ? mutableSmart : new Uint8Array(0);
      },
    };
    const response = {
      get contextSlot() {
        contextReads++;
        return contextReads === 1 ? CONTEXT_SLOT : 0;
      },
      get accounts() {
        accountsReads++;
        return accountsReads === 1
          ? [hostileSmart, ...base.accounts.slice(1)]
          : [];
      },
    };
    fixture.rpc.responseOverride = async () => response;
    const snapshot = await resolveAuthority(fixture);
    const authorizationStateBeforeMutation = snapshot.authorizationState.slice();
    mutableSmart.fill(0xff);
    expect(accountsReads).toBe(1);
    expect(contextReads).toBe(1);
    expect(smartDataReads).toBe(1);
    expect(snapshot.accountGeneration).toBe(ACCOUNT_GENERATION);
    expect(snapshot.authorizationState).toEqual(
      authorizationStateBeforeMutation,
    );
  });

  it("adapts web3 Connection using the exact commitment/minContextSlot contract and copies account bytes", async () => {
    const bytes = Uint8Array.of(1, 2, 3);
    let receivedKeys: PublicKey[] | undefined;
    let receivedConfig: unknown;
    const connection = {
      async getGenesisHash() {
        return SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES["solana:devnet"];
      },
      async getMultipleAccountsInfoAndContext(
        keys: PublicKey[],
        config: unknown,
      ) {
        receivedKeys = keys;
        receivedConfig = config;
        return {
          context: { slot: 77 },
          value: keys.map(
            () =>
              ({
                owner: WARDEN_PROGRAM,
                executable: false,
                data: Buffer.from(bytes),
                lamports: 1,
                rentEpoch: 0,
              }) satisfies AccountInfo<Buffer>,
          ),
        };
      },
    };
    const rpc = new ConnectionSessionAuthorityRpc(
      connection as unknown as Connection,
    );
    connection.getGenesisHash = async () =>
      SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES["solana:mainnet"];
    connection.getMultipleAccountsInfoAndContext = async () => ({
      context: { slot: 0 },
      value: [],
    });
    let addressesReads = 0;
    let commitmentReads = 0;
    let minContextSlotReads = 0;
    const request = {
      get addresses() {
        addressesReads++;
        return [SMART_ACCOUNT, SESSION_ACCOUNT];
      },
      get commitment() {
        commitmentReads++;
        return "confirmed" as const;
      },
      get minContextSlot() {
        minContextSlotReads++;
        return 70;
      },
    };
    expect(await rpc.getGenesisHash()).toBe(
      SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES["solana:devnet"],
    );
    const response = await rpc.getMultipleAccounts(request);
    bytes.fill(9);
    expect(receivedKeys?.map((value) => value.toBase58())).toEqual([
      SMART_ACCOUNT.toBase58(),
      SESSION_ACCOUNT.toBase58(),
    ]);
    expect(receivedConfig).toEqual({
      commitment: "confirmed",
      minContextSlot: 70,
    });
    expect({ addressesReads, commitmentReads, minContextSlotReads }).toEqual({
      addressesReads: 1,
      commitmentReads: 1,
      minContextSlotReads: 1,
    });
    expect(response).toEqual({
      contextSlot: 77,
      accounts: [
        { owner: WARDEN_PROGRAM, executable: false, data: Uint8Array.of(1, 2, 3) },
        { owner: WARDEN_PROGRAM, executable: false, data: Uint8Array.of(1, 2, 3) },
      ],
    });
  });

  it("runs the real resolver and deterministic gate through the real coordinator to exact-byte signing", async () => {
    const fixture = authorityFixture();
    const approvals = new MemoryApprovalOwner();
    const blockhash: SessionApprovalBlockhashClient = {
      async getLatestBlockhash(input) {
        return {
          blockhash: FINAL_BLOCKHASH,
          lastValidBlockHeight: 500,
          contextSlot: input.minContextSlot + 10,
        };
      },
      async isBlockhashValid(input) {
        return { valid: true, contextSlot: input.minContextSlot + 10 };
      },
    };
    const keyring: SessionApprovalKeyring = {
      async useSessionSignerBytes(_operation, use) {
        return use({
          account: SMART_ACCOUNT.toBytes(),
          genesisHash: DEVNET_GENESIS,
          programId: WARDEN_PROGRAM.toBytes(),
          seed: SESSION_SEED,
        });
      },
    };
    const coordinator = new SessionApprovalCoordinator(
      {
        authority: fixture.resolver,
        blockhash,
        intent: new DeterministicSessionIntentGate(),
        approvals,
        keyring,
      },
      { readNow: () => 1_900_000_000_000 },
    );
    const sourceMessage = new TransactionMessage({
      payerKey: SMART_ACCOUNT,
      recentBlockhash: key(0x77).toBase58(),
      instructions: [
        ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
        ComputeBudgetProgram.requestHeapFrame({ bytes: 128 * 1_024 }),
        new TransactionInstruction({
          programId: MEMO_PROGRAM,
          keys: [],
          data: Buffer.from("resolver integration"),
        }),
      ],
    }).compileToV0Message();
    const prepared = await coordinator.prepare({
      origin: "https://dapp.example",
      tabId: 1,
      frameId: 0,
      documentId: "resolver-integration-document",
      requestedAccount: SMART_ACCOUNT.toBytes(),
      method: "solana:signTransaction",
      chain: "solana:devnet",
      sourceTransactionBytes: new VersionedTransaction(sourceMessage).serialize(),
    });
    const signed = await coordinator.approve(prepared.id, prepared.messageDigest);
    expect(signed.transactionBytes).toHaveLength(394);
    expect(signed.signature).toHaveLength(64);
    expect(fixture.rpc.requests.map((request) => request.minContextSlot)).toEqual([
      0,
      52,
      52,
      52,
      62,
      62,
    ]);
    expect(SESSION_AUTHORITY_CLOCK_SAFETY_SECONDS).toBeGreaterThan(0);
  });
});
