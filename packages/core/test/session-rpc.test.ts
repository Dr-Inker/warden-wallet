import { PublicKey, type Connection } from "@solana/web3.js";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import type { ApprovalCreateParams, ApprovalRecord } from "../src/approval/record.js";
import {
  SessionApprovalCoordinator,
  type SessionApprovalKeyring,
  type SessionApprovalOwner,
} from "../src/transaction/session-approval-coordinator.js";
import {
  SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES,
  SESSION_AUTHORITY_WARDEN_PROGRAM_ID,
} from "../src/transaction/session-authority-resolver.js";
import {
  ConnectionSessionApprovalBlockhashClient,
  SessionApprovalRpcError,
  createPinnedSessionApprovalCoordinator,
  type PinnedSessionApprovalCompositionOptions,
  type SessionApprovalRpcErrorCode,
} from "../src/transaction/session-rpc.js";

const fill = (value: number): Uint8Array => new Uint8Array(32).fill(value);
const key = (value: number): PublicKey => new PublicKey(fill(value));
const DEVNET_GENESIS_STRING =
  SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES["solana:devnet"];
const DEVNET_GENESIS = new PublicKey(DEVNET_GENESIS_STRING).toBytes();
const BLOCKHASH = fill(0x77);
const BLOCKHASH_STRING = new PublicKey(BLOCKHASH).toBase58();

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

async function captureError(
  run: () => unknown | Promise<unknown>,
  code: SessionApprovalRpcErrorCode,
): Promise<SessionApprovalRpcError> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(SessionApprovalRpcError);
    expect((error as SessionApprovalRpcError).code).toBe(code);
    return error as SessionApprovalRpcError;
  }
  throw new Error(`expected ${code}`);
}

function connectionWith(overrides: Record<string, unknown> = {}): Connection {
  return {
    async getGenesisHash() {
      return DEVNET_GENESIS_STRING;
    },
    async getLatestBlockhashAndContext() {
      return {
        context: { slot: 70 },
        value: { blockhash: BLOCKHASH_STRING, lastValidBlockHeight: 500 },
      };
    },
    async isBlockhashValid() {
      return { context: { slot: 80 }, value: true };
    },
    ...overrides,
  } as unknown as Connection;
}

function latestRequest(overrides: Record<string, unknown> = {}) {
  return {
    chain: "solana:devnet" as const,
    genesisHash: DEVNET_GENESIS,
    commitment: "confirmed" as const,
    minContextSlot: 60,
    ...overrides,
  };
}

function validityRequest(overrides: Record<string, unknown> = {}) {
  return {
    ...latestRequest(),
    blockhash: BLOCKHASH,
    ...overrides,
  };
}

function inertApprovals(): SessionApprovalOwner {
  const unavailable = async (): Promise<never> => {
    throw new Error("not called during composition");
  };
  return {
    create: unavailable as (params: ApprovalCreateParams) => Promise<ApprovalRecord>,
    read: unavailable as (id: string) => Promise<ApprovalRecord | null>,
    readSigning: unavailable as SessionApprovalOwner["readSigning"],
    claimForSigning: unavailable as SessionApprovalOwner["claimForSigning"],
    completeSigning: unavailable as SessionApprovalOwner["completeSigning"],
    failSigning: unavailable as SessionApprovalOwner["failSigning"],
    reject: unavailable as (id: string) => Promise<ApprovalRecord>,
    cancel: unavailable as (id: string) => Promise<ApprovalRecord>,
  };
}

function inertKeyring(): SessionApprovalKeyring {
  return {
    async useSessionSignerBytes() {
      throw new Error("not called during composition");
    },
  };
}

function compositionOptions(
  overrides: Partial<PinnedSessionApprovalCompositionOptions> = {},
): PinnedSessionApprovalCompositionOptions {
  return {
    trustedConnection: connectionWith({
      async getMultipleAccountsInfoAndContext() {
        throw new Error("not called during composition");
      },
    }),
    releasePins: {
      chain: "solana:devnet",
      genesisHash: DEVNET_GENESIS,
      wardenProgram: new PublicKey(SESSION_AUTHORITY_WARDEN_PROGRAM_ID),
      wardenProgramDataSlot: 123n,
      wardenUpgradeAuthority: key(0xaa),
      wardenCodeHash: fill(0xab),
      wardenProgramDataHash: fill(0xac),
      wardenProgramDataBytes: 96,
    },
    sessionSigner: key(0x22),
    approvals: inertApprovals(),
    keyring: inertKeyring(),
    ...overrides,
  };
}

describe("chain-bound session blockhash RPC", () => {
  it("ships only as a separate opt-in subpath and remains absent from extension source", () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(import.meta.dirname, "../package.json"), "utf8"),
    ) as { exports: Record<string, { import: string; types: string }> };
    expect(packageJson.exports["./transaction/session-rpc"]).toEqual({
      types: "./dist/transaction/session-rpc.d.ts",
      import: "./dist/transaction/session-rpc.js",
    });
    expect(
      readFileSync(
        resolve(import.meta.dirname, "../src/transaction/index.ts"),
        "utf8",
      ),
    ).not.toContain("session-rpc");
    const extensionSource = readTypeScriptTree(
      resolve(import.meta.dirname, "../../../apps/extension/src"),
    );
    expect(extensionSource).not.toContain("session-rpc");
    expect(extensionSource).not.toContain(
      "ConnectionSessionApprovalBlockhashClient",
    );
    expect(extensionSource).not.toContain(
      "createPinnedSessionApprovalCoordinator",
    );
  });

  it("uses contextual web3 methods with exact config, single-read hostile fields, and owned bytes", async () => {
    const reads = {
      chain: 0,
      genesisHash: 0,
      commitment: 0,
      minContextSlot: 0,
      context: 0,
      value: 0,
      slot: 0,
      blockhash: 0,
      lastValidBlockHeight: 0,
    };
    const calls: unknown[] = [];
    const responseBytes = BLOCKHASH.slice();
    const connection = connectionWith({
      async getGenesisHash() {
        calls.push("genesis");
        return DEVNET_GENESIS_STRING;
      },
      async getLatestBlockhashAndContext(config: unknown) {
        calls.push(["latest", config]);
        return {
          get context() {
            reads.context++;
            return {
              get slot() {
                reads.slot++;
                return 70;
              },
            };
          },
          get value() {
            reads.value++;
            return {
              get blockhash() {
                reads.blockhash++;
                return new PublicKey(responseBytes).toBase58();
              },
              get lastValidBlockHeight() {
                reads.lastValidBlockHeight++;
                return 500;
              },
            };
          },
        };
      },
    });
    const client = new ConnectionSessionApprovalBlockhashClient({
      trustedConnection: connection,
      chain: "solana:devnet",
      genesisHash: DEVNET_GENESIS,
    });
    const request = {
      get chain() {
        reads.chain++;
        return "solana:devnet" as const;
      },
      get genesisHash() {
        reads.genesisHash++;
        return DEVNET_GENESIS;
      },
      get commitment() {
        reads.commitment++;
        return "confirmed" as const;
      },
      get minContextSlot() {
        reads.minContextSlot++;
        return 60;
      },
    };
    const result = await client.getLatestBlockhash(request);
    responseBytes.fill(0);
    expect(result).toEqual({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 500,
      contextSlot: 70,
    });
    expect(calls).toEqual([
      "genesis",
      ["latest", { commitment: "confirmed", minContextSlot: 60 }],
    ]);
    expect(reads).toEqual({
      chain: 1,
      genesisHash: 1,
      commitment: 1,
      minContextSlot: 1,
      context: 1,
      value: 1,
      slot: 1,
      blockhash: 1,
      lastValidBlockHeight: 1,
    });
  });

  it("copies the validity blockhash before the first await and sends canonical base58", async () => {
    let releaseGenesis!: (value: string) => void;
    const genesis = new Promise<string>((resolveGenesis) => {
      releaseGenesis = resolveGenesis;
    });
    let receivedBlockhash: string | undefined;
    let receivedConfig: unknown;
    const connection = connectionWith({
      getGenesisHash() {
        return genesis;
      },
      async isBlockhashValid(blockhash: string, config: unknown) {
        receivedBlockhash = blockhash;
        receivedConfig = config;
        return { context: { slot: 80 }, value: true };
      },
    });
    const client = new ConnectionSessionApprovalBlockhashClient({
      trustedConnection: connection,
      chain: "solana:devnet",
      genesisHash: DEVNET_GENESIS,
    });
    const mutableBlockhash = BLOCKHASH.slice();
    const pending = client.isBlockhashValid(
      validityRequest({ blockhash: mutableBlockhash }),
    );
    mutableBlockhash.fill(0);
    releaseGenesis(DEVNET_GENESIS_STRING);
    await expect(pending).resolves.toEqual({ valid: true, contextSlot: 80 });
    expect(receivedBlockhash).toBe(BLOCKHASH_STRING);
    expect(receivedConfig).toEqual({
      commitment: "confirmed",
      minContextSlot: 60,
    });
  });

  it("captures Connection capabilities at construction", async () => {
    const connection = connectionWith() as unknown as Record<string, unknown>;
    const client = new ConnectionSessionApprovalBlockhashClient({
      trustedConnection: connection as unknown as Connection,
      chain: "solana:devnet",
      genesisHash: DEVNET_GENESIS,
    });
    connection.getGenesisHash = async () => {
      throw new Error("mutated genesis method");
    };
    connection.getLatestBlockhashAndContext = async () => {
      throw new Error("mutated latest method");
    };
    connection.isBlockhashValid = async () => {
      throw new Error("mutated validity method");
    };
    await expect(client.getLatestBlockhash(latestRequest())).resolves.toEqual({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 500,
      contextSlot: 70,
    });
    await expect(client.isBlockhashValid(validityRequest())).resolves.toEqual({
      valid: true,
      contextSlot: 80,
    });
  });

  it("snapshots each config and request field before any later getter can mutate it", async () => {
    const connection = connectionWith() as unknown as Record<string, unknown>;
    const options = {
      get trustedConnection() {
        return connection as unknown as Connection;
      },
      get chain() {
        connection.getGenesisHash = async () => {
          throw new Error("later config getter replaced genesis");
        };
        connection.getLatestBlockhashAndContext = async () => {
          throw new Error("later config getter replaced latest");
        };
        return "solana:devnet" as const;
      },
      get genesisHash() {
        return DEVNET_GENESIS;
      },
    };
    const client = new ConnectionSessionApprovalBlockhashClient(options);
    const mutableGenesis = DEVNET_GENESIS.slice();
    const request = {
      get chain() {
        return "solana:devnet" as const;
      },
      get genesisHash() {
        return mutableGenesis;
      },
      get commitment() {
        mutableGenesis.fill(0);
        return "confirmed" as const;
      },
      get minContextSlot() {
        return 60;
      },
    };
    await expect(client.getLatestBlockhash(request)).resolves.toEqual({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 500,
      contextSlot: 70,
    });
  });

  it("snapshots response context before a later value getter can mutate it", async () => {
    const context = { slot: 70 };
    const client = new ConnectionSessionApprovalBlockhashClient({
      trustedConnection: connectionWith({
        async getLatestBlockhashAndContext() {
          return {
            get context() {
              return context;
            },
            get value() {
              context.slot = 0;
              return {
                blockhash: BLOCKHASH_STRING,
                lastValidBlockHeight: 500,
              };
            },
          };
        },
      }),
      chain: "solana:devnet",
      genesisHash: DEVNET_GENESIS,
    });
    await expect(client.getLatestBlockhash(latestRequest())).resolves.toEqual({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 500,
      contextSlot: 70,
    });
  });

  it("rejects cross-chain, genesis, commitment, context, and blockhash drift before blockhash I/O", async () => {
    let latestCalls = 0;
    let validityCalls = 0;
    const client = new ConnectionSessionApprovalBlockhashClient({
      trustedConnection: connectionWith({
        async getLatestBlockhashAndContext() {
          latestCalls++;
          throw new Error("must not be reached");
        },
        async isBlockhashValid() {
          validityCalls++;
          throw new Error("must not be reached");
        },
      }),
      chain: "solana:devnet",
      genesisHash: DEVNET_GENESIS,
    });
    await captureError(
      () => client.getLatestBlockhash(latestRequest({ chain: "solana:mainnet" })),
      "CHAIN_MISMATCH",
    );
    await captureError(
      () => client.getLatestBlockhash(latestRequest({ genesisHash: fill(0x44) })),
      "GENESIS_MISMATCH",
    );
    await captureError(
      () => client.getLatestBlockhash(latestRequest({ commitment: "processed" })),
      "INVALID_REQUEST",
    );
    await captureError(
      () => client.getLatestBlockhash(latestRequest({ minContextSlot: -1 })),
      "INVALID_REQUEST",
    );
    await captureError(
      () => client.isBlockhashValid(validityRequest({ blockhash: fill(0) })),
      "INVALID_REQUEST",
    );
    await captureError(
      () => client.isBlockhashValid(validityRequest({ blockhash: fill(0x44).subarray(1) })),
      "INVALID_REQUEST",
    );
    expect({ latestCalls, validityCalls }).toEqual({ latestCalls: 0, validityCalls: 0 });
  });

  it("re-binds endpoint genesis before every operation and distinguishes RPC failure from mismatch", async () => {
    let genesis = DEVNET_GENESIS_STRING;
    const client = new ConnectionSessionApprovalBlockhashClient({
      trustedConnection: connectionWith({
        async getGenesisHash() {
          if (genesis === "throw") throw new Error("offline");
          return genesis;
        },
      }),
      chain: "solana:devnet",
      genesisHash: DEVNET_GENESIS,
    });
    await expect(client.getLatestBlockhash(latestRequest())).resolves.toBeDefined();
    genesis = SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES["solana:mainnet"];
    await captureError(
      () => client.isBlockhashValid(validityRequest()),
      "GENESIS_MISMATCH",
    );
    genesis = "throw";
    await captureError(
      () => client.getLatestBlockhash(latestRequest()),
      "RPC_UNAVAILABLE",
    );
  });

  it.each([
    ["regressed latest context", { context: { slot: 59 }, value: { blockhash: BLOCKHASH_STRING, lastValidBlockHeight: 500 } }],
    ["zero latest blockhash", { context: { slot: 60 }, value: { blockhash: PublicKey.default.toBase58(), lastValidBlockHeight: 500 } }],
    ["malformed latest blockhash", { context: { slot: 60 }, value: { blockhash: "not-base58!", lastValidBlockHeight: 500 } }],
    ["negative last-valid height", { context: { slot: 60 }, value: { blockhash: BLOCKHASH_STRING, lastValidBlockHeight: -1 } }],
    ["unsafe last-valid height", { context: { slot: 60 }, value: { blockhash: BLOCKHASH_STRING, lastValidBlockHeight: Number.MAX_SAFE_INTEGER + 1 } }],
    ["missing latest value", { context: { slot: 60 } }],
  ])("rejects %s", async (_label, response) => {
    const client = new ConnectionSessionApprovalBlockhashClient({
      trustedConnection: connectionWith({
        async getLatestBlockhashAndContext() {
          return response;
        },
      }),
      chain: "solana:devnet",
      genesisHash: DEVNET_GENESIS,
    });
    await captureError(
      () => client.getLatestBlockhash(latestRequest()),
      "RPC_RESPONSE_INVALID",
    );
  });

  it.each([
    ["regressed validity context", { context: { slot: 59 }, value: true }],
    ["non-boolean validity", { context: { slot: 60 }, value: 1 }],
    ["missing validity context", { value: true }],
  ])("rejects %s", async (_label, response) => {
    const client = new ConnectionSessionApprovalBlockhashClient({
      trustedConnection: connectionWith({
        async isBlockhashValid() {
          return response;
        },
      }),
      chain: "solana:devnet",
      genesisHash: DEVNET_GENESIS,
    });
    await captureError(
      () => client.isBlockhashValid(validityRequest()),
      "RPC_RESPONSE_INVALID",
    );
  });

  it("requires canonical public-chain pins and an explicit nonzero localnet genesis", async () => {
    await captureError(
      () => new ConnectionSessionApprovalBlockhashClient({
        trustedConnection: connectionWith(),
        chain: "solana:devnet",
        genesisHash: fill(0x44),
      }),
      "INVALID_CONFIG",
    );
    await captureError(
      () => new ConnectionSessionApprovalBlockhashClient({
        trustedConnection: connectionWith(),
        chain: "solana:localnet",
        genesisHash: fill(0),
      }),
      "INVALID_CONFIG",
    );
    const localGenesis = fill(0x45);
    const local = new ConnectionSessionApprovalBlockhashClient({
      trustedConnection: connectionWith({
        async getGenesisHash() {
          return new PublicKey(localGenesis).toBase58();
        },
      }),
      chain: "solana:localnet",
      genesisHash: localGenesis,
    });
    await expect(
      local.getLatestBlockhash({
        chain: "solana:localnet",
        genesisHash: localGenesis,
        commitment: "confirmed",
        minContextSlot: 60,
      }),
    ).resolves.toEqual({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 500,
      contextSlot: 70,
    });
  });

  it("constructs the real coordinator only from an explicit trusted Connection and complete pins", async () => {
    const coordinator = createPinnedSessionApprovalCoordinator(
      compositionOptions(),
    );
    expect(coordinator).toBeInstanceOf(SessionApprovalCoordinator);

    const badProgram = compositionOptions();
    badProgram.releasePins.wardenProgram = key(0x99);
    await captureError(
      () => createPinnedSessionApprovalCoordinator(badProgram),
      "INVALID_CONFIG",
    );

    const missingConnection = compositionOptions({
      trustedConnection: {} as Connection,
    });
    await captureError(
      () => createPinnedSessionApprovalCoordinator(missingConnection),
      "INVALID_CONFIG",
    );
  });

  it("snapshots factory Connection and release pins before later config getters can mutate them", () => {
    const base = compositionOptions();
    const connection = base.trustedConnection as unknown as Record<string, unknown>;
    const codeHash = fill(0xab);
    const programDataHash = fill(0xac);
    const releasePins = {
      get chain() {
        return "solana:devnet" as const;
      },
      get genesisHash() {
        return DEVNET_GENESIS;
      },
      get wardenProgram() {
        return new PublicKey(SESSION_AUTHORITY_WARDEN_PROGRAM_ID);
      },
      get wardenProgramDataSlot() {
        return 123n;
      },
      get wardenUpgradeAuthority() {
        return key(0xaa);
      },
      get wardenCodeHash() {
        return codeHash;
      },
      get wardenProgramDataHash() {
        codeHash.fill(0);
        return programDataHash;
      },
      get wardenProgramDataBytes() {
        programDataHash.fill(0);
        return 96;
      },
    };
    const options = {
      get trustedConnection() {
        return base.trustedConnection;
      },
      get releasePins() {
        connection.getGenesisHash = undefined;
        connection.getMultipleAccountsInfoAndContext = undefined;
        connection.getLatestBlockhashAndContext = undefined;
        connection.isBlockhashValid = undefined;
        return releasePins;
      },
      get sessionSigner() {
        return base.sessionSigner;
      },
      get approvals() {
        return base.approvals;
      },
      get keyring() {
        return base.keyring;
      },
    };
    expect(
      createPinnedSessionApprovalCoordinator(options),
    ).toBeInstanceOf(SessionApprovalCoordinator);
  });
});
