import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

import { PublicKey, type Connection } from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import type { ApprovalCreateParams, ApprovalRecord } from "../src/approval/record.js";
import { deriveVaultPda } from "../src/deploy/accounts.js";
import { parseReleaseRow, type ReleaseRow } from "../src/deploy/cli.js";
import {
  MANIFESTS,
  SYNTHETIC_PIN,
  manifestDigest,
  type DeployPinConfig,
} from "../src/deploy/config.js";
import type {
  SessionApprovalKeyring,
  SessionApprovalOwner,
} from "../src/transaction/session-approval-coordinator.js";
import {
  SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES,
  SESSION_AUTHORITY_WARDEN_PROGRAM_ID,
  deriveWardenProgramDataAddress,
} from "../src/transaction/session-authority-resolver.js";
import {
  COMMITTED_SESSION_RELEASE_NAMES,
  SESSION_RELEASE_PREDICATE_TYPE,
  SESSION_RELEASE_STATEMENT_TYPE,
  SessionReleaseError,
  bindSessionReleaseStatement,
  createCommittedSessionApprovalCoordinator,
  parseSessionReleaseStatement,
  resolveCommittedSessionRelease,
  sessionReleaseStatementDigest,
  type SessionReleaseErrorCode,
} from "../src/transaction/session-release.js";

const RELEASE_NAME = "devnet-r1";
const RELEASE_SHA = "12".repeat(20);
const CODE_HASH_HEX = "34".repeat(32);
const PROGRAM_DATA_HASH_HEX = "56".repeat(32);
const SHIPPED_WARDEN = new PublicKey(SESSION_AUTHORITY_WARDEN_PROGRAM_ID);
const PROGRAM_DATA = new PublicKey(
  "Eb2gEx5X9TUwJ7z8hhg1SC4GHSEW72ohG7L7emve9bpf",
);
const DEVNET_GENESIS =
  SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES["solana:devnet"];

const FIXTURE_DEPLOY_PIN: DeployPinConfig = {
  ...SYNTHETIC_PIN,
  wardenProgramId: SHIPPED_WARDEN,
  expectedGenesisHash: DEVNET_GENESIS,
};
const UPGRADE_AUTHORITY = new PublicKey(
  "DqhBzLtsh5xp4rcEf1BwkHboCjSD1NS3LjkYr8csBn4q",
);
const DEPLOY_MANIFEST_DIGEST =
  "dbcb3308f2b7370c8aa8744440ddd77503af1c7055cc77bca084cf5ccfc0084a";
const STATEMENT_DIGEST =
  "53d57be3f49864c68168aef2193809110a6d49090bdb3bb71bf116cf48416ae2";

type JsonObject = Record<string, unknown>;

function validStatement(): JsonObject {
  return {
    _type: SESSION_RELEASE_STATEMENT_TYPE,
    subject: [
      {
        name: "target/deploy/warden.so",
        digest: { sha256: CODE_HASH_HEX },
      },
      {
        name: `solana:programdata:${PROGRAM_DATA.toBase58()}`,
        digest: { sha256: PROGRAM_DATA_HASH_HEX },
      },
    ],
    predicateType: SESSION_RELEASE_PREDICATE_TYPE,
    predicate: {
      schemaVersion: 1,
      releaseSha: RELEASE_SHA,
      deployManifest: {
        name: "fixture",
        digest: DEPLOY_MANIFEST_DIGEST,
      },
      chain: "solana:devnet",
      genesisHash: DEVNET_GENESIS,
      wardenProgram: SHIPPED_WARDEN.toBase58(),
      wardenProgramData: {
        address: PROGRAM_DATA.toBase58(),
        slot: "123",
        upgradeAuthority: UPGRADE_AUTHORITY.toBase58(),
        allocationBytes: 96,
      },
    },
  };
}

function statementPredicate(statement: JsonObject): JsonObject {
  return statement.predicate as JsonObject;
}

function statementProgramData(statement: JsonObject): JsonObject {
  return statementPredicate(statement).wardenProgramData as JsonObject;
}

function statementSubjects(statement: JsonObject): JsonObject[] {
  return statement.subject as JsonObject[];
}

function releaseMarkdown(
  statement: JsonObject,
  overrides: {
    releaseSha?: string;
    artifactHashHex?: string;
    manifestName?: string;
    manifestDigest?: string;
    sessionReleaseName?: string | null;
    sessionReleaseDigest?: string;
  } = {},
): string {
  const releaseSha = overrides.releaseSha ?? RELEASE_SHA;
  const artifactHashHex = overrides.artifactHashHex ?? CODE_HASH_HEX;
  const manifestName = overrides.manifestName ?? "fixture";
  const deployDigest = overrides.manifestDigest ?? DEPLOY_MANIFEST_DIGEST;
  const sessionReleaseName =
    overrides.sessionReleaseName === undefined
      ? RELEASE_NAME
      : overrides.sessionReleaseName;
  const statementDigest =
    overrides.sessionReleaseDigest ?? sessionReleaseStatementDigest(statement);
  const sessionCell =
    sessionReleaseName === null
      ? "none"
      : `\`session-release:${sessionReleaseName}@${statementDigest}\``;
  return (
    `| fixture | \`${releaseSha}\` | \`${artifactHashHex}\` | program | hash | ` +
    `authority | manifest:${manifestName}@${deployDigest} | ${sessionCell} | tools |`
  );
}

function releaseRow(
  statement = validStatement(),
  overrides: Parameters<typeof releaseMarkdown>[1] = {},
): ReleaseRow {
  const releaseSha = overrides.releaseSha ?? RELEASE_SHA;
  return parseReleaseRow(releaseMarkdown(statement, overrides), releaseSha);
}

function captureError(
  run: () => unknown,
  code: SessionReleaseErrorCode,
): SessionReleaseError {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(SessionReleaseError);
    expect((error as SessionReleaseError).code).toBe(code);
    return error as SessionReleaseError;
  }
  throw new Error(`expected ${code}`);
}

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

describe("repository-bound session release statements", () => {
  it("pins independent ProgramData, vault, deploy-manifest, and statement goldens", () => {
    expect(deriveWardenProgramDataAddress(SHIPPED_WARDEN).toBase58()).toBe(
      PROGRAM_DATA.toBase58(),
    );
    expect(
      deriveVaultPda(
        FIXTURE_DEPLOY_PIN.squadsProgramId,
        FIXTURE_DEPLOY_PIN.multisig,
        FIXTURE_DEPLOY_PIN.vaultIndex,
      ).toBase58(),
    ).toBe(UPGRADE_AUTHORITY.toBase58());
    expect(manifestDigest(FIXTURE_DEPLOY_PIN)).toBe(DEPLOY_MANIFEST_DIGEST);
    expect(sessionReleaseStatementDigest(validStatement())).toBe(STATEMENT_DIGEST);
  });

  it("keeps the incumbent deploy registry and nested member array frozen", () => {
    expect(Object.isFrozen(MANIFESTS)).toBe(true);
    expect(Object.getPrototypeOf(MANIFESTS)).toBeNull();
    expect(Object.isFrozen(SYNTHETIC_PIN)).toBe(true);
    expect(Object.isFrozen(SYNTHETIC_PIN.members)).toBe(true);
    expect(
      Reflect.set(MANIFESTS, "mainnet", FIXTURE_DEPLOY_PIN),
    ).toBe(false);
  });

  it("ships only as a separate opt-in subpath and remains absent from extension source", () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(import.meta.dirname, "../package.json"), "utf8"),
    ) as { exports: Record<string, { import: string; types: string }> };
    expect(packageJson.exports["./transaction/session-release"]).toEqual({
      types: "./dist/transaction/session-release.d.ts",
      import: "./dist/transaction/session-release.js",
    });
    expect(
      readFileSync(
        resolve(import.meta.dirname, "../src/transaction/index.ts"),
        "utf8",
      ),
    ).not.toContain("session-release");
    const extensionSource = readTypeScriptTree(
      resolve(import.meta.dirname, "../../../apps/extension/src"),
    );
    expect(extensionSource).not.toContain("session-release");
    expect(extensionSource).not.toContain(
      "createCommittedSessionApprovalCoordinator",
    );
    expect(extensionSource).not.toContain("resolveCommittedSessionRelease");
  });

  it("parses one exact in-toto-shaped statement into immutable primitive fields", () => {
    const parsed = parseSessionReleaseStatement(validStatement());
    expect(parsed).toEqual({
      releaseSha: RELEASE_SHA,
      deployManifestName: "fixture",
      deployManifestDigest: DEPLOY_MANIFEST_DIGEST,
      chain: "solana:devnet",
      genesisHash: DEVNET_GENESIS,
      wardenProgram: SHIPPED_WARDEN.toBase58(),
      wardenProgramDataAddress: PROGRAM_DATA.toBase58(),
      wardenProgramDataSlot: 123n,
      wardenUpgradeAuthority: UPGRADE_AUTHORITY.toBase58(),
      wardenCodeHashHex: CODE_HASH_HEX,
      wardenProgramDataHashHex: PROGRAM_DATA_HASH_HEX,
      wardenProgramDataBytes: 96,
    });
    expect(Object.isFrozen(parsed)).toBe(true);
  });

  it("uses one canonical digest independent of input key insertion order", () => {
    const statement = validStatement();
    const shuffled = {
      predicate: statement.predicate,
      predicateType: statement.predicateType,
      subject: statement.subject,
      _type: statement._type,
    };
    const digest = sessionReleaseStatementDigest(statement);
    expect(digest).toBe(sessionReleaseStatementDigest(shuffled));
    expect(digest).toBe(STATEMENT_DIGEST);
    expect(digest).toBe(
      createHash("sha256")
        .update(
          JSON.stringify({
            _type: "https://in-toto.io/Statement/v1",
            subject: [
              {
                name: "target/deploy/warden.so",
                digest: { sha256: CODE_HASH_HEX },
              },
              {
                name: `solana:programdata:${PROGRAM_DATA.toBase58()}`,
                digest: { sha256: PROGRAM_DATA_HASH_HEX },
              },
            ],
            predicateType: SESSION_RELEASE_PREDICATE_TYPE,
            predicate: {
              schemaVersion: 1,
              releaseSha: RELEASE_SHA,
              deployManifest: {
                name: "fixture",
                digest: DEPLOY_MANIFEST_DIGEST,
              },
              chain: "solana:devnet",
              genesisHash: DEVNET_GENESIS,
              wardenProgram: SHIPPED_WARDEN.toBase58(),
              wardenProgramData: {
                address: PROGRAM_DATA.toBase58(),
                slot: "123",
                upgradeAuthority: UPGRADE_AUTHORITY.toBase58(),
                allocationBytes: 96,
              },
            },
          }),
        )
        .digest("hex"),
    );
  });

  it("reads hostile fields once and snapshots a subject before a later getter mutates it", () => {
    const base = validStatement();
    const subjects = base.subject as JsonObject[];
    const reads = { type: 0, subject: 0, predicateType: 0, predicate: 0 };
    const hostile = {} as JsonObject;
    Object.defineProperties(hostile, {
      _type: {
        enumerable: true,
        get() {
          reads.type++;
          return base._type;
        },
      },
      subject: {
        enumerable: true,
        get() {
          reads.subject++;
          return subjects;
        },
      },
      predicateType: {
        enumerable: true,
        get() {
          reads.predicateType++;
          return base.predicateType;
        },
      },
      predicate: {
        enumerable: true,
        get() {
          reads.predicate++;
          ((subjects[0]!.digest as JsonObject).sha256 as string) = "00".repeat(32);
          return base.predicate;
        },
      },
    });
    const parsed = parseSessionReleaseStatement(hostile);
    expect(parsed.wardenCodeHashHex).toBe(CODE_HASH_HEX);
    expect(reads).toEqual({ type: 1, subject: 1, predicateType: 1, predicate: 1 });
  });

  it.each([
    ["an extra root key", () => Object.assign(validStatement(), { reviewed: true })],
    [
      "a custom statement prototype",
      () => {
        const statement = validStatement();
        Object.setPrototypeOf(statement, { reviewed: true });
        return statement;
      },
    ],
    [
      "a missing subject",
      () => {
        const statement = validStatement();
        delete statement.subject;
        return statement;
      },
    ],
    [
      "reordered subjects",
      () => {
        const statement = validStatement();
        statement.subject = [...statementSubjects(statement)].reverse();
        return statement;
      },
    ],
    [
      "an extra digest algorithm",
      () => {
        const statement = validStatement();
        (statementSubjects(statement)[0]!.digest as JsonObject).sha512 = "aa";
        return statement;
      },
    ],
    [
      "an extra subject-array property",
      () => {
        const statement = validStatement();
        Object.defineProperty(statement.subject as object, "reviewed", {
          value: true,
          enumerable: true,
        });
        return statement;
      },
    ],
    [
      "uppercase digest hex",
      () => {
        const statement = validStatement();
        (statementSubjects(statement)[0]!.digest as JsonObject).sha256 =
          "AB".repeat(32);
        return statement;
      },
    ],
    [
      "a boolean review assertion",
      () => {
        const statement = validStatement();
        statementPredicate(statement).reviewed = true;
        return statement;
      },
    ],
  ])("rejects %s instead of accepting a permissive schema", (_label, mutate) => {
    captureError(() => parseSessionReleaseStatement(mutate()), "INVALID_STATEMENT");
  });

  it.each([
    [
      "wrong statement type",
      () => {
        const statement = validStatement();
        statement._type = "https://in-toto.io/Statement/v0.1";
        return statement;
      },
    ],
    [
      "wrong predicate type",
      () => {
        const statement = validStatement();
        statement.predicateType = "https://example.invalid/predicate";
        return statement;
      },
    ],
    [
      "abbreviated release SHA",
      () => {
        const statement = validStatement();
        statementPredicate(statement).releaseSha = "12".repeat(4);
        return statement;
      },
    ],
    [
      "noncanonical manifest name",
      () => {
        const statement = validStatement();
        (statementPredicate(statement).deployManifest as JsonObject).name =
          "../fixture";
        return statement;
      },
    ],
    [
      "wrong public genesis",
      () => {
        const statement = validStatement();
        statementPredicate(statement).genesisHash =
          SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES["solana:mainnet"];
        return statement;
      },
    ],
    [
      "a localnet label aliased to a public genesis",
      () => {
        const statement = validStatement();
        statementPredicate(statement).chain = "solana:localnet";
        return statement;
      },
    ],
    [
      "a non-shipped Warden program",
      () => {
        const statement = validStatement();
        statementPredicate(statement).wardenProgram = PublicKey.default.toBase58();
        return statement;
      },
    ],
    [
      "a noncanonical ProgramData address",
      () => {
        const statement = validStatement();
        statementProgramData(statement).address = UPGRADE_AUTHORITY.toBase58();
        return statement;
      },
    ],
    [
      "a noncanonical slot",
      () => {
        const statement = validStatement();
        statementProgramData(statement).slot = "0123";
        return statement;
      },
    ],
    [
      "a slot above u64",
      () => {
        const statement = validStatement();
        statementProgramData(statement).slot = "18446744073709551616";
        return statement;
      },
    ],
    [
      "an invalid ProgramData allocation",
      () => {
        const statement = validStatement();
        statementProgramData(statement).allocationBytes = 45;
        return statement;
      },
    ],
  ])("rejects %s", (_label, mutate) => {
    captureError(() => parseSessionReleaseStatement(mutate()), "INVALID_STATEMENT");
  });

  it("binds every statement edge to the canonical release row and deploy pin", () => {
    const statement = validStatement();
    const pins = bindSessionReleaseStatement({
      releaseName: RELEASE_NAME,
      statement,
      releaseRow: releaseRow(statement),
      deployPin: FIXTURE_DEPLOY_PIN,
    });
    expect(pins).toEqual({
      chain: "solana:devnet",
      genesisHash: new PublicKey(DEVNET_GENESIS).toBytes(),
      wardenProgram: SHIPPED_WARDEN,
      wardenProgramDataSlot: 123n,
      wardenUpgradeAuthority: UPGRADE_AUTHORITY,
      wardenCodeHash: Uint8Array.from(Buffer.from(CODE_HASH_HEX, "hex")),
      wardenProgramDataHash: Uint8Array.from(
        Buffer.from(PROGRAM_DATA_HASH_HEX, "hex"),
      ),
      wardenProgramDataBytes: 96,
    });
  });

  it.each([
    [
      "release SHA drift",
      /release SHA differs/,
      (statement: JsonObject, row: ReleaseRow, pin: DeployPinConfig) => ({
        statement,
        row: { ...row, releaseSha: "ab".repeat(20) },
        pin,
      }),
    ],
    [
      "artifact/code hash drift",
      /code hash differs/,
      (statement: JsonObject, row: ReleaseRow, pin: DeployPinConfig) => ({
        statement,
        row: { ...row, artifactHashHex: "ab".repeat(32) },
        pin,
      }),
    ],
    [
      "missing session-release token",
      /has no session-release token/,
      (statement: JsonObject, _row: ReleaseRow, pin: DeployPinConfig) => ({
        statement,
        row: releaseRow(statement, { sessionReleaseName: null }),
        pin,
      }),
    ],
    [
      "statement digest drift",
      /statement digest differs/,
      (statement: JsonObject, row: ReleaseRow, pin: DeployPinConfig) => ({
        statement,
        row: { ...row, sessionReleaseDigest: "ab".repeat(32) },
        pin,
      }),
    ],
    [
      "deploy-manifest registry drift",
      /deploy pin content differs/,
      (statement: JsonObject, row: ReleaseRow, pin: DeployPinConfig) => ({
        statement,
        row,
        pin: { ...pin, registryVersion: pin.registryVersion + 1 },
      }),
    ],
    [
      "derived upgrade-authority drift",
      /upgrade authority is not/,
      (statement: JsonObject, _row: ReleaseRow, pin: DeployPinConfig) => {
        statementProgramData(statement).upgradeAuthority = new PublicKey(
          new Uint8Array(32).fill(0x99),
        ).toBase58();
        return { statement, row: releaseRow(statement), pin };
      },
    ],
  ])("refuses %s", (_label, expectedMessage, mutate) => {
    const statement = validStatement();
    const row = releaseRow(statement);
    const changed = mutate(statement, row, FIXTURE_DEPLOY_PIN);
    const error = captureError(
      () =>
        bindSessionReleaseStatement({
          releaseName: RELEASE_NAME,
          statement: changed.statement,
          releaseRow: changed.row,
          deployPin: changed.pin,
        }),
      "BINDING_MISMATCH",
    );
    expect(error.message).toMatch(expectedMessage);
  });

  it("has no committed release today and rejects prototype names as unknown", () => {
    expect(COMMITTED_SESSION_RELEASE_NAMES).toEqual([]);
    expect(Object.isFrozen(COMMITTED_SESSION_RELEASE_NAMES)).toBe(true);
    expect(resolveCommittedSessionRelease.length).toBe(1);
    for (const name of ["mainnet-r1", "__proto__", "constructor", "toString"]) {
      captureError(
        () => resolveCommittedSessionRelease(name),
        "UNKNOWN_RELEASE",
      );
    }
  });

  it("refuses an absent release before reading integrity text or any runtime capability", () => {
    const reads = {
      releaseName: 0,
      releaseIntegrityMarkdown: 0,
      trustedConnection: 0,
      sessionSigner: 0,
      approvals: 0,
      keyring: 0,
    };
    const options = {
      get releaseName() {
        reads.releaseName++;
        return "mainnet-r1";
      },
      get releaseIntegrityMarkdown() {
        reads.releaseIntegrityMarkdown++;
        throw new Error("must not read an integrity document for an absent release");
      },
      get trustedConnection() {
        reads.trustedConnection++;
        return {} as Connection;
      },
      get sessionSigner() {
        reads.sessionSigner++;
        return SHIPPED_WARDEN;
      },
      get approvals() {
        reads.approvals++;
        return inertApprovals();
      },
      get keyring() {
        reads.keyring++;
        return inertKeyring();
      },
    };
    captureError(
      () => createCommittedSessionApprovalCoordinator(options),
      "UNKNOWN_RELEASE",
    );
    expect(reads).toEqual({
      releaseName: 1,
      releaseIntegrityMarkdown: 0,
      trustedConnection: 0,
      sessionSigner: 0,
      approvals: 0,
      keyring: 0,
    });
  });
});
