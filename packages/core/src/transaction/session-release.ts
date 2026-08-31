//! Still-unreachable C7 repository release-statement boundary.
//!
//! This module turns an exact, committed in-toto Statement-shaped record into
//! the release pins C6 consumes. A statement is not a signature: repository
//! review is the current trust anchor, while DSSE/Sigstore authentication and
//! builder provenance remain future release gates. The committed registry is
//! deliberately empty, so no shipped chain can currently reach composition.

import { sha256 } from "@noble/hashes/sha2.js";
import { PublicKey, type Connection } from "@solana/web3.js";

import type { ApprovalChain } from "../approval/record.js";
import {
  PROGRAMDATA_METADATA_LEN,
  deriveVaultPda,
} from "../deploy/accounts.js";
import {
  parseReleaseRow,
  resolveManifestForRelease,
  type ReleaseRow,
} from "../deploy/cli.js";
import {
  manifestDigest,
  type DeployPinConfig,
  type PinnedMember,
} from "../deploy/config.js";
import type {
  SessionApprovalKeyring,
  SessionApprovalOwner,
} from "./session-approval-coordinator.js";
import { SessionApprovalCoordinator } from "./session-approval-coordinator.js";
import {
  SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES,
  SESSION_AUTHORITY_WARDEN_PROGRAM_ID,
  deriveWardenProgramDataAddress,
} from "./session-authority-resolver.js";
import {
  createPinnedSessionApprovalCoordinator,
  type SessionApprovalReleasePins,
} from "./session-rpc.js";

export const SESSION_RELEASE_STATEMENT_TYPE =
  "https://in-toto.io/Statement/v1" as const;
export const SESSION_RELEASE_PREDICATE_TYPE =
  "https://github.com/Dr-Inker/warden-wallet/blob/main/docs/security/SESSION-RELEASE-STATEMENT.md#v1" as const;
export const SESSION_RELEASE_CODE_SUBJECT =
  "target/deploy/warden.so" as const;
export const SESSION_RELEASE_PROGRAMDATA_SUBJECT_PREFIX =
  "solana:programdata:" as const;

const HASH_BYTES = 32;
const U64_MAX = 0xffff_ffff_ffff_ffffn;
const MAX_SOLANA_ACCOUNT_DATA_BYTES = 10 * 1_024 * 1_024;
const MAX_RELEASE_INTEGRITY_CHARACTERS = 1_048_576;
const SHIPPED_WARDEN = new PublicKey(SESSION_AUTHORITY_WARDEN_PROGRAM_ID);
const RELEASE_NAME = /^[a-z][a-z0-9-]{0,62}$/;
const RELEASE_SHA = /^[0-9a-f]{40}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const DECIMAL_U64 = /^(0|[1-9][0-9]{0,19})$/;
const CHAINS: ReadonlySet<string> = new Set([
  ...Object.keys(SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES),
  "solana:localnet",
]);

const ROOT_KEYS = ["_type", "subject", "predicateType", "predicate"] as const;
const SUBJECT_KEYS = ["name", "digest"] as const;
const DIGEST_KEYS = ["sha256"] as const;
const PREDICATE_KEYS = [
  "schemaVersion",
  "releaseSha",
  "deployManifest",
  "chain",
  "genesisHash",
  "wardenProgram",
  "wardenProgramData",
] as const;
const DEPLOY_MANIFEST_KEYS = ["name", "digest"] as const;
const PROGRAM_DATA_KEYS = [
  "address",
  "slot",
  "upgradeAuthority",
  "allocationBytes",
] as const;
const RELEASE_ROW_KEYS = [
  "releaseSha",
  "artifactHashHex",
  "manifestName",
  "manifestDigest",
  "sessionReleaseName",
  "sessionReleaseDigest",
] as const;
const DEPLOY_PIN_KEYS = [
  "wardenProgramId",
  "squadsProgramId",
  "multisig",
  "vaultIndex",
  "members",
  "threshold",
  "memberCount",
  "minTimeLockSeconds",
  "configAuthority",
  "squadsCodeHashHex",
  "expectedGenesisHash",
  "registryVersion",
  "registryTreasury",
] as const;
const MEMBER_KEYS = ["key", "mask"] as const;

export type SessionReleaseErrorCode =
  | "INVALID_STATEMENT"
  | "BINDING_MISMATCH"
  | "UNKNOWN_RELEASE"
  | "INTEGRITY_RECORD_INVALID"
  | "INVALID_CONFIG";

export class SessionReleaseError extends Error {
  readonly code: SessionReleaseErrorCode;

  constructor(
    code: SessionReleaseErrorCode,
    message: string,
    options: ErrorOptions = {},
  ) {
    super(`session release: ${message}`, options);
    this.name = "SessionReleaseError";
    this.code = code;
  }
}

export interface ParsedSessionReleaseStatement {
  readonly releaseSha: string;
  readonly deployManifestName: string;
  readonly deployManifestDigest: string;
  readonly chain: ApprovalChain;
  readonly genesisHash: string;
  readonly wardenProgram: string;
  readonly wardenProgramDataAddress: string;
  readonly wardenProgramDataSlot: bigint;
  readonly wardenUpgradeAuthority: string;
  readonly wardenCodeHashHex: string;
  readonly wardenProgramDataHashHex: string;
  readonly wardenProgramDataBytes: number;
}

export interface SessionReleaseBindingInput {
  readonly releaseName: string;
  readonly statement: unknown;
  readonly releaseRow: ReleaseRow;
  readonly deployPin: DeployPinConfig;
}

export interface CommittedSessionApprovalCompositionOptions {
  readonly releaseName: string;
  readonly trustedConnection: Connection;
  readonly sessionSigner: PublicKey;
  readonly approvals: SessionApprovalOwner;
  readonly keyring: SessionApprovalKeyring;
  readonly readNow?: () => number;
  readonly approvalTtlMs?: number;
}

interface ParsedSubject {
  readonly name: string;
  readonly hashHex: string;
}

interface OwnedReleaseRow extends ReleaseRow {}

interface CommittedSessionReleaseEntry {
  readonly statement: unknown;
  /** Exact canonical Markdown table row copied into reviewed source. */
  readonly releaseIntegrityRow: string;
}

function fail(
  code: SessionReleaseErrorCode,
  message: string,
  cause?: unknown,
): never {
  throw new SessionReleaseError(
    code,
    message,
    cause === undefined ? {} : { cause },
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactObject(
  value: unknown,
  label: string,
  expectedKeys: readonly string[],
  code: SessionReleaseErrorCode,
): Record<string, unknown> {
  if (!isObject(value)) fail(code, `${label} must be an object`);
  let keys: readonly PropertyKey[];
  let prototype: object | null;
  try {
    keys = Reflect.ownKeys(value);
    prototype = Object.getPrototypeOf(value);
  } catch (error) {
    fail(code, `${label} key access failed`, error);
  }
  if (prototype !== Object.prototype && prototype !== null) {
    fail(code, `${label} must have a plain or null prototype`);
  }
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string" || !expectedKeys.includes(key)) ||
    expectedKeys.some((key) => !keys.includes(key))
  ) {
    fail(code, `${label} must contain exactly: ${expectedKeys.join(", ")}`);
  }
  return value;
}

function exactArray(
  value: unknown,
  label: string,
  minimumLength: number,
  maximumLength: number,
  code: SessionReleaseErrorCode,
): unknown[] {
  if (!Array.isArray(value)) fail(code, `${label} must be an array`);
  let length: number;
  let keys: readonly PropertyKey[];
  let prototype: object | null;
  try {
    length = value.length;
    keys = Reflect.ownKeys(value);
    prototype = Object.getPrototypeOf(value);
  } catch (error) {
    fail(code, `${label} shape access failed`, error);
  }
  if (prototype !== Array.prototype) {
    fail(code, `${label} must be a plain array`);
  }
  if (length < minimumLength || length > maximumLength) {
    fail(
      code,
      `${label} must contain ${minimumLength === maximumLength ? `exactly ${minimumLength}` : `${minimumLength} to ${maximumLength}`} entries`,
    );
  }
  const expectedKeys = [
    ...Array.from({ length }, (_, index) => index.toString(10)),
    "length",
  ];
  if (
    keys.length !== expectedKeys.length ||
    keys.some(
      (key) => typeof key !== "string" || !expectedKeys.includes(key),
    ) ||
    expectedKeys.some((key) => !keys.includes(key))
  ) {
    fail(code, `${label} has sparse, symbolic, or extra own properties`);
  }
  return value;
}

function readField(
  value: Record<string, unknown>,
  field: string,
  label: string,
  code: SessionReleaseErrorCode,
): unknown {
  try {
    return value[field];
  } catch (error) {
    fail(code, `${label}.${field} access failed`, error);
  }
}

function requireString(
  value: unknown,
  label: string,
  code: SessionReleaseErrorCode,
): string {
  if (typeof value !== "string") fail(code, `${label} must be a string`);
  return value;
}

function requireSafeInteger(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number,
  code: SessionReleaseErrorCode,
): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < minimum ||
    (value as number) > maximum
  ) {
    fail(code, `${label} must be a safe integer from ${minimum} to ${maximum}`);
  }
  return value as number;
}

function requireReleaseName(
  value: unknown,
  label: string,
  code: SessionReleaseErrorCode,
): string {
  const name = requireString(value, label, code);
  if (!RELEASE_NAME.test(name)) {
    fail(code, `${label} is not a canonical release name`);
  }
  return name;
}

function requireReleaseSha(
  value: unknown,
  label: string,
  code: SessionReleaseErrorCode,
): string {
  const releaseSha = requireString(value, label, code);
  if (!RELEASE_SHA.test(releaseSha)) {
    fail(code, `${label} must be a full lowercase 40-hex commit id`);
  }
  return releaseSha;
}

function requireHashHex(
  value: unknown,
  label: string,
  code: SessionReleaseErrorCode,
): string {
  const hash = requireString(value, label, code);
  if (!SHA256_HEX.test(hash) || /^0+$/.test(hash)) {
    fail(code, `${label} must be a nonzero lowercase 64-hex sha256`);
  }
  return hash;
}

function requirePublicKeyString(
  value: unknown,
  label: string,
  allowZero: boolean,
  code: SessionReleaseErrorCode,
): string {
  const encoded = requireString(value, label, code);
  let key: PublicKey;
  try {
    key = new PublicKey(encoded);
  } catch (error) {
    fail(code, `${label} is malformed base58`, error);
  }
  if (key.toBase58() !== encoded) fail(code, `${label} is noncanonical base58`);
  if (!allowZero && key.equals(PublicKey.default)) {
    fail(code, `${label} must not be zero`);
  }
  return encoded;
}

function requirePublicKey(
  value: unknown,
  label: string,
  allowZero: boolean,
  code: SessionReleaseErrorCode,
): PublicKey {
  try {
    if (!(value instanceof PublicKey)) fail(code, `${label} must be a PublicKey`);
    const copy = new PublicKey(value.toBytes());
    if (!allowZero && copy.equals(PublicKey.default)) {
      fail(code, `${label} must not be zero`);
    }
    return copy;
  } catch (error) {
    if (error instanceof SessionReleaseError) throw error;
    fail(code, `${label} is malformed`, error);
  }
}

function parseDigest(value: unknown, label: string): string {
  const digest = exactObject(value, label, DIGEST_KEYS, "INVALID_STATEMENT");
  return requireHashHex(
    readField(digest, "sha256", label, "INVALID_STATEMENT"),
    `${label}.sha256`,
    "INVALID_STATEMENT",
  );
}

function parseSubject(value: unknown, label: string): ParsedSubject {
  const subject = exactObject(
    value,
    label,
    SUBJECT_KEYS,
    "INVALID_STATEMENT",
  );
  const name = requireString(
    readField(subject, "name", label, "INVALID_STATEMENT"),
    `${label}.name`,
    "INVALID_STATEMENT",
  );
  const hashHex = parseDigest(
    readField(subject, "digest", label, "INVALID_STATEMENT"),
    `${label}.digest`,
  );
  return Object.freeze({ name, hashHex });
}

function parseSubjects(value: unknown): readonly [ParsedSubject, ParsedSubject] {
  const subjects = exactArray(
    value,
    "subject",
    2,
    2,
    "INVALID_STATEMENT",
  );
  const code = parseSubject(subjects[0], "subject[0]");
  if (code.name !== SESSION_RELEASE_CODE_SUBJECT) {
    fail(
      "INVALID_STATEMENT",
      `subject[0].name must be ${SESSION_RELEASE_CODE_SUBJECT}`,
    );
  }
  const programData = parseSubject(subjects[1], "subject[1]");
  return Object.freeze([code, programData]);
}

function parsePredicate(value: unknown): Omit<
  ParsedSessionReleaseStatement,
  "wardenCodeHashHex" | "wardenProgramDataHashHex"
> {
  const predicate = exactObject(
    value,
    "predicate",
    PREDICATE_KEYS,
    "INVALID_STATEMENT",
  );
  const schemaVersion = readField(
    predicate,
    "schemaVersion",
    "predicate",
    "INVALID_STATEMENT",
  );
  if (schemaVersion !== 1) {
    fail("INVALID_STATEMENT", "predicate.schemaVersion must equal 1");
  }
  const releaseSha = requireReleaseSha(
    readField(predicate, "releaseSha", "predicate", "INVALID_STATEMENT"),
    "predicate.releaseSha",
    "INVALID_STATEMENT",
  );
  const deployManifestValue = readField(
    predicate,
    "deployManifest",
    "predicate",
    "INVALID_STATEMENT",
  );
  const deployManifest = exactObject(
    deployManifestValue,
    "predicate.deployManifest",
    DEPLOY_MANIFEST_KEYS,
    "INVALID_STATEMENT",
  );
  const deployManifestName = requireReleaseName(
    readField(
      deployManifest,
      "name",
      "predicate.deployManifest",
      "INVALID_STATEMENT",
    ),
    "predicate.deployManifest.name",
    "INVALID_STATEMENT",
  );
  const deployManifestDigest = requireHashHex(
    readField(
      deployManifest,
      "digest",
      "predicate.deployManifest",
      "INVALID_STATEMENT",
    ),
    "predicate.deployManifest.digest",
    "INVALID_STATEMENT",
  );
  const chainValue = readField(
    predicate,
    "chain",
    "predicate",
    "INVALID_STATEMENT",
  );
  if (typeof chainValue !== "string" || !CHAINS.has(chainValue)) {
    fail("INVALID_STATEMENT", "predicate.chain is unsupported");
  }
  const chain = chainValue as ApprovalChain;
  const genesisHash = requirePublicKeyString(
    readField(predicate, "genesisHash", "predicate", "INVALID_STATEMENT"),
    "predicate.genesisHash",
    false,
    "INVALID_STATEMENT",
  );
  if (chain !== "solana:localnet") {
    const canonical = SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES[
      chain as keyof typeof SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES
    ];
    if (genesisHash !== canonical) {
      fail(
        "INVALID_STATEMENT",
        `predicate.genesisHash does not equal the canonical ${chain} pin`,
      );
    }
  } else if (
    (Object.values(SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES) as readonly string[])
      .includes(genesisHash)
  ) {
    fail(
      "INVALID_STATEMENT",
      "predicate.genesisHash cannot alias a public cluster under localnet",
    );
  }
  const wardenProgram = requirePublicKeyString(
    readField(predicate, "wardenProgram", "predicate", "INVALID_STATEMENT"),
    "predicate.wardenProgram",
    false,
    "INVALID_STATEMENT",
  );
  if (wardenProgram !== SESSION_AUTHORITY_WARDEN_PROGRAM_ID) {
    fail(
      "INVALID_STATEMENT",
      "predicate.wardenProgram differs from the shipped client literal",
    );
  }
  const programDataValue = readField(
    predicate,
    "wardenProgramData",
    "predicate",
    "INVALID_STATEMENT",
  );
  const programData = exactObject(
    programDataValue,
    "predicate.wardenProgramData",
    PROGRAM_DATA_KEYS,
    "INVALID_STATEMENT",
  );
  const wardenProgramDataAddress = requirePublicKeyString(
    readField(
      programData,
      "address",
      "predicate.wardenProgramData",
      "INVALID_STATEMENT",
    ),
    "predicate.wardenProgramData.address",
    false,
    "INVALID_STATEMENT",
  );
  const canonicalProgramData = deriveWardenProgramDataAddress(
    new PublicKey(wardenProgram),
  ).toBase58();
  if (wardenProgramDataAddress !== canonicalProgramData) {
    fail(
      "INVALID_STATEMENT",
      "predicate.wardenProgramData.address is not the canonical loader-v3 PDA",
    );
  }
  const slotString = requireString(
    readField(
      programData,
      "slot",
      "predicate.wardenProgramData",
      "INVALID_STATEMENT",
    ),
    "predicate.wardenProgramData.slot",
    "INVALID_STATEMENT",
  );
  if (!DECIMAL_U64.test(slotString)) {
    fail(
      "INVALID_STATEMENT",
      "predicate.wardenProgramData.slot must be canonical unsigned decimal",
    );
  }
  const wardenProgramDataSlot = BigInt(slotString);
  if (wardenProgramDataSlot > U64_MAX) {
    fail("INVALID_STATEMENT", "predicate.wardenProgramData.slot exceeds u64");
  }
  const wardenUpgradeAuthority = requirePublicKeyString(
    readField(
      programData,
      "upgradeAuthority",
      "predicate.wardenProgramData",
      "INVALID_STATEMENT",
    ),
    "predicate.wardenProgramData.upgradeAuthority",
    false,
    "INVALID_STATEMENT",
  );
  const wardenProgramDataBytes = requireSafeInteger(
    readField(
      programData,
      "allocationBytes",
      "predicate.wardenProgramData",
      "INVALID_STATEMENT",
    ),
    "predicate.wardenProgramData.allocationBytes",
    PROGRAMDATA_METADATA_LEN + 1,
    MAX_SOLANA_ACCOUNT_DATA_BYTES,
    "INVALID_STATEMENT",
  );
  return Object.freeze({
    releaseSha,
    deployManifestName,
    deployManifestDigest,
    chain,
    genesisHash,
    wardenProgram,
    wardenProgramDataAddress,
    wardenProgramDataSlot,
    wardenUpgradeAuthority,
    wardenProgramDataBytes,
  });
}

/** Parse the exact v1 statement. Unknown, missing, inherited, or future fields reject. */
export function parseSessionReleaseStatement(
  value: unknown,
): ParsedSessionReleaseStatement {
  try {
    const root = exactObject(
      value,
      "statement",
      ROOT_KEYS,
      "INVALID_STATEMENT",
    );
    const statementType = readField(
      root,
      "_type",
      "statement",
      "INVALID_STATEMENT",
    );
    if (statementType !== SESSION_RELEASE_STATEMENT_TYPE) {
      fail("INVALID_STATEMENT", `statement._type must equal ${SESSION_RELEASE_STATEMENT_TYPE}`);
    }
    const subjects = parseSubjects(
      readField(root, "subject", "statement", "INVALID_STATEMENT"),
    );
    const predicateType = readField(
      root,
      "predicateType",
      "statement",
      "INVALID_STATEMENT",
    );
    if (predicateType !== SESSION_RELEASE_PREDICATE_TYPE) {
      fail(
        "INVALID_STATEMENT",
        `statement.predicateType must equal ${SESSION_RELEASE_PREDICATE_TYPE}`,
      );
    }
    const predicate = parsePredicate(
      readField(root, "predicate", "statement", "INVALID_STATEMENT"),
    );
    const expectedProgramDataName =
      SESSION_RELEASE_PROGRAMDATA_SUBJECT_PREFIX +
      predicate.wardenProgramDataAddress;
    if (subjects[1].name !== expectedProgramDataName) {
      fail(
        "INVALID_STATEMENT",
        `subject[1].name must equal ${expectedProgramDataName}`,
      );
    }
    return Object.freeze({
      ...predicate,
      wardenCodeHashHex: subjects[0].hashHex,
      wardenProgramDataHashHex: subjects[1].hashHex,
    });
  } catch (error) {
    if (error instanceof SessionReleaseError) throw error;
    fail("INVALID_STATEMENT", "statement access or validation failed", error);
  }
}

function canonicalStatement(parsed: ParsedSessionReleaseStatement): string {
  return JSON.stringify({
    _type: SESSION_RELEASE_STATEMENT_TYPE,
    subject: [
      {
        name: SESSION_RELEASE_CODE_SUBJECT,
        digest: { sha256: parsed.wardenCodeHashHex },
      },
      {
        name:
          SESSION_RELEASE_PROGRAMDATA_SUBJECT_PREFIX +
          parsed.wardenProgramDataAddress,
        digest: { sha256: parsed.wardenProgramDataHashHex },
      },
    ],
    predicateType: SESSION_RELEASE_PREDICATE_TYPE,
    predicate: {
      schemaVersion: 1,
      releaseSha: parsed.releaseSha,
      deployManifest: {
        name: parsed.deployManifestName,
        digest: parsed.deployManifestDigest,
      },
      chain: parsed.chain,
      genesisHash: parsed.genesisHash,
      wardenProgram: parsed.wardenProgram,
      wardenProgramData: {
        address: parsed.wardenProgramDataAddress,
        slot: parsed.wardenProgramDataSlot.toString(10),
        upgradeAuthority: parsed.wardenUpgradeAuthority,
        allocationBytes: parsed.wardenProgramDataBytes,
      },
    },
  });
}

function hexOf(value: Uint8Array): string {
  return Array.from(value)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function bytesOf(value: string): Uint8Array {
  const bytes = new Uint8Array(HASH_BYTES);
  for (let index = 0; index < HASH_BYTES; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

/** Canonical sha256 over the normalized, fixed-order v1 JSON statement. */
export function sessionReleaseStatementDigest(value: unknown): string {
  const parsed = parseSessionReleaseStatement(value);
  return hexOf(sha256(new TextEncoder().encode(canonicalStatement(parsed))));
}

function snapshotReleaseRow(value: unknown): OwnedReleaseRow {
  const row = exactObject(
    value,
    "releaseRow",
    RELEASE_ROW_KEYS,
    "BINDING_MISMATCH",
  );
  const releaseSha = requireReleaseSha(
    readField(row, "releaseSha", "releaseRow", "BINDING_MISMATCH"),
    "releaseRow.releaseSha",
    "BINDING_MISMATCH",
  );
  const artifactHashHex = requireHashHex(
    readField(row, "artifactHashHex", "releaseRow", "BINDING_MISMATCH"),
    "releaseRow.artifactHashHex",
    "BINDING_MISMATCH",
  );
  const manifestName = requireReleaseName(
    readField(row, "manifestName", "releaseRow", "BINDING_MISMATCH"),
    "releaseRow.manifestName",
    "BINDING_MISMATCH",
  );
  const manifestDigestValue = requireHashHex(
    readField(row, "manifestDigest", "releaseRow", "BINDING_MISMATCH"),
    "releaseRow.manifestDigest",
    "BINDING_MISMATCH",
  );
  const sessionNameValue = readField(
    row,
    "sessionReleaseName",
    "releaseRow",
    "BINDING_MISMATCH",
  );
  const sessionDigestValue = readField(
    row,
    "sessionReleaseDigest",
    "releaseRow",
    "BINDING_MISMATCH",
  );
  if (sessionNameValue === null || sessionDigestValue === null) {
    if (sessionNameValue !== null || sessionDigestValue !== null) {
      fail(
        "BINDING_MISMATCH",
        "releaseRow session-release name and digest must both be present or absent",
      );
    }
    return Object.freeze({
      releaseSha,
      artifactHashHex,
      manifestName,
      manifestDigest: manifestDigestValue,
      sessionReleaseName: null,
      sessionReleaseDigest: null,
    });
  }
  const sessionReleaseName = requireReleaseName(
    sessionNameValue,
    "releaseRow.sessionReleaseName",
    "BINDING_MISMATCH",
  );
  const sessionReleaseDigest = requireHashHex(
    sessionDigestValue,
    "releaseRow.sessionReleaseDigest",
    "BINDING_MISMATCH",
  );
  return Object.freeze({
    releaseSha,
    artifactHashHex,
    manifestName,
    manifestDigest: manifestDigestValue,
    sessionReleaseName,
    sessionReleaseDigest,
  });
}

function snapshotDeployPin(value: unknown): DeployPinConfig {
  const pin = exactObject(
    value,
    "deployPin",
    DEPLOY_PIN_KEYS,
    "BINDING_MISMATCH",
  );
  const wardenProgramId = requirePublicKey(
    readField(pin, "wardenProgramId", "deployPin", "BINDING_MISMATCH"),
    "deployPin.wardenProgramId",
    false,
    "BINDING_MISMATCH",
  );
  const squadsProgramId = requirePublicKey(
    readField(pin, "squadsProgramId", "deployPin", "BINDING_MISMATCH"),
    "deployPin.squadsProgramId",
    false,
    "BINDING_MISMATCH",
  );
  const multisig = requirePublicKey(
    readField(pin, "multisig", "deployPin", "BINDING_MISMATCH"),
    "deployPin.multisig",
    false,
    "BINDING_MISMATCH",
  );
  const vaultIndex = requireSafeInteger(
    readField(pin, "vaultIndex", "deployPin", "BINDING_MISMATCH"),
    "deployPin.vaultIndex",
    0,
    0xff,
    "BINDING_MISMATCH",
  );
  const membersValue = exactArray(
    readField(
      pin,
      "members",
      "deployPin",
      "BINDING_MISMATCH",
    ),
    "deployPin.members",
    0,
    0xff,
    "BINDING_MISMATCH",
  );
  const members: PinnedMember[] = membersValue.map((memberValue, index) => {
    const member = exactObject(
      memberValue,
      `deployPin.members[${index}]`,
      MEMBER_KEYS,
      "BINDING_MISMATCH",
    );
    return Object.freeze({
      key: requirePublicKey(
        readField(
          member,
          "key",
          `deployPin.members[${index}]`,
          "BINDING_MISMATCH",
        ),
        `deployPin.members[${index}].key`,
        false,
        "BINDING_MISMATCH",
      ),
      mask: requireSafeInteger(
        readField(
          member,
          "mask",
          `deployPin.members[${index}]`,
          "BINDING_MISMATCH",
        ),
        `deployPin.members[${index}].mask`,
        0,
        0xff,
        "BINDING_MISMATCH",
      ),
    });
  });
  const threshold = requireSafeInteger(
    readField(pin, "threshold", "deployPin", "BINDING_MISMATCH"),
    "deployPin.threshold",
    0,
    0xffff,
    "BINDING_MISMATCH",
  );
  const memberCount = requireSafeInteger(
    readField(pin, "memberCount", "deployPin", "BINDING_MISMATCH"),
    "deployPin.memberCount",
    0,
    0xffff,
    "BINDING_MISMATCH",
  );
  const minTimeLockSeconds = requireSafeInteger(
    readField(pin, "minTimeLockSeconds", "deployPin", "BINDING_MISMATCH"),
    "deployPin.minTimeLockSeconds",
    0,
    Number.MAX_SAFE_INTEGER,
    "BINDING_MISMATCH",
  );
  const configAuthorityValue = readField(
    pin,
    "configAuthority",
    "deployPin",
    "BINDING_MISMATCH",
  );
  const configAuthority =
    configAuthorityValue === null
      ? null
      : requirePublicKey(
          configAuthorityValue,
          "deployPin.configAuthority",
          true,
          "BINDING_MISMATCH",
        );
  const squadsCodeHashHex = requireHashHex(
    readField(pin, "squadsCodeHashHex", "deployPin", "BINDING_MISMATCH"),
    "deployPin.squadsCodeHashHex",
    "BINDING_MISMATCH",
  );
  const expectedGenesisHash = requirePublicKeyString(
    readField(pin, "expectedGenesisHash", "deployPin", "BINDING_MISMATCH"),
    "deployPin.expectedGenesisHash",
    false,
    "BINDING_MISMATCH",
  );
  const registryVersion = requireSafeInteger(
    readField(pin, "registryVersion", "deployPin", "BINDING_MISMATCH"),
    "deployPin.registryVersion",
    0,
    0xff,
    "BINDING_MISMATCH",
  );
  const registryTreasury = requirePublicKey(
    readField(pin, "registryTreasury", "deployPin", "BINDING_MISMATCH"),
    "deployPin.registryTreasury",
    false,
    "BINDING_MISMATCH",
  );
  return Object.freeze({
    wardenProgramId,
    squadsProgramId,
    multisig,
    vaultIndex,
    members: Object.freeze(members),
    threshold,
    memberCount,
    minTimeLockSeconds,
    configAuthority,
    squadsCodeHashHex,
    expectedGenesisHash,
    registryVersion,
    registryTreasury,
  });
}

function bindParsedStatement(
  releaseName: string,
  parsed: ParsedSessionReleaseStatement,
  statementDigest: string,
  row: OwnedReleaseRow,
  pin: DeployPinConfig,
): SessionApprovalReleasePins {
  if (row.sessionReleaseName === null || row.sessionReleaseDigest === null) {
    fail(
      "BINDING_MISMATCH",
      `RELEASE-INTEGRITY row ${row.releaseSha} has no session-release token`,
    );
  }
  if (row.sessionReleaseName !== releaseName) {
    fail(
      "BINDING_MISMATCH",
      `release name ${releaseName} differs from row binding ${row.sessionReleaseName}`,
    );
  }
  if (row.sessionReleaseDigest !== statementDigest) {
    fail(
      "BINDING_MISMATCH",
      "statement digest differs from the RELEASE-INTEGRITY row",
    );
  }
  if (row.releaseSha !== parsed.releaseSha) {
    fail("BINDING_MISMATCH", "statement release SHA differs from its row");
  }
  if (
    row.manifestName !== parsed.deployManifestName ||
    row.manifestDigest !== parsed.deployManifestDigest
  ) {
    fail(
      "BINDING_MISMATCH",
      "statement deploy-manifest binding differs from its release row",
    );
  }
  const actualManifestDigest = manifestDigest(pin);
  if (actualManifestDigest !== parsed.deployManifestDigest) {
    fail(
      "BINDING_MISMATCH",
      "deploy pin content differs from the statement-bound manifest digest",
    );
  }
  if (row.artifactHashHex !== parsed.wardenCodeHashHex) {
    fail(
      "BINDING_MISMATCH",
      "statement Warden code hash differs from the release artifact hash",
    );
  }
  if (pin.wardenProgramId.toBase58() !== parsed.wardenProgram) {
    fail(
      "BINDING_MISMATCH",
      "statement Warden program differs from the deploy manifest",
    );
  }
  if (pin.expectedGenesisHash !== parsed.genesisHash) {
    fail(
      "BINDING_MISMATCH",
      "statement genesis differs from the deploy manifest",
    );
  }
  const expectedAuthority = deriveVaultPda(
    pin.squadsProgramId,
    pin.multisig,
    pin.vaultIndex,
  );
  if (expectedAuthority.toBase58() !== parsed.wardenUpgradeAuthority) {
    fail(
      "BINDING_MISMATCH",
      "statement upgrade authority is not the deploy manifest's canonical Squads vault",
    );
  }
  return Object.freeze({
    chain: parsed.chain,
    genesisHash: new PublicKey(parsed.genesisHash).toBytes(),
    wardenProgram: new PublicKey(parsed.wardenProgram),
    wardenProgramDataSlot: parsed.wardenProgramDataSlot,
    wardenUpgradeAuthority: new PublicKey(parsed.wardenUpgradeAuthority),
    wardenCodeHash: bytesOf(parsed.wardenCodeHashHex),
    wardenProgramDataHash: bytesOf(parsed.wardenProgramDataHashHex),
    wardenProgramDataBytes: parsed.wardenProgramDataBytes,
  });
}

/**
 * Low-level structural binder for tests and release tooling. Supplying a pin
 * here does not make it reviewed; the committed resolver below is the only
 * repository-owned selection path.
 */
export function bindSessionReleaseStatement(
  inputValue: SessionReleaseBindingInput,
): SessionApprovalReleasePins {
  try {
    const input = exactObject(
      inputValue,
      "binding",
      ["releaseName", "statement", "releaseRow", "deployPin"],
      "BINDING_MISMATCH",
    );
    const releaseName = requireReleaseName(
      readField(input, "releaseName", "binding", "BINDING_MISMATCH"),
      "binding.releaseName",
      "BINDING_MISMATCH",
    );
    const statementValue = readField(
      input,
      "statement",
      "binding",
      "BINDING_MISMATCH",
    );
    const parsed = parseSessionReleaseStatement(statementValue);
    const statementDigest = hexOf(
      sha256(new TextEncoder().encode(canonicalStatement(parsed))),
    );
    const row = snapshotReleaseRow(
      readField(input, "releaseRow", "binding", "BINDING_MISMATCH"),
    );
    const pin = snapshotDeployPin(
      readField(input, "deployPin", "binding", "BINDING_MISMATCH"),
    );
    return bindParsedStatement(releaseName, parsed, statementDigest, row, pin);
  } catch (error) {
    if (error instanceof SessionReleaseError) {
      if (error.code === "INVALID_STATEMENT") {
        fail("BINDING_MISMATCH", "release statement is invalid", error);
      }
      throw error;
    }
    fail("BINDING_MISMATCH", "binding access or validation failed", error);
  }
}

// A real entry is added only with a reviewed production deploy manifest, exact
// RELEASE-INTEGRITY row, ProgramData readback, and release provenance evidence.
// Do not add synthetic or placeholder runtime pins here.
const committedSessionReleases = Object.freeze(
  Object.create(null) as Record<string, CommittedSessionReleaseEntry>,
);
export const COMMITTED_SESSION_RELEASE_NAMES: readonly string[] = Object.freeze(
  Object.keys(committedSessionReleases),
);

function committedEntry(nameValue: unknown): {
  readonly name: string;
  readonly entry: CommittedSessionReleaseEntry;
} {
  const name = requireReleaseName(
    nameValue,
    "releaseName",
    "UNKNOWN_RELEASE",
  );
  if (!Object.hasOwn(committedSessionReleases, name)) {
    fail(
      "UNKNOWN_RELEASE",
      `unknown committed release '${name}'; committed releases: ${COMMITTED_SESSION_RELEASE_NAMES.join(", ") || "none"}`,
    );
  }
  const entry = committedSessionReleases[name];
  if (entry === undefined) {
    fail("UNKNOWN_RELEASE", `committed release '${name}' is invalid`);
  }
  return Object.freeze({ name, entry });
}

function resolveCommittedEntry(
  selected: {
    readonly name: string;
    readonly entry: CommittedSessionReleaseEntry;
  },
  markdownValue: unknown,
): SessionApprovalReleasePins {
  const markdown = requireString(
    markdownValue,
    "releaseIntegrityMarkdown",
    "INTEGRITY_RECORD_INVALID",
  );
  if (markdown.length > MAX_RELEASE_INTEGRITY_CHARACTERS) {
    fail(
      "INTEGRITY_RECORD_INVALID",
      "releaseIntegrityMarkdown exceeds the bounded parser input",
    );
  }
  const parsed = parseSessionReleaseStatement(selected.entry.statement);
  let row: ReleaseRow;
  try {
    row = parseReleaseRow(markdown, parsed.releaseSha);
  } catch (error) {
    fail(
      "INTEGRITY_RECORD_INVALID",
      "canonical RELEASE-INTEGRITY row parsing failed",
      error,
    );
  }
  let deployPin: DeployPinConfig;
  try {
    deployPin = resolveManifestForRelease(
      parsed.deployManifestName,
      parsed.deployManifestDigest,
    );
  } catch (error) {
    fail(
      "BINDING_MISMATCH",
      "committed deploy-manifest resolution failed",
      error,
    );
  }
  return bindSessionReleaseStatement({
    releaseName: selected.name,
    statement: selected.entry.statement,
    releaseRow: row,
    deployPin,
  });
}

/**
 * Resolve only a source-committed statement and its source-embedded canonical
 * release row. Runtime callers cannot supply or replace either trust record.
 */
export function resolveCommittedSessionRelease(
  releaseName: string,
): SessionApprovalReleasePins {
  const selected = committedEntry(releaseName);
  return resolveCommittedEntry(
    selected,
    selected.entry.releaseIntegrityRow,
  );
}

/**
 * Release-gate drift guard: prove a repository RELEASE-INTEGRITY document still
 * carries the exact binding accepted for a committed entry. This assertion is
 * not used by wallet composition and cannot inject runtime pins.
 */
export function assertCommittedSessionReleaseDocumentBinding(
  releaseName: string,
  releaseIntegrityMarkdown: string,
): void {
  const selected = committedEntry(releaseName);
  resolveCommittedEntry(selected, releaseIntegrityMarkdown);
}

/**
 * The only repository-owned route into C6. With today's empty registry it
 * refuses synchronously before reading the integrity document or any runtime
 * Connection, approval-owner, signer, or keyring capability.
 */
export function createCommittedSessionApprovalCoordinator(
  optionsValue: CommittedSessionApprovalCompositionOptions,
): SessionApprovalCoordinator {
  if (!isObject(optionsValue)) fail("INVALID_CONFIG", "options must be an object");
  let selected: {
    readonly name: string;
    readonly entry: CommittedSessionReleaseEntry;
  };
  try {
    selected = committedEntry(optionsValue.releaseName);
  } catch (error) {
    if (error instanceof SessionReleaseError) throw error;
    fail("INVALID_CONFIG", "releaseName access failed", error);
  }
  const releasePins = resolveCommittedEntry(
    selected,
    selected.entry.releaseIntegrityRow,
  );
  return createPinnedSessionApprovalCoordinator({
    get trustedConnection() {
      return optionsValue.trustedConnection;
    },
    releasePins,
    get sessionSigner() {
      return optionsValue.sessionSigner;
    },
    get approvals() {
      return optionsValue.approvals;
    },
    get keyring() {
      return optionsValue.keyring;
    },
    get readNow() {
      return optionsValue.readNow;
    },
    get approvalTtlMs() {
      return optionsValue.approvalTtlMs;
    },
  });
}
