//! Pinned deployment configuration for the Warden deploy gate (Task 11R,
//! `WRD-DEP-01`). Every identity the gate trusts is PINNED here in versioned,
//! reviewed source — never taken from CLI input — so an operator cannot pass a
//! single-key "expected authority" plus an unrelated healthy multisig and get a
//! false green (WRDF-0017 round 1). The gate authenticates the ON-CHAIN accounts
//! against these pins and refuses on any mismatch.
//!
//! The values below are SYNTHETIC placeholders that make the fixture suite
//! deterministic. The REAL production governance identities (the mainnet Warden
//! program id, the audited Squads multisig pubkey + member set + permission masks,
//! the audited Squads program-code hash) are filled in from reviewed config at
//! release time; a live-cluster run stays honestly UNVERIFIED until then
//! (DEPLOY-GATE.md). Editing these is a governance change and must be reviewed.

import { PublicKey } from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha2";

/** Squads v4 member permission bits (Squads Protocol v4 `Permissions`). */
export const PERMISSION_INITIATE = 1 << 0; // propose
export const PERMISSION_VOTE = 1 << 1; // approve/reject
export const PERMISSION_EXECUTE = 1 << 2; // execute
/** A full member: propose + vote + execute. */
export const PERMISSION_ALL = PERMISSION_INITIATE | PERMISSION_VOTE | PERMISSION_EXECUTE;

/** The BPF Upgradeable Loader — every Program/ProgramData account MUST be owned by it. */
export const BPF_UPGRADEABLE_LOADER = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");

/** The spec's fixed governance shape (spec §5.5): 3-of-5, 7-day time-lock floor.
 *  These are HARD floors: `assertPinSpecFloors` refuses a pin that tries to
 *  weaken them, so a tampered or mis-selected manifest can never relax the
 *  reviewed shape (WRDF-0085). */
export const REQUIRED_THRESHOLD = 3;
export const REQUIRED_MEMBER_COUNT = 5;
export const MIN_TIME_LOCK_SECONDS = 7 * 24 * 60 * 60; // 604800

/** The Solana mainnet-beta genesis hash — the cluster-identity anchor. A deploy
 *  gate that trusts an arbitrary RPC endpoint can be fed fabricated accounts from
 *  an attacker-controlled fork that satisfies every pin (WRDF-0085); binding the
 *  genesis hash proves the readback came from mainnet. */
export const MAINNET_GENESIS_HASH = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

/** One pinned Squads member: its pubkey AND its exact permission mask (a member
 *  with only a subset, or an unexpected proposer/executor, changes real control —
 *  WRDF-0017 round 7). */
export interface PinnedMember {
  key: PublicKey;
  /** Exact permission mask — asserted equal, not a floor. */
  mask: number;
}

export interface DeployPinConfig {
  /** The Warden program id whose ProgramData upgrade authority is governed. */
  wardenProgramId: PublicKey;
  /** The mainnet Squads v4 program id — the multisig account MUST be owned by it. */
  squadsProgramId: PublicKey;
  /** The exact multisig account pubkey — asserted equal, never "any healthy multisig". */
  multisig: PublicKey;
  /** The vault index whose canonical PDA must equal the upgrade authority. */
  vaultIndex: number;
  /** The complete audited member set with per-member permission masks. */
  members: PinnedMember[];
  /** Required threshold (spec-exact). */
  threshold: number;
  /** Required member count (spec-exact). */
  memberCount: number;
  /** Time-lock floor in seconds (a longer lock is strictly safer). */
  minTimeLockSeconds: number;
  /** The Squads `config_authority` that may change members/threshold directly.
   *  MUST be the system default (autonomous multisig) unless an explicitly
   *  approved config authority is pinned here and independently attested
   *  (WRDF-0017 round 4). `null` ⇒ require `Pubkey::default()`. */
  configAuthority: PublicKey | null;
  /** The audited Squads program-CODE hash (sha256 of the deployed Squads ELF).
   *  A pinned program *id* is not a code identity while its ProgramData is
   *  upgradeable (WRDF-0017 round 6); this is the concrete trust-root anchor. */
  squadsCodeHashHex: string;
  /** The expected cluster genesis hash — normally mainnet-beta. Bound so the
   *  gate cannot be satisfied by an attacker-controlled fork (WRDF-0085). */
  expectedGenesisHash: string;
}

/**
 * Refuse a pin that weakens the spec-fixed governance shape (WRDF-0085): the
 * threshold, member count, time-lock floor and autonomous config authority are
 * NOT policy a manifest may relax — spec §5.5 fixes them. Enforced before any
 * RPC so a tampered or mis-selected manifest cannot pass with a 1-of-1 / 0-lock /
 * controlled-config shape. Throws on any violation.
 */
export function assertPinSpecFloors(pin: DeployPinConfig): void {
  if (pin.threshold !== REQUIRED_THRESHOLD) throw new Error(`pin.threshold ${pin.threshold} != spec-fixed ${REQUIRED_THRESHOLD}`);
  if (pin.memberCount !== REQUIRED_MEMBER_COUNT) throw new Error(`pin.memberCount ${pin.memberCount} != spec-fixed ${REQUIRED_MEMBER_COUNT}`);
  if (pin.members.length !== REQUIRED_MEMBER_COUNT) throw new Error(`pin.members has ${pin.members.length} entries, spec-fixed ${REQUIRED_MEMBER_COUNT}`);
  if (pin.minTimeLockSeconds < MIN_TIME_LOCK_SECONDS) throw new Error(`pin.minTimeLockSeconds ${pin.minTimeLockSeconds} < spec floor ${MIN_TIME_LOCK_SECONDS}`);
  if (pin.configAuthority !== null && !pin.configAuthority.equals(DEFAULT_PUBKEY)) {
    // A non-null configAuthority is permitted ONLY if it is the default (i.e.
    // autonomous) — a real non-default config authority must be an explicit,
    // separately-attested exception, which this floor does not grant.
    throw new Error("pin.configAuthority must be null (autonomous default); a non-default config authority needs explicit attestation");
  }
}

/** All-zero pubkey = `Pubkey::default()` = the autonomous-multisig config authority. */
export const DEFAULT_PUBKEY = new PublicKey(new Uint8Array(32));

/** Deterministic byte-pattern pubkey for synthetic fixtures/config. */
const synthetic = (byte: number): PublicKey => new PublicKey(new Uint8Array(32).fill(byte));

/**
 * The SYNTHETIC pinned config the fixture suite runs against. Real production
 * values replace these at release time (a reviewed governance change). The
 * mainnet Squads v4 program id is the one genuine public value; everything else
 * is a placeholder chosen so the happy-path fixture passes and each negative
 * fixture fails a specific assertion.
 */
export const SYNTHETIC_PIN: DeployPinConfig = {
  wardenProgramId: synthetic(0xa1),
  squadsProgramId: new PublicKey("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"),
  multisig: synthetic(0xb2),
  vaultIndex: 0,
  members: [
    { key: synthetic(0x01), mask: PERMISSION_ALL },
    { key: synthetic(0x02), mask: PERMISSION_ALL },
    { key: synthetic(0x03), mask: PERMISSION_ALL },
    { key: synthetic(0x04), mask: PERMISSION_ALL },
    { key: synthetic(0x05), mask: PERMISSION_ALL },
  ],
  threshold: REQUIRED_THRESHOLD,
  memberCount: REQUIRED_MEMBER_COUNT,
  minTimeLockSeconds: MIN_TIME_LOCK_SECONDS,
  configAuthority: null, // require the autonomous default
  squadsCodeHashHex: "5c".repeat(32), // synthetic audited-Squads-code hash
  expectedGenesisHash: MAINNET_GENESIS_HASH,
};

/**
 * The COMMITTED manifest registry (WRDF-0085): the deploy gate's live mode
 * selects a pin BY NAME from this reviewed-source map, never from an arbitrary
 * runtime file — so the trust anchor (which multisig, which members, which code
 * hash) is code-reviewed in git, not operator input. The production `mainnet`
 * manifest is added here at release time (a reviewed governance change); until
 * then only the synthetic template exists, and no live run can select a real
 * manifest that does not exist.
 */
export const MANIFESTS: Record<string, DeployPinConfig> = {
  synthetic: SYNTHETIC_PIN,
};

/**
 * A canonical sha256 digest of a manifest (WRDF-0085): so the release-integrity
 * record can bind ONE manifest name AND its exact content-digest to the release,
 * and the gate refuses any other selection or a drifted registry entry. Canonical
 * form = a stable field order with pubkeys as base58 and members sorted by key.
 */
export function manifestDigest(pin: DeployPinConfig): string {
  const canonical = JSON.stringify({
    wardenProgramId: pin.wardenProgramId.toBase58(),
    squadsProgramId: pin.squadsProgramId.toBase58(),
    multisig: pin.multisig.toBase58(),
    vaultIndex: pin.vaultIndex,
    threshold: pin.threshold,
    memberCount: pin.memberCount,
    minTimeLockSeconds: pin.minTimeLockSeconds,
    configAuthority: pin.configAuthority ? pin.configAuthority.toBase58() : null,
    squadsCodeHashHex: pin.squadsCodeHashHex,
    expectedGenesisHash: pin.expectedGenesisHash,
    members: [...pin.members]
      .map((m) => ({ key: m.key.toBase58(), mask: m.mask }))
      .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0)),
  });
  return Array.from(sha256(new TextEncoder().encode(canonical)))
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}
