//! Pinned-offset decoders for the accounts the deploy gate authenticates — the
//! BPF Upgradeable Loader's `Program`/`ProgramData` and the Squads v4 `Multisig`
//! — plus the canonical vault-PDA derivation and the program-code hash. Hand-
//! rolled against the pinned layouts (no `@sqds/multisig` dependency: the deploy
//! gate exists to shrink supply-chain surface, so it must not add npm surface to
//! the wallet). Every decoder is total and fail-closed: malformed or wrong-length
//! bytes throw, they never return a partial or guessed value.

import { PublicKey } from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha2";

/** A minimal on-chain account, as an RPC readback yields it. */
export interface RpcAccount {
  owner: PublicKey;
  data: Uint8Array;
  executable: boolean;
}

const hex = (b: Uint8Array): string => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const u32le = (d: Uint8Array, o: number): number => (d[o]! | (d[o + 1]! << 8) | (d[o + 2]! << 16) | (d[o + 3]! << 24)) >>> 0;
const u16le = (d: Uint8Array, o: number): number => d[o]! | (d[o + 1]! << 8);
/** Read a u64 LE as a bigint (transaction indices can exceed 2^53). */
const u64le = (d: Uint8Array, o: number): bigint => {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(d[o + i]!);
  return v;
};
const pubkeyAt = (d: Uint8Array, o: number): PublicKey => {
  if (o + 32 > d.length) throw new Error("pubkey read past end of account data");
  return new PublicKey(d.slice(o, o + 32));
};

// ---------------------------------------------------------------------------
// BPF Upgradeable Loader state (bincode: 4-byte u32 LE enum discriminant).
//   0 Uninitialized | 1 Buffer{auth:Option<Pk>} | 2 Program{programdata:Pk}
//   3 ProgramData{slot:u64, upgrade_authority:Option<Pk>, <ELF bytes…>}
// ---------------------------------------------------------------------------
const LOADER_PROGRAM = 2;
const LOADER_PROGRAM_DATA = 3;
/** Byte offset of the program ELF inside a ProgramData account (4 + 8 + 1 + 32). */
export const PROGRAMDATA_METADATA_LEN = 45;

/** Decode a `Program` account → the ProgramData address it encodes. Throws unless
 *  the bytes are exactly the Program variant. */
export function decodeProgramAccount(data: Uint8Array): { programDataAddress: PublicKey } {
  if (data.length < 4 + 32) throw new Error("Program account too short");
  if (u32le(data, 0) !== LOADER_PROGRAM) throw new Error(`not a Program account (variant ${u32le(data, 0)})`);
  return { programDataAddress: pubkeyAt(data, 4) };
}

/** Decode a `ProgramData` account → slot, optional upgrade authority, and the
 *  program-code hash. Throws unless the bytes are the ProgramData variant. */
export function decodeProgramDataAccount(data: Uint8Array): {
  slot: bigint;
  upgradeAuthority: PublicKey | null;
  codeHashHex: string;
} {
  if (data.length < PROGRAMDATA_METADATA_LEN) throw new Error("ProgramData account too short");
  if (u32le(data, 0) !== LOADER_PROGRAM_DATA) throw new Error(`not a ProgramData account (variant ${u32le(data, 0)})`);
  const slot = u64le(data, 4);
  const optionTag = data[12]!;
  let upgradeAuthority: PublicKey | null = null;
  if (optionTag === 1) upgradeAuthority = pubkeyAt(data, 13);
  else if (optionTag !== 0) throw new Error(`invalid Option tag ${optionTag} for upgrade_authority`);
  return { slot, upgradeAuthority, codeHashHex: programCodeHash(data) };
}

/**
 * The program-code hash `solana-verify get-program-hash` computes: sha256 over
 * the ProgramData's ELF region (offset 45..end) with trailing zero padding
 * stripped (ProgramData accounts are over-allocated for future upgrades). The
 * byte-exact match against `solana-verify` on a real cluster is the UNVERIFIED
 * residual until a release candidate; the fixtures pin this rule end to end.
 */
export function programCodeHash(programDataAccount: Uint8Array): string {
  if (programDataAccount.length < PROGRAMDATA_METADATA_LEN) throw new Error("ProgramData too short for a code hash");
  let end = programDataAccount.length;
  while (end > PROGRAMDATA_METADATA_LEN && programDataAccount[end - 1] === 0) end--;
  return hex(sha256(programDataAccount.slice(PROGRAMDATA_METADATA_LEN, end)));
}

// ---------------------------------------------------------------------------
// PROVENANCE / LICENSING (WRDF-0089 — carried for owner/counsel, NOT self-cleared).
// The decoder below reads the on-chain BINARY WIRE FORMAT of a Squads v4 Multisig
// account — byte offsets, the Anchor account discriminator (a derivable
// sha256("account:Multisig")[..8] fact), and the canonical vault-PDA seed literals
// ("multisig"/"vault"), which are the deployed on-chain protocol constants. No
// Squads source (Rust or TS) was copied; this is a clean-room interoperability
// reader of published on-chain state, the same category as reading a file format.
// Squads v4 is nonetheless AGPL-3.0 / reference-only in the prior-art corpus, and
// the corpus requires recognizable reuse to be flagged for counsel regardless of
// the clean-room argument. Carried as an owner/counsel release-blocker in
// docs/security/THIRD_PARTY_NOTICES.md (parallels WRDF-0050); do not treat as
// resolved without counsel sign-off.
//
// Squads v4 Multisig account (Anchor). Layout after the 8-byte discriminator:
//   create_key: Pubkey(32)
//   config_authority: Pubkey(32)
//   threshold: u16(2)
//   time_lock: u32(4)
//   transaction_index: u64(8)
//   stale_transaction_index: u64(8)
//   rent_collector: Option<Pubkey>(1 + [32])
//   bump: u8(1)
//   members: Vec<Member>(4-byte len + N * 33)   Member = { key: Pubkey(32), mask: u8(1) }
// ---------------------------------------------------------------------------

/** Anchor account discriminator: sha256("account:<Name>")[..8]. */
export function anchorAccountDiscriminator(name: string): Uint8Array {
  return sha256(new TextEncoder().encode(`account:${name}`)).slice(0, 8);
}
/** The pinned `Multisig` discriminator. */
export const MULTISIG_DISCRIMINATOR = anchorAccountDiscriminator("Multisig");

export interface MultisigMember {
  key: PublicKey;
  mask: number;
}
export interface DecodedMultisig {
  createKey: PublicKey;
  configAuthority: PublicKey;
  threshold: number;
  timeLock: number; // seconds
  transactionIndex: bigint;
  staleTransactionIndex: bigint;
  rentCollector: PublicKey | null;
  bump: number;
  members: MultisigMember[];
}

/**
 * Decode a Squads v4 `Multisig` account. Verifies the 8-byte discriminator, then
 * reads every field by pinned offset. Throws on a wrong discriminator, an invalid
 * Option tag, or a members-vector length that runs past the account — a decoder
 * that skips the discriminator would happily read spoofed bytes (WRDF-0017), so
 * this one refuses them.
 */
export function decodeMultisig(data: Uint8Array): DecodedMultisig {
  if (data.length < 8) throw new Error("Multisig account too short for a discriminator");
  for (let i = 0; i < 8; i++) {
    if (data[i] !== MULTISIG_DISCRIMINATOR[i]) throw new Error("account discriminator is not Multisig");
  }
  let o = 8;
  const createKey = pubkeyAt(data, o); o += 32;
  const configAuthority = pubkeyAt(data, o); o += 32;
  const threshold = u16le(data, o); o += 2;
  const timeLock = u32le(data, o); o += 4;
  const transactionIndex = u64le(data, o); o += 8;
  const staleTransactionIndex = u64le(data, o); o += 8;
  const rentTag = data[o]!; o += 1;
  let rentCollector: PublicKey | null = null;
  if (rentTag === 1) { rentCollector = pubkeyAt(data, o); o += 32; }
  else if (rentTag !== 0) throw new Error(`invalid Option tag ${rentTag} for rent_collector`);
  const bump = data[o]!; o += 1;
  if (o + 4 > data.length) throw new Error("Multisig truncated before members length");
  const memberCount = u32le(data, o); o += 4;
  if (o + memberCount * 33 > data.length) throw new Error("Multisig members vector runs past account data");
  const members: MultisigMember[] = [];
  for (let i = 0; i < memberCount; i++) {
    const key = pubkeyAt(data, o); o += 32;
    const mask = data[o]!; o += 1;
    members.push({ key, mask });
  }
  return { createKey, configAuthority, threshold, timeLock, transactionIndex, staleTransactionIndex, rentCollector, bump, members };
}

/** Squads v4 canonical vault PDA: seeds ["multisig", multisig, "vault", index:u8]. */
export function deriveVaultPda(squadsProgramId: PublicKey, multisig: PublicKey, vaultIndex: number): PublicKey {
  if (!Number.isInteger(vaultIndex) || vaultIndex < 0 || vaultIndex > 0xff) throw new Error(`vault index ${vaultIndex} is not a u8`);
  const [pda] = PublicKey.findProgramAddressSync(
    [new TextEncoder().encode("multisig"), multisig.toBytes(), new TextEncoder().encode("vault"), Uint8Array.from([vaultIndex])],
    squadsProgramId,
  );
  return pda;
}
