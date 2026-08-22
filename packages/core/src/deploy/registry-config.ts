//! Deploy-gate check 3 (WRD-DEP-02): the pinned, source-re-derived expectation for the
//! on-chain adapter `Registry`, and the diff that rejects any deviation.
//!
//! The expected adapter set is authored here as a reviewed constant and every 8-byte
//! selector is RE-DERIVED from its Anchor instruction name (sha256("global:<name>")[..8]),
//! never trusted as an opaque byte blob; non-Anchor targets carry their pinned literal
//! instruction tag (SPL/System/Memo/ATA use 1-byte / fixed-layout tags, not 8-byte
//! discriminators — spec §5.2 rule 1). A drift test asserts this constant agrees with
//! programs/warden's parity-locked `registry-default.json` (which agrees with the Rust
//! source of truth), so the reviewed pin cannot silently diverge from what `init_registry`
//! actually writes. This module is pure `.ts` (no JSON import) so it stays inside the
//! deploy verifier's attested source closure (WRD-DEP-01).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha2";
import { anchorInstructionSighash, type DecodedRegistry } from "./accounts.js";

// The committed, hash-pinned Jupiter v6 IDL (fetched from jup-ag/jupiter-cpi). The deploy
// verifier AUTHENTICATES each production Anchor selector's instruction NAME against this
// upstream source (WRDF-0095) — so a stale/typo'd name coordinated across Warden's own
// mirrors cannot pass: it must name a real instruction of the pinned target program.
export const JUPITER_V6_IDL_SHA256 = "764ea6d71b77458fd33aeb308d6e6bb19e660fc5320c5359f3b9cac96eba5c50";
const JUPITER_V6_IDL_PATH = fileURLToPath(new URL("./idl/jupiter-v6.idl.json", import.meta.url));

// Anchor computes an instruction sighash from the SNAKE_CASE name; Jupiter's IDL lists
// camelCase (`sharedAccountsRoute`), so normalize before matching.
const toSnakeCase = (s: string): string => s.replace(/([A-Z])/g, (m) => "_" + m.toLowerCase());

let _jupNames: Set<string> | null = null;
/** Read the committed Jupiter v6 IDL, verify its pinned sha256, and return its instruction
 *  names in Anchor snake_case form. Fail-closed: a missing / hash-mismatched / unparseable
 *  IDL throws, so the deploy verifier refuses rather than trust an unauthenticated source. */
export function authenticatedJupiterInstructionNames(): Set<string> {
  if (_jupNames) return _jupNames;
  const raw = readFileSync(JUPITER_V6_IDL_PATH);
  const got = Array.from(sha256(raw)).map((x) => x.toString(16).padStart(2, "0")).join("");
  if (got !== JUPITER_V6_IDL_SHA256) {
    throw new Error(`Jupiter v6 IDL sha256 ${got} != pinned ${JUPITER_V6_IDL_SHA256} — refusing an unauthenticated selector source`);
  }
  const idl = JSON.parse(new TextDecoder().decode(raw)) as { instructions?: { name: string }[] };
  const names = new Set<string>();
  for (const ix of idl.instructions ?? []) names.add(toSnakeCase(ix.name));
  _jupNames = names;
  return names;
}

// Adapter program ids (base58), mirrored from programs/warden/src/constants.rs.
export const SPL_TOKEN_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
export const ATA_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
export const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";
export const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
export const JUPITER_V6_ID = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
export const TEST_MUTATOR_ID = "An3yCfK4dXet5wEHRYT23gyS1CJbeGD5E2enchQLo49W";
export const TEST_JUP_MOCK_ID = "3dxuCX7mnVEse9PD1WSDdXYXgwFpECkJTfwsXBbPbzWU";

/** One reviewed adapter: an Anchor instruction (selector = re-derived sighash) or a
 *  literal-tag instruction (selector = the pinned tag bytes). `roleRules` is the
 *  authority-position role bitmask; `lists` are the allowlist ids it belongs to. */
export type ExpectedAdapter = {
  program: string;
  roleRules: number;
  lists: number[];
} & (
  // An Anchor instruction: selector = re-derived sighash. `source` says how the NAME is
  // authenticated — against the hash-pinned Jupiter IDL, or (test-only, list 2) a reviewed
  // Warden test-program instruction with no public IDL.
  | { anchor: string; source: "jupiter-idl" | "warden-test" }
  | { tag: number[] }
);

// The complete reviewed default registry (insertion order matches registry_default.rs).
export const EXPECTED_ADAPTERS: readonly ExpectedAdapter[] = [
  { program: SPL_TOKEN_ID, tag: [3], roleRules: 3, lists: [1] }, // SPL Transfer
  { program: SPL_TOKEN_ID, tag: [12], roleRules: 3, lists: [1] }, // SPL TransferChecked
  { program: ATA_PROGRAM_ID, tag: [1], roleRules: 0, lists: [1] }, // ATA CreateIdempotent
  { program: SYSTEM_PROGRAM_ID, tag: [2, 0, 0, 0], roleRules: 1, lists: [1] }, // System Transfer (u32 LE tag)
  { program: MEMO_PROGRAM_ID, tag: [], roleRules: 0, lists: [1] }, // Memo (tagless)
  { program: JUPITER_V6_ID, anchor: "route", source: "jupiter-idl", roleRules: 0, lists: [1] },
  { program: JUPITER_V6_ID, anchor: "shared_accounts_route", source: "jupiter-idl", roleRules: 0, lists: [1] },
  { program: TEST_MUTATOR_ID, anchor: "noop", source: "warden-test", roleRules: 0, lists: [2] },
  { program: TEST_MUTATOR_ID, anchor: "transfer_out", source: "warden-test", roleRules: 3, lists: [2] },
  { program: TEST_JUP_MOCK_ID, anchor: "route", source: "jupiter-idl", roleRules: 0, lists: [2] },
  { program: TEST_JUP_MOCK_ID, anchor: "shared_accounts_route", source: "jupiter-idl", roleRules: 0, lists: [2] },
];

export const hexOf = (b: Uint8Array | number[]): string =>
  Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");

export interface ExpectedEntry {
  program: string;
  /** Hex of the significant selector bytes (length === discLen). */
  selectorHex: string;
  discLen: number;
  roleRules: number;
  lists: number[];
}

/** Build the expected entries, RE-DERIVING every Anchor selector from its instruction
 *  name and validating literal tags. Throws if a tag is malformed (>8 bytes). */
export function expectedRegistryConfig(): ExpectedEntry[] {
  const jupNames = authenticatedJupiterInstructionNames();
  return EXPECTED_ADAPTERS.map((a) => {
    let selector: Uint8Array;
    if ("anchor" in a) {
      // Authenticate the instruction NAME against the pinned upstream IDL before hashing it
      // (WRDF-0095): a Jupiter-sourced name must be a real instruction of the authenticated
      // Jupiter v6 IDL, so a Warden-mirror typo cannot yield a self-consistent wrong selector.
      if (a.source === "jupiter-idl" && !jupNames.has(a.anchor)) {
        throw new Error(`Anchor adapter "${a.anchor}" (${a.program}) is not an instruction in the authenticated Jupiter v6 IDL`);
      }
      selector = anchorInstructionSighash(a.anchor); // 8 bytes, sighash of the authenticated name
    } else {
      if (a.tag.length > 8) throw new Error(`literal tag for ${a.program} exceeds 8 bytes`);
      selector = Uint8Array.from(a.tag);
    }
    return {
      program: a.program,
      selectorHex: hexOf(selector),
      discLen: selector.length,
      roleRules: a.roleRules,
      lists: [...a.lists].sort((x, y) => x - y),
    };
  });
}

/** The list ids an on-chain entry index belongs to, from the per-list bitmasks. */
export function onchainEntryLists(reg: DecodedRegistry, entryIndex: number): number[] {
  const ids: number[] = [];
  for (let k = 0; k < reg.lists.length; k++) {
    if ((reg.lists[k]! >> BigInt(entryIndex)) & 1n) ids.push(k + 1);
  }
  return ids;
}

const key = (program: string, selectorHex: string, discLen: number) => `${program}|${selectorHex}|${discLen}`;

/** The expected `allocated_lists` bitmask: bit (id-1) set for every list id that the
 *  reviewed config places at least one adapter into. `grant_session` authorizes against
 *  this exact field (WRDF-0094), so it is part of the complete config. */
export function expectedAllocatedLists(): number {
  let mask = 0;
  for (const e of expectedRegistryConfig()) for (const id of e.lists) mask |= 1 << (id - 1);
  return mask & 0xff;
}

/**
 * Diff a decoded on-chain Registry against the pinned, re-derived expectation. Returns a
 * list of violation strings (empty ⇒ the registry exactly matches). Rejects a wrong
 * version, bump, authority, treasury, or `allocated_lists`, and any missing / extra /
 * duplicate / wrong-selector entry, a role-validator (`role_rules`) mismatch, a
 * list-membership mismatch, and any list bit set for a non-existent entry index.
 */
export function diffRegistry(
  reg: DecodedRegistry,
  opts: { expectedVersion: number; expectedTreasuryB58: string; expectedAuthorityB58: string; expectedBump: number },
): string[] {
  const v: string[] = [];
  if (reg.version !== opts.expectedVersion) v.push(`version ${reg.version} != expected ${opts.expectedVersion}`);
  if (reg.bump !== opts.expectedBump) v.push(`bump ${reg.bump} != canonical ${opts.expectedBump}`);
  if (reg.authority.toBase58() !== opts.expectedAuthorityB58) {
    v.push(`authority ${reg.authority.toBase58()} != expected governed authority ${opts.expectedAuthorityB58}`);
  }
  if (reg.treasury.toBase58() !== opts.expectedTreasuryB58) {
    v.push(`treasury ${reg.treasury.toBase58()} != pinned ${opts.expectedTreasuryB58}`);
  }
  const expAllocated = expectedAllocatedLists();
  if (reg.allocatedLists !== expAllocated) {
    v.push(`allocated_lists 0x${reg.allocatedLists.toString(16)} != expected 0x${expAllocated.toString(16)} (grant_session authorizes against this — WRDF-0094)`);
  }

  const expected = expectedRegistryConfig();
  const expByKey = new Map<string, ExpectedEntry>();
  for (const e of expected) expByKey.set(key(e.program, e.selectorHex, e.discLen), e);

  const seen = new Map<string, number>();
  reg.entries.forEach((entry, i) => {
    const program = entry.programId.toBase58();
    const selectorHex = hexOf(entry.selector.slice(0, entry.discLen));
    const k = key(program, selectorHex, entry.discLen);
    seen.set(k, (seen.get(k) ?? 0) + 1);
    const exp = expByKey.get(k);
    if (!exp) {
      v.push(`unexpected entry #${i}: program ${program} selector 0x${selectorHex || "∅"} (disc_len ${entry.discLen})`);
      return;
    }
    if (entry.roleRules !== exp.roleRules) {
      v.push(`entry #${i} (${program} 0x${selectorHex || "∅"}) role_rules ${entry.roleRules} != expected ${exp.roleRules}`);
    }
    const gotLists = onchainEntryLists(reg, i);
    if (gotLists.join(",") !== exp.lists.join(",")) {
      v.push(`entry #${i} (${program} 0x${selectorHex || "∅"}) lists [${gotLists}] != expected [${exp.lists}]`);
    }
  });

  for (const [k, count] of seen) if (count > 1) v.push(`duplicate entry ${k} appears ${count} times`);
  for (const e of expected) {
    const k = key(e.program, e.selectorHex, e.discLen);
    if (!seen.has(k)) v.push(`missing expected entry: ${e.program} 0x${e.selectorHex || "∅"} (disc_len ${e.discLen})`);
  }

  // No list bitmask may reference an entry index >= n_entries (a stale/forged membership).
  for (let k = 0; k < reg.lists.length; k++) {
    const mask = reg.lists[k]!;
    for (let bit = reg.nEntries; bit < 64; bit++) {
      if ((mask >> BigInt(bit)) & 1n) { v.push(`list ${k + 1} has a bit set for non-existent entry index ${bit}`); break; }
    }
  }
  return v;
}
