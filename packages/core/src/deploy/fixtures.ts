//! Deterministic account ENCODERS + scenario builders for the deploy-gate fixture
//! suite. The encoders are the inverse of `accounts.ts`'s decoders and live in a
//! SEPARATE module/code path, so a happy-path round-trip is a genuine
//! encode→decode→assert-verdict test, not a tautology against one implementation.
//! No `node:fs` here — this is pure data; the recorded-JSON golden fixtures are
//! written only by the `gen-deploy-fixtures` maintenance script.

import { PublicKey } from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha2";
import { type RpcAccount } from "./accounts.js";
import { BPF_UPGRADEABLE_LOADER, DEFAULT_PUBKEY, MAINNET_GENESIS_HASH, PERMISSION_ALL, SYNTHETIC_PIN, type DeployPinConfig, type PinnedMember } from "./config.js";
import type { RpcSource } from "./gate.js";

// INDEPENDENT golden vectors — hard-coded, NOT derived from the production
// functions under test, so a bug in `anchorAccountDiscriminator`/`deriveVaultPda`
// (wrong seed literal, order, or index encoding) is caught rather than passed
// (WRDF-0086). Regenerated deliberately from the pinned Squads wire format:
//   sha256("account:Multisig")[..8]  and
//   findProgramAddress(["multisig", <0xb2..>, "vault", [0]], SQDS4ep6…).
const GOLDEN_MULTISIG_DISC = Uint8Array.from([0xe0, 0x74, 0x79, 0xba, 0x44, 0xa1, 0x4f, 0xec]);
/** The canonical vault PDA for `SYNTHETIC_PIN` (multisig 0xb2…, vault index 0). */
export const GOLDEN_VAULT_PDA = new PublicKey("DqhBzLtsh5xp4rcEf1BwkHboCjSD1NS3LjkYr8csBn4q");

const hex = (b: Uint8Array): string => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const u16 = (n: number): number[] => [n & 0xff, (n >> 8) & 0xff];
const u32 = (n: number): number[] => [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
const u64 = (n: bigint): number[] => { const o: number[] = []; let v = n; for (let i = 0; i < 8; i++) { o.push(Number(v & 0xffn)); v >>= 8n; } return o; };

/** Encode a BPF `Program` account (variant 2 ‖ programdata address). */
export function encodeProgramAccount(programDataAddress: PublicKey): Uint8Array {
  return Uint8Array.from([...u32(2), ...programDataAddress.toBytes()]);
}

/** Encode a BPF `ProgramData` account. The metadata is a FIXED 45 bytes as
 *  Solana writes it (variant:u32 ‖ slot:u64 ‖ option_tag:u8 ‖ authority:Pubkey) —
 *  the 32-byte authority slot is ALWAYS reserved (zeros when the tag is 0), and
 *  the ELF always begins at offset 45. */
export function encodeProgramData(opts: { slot?: bigint; authority: PublicKey | null; code: Uint8Array; trailingZeros?: number }): Uint8Array {
  const head = [...u32(3), ...u64(opts.slot ?? 100n)];
  const authSlot = opts.authority ? [1, ...opts.authority.toBytes()] : [0, ...new Array(32).fill(0)];
  const pad = new Uint8Array(opts.trailingZeros ?? 0);
  return Uint8Array.from([...head, ...authSlot, ...opts.code, ...pad]);
}

export interface MultisigSpec {
  createKey?: PublicKey;
  configAuthority?: PublicKey;
  threshold: number;
  timeLock: number;
  transactionIndex?: bigint;
  staleTransactionIndex?: bigint;
  rentCollector?: PublicKey | null;
  bump?: number;
  members: PinnedMember[];
}

/** Encode a Squads v4 `Multisig` account (discriminator ‖ fields ‖ members vec).
 *  Uses the INDEPENDENT golden discriminator (not the production constant), so a
 *  regression in `anchorAccountDiscriminator` makes `decodeMultisig` reject the
 *  fixture rather than round-trip a shared wrong value (WRDF-0086). */
export function encodeMultisig(spec: MultisigSpec): Uint8Array {
  const bytes: number[] = [...GOLDEN_MULTISIG_DISC];
  bytes.push(...(spec.createKey ?? DEFAULT_PUBKEY).toBytes());
  bytes.push(...(spec.configAuthority ?? DEFAULT_PUBKEY).toBytes());
  bytes.push(...u16(spec.threshold));
  bytes.push(...u32(spec.timeLock));
  bytes.push(...u64(spec.transactionIndex ?? 0n));
  bytes.push(...u64(spec.staleTransactionIndex ?? 0n));
  if (spec.rentCollector) bytes.push(1, ...spec.rentCollector.toBytes());
  else bytes.push(0);
  bytes.push(spec.bump ?? 254);
  bytes.push(...u32(spec.members.length));
  for (const m of spec.members) bytes.push(...m.key.toBytes(), m.mask & 0xff);
  return Uint8Array.from(bytes);
}

/** A map-backed RpcSource over a mutable account table. */
export class MapRpc implements RpcSource {
  public genesis: string = MAINNET_GENESIS_HASH;
  constructor(private readonly table: Map<string, RpcAccount>) {}
  // eslint-disable-next-line @typescript-eslint/require-await
  async getAccountInfo(pubkey: PublicKey): Promise<RpcAccount | null> {
    return this.table.get(pubkey.toBase58()) ?? null;
  }
  // eslint-disable-next-line @typescript-eslint/require-await
  async getGenesisHash(): Promise<string> {
    return this.genesis;
  }
  set(pubkey: PublicKey, acct: RpcAccount): void {
    this.table.set(pubkey.toBase58(), acct);
  }
  del(pubkey: PublicKey): void {
    this.table.delete(pubkey.toBase58());
  }
}

/** A data account (owned, not executable). */
const acct = (owner: PublicKey, data: Uint8Array): RpcAccount => ({ owner, data, executable: false });
/** A real program account: executable, loader-owned. */
const programAcct = (owner: PublicKey, data: Uint8Array): RpcAccount => ({ owner, data, executable: true });
const synthetic = (byte: number): PublicKey => new PublicKey(new Uint8Array(32).fill(byte));

export interface Scenario {
  rpc: MapRpc;
  pin: DeployPinConfig;
  expectedReleaseHashHex: string;
  /** Named accounts, for negative mutators. */
  addrs: {
    wardenProgramData: PublicKey;
    squadsProgramData: PublicKey;
    vaultPda: PublicKey;
  };
}

/**
 * Build a SELF-CONSISTENT happy-path scenario from a base pin: the code bytes are
 * generated here and the returned pin's `squadsCodeHashHex` + the
 * `expectedReleaseHashHex` are computed from them, so the happy path passes every
 * check. Negative tests mutate exactly one account/field and assert the specific
 * check fails.
 */
export function buildHappyScenario(base: DeployPinConfig): Scenario {
  const wardenProgramData = synthetic(0xd1);
  const squadsProgramData = synthetic(0xd2);
  // The expected upgrade authority is the INDEPENDENT golden vault PDA, not a
  // value produced by deriveVaultPda — so the gate's own derivation is checked
  // against it (a deriveVaultPda bug fails the happy path, WRDF-0086).
  const vaultPda = GOLDEN_VAULT_PDA;

  const wardenCode = new TextEncoder().encode("warden-elf-bytes-vX");
  const squadsCode = new TextEncoder().encode("squads-v4-elf-bytes");
  const expectedReleaseHashHex = hex(sha256(wardenCode));
  const squadsCodeHashHex = hex(sha256(squadsCode));

  const pin: DeployPinConfig = { ...base, squadsCodeHashHex };

  const table = new Map<string, RpcAccount>();
  const rpc = new MapRpc(table);
  // Warden: Program (EXECUTABLE) → ProgramData(authority = vault PDA, code → release hash).
  rpc.set(pin.wardenProgramId, programAcct(BPF_UPGRADEABLE_LOADER, encodeProgramAccount(wardenProgramData)));
  rpc.set(wardenProgramData, acct(BPF_UPGRADEABLE_LOADER, encodeProgramData({ authority: vaultPda, code: wardenCode, trailingZeros: 16 })));
  // Squads: Program (EXECUTABLE) → ProgramData(code → pinned audited hash).
  rpc.set(pin.squadsProgramId, programAcct(BPF_UPGRADEABLE_LOADER, encodeProgramAccount(squadsProgramData)));
  rpc.set(squadsProgramData, acct(BPF_UPGRADEABLE_LOADER, encodeProgramData({ authority: DEFAULT_PUBKEY, code: squadsCode })));
  // The multisig: pinned identity, 3-of-5, fresh, autonomous, exact member masks.
  rpc.set(pin.multisig, acct(pin.squadsProgramId, encodeMultisig({
    threshold: pin.threshold,
    timeLock: pin.minTimeLockSeconds,
    members: pin.members,
  })));

  return { rpc, pin, expectedReleaseHashHex, addrs: { wardenProgramData, squadsProgramData, vaultPda } };
}

/** A fresh 5-member all-permission set on deterministic keys. */
export function fiveMembers(): PinnedMember[] {
  return [0x11, 0x12, 0x13, 0x14, 0x15].map((b) => ({ key: synthetic(b), mask: PERMISSION_ALL }));
}

/** Named deterministic scenarios for the `--fixtures` CLI mode: `happy` passes,
 *  every other name tampers with exactly one field so the gate refuses. The set
 *  covers the representative failure classes; the exhaustive per-class matrix is
 *  in `test/deploy-gate.test.ts`. Returns null for an unknown name. */
export const FIXTURE_CASES = [
  "happy",
  "wrong-multisig-owner",
  "member-count",
  "attacker-members",
  "stale-governance",
  "forked-cluster",
  "authority-not-vault",
  "squads-code",
  "release-hash",
] as const;
export type FixtureCase = (typeof FIXTURE_CASES)[number];

export function namedScenario(name: string): Scenario | null {
  if (!(FIXTURE_CASES as readonly string[]).includes(name)) return null;
  const s = buildHappyScenario(SYNTHETIC_PIN_REF());
  const ms = (over: Partial<MultisigSpec>) =>
    acct(s.pin.squadsProgramId, encodeMultisig({ threshold: s.pin.threshold, timeLock: s.pin.minTimeLockSeconds, members: s.pin.members, ...over }));
  switch (name as FixtureCase) {
    case "happy":
      break;
    case "wrong-multisig-owner":
      s.rpc.set(s.pin.multisig, acct(synthetic(0x66), encodeMultisig({ threshold: 3, timeLock: s.pin.minTimeLockSeconds, members: s.pin.members })));
      break;
    case "member-count":
      s.rpc.set(s.pin.multisig, ms({ members: s.pin.members.slice(0, 4) }));
      break;
    case "attacker-members":
      s.rpc.set(s.pin.multisig, ms({ members: fiveMembers() }));
      break;
    case "stale-governance": // inconsistent boundary (WRDF-0087): stale > tx
      s.rpc.set(s.pin.multisig, ms({ transactionIndex: 2n, staleTransactionIndex: 5n }));
      break;
    case "forked-cluster": // WRDF-0085: wrong genesis hash
      s.rpc.genesis = "So11111111111111111111111111111111111111112";
      break;
    case "authority-not-vault":
      s.rpc.set(s.addrs.wardenProgramData, acct(BPF_UPGRADEABLE_LOADER, encodeProgramData({ authority: synthetic(0x44), code: new TextEncoder().encode("warden-elf-bytes-vX") })));
      break;
    case "squads-code":
      s.rpc.set(s.addrs.squadsProgramData, acct(BPF_UPGRADEABLE_LOADER, encodeProgramData({ authority: DEFAULT_PUBKEY, code: new TextEncoder().encode("MALICIOUS") })));
      break;
    case "release-hash":
      return { ...s, expectedReleaseHashHex: "00".repeat(32) };
  }
  return s;
}

// Indirection so `namedScenario` uses the exported synthetic pin without a
// circular static import ordering hazard.
function SYNTHETIC_PIN_REF(): DeployPinConfig {
  return SYNTHETIC_PIN;
}
