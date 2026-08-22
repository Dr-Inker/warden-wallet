//! The deploy-gate governance + hash verification (Task 11R, `WRD-DEP-01`). Given
//! a PINNED config (`config.ts`) and an injectable RPC source, it authenticates
//! the on-chain accounts and refuses on any mismatch. It covers DEPLOY-GATE.md
//! checks 1 (upgrade authority), 2 (Squads governance), 3 (adapter-selector diff
//! vs the on-chain Registry, `WRD-DEP-02`), and 4a (on-chain program hash).
//!
//! Every path is FAIL-CLOSED: a missing account, an RPC error, a wrong owner or
//! discriminator, or any assertion mismatch produces a failing result. There is
//! no path where an unverified condition reads as passing.

import { PublicKey } from "@solana/web3.js";
import {
  decodeProgramAccount,
  decodeProgramDataAccount,
  decodeMultisig,
  decodeRegistry,
  deriveVaultPda,
  type RpcAccount,
} from "./accounts.js";
import { BPF_UPGRADEABLE_LOADER, DEFAULT_PUBKEY, assertPinSpecFloors, type DeployPinConfig } from "./config.js";
import { diffRegistry } from "./registry-config.js";

/** The Warden adapter Registry is a program singleton PDA at seeds ["registry"]. */
export function deriveRegistryPda(wardenProgramId: PublicKey): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync([new TextEncoder().encode("registry")], wardenProgramId);
  return pda;
}

/** An injectable account reader. A live run wires this to an RPC endpoint; the
 *  fixture suite wires it to recorded responses. `null` = account does not exist. */
export interface RpcSource {
  getAccountInfo(pubkey: PublicKey): Promise<RpcAccount | null>;
  /** The cluster's genesis hash — bound to authenticate the cluster (WRDF-0085). */
  getGenesisHash(): Promise<string>;
}

export interface CheckResult {
  name: string;
  ok: boolean;
  detail: string;
}
export interface GateVerdict {
  ok: boolean;
  results: CheckResult[];
}

const b58 = (p: PublicKey): string => p.toBase58();

/** Fetch an account or throw a fail-closed error naming what was missing. */
async function fetchOrThrow(rpc: RpcSource, pubkey: PublicKey, role: string): Promise<RpcAccount> {
  let acct: RpcAccount | null;
  try {
    acct = await rpc.getAccountInfo(pubkey);
  } catch (e) {
    throw new Error(`RPC error fetching ${role} ${b58(pubkey)}: ${(e as Error).message}`);
  }
  if (!acct) throw new Error(`${role} account ${b58(pubkey)} does not exist`);
  return acct;
}

/** Authenticate a pinned Program id → its canonical ProgramData → the code hash
 *  and (for Warden) the upgrade authority. Every hop owner-checks the BPF loader
 *  and matches the loader state variant (WRDF-0017 rounds 5/6). */
async function authenticateProgram(
  rpc: RpcSource,
  programId: PublicKey,
  role: string,
): Promise<{ upgradeAuthority: PublicKey | null; codeHashHex: string }> {
  const prog = await fetchOrThrow(rpc, programId, `${role} Program`);
  if (!prog.owner.equals(BPF_UPGRADEABLE_LOADER)) {
    throw new Error(`${role} Program ${b58(programId)} is not owned by the BPF Upgradeable Loader (owner ${b58(prog.owner)})`);
  }
  // A real on-chain program account is executable; a data account merely owned by
  // the loader is not the program (WRDF-0086).
  if (!prog.executable) throw new Error(`${role} Program ${b58(programId)} is not executable`);
  const { programDataAddress } = decodeProgramAccount(prog.data); // throws unless the Program variant
  const pd = await fetchOrThrow(rpc, programDataAddress, `${role} ProgramData`);
  if (!pd.owner.equals(BPF_UPGRADEABLE_LOADER)) {
    throw new Error(`${role} ProgramData ${b58(programDataAddress)} is not owned by the BPF Upgradeable Loader (owner ${b58(pd.owner)})`);
  }
  const { upgradeAuthority, codeHashHex } = decodeProgramDataAccount(pd.data); // throws unless the ProgramData variant
  return { upgradeAuthority, codeHashHex };
}

/**
 * Run the governance + hash checks against the pinned config. `expectedReleaseHashHex`
 * is the Warden program-code hash recorded for the release SHA in
 * RELEASE-INTEGRITY.md; the gate refuses if the on-chain hash differs.
 */
export async function verifyDeployGate(
  pin: DeployPinConfig,
  opts: { rpc: RpcSource; expectedReleaseHashHex: string },
): Promise<GateVerdict> {
  const results: CheckResult[] = [];
  const check = async (name: string, fn: () => Promise<string>): Promise<void> => {
    try {
      results.push({ name, ok: true, detail: await fn() });
    } catch (e) {
      results.push({ name, ok: false, detail: (e as Error).message });
    }
  };

  // State carried between checks; `undefined` until its producing check succeeds.
  let wardenUpgradeAuthority: PublicKey | null | undefined;
  let wardenCodeHashHex: string | undefined;
  let vaultPda: PublicKey | undefined;

  // --- Check 0a: the pin may not weaken the spec-fixed governance shape --------
  await check("pin-spec-floors", async () => {
    assertPinSpecFloors(pin); // throws on a weakened threshold/count/time-lock/config authority
    return `pin meets the spec-fixed floors (3-of-5, >=7-day lock, autonomous config authority)`;
  });

  // --- Check 0b: authenticate the cluster (genesis hash) ----------------------
  await check("cluster-genesis", async () => {
    let genesis: string;
    try {
      genesis = await rpc(opts).getGenesisHash();
    } catch (e) {
      throw new Error(`RPC error fetching genesis hash: ${(e as Error).message}`);
    }
    if (genesis !== pin.expectedGenesisHash) {
      throw new Error(`cluster genesis ${genesis} != expected ${pin.expectedGenesisHash} — refusing an unauthenticated/forked cluster`);
    }
    return `cluster authenticated: genesis ${genesis}`;
  });

  // --- Check 1a: authenticate Warden's Program → ProgramData chain ------------
  await check("warden-programdata-chain", async () => {
    const { upgradeAuthority, codeHashHex } = await authenticateProgram(rpc(opts), pin.wardenProgramId, "Warden");
    wardenUpgradeAuthority = upgradeAuthority;
    wardenCodeHashHex = codeHashHex;
    if (!upgradeAuthority) throw new Error("Warden ProgramData is immutable (no upgrade authority) — cannot bind to a governed vault");
    return `Warden ProgramData authenticated; upgrade authority ${b58(upgradeAuthority)}`;
  });

  // --- Check 2: the Squads multisig is the pinned one, complete + fresh -------
  await check("squads-multisig-governance", async () => {
    const acct = await fetchOrThrow(rpc(opts), pin.multisig, "Squads multisig");
    if (!acct.owner.equals(pin.squadsProgramId)) {
      throw new Error(`multisig ${b58(pin.multisig)} is not owned by the pinned Squads program ${b58(pin.squadsProgramId)} (owner ${b58(acct.owner)})`);
    }
    const ms = decodeMultisig(acct.data); // verifies the Multisig discriminator
    if (ms.threshold !== pin.threshold) throw new Error(`threshold ${ms.threshold} != required ${pin.threshold}`);
    if (ms.members.length !== pin.memberCount) throw new Error(`member_count ${ms.members.length} != required ${pin.memberCount}`);
    if (ms.timeLock < pin.minTimeLockSeconds) throw new Error(`time_lock ${ms.timeLock}s < floor ${pin.minTimeLockSeconds}s`);

    // config_authority: autonomous default, or the explicitly pinned+attested one.
    const expectedConfigAuth = pin.configAuthority ?? DEFAULT_PUBKEY;
    if (!ms.configAuthority.equals(expectedConfigAuth)) {
      throw new Error(`config_authority ${b58(ms.configAuthority)} != expected ${b58(expectedConfigAuth)} (a non-default authority can rewrite members/threshold — WRDF-0017 round 4)`);
    }
    // Stale-governance safety (WRDF-0028) — PERMIT terminal history (WRDF-0087):
    // `transaction_index` is a monotonic "last index", nonzero after ANY proposal,
    // so requiring it to be 0 makes the gate unusable on any real, previously-used
    // multisig (and a Squads-mediated upgrade itself creates proposal state).
    // `stale_transaction_index` is the boundary Squads sets when the config
    // changes: every proposal with index <= it is invalidated and cannot execute.
    // A proposal approved under an OLD (weaker) config therefore cannot execute
    // once the config tightens — that enforcement lives in the Squads program,
    // whose CODE hash this gate pins (the `squads-code-hash` check is the trust
    // root for it). The one config-level anomaly the gate can flag cheaply:
    // `stale_transaction_index > transaction_index` is impossible in honest state.
    if (ms.staleTransactionIndex > ms.transactionIndex) {
      throw new Error(`stale_transaction_index ${ms.staleTransactionIndex} > transaction_index ${ms.transactionIndex} — inconsistent governance state`);
    }
    // Complete member set with EXACT permission masks (order-insensitive on key).
    const onchain = new Map(ms.members.map((m) => [b58(m.key), m.mask]));
    if (onchain.size !== ms.members.length) throw new Error("duplicate member key in the on-chain multisig");
    for (const pm of pin.members) {
      const mask = onchain.get(b58(pm.key));
      if (mask === undefined) throw new Error(`pinned member ${b58(pm.key)} is absent from the on-chain multisig`);
      if (mask !== pm.mask) throw new Error(`member ${b58(pm.key)} permission mask ${mask} != pinned ${pm.mask}`);
      onchain.delete(b58(pm.key));
    }
    if (onchain.size !== 0) throw new Error(`on-chain multisig has ${onchain.size} member(s) not in the pinned set: ${[...onchain.keys()].join(", ")}`);

    vaultPda = deriveVaultPda(pin.squadsProgramId, pin.multisig, pin.vaultIndex);
    return `multisig authenticated: pinned identity, ${pin.threshold}-of-${pin.memberCount}, time_lock ${ms.timeLock}s, autonomous config, consistent stale boundary (tx=${ms.transactionIndex}/stale=${ms.staleTransactionIndex}). Per-proposal actionable-stale enumeration is trust-rooted at the pinned Squads code hash; a live-chain Proposal/VaultTransaction/ConfigTransaction sweep is the documented residual`;
  });

  // --- Check 1b: bind the Warden upgrade authority to the derived vault PDA ----
  await check("upgrade-authority-is-vault-pda", async () => {
    if (wardenUpgradeAuthority === undefined) throw new Error("skipped: Warden chain check did not complete");
    if (vaultPda === undefined) throw new Error("skipped: multisig check did not complete");
    if (wardenUpgradeAuthority === null || !wardenUpgradeAuthority.equals(vaultPda)) {
      throw new Error(`upgrade authority ${wardenUpgradeAuthority ? b58(wardenUpgradeAuthority) : "none"} != derived vault PDA ${b58(vaultPda)}`);
    }
    return `upgrade authority == canonical vault PDA (index ${pin.vaultIndex}) ${b58(vaultPda)}`;
  });

  // --- Check: authenticate the Squads program's code (trust-root terminus) -----
  await check("squads-code-hash", async () => {
    const { codeHashHex } = await authenticateProgram(rpc(opts), pin.squadsProgramId, "Squads");
    if (codeHashHex !== pin.squadsCodeHashHex) {
      throw new Error(`Squads program code hash ${codeHashHex} != pinned audited hash ${pin.squadsCodeHashHex}`);
    }
    return `Squads program code hash matches the pinned audited hash`;
  });

  // --- Check 4a: the Warden release artifact hash --------------------------
  await check("warden-release-hash", async () => {
    if (wardenCodeHashHex === undefined) throw new Error("skipped: Warden chain check did not complete");
    if (wardenCodeHashHex !== opts.expectedReleaseHashHex) {
      throw new Error(`on-chain Warden code hash ${wardenCodeHashHex} != release-integrity hash ${opts.expectedReleaseHashHex}`);
    }
    return `on-chain Warden code hash matches the RELEASE-INTEGRITY row`;
  });

  // --- Check 3: adapter Registry authenticated + config matches source --------
  // (WRD-DEP-02) Fetch the canonical Registry PDA, owner-check it against the
  // Warden program, decode (the Registry discriminator is verified in-decoder),
  // and diff its complete config — every adapter selector RE-DERIVED from source,
  // role_rules, list membership, version, and the treasury — rejecting any
  // missing / extra / wrong / duplicate entry.
  await check("registry-config", async () => {
    const registryPda = deriveRegistryPda(pin.wardenProgramId);
    const acct = await fetchOrThrow(rpc(opts), registryPda, "Registry");
    if (!acct.owner.equals(pin.wardenProgramId)) {
      throw new Error(`Registry ${b58(registryPda)} is not owned by the Warden program ${b58(pin.wardenProgramId)} (owner ${b58(acct.owner)})`);
    }
    const reg = decodeRegistry(acct.data); // verifies the Registry discriminator + bounds
    const violations = diffRegistry(reg, {
      expectedVersion: pin.registryVersion,
      expectedTreasuryB58: pin.registryTreasury.toBase58(),
    });
    if (violations.length > 0) {
      throw new Error(`Registry config mismatch (${violations.length}): ${violations.join("; ")}`);
    }
    return `Registry authenticated at ${b58(registryPda)}: ${reg.nEntries} adapters, version ${reg.version}, treasury + all selectors/roles/lists match the source-re-derived pin`;
  });

  return { ok: results.every((r) => r.ok), results };
}

/** Tiny accessor so `check()` closures read `opts.rpc` without capturing it eagerly. */
function rpc(opts: { rpc: RpcSource }): RpcSource {
  return opts.rpc;
}
