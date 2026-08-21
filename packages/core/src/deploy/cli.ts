//! Importable, unit-testable pieces of the deploy-gate CLI (Task 11R round 3,
//! WRDF-0088): manifest resolution, positional-identity cross-checking, and the
//! proposal-state-audit result. Kept out of the thin runner script so every
//! bypass has a red/green test.

import { PublicKey } from "@solana/web3.js";
import { MANIFESTS, type DeployPinConfig } from "./config.js";
import { deriveVaultPda } from "./accounts.js";
import type { CheckResult } from "./gate.js";

/** Select a pin BY NAME from the COMMITTED registry — never an arbitrary file
 *  (WRDF-0085). Throws on an unknown name, listing the committed manifests. */
export function resolveManifest(name: string): DeployPinConfig {
  const pin = MANIFESTS[name];
  if (!pin) throw new Error(`unknown manifest '${name}'; committed manifests: ${Object.keys(MANIFESTS).join(", ")}`);
  return pin;
}

/**
 * Cross-check the shell's REQUIRED positional identities against the manifest and
 * the derived vault (WRDF-0085). All three are required; program+multisig must
 * equal the manifest, and the expected authority must equal the manifest's
 * canonical vault PDA. Throws on any mismatch or missing value.
 */
export function crossCheckIdentities(
  pin: DeployPinConfig,
  ids: { wardenProgram?: string; multisig?: string; authority?: string },
): void {
  if (!ids.wardenProgram || !ids.multisig || !ids.authority) {
    throw new Error("live mode requires --expect-warden-program, --expect-multisig, and --expect-authority (forwarded by deploy-gate.sh)");
  }
  if (ids.wardenProgram !== pin.wardenProgramId.toBase58()) {
    throw new Error(`--expect-warden-program ${ids.wardenProgram} != manifest wardenProgramId ${pin.wardenProgramId.toBase58()}`);
  }
  if (ids.multisig !== pin.multisig.toBase58()) {
    throw new Error(`--expect-multisig ${ids.multisig} != manifest multisig ${pin.multisig.toBase58()}`);
  }
  const derivedVault = deriveVaultPda(pin.squadsProgramId, pin.multisig, pin.vaultIndex).toBase58();
  if (ids.authority !== derivedVault) {
    throw new Error(`--expect-authority ${ids.authority} != derived vault PDA ${derivedVault}`);
  }
}

/**
 * The per-proposal governance-state audit (WRDF-0028/0029): enumerate every
 * Proposal / VaultTransaction / ConfigTransaction / batch between the stale
 * boundary and `transaction_index`, accept only conclusively-terminal history,
 * and bind the intended release proposal to its reviewed digest. This is NOT
 * implemented in-tool and there is NO attestation bypass — a plain string
 * verifies nothing (WRDF-0028 round 3). Live mode therefore FAILS CLOSED on this
 * check: the config-level checks are the rigorous automated part, and this deeper
 * sweep is a required pre-mainnet implementation, honestly refused until then.
 */
export function proposalAuditResult(): CheckResult {
  return {
    name: "governance-proposal-audit",
    ok: false,
    detail:
      "NOT IMPLEMENTED in-tool and NOT bypassable — the per-proposal actionable-stale " +
      "enumeration + release-digest binding is a required pre-mainnet implementation; " +
      "live mode fails closed on it (no attestation shortcut). Config-level checks above are the automated part.",
  };
}

/** Parse `--k v` argv pairs into a map (used by the runner + tested here). */
export function parseArgs(argv: string[]): Map<string, string> {
  const args = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i]?.startsWith("--")) throw new Error(`unexpected argument ${argv[i]}`);
    args.set(argv[i]!.slice(2), argv[i + 1] ?? "");
  }
  return args;
}

/** Validate a base58 pubkey string, or throw naming the field. */
export function assertPubkey(value: string, field: string): void {
  try {
    // eslint-disable-next-line no-new
    new PublicKey(value);
  } catch {
    throw new Error(`${field} is not a valid pubkey: ${value}`);
  }
}
