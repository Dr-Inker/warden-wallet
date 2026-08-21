//! Importable, unit-testable pieces of the deploy-gate CLI (Task 11R round 3,
//! WRDF-0088): manifest resolution, positional-identity cross-checking, and the
//! proposal-state-audit result. Kept out of the thin runner script so every
//! bypass has a red/green test.

import { PublicKey } from "@solana/web3.js";
import { MANIFESTS, manifestDigest, type DeployPinConfig } from "./config.js";
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
 * Select the manifest the RELEASE bound (WRDF-0085): the release-integrity record
 * names ONE manifest and its canonical digest. Resolve by name AND assert the
 * committed manifest's digest equals the release-bound digest — so a drifted
 * registry entry, a stale alternate, or a wrong name is refused, and the
 * release-sha selects a UNIQUE manifest. Throws on any mismatch.
 */
export function resolveManifestForRelease(name: string, expectedDigest: string): DeployPinConfig {
  const pin = resolveManifest(name);
  const actual = manifestDigest(pin);
  if (actual !== expectedDigest) {
    throw new Error(`manifest '${name}' digest ${actual} != release-bound digest ${expectedDigest} — the committed registry entry drifted from the reviewed release`);
  }
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

export interface ReleaseRow {
  artifactHashHex: string;
  manifestName: string;
  manifestDigest: string;
}

/**
 * Parse the RELEASE-INTEGRITY record for a release commit (WRDF-0085 round 5).
 * Requires an EXACT full 40-hex SHA and EXACTLY ONE matching table row (rejects
 * abbreviated identifiers and duplicate/ambiguous rows), and extracts the bound
 * `manifest:<name>@<64-hex digest>` token plus the artifact hash (the row's other
 * 64-hex value). Throws on any of: bad SHA form, zero/multiple rows, missing
 * token, or an indeterminable artifact hash.
 */
export function parseReleaseRow(md: string, releaseSha: string): ReleaseRow {
  if (!/^[0-9a-f]{40}$/.test(releaseSha)) {
    throw new Error(`release-sha '${releaseSha}' must be a full 40-hex commit id (no abbreviations)`);
  }
  const rows = md.split("\n").filter((l) => l.startsWith("| ") && l.includes(releaseSha));
  if (rows.length === 0) throw new Error(`no RELEASE-INTEGRITY row contains release-sha ${releaseSha}`);
  if (rows.length > 1) throw new Error(`${rows.length} RELEASE-INTEGRITY rows contain release-sha ${releaseSha} — ambiguous`);
  const row = rows[0]!;
  const tok = row.match(/manifest:([A-Za-z0-9_.-]+)@([0-9a-f]{64})/);
  if (!tok) throw new Error(`RELEASE-INTEGRITY row for ${releaseSha} has no manifest:<name>@<digest> token`);
  const manifestName = tok[1]!;
  const manifestDigest = tok[2]!;
  const hashes = [...row.matchAll(/\b[0-9a-f]{64}\b/g)].map((m) => m[0]).filter((h) => h !== manifestDigest);
  const unique = [...new Set(hashes)];
  if (unique.length !== 1) throw new Error(`RELEASE-INTEGRITY row for ${releaseSha} has ${unique.length} candidate artifact hashes (expected exactly 1)`);
  return { artifactHashHex: unique[0]!, manifestName, manifestDigest };
}

/**
 * Bind the operator-selected manifest to the release row (WRDF-0085): the selected
 * name MUST equal the release-bound name, and the committed manifest's digest MUST
 * equal the release-bound digest. Any disagreement is refused.
 */
export function bindReleaseManifest(selectedName: string, row: ReleaseRow): DeployPinConfig {
  if (selectedName !== row.manifestName) {
    throw new Error(`--manifest '${selectedName}' != release-bound manifest '${row.manifestName}' (the release selects a unique manifest)`);
  }
  return resolveManifestForRelease(row.manifestName, row.manifestDigest);
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
