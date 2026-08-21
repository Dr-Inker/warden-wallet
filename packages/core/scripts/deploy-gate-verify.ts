//! CLI for the deploy-gate governance + hash verification (Task 11R). Invoked by
//! `scripts/deploy-gate.sh` for DEPLOY-GATE.md checks 1/2/4a. Two modes:
//!
//!   tsx deploy-gate-verify.ts --fixtures <case>
//!       Run a deterministic in-process scenario (no network) — `happy` passes,
//!       every other case tampers with one field so the gate refuses.
//!
//!   tsx deploy-gate-verify.ts --rpc-url <url> --manifest <name> --expected-hash <hex>
//!       --expect-warden-program <pk> --expect-multisig <pk> --expect-authority <pk>
//!       [--proposal-audit-attested <ref>]
//!       Run the REAL checks against a live cluster. The pin is selected BY NAME
//!       from the COMMITTED manifest registry (config.ts `MANIFESTS`), NEVER from
//!       an arbitrary file (WRDF-0085) — the trust anchor is reviewed source. The
//!       shell's positional identities are REQUIRED and cross-checked against the
//!       pin (program/multisig) and the derived vault (authority). Live mode is
//!       honestly UNVERIFIED until a release candidate exists, and it assumes a
//!       TRUSTED RPC endpoint (the genesis-hash bind catches a wrong-cluster
//!       misconfiguration, not an actively-malicious RPC — that is out of the
//!       gate's threat model; mitigate with a known-good endpoint / quorum).
//!
//! Exit code is 0 only if EVERY check passes; any failure (or a bad invocation)
//! exits non-zero — fail-closed.

import { Connection, PublicKey } from "@solana/web3.js";
import { verifyDeployGate, type GateVerdict, type RpcSource } from "../src/deploy/gate.js";
import { namedScenario, FIXTURE_CASES } from "../src/deploy/fixtures.js";
import { MANIFESTS, type DeployPinConfig } from "../src/deploy/config.js";
import { deriveVaultPda } from "../src/deploy/accounts.js";

function die(msg: string): never {
  console.error(`deploy-gate-verify: ${msg}`);
  process.exit(2);
}

function printVerdict(v: GateVerdict, extra: string[] = []): never {
  for (const r of v.results) console.log(`  [${r.ok ? "PASS" : "REFUSE"}] ${r.name}: ${r.detail}`);
  for (const line of extra) console.log(line);
  const ok = v.ok && extra.every((l) => !l.includes("[REFUSE]"));
  console.log(ok ? "governance+hash: ALL CHECKS PASSED" : "governance+hash: REFUSE — at least one check failed");
  process.exit(ok ? 0 : 1);
}

/** Cross-check the shell's REQUIRED positional identities against the pin and the
 *  derived vault (WRDF-0085): the pin is the authority, but the shell also
 *  forwards program/multisig/authority; any disagreement means the operator is
 *  being misled, so refuse. */
function crossCheckArgs(pin: DeployPinConfig, args: Map<string, string>): void {
  const wp = args.get("expect-warden-program");
  const ms = args.get("expect-multisig");
  const auth = args.get("expect-authority");
  if (!wp || !ms || !auth) {
    die("live mode requires --expect-warden-program, --expect-multisig, and --expect-authority (forwarded by deploy-gate.sh)");
  }
  if (wp !== pin.wardenProgramId.toBase58()) die(`--expect-warden-program ${wp} != manifest wardenProgramId ${pin.wardenProgramId.toBase58()}`);
  if (ms !== pin.multisig.toBase58()) die(`--expect-multisig ${ms} != manifest multisig ${pin.multisig.toBase58()}`);
  const derivedVault = deriveVaultPda(pin.squadsProgramId, pin.multisig, pin.vaultIndex).toBase58();
  if (auth !== derivedVault) die(`--expect-authority ${auth} != derived vault PDA ${derivedVault} (the shell's expected authority must be the manifest's canonical vault)`);
}

/** A live RpcSource over a web3.js Connection. */
function connectionRpc(connection: Connection): RpcSource {
  return {
    async getAccountInfo(pubkey: PublicKey) {
      const info = await connection.getAccountInfo(pubkey, "finalized");
      if (!info) return null;
      return { owner: info.owner, data: new Uint8Array(info.data), executable: info.executable };
    },
    getGenesisHash() {
      return connection.getGenesisHash();
    },
  };
}

async function main(argv: string[]): Promise<void> {
  const args = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i]?.startsWith("--")) die(`unexpected argument ${argv[i]}`);
    args.set(argv[i]!.slice(2), argv[i + 1] ?? "");
  }

  const fixtureCase = args.get("fixtures");
  if (fixtureCase !== undefined) {
    const scenario = namedScenario(fixtureCase);
    if (!scenario) die(`unknown fixture case '${fixtureCase}'; known: ${FIXTURE_CASES.join(", ")}`);
    printVerdict(await verifyDeployGate(scenario.pin, { rpc: scenario.rpc, expectedReleaseHashHex: scenario.expectedReleaseHashHex }));
  }

  // Live mode — pin selected from the COMMITTED registry, never an arbitrary file.
  const rpcUrl = args.get("rpc-url");
  const manifest = args.get("manifest");
  const expectedHash = args.get("expected-hash");
  if (!rpcUrl || !manifest || !expectedHash) {
    die("live mode needs --rpc-url <url> --manifest <name> --expected-hash <hex> (or use --fixtures <case>)");
  }
  const pin = MANIFESTS[manifest];
  if (!pin) die(`unknown manifest '${manifest}'; committed manifests: ${Object.keys(MANIFESTS).join(", ")}`);
  crossCheckArgs(pin, args); // WRDF-0085: shell identities must agree with the pin + derived vault

  const rpc = connectionRpc(new Connection(rpcUrl, "finalized"));
  const verdict = await verifyDeployGate(pin, { rpc, expectedReleaseHashHex: expectedHash });

  // WRDF-0028: the per-proposal governance-state audit (enumerate every Proposal /
  // VaultTransaction / ConfigTransaction / batch between the stale boundary and
  // transaction_index; accept only conclusively-terminal history; bind the
  // intended release proposal to its reviewed digest) is a REQUIRED LIVE-RELEASE
  // step that this tool does NOT perform in-process. It is not silently passed:
  // live mode REFUSES unless the operator attests the sweep was done at the
  // release slot. The config-level checks above are the rigorous automated part.
  const extra: string[] = [];
  const attested = args.get("proposal-audit-attested");
  if (attested) {
    extra.push(`  [PASS] governance-proposal-audit: operator-attested live sweep at ${attested}`);
  } else {
    extra.push("  [REFUSE] governance-proposal-audit: per-proposal actionable-stale enumeration + release-digest binding NOT performed in-tool; run the live proposal-state sweep at the release slot and pass --proposal-audit-attested <ref>");
  }
  printVerdict(verdict, extra);
}

main(process.argv.slice(2)).catch((e) => die((e as Error).message));
