//! CLI for the deploy-gate governance + hash verification (Task 11R). Invoked by
//! `scripts/deploy-gate.sh` for DEPLOY-GATE.md checks 1/2/4a. Thin runner over the
//! testable logic in `src/deploy/cli.ts` (WRDF-0088). Two modes:
//!
//!   tsx deploy-gate-verify.ts --fixtures <case>
//!       Deterministic in-process scenario (no network); `happy` passes.
//!
//!   tsx deploy-gate-verify.ts --rpc-url <url> --manifest <name> --expected-hash <hex>
//!       --expect-warden-program <pk> --expect-multisig <pk> --expect-authority <pk>
//!       Real checks against a live cluster. The pin is a COMMITTED manifest
//!       selected by name (WRDF-0085); the shell's identities are REQUIRED and
//!       cross-checked. The per-proposal governance-state audit is NOT
//!       implemented in-tool and fails closed with NO attestation bypass
//!       (WRDF-0028). Live mode assumes a TRUSTED RPC endpoint (the genesis bind
//!       catches a wrong-cluster misconfig, not a malicious RPC).
//!
//! Exit 0 only if EVERY check passes; any failure exits non-zero (fail-closed).

import { readFileSync } from "node:fs";
import { Connection, PublicKey } from "@solana/web3.js";
import { verifyDeployGate, type GateVerdict, type RpcSource } from "../src/deploy/gate.js";
import { namedScenario, FIXTURE_CASES } from "../src/deploy/fixtures.js";
import { parseReleaseRow, bindReleaseManifest, crossCheckIdentities, proposalAuditResult, parseArgs } from "../src/deploy/cli.js";

function die(msg: string): never {
  console.error(`deploy-gate-verify: ${msg}`);
  process.exit(2);
}

function printVerdict(v: GateVerdict): never {
  for (const r of v.results) console.log(`  [${r.ok ? "PASS" : "REFUSE"}] ${r.name}: ${r.detail}`);
  console.log(v.ok ? "governance+hash: ALL CHECKS PASSED" : "governance+hash: REFUSE — at least one check failed");
  process.exit(v.ok ? 0 : 1);
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
  const args = parseArgs(argv);

  const fixtureCase = args.get("fixtures");
  if (fixtureCase !== undefined) {
    const scenario = namedScenario(fixtureCase);
    if (!scenario) die(`unknown fixture case '${fixtureCase}'; known: ${FIXTURE_CASES.join(", ")}`);
    printVerdict(await verifyDeployGate(scenario.pin, { rpc: scenario.rpc, expectedReleaseHashHex: scenario.expectedReleaseHashHex }));
  }

  // Live mode. The release row (parsed here, testably) binds a UNIQUE manifest
  // name + digest AND the on-chain artifact hash (WRDF-0085) — the shell forwards
  // only the release-sha and the file path, not trusted values it derived itself.
  const rpcUrl = args.get("rpc-url");
  const manifest = args.get("manifest");
  const releaseSha = args.get("release-sha");
  const releaseFile = args.get("release-integrity-file");
  if (!rpcUrl || !manifest || !releaseSha || !releaseFile) {
    die("live mode needs --rpc-url <url> --manifest <name> --release-sha <full-sha> --release-integrity-file <path> (or use --fixtures <case>)");
  }
  let pin;
  let expectedHash: string;
  try {
    const row = parseReleaseRow(readFileSync(releaseFile, "utf8"), releaseSha);
    pin = bindReleaseManifest(manifest, row);
    expectedHash = row.artifactHashHex;
    crossCheckIdentities(pin, {
      wardenProgram: args.get("expect-warden-program"),
      multisig: args.get("expect-multisig"),
      authority: args.get("expect-authority"),
    });
  } catch (e) {
    die((e as Error).message);
  }

  const rpc = connectionRpc(new Connection(rpcUrl, "finalized"));
  const verdict = await verifyDeployGate(pin, { rpc, expectedReleaseHashHex: expectedHash });
  // WRDF-0028: the proposal-state audit fails closed with no bypass.
  verdict.results.push(proposalAuditResult());
  verdict.ok = verdict.results.every((r) => r.ok);
  printVerdict(verdict);
}

main(process.argv.slice(2)).catch((e) => die((e as Error).message));
