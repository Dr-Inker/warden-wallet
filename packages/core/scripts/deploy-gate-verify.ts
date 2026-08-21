//! CLI for the deploy-gate governance + hash verification (Task 11R). Invoked by
//! `scripts/deploy-gate.sh` for DEPLOY-GATE.md checks 1/2/4a. Two modes:
//!
//!   tsx deploy-gate-verify.ts --fixtures <case>
//!       Run a deterministic in-process scenario (no network) — `happy` passes,
//!       every other case tampers with one field so the gate refuses. This is the
//!       fixture-verified path CI/dev exercises.
//!
//!   tsx deploy-gate-verify.ts --rpc-url <url> --pin <config.json> --expected-hash <hex>
//!       Run the REAL checks against a live cluster with a reviewed pin config.
//!       Wired but honestly UNVERIFIED until a release candidate exists.
//!
//! Exit code is 0 only if EVERY check passes; any failure (or a bad invocation)
//! exits non-zero — fail-closed.

import { readFileSync } from "node:fs";
import { Connection, PublicKey } from "@solana/web3.js";
import { verifyDeployGate, type GateVerdict, type RpcSource } from "../src/deploy/gate.js";
import { namedScenario, FIXTURE_CASES } from "../src/deploy/fixtures.js";
import {
  MIN_TIME_LOCK_SECONDS,
  REQUIRED_MEMBER_COUNT,
  REQUIRED_THRESHOLD,
  type DeployPinConfig,
  type PinnedMember,
} from "../src/deploy/config.js";

function die(msg: string): never {
  console.error(`deploy-gate-verify: ${msg}`);
  process.exit(2);
}

function printVerdict(v: GateVerdict): never {
  for (const r of v.results) console.log(`  [${r.ok ? "PASS" : "REFUSE"}] ${r.name}: ${r.detail}`);
  console.log(v.ok ? "governance+hash: ALL CHECKS PASSED" : "governance+hash: REFUSE — at least one check failed");
  process.exit(v.ok ? 0 : 1);
}

/** Parse a reviewed pin config JSON (pubkeys as base58 strings). Fail-closed on a
 *  missing or malformed field — a deploy gate must not run on a half-read pin. */
function loadPin(path: string): DeployPinConfig {
  const raw = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  const pk = (v: unknown, name: string): PublicKey => {
    if (typeof v !== "string") die(`pin.${name} must be a base58 string`);
    try {
      return new PublicKey(v as string);
    } catch {
      return die(`pin.${name} is not a valid pubkey: ${String(v)}`);
    }
  };
  const members = raw.members;
  if (!Array.isArray(members) || members.length === 0) die("pin.members must be a non-empty array");
  const parsedMembers: PinnedMember[] = members.map((m, i) => {
    const mm = m as Record<string, unknown>;
    if (typeof mm.mask !== "number") die(`pin.members[${i}].mask must be a number`);
    return { key: pk(mm.key, `members[${i}].key`), mask: mm.mask };
  });
  return {
    wardenProgramId: pk(raw.wardenProgramId, "wardenProgramId"),
    squadsProgramId: pk(raw.squadsProgramId, "squadsProgramId"),
    multisig: pk(raw.multisig, "multisig"),
    vaultIndex: typeof raw.vaultIndex === "number" ? raw.vaultIndex : die("pin.vaultIndex must be a number"),
    members: parsedMembers,
    threshold: typeof raw.threshold === "number" ? raw.threshold : REQUIRED_THRESHOLD,
    memberCount: typeof raw.memberCount === "number" ? raw.memberCount : REQUIRED_MEMBER_COUNT,
    minTimeLockSeconds: typeof raw.minTimeLockSeconds === "number" ? raw.minTimeLockSeconds : MIN_TIME_LOCK_SECONDS,
    configAuthority: raw.configAuthority == null ? null : pk(raw.configAuthority, "configAuthority"),
    squadsCodeHashHex: typeof raw.squadsCodeHashHex === "string" ? raw.squadsCodeHashHex : die("pin.squadsCodeHashHex must be a hex string"),
  };
}

/** A live RpcSource over a web3.js Connection. */
function connectionRpc(connection: Connection): RpcSource {
  return {
    async getAccountInfo(pubkey: PublicKey) {
      const info = await connection.getAccountInfo(pubkey, "finalized");
      if (!info) return null;
      return { owner: info.owner, data: new Uint8Array(info.data), executable: info.executable };
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

  // Live mode.
  const rpcUrl = args.get("rpc-url");
  const pinPath = args.get("pin");
  const expectedHash = args.get("expected-hash");
  if (!rpcUrl || !pinPath || !expectedHash) {
    die("live mode needs --rpc-url <url> --pin <config.json> --expected-hash <hex> (or use --fixtures <case>)");
  }
  const pin = loadPin(pinPath);
  const rpc = connectionRpc(new Connection(rpcUrl, "finalized"));
  printVerdict(await verifyDeployGate(pin, { rpc, expectedReleaseHashHex: expectedHash }));
}

main(process.argv.slice(2)).catch((e) => die((e as Error).message));
