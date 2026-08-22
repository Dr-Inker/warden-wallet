#!/usr/bin/env node
// Regenerates docs/security/verifier-attestation.json — the committed sha256 manifest
// of the deploy-gate verifier's verdict-bearing SOURCE closure (WRDF-0092 round 10).
//
// The deploy gate authenticates the SOURCE the toolchain will consume: before running
// the verifier it re-hashes each file below and refuses on any mismatch or missing file.
// This defeats a swapped .ts or a decoy entrypoint INDEPENDENTLY of the clean-tree check
// (which is blind to gitignored node_modules). It does NOT — and cannot — attest the JS
// transpiler/runtime below the source: node, tsx, and their node_modules closure are the
// declared trust-root terminus (docs/security/DEPLOY-GATE-TRUST-ROOT.md), the same kind of
// external THREATMODEL assumption already accepted for the Squads audited-code hash.
//
// Run from the repo root: `node scripts/gen-verifier-attestation.mjs`. A drift guard
// (packages/core/test/deploy-attestation.test.ts) fails if the committed manifest is stale.
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

// The verdict-bearing closure: the CLI entrypoint + every module it transitively imports
// from @warden/core's deploy surface. Paths are repo-root-relative and stable.
export const VERIFIER_SOURCE_CLOSURE = [
  "packages/core/scripts/deploy-gate-verify.ts",
  "packages/core/src/deploy/gate.ts",
  "packages/core/src/deploy/config.ts",
  "packages/core/src/deploy/accounts.ts",
  "packages/core/src/deploy/cli.ts",
  "packages/core/src/deploy/fixtures.ts",
];
export const ATTESTATION_PATH = "docs/security/verifier-attestation.json";
// The entrypoint the gate is hard-wired to invoke; recorded so the gate and tests share
// one source of truth and a decoy path is detectable.
export const VERIFIER_ENTRYPOINT = "packages/core/scripts/deploy-gate-verify.ts";

export function sha256File(absPath) {
  return createHash("sha256").update(readFileSync(absPath)).digest("hex");
}

export function buildManifest(repoRoot) {
  const files = {};
  for (const rel of VERIFIER_SOURCE_CLOSURE) files[rel] = sha256File(`${repoRoot}/${rel}`);
  return { schema: 1, entrypoint: VERIFIER_ENTRYPOINT, files };
}

// Canonical serialization: sorted keys, trailing newline — stable across regenerations.
export function serializeManifest(m) {
  const files = {};
  for (const k of Object.keys(m.files).sort()) files[k] = m.files[k];
  return JSON.stringify({ schema: m.schema, entrypoint: m.entrypoint, files }, null, 2) + "\n";
}

// Only write when executed directly (not when imported by the drift guard).
if (import.meta.url === `file://${process.argv[1]}`) {
  const repoRoot = process.cwd();
  const out = serializeManifest(buildManifest(repoRoot));
  writeFileSync(`${repoRoot}/${ATTESTATION_PATH}`, out);
  process.stdout.write(`verifier-attestation.json regenerated (${VERIFIER_SOURCE_CLOSURE.length} files).\n`);
}
