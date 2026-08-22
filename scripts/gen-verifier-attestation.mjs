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
// The closure is DISCOVERED by statically traversing the entrypoint's local import graph
// (WRDF-0088 round 11) — never a hand-maintained list — so a new verdict-bearing import
// cannot be silently omitted from attestation. Run from the repo root:
// `node scripts/gen-verifier-attestation.mjs`. A drift guard
// (packages/core/test/deploy-attestation.test.ts) fails if the committed manifest is stale
// or if discovery diverges from what is pinned.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve, relative } from "node:path";

// The CLI entrypoint the gate is hard-wired to invoke; the seed of the import graph and
// recorded in the manifest so the gate and tests share one source of truth.
export const VERIFIER_ENTRYPOINT = "packages/core/scripts/deploy-gate-verify.ts";
export const ATTESTATION_PATH = "docs/security/verifier-attestation.json";

// The closure discovery is expected to yield exactly these files for the current tree.
// This is a documented CHECK (asserted by the drift guard against live discovery), NOT
// the input to hashing — the manifest is always built from discovery, so adding a local
// import auto-extends the attested set and a stale manifest fails the guard.
export const EXPECTED_CLOSURE = [
  "packages/core/scripts/deploy-gate-verify.ts",
  "packages/core/src/deploy/gate.ts",
  "packages/core/src/deploy/config.ts",
  "packages/core/src/deploy/accounts.ts",
  "packages/core/src/deploy/cli.ts",
  "packages/core/src/deploy/fixtures.ts",
];

export function sha256File(absPath) {
  return createHash("sha256").update(readFileSync(absPath)).digest("hex");
}

// A LOCAL module specifier is a relative path (./ or ../); anything else (@scope/…,
// node:…) is an external dependency and the declared trust-root terminus — not traversed.
function isLocal(spec) {
  return spec.startsWith("./") || spec.startsWith("../");
}

// Resolve a local specifier from the importing file to a source .ts on disk. Imports use
// NodeNext `.js` specifiers that map to sibling `.ts` sources; a bare or `.ts` specifier
// is accepted too. Throws (fail-closed) on any local import that cannot be resolved.
function resolveLocalTs(fromAbs, spec) {
  const base = resolve(dirname(fromAbs), spec);
  const candidates = base.endsWith(".ts")
    ? [base]
    : base.endsWith(".js")
      ? [base.slice(0, -3) + ".ts"]
      : [base + ".ts", base + "/index.ts"];
  for (const c of candidates) if (existsSync(c)) return c;
  throw new Error(`verifier closure: unresolved local import ${JSON.stringify(spec)} from ${fromAbs}`);
}

// Statically traverse every LOCAL import/export reachable from the entrypoint. Rejects
// dynamic import() outright (unanalyzable, fail-closed). Returns sorted repo-relative
// .ts paths. External (bare) imports terminate the walk — they are the toolchain terminus.
export function discoverClosure(repoRoot, entryRel = VERIFIER_ENTRYPOINT) {
  const seen = new Set();
  const walk = (relPath) => {
    if (seen.has(relPath)) return;
    seen.add(relPath);
    const abs = `${repoRoot}/${relPath}`;
    const src = readFileSync(abs, "utf8");
    if (/\bimport\s*\(/.test(src)) {
      throw new Error(`verifier closure: dynamic import() is not allowed in ${relPath} (unanalyzable)`);
    }
    // Both `… from "spec"` (import/export) and side-effect `import "spec"`.
    const specs = [];
    for (const m of src.matchAll(/\bfrom\s*['"]([^'"]+)['"]/g)) specs.push(m[1]);
    for (const m of src.matchAll(/\bimport\s+['"]([^'"]+)['"]/g)) specs.push(m[1]);
    for (const spec of specs) {
      if (!isLocal(spec)) continue; // external dep = terminus
      const childRel = relative(repoRoot, resolveLocalTs(abs, spec));
      walk(childRel);
    }
  };
  walk(entryRel);
  return [...seen].sort();
}

export function buildManifest(repoRoot, closure = discoverClosure(repoRoot)) {
  const files = {};
  for (const rel of closure) files[rel] = sha256File(`${repoRoot}/${rel}`);
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
  const closure = discoverClosure(repoRoot);
  const out = serializeManifest(buildManifest(repoRoot, closure));
  writeFileSync(`${repoRoot}/${ATTESTATION_PATH}`, out);
  process.stdout.write(`verifier-attestation.json regenerated (${closure.length} files, discovered from ${VERIFIER_ENTRYPOINT}).\n`);
}
