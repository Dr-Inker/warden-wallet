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
// The closure is DISCOVERED by traversing the entrypoint's import graph with the real
// TypeScript parser (WRDF-0088 rounds 11-13) — never regex, which missed escaped specifiers
// and comment-separated forms. String-literal specifiers are read DECODED from the AST and
// classified by an ALLOW-list (round 13): a relative import is traversed in-repo, an
// exact-match permitted external dependency is the terminus, and EVERYTHING ELSE is rejected
// fail-closed — absolute paths, file:/data: URLs, surprise packages, `node:module` (the path
// to createRequire), and every non-static loading form (dynamic import(), require/
// createRequire, `import x = require(...)`, a non-literal specifier, an out-of-repo
// resolution). A deny-list cannot bound a reflective language; the allow-list can.
// Run from the repo root:
// `node scripts/gen-verifier-attestation.mjs`. A drift guard
// (packages/core/test/deploy-attestation.test.ts) fails if the committed manifest is stale
// or if discovery diverges from what is pinned.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve, relative, sep } from "node:path";
import ts from "typescript";

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
  "packages/core/src/deploy/registry-config.ts",
];

export function sha256File(absPath) {
  return createHash("sha256").update(readFileSync(absPath)).digest("hex");
}

// The verifier's ONLY permitted external dependencies (the declared toolchain terminus).
// This is an ALLOW-list, not a deny-list (WRDF-0088 round 13): a deny-list cannot win
// against a reflective language, so every specifier that is neither a relative import nor
// an exact member of this set is rejected fail-closed — including absolute paths, file:/
// data: URLs, surprise packages, and reflective-loading modules such as `node:module`
// (which is the only way to reach createRequire). A new genuine dependency requires a
// reviewed edit here; the drift guard asserts this set matches the closure's real externals.
export const PERMITTED_EXTERNAL = new Set([
  "@solana/web3.js",
  "@noble/hashes/sha2",
  "node:fs",
]);

// Classify a static module specifier: "local" (relative → traverse in-repo), "external"
// (an allow-listed dependency → terminus, not traversed), or null (everything else →
// reject fail-closed).
function classifySpecifier(spec) {
  if (spec.startsWith("./") || spec.startsWith("../")) return "local";
  if (PERMITTED_EXTERNAL.has(spec)) return "external";
  return null;
}

// Resolve a local specifier from the importing file to a source .ts on disk. Imports use
// NodeNext `.js` specifiers that map to sibling `.ts` sources; a bare or `.ts` specifier
// is accepted too. Throws (fail-closed) on any local import that cannot be resolved, or
// that resolves OUTSIDE the repo tree (a traversal escape).
function resolveLocalTs(repoRoot, fromAbs, spec) {
  const base = resolve(dirname(fromAbs), spec);
  const candidates = base.endsWith(".ts")
    ? [base]
    : base.endsWith(".js")
      ? [base.slice(0, -3) + ".ts"]
      : [base + ".ts", base + "/index.ts"];
  for (const c of candidates) {
    if (!existsSync(c)) continue;
    if (c !== repoRoot && !c.startsWith(repoRoot + sep)) {
      throw new Error(`verifier closure: local import ${JSON.stringify(spec)} resolves outside the repo (${c})`);
    }
    return c;
  }
  throw new Error(`verifier closure: unresolved local import ${JSON.stringify(spec)} from ${fromAbs}`);
}

// Names of reflective module-loading / code-evaluation APIs that can pull in an unattested
// module WITHOUT a static import (WRDF-0088 round 14). Static analysis can never SOUNDLY
// enumerate every such form, so this is a SOUND-OR-LOUD gate, not the primary defense: any
// reference to one of these in a verdict-bearing module is rejected fail-closed, so the
// module graph is never SILENTLY under-attested. The primary defense remains the sha256
// pin — this code must live in an already-attested source file, so introducing it changes
// that file's pinned hash and the gate refuses (docs/security/DEPLOY-GATE-TRUST-ROOT.md).
// Reflection primitives + module/eval APIs. The verifier's real source references NONE of
// these (it uses `process` for argv/exit only). This closes the demonstrated vectors
// (Reflect.get(globalThis,"eval"), process.getBuiltinModule, etc.). It is EXPLICITLY NOT a
// completeness proof — a reflective language admits further aliases — see the honest scope
// note in docs/security/DEPLOY-GATE-TRUST-ROOT.md: a fully-sound guarantee needs a runtime
// permission boundary (deferred), and the two-model review lane is the interim control
// against malicious reflective code committed into an attested file.
const REFLECTIVE_LOADERS = new Set([
  "eval", "Function", "getBuiltinModule", "createRequire", "require", "binding",
  "Reflect", "globalThis", "global", "constructor",
]);

// Parse ONE module with the TypeScript scanner/parser and return its static import/export
// specifiers (decoded). Fail-closed on any non-static loading form (dynamic import(),
// `import x = require(...)`, a non-literal specifier) OR any reference to a reflective
// loader/eval API by identifier, member name, or string element-access.
function staticSpecifiers(relPath, srcText) {
  const sf = ts.createSourceFile(relPath, srcText, ts.ScriptTarget.Latest, /*setParentNodes*/ true, ts.ScriptKind.TS);
  const specs = [];
  const reject = (why) => {
    throw new Error(`verifier closure: ${why} in ${relPath} (unanalyzable / unsupported loading form, fail-closed)`);
  };
  const visit = (node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
      if (!ts.isStringLiteral(node.moduleSpecifier)) reject("non-literal module specifier");
      specs.push(node.moduleSpecifier.text); // AST text is the DECODED specifier value
    } else if (ts.isImportEqualsDeclaration(node)) {
      reject("`import … = require(…)` form");
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      reject("dynamic import()");
    } else if (ts.isIdentifier(node) && REFLECTIVE_LOADERS.has(node.text)) {
      reject(`reflective loader / eval reference \`${node.text}\``);
    } else if (ts.isPropertyAccessExpression(node) && REFLECTIVE_LOADERS.has(node.name.text)) {
      reject(`reflective member \`.${node.name.text}\``);
    } else if (ts.isElementAccessExpression(node) && node.argumentExpression && ts.isStringLiteral(node.argumentExpression) && REFLECTIVE_LOADERS.has(node.argumentExpression.text)) {
      reject(`reflective member [${JSON.stringify(node.argumentExpression.text)}]`);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return specs;
}

// Statically traverse every LOCAL import/export reachable from the entrypoint. Returns
// sorted repo-relative .ts paths. External (bare) imports terminate the walk — they are
// the toolchain terminus.
export function discoverClosure(repoRoot, entryRel = VERIFIER_ENTRYPOINT) {
  const seen = new Set();
  const walk = (relPath) => {
    if (seen.has(relPath)) return;
    seen.add(relPath);
    const abs = `${repoRoot}/${relPath}`;
    for (const spec of staticSpecifiers(relPath, readFileSync(abs, "utf8"))) {
      const kind = classifySpecifier(spec);
      if (kind === "external") continue; // allow-listed dependency = terminus
      if (kind === null) {
        throw new Error(`verifier closure: disallowed module specifier ${JSON.stringify(spec)} in ${relPath} — only relative imports and the permitted external allow-list are allowed (fail-closed)`);
      }
      walk(relative(repoRoot, resolveLocalTs(repoRoot, abs, spec)));
    }
  };
  walk(entryRel);
  return [...seen].sort();
}

// The set of EXTERNAL (allow-listed) specifiers actually imported across the discovered
// closure — used by the drift guard to assert PERMITTED_EXTERNAL has no dead entries and no
// missing ones. Throws (via discovery) if any disallowed specifier is present.
export function externalDeps(repoRoot) {
  const out = new Set();
  for (const rel of discoverClosure(repoRoot)) {
    for (const spec of staticSpecifiers(rel, readFileSync(`${repoRoot}/${rel}`, "utf8"))) {
      if (classifySpecifier(spec) === "external") out.add(spec);
    }
  }
  return [...out].sort();
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
