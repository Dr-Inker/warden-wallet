import { describe, it, expect } from "vitest";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  EXPECTED_CLOSURE,
  VERIFIER_ENTRYPOINT,
  ATTESTATION_PATH,
  PERMITTED_EXTERNAL,
  discoverClosure,
  externalDeps,
  buildManifest,
  serializeManifest,
} from "../../../scripts/gen-verifier-attestation.mjs";

// The deploy gate authenticates its verifier's SOURCE closure against a committed sha256
// manifest (WRDF-0092 round 10). The closure is DISCOVERED from the entrypoint's import
// graph, not a hand list (WRDF-0088 round 11), so a new verdict-bearing import cannot be
// silently omitted from attestation. This guard fails on drift or on a discovery mismatch —
// run `node scripts/gen-verifier-attestation.mjs` to refresh the manifest. The synthetic
// fixture repos below are pure-fs (no git), so nothing here can touch the real repo.
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const TMP_ROOT = join(REPO, "target", "attestation-testtmp");

describe("verifier source attestation (docs/security/verifier-attestation.json)", () => {
  it("discovers the closure from the entrypoint's import graph — matching the expected set", () => {
    // Independent of any hand list: traversing real imports yields exactly EXPECTED_CLOSURE.
    expect(discoverClosure(REPO).sort()).toEqual([...(EXPECTED_CLOSURE as string[])].sort());
  });

  it("matches the current verifier source closure byte-for-byte (regenerate if this fails)", () => {
    const committed = readFileSync(join(REPO, ATTESTATION_PATH as string), "utf8");
    const fresh = serializeManifest(buildManifest(REPO)); // buildManifest defaults to live discovery
    expect(committed).toBe(fresh);
  });

  it("pins the entrypoint and every module the entrypoint transitively imports", () => {
    const m = JSON.parse(readFileSync(join(REPO, ATTESTATION_PATH as string), "utf8"));
    expect(m.entrypoint).toBe(VERIFIER_ENTRYPOINT);
    expect(discoverClosure(REPO).includes(VERIFIER_ENTRYPOINT as string)).toBe(true);
    for (const rel of discoverClosure(REPO)) {
      expect(m.files[rel], `missing pin for ${rel}`).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("REJECTS a verdict-bearing module that uses a dynamic import (unanalyzable, fail-closed)", () => {
    mkdirSync(TMP_ROOT, { recursive: true });
    const d = mkdtempSync(join(TMP_ROOT, "dyn-"));
    try {
      const entryRel = "packages/core/scripts/deploy-gate-verify.ts";
      mkdirSync(join(d, dirname(entryRel)), { recursive: true });
      mkdirSync(join(d, "packages/core/src/deploy"), { recursive: true });
      writeFileSync(join(d, entryRel), `import { x } from "../src/deploy/gate.js";\n`);
      // The imported module smuggles in a dynamic import — discovery must refuse.
      writeFileSync(join(d, "packages/core/src/deploy/gate.ts"), `const m = import("./evil.js");\n`);
      expect(() => discoverClosure(d)).toThrow(/dynamic import/);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("REJECTS an unresolved local import (fail-closed)", () => {
    mkdirSync(TMP_ROOT, { recursive: true });
    const d = mkdtempSync(join(TMP_ROOT, "unres-"));
    try {
      const entryRel = "packages/core/scripts/deploy-gate-verify.ts";
      mkdirSync(join(d, dirname(entryRel)), { recursive: true });
      writeFileSync(join(d, entryRel), `import { y } from "../src/deploy/missing.js";\n`);
      expect(() => discoverClosure(d)).toThrow(/unresolved local import/);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("DECODES an escaped module specifier and still attests the real target (WRDF-0088 round 12)", () => {
    // The regex parser saw the raw chars `./…` as non-local and OMITTED the executed
    // module; the AST reads the DECODED specifier, so the escaped import is traversed.
    mkdirSync(TMP_ROOT, { recursive: true });
    const d = mkdtempSync(join(TMP_ROOT, "esc-"));
    try {
      const entryRel = "packages/core/scripts/deploy-gate-verify.ts";
      mkdirSync(join(d, dirname(entryRel)), { recursive: true });
      mkdirSync(join(d, "packages/core/src/deploy"), { recursive: true });
      // "../src/deploy/gate.js" decodes to "../src/deploy/gate.js".
      writeFileSync(join(d, entryRel), `import { x } from "\\u002e\\u002e/src/deploy/gate.js";\n`);
      writeFileSync(join(d, "packages/core/src/deploy/gate.ts"), `export const x = 1;\n`);
      expect(discoverClosure(d)).toContain("packages/core/src/deploy/gate.ts");
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("REJECTS a comment-separated dynamic import that the regex check missed (WRDF-0088 round 12)", () => {
    mkdirSync(TMP_ROOT, { recursive: true });
    const d = mkdtempSync(join(TMP_ROOT, "cmt-"));
    try {
      const entryRel = "packages/core/scripts/deploy-gate-verify.ts";
      mkdirSync(join(d, dirname(entryRel)), { recursive: true });
      mkdirSync(join(d, "packages/core/src/deploy"), { recursive: true });
      writeFileSync(join(d, entryRel), `import { x } from "../src/deploy/gate.js";\n`);
      writeFileSync(join(d, "packages/core/src/deploy/gate.ts"), `const m = import /*gap*/ ("./evil.js");\n`);
      expect(() => discoverClosure(d)).toThrow(/dynamic import/);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("REJECTS a local require()/createRequire (unsupported loading form, fail-closed)", () => {
    mkdirSync(TMP_ROOT, { recursive: true });
    const d = mkdtempSync(join(TMP_ROOT, "req-"));
    try {
      const entryRel = "packages/core/scripts/deploy-gate-verify.ts";
      mkdirSync(join(d, dirname(entryRel)), { recursive: true });
      writeFileSync(join(d, entryRel), `const x = require("./evil.js");\n`);
      expect(() => discoverClosure(d)).toThrow(/require/);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  // WRDF-0088 round 13: a deny-list cannot bound a reflective language, so classification is
  // an ALLOW-list — relative OR an exact permitted external; everything else fail-closed.
  for (const [label, entrySrc, pattern] of [
    ["an absolute-path import (executed but non-relative)", `import x from "/tmp/ignored-evil.mjs";\n`, /disallowed module specifier/],
    ["a node:module import (the only path to createRequire)", `import * as m from "node:module";\n`, /disallowed module specifier/],
    ["a file: URL import", `import x from "file:///tmp/evil.mjs";\n`, /disallowed module specifier/],
    ["a surprise bare package not on the allow-list", `import x from "left-pad";\n`, /disallowed module specifier/],
  ] as const) {
    it(`REJECTS ${label} (allow-list, fail-closed)`, () => {
      mkdirSync(TMP_ROOT, { recursive: true });
      const d = mkdtempSync(join(TMP_ROOT, "allow-"));
      try {
        const entryRel = "packages/core/scripts/deploy-gate-verify.ts";
        mkdirSync(join(d, dirname(entryRel)), { recursive: true });
        writeFileSync(join(d, entryRel), entrySrc);
        expect(() => discoverClosure(d)).toThrow(pattern);
      } finally {
        rmSync(d, { recursive: true, force: true });
      }
    });
  }

  // WRDF-0088 round 14: reflective module-loading / eval APIs can pull in an unattested
  // module with NO static import. Static analysis can't soundly enumerate every form, so
  // discovery is SOUND-OR-LOUD: any such reference is rejected fail-closed (the primary
  // defense stays the sha256 pin — this code must live in an already-attested file).
  for (const [label, entrySrc] of [
    ["process.getBuiltinModule (round-14 probe)", `const cr = process.getBuiltinModule("module");\n`],
    ["Reflect.get(globalThis, \"eval\")(readFileSync(...)) (round-15 probe)", `import { readFileSync } from "node:fs";\nReflect.get(globalThis, "eval")(readFileSync("./evil.js", "utf8"));\n`],
    ["globalThis element-access eval", `globalThis["eval"]("1+1");\n`],
    ["eval", `const x = eval("1+1");\n`],
    ["new Function code compilation", `const f = new Function("return process")();\n`],
    ["constructor-chain (fn.constructor)", `const f = (() => {}).constructor("return 1");\n`],
  ] as const) {
    it(`REJECTS a reflective loader: ${label} (sound-or-loud, fail-closed)`, () => {
      mkdirSync(TMP_ROOT, { recursive: true });
      const d = mkdtempSync(join(TMP_ROOT, "refl-"));
      try {
        const entryRel = "packages/core/scripts/deploy-gate-verify.ts";
        mkdirSync(join(d, dirname(entryRel)), { recursive: true });
        writeFileSync(join(d, entryRel), entrySrc);
        expect(() => discoverClosure(d)).toThrow(/reflective/);
      } finally {
        rmSync(d, { recursive: true, force: true });
      }
    });
  }

  it("the permitted-external allow-list exactly matches the closure's real external deps (no dead/missing entries)", () => {
    expect(externalDeps(REPO)).toEqual([...(PERMITTED_EXTERNAL as Set<string>)].sort());
  });

  it("the gate script reads exactly this manifest path and entrypoint", () => {
    const gate = readFileSync(join(REPO, "scripts", "deploy-gate.sh"), "utf8");
    expect(gate).toContain(ATTESTATION_PATH as string);
    expect(gate).toContain(VERIFIER_ENTRYPOINT as string);
    expect(gate).toMatch(/verify_source_attestation[\s\S]*run_gov_hash_verifier/);
  });
});
