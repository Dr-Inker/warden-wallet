import { describe, it, expect } from "vitest";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  EXPECTED_CLOSURE,
  VERIFIER_ENTRYPOINT,
  ATTESTATION_PATH,
  discoverClosure,
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

  it("the gate script reads exactly this manifest path and entrypoint", () => {
    const gate = readFileSync(join(REPO, "scripts", "deploy-gate.sh"), "utf8");
    expect(gate).toContain(ATTESTATION_PATH as string);
    expect(gate).toContain(VERIFIER_ENTRYPOINT as string);
    expect(gate).toMatch(/verify_source_attestation[\s\S]*run_gov_hash_verifier/);
  });
});
