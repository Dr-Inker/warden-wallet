import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  VERIFIER_SOURCE_CLOSURE,
  VERIFIER_ENTRYPOINT,
  ATTESTATION_PATH,
  buildManifest,
  serializeManifest,
} from "../../../scripts/gen-verifier-attestation.mjs";

// The deploy gate authenticates its verifier's SOURCE closure against a committed sha256
// manifest (WRDF-0092 round 10). This guard fails if the committed manifest drifts from
// the source it pins — run `node scripts/gen-verifier-attestation.mjs` to refresh it.
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

describe("verifier source attestation (docs/security/verifier-attestation.json)", () => {
  it("matches the current verifier source closure byte-for-byte (regenerate if this fails)", () => {
    const committed = readFileSync(join(REPO, ATTESTATION_PATH as string), "utf8");
    const fresh = serializeManifest(buildManifest(REPO));
    expect(committed).toBe(fresh);
  });

  it("pins the entrypoint and every module the entrypoint transitively imports", () => {
    const m = JSON.parse(readFileSync(join(REPO, ATTESTATION_PATH as string), "utf8"));
    expect(m.entrypoint).toBe(VERIFIER_ENTRYPOINT);
    // Entrypoint is part of the hashed closure, and every closure file has a 64-hex pin.
    expect((VERIFIER_SOURCE_CLOSURE as string[]).includes(VERIFIER_ENTRYPOINT as string)).toBe(true);
    for (const rel of VERIFIER_SOURCE_CLOSURE as string[]) {
      expect(m.files[rel], `missing pin for ${rel}`).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("the gate script reads exactly this manifest path and entrypoint", () => {
    const gate = readFileSync(join(REPO, "scripts", "deploy-gate.sh"), "utf8");
    expect(gate).toContain(ATTESTATION_PATH as string);
    expect(gate).toContain(VERIFIER_ENTRYPOINT as string);
    // The attestation runs BEFORE the verifier is ever invoked, and is fatal.
    expect(gate).toMatch(/verify_source_attestation[\s\S]*run_gov_hash_verifier/);
  });
});
