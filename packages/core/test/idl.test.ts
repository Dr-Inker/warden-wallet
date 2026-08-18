import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// Guards against packages/core/idl/warden.json drifting from a fresh
// `anchor build` output (target/idl/warden.json) — see .claude/test-gate.sh's
// `cmp` parity check, which this test complements by asserting on shape
// rather than byte-identity (useful even when target/idl isn't present, e.g.
// in a checkout that only has the committed IDL).
const idlPath = fileURLToPath(new URL("../idl/warden.json", import.meta.url));
const idl = JSON.parse(readFileSync(idlPath, "utf8"));

describe("warden.json IDL", () => {
  const instructionNames = new Set(
    (idl.instructions as Array<{ name: string }>).map((i) => i.name),
  );
  const requiredInstructions = [
    "transfer",
    "grant_session",
    "create_account",
    "rotate_nonce",
    "freeze",
    "unfreeze",
    "revoke_session_root",
    "revoke_session_self",
  ];
  for (const name of requiredInstructions) {
    it(`includes instruction ${name}`, () => {
      expect(instructionNames.has(name)).toBe(true);
    });
  }

  it("error codes cover at least 6000..6035", () => {
    const codes = (idl.errors as Array<{ code: number }>).map((e) => e.code);
    const max = Math.max(...codes);
    expect(codes).toContain(6000);
    expect(max).toBeGreaterThanOrEqual(6035);
  });

  it("GrantBody type has prior_authority_hash", () => {
    const grantBody = (idl.types as Array<{ name: string; type: { fields?: Array<{ name: string }> } }>).find(
      (t) => t.name === "GrantBody",
    );
    expect(grantBody).toBeDefined();
    const fieldNames = (grantBody?.type.fields ?? []).map((f) => f.name);
    expect(fieldNames).toContain("prior_authority_hash");
  });
});
