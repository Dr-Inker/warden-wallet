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

  it("error codes cover at least 6000..6038", () => {
    const codes = (idl.errors as Array<{ code: number }>).map((e) => e.code);
    const max = Math.max(...codes);
    expect(codes).toContain(6000);
    expect(max).toBeGreaterThanOrEqual(6038);
  });

  // Phase 1B Task 0: the slot-freshness + top-level-only ABI block. Named, not
  // just counted, because a client that maps 6036 to the wrong message is
  // exactly the drift this file exists to catch.
  it("names the Phase 1B Task 0 errors at their pinned codes", () => {
    const byCode = new Map(
      (idl.errors as Array<{ code: number; name: string }>).map((e) => [e.code, e.name]),
    );
    expect(byCode.get(6036)).toBe("RootSlotStale");
    expect(byCode.get(6037)).toBe("RootSlotInFuture");
    expect(byCode.get(6038)).toBe("RootRequiresTopLevel");
  });

  // The transcript ABI: `signed_slot` must be in the IDL's `RootArgs`, and it
  // must be the LAST field — the wire order the TS client borsh-encodes and
  // the position `packages/core/src/webauthn/transcript.ts` mirrors.
  it("RootArgs carries signed_slot as its trailing u64", () => {
    const rootArgs = (idl.types as Array<{ name: string; type: { fields?: Array<{ name: string; type: string }> } }>).find(
      (t) => t.name === "RootArgs",
    );
    expect(rootArgs).toBeDefined();
    const fields = rootArgs?.type.fields ?? [];
    expect(fields.map((f) => f.name)).toContain("signed_slot");
    expect(fields[fields.length - 1]?.name).toBe("signed_slot");
    expect(fields[fields.length - 1]?.type).toBe("u64");
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
