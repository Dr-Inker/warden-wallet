import { describe, it, expect } from "vitest";
import { resolveManifest, crossCheckIdentities, proposalAuditResult, parseArgs, assertPubkey } from "../src/deploy/cli.js";
import { SYNTHETIC_PIN } from "../src/deploy/config.js";
import { deriveVaultPda } from "../src/deploy/accounts.js";

const goodIds = () => ({
  wardenProgram: SYNTHETIC_PIN.wardenProgramId.toBase58(),
  multisig: SYNTHETIC_PIN.multisig.toBase58(),
  authority: deriveVaultPda(SYNTHETIC_PIN.squadsProgramId, SYNTHETIC_PIN.multisig, SYNTHETIC_PIN.vaultIndex).toBase58(),
});

describe("deploy-gate CLI logic (WRDF-0088)", () => {
  it("resolveManifest returns a committed pin and rejects an unknown name (WRDF-0085)", () => {
    expect(resolveManifest("synthetic")).toBe(SYNTHETIC_PIN);
    expect(() => resolveManifest("mainnet")).toThrow(/unknown manifest 'mainnet'/);
    expect(() => resolveManifest("../../etc/passwd")).toThrow(/unknown manifest/);
  });

  it("crossCheckIdentities accepts the exact manifest identities + derived vault", () => {
    expect(() => crossCheckIdentities(SYNTHETIC_PIN, goodIds())).not.toThrow();
  });

  it("crossCheckIdentities refuses missing or mismatched identities (WRDF-0085)", () => {
    expect(() => crossCheckIdentities(SYNTHETIC_PIN, {})).toThrow(/requires --expect-warden-program/);
    expect(() => crossCheckIdentities(SYNTHETIC_PIN, { ...goodIds(), wardenProgram: SYNTHETIC_PIN.multisig.toBase58() })).toThrow(/expect-warden-program .* != manifest wardenProgramId/);
    expect(() => crossCheckIdentities(SYNTHETIC_PIN, { ...goodIds(), multisig: SYNTHETIC_PIN.wardenProgramId.toBase58() })).toThrow(/expect-multisig .* != manifest multisig/);
    // A wrong authority (not the derived vault) is refused — the authority is
    // authenticated against the manifest's canonical vault, not accepted as-is.
    expect(() => crossCheckIdentities(SYNTHETIC_PIN, { ...goodIds(), authority: SYNTHETIC_PIN.multisig.toBase58() })).toThrow(/expect-authority .* != derived vault PDA/);
  });

  it("proposalAuditResult ALWAYS fails closed — no attestation bypass (WRDF-0028)", () => {
    const r = proposalAuditResult();
    expect(r.name).toBe("governance-proposal-audit");
    expect(r.ok).toBe(false); // no argument, string, or flag can make this pass
    expect(r.detail).toMatch(/NOT IMPLEMENTED in-tool and NOT bypassable/);
  });

  it("parseArgs maps --k v pairs and rejects a stray token", () => {
    expect(parseArgs(["--a", "1", "--b", "2"]).get("b")).toBe("2");
    expect(() => parseArgs(["oops"])).toThrow(/unexpected argument oops/);
  });

  it("assertPubkey validates base58 pubkeys", () => {
    expect(() => assertPubkey(SYNTHETIC_PIN.multisig.toBase58(), "x")).not.toThrow();
    expect(() => assertPubkey("not-a-key", "field")).toThrow(/field is not a valid pubkey/);
  });
});
