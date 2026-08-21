import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveManifest, resolveManifestForRelease, parseReleaseRow, bindReleaseManifest, crossCheckIdentities, proposalAuditResult, parseArgs, assertPubkey } from "../src/deploy/cli.js";
import { SYNTHETIC_PIN, manifestDigest } from "../src/deploy/config.js";
import { deriveVaultPda } from "../src/deploy/accounts.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const DEV_SHA = "f0f38cab713d1d9165e367f3397e11a152620eab";
const digest = () => manifestDigest(SYNTHETIC_PIN);
const rowMd = (sha: string, extra = "") =>
  `| dev | \`${sha}\` | \`${"2a".repeat(32)}\` | id | x | y | z ${extra} manifest:synthetic@${digest()} | v |`;

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

  it("resolveManifestForRelease binds a unique manifest by name AND digest (WRDF-0085)", () => {
    const digest = manifestDigest(SYNTHETIC_PIN);
    expect(resolveManifestForRelease("synthetic", digest)).toBe(SYNTHETIC_PIN);
    // A drifted registry entry / stale alternate / wrong digest is refused.
    expect(() => resolveManifestForRelease("synthetic", "00".repeat(32))).toThrow(/digest .* != release-bound digest/);
    expect(() => resolveManifestForRelease("mainnet", digest)).toThrow(/unknown manifest 'mainnet'/);
  });

  // WRDF-0085 round 5: the release row must uniquely + non-self-referentially bind
  // the manifest. parseReleaseRow + bindReleaseManifest are the testable core.
  it("parseReleaseRow extracts the artifact hash + bound manifest from exactly one full-SHA row", () => {
    const r = parseReleaseRow(rowMd(DEV_SHA), DEV_SHA);
    expect(r.manifestName).toBe("synthetic");
    expect(r.manifestDigest).toBe(digest());
    expect(r.artifactHashHex).toBe("2a".repeat(32));
  });

  it("parseReleaseRow rejects abbreviated SHAs, zero rows, ambiguous rows, and a missing token", () => {
    expect(() => parseReleaseRow(rowMd(DEV_SHA), "f0f38ca")).toThrow(/full 40-hex/);
    expect(() => parseReleaseRow("| no matching row |", DEV_SHA)).toThrow(/no RELEASE-INTEGRITY row contains/);
    expect(() => parseReleaseRow(rowMd(DEV_SHA) + "\n" + rowMd(DEV_SHA), DEV_SHA)).toThrow(/ambiguous/);
    const noToken = `| dev | \`${DEV_SHA}\` | \`${"2a".repeat(32)}\` | id |`;
    expect(() => parseReleaseRow(noToken, DEV_SHA)).toThrow(/no manifest:<name>@<digest> token/);
  });

  it("bindReleaseManifest refuses a name mismatch and a digest mismatch", () => {
    const goodRow = parseReleaseRow(rowMd(DEV_SHA), DEV_SHA);
    expect(bindReleaseManifest("synthetic", goodRow)).toBe(SYNTHETIC_PIN);
    expect(() => bindReleaseManifest("mainnet", goodRow)).toThrow(/!= release-bound manifest 'synthetic'/);
    const wrongDigest = { ...goodRow, manifestDigest: "00".repeat(32) };
    expect(() => bindReleaseManifest("synthetic", wrongDigest)).toThrow(/digest .* != release-bound digest/);
  });

  it("the committed RELEASE-INTEGRITY dev row parses + binds end-to-end", () => {
    const md = readFileSync(join(REPO, "docs/security/RELEASE-INTEGRITY.md"), "utf8");
    const row = parseReleaseRow(md, DEV_SHA);
    expect(bindReleaseManifest("synthetic", row)).toBe(SYNTHETIC_PIN); // real row → real binding
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
