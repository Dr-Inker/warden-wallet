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
  `| dev | \`${sha}\` | \`${"2a".repeat(32)}\` | id | x | y | z ${extra} manifest:synthetic@${digest()} | none | v |`;

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
    expect(() => resolveManifest("__proto__")).toThrow(/unknown manifest/);
    expect(() => resolveManifest("constructor")).toThrow(/unknown manifest/);
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
    expect(r.releaseSha).toBe(DEV_SHA);
    expect(r.sessionReleaseName).toBeNull();
    expect(r.sessionReleaseDigest).toBeNull();
  });

  it("parses a session-release token only from its dedicated leading-value column", () => {
    const statementDigest = "7b".repeat(32);
    const exact = rowMd(
      DEV_SHA,
    ).replace("| none | v |", `| \`session-release:devnet-r1@${statementDigest}\` | v |`);
    const parsed = parseReleaseRow(exact, DEV_SHA);
    expect(parsed.sessionReleaseName).toBe("devnet-r1");
    expect(parsed.sessionReleaseDigest).toBe(statementDigest);

    const mentioned = rowMd(DEV_SHA).replace(
      "| none | v |",
      `| pending; later \`session-release:devnet-r1@${statementDigest}\` | v |`,
    );
    const unbound = parseReleaseRow(mentioned, DEV_SHA);
    expect(unbound.sessionReleaseName).toBeNull();
    expect(unbound.sessionReleaseDigest).toBeNull();

    const ambiguous = exact.replace(
      "| v |",
      ` also \`session-release:other-r1@${"8c".repeat(32)}\` | v |`,
    );
    expect(() => parseReleaseRow(ambiguous, DEV_SHA)).toThrow(
      /multiple session-release tokens/,
    );
  });

  it("parseReleaseRow rejects abbreviated SHAs, zero rows, ambiguous rows, and a missing token", () => {
    expect(() => parseReleaseRow(rowMd(DEV_SHA), "f0f38ca")).toThrow(/full 40-hex/);
    expect(() => parseReleaseRow("| no matching row |", DEV_SHA)).toThrow(/no RELEASE-INTEGRITY row has release-sha .* in its Git-SHA column/);
    expect(() => parseReleaseRow(rowMd(DEV_SHA) + "\n" + rowMd(DEV_SHA), DEV_SHA)).toThrow(/ambiguous/);
    const noToken = `| dev | \`${DEV_SHA}\` | \`${"2a".repeat(32)}\` | id |`;
    expect(() => parseReleaseRow(noToken, DEV_SHA)).toThrow(/has 0 manifest:<name>@<digest> tokens/);
  });

  it("requires the LEADING backtick value of the Git-SHA column, not one mid-cell (WRDF-0085 round 7)", () => {
    const A = "1".repeat(40);
    // A appears in the Git-SHA cell but NOT as its leading value (it is in a
    // trailing caveat) → must not bind for A.
    const midCell = `| dev | \`${"2".repeat(40)}\` supersedes \`${A}\` | \`${"2a".repeat(32)}\` | manifest:synthetic@${digest()} |`;
    expect(() => parseReleaseRow(midCell, A)).toThrow(/no RELEASE-INTEGRITY row has release-sha .* in its Git-SHA column/);
  });

  it("anchors to the Git-SHA COLUMN, not a substring in notes (WRDF-0085 round 6)", () => {
    // A row for release B whose NOTES mention A must not bind when invoked for A.
    const A = "1".repeat(40);
    const B = "2".repeat(40);
    const rowForB = `| dev | \`${B}\` | \`${"2a".repeat(32)}\` | id | x | y | supersedes \`${A}\` manifest:synthetic@${digest()} | v |`;
    expect(() => parseReleaseRow(rowForB, A)).toThrow(/no RELEASE-INTEGRITY row has release-sha .* in its Git-SHA column/);
    // Invoked for B (its actual column) it parses fine.
    expect(parseReleaseRow(rowForB, B).manifestName).toBe("synthetic");
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
    expect(row.sessionReleaseName).toBeNull();
    expect(row.sessionReleaseDigest).toBeNull();
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
