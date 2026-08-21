import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync, chmodSync, cpSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

// Hermetic shell coverage of the live deploy-gate wiring (WRDF-0085/0088/0091/0092).
// Temp repos live UNDER the repo's gitignored target/ (on /opt) — never /tmp — with
// prefix-guarded cleanup (WRDF-0091). The verifier is stubbed by shadowing `pnpm`
// on PATH — the gate has NO production override env var (WRDF-0092).
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const TMP_ROOT = join(REPO, "target", "deploy-gate-testtmp");
const PREFLIGHT = join(REPO, "scripts", "deploy-preflight.sh");
const GATE = join(REPO, "scripts", "deploy-gate.sh");
const ID = "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2";
const gitEnv = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };

function mkTemp(prefix: string): string {
  mkdirSync(TMP_ROOT, { recursive: true });
  return mkdtempSync(join(TMP_ROOT, prefix));
}
function safeRm(target: string): void {
  if (target.startsWith(TMP_ROOT + "/")) rmSync(target, { recursive: true, force: true }); // prefix-guarded (WRDF-0091)
}
function run(cmd: string, args: string[], cwd: string, env = process.env): { code: number; out: string; err: string } {
  try {
    return { code: 0, out: execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], env }), err: "" };
  } catch (e) {
    const ee = e as { status?: number; stdout?: string; stderr?: string };
    return { code: ee.status ?? 1, out: ee.stdout ?? "", err: ee.stderr ?? "" };
  }
}
const git = (dir: string, ...a: string[]) => execFileSync("git", a, { cwd: dir, stdio: "pipe", env: gitEnv });
const head = (dir: string) => execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).trim();

describe("scripts/deploy-preflight.sh — hermetic checkout binding (WRDF-0088/0091)", () => {
  let dir: string;
  let releaseSha = "";
  beforeAll(() => {
    dir = mkTemp("preflight-");
    cpSync(PREFLIGHT, join(dir, "deploy-preflight.sh"));
    git(dir, "init", "-q");
    writeFileSync(join(dir, "code.txt"), "v1"); git(dir, "add", "-A"); git(dir, "commit", "-qm", "release C");
    releaseSha = head(dir);
    writeFileSync(join(dir, "attest.txt"), "row for C"); git(dir, "add", "-A"); git(dir, "commit", "-qm", "attestation A");
  });
  afterAll(() => safeRm(dir));

  it("ACCEPTS a clean tree with the release-sha an ancestor of HEAD (prints the full SHA)", () => {
    const r = run("bash", ["deploy-preflight.sh", releaseSha], dir);
    expect(r.code).toBe(0);
    expect(r.out.trim()).toBe(releaseSha);
  });
  it("REFUSES a dirty working tree", () => {
    writeFileSync(join(dir, "dirty.txt"), "x");
    const r = run("bash", ["deploy-preflight.sh", releaseSha], dir);
    rmSync(join(dir, "dirty.txt"));
    expect(r.code).not.toBe(0);
    expect(r.err).toMatch(/CLEAN working tree/);
  });
  it("REFUSES a non-ancestor commit", () => {
    git(dir, "branch", "side", releaseSha); git(dir, "checkout", "-q", "side");
    writeFileSync(join(dir, "side.txt"), "s"); git(dir, "add", "-A"); git(dir, "commit", "-qm", "side");
    const sideSha = head(dir);
    git(dir, "checkout", "-q", "-");
    const r = run("bash", ["deploy-preflight.sh", sideSha], dir);
    expect(r.code).not.toBe(0);
    expect(r.err).toMatch(/is not an ancestor of HEAD/);
  });
  it("REFUSES an unresolved release-sha", () => {
    const r = run("bash", ["deploy-preflight.sh", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"], dir);
    expect(r.code).not.toBe(0);
    expect(r.err).toMatch(/does not resolve to a commit/);
  });
});

describe("scripts/deploy-gate.sh — live wiring with a PATH-shadowed verifier (WRDF-0088/0092)", () => {
  let dir: string;
  let cSha = "";
  const digest = "d462c1fcd13cff9bf0b23b0df1e28b870fd5e570dfe80408d40cc39ed4c8a143"; // synthetic manifest digest
  const artifact = createHash("sha256").update("warden-so-bytes").digest("hex");
  let argsFile = "";
  let binDir = "";
  let absReleaseFile = "";

  beforeAll(() => {
    dir = mkTemp("fullgate-");
    argsFile = join(dir, "verifier-args.txt");
    binDir = join(dir, "fakebin");
    absReleaseFile = join(dir, "docs", "security", "RELEASE-INTEGRITY.md");
    for (const d of ["scripts", "docs/security", "programs", "packages", "target/deploy", "fakebin"]) mkdirSync(join(dir, d), { recursive: true });
    cpSync(GATE, join(dir, "scripts", "deploy-gate.sh"));
    cpSync(PREFLIGHT, join(dir, "scripts", "deploy-preflight.sh"));
    writeFileSync(join(dir, "target", "deploy", "warden.so"), "warden-so-bytes");

    // A committed `pnpm` shadow (test/fixtures/fake-pnpm.sh) that ENFORCES the
    // verifier's real flag/value contract. There is NO gate override env var
    // (WRDF-0092) — we shadow the real `pnpm` on PATH.
    const fakePnpm = join(binDir, "pnpm");
    cpSync(join(dirname(fileURLToPath(import.meta.url)), "fixtures", "fake-pnpm.sh"), fakePnpm);
    chmodSync(fakePnpm, 0o755);

    git(dir, "init", "-q");
    writeFileSync(join(dir, "code.txt"), "v1"); git(dir, "add", "-A"); git(dir, "commit", "-qm", "release C");
    cSha = head(dir);
    const row = `| dev | \`${cSha}\` | \`${artifact}\` | id | x | y | none manifest:synthetic@${digest} | v |`;
    writeFileSync(absReleaseFile, `# Release integrity\n\n${row}\n`);
    git(dir, "add", "-A"); git(dir, "commit", "-qm", "attestation A for C");
  });
  afterAll(() => safeRm(dir));

  const liveEnv = (exit = 0) => ({
    ...gitEnv,
    PATH: `${binDir}:${process.env.PATH}`,
    SOLANA_RPC_URL: "",
    FAKE_ARTIFACT_HASH: artifact,
    FAKE_ARGS_FILE: argsFile,
    FAKE_VERIFIER_EXIT: String(exit),
  });
  const liveArgs = () => [ID, ID, ID, cSha, "--manifest", "synthetic", "--rpc-url", "http://127.0.0.1:1"];

  it("forwards the EXACT verifier argument array (normalized SHA, release file, identities)", () => {
    safeRm(argsFile);
    run("bash", [join(dir, "scripts", "deploy-gate.sh"), ...liveArgs()], dir, liveEnv(0));
    expect(existsSync(argsFile)).toBe(true);
    const got = readFileSync(argsFile, "utf8").trim().split("\n");
    expect(got).toEqual([
      "--rpc-url", "http://127.0.0.1:1",
      "--manifest", "synthetic",
      "--release-sha", cSha,
      "--release-integrity-file", absReleaseFile,
      "--expect-warden-program", ID,
      "--expect-multisig", ID,
      "--expect-authority", ID,
    ]);
  }, 30_000);

  it("propagates a FAILING verifier to a nonzero gate result", () => {
    safeRm(argsFile);
    const r = run("bash", [join(dir, "scripts", "deploy-gate.sh"), ...liveArgs()], dir, liveEnv(7));
    expect(r.code).not.toBe(0);
    expect(r.err).toMatch(/live governance\+hash checks failed/);
  }, 30_000);

  it("REFUSES a dirty tree BEFORE the verifier is reached (no args recorded)", () => {
    safeRm(argsFile);
    writeFileSync(join(dir, "code.txt"), "MUTATED");
    const r = run("bash", [join(dir, "scripts", "deploy-gate.sh"), ...liveArgs()], dir, liveEnv(0));
    git(dir, "checkout", "--", "code.txt");
    expect(r.code).not.toBe(0);
    expect(r.err).toMatch(/CLEAN working tree/);
    expect(existsSync(argsFile)).toBe(false); // verifier never ran
  }, 30_000);
});

describe("scripts/deploy-gate.sh --dry-run (WRDF-0088)", () => {
  it("runs cleanly and never claims a verdict", () => {
    const r = run("bash", [GATE, ID, ID, ID, "f0f38cab713d1d9165e367f3397e11a152620eab", "--dry-run"], REPO);
    expect(r.err).not.toMatch(/command not found/);
    expect(r.out + r.err).toMatch(/DRY RUN — NOT VERIFIED/);
    expect(r.out + r.err).not.toMatch(/ALL CHECKS PASSED/);
  }, 30_000);
});
