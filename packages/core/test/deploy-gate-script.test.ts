import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, cpSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Hermetic shell coverage of the live checkout boundary (WRDF-0085/0088). The
// git-only preflight (clean tree + release-sha resolves + ancestor-of-HEAD) lives
// in scripts/deploy-preflight.sh so it can run in throwaway git repos with no RPC.
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PREFLIGHT = join(REPO, "scripts", "deploy-preflight.sh");
const GATE = join(REPO, "scripts", "deploy-gate.sh");
const ID = "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2";

function run(cmd: string, args: string[], cwd: string): { code: number; out: string; err: string } {
  try {
    return { code: 0, out: execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }), err: "" };
  } catch (e) {
    const ee = e as { status?: number; stdout?: string; stderr?: string };
    return { code: ee.status ?? 1, out: ee.stdout ?? "", err: ee.stderr ?? "" };
  }
}

describe("scripts/deploy-preflight.sh — hermetic checkout binding (WRDF-0088)", () => {
  let dir: string;
  let releaseSha = "";

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "warden-preflight-"));
    cpSync(PREFLIGHT, join(dir, "deploy-preflight.sh"));
    const git = (...a: string[]) => execFileSync("git", a, { cwd: dir, stdio: "pipe", env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" } });
    git("init", "-q");
    // Release commit C, then a later "attestation" commit A (HEAD) — C is an ancestor.
    writeFileSync(join(dir, "code.txt"), "v1");
    git("add", "-A"); git("commit", "-qm", "release C");
    releaseSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).trim();
    writeFileSync(join(dir, "attest.txt"), "release row for C");
    git("add", "-A"); git("commit", "-qm", "attestation A");
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

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

  it("REFUSES a non-ancestor commit (HEAD is not a descendant)", () => {
    // A sibling commit on a detached branch is not an ancestor of HEAD.
    const git = (...a: string[]) => execFileSync("git", a, { cwd: dir, stdio: "pipe", env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" } });
    git("branch", "side", releaseSha);
    git("checkout", "-q", "side");
    writeFileSync(join(dir, "side.txt"), "s"); git("add", "-A"); git("commit", "-qm", "side commit");
    const sideSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).trim();
    git("checkout", "-q", "-"); // back to the main line where sideSha is NOT an ancestor
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

describe("scripts/deploy-gate.sh --dry-run (WRDF-0088)", () => {
  it("runs cleanly (no 'fail: command not found') and never claims a verdict", () => {
    const r = run("bash", [GATE, ID, ID, ID, "f0f38cab713d1d9165e367f3397e11a152620eab", "--dry-run"], REPO);
    expect(r.err).not.toMatch(/command not found/);
    expect(r.out + r.err).toMatch(/DRY RUN — NOT VERIFIED/);
    expect(r.out + r.err).not.toMatch(/ALL CHECKS PASSED/);
  }, 30_000);
});
