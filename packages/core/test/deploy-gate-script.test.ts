import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync, chmodSync, cpSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

// Hermetic shell coverage of the live deploy-gate wiring (WRDF-0085/0088/0091).
// Temp repos live UNDER the repo's gitignored target/ (on /opt) — never /tmp —
// and cleanup is prefix-guarded (WRDF-0091).
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
function safeRm(dir: string): void {
  if (dir.startsWith(TMP_ROOT + "/")) rmSync(dir, { recursive: true, force: true }); // prefix-guarded (WRDF-0091)
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

describe("scripts/deploy-preflight.sh — hermetic checkout binding (WRDF-0088/0091)", () => {
  let dir: string;
  let releaseSha = "";
  beforeAll(() => {
    dir = mkTemp("preflight-");
    cpSync(PREFLIGHT, join(dir, "deploy-preflight.sh"));
    git(dir, "init", "-q");
    writeFileSync(join(dir, "code.txt"), "v1"); git(dir, "add", "-A"); git(dir, "commit", "-qm", "release C");
    releaseSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).trim();
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
    const sideSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).trim();
    git(dir, "checkout", "-q", "-");
    const r = run("bash", ["deploy-preflight.sh", sideSha], dir);
    expect(r.err).toMatch(/is not an ancestor of HEAD/);
  });
  it("REFUSES an unresolved release-sha", () => {
    const r = run("bash", ["deploy-preflight.sh", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"], dir);
    expect(r.err).toMatch(/does not resolve to a commit/);
  });
});

describe("scripts/deploy-gate.sh — live wiring with a stubbed verifier (WRDF-0088)", () => {
  let dir: string;
  let cSha = "";
  const digest = "d462c1fcd13cff9bf0b23b0df1e28b870fd5e570dfe80408d40cc39ed4c8a143"; // synthetic manifest digest
  const artifact = createHash("sha256").update("warden-so-bytes").digest("hex");
  let argsFile = "";

  beforeAll(() => {
    dir = mkTemp("fullgate-");
    argsFile = join(dir, "verifier-args.txt");
    // Minimal monorepo shape the gate touches.
    mkdirSync(join(dir, "scripts"), { recursive: true });
    mkdirSync(join(dir, "docs", "security"), { recursive: true });
    mkdirSync(join(dir, "programs"), { recursive: true });
    mkdirSync(join(dir, "packages"), { recursive: true });
    mkdirSync(join(dir, "target", "deploy"), { recursive: true });
    cpSync(GATE, join(dir, "scripts", "deploy-gate.sh"));
    cpSync(PREFLIGHT, join(dir, "scripts", "deploy-preflight.sh"));
    writeFileSync(join(dir, "target", "deploy", "warden.so"), "warden-so-bytes");
    // A stubbed verifier: prints the artifact hash for --parse-release-hash, else
    // records its args and exits 0 (the live check). Exercises the real forwarding.
    const stub = join(dir, "verifier-stub.sh");
    writeFileSync(stub, `#!/usr/bin/env bash\nif [ "$1" = "--parse-release-hash" ]; then echo "${artifact}"; exit 0; fi\nprintf '%s\\n' "$@" > "${argsFile}"\nexit 0\n`);
    chmodSync(stub, 0o755);

    git(dir, "init", "-q");
    // Release commit C (no row yet — a commit can't contain its own SHA).
    writeFileSync(join(dir, "code.txt"), "v1"); git(dir, "add", "-A"); git(dir, "commit", "-qm", "release C");
    cSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).trim();
    // Attestation commit A (HEAD): adds the RELEASE-INTEGRITY row binding C.
    const row = `| dev | \`${cSha}\` | \`${artifact}\` | id | x | y | none manifest:synthetic@${digest} | v |`;
    writeFileSync(join(dir, "docs", "security", "RELEASE-INTEGRITY.md"), `# Release integrity\n\n${row}\n`);
    git(dir, "add", "-A"); git(dir, "commit", "-qm", "attestation A for C");
  });
  afterAll(() => safeRm(dir));

  it("forwards the normalized full SHA + release file + manifest to the verifier", () => {
    const r = run("bash", [join(dir, "scripts", "deploy-gate.sh"), ID, ID, ID, cSha, "--manifest", "synthetic", "--rpc-url", "http://127.0.0.1:1"],
      dir, { ...gitEnv, WARDEN_DEPLOY_VERIFIER: join(dir, "verifier-stub.sh"), SOLANA_RPC_URL: "" });
    // The live verifier stub was reached (preflight passed: clean + ancestor) and
    // received the normalized full SHA, the absolute release file, and the manifest.
    expect(existsSync(argsFile), `verifier stub not invoked; gate out:\n${r.out}\n${r.err}`).toBe(true);
    const a = readFileSync(argsFile, "utf8");
    expect(a).toMatch(new RegExp(`^${cSha}$`, "m")); // normalized full SHA forwarded
    expect(a).toMatch(/RELEASE-INTEGRITY\.md/); // release file forwarded
    expect(a).toMatch(/^synthetic$/m); // manifest forwarded
    expect(a).not.toMatch(/command not found/);
  }, 30_000);

  it("REFUSES the live run when the working tree is dirty (preflight, before the verifier)", () => {
    safeRm(argsFile);
    writeFileSync(join(dir, "code.txt"), "MUTATED"); // dirty
    const r = run("bash", [join(dir, "scripts", "deploy-gate.sh"), ID, ID, ID, cSha, "--manifest", "synthetic", "--rpc-url", "http://127.0.0.1:1"],
      dir, { ...gitEnv, WARDEN_DEPLOY_VERIFIER: join(dir, "verifier-stub.sh"), SOLANA_RPC_URL: "" });
    git(dir, "checkout", "--", "code.txt");
    expect(r.err).toMatch(/CLEAN working tree/);
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
