import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync, chmodSync, cpSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { VERIFIER_SOURCE_CLOSURE, buildManifest, serializeManifest, ATTESTATION_PATH } from "../../../scripts/gen-verifier-attestation.mjs";

// Hermetic shell coverage of the live deploy-gate wiring (WRDF-0085/0088/0091/0092).
// Temp repos live UNDER the repo's gitignored target/ (on /opt) — never /tmp — with
// prefix-guarded cleanup (WRDF-0091). The gate runs the verifier through the repo's
// OWN <repo>/packages/core/node_modules/.bin/tsx by absolute path — no bare binary,
// no PATH surface, no override env var (WRDF-0092). The test injects its stub into
// its own temp-repo toolchain, which the production gate has no equivalent of.
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

describe("scripts/deploy-gate.sh — live wiring via the repo's own toolchain (WRDF-0088/0092)", () => {
  let dir: string;
  let outDir: string;
  let cSha = "";
  const digest = "d462c1fcd13cff9bf0b23b0df1e28b870fd5e570dfe80408d40cc39ed4c8a143"; // synthetic manifest digest
  const artifact = createHash("sha256").update("warden-so-bytes").digest("hex");
  let argsFile = "";
  let parseArgsFile = "";
  let entryFile = "";
  let absReleaseFile = "";
  let expectedEntry = "";
  const attestedSrc = (rel: string) => join(dir, rel); // an attested closure file inside the temp repo

  beforeAll(() => {
    dir = mkTemp("fullgate-");
    // The recorded sinks live OUTSIDE the repo tree: the gate's clean-tree preflight
    // (deploy-preflight.sh) counts untracked files as dirty, so writing them inside
    // `dir` would make the SECOND gate run refuse before it ever reaches the verifier
    // — a test-only artifact, not a gate property under test.
    outDir = mkTemp("fullgate-out-");
    argsFile = join(outDir, "verifier-args.txt");
    parseArgsFile = join(outDir, "parse-args.txt");
    entryFile = join(outDir, "entry.txt");
    absReleaseFile = join(dir, "docs", "security", "RELEASE-INTEGRITY.md");
    expectedEntry = join(dir, "packages", "core", "scripts", "deploy-gate-verify.ts");
    // The gate invokes <repo>/packages/core/node_modules/.bin/tsx by ABSOLUTE path
    // (WRDF-0092): no bare pnpm/tsx, no PATH surface, no env override. The test
    // injects the stub into ITS OWN temp repo's toolchain path — exactly what a
    // controlled test repo may do, and NOT a production bypass.
    for (const d of ["scripts", "docs/security", "programs", "packages/core/node_modules/.bin", "packages/core/scripts", "target/deploy"]) mkdirSync(join(dir, d), { recursive: true });
    cpSync(GATE, join(dir, "scripts", "deploy-gate.sh"));
    cpSync(PREFLIGHT, join(dir, "scripts", "deploy-preflight.sh"));
    writeFileSync(join(dir, "target", "deploy", "warden.so"), "warden-so-bytes");
    const stub = join(dir, "packages", "core", "node_modules", ".bin", "tsx");
    cpSync(join(dirname(fileURLToPath(import.meta.url)), "fixtures", "fake-verifier-tsx.sh"), stub);
    chmodSync(stub, 0o755);
    // Place the verdict-bearing SOURCE closure (a placeholder at each attested path —
    // the stub tsx never reads their contents) and a MATCHING committed attestation
    // manifest, so verify_source_attestation authenticates the real entrypoint + source
    // before invoking the verifier (WRDF-0092/0088 round 10). A later test mutates one
    // of these files and asserts the gate refuses BEFORE reaching the verifier.
    for (const rel of VERIFIER_SOURCE_CLOSURE as string[]) {
      mkdirSync(dirname(attestedSrc(rel)), { recursive: true });
      writeFileSync(attestedSrc(rel), `// hermetic placeholder for ${rel}\n`);
    }
    writeFileSync(join(dir, ATTESTATION_PATH as string), serializeManifest(buildManifest(dir)));

    git(dir, "init", "-q");
    writeFileSync(join(dir, "code.txt"), "v1"); git(dir, "add", "-A"); git(dir, "commit", "-qm", "release C");
    cSha = head(dir);
    const row = `| dev | \`${cSha}\` | \`${artifact}\` | id | x | y | none manifest:synthetic@${digest} | v |`;
    writeFileSync(absReleaseFile, `# Release integrity\n\n${row}\n`);
    git(dir, "add", "-A"); git(dir, "commit", "-qm", "attestation A for C");
  });
  afterAll(() => { safeRm(dir); safeRm(outDir); });

  const liveEnv = (exit = 0) => ({
    ...gitEnv,
    SOLANA_RPC_URL: "",
    FAKE_ARTIFACT_HASH: artifact,
    FAKE_ARGS_FILE: argsFile,
    FAKE_PARSE_ARGS_FILE: parseArgsFile,
    FAKE_ENTRY_FILE: entryFile,
    FAKE_VERIFIER_EXIT: String(exit),
  });
  const liveArgs = () => [ID, ID, ID, cSha, "--manifest", "synthetic", "--rpc-url", "http://127.0.0.1:1"];
  const gate = () => join(dir, "scripts", "deploy-gate.sh");

  it("forwards the EXACT parse-mode AND live verifier argument arrays", () => {
    safeRm(argsFile); safeRm(parseArgsFile); safeRm(entryFile);
    run("bash", [gate(), ...liveArgs()], dir, liveEnv(0));
    // Entrypoint identity (WRDF-0088 round 10): the gate ran the committed verifier path,
    // not a decoy — the stub recorded argv[1] and it is exactly the attested entrypoint.
    expect(existsSync(entryFile), "verifier entrypoint not recorded").toBe(true);
    expect(readFileSync(entryFile, "utf8").trim()).toBe(expectedEntry);
    // Parse mode: the canonical hash lookup carries BOTH release bindings.
    expect(existsSync(parseArgsFile), "parse-mode verifier not invoked").toBe(true);
    expect(readFileSync(parseArgsFile, "utf8").trim().split("\n")).toEqual([
      "--parse-release-hash", "1", "--release-sha", cSha, "--release-integrity-file", absReleaseFile,
    ]);
    // Live mode: the exact governance+hash argument array.
    expect(existsSync(argsFile), "live verifier not invoked").toBe(true);
    expect(readFileSync(argsFile, "utf8").trim().split("\n")).toEqual([
      "--rpc-url", "http://127.0.0.1:1",
      "--manifest", "synthetic",
      "--release-sha", cSha,
      "--release-integrity-file", absReleaseFile,
      "--expect-warden-program", ID,
      "--expect-multisig", ID,
      "--expect-authority", ID,
    ]);
  }, 30_000);

  it("propagates a FAILING verifier as its OWN specific refusal (not the check-3 deferral)", () => {
    safeRm(argsFile);
    const r = run("bash", [gate(), ...liveArgs()], dir, liveEnv(7));
    expect(r.code).not.toBe(0);
    // The failure is attributed to the governance+hash verifier specifically — a
    // message check-3's separate refusal never produces.
    expect(r.err).toMatch(/live governance\+hash checks failed/);
    expect(existsSync(argsFile)).toBe(true); // it DID reach the live verifier (which then failed)
  }, 30_000);

  it("REFUSES a dirty tree BEFORE the verifier is reached (no args recorded)", () => {
    safeRm(argsFile); safeRm(parseArgsFile);
    writeFileSync(join(dir, "code.txt"), "MUTATED");
    const r = run("bash", [gate(), ...liveArgs()], dir, liveEnv(0));
    git(dir, "checkout", "--", "code.txt");
    expect(r.code).not.toBe(0);
    expect(r.err).toMatch(/CLEAN working tree/);
    expect(existsSync(argsFile)).toBe(false); // live verifier never ran
  }, 30_000);

  it("REFUSES (fatally) when an attested verifier source file is altered — verifier never runs", () => {
    safeRm(argsFile); safeRm(parseArgsFile); safeRm(entryFile);
    const saved = head(dir);
    // Commit a tampered attested source WITHOUT regenerating the manifest: the tree is
    // CLEAN (git sees a committed change) yet the committed attestation still pins the old
    // hash. This is the swap the clean-tree check alone cannot catch.
    const target = attestedSrc(VERIFIER_SOURCE_CLOSURE[1] as string); // an src/deploy/*.ts
    writeFileSync(target, "// TAMPERED — not the attested content\n");
    git(dir, "add", "-A"); git(dir, "commit", "-qm", "tamper attested source");
    const r = run("bash", [gate(), ...liveArgs()], dir, liveEnv(0));
    git(dir, "reset", "-q", "--hard", saved);
    expect(r.code).not.toBe(0);
    expect(r.err).toMatch(/attested verifier source altered/);
    expect(existsSync(entryFile)).toBe(false); // fatal BEFORE any verifier invocation
    expect(existsSync(argsFile)).toBe(false);
  }, 30_000);

  it("REFUSES (fatally) when the attestation manifest is absent — verifier never runs", () => {
    safeRm(argsFile); safeRm(entryFile);
    const saved = head(dir);
    git(dir, "rm", "-q", ATTESTATION_PATH as string); git(dir, "commit", "-qm", "drop attestation");
    const r = run("bash", [gate(), ...liveArgs()], dir, liveEnv(0));
    git(dir, "reset", "-q", "--hard", saved);
    expect(r.code).not.toBe(0);
    expect(r.err).toMatch(/attestation manifest missing/);
    expect(existsSync(entryFile)).toBe(false);
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
