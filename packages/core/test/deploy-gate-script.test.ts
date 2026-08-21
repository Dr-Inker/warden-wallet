import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Shell-level integration for scripts/deploy-gate.sh (WRDF-0088): the checkout
// boundary + release→manifest binding + the `fail`-before-definition fix live in
// bash, outside the unit tests, so exercise the actual script here.
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SCRIPT = join(REPO, "scripts", "deploy-gate.sh");
const ID = "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2"; // any valid-looking base58 pubkey

/** Run the gate; returns { code, stdout, stderr } without throwing. */
function runGate(args: string[]): { code: number; out: string; err: string } {
  try {
    const out = execFileSync("bash", [SCRIPT, ...args], { cwd: REPO, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
    return { code: 0, out, err: "" };
  } catch (e) {
    const ee = e as { status?: number; stdout?: string; stderr?: string };
    return { code: ee.status ?? 1, out: ee.stdout ?? "", err: ee.stderr ?? "" };
  }
}

describe("scripts/deploy-gate.sh (WRDF-0088)", () => {
  it("--dry-run runs cleanly (no 'fail: command not found') and never claims a verdict", () => {
    const r = runGate([ID, ID, ID, "f0f38cab713d1d9165e367f3397e11a152620eab", "--dry-run"]);
    expect(r.err).not.toMatch(/command not found/); // the fail-before-definition bug
    expect(r.out + r.err).toMatch(/DRY RUN — NOT VERIFIED/);
    expect(r.out + r.err).not.toMatch(/ALL CHECKS PASSED/);
  }, 30_000);

  it("a live --manifest run refuses when the release-sha is not a real commit (checkout boundary)", () => {
    // 'deadbeef' is valid-format but resolves to no commit → the WRDF-0085 preflight
    // refuses. The specific assertion is the SHA-resolution refusal (not a generic
    // one), and it must fire before the verifier is spawned.
    const r = runGate([ID, ID, ID, "deadbeef", "--manifest", "synthetic", "--rpc-url", "http://127.0.0.1:1"]);
    expect(r.code).not.toBe(0);
    expect(r.err).toMatch(/release-sha 'deadbeef' does not resolve to a commit/);
    expect(r.err).not.toMatch(/command not found/);
  }, 30_000);

  // Note: the manifest name/digest + artifact-hash binding is exercised
  // deterministically in deploy-cli.test.ts (parseReleaseRow / bindReleaseManifest
  // against both synthetic rows and the committed RELEASE-INTEGRITY.md) — the
  // earlier "manifest disagrees" shell test was vacuous because the checkout
  // preconditions fired first (WRDF-0088), so it was removed in favour of the
  // isolated TS coverage.
});
