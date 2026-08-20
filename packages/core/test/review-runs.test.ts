// Assurance layer L3 guard rails for the review-RUN record (campaign plan 2026-08-20, gap G2).
//
// REVIEW-SCORECARD.jsonl records findings; REVIEW-RUNS.jsonl records rounds. The property that
// matters — and the one these tests pin — is the asymmetry:
//   - a VALIDATED round with ZERO findings appends exactly ONE run record;
//   - a round whose artefact FAILS validation appends NOTHING.
// Without the first, review coverage is invisible; without the second, a garbage artefact could
// buy a coverage line.
import { describe, it, expect } from "vitest";
import { readFileSync, writeFileSync, existsSync, mkdtempSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildRunRecord } from "../../../scripts/append-review-run.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const RUNS = join(REPO, "docs/security/REVIEW-RUNS.jsonl");
const EXAMPLE = join(REPO, ".codex/schemas/warden-findings.example.json");
const EXPECT_FILE = join(REPO, ".codex/schemas/warden-findings.example.expect.json");
const APPENDER = join(REPO, "scripts/append-review-run.mjs");

const KINDS = ["task-diff", "docs", "milestone", "whole-feature", "baseline-not-recorded"];

interface Run {
  date: string;
  kind: string;
  base_sha: string | null;
  head_sha: string | null;
  thread: string | null;
  reviewer_model: string | null;
  effort: string | null;
  seeded_count: number | null;
  findings_count: number | null;
  artefact: string;
  notes?: string;
  recorded_by: string;
  __line: number;
}

const runs: Run[] = readFileSync(RUNS, "utf8")
  .split("\n")
  .map((text, i) => ({ text, line: i + 1 }))
  .filter((l) => l.text.trim().length > 0)
  .map((l) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(l.text);
    } catch (e) {
      throw new Error(`REVIEW-RUNS.jsonl line ${l.line} is not valid JSON: ${(e as Error).message}`);
    }
    return { ...(parsed as Run), __line: l.line };
  });

const fresh = () => JSON.parse(readFileSync(EXAMPLE, "utf8"));
const expectations = () => JSON.parse(readFileSync(EXPECT_FILE, "utf8"));
/** The example artefact with its findings stripped — a valid ZERO-finding round. */
const zeroFinding = () => {
  const doc = fresh();
  doc.findings = [];
  for (const v of doc.invariant_verdicts) delete v.finding_ids;
  return doc;
};

describe("review-run record (docs/security/REVIEW-RUNS.jsonl)", () => {
  it("is non-empty and every line parses", () => {
    expect(runs.length).toBeGreaterThanOrEqual(1);
  });

  it("carries the required fields on every run", () => {
    for (const r of runs) {
      expect(r.date, `line ${r.__line}`).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(KINDS, `line ${r.__line} kind`).toContain(r.kind);
      expect(typeof r.artefact, `line ${r.__line} artefact`).toBe("string");
      expect(r.recorded_by, `line ${r.__line}`).toBeTruthy();
    }
  });

  it("gives every LIVE run full provenance, counts, and an immutable artefact digest", () => {
    for (const r of runs.filter((x) => x.artefact !== "not-recorded")) {
      const at = `line ${r.__line}`;
      expect(r.base_sha, at).toMatch(/^[0-9a-f]{7,40}$/);
      expect(r.head_sha, at).toMatch(/^[0-9a-f]{7,40}$/);
      expect(r.thread, at).toBeTruthy();
      expect(r.reviewer_model, at).toBeTruthy();
      expect(typeof r.findings_count, at).toBe("number");
      expect(typeof r.seeded_count, at).toBe("number");
      expect((r as Run & { artefact_sha256?: string }).artefact_sha256, at).toMatch(/^[0-9a-f]{64}$/);
      expect(r.kind, `${at}: a live run may not claim the baseline kind`).not.toBe("baseline-not-recorded");
    }
  });

  it("never records two live runs with the same artefact digest (replay guard)", () => {
    const digests = runs
      .map((r) => (r as Run & { artefact_sha256?: string }).artefact_sha256)
      .filter(Boolean);
    expect(new Set(digests).size).toBe(digests.length);
  });

  it("makes every NOT-RECORDED baseline entry say so honestly", () => {
    for (const r of runs.filter((x) => x.artefact === "not-recorded")) {
      const at = `line ${r.__line}`;
      expect(r.kind, at).toBe("baseline-not-recorded");
      expect(r.notes ?? "", `${at}: a not-recorded entry must explain itself`).toMatch(
        /retrospectiv|UNVERIFIED/i,
      );
      // A baseline entry must never invent a finding count it cannot source.
      if (typeof r.findings_count === "number") {
        expect(r.notes ?? "", `${at}: a counted baseline entry must name its source`).toMatch(
          /recorded in|per the reviewed document|PHASE1B-MEASUREMENTS|§/,
        );
      }
    }
  });
});

describe("buildRunRecord (scripts/append-review-run.mjs)", () => {
  it("builds a record for the worked example against its expectations", async () => {
    const rec = await buildRunRecord(fresh(), expectations(), { kind: "task-diff", effort: "max" });
    expect(rec.findings_count).toBe(fresh().findings.length);
    expect(rec.seeded_count).toBe(fresh().seeded_invariants.length);
    expect(rec.base_sha).toBe(fresh().base_sha);
    expect(rec.thread).toBe(fresh().thread);
  });

  it("records a VALIDATED zero-finding round as one run with findings_count 0", async () => {
    const rec = await buildRunRecord(zeroFinding(), expectations(), { kind: "task-diff" });
    expect(rec.findings_count).toBe(0);
    expect(rec.seeded_count).toBeGreaterThan(0);
  });

  it("REFUSES an artefact that fails validation (dropped seeded invariant)", async () => {
    const doc = fresh();
    const dropped = doc.seeded_invariants.pop();
    doc.invariant_verdicts = doc.invariant_verdicts.filter(
      (v: { invariant_id: string }) => v.invariant_id !== dropped,
    );
    await expect(buildRunRecord(doc, expectations())).rejects.toThrow(/fails validation/);
  });

  it("REFUSES a run with no expectations — unverifiable rounds are not coverage", async () => {
    await expect(buildRunRecord(fresh(), undefined as never)).rejects.toThrow(/expectations/);
  });

  it("REFUSES to append a baseline entry — those are hand-written history", async () => {
    await expect(
      buildRunRecord(fresh(), expectations(), { kind: "baseline-not-recorded" }),
    ).rejects.toThrow(/hand-written/);
  });

  it("wrapper-supplied model/thread override the model's self-report (WRDF-0002)", async () => {
    const rec = await buildRunRecord(fresh(), expectations(), {
      kind: "task-diff",
      model: "gpt-5.6-sol@max",
      thread: "wrapper-round-1",
    });
    expect(rec.reviewer_model).toBe("gpt-5.6-sol@max");
    expect(rec.thread).toBe("wrapper-round-1");
    expect(rec.artefact_sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("append-review-run.mjs CLI", () => {
  const tmp = mkdtempSync(join(tmpdir(), "warden-review-runs-"));
  const runsFile = join(tmp, "runs.jsonl");

  it("appends exactly one line for a validated zero-finding round", () => {
    const artefact = join(tmp, "zero.json");
    writeFileSync(artefact, JSON.stringify(zeroFinding()));
    execFileSync("node", [APPENDER, artefact, "--expect", EXPECT_FILE, "--runs", runsFile, "--kind", "task-diff", "--effort", "max"]);
    const lines = readFileSync(runsFile, "utf8").split("\n").filter((l) => l.trim());
    expect(lines.length).toBe(1);
    const rec = JSON.parse(lines[0]);
    expect(rec.findings_count).toBe(0);
    expect(rec.artefact).toBe(artefact);
    expect(rec.recorded_by).toBe("scripts/append-review-run.mjs");
  });

  it("appends NOTHING for an artefact that fails validation, and exits non-zero", () => {
    const doc = fresh();
    doc.invariant_verdicts[0].verdict = "not_reviewed";
    const artefact = join(tmp, "invalid.json");
    writeFileSync(artefact, JSON.stringify(doc));
    const before = readFileSync(runsFile, "utf8");
    expect(() =>
      execFileSync("node", [APPENDER, artefact, "--expect", EXPECT_FILE, "--runs", runsFile], { stdio: "pipe" }),
    ).toThrow();
    expect(readFileSync(runsFile, "utf8")).toBe(before);
  });

  it("REFUSES a byte-identical replay of an already-recorded artefact (WRDF-0003)", () => {
    const artefact = join(tmp, "zero-replay.json");
    writeFileSync(artefact, JSON.stringify(zeroFinding()));
    const before = readFileSync(runsFile, "utf8");
    // The zero-finding artefact was already recorded by the first CLI test above.
    expect(() =>
      execFileSync("node", [APPENDER, artefact, "--expect", EXPECT_FILE, "--runs", runsFile], { stdio: "pipe" }),
    ).toThrow();
    expect(readFileSync(runsFile, "utf8")).toBe(before);
  });

  it("--dry-run prints the record without appending", () => {
    const artefact = join(tmp, "zero2.json");
    writeFileSync(artefact, JSON.stringify(zeroFinding()));
    const before = readFileSync(runsFile, "utf8");
    const out = execFileSync("node", [APPENDER, artefact, "--expect", EXPECT_FILE, "--runs", runsFile, "--dry-run"]);
    expect(JSON.parse(out.toString()).findings_count).toBe(0);
    expect(readFileSync(runsFile, "utf8")).toBe(before);
  });

  it("the committed baseline exists and is loadable by the same contract this suite enforces", () => {
    expect(existsSync(RUNS)).toBe(true);
    expect(runs.some((r) => r.kind === "baseline-not-recorded")).toBe(true);
  });
});
