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
import { buildRunRecord, buildScorecardLines } from "../../../scripts/append-review-run.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const RUNS = join(REPO, "docs/security/REVIEW-RUNS.jsonl");
const SCORECARD = join(REPO, "docs/security/REVIEW-SCORECARD.jsonl");
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

describe("buildScorecardLines reproducer persistence (WRDF-0015)", () => {
  const record = { thread: "t", date: "2026-08-21", reviewer_model: "m" };

  it("persists a verified reproducer's full coordinates under claimed_reproducer", () => {
    const reproducer = { base_sha: "a".repeat(40), fixed_sha: "b".repeat(40), test_path: "programs/warden/tests/x.rs", test_name: "repro", verified: true };
    const doc = { base_sha: "a".repeat(40), head_sha: "b".repeat(40), findings: [{ id: "WRDF-9001", severity: "important", truth_status: "CONFIRMED", evidence_type: "red_test", invariant_ids: [], reproducer, rationale: "x" }] };
    const [line] = buildScorecardLines(doc, record).map((l: string) => JSON.parse(l));
    expect(line.claimed_reproducer_verified).toBe(true);
    expect(line.claimed_reproducer).toEqual(reproducer); // every coordinate preserved
    expect(line.claimed_reproducer.base_sha).not.toBe(line.claimed_reproducer.fixed_sha);
  });

  it("carries a null claimed_reproducer (and false verified) for an infeasible-reproducer finding", () => {
    const doc = { base_sha: "a".repeat(40), head_sha: "b".repeat(40), findings: [{ id: "WRDF-9002", severity: "minor", truth_status: "POTENTIAL", evidence_type: "static_trace", invariant_ids: [], reproducer: null, reproducer_infeasible_reason: "static-trace client finding", rationale: "x" }] };
    const [line] = buildScorecardLines(doc, record).map((l: string) => JSON.parse(l));
    expect(line.claimed_reproducer).toBeNull();
    expect(line.claimed_reproducer_verified).toBe(false);
  });
});

describe("append-review-run.mjs CLI", () => {
  const tmp = mkdtempSync(join(tmpdir(), "warden-review-runs-"));
  const runsFile = join(tmp, "runs.jsonl");
  const cardFile = join(tmp, "scorecard.jsonl");
  const cli = (artefact: string, ...extra: string[]) =>
    execFileSync(
      "node",
      [APPENDER, artefact, "--expect", EXPECT_FILE, "--runs", runsFile, "--scorecard", cardFile, ...extra],
      { stdio: "pipe" },
    );

  it("appends exactly one run line and ZERO scorecard lines for a validated zero-finding round", () => {
    const artefact = join(tmp, "zero.json");
    writeFileSync(artefact, JSON.stringify(zeroFinding()));
    cli(artefact, "--kind", "task-diff", "--effort", "max");
    const lines = readFileSync(runsFile, "utf8").split("\n").filter((l) => l.trim());
    expect(lines.length).toBe(1);
    const rec = JSON.parse(lines[0]);
    expect(rec.findings_count).toBe(0);
    expect(rec.artefact).toBe(artefact);
    expect(rec.recorded_by).toBe("scripts/append-review-run.mjs");
    expect(existsSync(cardFile)).toBe(false);
  });

  it("appends one run line AND one scorecard line per finding, atomically (WRDF-0007)", () => {
    const doc = fresh();
    const artefact = join(tmp, "with-findings.json");
    writeFileSync(artefact, JSON.stringify(doc));
    cli(artefact, "--model", "gpt-5.6-sol@max", "--thread", "round-x");
    const runs2 = readFileSync(runsFile, "utf8").split("\n").filter((l) => l.trim());
    expect(runs2.length).toBe(2);
    const card = readFileSync(cardFile, "utf8").split("\n").filter((l) => l.trim());
    expect(card.length).toBe(doc.findings.length);
    for (const l of card) {
      const row = JSON.parse(l);
      expect(row.thread).toBe("round-x");
      expect(row.reviewer_model).toBe("gpt-5.6-sol@max");
    }
  });

  it("never copies model adjudication or self-claimed truth into the scorecard (WRDF-0009)", () => {
    // The worked example deliberately carries an adjudication object and a CONFIRMED finding —
    // both are untrusted model output and must enter as pending/POTENTIAL claims.
    const doc = fresh();
    expect(doc.findings.some((f: { adjudication?: unknown }) => f.adjudication)).toBe(true);
    expect(doc.findings.some((f: { truth_status: string }) => f.truth_status === "CONFIRMED")).toBe(true);
    const card = readFileSync(cardFile, "utf8").split("\n").filter((l) => l.trim()).map((l: string) => JSON.parse(l));
    for (const row of card) {
      expect(row.ruling).toBe("pending");
      expect(row.ruled_by).toBeNull();
      expect(row.truth_status).toBe("POTENTIAL");
    }
    expect(card.some((r) => r.claimed_truth_status === "CONFIRMED")).toBe(true);
  });

  it("appends NOTHING to either ledger for an artefact that fails validation", () => {
    const doc = fresh();
    doc.invariant_verdicts[0].verdict = "not_reviewed";
    const artefact = join(tmp, "invalid.json");
    writeFileSync(artefact, JSON.stringify(doc));
    const beforeRuns = readFileSync(runsFile, "utf8");
    const beforeCard = readFileSync(cardFile, "utf8");
    expect(() => cli(artefact)).toThrow();
    expect(readFileSync(runsFile, "utf8")).toBe(beforeRuns);
    expect(readFileSync(cardFile, "utf8")).toBe(beforeCard);
  });

  it("REFUSES a replay of an already-recorded artefact — mutated self-report fields and reordered keys included (WRDF-0003)", () => {
    const doc = zeroFinding();
    doc.thread = "totally-different-self-report";
    // Order must not matter either: reverse both object-key insertion order and the
    // set-semantics seeded_invariants array; a mutated (boundary-ignored) adjudication on a
    // verdict must not matter both ways.
    doc.seeded_invariants = [...doc.seeded_invariants].reverse();
    const reordered = Object.fromEntries(Object.entries(doc).reverse());
    const artefact = join(tmp, "zero-replay.json");
    writeFileSync(artefact, JSON.stringify(reordered));
    const before = readFileSync(runsFile, "utf8");
    // The zero-finding artefact's SUBSTANCE was already recorded by the first CLI test above;
    // neither the self-reported thread, nor property order, nor seed order buys a fresh digest.
    expect(() => cli(artefact)).toThrow();
    expect(readFileSync(runsFile, "utf8")).toBe(before);
  });

  it("rolls the run record back when the scorecard write fails mid-round (WRDF-0007)", () => {
    // A fresh, empty runs file: the preflight passes, the run record lands, and THEN the
    // scorecard append fails (its parent directory does not exist) — the rollback must leave the
    // runs file exactly as it was.
    const doc = fresh();
    const artefact = join(tmp, "rollback.json");
    writeFileSync(artefact, JSON.stringify(doc));
    const runsFile2 = join(tmp, "runs-rollback.jsonl");
    const missingCard = join(tmp, "no-such-dir", "scorecard.jsonl");
    expect(() =>
      execFileSync(
        "node",
        [APPENDER, artefact, "--expect", EXPECT_FILE, "--runs", runsFile2, "--scorecard", missingCard],
        { stdio: "pipe" },
      ),
    ).toThrow();
    expect(existsSync(runsFile2) ? readFileSync(runsFile2, "utf8") : "").toBe("");
  });

  it("REFUSES to extend an inconsistent ledger pair — a run claiming findings the scorecard lacks (WRDF-0007)", () => {
    const orphanRuns = join(tmp, "runs-orphan.jsonl");
    writeFileSync(
      orphanRuns,
      JSON.stringify({ date: "2026-08-20", kind: "task-diff", base_sha: "a".repeat(40), head_sha: "b".repeat(40), thread: "orphan-round", reviewer_model: "x", effort: null, seeded_count: 1, findings_count: 3, artefact: "gone.json", artefact_sha256: "c".repeat(64), recorded_by: "test" }) + "\n",
    );
    // A PARTIAL scorecard (1 of the 3 claimed findings survived a torn write) must also refuse —
    // the contract is one row per finding, not merely non-emptiness.
    const emptyCard = join(tmp, "card-orphan.jsonl");
    writeFileSync(emptyCard, JSON.stringify({ finding_id: "WRDF-9001", thread: "orphan-round" }) + "\n");
    const doc = zeroFinding();
    doc.invariant_verdicts[0].rationale += " (orphan variant)"; // fresh digest
    const artefact = join(tmp, "orphan-next.json");
    writeFileSync(artefact, JSON.stringify(doc));
    expect(() =>
      execFileSync(
        "node",
        [APPENDER, artefact, "--expect", EXPECT_FILE, "--runs", orphanRuns, "--scorecard", emptyCard],
        { stdio: "pipe" },
      ),
    ).toThrow(/inconsistent ledgers/);
  });

  it("--dry-run prints the record without appending", () => {
    const artefact = join(tmp, "zero2.json");
    writeFileSync(artefact, JSON.stringify(zeroFinding()));
    const before = readFileSync(runsFile, "utf8");
    const out = execFileSync("node", [APPENDER, artefact, "--expect", EXPECT_FILE, "--runs", runsFile, "--scorecard", cardFile, "--dry-run"]);
    expect(JSON.parse(out.toString()).findings_count).toBe(0);
    expect(readFileSync(runsFile, "utf8")).toBe(before);
  });

  it("the committed baseline exists and is loadable by the same contract this suite enforces", () => {
    expect(existsSync(RUNS)).toBe(true);
    expect(runs.some((r) => r.kind === "baseline-not-recorded")).toBe(true);
  });
});

// WRDF-0015 / 0083 / 0084: two SEPARATE provenance axes on a scorecard row, each
// validated so neither can be asserted without its evidence.
//   * claimed_reproducer_verified: a red/green REPRODUCER was run. True ONLY when
//     the row carries the reproducer object (claimed_reproducer) with distinct
//     base/fixed SHAs and verified=true. The appender persists it (WRDF-0015).
//   * remediation_verified: a static-trace finding whose fix the GATE confirmed.
//     True ONLY with a real fixing SHA, a real gate SHA that CONTAINS the fix (fix
//     is ancestor-or-equal of gate) and is reachable from the reviewed HEAD, and a
//     non-blank gate command (WRDF-0083). Mutually exclusive with a reproducer claim.
const SHA_RE = /^[0-9a-f]{7,40}$/;

// Injected git predicates so the pure validator is unit-testable, and so the live
// check can skip objects genuinely absent in a shallow clone (WRDF-0084) while
// staying fail-closed in a full clone. null = skip git-dependent checks.
interface GitProbe {
  commitExists(sha: string): boolean;
  isAncestorOrEqual(a: string, b: string): boolean; // a is ancestor of, or equal to, b
  head: string;
  shallow: boolean; // a well-formed SHA absent from a FULL clone is a fabricated/mistyped SHA (fail-closed); absent from a shallow clone is unverifiable (skip). (WRDF-0083)
}

// Validate ONE scorecard row's provenance. Returns violation strings (empty = ok).
export function validateScorecardProvenance(r: Record<string, unknown>, git: GitProbe | null): string[] {
  const id = String(r.finding_id ?? "?");
  const errs: string[] = [];
  if (r.claimed_reproducer_verified === true) {
    const rep = r.claimed_reproducer as { base_sha?: string; fixed_sha?: string; verified?: boolean } | null | undefined;
    if (!rep) errs.push(`${id}: claimed_reproducer_verified=true but no claimed_reproducer object`);
    else {
      if (rep.verified !== true) errs.push(`${id}: reproducer not verified`);
      if (!SHA_RE.test(rep.base_sha ?? "")) errs.push(`${id}: reproducer base_sha malformed`);
      if (!SHA_RE.test(rep.fixed_sha ?? "")) errs.push(`${id}: reproducer fixed_sha malformed`);
      if (rep.base_sha === rep.fixed_sha) errs.push(`${id}: reproducer base_sha equals fixed_sha`);
    }
  }
  if (r.remediation_verified === true) {
    if (r.claimed_reproducer_verified === true) errs.push(`${id}: a remediation row must not also claim a reproducer`);
    const fix = r.remediation_sha as string | null;
    const gate = r.remediation_gate_sha as string | null;
    const cmd = r.remediation_gate_cmd;
    if (!SHA_RE.test(fix ?? "")) errs.push(`${id}: remediation_sha malformed or null`);
    if (!SHA_RE.test(gate ?? "")) errs.push(`${id}: remediation_gate_sha malformed or null`);
    if (typeof cmd !== "string" || cmd.trim().length === 0) errs.push(`${id}: remediation_gate_cmd blank`);
    if (git && SHA_RE.test(fix ?? "") && SHA_RE.test(gate ?? "")) {
      const fixHere = git.commitExists(fix!);
      const gateHere = git.commitExists(gate!);
      // A well-formed SHA the FULL clone does not have is fabricated or mistyped
      // — fail-closed. Only a genuinely shallow clone may skip an absent object.
      if (!fixHere && !git.shallow) errs.push(`${id}: remediation_sha ${fix} is not a commit in this full clone`);
      if (!gateHere && !git.shallow) errs.push(`${id}: remediation_gate_sha ${gate} is not a commit in this full clone`);
      if (fixHere && gateHere) {
        if (!git.isAncestorOrEqual(fix!, gate!)) errs.push(`${id}: gate ${gate} does not contain fix ${fix}`);
        if (!git.isAncestorOrEqual(gate!, git.head)) errs.push(`${id}: gate ${gate} is not reachable from reviewed HEAD`);
      }
    }
  }
  return errs;
}

// The allowed axes (from .codex/schemas/warden-findings.json), pinned here so the standing
// validator rejects an out-of-enum value rather than merely type-checking it (WRDF-0101).
const TRUTH_STATUSES = new Set(["POTENTIAL", "CONFIRMED", "REFUTED"]);
const EVIDENCE_TYPES = new Set(["red_test", "static_trace", "formal_counterexample", "config_attestation", "primary_source", "none"]);

/**
 * Validate ONE scorecard row's STANDING (truth_status / ruling / adjudication metadata), a
 * separate axis from provenance. Returns violation strings (empty = ok). A CONFIRMED standing
 * is a human promotion, so it must carry the adjudication metadata and real evidence the
 * ledger contract requires; claimed_truth_status must remain a valid entry-time enum value,
 * never an arbitrary/tampered string (WRDF-0100/0101).
 */
export function validateScorecardStanding(r: Record<string, unknown>): string[] {
  const id = String(r.finding_id ?? "?");
  const errs: string[] = [];
  const ts = r.truth_status, cts = r.claimed_truth_status;
  if (ts !== undefined && !TRUTH_STATUSES.has(ts as string)) errs.push(`${id}: truth_status ${JSON.stringify(ts)} is not a valid standing`);
  if (cts !== undefined && cts !== null && !TRUTH_STATUSES.has(cts as string)) errs.push(`${id}: claimed_truth_status ${JSON.stringify(cts)} is not a valid entry-time standing`);
  if (r.remediation_verified === true) {
    if (ts !== "CONFIRMED") errs.push(`${id}: remediation_verified but truth_status=${JSON.stringify(ts)} (a verified remediation promotes to CONFIRMED)`);
    if (r.ruling !== "adopted") errs.push(`${id}: remediation_verified but ruling=${JSON.stringify(r.ruling)} (must be adopted)`);
    if (typeof cts !== "string" || !TRUTH_STATUSES.has(cts)) errs.push(`${id}: remediation_verified but claimed_truth_status not a preserved enum value`);
  }
  if (ts === "CONFIRMED") {
    if (r.ruling !== "adopted") errs.push(`${id}: CONFIRMED but ruling=${JSON.stringify(r.ruling)} — the promotion authority is a human adjudication`);
    if (typeof r.ruled_by !== "string" || (r.ruled_by as string).length === 0) errs.push(`${id}: CONFIRMED but no ruled_by adjudicator`);
    if (!EVIDENCE_TYPES.has(r.evidence_type as string) || r.evidence_type === "none") {
      errs.push(`${id}: CONFIRMED but evidence_type=${JSON.stringify(r.evidence_type)} (a confirmed standing needs a real, non-none evidence type)`);
    }
  }
  if (ts === "REFUTED" && r.remediation_verified === true) errs.push(`${id}: REFUTED yet remediation_verified (nothing to remediate)`);
  return errs;
}

describe("scorecard provenance (docs/security/REVIEW-SCORECARD.jsonl)", () => {
  const cardRows = readFileSync(SCORECARD, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l: string) => JSON.parse(l) as Record<string, unknown>);

  // Shallow-aware git probe, mirroring security-ledger.test.ts: in a shallow clone
  // absent objects are skipped; in a full clone (CI sets fetch-depth: 0) the checks
  // are load-bearing and fail-closed.
  const probe: GitProbe | null = (() => {
    const git = (args: string[]): string | null => {
      try { return execFileSync("git", ["-C", REPO, ...args], { stdio: "pipe" }).toString().trim(); }
      catch { return null; }
    };
    if (git(["rev-parse", "--is-inside-work-tree"]) !== "true") return null;
    const head = git(["rev-parse", "HEAD"]);
    if (!head) return null;
    // Older git lacking the flag → treat as full (fail-closed on missing objects).
    const shallow = git(["rev-parse", "--is-shallow-repository"]) === "true";
    return {
      head,
      shallow,
      commitExists: (sha: string) => {
        try { execFileSync("git", ["-C", REPO, "cat-file", "-e", `${sha}^{commit}`], { stdio: "pipe" }); return true; }
        catch { return false; }
      },
      isAncestorOrEqual: (a: string, b: string) => {
        try { execFileSync("git", ["-C", REPO, "merge-base", "--is-ancestor", a, b], { stdio: "pipe" }); return true; }
        catch { return false; }
      },
    };
  })();

  it("every committed row satisfies both provenance axes", () => {
    const all = cardRows.flatMap((r) => validateScorecardProvenance(r, probe));
    expect(all, all.join("\n")).toEqual([]);
  }, 30_000);

  it("every committed row has an internally-consistent standing (WRDF-0100/0101)", () => {
    const bad = cardRows.flatMap((r) => validateScorecardStanding(r));
    expect(bad, bad.join("\n")).toEqual([]);
  });

  const stub = (opts: { exists?: (s: string) => boolean; anc?: (a: string, b: string) => boolean; head?: string; shallow?: boolean }): GitProbe => ({
    head: opts.head ?? "h".repeat(40),
    commitExists: opts.exists ?? (() => true),
    isAncestorOrEqual: opts.anc ?? (() => true),
    shallow: opts.shallow ?? false,
  });
  const fixS = "a".repeat(40), gateS = "b".repeat(40);
  const row = (over: Record<string, unknown>) => ({ finding_id: "WRDF-TEST", remediation_verified: true, remediation_sha: fixS, remediation_gate_sha: gateS, remediation_gate_cmd: "cmd", ...over });

  it("rejects a gate that does not contain the fix", () => {
    expect(validateScorecardProvenance(row({}), stub({ anc: (a, b) => !(a === fixS && b === gateS) })).join()).toMatch(/does not contain fix/);
  });
  it("rejects a gate unreachable from HEAD", () => {
    expect(validateScorecardProvenance(row({}), stub({ anc: (a) => a === fixS })).join()).toMatch(/not reachable from reviewed HEAD/);
  });
  it("rejects a whitespace-only gate command", () => {
    expect(validateScorecardProvenance(row({ remediation_gate_cmd: "   " }), null).join()).toMatch(/gate_cmd blank/);
  });
  it("rejects a null remediation SHA", () => {
    expect(validateScorecardProvenance(row({ remediation_sha: null }), null).join()).toMatch(/remediation_sha malformed/);
  });
  it("rejects a row claiming both a reproducer and a remediation", () => {
    expect(validateScorecardProvenance(row({ claimed_reproducer_verified: true, claimed_reproducer: { base_sha: fixS, fixed_sha: gateS, verified: true } }), null).join()).toMatch(/must not also claim a reproducer/);
  });
  it("rejects a fabricated fix commit absent from a FULL clone", () => {
    const errs = validateScorecardProvenance(row({}), stub({ exists: (s) => s !== fixS, shallow: false }));
    expect(errs.join()).toMatch(/remediation_sha .* is not a commit in this full clone/);
  });
  it("rejects a fabricated gate commit absent from a FULL clone", () => {
    const errs = validateScorecardProvenance(row({}), stub({ exists: (s) => s !== gateS, shallow: false }));
    expect(errs.join()).toMatch(/remediation_gate_sha .* is not a commit in this full clone/);
  });
  it("SKIPS an absent object only in a genuinely shallow clone", () => {
    const errs = validateScorecardProvenance(row({}), stub({ exists: () => false, shallow: true }));
    expect(errs).toEqual([]); // unverifiable in shallow → no false failure, no false pass on ancestry
  });
  it("accepts a well-formed remediation row", () => {
    expect(validateScorecardProvenance(row({}), stub({}))).toEqual([]);
  });
});

describe("scorecard STANDING validator (WRDF-0100/0101) — adversarial mutations", () => {
  // A well-formed CONFIRMED + verified-remediation row (the standing the ledger promotes to).
  const good = (): Record<string, unknown> => ({
    finding_id: "WRDF-STAND",
    truth_status: "CONFIRMED",
    claimed_truth_status: "POTENTIAL",
    ruling: "adopted",
    ruled_by: "claude-fable-5",
    evidence_type: "static_trace",
    remediation_verified: true,
  });

  it("accepts a well-formed CONFIRMED / verified-remediation row", () => {
    expect(validateScorecardStanding(good())).toEqual([]);
  });

  // The three tampers WRDF-0101 showed the type-only check missed.
  it("REJECTS a tampered claimed_truth_status (not a valid entry-time enum)", () => {
    expect(validateScorecardStanding({ ...good(), claimed_truth_status: "tampered" }).join()).toMatch(/claimed_truth_status/);
  });
  it("REJECTS a CONFIRMED row that lost its adjudicator (ruled_by=null)", () => {
    expect(validateScorecardStanding({ ...good(), ruled_by: null }).join()).toMatch(/no ruled_by adjudicator/);
  });
  it("REJECTS a CONFIRMED row with evidence_type none", () => {
    expect(validateScorecardStanding({ ...good(), evidence_type: "none" }).join()).toMatch(/evidence_type/);
  });
  it("REJECTS a verified remediation left at POTENTIAL", () => {
    expect(validateScorecardStanding({ ...good(), truth_status: "POTENTIAL" }).join()).toMatch(/promotes to CONFIRMED/);
  });
  it("REJECTS a CONFIRMED row that is not adopted", () => {
    expect(validateScorecardStanding({ ...good(), ruling: "disputed" }).join()).toMatch(/promotion authority/);
  });
  it("REJECTS a REFUTED row carrying a remediation", () => {
    expect(validateScorecardStanding({ ...good(), truth_status: "REFUTED" }).join()).toMatch(/REFUTED/);
  });
  it("REJECTS an out-of-enum truth_status", () => {
    expect(validateScorecardStanding({ ...good(), truth_status: "MAYBE" }).join()).toMatch(/not a valid standing/);
  });
});
