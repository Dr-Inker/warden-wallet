#!/usr/bin/env node
// Appends ONE run record to docs/security/REVIEW-RUNS.jsonl after a review round completes.
//
//   node scripts/append-review-run.mjs <findings.json> --expect <expect.json>
//        [--kind task-diff|docs|milestone|whole-feature] [--effort <e>] [--runs <path>] [--dry-run]
//
// WHY THIS EXISTS (campaign plan 2026-08-20, gap G2): REVIEW-SCORECARD.jsonl records *findings*,
// so a round that returns zero findings is invisible and L3 cannot demonstrate that reviews ran
// at all. This file records *rounds*. The two are different populations on purpose:
//   - a validated round with zero findings appends exactly ONE run record and ZERO scorecard lines;
//   - a round whose artefact fails validation appends NOTHING anywhere — the absence of a run
//     record is the honest state for a round that did not complete.
//
// This script does not trust its caller to have validated the artefact: it re-runs the SAME
// independent validation review.sh uses (scripts/validate-findings.mjs against the wrapper's
// expectations file), so invoking it directly on garbage cannot log a run.
import { readFileSync, appendFileSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  validateFindings,
  loadKnownInvariantIds,
  loadKnownPriorArtIds,
  compileSchema,
} from "./validate-findings.mjs";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA = join(REPO_ROOT, ".codex/schemas/warden-findings.json");
const DEFAULT_RUNS = join(REPO_ROOT, "docs/security/REVIEW-RUNS.jsonl");
const KINDS = ["task-diff", "docs", "milestone", "whole-feature", "baseline-not-recorded"];

/**
 * Build the run record for a VALIDATED findings artefact. Throws (never appends) on any
 * validation error — the caller decides what to do with the throw; nothing is logged for it.
 */
export async function buildRunRecord(doc, expect, opts = {}) {
  const { kind = "task-diff", effort = null, artefact = null, repoRoot = REPO_ROOT } = opts;
  if (!KINDS.includes(kind)) throw new Error(`unknown kind "${kind}" (allowed: ${KINDS.join(", ")})`);
  if (kind === "baseline-not-recorded")
    throw new Error("baseline-not-recorded entries are hand-written history, never appended by this script");
  if (!expect || typeof expect !== "object")
    throw new Error("an expectations file is required — a run without wrapper expectations is unverifiable");

  const errors = validateFindings(doc, {
    validateSchema: await compileSchema(SCHEMA),
    expect,
    knownInvariants: loadKnownInvariantIds(repoRoot),
    knownPriorArt: loadKnownPriorArtIds(repoRoot),
  });
  if (errors.length) {
    throw new Error(
      `refusing to record a run for an artefact that fails validation (${errors.length} error(s)):\n  ` +
        errors.join("\n  "),
    );
  }

  // Provenance is WRAPPER-authoritative where the wrapper supplies it (WRDF-0002): the caller
  // invoked the model, so its record wins over the model's self-report. The artefact digest gives
  // the run an immutable identity independent of the mutable, gitignored artefact path (WRDF-0003);
  // it is computed over a CANONICAL form — keys sorted recursively, the untrusted self-report
  // provenance fields (thread / reviewer_model, at every level) removed — so neither key order nor
  // a semantically ignored field can buy a copied artefact a fresh digest.
  return {
    date: new Date().toISOString().slice(0, 10),
    kind,
    base_sha: doc.base_sha,
    head_sha: doc.head_sha,
    thread: opts.thread ?? doc.thread,
    reviewer_model: opts.model ?? doc.reviewer_model,
    effort,
    seeded_count: new Set(doc.seeded_invariants).size,
    findings_count: doc.findings.length,
    artefact,
    artefact_sha256: createHash("sha256").update(canonicalJson(doc)).digest("hex"),
    recorded_by: "scripts/append-review-run.mjs",
  };
}

/** Deterministic serialization for hashing: sorted keys, self-report provenance stripped. */
export function canonicalJson(node) {
  if (Array.isArray(node)) return `[${node.map(canonicalJson).join(",")}]`;
  if (node && typeof node === "object") {
    const keys = Object.keys(node)
      .filter((k) => k !== "thread" && k !== "reviewer_model")
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(node[k])}`).join(",")}}`;
  }
  return JSON.stringify(node);
}

/**
 * Scorecard lines for every finding — disputed and scoped-out included (L3).
 *
 * NOTHING adjudicative is copied from the artefact (WRDF-0009): the model's `adjudication`
 * object, a self-claimed CONFIRMED, and a self-claimed verified reproducer are all untrusted model
 * output. Every finding ENTERS the scorecard as pending/POTENTIAL, with the model's claims kept
 * under claimed_* fields; only a human editing the committed scorecard (or evidence) promotes.
 */
export function buildScorecardLines(doc, record) {
  return doc.findings.map((f) =>
    JSON.stringify({
      finding_id: f.id,
      thread: record.thread,
      date: record.date,
      reviewer_model: record.reviewer_model,
      base_sha: doc.base_sha,
      head_sha: doc.head_sha,
      severity: f.severity,
      truth_status: "POTENTIAL",
      claimed_truth_status: f.truth_status,
      evidence_type: f.evidence_type,
      invariant_ids: f.invariant_ids,
      prior_art_cited: f.prior_art_cited || [],
      ruling: "pending",
      ruled_by: null,
      rationale: f.rationale,
      claimed_reproducer_verified: !!(f.reproducer && f.reproducer.verified),
    }),
  );
}

async function main(argv) {
  const args = argv.slice(2);
  let findingsPath = null;
  let expectPath = null;
  let runsPath = DEFAULT_RUNS;
  let scorecardPath = join(REPO_ROOT, "docs/security/REVIEW-SCORECARD.jsonl");
  let kind = "task-diff";
  let effort = null;
  let model = null;
  let thread = null;
  let dryRun = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--expect") expectPath = args[++i];
    else if (a === "--runs") runsPath = args[++i];
    else if (a === "--scorecard") scorecardPath = args[++i];
    else if (a === "--kind") kind = args[++i];
    else if (a === "--effort") effort = args[++i];
    else if (a === "--model") model = args[++i];
    else if (a === "--thread") thread = args[++i];
    else if (a === "--dry-run") dryRun = true;
    else if (a.startsWith("-")) throw new Error(`unknown option ${a}`);
    else findingsPath = a;
  }
  if (!findingsPath || !expectPath) {
    console.error("usage: append-review-run.mjs <findings.json> --expect <expect.json> [--kind k] [--effort e] [--runs p] [--dry-run]");
    process.exit(2);
  }
  if (!existsSync(findingsPath)) throw new Error(`no such file: ${findingsPath}`);
  const doc = JSON.parse(readFileSync(findingsPath, "utf8"));
  const expect = JSON.parse(readFileSync(expectPath, "utf8"));
  const record = await buildRunRecord(doc, expect, { kind, effort, model, thread, artefact: findingsPath });
  if (dryRun) {
    console.log(JSON.stringify(record));
    return;
  }
  // A substantively identical artefact is a REPLAY, not a second round — refuse it (WRDF-0003).
  if (existsSync(runsPath)) {
    const dup = readFileSync(runsPath, "utf8").split("\n").filter((l) => l.trim())
      .map((l) => JSON.parse(l))
      .find((r) => r.artefact_sha256 && r.artefact_sha256 === record.artefact_sha256);
    if (dup) throw new Error(`refusing replay: an identical artefact (sha256 ${record.artefact_sha256.slice(0, 12)}…) is already recorded as thread ${dup.thread}`);
  }
  // Cross-ledger consistency preflight (WRDF-0007 residual): a hard kill between the two appends
  // below cannot be prevented without a journal, but it CAN be detected — the last run row would
  // claim findings the scorecard does not carry. Refuse to extend an inconsistent pair; both files
  // are git-tracked, so the repair is a visible edit, not a silent overwrite.
  const readOr = (p) => { try { return existsSync(p) ? readFileSync(p, "utf8") : ""; } catch { return ""; } };
  const prevRuns = readOr(runsPath);
  const prevCard = readOr(scorecardPath);
  const lastRun = prevRuns.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l)).pop();
  if (lastRun && lastRun.artefact !== "not-recorded" && lastRun.findings_count > 0) {
    const carried = prevCard.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l))
      .filter((r) => r.thread === lastRun.thread).length;
    if (carried === 0)
      throw new Error(
        `inconsistent ledgers: last run (thread ${lastRun.thread}) claims ${lastRun.findings_count} finding(s) but the scorecard carries none — a previous round was interrupted mid-write; repair the committed files before recording new rounds`,
      );
  }
  // BOTH ledgers are written by this one process, run record first, and rolled back together on a
  // synchronous failure. Rollback is a truncate-to-previous-content, safe because these files are
  // only ever appended to.
  try {
    appendFileSync(runsPath, JSON.stringify(record) + "\n");
    const lines = buildScorecardLines(doc, record);
    if (lines.length) appendFileSync(scorecardPath, lines.join("\n") + "\n");
    console.error(`recorded 1 run (${record.findings_count} finding(s)) in ${runsPath}`);
    if (lines.length) console.error(`appended ${lines.length} finding(s) to ${scorecardPath}`);
  } catch (e) {
    try { writeFileSync(runsPath, prevRuns); } catch { /* restore is best-effort per file */ }
    try { writeFileSync(scorecardPath, prevCard); } catch { /* a dir/unwritable target was never modified */ }
    throw new Error(`cross-ledger write failed and was rolled back: ${e.message}`);
  }
}

if (process.argv[1] && process.argv[1].endsWith("append-review-run.mjs")) {
  main(process.argv).catch((e) => {
    console.error(`error: ${e.message}`);
    process.exit(1);
  });
}
