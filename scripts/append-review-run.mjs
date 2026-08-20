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
  // it is computed over the artefact NORMALIZED without the self-report provenance fields, so a
  // copied artefact cannot buy a fresh digest by mutating a field nothing else trusts anyway.
  const { thread: _t, reviewer_model: _m, ...substance } = doc;
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
    artefact_sha256: createHash("sha256").update(JSON.stringify(substance)).digest("hex"),
    recorded_by: "scripts/append-review-run.mjs",
  };
}

/** Scorecard lines for every finding — disputed and scoped-out included (L3). */
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
      truth_status: f.truth_status,
      evidence_type: f.evidence_type,
      invariant_ids: f.invariant_ids,
      prior_art_cited: f.prior_art_cited || [],
      ruling: f.adjudication ? f.adjudication.ruling : "pending",
      ruled_by: f.adjudication ? f.adjudication.by : null,
      rationale: f.adjudication ? f.adjudication.rationale : f.rationale,
      reproducer_verified: !!(f.reproducer && f.reproducer.verified),
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
  // BOTH ledgers are written by this one process, run record first, and rolled back together on
  // failure — a rejected or interrupted round leaves neither a run row nor orphan scorecard lines
  // (WRDF-0007). Rollback is a truncate-to-previous-content, safe because these files are only ever
  // appended to.
  const prevRuns = existsSync(runsPath) ? readFileSync(runsPath, "utf8") : "";
  const prevCard = existsSync(scorecardPath) ? readFileSync(scorecardPath, "utf8") : "";
  try {
    appendFileSync(runsPath, JSON.stringify(record) + "\n");
    const lines = buildScorecardLines(doc, record);
    if (lines.length) appendFileSync(scorecardPath, lines.join("\n") + "\n");
    console.error(`recorded 1 run (${record.findings_count} finding(s)) in ${runsPath}`);
    if (lines.length) console.error(`appended ${lines.length} finding(s) to ${scorecardPath}`);
  } catch (e) {
    writeFileSync(runsPath, prevRuns);
    writeFileSync(scorecardPath, prevCard);
    throw new Error(`cross-ledger write failed and was rolled back: ${e.message}`);
  }
}

if (process.argv[1] && process.argv[1].endsWith("append-review-run.mjs")) {
  main(process.argv).catch((e) => {
    console.error(`error: ${e.message}`);
    process.exit(1);
  });
}
