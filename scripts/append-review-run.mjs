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
import { readFileSync, appendFileSync, existsSync } from "node:fs";
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

  return {
    date: new Date().toISOString().slice(0, 10),
    kind,
    base_sha: doc.base_sha,
    head_sha: doc.head_sha,
    thread: doc.thread,
    reviewer_model: doc.reviewer_model,
    effort,
    seeded_count: doc.seeded_invariants.length,
    findings_count: doc.findings.length,
    artefact,
    recorded_by: "scripts/append-review-run.mjs",
  };
}

async function main(argv) {
  const args = argv.slice(2);
  let findingsPath = null;
  let expectPath = null;
  let runsPath = DEFAULT_RUNS;
  let kind = "task-diff";
  let effort = null;
  let dryRun = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--expect") expectPath = args[++i];
    else if (a === "--runs") runsPath = args[++i];
    else if (a === "--kind") kind = args[++i];
    else if (a === "--effort") effort = args[++i];
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
  const record = await buildRunRecord(doc, expect, { kind, effort, artefact: findingsPath });
  if (dryRun) {
    console.log(JSON.stringify(record));
    return;
  }
  appendFileSync(runsPath, JSON.stringify(record) + "\n");
  console.error(`recorded 1 run (${record.findings_count} finding(s)) in ${runsPath}`);
}

if (process.argv[1] && process.argv[1].endsWith("append-review-run.mjs")) {
  main(process.argv).catch((e) => {
    console.error(`error: ${e.message}`);
    process.exit(1);
  });
}
