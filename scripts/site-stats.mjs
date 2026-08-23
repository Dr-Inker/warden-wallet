#!/usr/bin/env node
// scripts/site-stats.mjs — the numbers printed on wardenwallet.io's build receipt.
//
// WHY THIS EXISTS
//   The landing page states counts (invariants covered, review rounds, findings,
//   tests) as fact. Hand-typing them means the page silently drifts into claiming
//   numbers that were true once — which is exactly the over-claim class the
//   assurance lane exists to catch, just moved somewhere nobody reviews.
//   Every figure here is READ from the ledgers, never typed.
//
// USAGE
//   node scripts/site-stats.mjs                 # print the numbers as JSON
//   node scripts/site-stats.mjs --patch <file>  # rewrite that page's receipt in place
//
//   Test counts cannot be derived from a file — they are the gate's output — so
//   they are passed in explicitly and the script refuses to invent them:
//   node scripts/site-stats.mjs --patch <file> --program-tests 659 --client-tests 301
//
// The page also carries an "as of" date. A dated snapshot is honest when slightly
// stale; an undated number implies live.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const readJsonl = (p) =>
  readFileSync(join(ROOT, p), 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));

const invariants = readJsonl('docs/security/invariants.jsonl');
const runs = readJsonl('docs/security/REVIEW-RUNS.jsonl');
const findings = readJsonl('docs/security/REVIEW-SCORECARD.jsonl');

const stats = {
  invariantsTotal: invariants.length,
  invariantsCovered: invariants.filter((r) => r.status === 'test-covered').length,
  reviewRounds: runs.length,
  findings: findings.length,
  findingsCritical: findings.filter((f) => f.severity === 'critical').length,
};

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  return i === -1 ? null : args[i + 1];
};

const target = flag('--patch');
if (!target) {
  console.log(JSON.stringify(stats, null, 2));
  process.exit(0);
}

const programTests = flag('--program-tests');
const clientTests = flag('--client-tests');
if (!programTests || !clientTests) {
  console.error(
    'refusing to patch: --program-tests and --client-tests are required.\n' +
      'They come from the gate (bash .claude/test-gate.sh), not from any file here.\n' +
      'Run the gate, read its real counts, and pass them in.'
  );
  process.exit(1);
}

const asOf = new Date().toLocaleDateString('en-GB', {
  day: 'numeric', month: 'short', year: 'numeric',
});

let html = readFileSync(target, 'utf8');
const before = html;

// Each replacement is anchored on the row's own label, so a structural change to
// the page fails loudly below rather than silently patching the wrong number.
const rows = [
  [/(security invariants<\/span><span class="r-dots"><\/span><span class="r-v">)[^<]*/,
    `$1${stats.invariantsCovered} / ${stats.invariantsTotal} covered`],
  [/(adversarial review rounds<\/span><span class="r-dots"><\/span><span class="r-v">)[^<]*/,
    `$1${stats.reviewRounds}`],
  [/(findings logged<\/span><span class="r-dots"><\/span><span class="r-v">)[^<]*/,
    `$1${stats.findings}`],
  [/(of those, critical<\/span><span class="r-dots"><\/span><span class="r-v">)[^<]*/,
    `$1${stats.findingsCritical}`],
  [/(program tests<\/span><span class="r-dots"><\/span><span class="r-v">)[^<]*/,
    `$1${programTests} passing`],
  [/(client tests<\/span><span class="r-dots"><\/span><span class="r-v">)[^<]*/,
    `$1${clientTests} passing`],
  [/(<span class="r-asof">)[^<]*/, `$1as of ${asOf}`],
];

let patched = 0;
for (const [re, to] of rows) {
  if (!re.test(html)) {
    console.error(`refusing to patch: no row matched ${re}\n` +
      'The page structure changed — update this script rather than letting a stale number stand.');
    process.exit(1);
  }
  html = html.replace(re, to);
  patched++;
}

if (html === before) {
  console.log(`already current (${patched} rows checked)`);
} else {
  writeFileSync(target, html);
  console.log(`patched ${patched} rows in ${target}`);
}
console.log(JSON.stringify({ ...stats, programTests: +programTests, clientTests: +clientTests, asOf }, null, 2));
