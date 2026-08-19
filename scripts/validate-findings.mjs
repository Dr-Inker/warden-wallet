#!/usr/bin/env node
// Independent schema validation of a Codex findings JSON.
//
//   node scripts/validate-findings.mjs <findings.json> [schema.json]
//
// "Independent" is the whole point: `codex exec review --output-schema` constrains the model's FINAL
// RESPONSE, not every JSONL event on the way there, so a pipeline that trusts the flag (or greps
// intermediate events) will mis-parse. Validate the artefact, always.
//
// Beyond schema validation this enforces two rules the schema cannot express on its own:
//   - every seeded invariant has a verdict, and no verdict is `not_reviewed`
//     (silence on a seeded invariant is a FAIL, not a pass);
//   - every invariant id and prior-art id referenced actually exists in the ledger / corpus.
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { createRequire } from "node:module";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(join(ROOT, "packages/core/package.json"));

const [, , findingsArg, schemaArg] = process.argv;
if (!findingsArg) {
  console.error("usage: node scripts/validate-findings.mjs <findings.json> [schema.json]");
  process.exit(2);
}
const findingsPath = resolve(findingsArg);
const schemaPath = resolve(schemaArg ?? join(ROOT, ".codex/schemas/warden-findings.json"));

const fail = (msg) => {
  console.error(`FAIL: ${msg}`);
  process.exitCode = 1;
};

const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
const doc = JSON.parse(readFileSync(findingsPath, "utf8"));

const Ajv = require("ajv/dist/2020.js").default ?? require("ajv/dist/2020.js");
const ajv = new Ajv({ allErrors: true, strict: false, validateFormats: false });
const validate = ajv.compile(schema);
if (!validate(doc)) {
  for (const e of validate.errors ?? []) fail(`${e.instancePath || "/"} ${e.message}`);
  console.error(`\n${findingsPath} does not validate against ${schemaPath}`);
  process.exit(1);
}

// --- cross-artefact checks -------------------------------------------------
const ledgerPath = join(ROOT, "docs/security/invariants.jsonl");
const knownInvariants = new Set(
  existsSync(ledgerPath)
    ? readFileSync(ledgerPath, "utf8")
        .split("\n")
        .filter((l) => l.trim())
        .map((l) => JSON.parse(l).id)
    : [],
);
const priorArtPath = join(ROOT, "docs/security/PRIOR-ART-FINDINGS.md");
const knownPriorArt = new Set(
  existsSync(priorArtPath)
    ? [...readFileSync(priorArtPath, "utf8").matchAll(/^\| `([A-Z0-9-]+)` \|/gm)].map((m) => m[1])
    : [],
);

const verdicts = new Map(doc.invariant_verdicts.map((v) => [v.invariant_id, v.verdict]));
for (const id of doc.seeded_invariants) {
  if (!verdicts.has(id)) fail(`seeded invariant ${id} has no verdict — silence is a FAIL, not a pass`);
  else if (verdicts.get(id) === "not_reviewed") fail(`seeded invariant ${id} came back not_reviewed`);
  if (knownInvariants.size && !knownInvariants.has(id)) fail(`seeded invariant ${id} is not in invariants.jsonl`);
}
for (const f of doc.findings) {
  for (const id of f.invariant_ids)
    if (knownInvariants.size && !knownInvariants.has(id)) fail(`${f.id}: unknown invariant ${id}`);
  for (const id of f.prior_art_cited ?? [])
    if (knownPriorArt.size && !knownPriorArt.has(id)) fail(`${f.id}: unknown prior-art id ${id}`);
  if (f.reproducer && f.reproducer.base_sha === f.reproducer.fixed_sha)
    fail(`${f.id}: reproducer base_sha == fixed_sha — it must FAIL on base and PASS on fixed`);
}

if (process.exitCode) {
  console.error("\nvalidation FAILED");
  process.exit(1);
}
const counts = doc.findings.reduce((a, f) => ((a[f.severity] = (a[f.severity] ?? 0) + 1), a), {});
console.log(`OK  ${findingsPath}`);
console.log(`    thread=${doc.thread} model=${doc.reviewer_model ?? "?"} base=${doc.base_sha}`);
console.log(`    seeded=${doc.seeded_invariants.length} findings=${doc.findings.length} ${JSON.stringify(counts)}`);
for (const f of doc.findings)
  console.log(`    [${f.severity}/${f.truth_status}/${f.evidence_type}] ${f.id} ${f.title} (${f.file}:${f.line})`);
