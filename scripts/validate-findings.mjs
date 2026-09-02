#!/usr/bin/env node
// Independent validation of a Codex findings JSON.
//
//   node scripts/validate-findings.mjs <findings.json> [--schema <f>] [--expect <f>] [--repo-root <dir>]
//
// "Independent" is the point. `codex exec --output-schema` constrains the model's FINAL RESPONSE,
// not every JSONL event on the way there, so a pipeline that trusts the flag will mis-parse. And a
// model that reports its own seed list can satisfy "one verdict per seeded invariant" by shortening
// the list — the anti-silence rule is only real if the EXPECTED seeds come from the wrapper, not from
// the model. `--expect` is that channel: review.sh writes it from invariants.jsonl before the model
// runs, and validation requires exact set equality against it.
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";

export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

export function loadKnownInvariantIds(root = REPO_ROOT) {
  const p = join(root, "docs/security/invariants.jsonl");
  if (!existsSync(p)) return new Set();
  return new Set(
    readFileSync(p, "utf8")
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l).id),
  );
}

export function loadKnownPriorArtIds(root = REPO_ROOT) {
  const p = join(root, "docs/security/PRIOR-ART-FINDINGS.md");
  if (!existsSync(p)) return new Set();
  return new Set([...readFileSync(p, "utf8").matchAll(/^\| `([A-Z0-9-]+)` \|/gm)].map((m) => m[1]));
}

/**
 * Validate a findings document. Returns an array of error strings; empty means valid.
 *
 * @param {object}  doc      the parsed findings JSON
 * @param {object}  opts
 * @param {Function} opts.validateSchema  a compiled ajv validator for warden-findings.json
 * @param {object=} opts.expect  wrapper-supplied expectations
 *                  {base_sha, head_sha, finding_id_start?, seeded_invariants[], sibling_files[]}
 * @param {Set=}    opts.knownInvariants
 * @param {Set=}    opts.knownPriorArt
 */
export function validateFindings(doc, opts) {
  const errors = [];
  const fail = (m) => errors.push(m);
  const { validateSchema, expect, knownInvariants = new Set(), knownPriorArt = new Set() } = opts;

  if (!validateSchema(doc)) {
    for (const e of validateSchema.errors ?? []) fail(`schema: ${e.instancePath || "/"} ${e.message}`);
    return errors; // structure is unusable; the checks below would report noise
  }

  // ---- provenance: a round with no identity cannot be scored (L3) -----------
  for (const k of ["thread", "base_sha", "head_sha", "reviewer_model"]) {
    if (!doc[k] || String(doc[k]).trim() === "") fail(`provenance: \`${k}\` is missing or empty`);
  }

  // ---- verdict hygiene -----------------------------------------------------
  const seen = new Map();
  for (const v of doc.invariant_verdicts) {
    if (seen.has(v.invariant_id)) {
      const prev = seen.get(v.invariant_id);
      fail(
        prev === v.verdict
          ? `duplicate verdict for ${v.invariant_id}`
          : `contradictory verdicts for ${v.invariant_id}: ${prev} and ${v.verdict}`,
      );
    }
    seen.set(v.invariant_id, v.verdict);
    if (v.verdict === "not_reviewed")
      fail(`${v.invariant_id} came back not_reviewed — silence on a seeded invariant is a FAIL, not a pass`);
    if (knownInvariants.size && !knownInvariants.has(v.invariant_id))
      fail(`verdict names unknown invariant ${v.invariant_id}`);
  }

  // ---- the anti-silence guarantee, against WRAPPER-supplied expectations ----
  if (expect) {
    const want = new Set(expect.seeded_invariants ?? []);
    if (want.size === 0) fail("expectations name no seeded invariants — refusing to accept an unseeded round");
    const got = new Set(doc.seeded_invariants ?? []);
    for (const id of want) {
      if (!got.has(id)) fail(`model dropped seeded invariant ${id} from seeded_invariants`);
      if (!seen.has(id)) fail(`no verdict for seeded invariant ${id} — silence is a FAIL, not a pass`);
    }
    for (const id of got) if (!want.has(id)) fail(`model invented seeded invariant ${id} (not in the wrapper's seed list)`);
    for (const id of seen.keys()) if (!want.has(id)) fail(`verdict for un-seeded invariant ${id}`);
    if (expect.base_sha && doc.base_sha !== expect.base_sha)
      fail(`base_sha mismatch: document ${doc.base_sha}, wrapper ${expect.base_sha}`);
    if (expect.head_sha && doc.head_sha !== expect.head_sha)
      fail(`head_sha mismatch: document ${doc.head_sha}, wrapper ${expect.head_sha}`);
    for (const f of expect.sibling_files ?? [])
      if (!(doc.sibling_files_read ?? []).includes(f)) fail(`sibling file not reported as read: ${f}`);
  } else {
    // No expectations file: the self-reported seed list is all there is. Say so loudly.
    fail("no --expect file supplied — the anti-silence guarantee is unverifiable from the model's own output alone");
  }

  // ---- findings ------------------------------------------------------------
  const findingIds = new Set();
  for (const f of doc.findings) {
    if (findingIds.has(f.id)) fail(`duplicate finding id ${f.id}`);
    findingIds.add(f.id);
    for (const id of f.invariant_ids)
      if (knownInvariants.size && !knownInvariants.has(id)) fail(`${f.id}: unknown invariant ${id}`);
    for (const id of f.prior_art_cited ?? [])
      if (knownPriorArt.size && !knownPriorArt.has(id)) fail(`${f.id}: unknown prior-art id ${id}`);
    if (f.reproducer && f.reproducer.base_sha === f.reproducer.fixed_sha)
      fail(`${f.id}: reproducer base_sha == fixed_sha — it must FAIL on base and PASS on fixed`);
  }
  for (const v of doc.invariant_verdicts)
    for (const id of v.finding_ids ?? [])
      if (!findingIds.has(id)) fail(`${v.invariant_id}: verdict cites unknown finding ${id}`);

  // Finding ids belong to the committed scorecard namespace. The wrapper computes the first id
  // before a round (or receives the integration branch's next id for a detached historical
  // review); the model may not silently allocate from an older checkout's ledger.
  if (expect?.finding_id_start) {
    const match = String(expect.finding_id_start).match(/^WRDF-(\d{4})$/);
    if (!match || Number(match[1]) === 0) {
      fail(`expectations carry invalid finding_id_start ${expect.finding_id_start}`);
    } else {
      const start = Number(match[1]);
      const wanted = doc.findings.map((_, i) => `WRDF-${String(start + i).padStart(4, "0")}`);
      const got = doc.findings.map((f) => f.id);
      if (start + got.length - 1 > 9999 || got.some((id, i) => id !== wanted[i]))
        fail(
          `finding id allocation mismatch: wrapper requires contiguous ids from ${expect.finding_id_start}; got ${got.join(", ") || "no findings"}`,
        );
    }
  }

  return errors;
}

export async function compileSchema(schemaPath) {
  // ajv is a devDependency of packages/core, not of the repo root, so resolve it from there rather
  // than relying on a hoisted node_modules layout that pnpm deliberately does not provide.
  const req = createRequire(join(REPO_ROOT, "packages/core/package.json"));
  const { default: Ajv2020 } = await import(pathToFileURL(req.resolve("ajv/dist/2020.js")).href);
  const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false });
  return ajv.compile(JSON.parse(readFileSync(schemaPath, "utf8")));
}

async function main(argv) {
  const args = argv.slice(2);
  const valueFlags = new Set(["--schema", "--expect", "--repo-root"]);
  const findingsPath = args.find((a, i) => !a.startsWith("--") && !valueFlags.has(args[i - 1]));
  const flag = (n) => {
    const i = args.indexOf(n);
    return i >= 0 ? args[i + 1] : undefined;
  };
  if (!findingsPath) {
    console.error("usage: node scripts/validate-findings.mjs <findings.json> [--schema <f>] [--expect <f>] [--repo-root <dir>]");
    process.exit(2);
  }
  const schemaPath = resolve(flag("--schema") ?? join(REPO_ROOT, ".codex/schemas/warden-findings.json"));
  const expectPath = flag("--expect");
  const repoRoot = resolve(flag("--repo-root") ?? REPO_ROOT);
  const doc = JSON.parse(readFileSync(resolve(findingsPath), "utf8"));
  const errors = validateFindings(doc, {
    validateSchema: await compileSchema(schemaPath),
    expect: expectPath ? JSON.parse(readFileSync(resolve(expectPath), "utf8")) : undefined,
    knownInvariants: loadKnownInvariantIds(repoRoot),
    knownPriorArt: loadKnownPriorArtIds(repoRoot),
  });
  if (errors.length) {
    for (const e of errors) console.error(`FAIL: ${e}`);
    console.error(`\n${findingsPath} FAILED validation (${errors.length} error(s))`);
    process.exit(1);
  }
  const counts = doc.findings.reduce((a, f) => ((a[f.severity] = (a[f.severity] ?? 0) + 1), a), {});
  console.log(`OK  ${findingsPath}`);
  console.log(`    thread=${doc.thread} model=${doc.reviewer_model} base=${doc.base_sha} head=${doc.head_sha}`);
  console.log(`    seeded=${doc.seeded_invariants.length} findings=${doc.findings.length} ${JSON.stringify(counts)}`);
  for (const f of doc.findings)
    console.log(`    [${f.severity}/${f.truth_status}/${f.evidence_type}] ${f.id} ${f.title} (${f.file}:${f.line})`);
}

if (process.argv[1] && process.argv[1].endsWith("validate-findings.mjs")) await main(process.argv);
