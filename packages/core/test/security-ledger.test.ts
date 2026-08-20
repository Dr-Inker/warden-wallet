// Assurance layer L1/L2 guard rails, run by `pnpm test`.
//
// These tests are the mechanical half of spec §17: the ledger is only useful if it stays parseable,
// unique, honestly-statused and pointed at evidence that exists, and the findings schema is only
// useful if something independent of Codex actually validates against it.
import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import {
  validateFindings,
  loadKnownInvariantIds,
  loadKnownPriorArtIds,
} from "../../../scripts/validate-findings.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const LEDGER = join(REPO, "docs/security/invariants.jsonl");
const SCHEMA = join(REPO, ".codex/schemas/warden-findings.json");
const EXAMPLE = join(REPO, ".codex/schemas/warden-findings.example.json");
const PRIOR_ART = join(REPO, "docs/security/PRIOR-ART-FINDINGS.md");
const INVARIANTS_MD = join(REPO, "docs/security/INVARIANTS.md");

const STATUSES = [
  "unimplemented",
  "llm-asserted",
  "test-covered",
  "mutation-tested",
  "proven",
  "holds",
] as const;
const EVIDENCE_TYPES = [
  "red_test",
  "static_trace",
  "formal_counterexample",
  "config_attestation",
  "primary_source",
] as const;
/** Statuses that assert an executable artefact exists, so evidence is mandatory. */
const EVIDENCED = ["test-covered", "mutation-tested", "proven", "holds"];

interface Evidence {
  type: string;
  path: string;
  name?: string;
  sha: string;
}
interface Row {
  id: string;
  title: string;
  statement: string;
  spec_ref: string;
  code_ref: string | null;
  phase: string;
  prior_art: string[];
  status: string;
  evidence: Evidence[];
  last_reviewed: { thread: string; date: string };
  notes: string;
  __line: number;
}

const rows: Row[] = readFileSync(LEDGER, "utf8")
  .split("\n")
  .map((text, i) => ({ text, line: i + 1 }))
  .filter((l) => l.text.trim().length > 0)
  .map((l) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(l.text);
    } catch (e) {
      throw new Error(`invariants.jsonl line ${l.line} is not valid JSON: ${(e as Error).message}`);
    }
    return { ...(parsed as Row), __line: l.line };
  });

describe("invariant ledger (docs/security/invariants.jsonl)", () => {
  it("is non-empty and every line parses", () => {
    expect(rows.length).toBeGreaterThanOrEqual(30);
  });

  it("has unique, well-formed ids", () => {
    const seen = new Map<string, number>();
    for (const r of rows) {
      expect(r.id, `line ${r.__line}`).toMatch(/^WRD-[A-Z]+-\d{2}$/);
      expect(seen.has(r.id), `duplicate id ${r.id} (lines ${seen.get(r.id)} and ${r.__line})`).toBe(false);
      seen.set(r.id, r.__line);
    }
  });

  it("uses only the six ascending status values and never a `holds` boolean alongside them", () => {
    for (const r of rows) {
      expect(STATUSES, `${r.id}`).toContain(r.status);
      // A second representation of the same fact is a desync waiting to happen (spec §17).
      expect(Object.prototype.hasOwnProperty.call(r, "holds"), `${r.id} must not carry a holds field`).toBe(false);
    }
  });

  it("carries the required fields on every row", () => {
    for (const r of rows) {
      expect(r.title.length, r.id).toBeGreaterThan(0);
      expect(r.statement.length, r.id).toBeGreaterThan(20);
      expect(r.spec_ref, r.id).toBeTruthy();
      expect(["1A", "1B", "1C"], r.id).toContain(r.phase);
      expect(Array.isArray(r.prior_art), r.id).toBe(true);
      expect(Array.isArray(r.evidence), r.id).toBe(true);
      expect(r.last_reviewed?.thread, r.id).toBeTruthy();
      expect(r.last_reviewed?.date, r.id).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });

  it("seeds nothing at `holds` — a status only an evidence artefact or a human adjudication may set", () => {
    expect(rows.filter((r) => r.status === "holds").map((r) => r.id)).toEqual([]);
  });

  it("gives every evidenced row at least one evidence entry whose file actually exists", () => {
    for (const r of rows.filter((x) => EVIDENCED.includes(x.status))) {
      expect(r.evidence.length, `${r.id} claims status ${r.status} with no evidence`).toBeGreaterThanOrEqual(1);
      for (const e of r.evidence) {
        expect(EVIDENCE_TYPES, `${r.id} evidence type`).toContain(e.type);
        expect(existsSync(join(REPO, e.path)), `${r.id} evidence path does not exist: ${e.path}`).toBe(true);
        expect(e.sha, `${r.id} evidence sha`).toMatch(/^[0-9a-f]{7,40}$/);
      }
    }
  });

  // A path that exists proves nothing: a renamed or deleted test leaves the file in place and the
  // ledger still pointing at it. This is the check that actually keeps `test-covered` honest.
  it("cites test names that still exist in the file they name, at HEAD", () => {
    for (const r of rows) {
      for (const e of r.evidence) {
        if (!e.name) continue;
        const src = readFileSync(join(REPO, e.path), "utf8");
        if (e.path.endsWith(".rs")) {
          // Rust: `tests::foo` (a #[cfg(test)] module fn) or a bare integration-test fn.
          const leaf = e.name.split("::").pop()!;
          expect(
            new RegExp(`\\bfn\\s+${leaf}\\s*\\(`).test(src),
            `${r.id}: ${e.path} has no \`fn ${leaf}(\` — the test was renamed or removed`,
          ).toBe(true);
          // and it must actually be a test, not a helper the ledger mistook for one
          const at = src.indexOf(`fn ${leaf}(`);
          expect(
            src.slice(Math.max(0, at - 200), at).includes("#[test]"),
            `${r.id}: ${e.path}::${leaf} is not annotated #[test] — it is a helper, not evidence`,
          ).toBe(true);
        } else if (e.path.endsWith(".ts")) {
          expect(src.includes(e.name), `${r.id}: ${e.path} has no test named "${e.name}"`).toBe(true);
        }
      }
    }
  });

  // WRDF-0013: a name existing at HEAD is not proof it existed at the SHA the row cites — a fix's
  // evidence can be mis-pinned to a pre-fix commit. This resolves each cited (sha, path, name) in
  // the actual git object. Skipped gracefully when git or the object is unavailable (shallow CI).
  it("cites test names that exist AT the SHA each evidence entry names, not merely at HEAD", () => {
    const { execFileSync } = require("node:child_process") as typeof import("node:child_process");
    let gitOk = true;
    try {
      execFileSync("git", ["-C", REPO, "rev-parse", "--is-inside-work-tree"], { stdio: "pipe" });
    } catch {
      gitOk = false;
    }
    if (!gitOk) return; // not a git checkout — nothing to verify
    for (const r of rows) {
      for (const e of r.evidence) {
        if (!e.name || !/^[0-9a-f]{7,40}$/.test(e.sha)) continue;
        let blob: string;
        try {
          blob = execFileSync("git", ["-C", REPO, "show", `${e.sha}:${e.path}`], {
            stdio: ["pipe", "pipe", "pipe"],
            maxBuffer: 32 * 1024 * 1024,
          }).toString();
        } catch {
          continue; // object not present locally (shallow clone) — cannot verify, do not fail
        }
        const leaf = e.name.split("::").pop()!;
        const present = e.path.endsWith(".rs")
          ? new RegExp(`\\bfn\\s+${leaf}\\s*\\(`).test(blob)
          : blob.includes(e.name);
        expect(
          present,
          `${r.id}: evidence "${e.name}" is NOT present in ${e.path} at cited sha ${e.sha} (it may be pinned to a pre-fix commit)`,
        ).toBe(true);
      }
    }
  });

  it("leaves unimplemented rows honest: no evidence, no code_ref", () => {
    for (const r of rows.filter((x) => x.status === "unimplemented")) {
      expect(r.evidence.length, `${r.id} is unimplemented but cites evidence`).toBe(0);
      expect(r.code_ref, `${r.id} is unimplemented but has a code_ref`).toBeNull();
    }
  });

  it("only cites prior-art ids that exist in PRIOR-ART-FINDINGS.md", () => {
    const md = readFileSync(PRIOR_ART, "utf8");
    const known = new Set([...md.matchAll(/^\| `([A-Z0-9-]+)` \|/gm)].map((m) => m[1]));
    for (const r of rows) {
      for (const id of r.prior_art) {
        expect(known.has(id), `${r.id} cites unknown prior-art id ${id}`).toBe(true);
      }
    }
  });

  it("covers the namespaces Phase 1A and 1B are required to seed", () => {
    const ns = new Set(rows.map((r) => r.id.split("-")[1]));
    for (const n of ["NONCE", "CAP", "SESS", "EXEC", "FRZ", "ROOT", "DENY", "BUF", "STAGE"]) {
      expect(ns.has(n), `namespace WRD-${n}-* is not seeded`).toBe(true);
    }
  });

  it("is fully rendered into INVARIANTS.md (run `node scripts/gen-invariants.mjs` if this fails)", () => {
    const md = readFileSync(INVARIANTS_MD, "utf8");
    expect(md).toContain("<!-- BEGIN GENERATED");
    for (const r of rows) expect(md, `${r.id} missing from the rendered table`).toContain(`\`${r.id}\``);
  });
});

describe("findings schema (.codex/schemas/warden-findings.json)", () => {
  const schema = JSON.parse(readFileSync(SCHEMA, "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false });
  const validate = ajv.compile(schema);

  it("compiles as draft 2020-12", () => {
    expect(schema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(typeof validate).toBe("function");
  });

  it("keeps truth_status and evidence_type as separate axes", () => {
    const f = schema.$defs.finding.properties;
    expect(f.truth_status.enum).toEqual(["POTENTIAL", "CONFIRMED", "REFUTED"]);
    expect(f.evidence_type.enum).toEqual([
      "red_test",
      "static_trace",
      "formal_counterexample",
      "config_attestation",
      "primary_source",
      "none",
    ]);
    expect(f.severity.enum).toEqual(["critical", "important", "minor", "info"]);
    // Both axes are required on every finding: neither may be inferred from the other.
    expect(schema.$defs.finding.required).toEqual(
      expect.arrayContaining(["truth_status", "evidence_type", "reproducer", "invariant_ids"]),
    );
  });

  it("validates the worked example", () => {
    const example = JSON.parse(readFileSync(EXAMPLE, "utf8"));
    const ok = validate(example);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("the example exercises all three truth_status values and a null reproducer", () => {
    const example = JSON.parse(readFileSync(EXAMPLE, "utf8"));
    const statuses = new Set(example.findings.map((f: { truth_status: string }) => f.truth_status));
    expect([...statuses].sort()).toEqual(["CONFIRMED", "POTENTIAL", "REFUTED"]);
    expect(example.findings.some((f: { reproducer: unknown }) => f.reproducer === null)).toBe(true);
  });

  it("rejects a null reproducer with no infeasibility reason", () => {
    const doc = JSON.parse(readFileSync(EXAMPLE, "utf8"));
    delete doc.findings[1].reproducer_infeasible_reason;
    expect(validate(doc)).toBe(false);
  });

  it("rejects a CONFIRMED finding carrying evidence_type `none`", () => {
    const doc = JSON.parse(readFileSync(EXAMPLE, "utf8"));
    doc.findings[0].evidence_type = "none";
    expect(validate(doc)).toBe(false);
  });

  it("rejects an unknown severity and unknown extra properties", () => {
    const doc = JSON.parse(readFileSync(EXAMPLE, "utf8"));
    doc.findings[0].severity = "blocker";
    expect(validate(doc)).toBe(false);
    const doc2 = JSON.parse(readFileSync(EXAMPLE, "utf8"));
    doc2.findings[0].vibes = "bad";
    expect(validate(doc2)).toBe(false);
  });

  it("requires a verdict for every seeded invariant (silence is a FAIL)", () => {
    const doc = JSON.parse(readFileSync(EXAMPLE, "utf8"));
    const verdicts = new Set(
      doc.invariant_verdicts.map((v: { invariant_id: string }) => v.invariant_id),
    );
    for (const id of doc.seeded_invariants) expect(verdicts.has(id)).toBe(true);
    expect(
      doc.invariant_verdicts.every((v: { verdict: string }) => v.verdict !== "not_reviewed"),
    ).toBe(true);
  });

  it("only references invariant ids and prior-art ids that exist", () => {
    const doc = JSON.parse(readFileSync(EXAMPLE, "utf8"));
    const ids = new Set(rows.map((r) => r.id));
    const md = readFileSync(PRIOR_ART, "utf8");
    const priorArt = new Set([...md.matchAll(/^\| `([A-Z0-9-]+)` \|/gm)].map((m) => m[1]));
    for (const id of doc.seeded_invariants) expect(ids.has(id), `unknown invariant ${id}`).toBe(true);
    for (const f of doc.findings) {
      for (const id of f.invariant_ids) expect(ids.has(id), `unknown invariant ${id}`).toBe(true);
      for (const id of f.prior_art_cited ?? [])
        expect(priorArt.has(id), `unknown prior-art id ${id}`).toBe(true);
    }
  });
});

describe("prior-art corpus (docs/security/PRIOR-ART-FINDINGS.md)", () => {
  const md = readFileSync(PRIOR_ART, "utf8");
  const tableRows = md.split("\n").filter((l) => /^\| `[A-Z0-9-]+` \|/.test(l));

  it("has at least 12 rows", () => {
    expect(tableRows.length).toBeGreaterThanOrEqual(12);
  });

  it("gives every row a source URL", () => {
    for (const r of tableRows) {
      const id = r.match(/^\| `([A-Z0-9-]+)` \|/)![1];
      expect(r, `prior-art row ${id} has no source URL`).toMatch(/https?:\/\/\S+/);
    }
  });

  it("names the non-negotiable findings", () => {
    for (const id of [
      "TOB-SQUADS-7",
      "TOB-SQUADS-8",
      "ND-SQD3-LO-01",
      "CERTORA-H-01",
      "LZR-ACC-C1",
      "LZR-ACC-C2",
      "LZR-ACC-H1",
      "LZR-ACC-H2",
      "LZR-ACC-M1",
      "LZR-ACC-M2",
      "SWIG-ACC-C1",
      "SWIG-ACC-C2",
      "ARGENT-ZERO-GUARDIAN",
      "MOONWELL-DIMENSIONAL",
    ]) {
      expect(md, `prior-art corpus is missing ${id}`).toContain(`\`${id}\``);
    }
  });

  it("records the licensing constraint on non-MIT prior art", () => {
    expect(md).toMatch(/AGPL/);
    expect(md).toMatch(/counsel/i);
  });
});

// ---------------------------------------------------------------------------
// The anti-silence guarantee, tested against the validator itself.
//
// The rule that matters — "silence on a seeded invariant is a FAIL, not a pass" — is only real if
// the EXPECTED seed list comes from the wrapper (scripts/review.sh, from invariants.jsonl) rather
// than from the model's own report of what it was asked. These cases pin that: every one of them
// would PASS if the validator trusted `doc.seeded_invariants`.
// ---------------------------------------------------------------------------
describe("findings validator (scripts/validate-findings.mjs)", () => {
  const schema = JSON.parse(readFileSync(SCHEMA, "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false });
  const validateSchema = ajv.compile(schema);
  const EXPECT_FILE = join(REPO, ".codex/schemas/warden-findings.example.expect.json");
  const knownInvariants = loadKnownInvariantIds(REPO);
  const knownPriorArt = loadKnownPriorArtIds(REPO);

  const fresh = () => JSON.parse(readFileSync(EXAMPLE, "utf8"));
  const expectations = () => JSON.parse(readFileSync(EXPECT_FILE, "utf8"));
  const run = (doc: unknown, expect_?: unknown) =>
    validateFindings(doc, { validateSchema, expect: expect_, knownInvariants, knownPriorArt });

  it("accepts the worked example against its expectations file", () => {
    expect(run(fresh(), expectations())).toEqual([]);
  });

  it("the expectations file matches the example's own seed list", () => {
    expect([...expectations().seeded_invariants].sort()).toEqual([...fresh().seeded_invariants].sort());
  });

  it("FAILS when the model drops a seeded invariant from both the seed list and the verdicts", () => {
    const doc = fresh();
    const dropped = doc.seeded_invariants.pop();
    doc.invariant_verdicts = doc.invariant_verdicts.filter(
      (v: { invariant_id: string }) => v.invariant_id !== dropped,
    );
    // Self-consistent — and exactly the shape a self-reported check would wave through.
    expect(run(doc)).not.toEqual([]);
    const errs = run(doc, expectations());
    expect(errs.some((e) => e.includes(dropped) && e.includes("dropped"))).toBe(true);
    expect(errs.some((e) => e.includes(dropped) && e.includes("silence is a FAIL"))).toBe(true);
  });

  it("FAILS when a seeded invariant has no verdict", () => {
    const doc = fresh();
    const missing = doc.seeded_invariants[0];
    doc.invariant_verdicts = doc.invariant_verdicts.filter(
      (v: { invariant_id: string }) => v.invariant_id !== missing,
    );
    expect(run(doc, expectations()).some((e) => e.includes(missing) && e.includes("silence is a FAIL"))).toBe(true);
  });

  it("FAILS on a duplicated verdict and on contradictory verdicts for one id", () => {
    const dup = fresh();
    dup.invariant_verdicts.push({ ...dup.invariant_verdicts[0] });
    expect(run(dup, expectations()).some((e) => e.startsWith("duplicate verdict"))).toBe(true);

    const contra = fresh();
    contra.invariant_verdicts.push({ ...contra.invariant_verdicts[0], verdict: "violated" });
    expect(run(contra, expectations()).some((e) => e.startsWith("contradictory verdicts"))).toBe(true);
  });

  it("FAILS on empty seeded_invariants, empty verdicts, and empty expectations", () => {
    const empty = fresh();
    empty.seeded_invariants = [];
    empty.invariant_verdicts = [];
    // Against the wrapper's expectations this is the worst case, not a clean round.
    expect(run(empty, expectations()).length).toBeGreaterThanOrEqual(expectations().seeded_invariants.length);
    // And an expectations file that itself seeds nothing is refused rather than trivially satisfied.
    expect(run(empty, { ...expectations(), seeded_invariants: [] }).some((e) => e.includes("unseeded round"))).toBe(true);
  });

  it("FAILS when a verdict comes back not_reviewed", () => {
    const doc = fresh();
    doc.invariant_verdicts[0].verdict = "not_reviewed";
    expect(run(doc, expectations()).some((e) => e.includes("not_reviewed"))).toBe(true);
  });

  it("FAILS when the model invents a seed or rules on an un-seeded invariant", () => {
    const doc = fresh();
    doc.seeded_invariants.push("WRD-CAP-01");
    doc.invariant_verdicts.push({ invariant_id: "WRD-CAP-01", verdict: "upheld", rationale: "n/a" });
    const errs = run(doc, expectations());
    expect(errs.some((e) => e.includes("invented seeded invariant WRD-CAP-01"))).toBe(true);
    expect(errs.some((e) => e.includes("verdict for un-seeded invariant WRD-CAP-01"))).toBe(true);
  });

  it("FAILS on base_sha / head_sha drift from the range the wrapper asked for", () => {
    const doc = fresh();
    doc.head_sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    expect(run(doc, expectations()).some((e) => e.includes("head_sha mismatch"))).toBe(true);
    const doc2 = fresh();
    doc2.base_sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    expect(run(doc2, expectations()).some((e) => e.includes("base_sha mismatch"))).toBe(true);
  });

  it("FAILS on missing provenance the schema alone would let through", () => {
    // `reviewer_model` and `head_sha` are schema-optional on purpose (a hand-written finding may not
    // have them). A round with no identity cannot be scored in the L3 scorecard, so the validator
    // requires them anyway — this is the gap between "well-formed" and "usable".
    for (const k of ["reviewer_model", "head_sha"]) {
      const doc = fresh();
      delete doc[k];
      const errs = run(doc, expectations());
      expect(errs.some((e) => e.startsWith("provenance:") && e.includes(k)), `${k} not caught`).toBe(true);
    }
    // An empty required string is caught one layer earlier, by the schema.
    const blank = fresh();
    blank.thread = "";
    expect(run(blank, expectations()).some((e) => e.startsWith("schema:"))).toBe(true);
  });

  it("FAILS when a sibling file the wrapper required was not read", () => {
    const doc = fresh();
    doc.sibling_files_read = [];
    const errs = run(doc, expectations());
    expect(errs.filter((e) => e.startsWith("sibling file not reported as read")).length).toBe(
      expectations().sibling_files.length,
    );
  });

  it("FAILS on unknown invariant ids, unknown prior art, and a dangling finding reference", () => {
    const doc = fresh();
    doc.findings[0].invariant_ids = ["WRD-NOPE-99"];
    expect(run(doc, expectations()).some((e) => e.includes("unknown invariant WRD-NOPE-99"))).toBe(true);

    const doc2 = fresh();
    doc2.findings[0].prior_art_cited = ["NOT-A-REAL-FINDING"];
    expect(run(doc2, expectations()).some((e) => e.includes("unknown prior-art id"))).toBe(true);

    const doc3 = fresh();
    doc3.invariant_verdicts[0].finding_ids = ["WRDF-9999"];
    expect(run(doc3, expectations()).some((e) => e.includes("unknown finding WRDF-9999"))).toBe(true);
  });

  it("FAILS a reproducer whose base_sha equals its fixed_sha", () => {
    const doc = fresh();
    doc.findings[0].reproducer.fixed_sha = doc.findings[0].reproducer.base_sha;
    expect(run(doc, expectations()).some((e) => e.includes("base_sha == fixed_sha"))).toBe(true);
  });

  it("refuses to certify a round with no expectations file at all", () => {
    expect(run(fresh()).some((e) => e.includes("no --expect file supplied"))).toBe(true);
  });
});
