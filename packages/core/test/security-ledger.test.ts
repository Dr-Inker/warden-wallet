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
    for (const n of ["NONCE", "CAP", "EXEC", "FRZ", "ROOT", "DENY", "BUF"]) {
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
