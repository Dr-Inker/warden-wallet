#!/usr/bin/env bash
# =============================================================================
# scripts/review.sh — Warden adversarial review round (assurance layer L2)
#
# USAGE
#   scripts/review.sh <base-sha> [head]            review base..head
#   scripts/review.sh <base-sha> <old-head> --historical  review an old head in a temporary,
#                                                       detached read-only worktree
#   scripts/review.sh <base-sha> [head] --dry-run  assemble everything, invoke nothing
#   scripts/review.sh --selftest                   assert every codex flag this script uses exists
#   scripts/review.sh --validate <f.json> [--expect <f>]   validate an existing findings file
#
#   Options: --dry-run · --with-tools · --out <path> · --model <m> · --effort <e> · --kind <k>
#            --finding-id-start <WRDF-NNNN> · --historical
#
# WHAT IT DOES
#   1. Refuses to run with a dirty integration tree. The review worktree must be exactly <head>:
#      normally that is the integration checkout; --historical instead creates a temporary,
#      detached worktree at an old head while keeping the current review machinery and scorecard
#      authoritative. A mismatched or dirty worktree is not reproducible, and `codex review --base`
#      on a dirty tree repeats HALLUCINATED findings unrelated to the diff (openai/codex#8404).
#   2. Computes the seed list ITSELF from docs/security/invariants.jsonl and writes it, with the two
#      SHAs and the sibling-file list, to an EXPECTATIONS file. The validator checks the model's
#      output against that file, not against the model's own account of what it was asked. Without
#      this the anti-silence rule is self-reported and therefore worthless.
#   3. Seeds the prompt with those invariants, docs/security/PRIOR-ART-FINDINGS.md, and the named
#      sibling files carrying cross-cutting invariants. The one false positive in the Phase 1A pilot
#      came from reviewer SCOPE, not model identity.
#   4. Runs `codex exec` (see below) with --output-schema, tool-free, blind, anti-rewrite.
#   5. Validates the artefact with an INDEPENDENT validator against the expectations file.
#   6. Hands the artefact to append-review-run.mjs, which re-validates it independently, refuses
#      replays, and then writes BOTH ledgers in one process — exactly ONE run record to
#      REVIEW-RUNS.jsonl (zero-finding rounds included) and every finding (disputed and scoped-out
#      included) to REVIEW-SCORECARD.jsonl — rolling both back together on any failure (WRDF-0007).
#
# WHY `codex exec` AND NOT `codex exec review` (codex-cli 0.147.0, checked on this host)
#   `codex exec review` looks like the right subcommand and is not usable here:
#     * it REJECTS a prompt argument together with --base (clap exits 2), so the invariant seeds,
#       the prior-art corpus and the round's rules cannot be delivered at all;
#     * --title requires --commit;
#     * the review operation IGNORES --output-schema, so the output is prose, not typed JSON.
#   Plain `codex exec` accepts a stdin prompt AND honours --output-schema. The diff range is
#   therefore delivered IN THE PROMPT as `<base>..<head>` and the model runs `git diff` itself,
#   which is why the sandbox stays read-only rather than tool-free-with-no-shell.
#   Flags used below and confirmed present on `codex exec --help`: --output-schema · --ephemeral ·
#   -o/--output-last-message · -m/--model · -c/--config · -s/--sandbox · -C/--cd. `--selftest`
#   re-checks all of them against the installed binary so this comment cannot rot silently.
# =============================================================================
set -euo pipefail

# Review coordinates name immutable Git objects, not the caller's local replacement-ref view.
# Export this before commit resolution so historical worktrees, seed diffs, and the Codex process
# all read the original object graph (WRDF-0159). A clean worktree does not reveal refs/replace/*.
export GIT_NO_REPLACE_OBJECTS=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REVIEW_ROOT="$REPO_ROOT"
HISTORICAL_ROOT=""
PROMPT_FILE=""
cd "$REPO_ROOT"

SCHEMA="$REPO_ROOT/.codex/schemas/warden-findings.json"
PRIOR_ART="docs/security/PRIOR-ART-FINDINGS.md"
LEDGER="docs/security/invariants.jsonl"
SCORECARD="$REPO_ROOT/docs/security/REVIEW-SCORECARD.jsonl"
OUT_DIR="$REPO_ROOT/.superpowers/reviews"
MODEL="gpt-5.6-sol"
EFFORT="max"
# Flags this script passes to `codex exec`. --selftest asserts every one of them exists.
REQUIRED_FLAGS=(--output-schema --ephemeral --output-last-message --model --config --sandbox --cd)
SIBLINGS=(
  "programs/warden/src/root_verify/transcript.rs"
  "programs/warden/src/state/session.rs"
  "programs/warden/src/errors.rs"
  "programs/warden/src/buckets.rs"
)

die() { echo "error: $*" >&2; exit 1; }

# ---- --selftest: the codex CLI contract this script depends on --------------
if [[ "${1:-}" == "--selftest" ]]; then
  command -v codex >/dev/null || die "codex CLI not found on PATH"
  HELP="$(codex exec --help 2>&1)"
  echo "codex: $(codex --version 2>&1 | head -1)"
  rc=0
  for f in "${REQUIRED_FLAGS[@]}"; do
    if grep -qE -- "(^|[ ,])$f([ ,=<]|$)" <<<"$HELP"; then
      echo "  ok      codex exec $f"
    else
      echo "  MISSING codex exec $f"; rc=1
    fi
  done
  # `codex exec review` is deliberately NOT used: it ignores --output-schema and rejects a prompt
  # alongside --base. If a future version fixes that, this notice is the prompt to revisit.
  if codex exec review --help >/dev/null 2>&1; then
    echo "  note    'codex exec review' exists but is unused (ignores --output-schema, rejects a prompt with --base)"
  fi
  [[ $rc -eq 0 ]] || die "the installed codex is missing flags this script requires"
  echo "selftest OK"
  exit 0
fi

# ---- --validate mode --------------------------------------------------------
if [[ "${1:-}" == "--validate" ]]; then
  [[ -n "${2:-}" ]] || die "usage: scripts/review.sh --validate <findings.json> [--expect <f>]"
  shift
  exec node "$REPO_ROOT/scripts/validate-findings.mjs" "$@" --schema "$SCHEMA" --repo-root "$REPO_ROOT"
fi

DRY_RUN=0; WITH_TOOLS=0; HISTORICAL=0; OUT=""; BASE=""; HEAD_REF="HEAD"; KIND="task-diff"; FINDING_ID_START=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift;;
    --with-tools) WITH_TOOLS=1; shift;;
    --out) OUT="${2:?}"; shift 2;;
    --model) MODEL="${2:?}"; shift 2;;
    --effort) EFFORT="${2:?}"; shift 2;;
    --kind) KIND="${2:?}"; shift 2;;
    --finding-id-start) FINDING_ID_START="${2:?}"; shift 2;;
    --historical) HISTORICAL=1; shift;;
    -h|--help) sed -n '2,40p' "$0"; exit 0;;
    -*) die "unknown option $1";;
    *) if [[ -z "$BASE" ]]; then BASE="$1"; else HEAD_REF="$1"; fi; shift;;
  esac
done
[[ -n "$BASE" ]] || die "usage: scripts/review.sh <base-sha> [head] [--dry-run]"

command -v codex >/dev/null || die "codex CLI not found on PATH"
command -v node  >/dev/null || die "node not found on PATH"

BASE_SHA="$(git rev-parse --verify "$BASE^{commit}" 2>/dev/null)" || die "not a commit: $BASE"
HEAD_SHA="$(git rev-parse --verify "$HEAD_REF^{commit}" 2>/dev/null)" || die "not a commit: $HEAD_REF"

# ---- 1. clean integration tree + an exact worktree for <head> ----------------
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]]; then
  echo "error: working tree is dirty." >&2
  echo "  A dirty-tree review is void: codex repeats HALLUCINATED findings unrelated to the diff" >&2
  echo "  (openai/codex#8404), and the range under review would not match the files on disk." >&2
  git -C "$REPO_ROOT" status --short >&2
  exit 1
fi
CURRENT_HEAD="$(git -C "$REPO_ROOT" rev-parse --verify HEAD)"
if [[ "$CURRENT_HEAD" != "$HEAD_SHA" ]]; then
  [[ $HISTORICAL -eq 1 ]] || die "checked-out HEAD is $CURRENT_HEAD but the requested head is $HEAD_SHA — check out $HEAD_SHA or pass --historical; the model reads files from an exact worktree"
  HISTORICAL_ROOT="$(mktemp -d /tmp/warden-review-worktree.XXXXXX)"
  rmdir "$HISTORICAL_ROOT"
  git -C "$REPO_ROOT" worktree add --detach "$HISTORICAL_ROOT" "$HEAD_SHA" >/dev/null
  REVIEW_ROOT="$HISTORICAL_ROOT"
fi
cleanup() {
  [[ -z "$PROMPT_FILE" ]] || rm -f "$PROMPT_FILE"
  if [[ -n "$HISTORICAL_ROOT" ]]; then
    git -C "$REPO_ROOT" worktree remove --force "$HISTORICAL_ROOT" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
cd "$REVIEW_ROOT"
[[ -z "$(git status --porcelain)" ]] || die "review worktree is dirty: $REVIEW_ROOT"
[[ "$(git rev-parse --verify HEAD)" == "$HEAD_SHA" ]] || die "review worktree is not at $HEAD_SHA"
for f in "$SCHEMA" "$PRIOR_ART" "$LEDGER"; do [[ -f "$f" ]] || die "missing $f"; done

# Finding ids are one committed-ledger namespace, not local to the historical checkout being
# reviewed. The integration scorecard is authoritative even when REVIEW_ROOT is historical.
NEXT_FINDING_ID="$(SCORECARD="$SCORECARD" node -e '
    const fs = require("fs");
    let max = 0;
    if (fs.existsSync(process.env.SCORECARD)) {
      for (const line of fs.readFileSync(process.env.SCORECARD, "utf8").split("\n")) {
        if (!line.trim()) continue;
        const m = String(JSON.parse(line).finding_id ?? "").match(/^WRDF-(\d{4})$/);
        if (m) max = Math.max(max, Number(m[1]));
      }
    }
    if (max >= 9999) throw new Error("WRDF finding id namespace exhausted");
    process.stdout.write(`WRDF-${String(max + 1).padStart(4, "0")}`);
  ')"
if [[ -z "$FINDING_ID_START" ]]; then
  FINDING_ID_START="$NEXT_FINDING_ID"
elif [[ "$FINDING_ID_START" != "$NEXT_FINDING_ID" ]]; then
  die "--finding-id-start must equal the integration scorecard's next contiguous finding id $NEXT_FINDING_ID (got $FINDING_ID_START)"
fi
[[ "$FINDING_ID_START" =~ ^WRDF-[0-9]{4}$ && "$FINDING_ID_START" != "WRDF-0000" ]] || \
  die "--finding-id-start must be WRDF-0001..WRDF-9999 (got ${FINDING_ID_START})"

# ---- 2. seed list + expectations file (computed by the WRAPPER) -------------
CHANGED="$(git diff --name-only "$BASE_SHA" "$HEAD_SHA")"
[[ -n "$CHANGED" ]] || die "no changes between $BASE_SHA and $HEAD_SHA"

mkdir -p "$OUT_DIR"
# Round id and artefact path are WRAPPER-owned (WRDF-0002/-0003): the timestamp keeps a re-round
# over the same head from overwriting the previous artefact, and the round id — not the model's
# self-report — is what lands in the scorecard and run record.
ROUND_ID="${HEAD_SHA:0:12}-$(date -u +%Y%m%dT%H%M%SZ)"
[[ -n "$OUT" ]] || OUT=".superpowers/reviews/$ROUND_ID.json"
if [[ "$OUT" = /* ]]; then OUT_PATH="$OUT"; else OUT_PATH="$REPO_ROOT/$OUT"; fi
EXPECT="${OUT_PATH%.json}.expect.json"

# Rows whose LEDGER ENTRY changed in the range are seeded too — a review of the commit that adds
# or edits an invariant must rule on that invariant (WRDF-0001: the round introducing WRD-CONS-*
# did not seed them). And every unimplemented row is ALWAYS seeded, never displaced by a narrow
# code hit: over-seeding is the safe direction, and a single-module diff must not suppress the
# cross-cutting rows the fallback used to carry.
# Whitespace-tolerant: a re-indented row is still that row (WRDF-0001 round-3 residual).
LEDGER_DIFF="$(git diff "$BASE_SHA" "$HEAD_SHA" -- docs/security/invariants.jsonl | grep -E '^\+[[:space:]]*\{' || true)"
# A published invariant id is immutable: it is retired in place (status/notes), never deleted. A
# deleted row would otherwise vanish from seeding and pass the anti-silence gate (WRDF-0006).
LEDGER_REMOVED="$(git diff "$BASE_SHA" "$HEAD_SHA" -- docs/security/invariants.jsonl | grep -E '^-[[:space:]]*\{' || true)"
DELETED_IDS="$(LEDGER_DIFF="$LEDGER_DIFF" LEDGER_REMOVED="$LEDGER_REMOVED" node -e '
const parse = (s) => (s || "").split("\n").filter(Boolean)
  .map((l) => { try { return JSON.parse(l.slice(1)).id; } catch { return null; } }).filter(Boolean);
const fs = require("fs");
const atHead = new Set(fs.readFileSync("docs/security/invariants.jsonl", "utf8")
  .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l).id));
const added = new Set(parse(process.env.LEDGER_DIFF));
const gone = parse(process.env.LEDGER_REMOVED).filter((id) => !added.has(id) && !atHead.has(id));
process.stdout.write([...new Set(gone)].join(" "));
')"
[[ -z "$DELETED_IDS" ]] || die "range DELETES published invariant id(s): $DELETED_IDS — retire in place (status/notes), never delete; a deleted id escapes every future seeding"
SEED_JSON="$(CHANGED="$CHANGED" LEDGER_DIFF="$LEDGER_DIFF" node -e '
const fs = require("fs");
const changed = (process.env.CHANGED || "").split("\n").filter(Boolean);
const rows = fs.readFileSync("docs/security/invariants.jsonl", "utf8")
  .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
// code_ref may name SEVERAL files, ";"-separated, each optionally annotated "path (fn)" or
// "path:line" (WRDF-0010: an invariant enforced across two modules must seed on a change to either).
const touches = (p) => { if (!p) return false;
  return p.split(";").some((part) => {
    const f = part.trim().split(":")[0].split(" ")[0];
    return f && changed.some((c) => c === f || f.startsWith(c + "/") || c.startsWith(f));
  }); };
const changedRowIds = new Set((process.env.LEDGER_DIFF || "").split("\n").filter(Boolean)
  .map((l) => { try { return JSON.parse(l.slice(1)).id; } catch { return null; } }).filter(Boolean));
const ids = new Set();
for (const r of rows) {
  if (touches(r.code_ref) || (r.evidence || []).some((e) => touches(e.path))) ids.add(r.id);
  if (changedRowIds.has(r.id)) ids.add(r.id);
  if (r.status === "unimplemented") ids.add(r.id);
}
const out = rows.filter((r) => ids.has(r.id));
process.stdout.write(JSON.stringify(out.map((r) => ({ id: r.id, title: r.title, statement: r.statement,
  status: r.status, spec_ref: r.spec_ref, prior_art: r.prior_art, notes: r.notes })), null, 1));
')"
SEED_IDS="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).map(r=>r.id).join(" "))' "$SEED_JSON")"
[[ -n "$SEED_IDS" ]] || die "no invariants selected — refusing to run an unseeded review"

SEED_JSON="$SEED_JSON" BASE_SHA="$BASE_SHA" HEAD_SHA="$HEAD_SHA" FINDING_ID_START="$FINDING_ID_START" \
SIBS="$(printf '%s\n' "${SIBLINGS[@]}")" EXPECT="$EXPECT" node -e '
const fs = require("fs");
fs.writeFileSync(process.env.EXPECT, JSON.stringify({
  base_sha: process.env.BASE_SHA, head_sha: process.env.HEAD_SHA,
  finding_id_start: process.env.FINDING_ID_START,
  seeded_invariants: JSON.parse(process.env.SEED_JSON).map((r) => r.id),
  sibling_files: process.env.SIBS.split("\n").filter(Boolean).filter((f) => fs.existsSync(f)),
}, null, 2) + "\n");
'

PROMPT_FILE="$(mktemp -t warden-review-prompt.XXXXXX)"

# ---- 3. assemble the prompt -------------------------------------------------
{
  cat <<HDR
You are performing a defensive assurance review of a Solana Anchor program: the Warden smart-account
wallet. You are not the author; no author framing is provided; verify the change independently.

THE RANGE UNDER REVIEW IS THE COMMIT RANGE  ${BASE_SHA}..${HEAD_SHA}
The repository is checked out at ${HEAD_SHA}. Obtain the diff yourself, e.g.:
    git diff ${BASE_SHA}..${HEAD_SHA}
    git diff --stat ${BASE_SHA}..${HEAD_SHA}
Read whole files where the diff is not self-explanatory. Review ONLY changes in that range, but you
may read anything in the tree to decide whether a change in the range is safe.
HDR
  cat <<'HDR'

RULES OF THIS ROUND
1. SILENCE ON A SEEDED INVARIANT IS A FAIL, NOT A PASS. Return exactly one entry in
   `invariant_verdicts` for EVERY seeded invariant id below — no more, no fewer, no duplicates. Echo
   the same ids back in `seeded_invariants`. `not_reviewed` is a failure of the round. The list is
   checked against the one the wrapper computed before you ran; shortening it is detected.
2. `truth_status` and `evidence_type` are ORTHOGONAL and must never be collapsed. Everything you raise
   enters as POTENTIAL. Do not mark anything CONFIRMED without an evidence artefact you can name
   (red_test, static_trace, formal_counterexample, config_attestation, primary_source). "No red test"
   does NOT mean inconclusive: static traces, supply-chain and dependency-provenance issues,
   key-management and release-credential failures, upgrade-authority misconfiguration, economic/MEV
   and liveness attacks, and formal counterexamples are all real and mostly unreproducible as a
   LiteSVM test.
3. If a reproducer is feasible, describe one that FAILS at the base SHA and PASSES at the fixed SHA.
   "Fails on HEAD" is the wrong predicate. If a reproducer is infeasible, set `reproducer` to null and
   give `reproducer_infeasible_reason`; the finding is NOT downgraded for lacking one.
4. DO NOT propose rewriting working code. Report defects, not preferences.
5. STANDING CHECKLIST — DIMENSIONAL AND SCALING BUGS. Units, decimals and scaling on every arithmetic
   path: lamports vs SOL, token base units vs UI amounts, bps vs fractions, seconds vs slots, u64 vs
   i64 vs u32 truncation. A cbETH/ETH ratio used as if USD-denominated cost Moonwell $1.78M and a
   human reviewer missed it. This class is structurally invisible to free-form review.
6. STANDING CHECKLIST — LICENSING. Does this diff reproduce structure, naming or comments recognisably
   from Swig, Squads or Backpack? Those are AGPL/GPL and reference-only. Flag it; do not adjudicate it.
7. Read every SIBLING FILE listed below before ruling, and list them in `sibling_files_read`. The one
   false positive in the Phase 1A pilot came from reviewer scope, not model identity: a property
   documented as knowingly deferred, in a file the reviewer had not been shown.
8. Output MUST be a single JSON object conforming to the supplied output schema, and it MUST carry
   `base_sha`, `head_sha`, `thread` and `reviewer_model`. No prose outside the JSON.
HDR
  echo "9. FINDING IDS ARE WRAPPER-OWNED. If you raise findings, assign them contiguously in output"
  echo "   order beginning at ${FINDING_ID_START}; do not reuse any lower WRDF id. A zero-finding"
  echo "   response is valid. The independent validator rejects any other allocation."
  cat <<'HDR'
10. PRESERVE REVIEW CONTEXT. Keep every shell result narrowly bounded: start with `--stat`/`--name-only`,
   use `rg -n` and targeted line ranges, and do not print an entire large file or an entire diff over
   500 lines. The seeded rows and prior-art corpus are already in this prompt; do not dump them again.
   Read required sibling files in bounded chunks. Do not explore unrelated refs, worktrees, reflogs, or
   unreachable objects unless a changed evidence citation requires one exact ancestry/object check.
   Once the changed code, its direct callers/tests, seeded invariants, siblings, and prior-art classes
   are decided, return the typed JSON promptly; repeated re-reading does not strengthen the review.
11. KEEP ALL OUTPUT STRICTLY DEFENSIVE AND CONCISE. Describe a defect only as a validation mismatch:
   name the affected function, the violated invariant, the state shape that must be rejected, and the
   expected fail-closed error. Do not narrate an unauthorized actor's objective or benefit; do not
   describe asset movement, transaction construction, payload composition, invocation ordering,
   operational feasibility, executable bytes, or a step-by-step sequence. Do not use exploit-guide
   language. In `rationale`, give only the bounded source trace that proves the missing validation.
   In `reproducer`, name a defensive regression fixture and its expected rejection at a high level;
   the remediation owner can implement it from the cited source locations. If more detail would be
   needed, omit it and cite the relevant file and line instead. This is an assurance artefact whose
   sole purpose is to make the implementation fail closed.
HDR
  echo
  echo "BASE SHA: $BASE_SHA"
  echo "HEAD SHA: $HEAD_SHA"
  echo
  echo "SEEDED INVARIANTS — rule 1 applies to every id here ($(wc -w <<<"$SEED_IDS") of them):"
  echo "$SEED_IDS" | tr ' ' '\n' | sed 's/^/  - /'
  echo
  echo "$SEED_JSON"
  echo
  echo "SIBLING FILES CARRYING CROSS-CUTTING INVARIANTS — read all of these:"
  for f in "${SIBLINGS[@]}"; do [[ -f "$f" ]] && echo "  - $f"; done
  echo
  echo "CHANGED FILES IN RANGE:"
  echo "$CHANGED" | sed 's/^/  - /'
  echo
  echo "PRIOR-ART FINDINGS CORPUS — check the range against every class below (mandatory every round;"
  echo "source of truth: $PRIOR_ART):"
  echo
  cat "$PRIOR_ART"
} > "$PROMPT_FILE"

# ---- 4. build the codex invocation ------------------------------------------
# Plain `codex exec`, NOT `codex exec review` — see the header. Read-only sandbox: the model needs a
# shell to run `git diff` and read files, and must not be able to write.
#
# The schema handed to --output-schema is DERIVED from the canonical one at runtime, because
# OpenAI's structured-output subset (observed live, 2026-08-20, two 400s) differs from JSON Schema:
#   * `allOf`/`if`/`then`, `oneOf` and `format` are rejected  → stripped / oneOf→anyOf;
#   * every property must appear in `required`               → optionals become required-but-
#     nullable, and step 6 strips those explicit nulls back out before validation.
# The transformations only change the ENCODING of optionality, never admit a value the canonical
# schema forbids — and step 6's independent validator enforces the FULL canonical schema on the
# canonicalized output. The API-side schema shapes generation; the validator is the gate.
API_SCHEMA="$OUT_DIR/warden-findings.openai.json"
SCHEMA="$SCHEMA" API_SCHEMA="$API_SCHEMA" node -e '
const fs = require("fs");
const nullable = (s) => {
  if (s && typeof s === "object") {
    if (s.$ref || s.anyOf) return { anyOf: [...(s.anyOf ?? [s]), { type: "null" }] };
    const withNullType =
      typeof s.type === "string" ? { ...s, type: [s.type, "null"] }
      : Array.isArray(s.type) && !s.type.includes("null") ? { ...s, type: [...s.type, "null"] }
      : s;
    // A nullable enum needs null IN the enum, not just in the type union.
    if (Array.isArray(withNullType.enum) && !withNullType.enum.includes(null))
      return { ...withNullType, enum: [...withNullType.enum, null] };
    return withNullType;
  }
  return s;
};
const walk = (n) => {
  if (Array.isArray(n)) return n.map(walk);
  if (!n || typeof n !== "object") return n;
  const out = {};
  for (const [k, v] of Object.entries(n)) {
    if (k === "allOf" || k === "if" || k === "then" || k === "else" || k === "format") continue;
    out[k === "oneOf" ? "anyOf" : k] = walk(v);
  }
  // Strict mode forbids keywords beside $ref (drops only annotations like description here —
  // constraint keywords never ride beside $ref in the canonical schema).
  if (out.$ref) return { $ref: out.$ref };
  // Strict mode requires an explicit `type` on every schema node; `const`/`enum` alone are
  // rejected. Infer it from the literal(s) — pure annotation, admits nothing new.
  if (!out.type && !out.$ref && !out.anyOf) {
    const sample = "const" in out ? out.const : Array.isArray(out.enum) ? out.enum[0] : undefined;
    if (sample !== undefined)
      out.type = sample === null ? "null" : Array.isArray(sample) ? "array" : typeof sample === "number" ? (Number.isInteger(sample) ? "integer" : "number") : typeof sample;
  }
  if (out.properties && typeof out.properties === "object") {
    const originallyRequired = new Set(Array.isArray(out.required) ? out.required : []);
    for (const key of Object.keys(out.properties)) {
      if (!originallyRequired.has(key)) out.properties[key] = nullable(out.properties[key]);
    }
    out.required = Object.keys(out.properties);
  }
  return out;
};
fs.writeFileSync(process.env.API_SCHEMA,
  JSON.stringify(walk(JSON.parse(fs.readFileSync(process.env.SCHEMA, "utf8"))), null, 2) + "\n");
'
CODEX_ARGS=(exec
  --output-schema "$API_SCHEMA"
  --ephemeral
  -s read-only
  -C "$REVIEW_ROOT"
  -o "$OUT_PATH"
  -m "$MODEL"
  -c "model_reasoning_effort=$EFFORT"
  # A caller-owned include/exclude policy must not strip the raw-object pin from reviewer tool
  # shells. Replace the policy at the CLI layer: preserve the caller environment needed by Codex,
  # apply the default secret-name exclusions, clear filters, then inject the one required Git
  # control after exclusions (WRDF-0160; Codex config reference: shell_environment_policy.set).
  -c 'shell_environment_policy={inherit="all",ignore_default_excludes=false,filters={},set={GIT_NO_REPLACE_OBJECTS="1"}}'
)
# Tool-free by default: nothing to fetch, nothing to be prompt-injected through.
# CAVEAT (UNVERIFIED): `-c mcp_servers={}` relies on the value parsing as an empty TOML inline table
# and on that clearing rather than merging the server map. No real review has been run from this
# script yet. If a round comes back with MCP tool calls in it, drop to `--ignore-user-config` (which
# skips $CODEX_HOME/config.toml entirely, auth aside) and pass every setting as -c. Relatedly, the
# claim that MCP servers silently disable --output-schema is from an unofficial blog and stays
# UNVERIFIED; running tool-free costs nothing and removes the variable either way.
[[ $WITH_TOOLS -eq 1 ]] || CODEX_ARGS+=(-c 'mcp_servers={}')

echo "==> range  $BASE_SHA..$HEAD_SHA"
echo "==> seeded $(wc -w <<<"$SEED_IDS") invariants: $SEED_IDS"
echo "==> expect $EXPECT"
echo "==> out    $OUT_PATH"
echo "==> codex ${CODEX_ARGS[*]} - < $PROMPT_FILE"

if [[ $DRY_RUN -eq 1 ]]; then
  echo
  echo "---- DRY RUN: expectations file written, prompt below, codex NOT invoked ----"
  cat "$PROMPT_FILE"
  exit 0
fi

# ---- 5. run ------------------------------------------------------------------
codex "${CODEX_ARGS[@]}" - < "$PROMPT_FILE"
[[ -s "$OUT_PATH" ]] || die "codex produced no output at $OUT_PATH"

# ---- 6. canonicalize, then validate independently against the WRAPPER's expectations --------
# The API-side schema forces optionals to be present-but-null (see step 4). Strip those explicit
# nulls back out — EXCEPT `reproducer`, where null is meaningful in the canonical schema (it means
# "infeasible", and must co-occur with reproducer_infeasible_reason) — then validate the result
# against the FULL canonical schema. The raw model output is preserved alongside as *.raw.json.
cp "$OUT_PATH" "${OUT_PATH%.json}.raw.json"
OUT="$OUT_PATH" node -e '
const fs = require("fs");
const strip = (n, key) => {
  if (Array.isArray(n)) return n.map((x) => strip(x, null));
  if (n && typeof n === "object") {
    const out = {};
    for (const [k, v] of Object.entries(n)) {
      if (v === null && k !== "reproducer") continue;
      out[k] = strip(v, k);
    }
    return out;
  }
  return n;
};
const doc = strip(JSON.parse(fs.readFileSync(process.env.OUT, "utf8")), null);
fs.writeFileSync(process.env.OUT, JSON.stringify(doc, null, 2) + "\n");
'
node "$REPO_ROOT/scripts/validate-findings.mjs" "$OUT_PATH" --schema "$SCHEMA" --expect "$EXPECT" --repo-root "$REVIEW_ROOT"

# ---- 7. record the RUN itself FIRST — zero-finding rounds included -----------------
# Re-validates independently (and refuses a replayed artefact) BEFORE any ledger mutation, so a
# rejected run leaves the scorecard untouched (WRDF-0007). Model and thread are wrapper-
# authoritative, and the artefact digest gives the run an immutable identity (WRDF-0002/-0003).
(cd "$REPO_ROOT" && node scripts/append-review-run.mjs "$OUT" --expect "$EXPECT" --kind "$KIND" \
  --model "$MODEL@$EFFORT" --thread "$ROUND_ID" --effort "$EFFORT" --scorecard "$SCORECARD" \
  --repo-root "$REVIEW_ROOT")

# (The scorecard append now lives INSIDE append-review-run.mjs — one process writes both ledgers,
# run record first, with rollback on failure, so a rejected or interrupted round leaves neither a
# run row nor orphan scorecard lines. WRDF-0007.)

echo
echo "Next: adjudicate every finding (disputed and scoped-out included), record the ruling in"
echo "$SCORECARD, and update docs/security/invariants.jsonl in the SAME commit as the fix."
echo "A CONFIRMED finding knocks its invariant row down; a task is not done while its invariants sit at llm-asserted."
