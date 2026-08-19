#!/usr/bin/env bash
# =============================================================================
# scripts/review.sh — Warden adversarial review round (assurance layer L2)
#
# USAGE
#   scripts/review.sh <base-sha> [head]            run a review of base..head
#   scripts/review.sh <base-sha> --dry-run         print the prompt + command, run nothing
#   scripts/review.sh --validate <findings.json>   validate an existing findings file only
#
#   Options:
#     --dry-run        assemble everything, print the exact codex invocation, do not call codex
#     --with-tools     do NOT clear the MCP server table (default is tool-free)
#     --title <s>      passed through to codex as --title
#     --out <path>     override the output path (default .superpowers/reviews/<head-sha>.json)
#
# WHAT IT DOES
#   1. Refuses to run on a dirty tree.  `codex review --base <sha>` on a dirty tree repeats
#      HALLUCINATED findings unrelated to the diff — openai/codex#8404. A review run on a dirty
#      tree is void, not merely noisy.
#   2. Seeds the prompt with (a) the invariant rows whose code_ref/evidence paths overlap the
#      diff, (b) docs/security/PRIOR-ART-FINDINGS.md, (c) the named sibling files carrying
#      cross-cutting invariants. The one false positive in the Phase 1A pilot came from reviewer
#      SCOPE, not model identity.
#   3. Runs tool-free, blind (no author framing) and anti-rewrite.
#   4. Writes typed JSON to .superpowers/reviews/<sha>.json (gitignored — .superpowers/ is never
#      committed; this is a public repo).
#   5. Validates that JSON with an INDEPENDENT validator (scripts/validate-findings.mjs). The
#      --output-schema flag constrains the model's FINAL RESPONSE, not every JSONL event, so it is
#      never sufficient on its own.
#   6. Prints a summary and appends each finding to docs/security/REVIEW-SCORECARD.jsonl.
#
# CLI FACTS, VERIFIED AGAINST codex-cli 0.147.0 ON THIS HOST (2026-08-19)
#   * `codex exec review` EXISTS and is the subcommand to use. It accepts:
#       --base <BRANCH> · --commit <SHA> · --uncommitted · --output-schema <FILE> · --ephemeral
#       --json · -o/--output-last-message <FILE> · -m/--model · -c/--config key=value
#       --title · --ignore-user-config · --ignore-rules · --enable/--disable · --strict-config
#   * The TOP-LEVEL `codex review` also exists but has NO --output-schema, NO --ephemeral and NO
#     -m/--model. Do not use it here.
#   * `codex exec review` has NO -p/--profile flag (unlike `codex exec`, which does). So the review
#     profile at $CODEX_HOME/warden-review.config.toml CANNOT be selected for this subcommand in
#     0.147.0 — its settings are passed as -c overrides below instead. Profiles do resolve from
#     $CODEX_HOME/<name>.config.toml (NOT a repo-local .codex/profiles/ path); the constraint is the
#     missing flag, not the location.
#   * `codex exec review` has NO -s/--sandbox and NO -C/--cd flag.
#   * --base is documented as taking a BRANCH. We resolve the argument with `git rev-parse` first and
#     pass the resolved SHA; that a raw SHA is accepted has NOT been verified by a live run — if it
#     is rejected, use `--commit <sha>` or pass a branch name.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SCHEMA=".codex/schemas/warden-findings.json"
PRIOR_ART="docs/security/PRIOR-ART-FINDINGS.md"
LEDGER="docs/security/invariants.jsonl"
SCORECARD="docs/security/REVIEW-SCORECARD.jsonl"
OUT_DIR=".superpowers/reviews"
MODEL="gpt-5.6-sol"
EFFORT="max"
SIBLINGS=(
  "programs/warden/src/root_verify/transcript.rs"
  "programs/warden/src/state/session.rs"
  "programs/warden/src/errors.rs"
  "programs/warden/src/buckets.rs"
)

die() { echo "error: $*" >&2; exit 1; }

# ---- --validate mode --------------------------------------------------------
if [[ "${1:-}" == "--validate" ]]; then
  [[ -n "${2:-}" ]] || die "usage: scripts/review.sh --validate <findings.json>"
  exec node scripts/validate-findings.mjs "$2" "$SCHEMA"
fi

DRY_RUN=0; WITH_TOOLS=0; TITLE=""; OUT=""; BASE=""; HEAD_REF="HEAD"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift;;
    --with-tools) WITH_TOOLS=1; shift;;
    --title) TITLE="${2:?}"; shift 2;;
    --out) OUT="${2:?}"; shift 2;;
    -h|--help) sed -n '2,45p' "$0"; exit 0;;
    -*) die "unknown option $1";;
    *) if [[ -z "$BASE" ]]; then BASE="$1"; else HEAD_REF="$1"; fi; shift;;
  esac
done
[[ -n "$BASE" ]] || die "usage: scripts/review.sh <base-sha> [head] [--dry-run]"

command -v codex >/dev/null || die "codex CLI not found on PATH"
command -v node  >/dev/null || die "node not found on PATH"
[[ -f "$SCHEMA"    ]] || die "missing $SCHEMA"
[[ -f "$PRIOR_ART" ]] || die "missing $PRIOR_ART — every review prompt must seed it"
[[ -f "$LEDGER"    ]] || die "missing $LEDGER"

BASE_SHA="$(git rev-parse --verify "$BASE^{commit}" 2>/dev/null)" || die "not a commit: $BASE"
HEAD_SHA="$(git rev-parse --verify "$HEAD_REF^{commit}")"

# ---- 1. clean tree is a hard precondition (openai/codex#8404) ---------------
if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is dirty." >&2
  echo "  codex review --base <sha> on a dirty tree repeats HALLUCINATED findings unrelated to" >&2
  echo "  the diff (openai/codex#8404). Commit or stash first; a dirty-tree run is void." >&2
  git status --short >&2
  exit 1
fi

# ---- 2. work out which invariants overlap the diff --------------------------
CHANGED="$(git diff --name-only "$BASE_SHA" "$HEAD_SHA")"
[[ -n "$CHANGED" ]] || die "no changes between $BASE_SHA and $HEAD_SHA"

SEED_JSON="$(CHANGED="$CHANGED" node -e '
const fs = require("fs");
const changed = (process.env.CHANGED || "").split("\n").filter(Boolean);
const rows = fs.readFileSync("docs/security/invariants.jsonl", "utf8")
  .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
const touches = (p) => p && changed.some((c) => c === p.split(":")[0] || p.split(":")[0].startsWith(c));
const hit = rows.filter((r) => touches(r.code_ref) || (r.evidence || []).some((e) => touches(e.path)));
// a diff that adds a brand-new surface touches no existing code_ref: fall back to the phase.
const out = hit.length ? hit : rows.filter((r) => r.status === "unimplemented");
process.stdout.write(JSON.stringify(out.map((r) => ({ id: r.id, title: r.title, statement: r.statement, status: r.status, prior_art: r.prior_art, notes: r.notes })), null, 1));
')"
SEED_IDS="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).map(r=>r.id).join(", "))' "$SEED_JSON")"
[[ -n "$SEED_IDS" ]] || die "no invariants selected — refusing to run an unseeded review"

mkdir -p "$OUT_DIR"
[[ -n "$OUT" ]] || OUT="$OUT_DIR/${HEAD_SHA:0:12}.json"
PROMPT_FILE="$(mktemp -t warden-review-prompt.XXXXXX)"
trap 'rm -f "$PROMPT_FILE"' EXIT

# ---- 3. assemble the prompt -------------------------------------------------
{
  cat <<'HDR'
You are performing an adversarial security review of a Solana Anchor program (the Warden smart-account
wallet). Review the diff ONLY against the invariants and prior-art classes seeded below. You are not
the author and no author framing is provided; do not assume the change is correct.

RULES OF THIS ROUND
1. SILENCE ON A SEEDED INVARIANT IS A FAIL, NOT A PASS. Return exactly one entry in
   `invariant_verdicts` for every seeded invariant id. `not_reviewed` is a failure of the round.
2. `truth_status` and `evidence_type` are ORTHOGONAL axes and must never be collapsed. Everything you
   raise enters as POTENTIAL. Do not mark anything CONFIRMED without an evidence artefact you can name
   (red_test, static_trace, formal_counterexample, config_attestation, primary_source). "No red test"
   does NOT mean inconclusive: static traces, supply-chain and dependency-provenance issues,
   key-management and release-credential failures, upgrade-authority misconfiguration, economic/MEV and
   liveness attacks, and formal counterexamples are all real and mostly unreproducible as a LiteSVM test.
3. If a reproducer is feasible, describe one that FAILS at base_sha and PASSES at the fixed SHA.
   "Fails on HEAD" is the wrong predicate. If a reproducer is infeasible, set `reproducer` to null and
   give `reproducer_infeasible_reason`; the finding is NOT downgraded for lacking one.
4. DO NOT propose rewriting working code. Report defects, not preferences. Unnecessary rewrites are a
   measured source of regressions.
5. STANDING CHECKLIST — DIMENSIONAL AND SCALING BUGS. Check units, decimals and scaling on every
   arithmetic path: lamports vs SOL, token base units vs UI amounts, bps vs fractions, seconds vs slots,
   u64 vs i64 vs u32 truncation. A cbETH/ETH ratio used as if USD-denominated cost Moonwell $1.78M and a
   human reviewer missed it. This class is structurally invisible to free-form review.
6. STANDING CHECKLIST — LICENSING. Does this diff reproduce structure, naming or comments recognisably
   from Swig, Squads or Backpack? Those are AGPL/GPL and reference-only. Flag it; do not adjudicate it.
7. Read the SIBLING FILES listed below before ruling. The one false positive in the Phase 1A pilot came
   from reviewer scope, not model identity: a property documented as knowingly deferred in a file the
   reviewer had not been shown.
8. Output MUST be a single JSON object conforming to the supplied output schema. No prose outside it.
HDR
  echo
  echo "BASE SHA: $BASE_SHA"
  echo "HEAD SHA: $HEAD_SHA"
  echo
  echo "SEEDED INVARIANTS (rule 1 applies to every id here):"
  echo "$SEED_JSON"
  echo
  echo "SIBLING FILES CARRYING CROSS-CUTTING INVARIANTS — read all of these:"
  for f in "${SIBLINGS[@]}"; do [[ -f "$f" ]] && echo "  - $f"; done
  echo
  echo "CHANGED FILES:"
  echo "$CHANGED" | sed 's/^/  - /'
  echo
  echo "PRIOR-ART FINDINGS CORPUS — check the diff against every class below (mandatory every round):"
  echo "  (source of truth: $PRIOR_ART)"
  echo
  cat "$PRIOR_ART"
} > "$PROMPT_FILE"

# ---- 4. build the codex invocation ------------------------------------------
CODEX_ARGS=(exec review
  --base "$BASE_SHA"
  --output-schema "$SCHEMA"
  --ephemeral
  -o "$OUT"
  -c "model=$MODEL"
  -c "model_reasoning_effort=$EFFORT"
)
# Tool-free by default: nothing to fetch, nothing to be prompt-injected through. `codex exec review`
# has no --profile flag in 0.147.0, so the profile's settings are passed as -c overrides.
# CAVEAT (UNVERIFIED): `-c mcp_servers={}` relies on the value parsing as an empty TOML inline table
# and on that clearing the server map rather than merging with it. It has NOT been confirmed by a live
# run — no real review has been executed from this script yet. If a round comes back with tool calls in
# it, drop to `--ignore-user-config` (which skips $CODEX_HOME/config.toml entirely, auth aside) and pass
# every setting as -c. Related and also UNVERIFIED: the claim that MCP servers silently disable
# --output-schema comes from an unofficial blog and stays UNVERIFIED until a local 0.147 test
# reproduces it; running tool-free costs nothing and removes the variable either way.
[[ $WITH_TOOLS -eq 1 ]] || CODEX_ARGS+=(-c 'mcp_servers={}')
[[ -n "$TITLE" ]] && CODEX_ARGS+=(--title "$TITLE")

echo "==> base   $BASE_SHA"
echo "==> head   $HEAD_SHA"
echo "==> seeded $SEED_IDS"
echo "==> out    $OUT"
echo "==> codex ${CODEX_ARGS[*]} < $PROMPT_FILE"

if [[ $DRY_RUN -eq 1 ]]; then
  echo
  echo "---- DRY RUN: prompt below, codex NOT invoked ----"
  cat "$PROMPT_FILE"
  exit 0
fi

# ---- 5. run ------------------------------------------------------------------
codex "${CODEX_ARGS[@]}" - < "$PROMPT_FILE"
[[ -s "$OUT" ]] || die "codex produced no output at $OUT"

# ---- 6. validate independently ----------------------------------------------
node scripts/validate-findings.mjs "$OUT" "$SCHEMA"

# ---- 7. append every finding to the scorecard (disputed and scoped-out too) --
OUT="$OUT" node -e '
const fs = require("fs");
const doc = JSON.parse(fs.readFileSync(process.env.OUT, "utf8"));
const date = new Date().toISOString().slice(0, 10);
const lines = doc.findings.map((f) => JSON.stringify({
  finding_id: f.id, thread: doc.thread, date,
  reviewer_model: f.reviewer_model || doc.reviewer_model || null,
  base_sha: doc.base_sha, severity: f.severity,
  truth_status: f.truth_status, evidence_type: f.evidence_type,
  invariant_ids: f.invariant_ids, prior_art_cited: f.prior_art_cited || [],
  ruling: f.adjudication ? f.adjudication.ruling : "pending",
  ruled_by: f.adjudication ? f.adjudication.by : null,
  rationale: f.adjudication ? f.adjudication.rationale : f.rationale,
  reproducer_verified: !!(f.reproducer && f.reproducer.verified),
}));
if (lines.length) fs.appendFileSync("docs/security/REVIEW-SCORECARD.jsonl", lines.join("\n") + "\n");
console.error(`appended ${lines.length} finding(s) to docs/security/REVIEW-SCORECARD.jsonl`);
'

echo
echo "Next: adjudicate every finding (including disputed and scoped-out ones), record the ruling in"
echo "$SCORECARD, and update docs/security/invariants.jsonl in the SAME commit as the fix."
echo "A CONFIRMED finding knocks its invariant row down; a task is not done while its invariants sit at llm-asserted."
