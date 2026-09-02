#!/usr/bin/env bash
# =============================================================================
# scripts/review-grok.sh — Warden adversarial review round, GROK lane (assurance layer L2)
#
# USAGE
#   scripts/review-grok.sh <base-sha> [head]            review base..head
#   scripts/review-grok.sh <base-sha> <old-head> --historical  review an old head in a temporary,
#                                                            detached read-only worktree
#   scripts/review-grok.sh <base-sha> [head] --dry-run  assemble everything, invoke nothing
#   scripts/review-grok.sh --selftest                   check node/fetch, key resolution, inputs
#   scripts/review-grok.sh --validate <f.json> [--expect <f>]   validate an existing findings file
#
#   Options: --dry-run · --out <path> · --model <m> · --kind <k> · --max-chars <n> ·
#            --max-tokens <n> · --finding-id-start <WRDF-NNNN> · --historical · --no-full-files
#
# WHY THIS EXISTS
#   scripts/review.sh is the canonical recorded lane (Codex, gpt-5.6-sol@max). It has now been
#   blocked three rounds running by OpenAI's cyber content filter ("flagged for possible
#   cybersecurity risk") on ranges containing our OWN defensive regression tests — tests that
#   deliberately execute a token drain to prove a vulnerability was real. That is a documented
#   false-positive class, but the effect is that the assurance methodology has a SINGLE-PROVIDER
#   dependency and no round over those ranges can be recorded at all.
#   This script makes Grok (xAI) a FIRST-CLASS RECORDED reviewer on the same integrity machinery,
#   so a block on one provider no longer stalls the loop. It is not a "second opinion" lane: its
#   rounds land in REVIEW-RUNS.jsonl / REVIEW-SCORECARD.jsonl through exactly the same validator
#   and the same recorder as the Codex lane. (The grok MCP server at
#   ~/.claude/mcp-servers/grok/server.mjs remains the UNRECORDED second-opinion path.)
#
# WHAT IT DOES — the same six safeguards as review.sh, for the same reasons
#   1. Refuses to run on a dirty integration tree. The review worktree must be exactly <head>:
#      normally that is the integration checkout; --historical instead creates a temporary,
#      detached worktree at the requested old head while the current wrapper and integration
#      scorecard remain authoritative. (Grok cannot read the worktree at all, but the wrapper reads
#      it ON ITS BEHALF to build the prompt.)
#   2. The WRAPPER computes the seed list ITSELF from docs/security/invariants.jsonl and writes it,
#      with both SHAs and the sibling-file list, to an EXPECTATIONS file. The validator checks the
#      model's output against THAT file, never against the model's own account of what it was
#      asked. Without this the anti-silence rule is self-reported and therefore worthless.
#   3. Validates the artefact with the INDEPENDENT validator (scripts/validate-findings.mjs)
#      against the canonical schema + the expectations file.
#   4. Hands the artefact to scripts/append-review-run.mjs, which re-validates it independently,
#      refuses replays, writes BOTH ledgers in one process and rolls them back together on any
#      failure (WRDF-0007). This script NEVER writes a ledger row itself.
#   5. Same round-id / artefact naming convention under .superpowers/reviews/.
#   6. --dry-run assembles everything and invokes nothing; --validate is a passthrough.
#
# THE ONE REAL DIFFERENCE: GROK HAS NO SHELL
#   `codex exec` runs in a read-only sandbox and is simply TOLD the range, so review.sh can say
#   "run `git diff` yourself" and "read these sibling files". The xAI chat-completions API has no
#   tools and no filesystem. Everything the reviewer is allowed to see must therefore be EMBEDDED
#   in the prompt by this wrapper:
#     * the full `git diff <base>..<head>` and the changed-file list;
#     * the seeded invariant JSON, the prior-art corpus, and the sibling files' CONTENTS
#       (review.sh only LISTS sibling paths — Codex can open them; Grok cannot);
#     * the full current contents of changed .rs/.ts source files, because whole-file context is
#       what makes a correctness judgement possible rather than a diff-window guess;
#     * the canonical JSON schema, inline, because xAI does not accept a full JSON Schema the way
#       codex's --output-schema does.
#   Consequence: the prompt is the ENTIRE evidence base of the round. It is therefore saved next to
#   the artefact as <round>.prompt.txt so a recorded round is reproducible.
#
# SIZE BUDGET AND COMPLETENESS — ELISION ABORTS THE ROUND
#   Embedding all of that can exceed any context. Sections are budgeted (see ASSEMBLER below) and
#   anything over budget is truncated MIDDLE-OUT — head and tail both carry signal (a diff's first
#   hunks and its last hunks are equally load-bearing; a Rust file's imports and its test module
#   are at opposite ends). The assembler still reports every would-be elision with exact byte
#   counts, but the wrapper then aborts before the API call and before either ledger append. The
#   canonical schema deliberately has no publishable "insufficient context" verdict, so a partial
#   evidence base cannot produce a recordable assurance round. Raise --max-chars and rerun.
#
# API-SIDE SHAPING vs THE GATE
#   The request sets response_format={"type":"json_object"} and inlines the canonical schema in the
#   prompt. Mirroring review.sh's stance exactly: the API-side constraint SHAPES GENERATION, and
#   scripts/validate-findings.mjs REMAINS THE GATE. json_object mode guarantees only well-formed
#   JSON, not a conforming document — nothing is trusted merely because the flag was passed.
#
# reviewer_model IS WRAPPER-AUTHORITATIVE
#   A model's self-report of its own identity is not trustworthy (it will happily echo whatever the
#   prompt's example showed, including the Codex model id). The recorded reviewer_model is taken
#   from the API RESPONSE's `model` field, falling back to the configured id — never from the
#   document the model produced. See step 6.
#
# !!! DUPLICATED PROMPT TEXT — KEEP IN SYNC WITH scripts/review.sh !!!
#   The "RULES OF THIS ROUND" block below (8 numbered rules: anti-silence, orthogonal
#   truth_status/evidence_type, the base-fails/fixed-passes reproducer predicate, no-rewrites, the
#   dimensional-and-scaling standing checklist, the licensing standing checklist, siblings, JSON
#   output) is a DELIBERATE DUPLICATE of the block in scripts/review.sh. It was not factored out
#   into a shared file because review.sh is currently the only lane with recorded rounds and must
#   not be touched. THE DEBT IS REAL: if you change a rule in one lane and not the other, the two
#   lanes stop reviewing under the same contract and their findings stop being comparable — which
#   is the entire point of having a second provider. Change both, together, or factor them out.
#   (The mirror-image warning could not be added to review.sh: this change is forbidden from
#   modifying that file. Grep for "RULES OF THIS ROUND" to find both sites.)
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REVIEW_ROOT="$REPO_ROOT"
HISTORICAL_ROOT=""
TMPD=""
cd "$REPO_ROOT"

SCHEMA="$REPO_ROOT/.codex/schemas/warden-findings.json"
PRIOR_ART="docs/security/PRIOR-ART-FINDINGS.md"
LEDGER="docs/security/invariants.jsonl"
SCORECARD="$REPO_ROOT/docs/security/REVIEW-SCORECARD.jsonl"
OUT_DIR="$REPO_ROOT/.superpowers/reviews"
# The configured model id. It is a FALLBACK for the recorded reviewer_model; the API response's
# own `model` field wins when present. Never a copy of the Codex lane's id.
MODEL="${XAI_TEXT_MODEL:-grok-4.3}"
ENDPOINT="${XAI_ENDPOINT:-https://api.x.ai/v1/chat/completions}"
ENV_FILE="${XAI_ENV_FILE:-/opt/berthalla/.env}"
# Total prompt budget in characters, and the completion cap. A truncated COMPLETION yields invalid
# JSON, which fails validation loudly — it can never be mistaken for a clean round.
MAX_CHARS="${GROK_REVIEW_MAX_CHARS:-600000}"
MAX_TOKENS="${GROK_REVIEW_MAX_TOKENS:-32768}"
TIMEOUT_MS="${GROK_REVIEW_TIMEOUT_MS:-1800000}"
FULL_FILES=1
# Same list as review.sh — but here their CONTENTS are inlined, not just their paths.
SIBLINGS=(
  "programs/warden/src/root_verify/transcript.rs"
  "programs/warden/src/state/session.rs"
  "programs/warden/src/errors.rs"
  "programs/warden/src/buckets.rs"
)

die() { echo "error: $*" >&2; exit 1; }

# ---- --selftest: the contract this script depends on ------------------------
# The Codex lane asserts codex's CLI flags exist. The equivalent here is: a Node with global
# fetch, a resolvable key (NEVER printed), and the canonical inputs on disk. No network call.
if [[ "${1:-}" == "--selftest" ]]; then
  command -v node >/dev/null || die "node not found on PATH"
  echo "node: $(node --version)"
  node -e 'if (typeof fetch !== "function") { console.error("  MISSING global fetch (node >= 18 required)"); process.exit(1); } console.log("  ok      global fetch")'
  if [[ -n "${XAI_API_KEY:-}" ]]; then
    echo "  ok      xAI key resolved from \$XAI_API_KEY (value never printed)"
  elif [[ -f "$ENV_FILE" ]] && grep -qE '^[[:space:]]*XAI_API_KEY[[:space:]]*=' "$ENV_FILE"; then
    echo "  ok      xAI key resolved from $ENV_FILE (value never printed)"
  else
    echo "  MISSING xAI key: set XAI_API_KEY or put XAI_API_KEY= in $ENV_FILE"; exit 1
  fi
  rc=0
  for f in "$SCHEMA" "$PRIOR_ART" "$LEDGER" scripts/validate-findings.mjs scripts/append-review-run.mjs; do
    if [[ -f "$f" ]]; then echo "  ok      $f"; else echo "  MISSING $f"; rc=1; fi
  done
  [[ $rc -eq 0 ]] || die "inputs this script requires are missing"
  echo "selftest OK  (model=$MODEL endpoint=$ENDPOINT)"
  exit 0
fi

# ---- --validate mode --------------------------------------------------------
if [[ "${1:-}" == "--validate" ]]; then
  [[ -n "${2:-}" ]] || die "usage: scripts/review-grok.sh --validate <findings.json> [--expect <f>]"
  shift
  exec node "$REPO_ROOT/scripts/validate-findings.mjs" "$@" --schema "$SCHEMA" --repo-root "$REPO_ROOT"
fi

DRY_RUN=0; HISTORICAL=0; OUT=""; BASE=""; HEAD_REF="HEAD"; KIND="task-diff"; FINDING_ID_START=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift;;
    --out) OUT="${2:?}"; shift 2;;
    --model) MODEL="${2:?}"; shift 2;;
    --kind) KIND="${2:?}"; shift 2;;
    --max-chars) MAX_CHARS="${2:?}"; shift 2;;
    --max-tokens) MAX_TOKENS="${2:?}"; shift 2;;
    --finding-id-start) FINDING_ID_START="${2:?}"; shift 2;;
    --historical) HISTORICAL=1; shift;;
    --no-full-files) FULL_FILES=0; shift;;
    -h|--help) sed -n '2,40p' "$0"; exit 0;;
    -*) die "unknown option $1";;
    *) if [[ -z "$BASE" ]]; then BASE="$1"; else HEAD_REF="$1"; fi; shift;;
  esac
done
[[ -n "$BASE" ]] || die "usage: scripts/review-grok.sh <base-sha> [head] [--dry-run]"

command -v node >/dev/null || die "node not found on PATH"
command -v git  >/dev/null || die "git not found on PATH"

BASE_SHA="$(git -C "$REPO_ROOT" rev-parse --verify "$BASE^{commit}" 2>/dev/null)" || die "not a commit: $BASE"
HEAD_SHA="$(git -C "$REPO_ROOT" rev-parse --verify "$HEAD_REF^{commit}" 2>/dev/null)" || die "not a commit: $HEAD_REF"

# ---- 1. clean integration tree + an exact worktree for <head> ----------------
# Same refusal as review.sh, for a reason that is if anything STRONGER here: this wrapper reads an
# exact worktree to build the prompt (sibling contents, whole-file context) on Grok's behalf.
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]]; then
  echo "error: working tree is dirty." >&2
  echo "  A dirty-tree review is void: the whole-file context and sibling contents embedded in the" >&2
  echo "  prompt would not be the code in the range under review." >&2
  git -C "$REPO_ROOT" status --short >&2
  exit 1
fi
CURRENT_HEAD="$(git -C "$REPO_ROOT" rev-parse --verify HEAD)"
if [[ "$CURRENT_HEAD" != "$HEAD_SHA" ]]; then
  [[ $HISTORICAL -eq 1 ]] || die "checked-out HEAD is $CURRENT_HEAD but the requested head is $HEAD_SHA — check out $HEAD_SHA or pass --historical; the wrapper reads files from an exact worktree"
  HISTORICAL_ROOT="$(mktemp -d /tmp/warden-grok-review-worktree.XXXXXX)"
  rmdir "$HISTORICAL_ROOT"
  git -C "$REPO_ROOT" worktree add --detach "$HISTORICAL_ROOT" "$HEAD_SHA" >/dev/null
  REVIEW_ROOT="$HISTORICAL_ROOT"
fi
cleanup() {
  [[ -z "$TMPD" ]] || rm -rf "$TMPD"
  if [[ -n "$HISTORICAL_ROOT" ]]; then
    git -C "$REPO_ROOT" worktree remove --force "$HISTORICAL_ROOT" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
cd "$REVIEW_ROOT"
[[ -z "$(git status --porcelain)" ]] || die "review worktree is dirty: $REVIEW_ROOT"
[[ "$(git rev-parse --verify HEAD)" == "$HEAD_SHA" ]] || die "review worktree is not at $HEAD_SHA"
for f in "$SCHEMA" "$PRIOR_ART" "$LEDGER"; do [[ -f "$f" ]] || die "missing $f"; done

# ---- 2. seed list + expectations file (computed by the WRAPPER) -------------
# NOTE: steps 2's seeding logic is a deliberate duplicate of review.sh's, for the same reason as the
# rules block — the two lanes must seed IDENTICALLY or their rounds are not comparable. Keep in sync.
CHANGED="$(git diff --name-only "$BASE_SHA" "$HEAD_SHA")"
[[ -n "$CHANGED" ]] || die "no changes between $BASE_SHA and $HEAD_SHA"

mkdir -p "$OUT_DIR"
# Round id and artefact path are WRAPPER-owned (WRDF-0002/-0003), same convention as review.sh: the
# timestamp keeps a re-round over the same head from overwriting the previous artefact, and the
# round id — not the model's self-report — is what lands in the scorecard and run record.
ROUND_ID="${HEAD_SHA:0:12}-$(date -u +%Y%m%dT%H%M%SZ)"
[[ -n "$OUT" ]] || OUT=".superpowers/reviews/$ROUND_ID.json"
OUT_RECORD="$OUT"
if [[ "$OUT" = /* ]]; then OUT_PATH="$OUT"; else OUT_PATH="$REPO_ROOT/$OUT"; fi
OUT="$OUT_PATH"
EXPECT="${OUT%.json}.expect.json"
PROMPT_SAVE="${OUT%.json}.prompt.txt"

# Rows whose LEDGER ENTRY changed in the range are seeded too — a review of the commit that adds
# or edits an invariant must rule on that invariant (WRDF-0001). And every unimplemented row is
# ALWAYS seeded, never displaced by a narrow code hit: over-seeding is the safe direction.
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

# Finding ids belong to the committed scorecard namespace, not to one provider
# lane. Bind the next contiguous id into both the expectation gate and the prompt
# so a unique-but-out-of-sequence model-selected id cannot enter the ledger.
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
[[ "$FINDING_ID_START" =~ ^WRDF-[0-9]{4}$ && "$FINDING_ID_START" != "WRDF-0000" ]] ||
  die "--finding-id-start must be WRDF-0001..WRDF-9999 (got $FINDING_ID_START)"

SEED_JSON="$SEED_JSON" BASE_SHA="$BASE_SHA" HEAD_SHA="$HEAD_SHA" \
FINDING_ID_START="$FINDING_ID_START" \
SIBS="$(printf '%s\n' "${SIBLINGS[@]}")" EXPECT="$EXPECT" node -e '
const fs = require("fs");
fs.writeFileSync(process.env.EXPECT, JSON.stringify({
  base_sha: process.env.BASE_SHA, head_sha: process.env.HEAD_SHA,
  finding_id_start: process.env.FINDING_ID_START,
  seeded_invariants: JSON.parse(process.env.SEED_JSON).map((r) => r.id),
  sibling_files: process.env.SIBS.split("\n").filter(Boolean).filter((f) => fs.existsSync(f)),
}, null, 2) + "\n");
'

# ---- 3. assemble the prompt -------------------------------------------------
# Large material goes to the assembler through FILES, not environment variables: a 127 KB diff is
# within a hair of Linux's 128 KB per-string exec limit, and an E2BIG here would look like a
# mysterious assembler failure rather than what it is.
TMPD="$(mktemp -d -t warden-grok-review.XXXXXX)"
PROMPT_FILE="$TMPD/prompt.txt"

git diff "$BASE_SHA" "$HEAD_SHA" > "$TMPD/diff.txt"
printf '%s' "$SEED_JSON" > "$TMPD/seeds.json"
printf '%s\n' "$CHANGED" > "$TMPD/changed.txt"
printf '%s\n' "${SIBLINGS[@]}" > "$TMPD/siblings.txt"

# Whole-file context: changed .rs/.ts sources that still exist at HEAD. Deleted files are covered by
# the diff and cannot be read; generated/vendored JSON is not source and is excluded on purpose.
: > "$TMPD/fulls.txt"
if [[ $FULL_FILES -eq 1 ]]; then
  while IFS= read -r f; do
    [[ "$f" =~ \.(rs|ts)$ ]] || continue
    [[ "$f" =~ \.d\.ts$ ]] && continue
    [[ -f "$f" ]] || continue
    echo "$f" >> "$TMPD/fulls.txt"
  done <<< "$CHANGED"
fi

SEED_COUNT="$(wc -w <<<"$SEED_IDS" | tr -d ' ')"

# ---- the header + RULES OF THIS ROUND ---------------------------------------
# !!! THE RULES BLOCK BELOW IS DUPLICATED FROM scripts/review.sh — KEEP THE TWO IN SYNC. !!!
# Only rules 1's closing sentence, rule 7, rule 8 and provider-specific rule 9 differ:
# review.sh tells Codex to open the sibling files itself; here their contents are inlined, so the
# rule points at the inlined section instead of at the filesystem. Every other word is verbatim,
# deliberately: the two lanes must review under the same contract or their findings are not
# comparable, which is the whole reason for having a second provider. See the file header.
{
  cat <<HDR
You are performing an adversarial security review of a Solana Anchor program: the Warden smart-account
wallet. You are not the author; no author framing is provided; do not assume the change is correct.

THE RANGE UNDER REVIEW IS THE COMMIT RANGE  ${BASE_SHA}..${HEAD_SHA}

YOU HAVE NO SHELL AND NO FILESYSTEM. Everything you are permitted to see has been EMBEDDED below by
the wrapper that invoked you: the full diff, the changed-file list, the seeded invariants, the
sibling files' contents, the current contents of the changed source files, and the prior-art corpus.
Do not ask for a file and do not claim to have run a command. If a judgement genuinely depends on
material that is not below, say so explicitly in your rationale rather than guessing — an
"insufficient context" statement is a publishable result; a confident guess is not.
Review ONLY changes in that range; the surrounding material is there to let you decide whether a
change in the range is safe.
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
7. Read every SIBLING FILE below before ruling, and list them in `sibling_files_read`. Their full
   contents are inlined for you under "SIBLING FILES CARRYING CROSS-CUTTING INVARIANTS"; list the
   PATHS exactly as given there. The one false positive in the Phase 1A pilot came from reviewer
   scope, not model identity: a property documented as knowingly deferred, in a file the reviewer had
   not been shown.
8. Output MUST be a single JSON object conforming to the OUTPUT SCHEMA reproduced at the end of this
   prompt, and it MUST carry `base_sha`, `head_sha`, `thread` and `reviewer_model`. Copy `base_sha`
   and `head_sha` VERBATIM from the two lines below — they are checked against the wrapper's record
   and a paraphrase fails the round. No prose outside the JSON, no markdown fences.
HDR
  echo "9. FINDING IDS ARE WRAPPER-OWNED. If you raise findings, assign them contiguously in output"
  echo "   order beginning at ${FINDING_ID_START}; do not reuse any lower WRDF id. A zero-finding"
  echo "   response is valid. The independent validator rejects any other allocation."
} > "$TMPD/header.txt"

cat > "$TMPD/assemble.cjs" <<'ASM'
// Prompt assembler for the Grok lane. Budgets each embedded section, truncates MIDDLE-OUT, and
// reports every elision three ways: inline at the cut, in a notice at the TOP of the prompt (so the
// MODEL knows its evidence is partial), and on stderr (so the OPERATOR does). Nothing is ever
// shortened silently — a review of a silently shortened diff is a false green.
const fs = require("fs");
const path = require("path");

const env = process.env;
const read = (p) => fs.readFileSync(p, "utf8");
const lines = (p) => read(p).split("\n").map((s) => s.trim()).filter(Boolean);
const MAX = Number(env.ASM_MAX_CHARS);
const warnings = [];

/** Middle-out: a diff's first and last hunks are equally load-bearing, and a Rust file's imports
 *  and its `mod tests` sit at opposite ends. Cutting the tail off would bias every long input. */
function clamp(text, limit, label) {
  if (text.length <= limit) return text;
  const half = Math.max(0, Math.floor((limit - 260) / 2));
  const dropped = text.length - 2 * half;
  warnings.push({ section: label, total: text.length, kept: 2 * half, dropped });
  return (
    text.slice(0, half) +
    `\n\n[!!! ELIDED: ${dropped} of ${text.length} characters of ${label} were removed FROM THE MIDDLE ` +
    `(head and tail retained). THIS MATERIAL IS INCOMPLETE. If a verdict depends on what is missing, ` +
    `say so instead of guessing. !!!]\n\n` +
    text.slice(text.length - half)
  );
}

// ---- gather the sections ----------------------------------------------------
const header = read(env.ASM_HEADER);
const schema = read(env.ASM_SCHEMA);
const seedIds = env.ASM_SEED_IDS.split(/\s+/).filter(Boolean);
const seedJson = read(env.ASM_SEEDS);
const changed = lines(env.ASM_CHANGED);
const siblingPaths = lines(env.ASM_SIBLINGS).filter((f) => fs.existsSync(f));
const fullPaths = fs.existsSync(env.ASM_FULLS) ? lines(env.ASM_FULLS) : [];
const diff = read(env.ASM_DIFF);

const idList = seedIds.map((i) => `  - ${i}`).join("\n");
const changedList = changed.map((f) => `  - ${f}`).join("\n");
const siblingBody = siblingPaths
  .map((f) => `\n===== SIBLING FILE ${f} (${fs.statSync(f).size} bytes, at HEAD) =====\n${read(f)}`)
  .join("\n");

// ---- budget -----------------------------------------------------------------
// The FIXED material — rules, schema, seed ids, file lists — is never truncated: it defines the
// contract the round is judged against, and a shortened contract is not a cheaper round, it is an
// invalid one. It is charged against MAX first; what remains is shared out below.
const fixed = header.length + schema.length + idList.length + changedList.length + 4000;
if (MAX - fixed < 40000) {
  console.error(
    `error: --max-chars ${MAX} leaves only ${MAX - fixed} chars for the diff and context after the ` +
      `${fixed}-char fixed material (rules + schema + seed list). Raise --max-chars.`,
  );
  process.exit(1);
}

// Weighted max-min allocation: every section that wants less than its share donates the surplus to
// the ones that want more, repeatedly, so a small range is embedded COMPLETE and only a genuinely
// oversized one gets cut. Weights encode priority when there is not enough to go round.
const sections = [
  { key: "diff", weight: 0.4, want: diff.length },
  { key: "seeds", weight: 0.16, want: seedJson.length },
  { key: "siblings", weight: 0.14, want: siblingBody.length },
  { key: "fulls", weight: 0.2, want: fullPaths.reduce((a, f) => a + fs.statSync(f).size, 0) },
  { key: "prior_art", weight: 0.1, want: fs.statSync(env.ASM_PRIOR_ART).size },
];
let pool = MAX - fixed;
const alloc = Object.fromEntries(sections.map((s) => [s.key, 0]));
let open = sections.slice();
while (open.length && pool > 0) {
  const wsum = open.reduce((a, s) => a + s.weight, 0);
  let progressed = false;
  const still = [];
  let spent = 0;
  for (const s of open) {
    const share = Math.floor((pool * s.weight) / wsum);
    if (s.want <= share) {
      alloc[s.key] = s.want;
      spent += s.want;
      progressed = true;
    } else {
      still.push(s);
    }
  }
  if (!progressed) {
    for (const s of still) alloc[s.key] = Math.floor((pool * s.weight) / wsum);
    break;
  }
  pool -= spent;
  open = still;
}

// Whole-file context: max-min fair share ACROSS the files, smallest first, so small files arrive
// whole and only the largest ones are cut. A file's own budget is then applied middle-out.
let fullsBody = "";
if (fullPaths.length) {
  const items = fullPaths
    .map((f, i) => ({ f, i, text: read(f) }))
    .sort((a, b) => a.text.length - b.text.length);
  let left = items.length;
  let filePool = alloc.fulls;
  for (const it of items) {
    const share = Math.max(0, Math.floor(filePool / left));
    it.keep = Math.min(it.text.length, share);
    filePool -= it.keep;
    left--;
  }
  fullsBody = items
    .sort((a, b) => a.i - b.i)
    .map((it) =>
      it.keep < 400
        ? `\n===== FILE ${it.f} =====\n[!!! OMITTED ENTIRELY: ${it.text.length} chars did not fit the whole-file context budget. ` +
          `Only the diff hunks for this file are available to you. !!!]`
        : `\n===== FILE ${it.f} (${it.text.length} bytes, at HEAD) =====\n` +
          clamp(it.text, it.keep, `whole-file context for ${it.f}`),
    )
    .join("\n");
  for (const it of items)
    if (it.keep < 400)
      warnings.push({ section: `whole-file context for ${it.f}`, total: it.text.length, kept: 0, dropped: it.text.length });
}

const seedsOut = clamp(seedJson, alloc.seeds, "seeded invariant details");
const siblingsOut = clamp(siblingBody, alloc.siblings, "sibling file contents");
const diffOut = clamp(diff, alloc.diff, `the diff ${env.ASM_BASE}..${env.ASM_HEAD}`);
const priorOut = clamp(read(env.ASM_PRIOR_ART), alloc.prior_art, "the prior-art corpus");

// ---- the completeness notice, at the TOP -------------------------------------
const notice = warnings.length
  ? "\nCONTEXT COMPLETENESS NOTICE — READ BEFORE RULING\n" +
    "Your evidence base is INCOMPLETE. The wrapper had to elide material to fit the budget:\n" +
    warnings
      .map((w) => `  - ${w.section}: ${w.dropped} of ${w.total} chars elided (${w.kept} kept, middle removed)`)
      .join("\n") +
    "\nWhere a verdict would depend on elided material, return it with an explicit statement that the\n" +
    "context was truncated. Do NOT infer the missing content. Do NOT mark an invariant `upheld`\n" +
    "because you could not see the code that would violate it — that is exactly the silence rule 1\n" +
    "forbids; say the context was insufficient in the rationale instead.\n"
  : "\nCONTEXT COMPLETENESS NOTICE\nEvery section below is COMPLETE — nothing was elided.\n";

const out =
  header +
  notice +
  `\nBASE SHA: ${env.ASM_BASE}\nHEAD SHA: ${env.ASM_HEAD}\n` +
  `\nSEEDED INVARIANTS — rule 1 applies to every id here (${seedIds.length} of them):\n${idList}\n` +
  `\n${seedsOut}\n` +
  `\nSIBLING FILES CARRYING CROSS-CUTTING INVARIANTS — read all of these (rule 7). Report these exact\npaths in \`sibling_files_read\`:\n` +
  siblingPaths.map((f) => `  - ${f}`).join("\n") +
  `\n${siblingsOut}\n` +
  `\nCHANGED FILES IN RANGE:\n${changedList}\n` +
  (fullPaths.length
    ? `\nWHOLE-FILE CONTEXT — the CURRENT (at ${env.ASM_HEAD}) contents of the changed source files, so a\njudgement can rest on the whole function rather than the diff window:\n${fullsBody}\n`
    : "\nWHOLE-FILE CONTEXT: not embedded for this round (no changed .rs/.ts sources, or --no-full-files).\n") +
  `\n===== DIFF ${env.ASM_BASE}..${env.ASM_HEAD} =====\n${diffOut}\n` +
  `\nPRIOR-ART FINDINGS CORPUS — check the range against every class below (mandatory every round;\nsource of truth: ${env.ASM_PRIOR_ART_PATH}):\n\n${priorOut}\n` +
  `\n===== OUTPUT SCHEMA — your single JSON object MUST conform to this exactly =====\n${schema}\n`;

fs.writeFileSync(env.ASM_OUT, out);
fs.writeFileSync(env.ASM_WARN, JSON.stringify(warnings, null, 2) + "\n");
for (const w of warnings)
  console.error(
    `WARNING: elided ${w.dropped} of ${w.total} chars from ${w.section} (kept ${w.kept}, middle removed)`,
  );
console.error(
  `assembled prompt: ${out.length} chars (budget ${MAX}; fixed ${fixed}; ` +
    Object.entries(alloc).map(([k, v]) => `${k}=${v}`).join(" ") +
    `) — ${warnings.length} elision(s)`,
);
if (warnings.length) {
  console.error(
    "error: refusing a recordable review with elided mandatory evidence; " +
      "raise --max-chars until the assembler reports zero elisions",
  );
  process.exit(2);
}
ASM

ASM_OUT="$PROMPT_FILE" ASM_WARN="$TMPD/warnings.json" ASM_HEADER="$TMPD/header.txt" \
ASM_SCHEMA="$SCHEMA" ASM_SEEDS="$TMPD/seeds.json" ASM_SEED_IDS="$SEED_IDS" \
ASM_CHANGED="$TMPD/changed.txt" ASM_SIBLINGS="$TMPD/siblings.txt" ASM_FULLS="$TMPD/fulls.txt" \
ASM_DIFF="$TMPD/diff.txt" ASM_PRIOR_ART="$PRIOR_ART" ASM_PRIOR_ART_PATH="$PRIOR_ART" \
ASM_BASE="$BASE_SHA" ASM_HEAD="$HEAD_SHA" ASM_MAX_CHARS="$MAX_CHARS" \
  node "$TMPD/assemble.cjs"

PROMPT_CHARS="$(wc -c < "$PROMPT_FILE" | tr -d ' ')"
# The prompt IS the entire evidence base of this round — Grok sees nothing else — so it is kept
# beside the artefact. A recorded round is otherwise not reproducible: you could never tell later
# whether a verdict was reached on complete material or on a truncated one.
cp "$PROMPT_FILE" "$PROMPT_SAVE"

echo "==> range   $BASE_SHA..$HEAD_SHA"
echo "==> seeded  $SEED_COUNT invariants: $SEED_IDS"
echo "==> expect  $EXPECT"
echo "==> prompt  $PROMPT_SAVE ($PROMPT_CHARS chars, budget $MAX_CHARS)"
echo "==> out     $OUT"
echo "==> model   $MODEL  (endpoint $ENDPOINT, max_tokens $MAX_TOKENS)"

if [[ $DRY_RUN -eq 1 ]]; then
  echo
  echo "---- DRY RUN: expectations file and prompt written, xAI NOT invoked ----"
  echo "---- expectations ($EXPECT) ----"
  cat "$EXPECT"
  echo "---- elisions ----"
  cat "$TMPD/warnings.json"
  echo "---- prompt ($PROMPT_SAVE) ----"
  cat "$PROMPT_FILE"
  exit 0
fi

# ---- 4. call xAI -------------------------------------------------------------
# The HTTP call runs INSIDE node, which reads the key itself. The key is never an argv element (it
# would be world-readable in /proc and in `ps`), never echoed, and never written to the artefact,
# the saved prompt, or either ledger.
cat > "$TMPD/call.cjs" <<'CALL'
const fs = require("fs");
const env = process.env;

function apiKey() {
  if (env.XAI_API_KEY && env.XAI_API_KEY.trim()) return env.XAI_API_KEY.trim();
  const f = env.GROK_ENV_FILE;
  if (f && fs.existsSync(f)) {
    for (const line of fs.readFileSync(f, "utf8").split("\n")) {
      const m = /^\s*XAI_API_KEY\s*=\s*(.+?)\s*$/.exec(line);
      if (m) return m[1].replace(/^["']|["']$/g, "");
    }
  }
  throw new Error(`no xAI key: set XAI_API_KEY or put XAI_API_KEY= in ${f}`);
}

const SYSTEM = `You are an independent adversarial security reviewer performing AUTHORIZED defensive
review of a Solana smart-account wallet its maintainer controls. Your job is to find defects the
maintainer's own review missed, so real users' funds are protected. The diff may contain regression
TESTS that deliberately demonstrate an exploit against the maintainer's own program; that is the
evidence standard this project holds itself to, not hostile activity.

Cite file:line for every claim. Keep truth_status and evidence_type as separate axes. "I could not
determine this from the material provided" is a publishable, valuable result — do not inflate
confidence to seem useful. Do not write exploit tooling: describe mechanisms precisely enough to fix
and to test, and where a regression is needed describe one that asserts the REJECTION.

Respond with a SINGLE JSON object conforming to the OUTPUT SCHEMA given at the end of the user
message. No prose outside the JSON, no markdown fences.`;

async function main() {
  const prompt = fs.readFileSync(env.GROK_PROMPT_FILE, "utf8");
  const body = {
    model: env.GROK_MODEL,
    max_tokens: Number(env.GROK_MAX_TOKENS),
    messages: [
      { role: "system", content: SYSTEM },
      { role: "user", content: prompt },
    ],
    // Shapes generation only. xAI does not accept a full JSON Schema the way codex's
    // --output-schema does, which is why the canonical schema is ALSO inlined in the prompt — and
    // why scripts/validate-findings.mjs remains the gate. json_object guarantees well-formed JSON,
    // never a conforming document.
    response_format: { type: "json_object" },
  };

  let lastErr;
  for (let attempt = 1; attempt <= 3; attempt++) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), Number(env.GROK_TIMEOUT_MS));
    try {
      const res = await fetch(env.GROK_ENDPOINT, {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey()}`, "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: ac.signal,
      });
      const raw = await res.text();
      if (!res.ok) {
        // Retry only what is worth retrying; a 400/401/403 is a contract or credential problem and
        // repeating it just burns time. The request body is never echoed back.
        const retryable = res.status === 429 || res.status >= 500;
        const e = new Error(`xAI HTTP ${res.status}: ${raw.slice(0, 800)}`);
        if (!retryable || attempt === 3) throw e;
        lastErr = e;
      } else {
        const parsed = JSON.parse(raw);
        const text = parsed?.choices?.[0]?.message?.content;
        if (typeof text !== "string" || !text.trim())
          throw new Error(`xAI response had no message content: ${raw.slice(0, 400)}`);
        const finish = parsed?.choices?.[0]?.finish_reason;
        fs.writeFileSync(env.GROK_RAW, text);
        // reviewer_model is taken from the RESPONSE, not from the document the model wrote: a
        // model's self-report of its own identity is untrusted (it will echo whatever id the
        // prompt's examples showed). Falls back to the configured id if the API omits it.
        fs.writeFileSync(env.GROK_MODEL_FILE, String(parsed.model || env.GROK_MODEL));
        const u = parsed.usage || {};
        console.error(
          `xAI ok: model=${parsed.model || env.GROK_MODEL} finish=${finish} ` +
            `prompt_tokens=${u.prompt_tokens ?? "?"} completion_tokens=${u.completion_tokens ?? "?"}`,
        );
        if (finish === "length")
          console.error(
            "WARNING: the completion hit max_tokens and is TRUNCATED — the JSON will not parse and " +
              "the round will fail validation. Re-run with a larger --max-tokens.",
          );
        // Strip a markdown fence if one slipped through, then re-emit canonical JSON. A parse
        // failure here is a hard failure: no artefact is written, so no round can be recorded.
        const fenced = /^\s*```(?:json)?\s*([\s\S]*?)\s*```\s*$/.exec(text);
        const doc = JSON.parse(fenced ? fenced[1] : text);
        fs.writeFileSync(env.GROK_OUT, JSON.stringify(doc, null, 2) + "\n");
        return;
      }
    } catch (e) {
      if (attempt === 3) throw e;
      lastErr = e;
    } finally {
      clearTimeout(timer);
    }
    await new Promise((r) => setTimeout(r, 2000 * attempt));
  }
  throw lastErr || new Error("xAI call failed");
}

main().catch((e) => {
  console.error(`error: ${e.message}`);
  process.exit(1);
});
CALL

RAW="${OUT%.json}.raw.json"
MODEL_FILE="$TMPD/model.txt"
GROK_PROMPT_FILE="$PROMPT_FILE" GROK_OUT="$OUT" GROK_RAW="$RAW" GROK_MODEL_FILE="$MODEL_FILE" \
GROK_MODEL="$MODEL" GROK_ENDPOINT="$ENDPOINT" GROK_ENV_FILE="$ENV_FILE" \
GROK_MAX_TOKENS="$MAX_TOKENS" GROK_TIMEOUT_MS="$TIMEOUT_MS" \
  node "$TMPD/call.cjs"
[[ -s "$OUT" ]] || die "xAI produced no output at $OUT"

# The model id that actually served the request. Wrapper-authoritative — see step 4's comment.
REVIEWER_MODEL="$(cat "$MODEL_FILE" 2>/dev/null || true)"
[[ -n "$REVIEWER_MODEL" ]] || REVIEWER_MODEL="$MODEL"

# ---- 5. canonicalize ---------------------------------------------------------
# Two fixes, both encoding-level only — neither admits a value the canonical schema forbids:
#   * explicit nulls for ABSENT optional fields are stripped (models emit `"suggested_fix": null`
#     for "none"; the canonical schema types that field as a string). `reproducer` is EXEMPT: null
#     is meaningful there — it means "infeasible" and must co-occur with the infeasible reason.
#     Same transformation, and the same exemption, as review.sh step 6.
#   * `reviewer_model` is OVERWRITTEN with the wrapper's value and `thread` is filled in when the
#     model left it empty. The self-report is not evidence of anything; the run record and the
#     scorecard take these from the wrapper anyway (append-review-run.mjs strips both from the
#     artefact digest), so making the artefact agree with the record removes a confusing mismatch
#     rather than laundering a claim.
OUT="$OUT" RM="$REVIEWER_MODEL" TID="$ROUND_ID" node -e '
const fs = require("fs");
const strip = (n) => {
  if (Array.isArray(n)) return n.map((x) => strip(x));
  if (n && typeof n === "object") {
    const out = {};
    for (const [k, v] of Object.entries(n)) {
      if (v === null && k !== "reproducer") continue;
      out[k] = strip(v);
    }
    return out;
  }
  return n;
};
const doc = strip(JSON.parse(fs.readFileSync(process.env.OUT, "utf8")));
doc.reviewer_model = process.env.RM;
if (!doc.thread || String(doc.thread).trim() === "") doc.thread = process.env.TID;
fs.writeFileSync(process.env.OUT, JSON.stringify(doc, null, 2) + "\n");
'

# ---- 6. validate independently against the WRAPPER's expectations ------------
node "$REPO_ROOT/scripts/validate-findings.mjs" "$OUT" --schema "$SCHEMA" --expect "$EXPECT" --repo-root "$REVIEW_ROOT"

# ---- 7. record the RUN itself — zero-finding rounds included ------------------
# append-review-run.mjs re-validates independently, refuses a replayed artefact, and writes BOTH
# ledgers in one process with rollback (WRDF-0007). This script never writes a ledger row itself.
# --effort is deliberately NOT passed: xAI exposes no reasoning-effort knob, and inventing one would
# put a fiction in the ledger. The run record carries effort: null, which is the honest value.
(cd "$REPO_ROOT" && node scripts/append-review-run.mjs "$OUT_RECORD" --expect "$EXPECT" --kind "$KIND" \
  --model "$REVIEWER_MODEL" --thread "$ROUND_ID" --scorecard "$SCORECARD" \
  --repo-root "$REVIEW_ROOT")

echo
echo "Next: adjudicate every finding (disputed and scoped-out included), record the ruling in"
echo "$SCORECARD, and update docs/security/invariants.jsonl in the SAME commit as the fix."
echo "A CONFIRMED finding knocks its invariant row down; a task is not done while its invariants sit at llm-asserted."
