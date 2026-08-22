#!/usr/bin/env bash
# L7 deployment gate (spec §17, plan Task 11 item 5).
# Full spec: docs/security/DEPLOY-GATE.md — read that first.
#
# Refuses to deploy (non-zero exit) on any check failure OR any check that
# is not yet wired up for real (fail-closed). See DEPLOY-GATE.md "What's
# stubbed in this Task-11 pass" for exactly which checks are live today.
#
# Usage:
#   scripts/deploy-gate.sh <program-id> <expected-authority> <squads-multisig> <release-sha> [--dry-run] [--rpc-url <url>]
#
# --dry-run performs only the checks that need no RPC, and prints (never
# executes) the RPC-dependent ones. No network calls are made in --dry-run
# mode, ever — this is what tests and CI exercise.
set -euo pipefail
# Resolve the script dir without an external `dirname` (one less PATH-resolved binary
# on the way to a verdict, WRDF-0092). After this cd, the repo root is the CWD and all
# in-repo helpers are referenced by repo-relative path.
_sd="${0%/*}"; [ "$_sd" = "$0" ] && _sd="."
cd "$_sd/.."

usage() {
  cat >&2 <<'EOF'
Usage: scripts/deploy-gate.sh <program-id> <expected-authority> <squads-multisig> <release-sha> [options]
  --dry-run                 print the plan, run only the local checks (no RPC)
  --fixtures <case>         run checks 1/2/4a against a deterministic scenario (no RPC)
  --manifest <name> --rpc-url <url>
                            live run: pin from the COMMITTED manifest registry (never a file);
                            requires a clean tree with the release-sha an ancestor of HEAD (WRDF-0085).
                            The per-proposal governance audit fails closed in-tool (WRDF-0028).
EOF
  exit 2
}

if [ "$#" -lt 4 ]; then
  usage
fi

PROGRAM_ID="$1"; shift
EXPECTED_AUTHORITY="$1"; shift
SQUADS_MULTISIG="$1"; shift
RELEASE_SHA="$1"; shift

DRY_RUN=0
RPC_URL="${SOLANA_RPC_URL:-}"
FIXTURE_CASE=""   # Task 11R: run the governance+hash checks against a deterministic scenario
MANIFEST=""       # Task 11R: a COMMITTED manifest NAME for a real run (WRDF-0085, never a file path)

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --rpc-url) RPC_URL="${2:-}"; shift 2 ;;
    --fixtures) FIXTURE_CASE="${2:-}"; shift 2 ;;
    --manifest) MANIFEST="${2:-}"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

# `fail` and `status` MUST be defined before the preflight that calls them
# (WRDF-0088 — a "fail: command not found" would fail-closed only by luck).
status=0
fail() { echo "REFUSE: $1" >&2; status=1; }

# Base58 pubkeys are 32-44 chars from the base58 alphabet (no 0, O, I, l).
is_pubkey() {
  [[ "$1" =~ ^[1-9A-HJ-NP-Za-km-z]{32,44}$ ]]
}

# The Task 11R governance+hash verifier (DEPLOY-GATE.md checks 1, 2, 4a). Hand-rolled
# in packages/core/src/deploy (no @sqds dependency). Invoked via the REPO's OWN
# toolchain by ABSOLUTE path — never a bare `pnpm`/`tsx` resolved through the caller's
# $PATH, never a command-override env var (WRDF-0092).
#
# TRUST BOUNDARY (WRDF-0092 round 10, docs/security/DEPLOY-GATE-TRUST-ROOT.md):
# The gate AUTHENTICATES the verifier's verdict-bearing SOURCE — verify_source_attestation
# re-hashes the committed closure (docs/security/verifier-attestation.json) and refuses on
# any missing/altered file or a decoy entrypoint, independently of the clean-tree check
# (which is blind to gitignored node_modules). Below the attested source, the JS runtime
# and its module transpiler/resolver (node, tsx, packages/core/node_modules) are the
# DECLARED trust-root terminus: an actor who can replace a file there already has local
# write/execute on the deploy host and can equally replace this script, the node binary,
# or the shell — no in-repo mechanism defends a compromised local host. This is the same
# external THREATMODEL assumption already accepted for the Squads audited-code hash
# (WRDF-0017 r6) and the trusted-RPC assumption. A hermetic test injects ITS OWN temp
# repo's tsx (a controlled test repo populating its own node_modules), not production PATH.
REPO_ROOT="$(pwd)"
DEPLOY_VERIFIER_TSX="$REPO_ROOT/packages/core/node_modules/.bin/tsx"
DEPLOY_VERIFIER_ENTRY_REL="packages/core/scripts/deploy-gate-verify.ts"
DEPLOY_VERIFIER_JS="$REPO_ROOT/$DEPLOY_VERIFIER_ENTRY_REL"
VERIFIER_ATTESTATION="docs/security/verifier-attestation.json"
run_gov_hash_verifier() {
  "$DEPLOY_VERIFIER_TSX" "$DEPLOY_VERIFIER_JS" "$@"
}

# Authenticate the verifier SOURCE the toolchain will consume, before any invocation.
# Refuses on: missing manifest, entrypoint identity mismatch, or any attested file that
# is missing or whose sha256 differs from the committed pin. Parses the canonical
# manifest lines (`"<path>.ts": "<64hex>"`); the exact serialization is drift-guarded by
# packages/core/test/deploy-attestation.test.ts, and the entrypoint line (a .ts VALUE,
# not a hex value) is deliberately excluded from the file loop and checked separately.
verify_source_attestation() {
  [ -f "$VERIFIER_ATTESTATION" ] || { fail "verifier attestation manifest missing: $VERIFIER_ATTESTATION"; return; }
  local want_entry
  want_entry="$(grep -oE '"entrypoint": *"[^"]+"' "$VERIFIER_ATTESTATION" | sed -E 's/.*: *"([^"]+)"/\1/')"
  [ "$want_entry" = "$DEPLOY_VERIFIER_ENTRY_REL" ] \
    || { fail "attestation entrypoint '$want_entry' != gate entrypoint '$DEPLOY_VERIFIER_ENTRY_REL'"; return; }
  local n=0 path want got
  while IFS='|' read -r path want; do
    [ -n "$path" ] || continue
    n=$((n+1))
    [ -f "$path" ] || { fail "attested verifier source missing: $path"; continue; }
    got="$(sha256sum "$path" | cut -d' ' -f1)"
    [ "$got" = "$want" ] || fail "attested verifier source altered (sha256 mismatch): $path"
  done < <(grep -oE '"[^"]+\.ts": *"[0-9a-f]{64}"' "$VERIFIER_ATTESTATION" | sed -E 's/"([^"]+)": *"([0-9a-f]{64})"/\1|\2/')
  [ "$n" -ge 1 ] || fail "attestation manifest listed no verifier source files"
}

# ---- WRDF-0085: bind a live run to the release, without self-reference --------
# A commit cannot contain its own SHA, so the RELEASE-INTEGRITY row for release
# commit C (which names C + the manifest token) is ADDED in a LATER, reviewed
# commit — the attestation point. So a live run binds like this: (a) a CLEAN tree;
# (b) C resolves to a FULL commit id that is an ANCESTOR-OR-EQUAL of HEAD (C is in
# the reviewed history the gate runs over); (c) the row parsing + unique
# manifest-name/digest + artifact-hash binding is done by the verifier (testable
# TS), reading the release-sha and the RELEASE-INTEGRITY file — the shell forwards
# identifiers, never trusted values it derived itself.
RELEASE_FULL_SHA=""
if [ "$DRY_RUN" -eq 0 ] && [ -z "$FIXTURE_CASE" ] && [ -n "$MANIFEST" ]; then
  # The git-only checkout binding lives in the separately-tested deploy-preflight.sh
  # (clean tree + release-sha resolves + ancestor-of-HEAD). Merge stdout+stderr:
  # on success stdout is the full SHA; on refusal stderr carries the reason.
  if pf_out="$(bash scripts/deploy-preflight.sh "$RELEASE_SHA" 2>&1)"; then
    RELEASE_FULL_SHA="$pf_out"
  else
    fail "${pf_out#REFUSE: }"
  fi
fi

echo "== L7 deploy gate =="
echo "program-id:          $PROGRAM_ID"
echo "expected-authority:  $EXPECTED_AUTHORITY"
echo "squads-multisig:     $SQUADS_MULTISIG"
echo "release-sha:         $RELEASE_SHA"
echo "mode:                $([ "$DRY_RUN" -eq 1 ] && echo dry-run || echo REAL)"
echo

echo "-- arg sanity --"
is_pubkey "$PROGRAM_ID" || fail "program-id '$PROGRAM_ID' does not look like a base58 pubkey"
is_pubkey "$EXPECTED_AUTHORITY" || fail "expected-authority '$EXPECTED_AUTHORITY' does not look like a base58 pubkey"
is_pubkey "$SQUADS_MULTISIG" || fail "squads-multisig '$SQUADS_MULTISIG' does not look like a base58 pubkey"
[[ "$RELEASE_SHA" =~ ^[0-9a-f]{7,40}$ ]] || fail "release-sha '$RELEASE_SHA' does not look like a git SHA"

echo
echo "-- verifier source attestation (committed sha256 closure, WRDF-0092) --"
# FATAL, not deferred: an unauthenticated verifier source must NEVER be executed — so we
# refuse here, before any run_gov_hash_verifier invocation, rather than letting a forged
# verifier run and merely marking the aggregate exit nonzero.
verify_source_attestation
if [ "$status" -ne 0 ]; then
  echo "== L7 deploy gate: REFUSE TO DEPLOY (verifier source attestation failed) ==" >&2
  exit 1
fi
echo "   OK: verifier source closure matches the committed attestation"

echo
echo "-- checks 1, 2, 4a: governance + release-hash (deploy-gate-verify, Task 11R) --"
echo "   (upgrade authority chain, pinned Squads 3-of-5 governance, on-chain program hash)"

# Extract the recorded release hash via the ONE canonical parser (WRDF-0085 round
# 7) — the same `parseReleaseRow` the verifier uses, so the local (.so) check and
# the on-chain check can never bind different rows. No second shell grep parser.
# A missing file / no row / ambiguous row / missing hash all fail closed.
RELEASE_INTEGRITY_DOC="docs/security/RELEASE-INTEGRITY.md"
RELEASE_INTEGRITY_ABS="$(pwd)/$RELEASE_INTEGRITY_DOC"  # absolute: pnpm exec runs the verifier in packages/core
recorded_hash=""
if [ ! -f "$RELEASE_INTEGRITY_DOC" ]; then
  fail "$RELEASE_INTEGRITY_DOC is missing"
else
  # Resolve to a full 40-hex commit id so the canonical parser (which requires the
  # full SHA) can key on the Git-SHA column exactly. Falls back to the raw arg only
  # if it is already a full SHA not resolvable in a shallow/foreign checkout.
  parse_sha="$(git rev-parse --verify "${RELEASE_SHA}^{commit}" 2>/dev/null || echo "$RELEASE_SHA")"
  if recorded_hash="$(run_gov_hash_verifier --parse-release-hash 1 --release-sha "$parse_sha" --release-integrity-file "$RELEASE_INTEGRITY_ABS" 2>/dev/null)"; then
    recorded_hash="$(printf '%s' "$recorded_hash" | tr -d '[:space:]')"
    # The canonical parser must yield EXACTLY one lowercase 64-hex hash (WRDF-0092).
    [[ "$recorded_hash" =~ ^[0-9a-f]{64}$ ]] || { recorded_hash=""; fail "canonical parse did not return a single 64-hex artifact hash"; }
  else
    recorded_hash=""
    fail "canonical parse of the RELEASE-INTEGRITY row for '$RELEASE_SHA' failed (no unique row / no artifact hash / bad token)"
  fi
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo "[dry-run] would run: deploy-gate-verify against the pinned config, asserting:"
  echo "  1  Warden Program->ProgramData chain (BPF-loader owned), upgrade_authority == derived Squads vault PDA"
  echo "  2  the multisig IS the pinned pubkey, owned by the pinned Squads program, discriminator-checked,"
  echo "     threshold == 3 AND member_count == 5 AND time_lock >= $((7*24*3600))s AND configAuthority == default"
  echo "     AND no actionable stale governance state AND the complete member set + permission masks,"
  echo "     AND the Squads program code hash == the pinned audited hash (trust-root terminus)"
  echo "  4a on-chain Warden program code hash == RELEASE-INTEGRITY.md row (${recorded_hash:-<none>})"
elif [ -n "$FIXTURE_CASE" ]; then
  echo "[fixtures] deterministic scenario: $FIXTURE_CASE"
  if run_gov_hash_verifier --fixtures "$FIXTURE_CASE"; then
    echo "   OK: governance+hash checks passed for fixture '$FIXTURE_CASE'"
  else
    fail "governance+hash checks failed for fixture '$FIXTURE_CASE'"
  fi
elif [ -n "$MANIFEST" ] && [ -n "$RPC_URL" ]; then
  # Forward the REQUIRED shell identities so the verifier cross-checks them against
  # the committed manifest + derived vault (WRDF-0085). The per-proposal governance
  # audit fails closed in-tool with NO bypass (WRDF-0028).
  if [ -z "$recorded_hash" ]; then
    fail "cannot run the live governance+hash checks without a release-integrity hash"
  elif run_gov_hash_verifier --rpc-url "$RPC_URL" --manifest "$MANIFEST" \
        --release-sha "$RELEASE_FULL_SHA" --release-integrity-file "$RELEASE_INTEGRITY_ABS" \
        --expect-warden-program "$PROGRAM_ID" --expect-multisig "$SQUADS_MULTISIG" --expect-authority "$EXPECTED_AUTHORITY"; then
    echo "   OK: live governance+hash checks passed against $RPC_URL"
  else
    fail "live governance+hash checks failed (see output above)"
  fi
else
  fail "checks 1/2/4a NOT RUN — supply --fixtures <case> for the fixture-verified path, or --manifest <name> + --rpc-url <url> for a live run (the pin is a COMMITTED, reviewed manifest selected by name — never an arbitrary file; CLI pubkeys alone cannot pin the member set/masks/code hash — WRDF-0017/0085)"
fi

echo
echo "-- check 3/5: adapter selectors re-derived from source, diffed against on-chain Registry (WRD-DEP-02) --"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "[dry-run] would re-derive: Anchor IDL sighash per target, or per-program instruction tag for non-Anchor targets (spec §5.2 rule 1 / DECISION.md C9)"
  echo "[dry-run] would diff against: on-chain Registry account contents"
else
  fail "check 3 (adapter selector diff, WRD-DEP-02) NOT IMPLEMENTED — a separate deliverable from Task 11R (scope boundary WRDF-0018); the Registry exists (Task 3) but the selector re-derivation + diff tool is not wired here yet"
fi

echo
echo "-- check 4b/5: local target/deploy/warden.so hash == RELEASE-INTEGRITY.md row (best-effort sanity) --"
if [ -n "$recorded_hash" ]; then
  echo "recorded hash: $recorded_hash"
  if [ -f target/deploy/warden.so ]; then
    local_hash="$(sha256sum target/deploy/warden.so | awk '{print $1}')"
    if [ "$local_hash" != "$recorded_hash" ]; then
      fail "4b. target/deploy/warden.so sha256 ($local_hash) != RELEASE-INTEGRITY.md row ($recorded_hash)"
    else
      echo "   OK: local target/deploy/warden.so matches recorded hash $recorded_hash"
    fi
  else
    # A missing local artifact is a FAILURE, not a note (silent-pass is the failure
    # mode this gate exists to close).
    fail "4b. target/deploy/warden.so not found locally — cannot verify; refusing rather than passing with nothing checked"
  fi
fi

echo
echo "-- check 5/5: scoped TODO/unimplemented!/#[ignore] scan (programs/, packages/) --"
hits="$(git grep -nE 'TODO|unimplemented!|#\[ignore\]' -- programs packages 2>/dev/null || true)"
if [ -n "$hits" ]; then
  echo "$hits"
  fail "shipped source contains TODO/unimplemented!/#[ignore] — see hits above"
else
  echo "none found"
fi

echo
if [ "$DRY_RUN" -eq 1 ]; then
  # Never claim success for a dry run: checks 1-3 are only ever printed as a
  # plan in this mode (real mode is the only mode that can fail them), so a
  # clean dry-run exit means "the plan looks sane and the two local-only
  # checks passed" — it is explicitly NOT a verified deploy decision.
  echo "== L7 deploy gate: DRY RUN — NOT VERIFIED =="
  echo "   (checks 1-3 were only printed as a plan; run without --dry-run"
  echo "   against a real RPC endpoint, once wired, for an actual verdict)"
elif [ "$status" -ne 0 ]; then
  echo "== L7 deploy gate: REFUSE TO DEPLOY =="
else
  echo "== L7 deploy gate: ALL CHECKS PASSED =="
fi
exit "$status"
