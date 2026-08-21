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
cd "$(dirname "$0")/.."

usage() {
  cat >&2 <<'EOF'
Usage: scripts/deploy-gate.sh <program-id> <expected-authority> <squads-multisig> <release-sha> [options]
  --dry-run                 print the plan, run only the local checks (no RPC)
  --fixtures <case>         run checks 1/2/4a against a deterministic scenario (no RPC)
  --manifest <name> --rpc-url <url>
                            live run: pin from the COMMITTED manifest registry (never a file);
                            requires a clean tree with HEAD == the release-sha commit (WRDF-0085).
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
# in packages/core/src/deploy (no @sqds dependency); run via the workspace's tsx.
run_gov_hash_verifier() {
  pnpm --filter @warden/core exec tsx scripts/deploy-gate-verify.ts "$@"
}

# ---- WRDF-0085: bind the release-sha to a UNIQUE, checkout-bound manifest -----
# A live run must (a) execute AT the exact reviewed release commit on a clean tree,
# so the committed manifest registry IS the reviewed release's, and (b) select the
# manifest the RELEASE-INTEGRITY row bound (name @ canonical digest) — NOT a free
# operator choice. RELEASE_MANIFEST_NAME / _DIGEST are extracted from the matched
# row below and forwarded to the verifier, which refuses a name/digest mismatch.
RELEASE_MANIFEST_NAME=""
RELEASE_MANIFEST_DIGEST=""
if [ "$DRY_RUN" -eq 0 ] && [ -z "$FIXTURE_CASE" ] && [ -n "$MANIFEST" ]; then
  if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    fail "live run requires a CLEAN working tree (uncommitted changes could alter the manifest or gate code)"
  fi
  resolved_head="$(git rev-parse HEAD 2>/dev/null || echo '')"
  resolved_release="$(git rev-parse "$RELEASE_SHA^{commit}" 2>/dev/null || echo '')"
  if [ -z "$resolved_release" ]; then
    fail "release-sha '$RELEASE_SHA' does not resolve to a commit in this repo"
  elif [ "$resolved_head" != "$resolved_release" ]; then
    fail "HEAD ($resolved_head) != resolved release-sha ($resolved_release) — a live gate must run AT the reviewed release commit (WRDF-0085)"
  fi
  # Extract the release-bound manifest token `manifest:<name>@<digest>` from the row.
  rel_row="$(grep -F "$RELEASE_SHA" docs/security/RELEASE-INTEGRITY.md 2>/dev/null | grep '^| ' | head -1 || true)"
  tok="$(printf '%s' "$rel_row" | grep -oE 'manifest:[A-Za-z0-9_.-]+@[0-9a-f]{64}' | head -1 || true)"
  if [ -z "$tok" ]; then
    fail "release-sha '$RELEASE_SHA' has no bound manifest token (manifest:<name>@<digest>) in RELEASE-INTEGRITY.md (WRDF-0085)"
  else
    RELEASE_MANIFEST_NAME="${tok#manifest:}"; RELEASE_MANIFEST_NAME="${RELEASE_MANIFEST_NAME%@*}"
    RELEASE_MANIFEST_DIGEST="${tok#*@}"
    if [ "$MANIFEST" != "$RELEASE_MANIFEST_NAME" ]; then
      fail "--manifest '$MANIFEST' != release-bound manifest '$RELEASE_MANIFEST_NAME' (the release-sha selects a unique manifest — WRDF-0085)"
    fi
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
echo "-- checks 1, 2, 4a: governance + release-hash (deploy-gate-verify, Task 11R) --"
echo "   (upgrade authority chain, pinned Squads 3-of-5 governance, on-chain program hash)"

# Extract the recorded release hash up front — the verifier's live mode needs it,
# and check 4b (local .so) reuses it. A missing row is fatal (fail-closed).
RELEASE_INTEGRITY_DOC="docs/security/RELEASE-INTEGRITY.md"
recorded_hash=""
if [ ! -f "$RELEASE_INTEGRITY_DOC" ]; then
  fail "$RELEASE_INTEGRITY_DOC is missing"
else
  row="$(grep -F "$RELEASE_SHA" "$RELEASE_INTEGRITY_DOC" | grep '^| ' || true)"
  if [ -z "$row" ]; then
    fail "no row for release-sha '$RELEASE_SHA' found in $RELEASE_INTEGRITY_DOC"
  else
    recorded_hash="$(echo "$row" | grep -oE '[0-9a-f]{64}' | head -1 || true)"
    [ -z "$recorded_hash" ] && fail "could not extract a sha256 hash from the matched row in $RELEASE_INTEGRITY_DOC"
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
  elif run_gov_hash_verifier --rpc-url "$RPC_URL" --manifest "$MANIFEST" --manifest-digest "$RELEASE_MANIFEST_DIGEST" --expected-hash "$recorded_hash" \
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
