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
Usage: scripts/deploy-gate.sh <program-id> <expected-authority> <squads-multisig> <release-sha> [--dry-run] [--rpc-url <url>]
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

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --rpc-url) RPC_URL="${2:-}"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

# Base58 pubkeys are 32-44 chars from the base58 alphabet (no 0, O, I, l).
is_pubkey() {
  [[ "$1" =~ ^[1-9A-HJ-NP-Za-km-z]{32,44}$ ]]
}

status=0
fail() { echo "REFUSE: $1" >&2; status=1; }

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
echo "-- check 1/5: ProgramData upgrade_authority_address == expected authority --"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "[dry-run] would run: solana program show --url <rpc> $PROGRAM_ID (or getAccountInfo on the ProgramData PDA)"
  echo "[dry-run] would assert: upgrade_authority_address == $EXPECTED_AUTHORITY"
else
  fail "check 1 (upgrade authority) NOT IMPLEMENTED — no RPC client wired into this script yet; see docs/security/DEPLOY-GATE.md 'What's stubbed'"
fi

echo
echo "-- check 2/5: Squads multisig governance == spec §5.5 exactly (3-of-5, time_lock >= 7d) --"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "[dry-run] would fetch: Squads multisig config account at $SQUADS_MULTISIG"
  # Spec §5.5 pins an EXACT governance shape, not a floor: "the BPF-loader
  # upgrade authority IS a Squads multisig (3-of-5)". threshold and member
  # count are asserted == (not >=) — a 4-of-7 multisig is not what spec §5.5
  # authorized, even though it is nominally "stronger"; time_lock is the one
  # field with an explicit floor (>= 7 days) since a longer lock is strictly
  # safer, unlike a different threshold/membership shape.
  echo "[dry-run] would assert: threshold == 3 AND member_count == 5 AND time_lock_secs >= $((7*24*3600))"
else
  fail "check 2 (multisig governance) NOT IMPLEMENTED — needs the Squads SDK to decode the account; see docs/security/DEPLOY-GATE.md 'What's stubbed'"
fi

echo
echo "-- check 3/5: adapter selectors re-derived from source, diffed against on-chain Registry --"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "[dry-run] would re-derive: Anchor IDL sighash per target, or per-program instruction tag for non-Anchor targets (spec §5.2 rule 1 / DECISION.md C9)"
  echo "[dry-run] would diff against: on-chain Registry account contents"
else
  fail "check 3 (adapter selector diff) NOT IMPLEMENTED — programs/warden has no Registry account yet (DECISION.md C9 is open); see docs/security/DEPLOY-GATE.md 'What's stubbed'"
fi

echo
echo "-- check 4/5: deployed .so hash matches docs/security/RELEASE-INTEGRITY.md row --"
RELEASE_INTEGRITY_DOC="docs/security/RELEASE-INTEGRITY.md"
if [ ! -f "$RELEASE_INTEGRITY_DOC" ]; then
  fail "$RELEASE_INTEGRITY_DOC is missing"
else
  # The per-release table's rows are markdown-table lines starting with
  # `| ` and containing the release SHA in the second cell. Match loosely
  # (short or full SHA) since the table records full SHAs.
  row="$(grep -F "$RELEASE_SHA" "$RELEASE_INTEGRITY_DOC" | grep '^| ' || true)"
  if [ -z "$row" ]; then
    fail "no row for release-sha '$RELEASE_SHA' found in $RELEASE_INTEGRITY_DOC"
  else
    echo "found row:"
    echo "$row"
    # Extract the sha256 cell (3rd `|`-delimited field after the tag/label
    # and git-SHA columns) — best-effort; a 64-hex-char token in the row.
    recorded_hash="$(echo "$row" | grep -oE '[0-9a-f]{64}' | head -1 || true)"
    if [ -z "$recorded_hash" ]; then
      fail "could not extract a sha256 hash from the matched row in $RELEASE_INTEGRITY_DOC"
    else
      echo
      echo "   4a. on-chain hash (the authoritative comparison — what is actually"
      echo "       deployed, not what happens to be sitting in a local build dir):"
      if [ "$DRY_RUN" -eq 1 ]; then
        echo "   [dry-run] would dump the ON-CHAIN program (e.g. \`solana-verify"
        echo "   get-program-hash --url <rpc> $PROGRAM_ID\`, or a raw getAccountInfo"
        echo "   of the ProgramData account's code buffer, hashed the same way"
        echo "   target/deploy/warden.so is) and assert it equals $recorded_hash"
      else
        fail "4a. on-chain hash dump NOT IMPLEMENTED — no RPC client wired into this script yet; see docs/security/DEPLOY-GATE.md 'What's stubbed'"
      fi
      echo
      echo "   4b. local .so sanity check (best-effort, NOT a substitute for 4a —"
      echo "       a local build dir can be stale or tampered independently of"
      echo "       what is actually on-chain):"
      if [ -f target/deploy/warden.so ]; then
        local_hash="$(sha256sum target/deploy/warden.so | awk '{print $1}')"
        if [ "$local_hash" != "$recorded_hash" ]; then
          fail "4b. target/deploy/warden.so sha256 ($local_hash) != RELEASE-INTEGRITY.md row ($recorded_hash)"
        else
          echo "   OK: local target/deploy/warden.so matches recorded hash $recorded_hash"
        fi
      else
        # A missing local artifact is a FAILURE, not a note: a deploy gate
        # that shrugs at "nothing to check" and lets the overall check pass
        # is exactly the silent-pass failure mode this gate exists to close.
        fail "4b. target/deploy/warden.so not found locally — cannot verify; refusing rather than passing with nothing checked"
      fi
    fi
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
