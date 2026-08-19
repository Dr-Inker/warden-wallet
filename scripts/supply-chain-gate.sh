#!/usr/bin/env bash
# L9 supply-chain gate (spec §17, Task 11).
#
# Runs the dependency-provenance checks CI enforces as failing gates:
#   1. `cargo deny check` (advisories + bans + sources + licenses) against
#      the root workspace (`programs/*`), per `deny.toml`.
#   2. `pnpm install --frozen-lockfile` — fails if `pnpm-lock.yaml` would
#      change, i.e. it is not in sync with `package.json` files.
#   3. `pnpm audit --audit-level=high`, SCOPED to shipped code (spikes/
#      excluded — see the `evaluate_audit_json` comment below) and FAIL
#      CLOSED if the audit service itself is unavailable (see below).
#   4. A scoped `git grep` for TODO/FIXME/XXX markers under `programs/` and
#      `packages/` — informational only, never fails the gate. (The L7
#      deploy-time gate in `scripts/deploy-gate.sh` has its own, *fatal*,
#      narrower grep for TODO/unimplemented!/#[ignore] — see spec §17 L7
#      and the plan's Task 11 item 3. Keeping that scoped to `programs/` and
#      `packages/` only is deliberate: `docs/`, `spikes/` and the plan itself
#      legitimately contain those strings, and an unscoped grep fails
#      permanently and gets disabled, which is worse than not having it.)
#
# Exit status: non-zero if cargo-deny or the scoped pnpm audit fail. The
# TODO/FIXME/XXX report never affects the exit status.
#
# Usage:
#   scripts/supply-chain-gate.sh            # run for real
#   scripts/supply-chain-gate.sh --dry-run  # print what would run, do nothing
#   scripts/supply-chain-gate.sh --selftest # unit-check the audit-scoping
#                                            # jq logic against fixtures
#                                            # (including the fail-closed
#                                            # path) with no network/cargo
#                                            # calls at all
set -euo pipefail
cd "$(dirname "$0")/.."

# ---------------------------------------------------------------------------
# evaluate_audit_json — reads a `pnpm audit --json`-shaped payload on stdin,
# prints its verdict, and returns 0 (nothing blocking) or 1 (blocking, or
# the audit itself could not be trusted).
#
# FAILS CLOSED (returns 1) on any of:
#   - empty input
#   - input that isn't valid JSON
#   - a top-level "error" key (this is what pnpm emits when the audit
#     service/registry itself is unreachable or erroring — an unreachable
#     registry returning `{"error": {...}}` must never be read as "zero
#     advisories, so pass": that is exactly the fail-OPEN bug this function
#     exists to close)
#   - no "advisories" key at all (any other unexpected shape)
#
# Otherwise: drops any advisory whose EVERY finding path is entirely under
# a `spikes__*`-prefixed workspace project (pnpm's audit JSON prefixes each
# dependency path with the mangled importer name, e.g.
# `spikes__03-txbudget__ts>...`) — an advisory that also reaches shipped
# code through any OTHER path still blocks — then fails if any remaining
# advisory is high/critical severity.
#
# `pnpm audit` does NOT support `--filter` (verified 2026-08-19: `pnpm
# --filter '!./spikes/**' audit --audit-level=high` still reports the
# spikes-only bigint-buffer/uuid advisories — pnpm audits the whole merged
# lockfile regardless of any workspace filter passed before the `audit`
# subcommand), which is why this scopes via `--json` + jq instead. The
# non-blocking spikes-audit CI job (.github/workflows/ci.yml) covers
# spikes/ advisories on its own, separately, non-blocking.
# ---------------------------------------------------------------------------
evaluate_audit_json() {
  local json
  json="$(cat)"

  if [ -z "$json" ]; then
    echo "FAIL: audit unavailable — empty output, failing closed" >&2
    return 1
  fi
  if ! echo "$json" | jq -e . >/dev/null 2>&1; then
    echo "FAIL: audit unavailable — output is not valid JSON, failing closed" >&2
    return 1
  fi
  if echo "$json" | jq -e 'has("error")' >/dev/null 2>&1; then
    echo "FAIL: audit unavailable — audit service returned an error, failing closed: $(echo "$json" | jq -c '.error')" >&2
    return 1
  fi
  if ! echo "$json" | jq -e 'has("advisories")' >/dev/null 2>&1; then
    echo "FAIL: audit unavailable — output has no \"advisories\" key, failing closed" >&2
    return 1
  fi

  local scoped_hits scoped_count spikes_only_count
  scoped_hits="$(echo "$json" | jq '
    [.advisories | to_entries[] | .value
     | select(
         ((.findings | map(.paths) | add // []) | all(startswith("spikes__")))
         | not
       )
     | select(.severity == "high" or .severity == "critical")
    ]
  ')"
  scoped_count="$(echo "$scoped_hits" | jq 'length')"
  if [ "$scoped_count" -gt 0 ]; then
    echo "FAIL: $scoped_count high/critical advisory(ies) reach shipped code (outside spikes/):" >&2
    echo "$scoped_hits" | jq -r '.[] | "  - \(.module_name) (\(.severity)): \(.url)"' >&2
    return 1
  fi

  spikes_only_count="$(echo "$json" | jq '[.advisories | to_entries[] | select(.value.severity == "high" or .value.severity == "critical")] | length')"
  echo "OK: 0 high/critical advisories reach shipped code; $spikes_only_count high/critical advisory(ies) exist but are entirely under spikes/ (non-blocking; see the spikes-audit CI job)"
  return 0
}

# ---------------------------------------------------------------------------
# --selftest: fixtures for evaluate_audit_json, run with no network/cargo
# calls. This is the "test stub (feed the error JSON through the jq path)
# proving it fails" the round-3 review asked for, kept in the script itself
# so it stays next to the logic it tests rather than drifting from it.
# ---------------------------------------------------------------------------
run_selftest() {
  local failures=0

  check() {
    local name="$1" json="$2" expect="$3" actual
    if echo "$json" | evaluate_audit_json >/dev/null 2>&1; then
      actual=pass
    else
      actual=fail
    fi
    if [ "$actual" = "$expect" ]; then
      echo "SELFTEST OK:   $name (expected $expect, got $actual)"
    else
      echo "SELFTEST FAIL: $name (expected $expect, got $actual)"
      failures=$((failures + 1))
    fi
  }

  check "empty input fails closed" \
    "" fail

  check "non-JSON input fails closed" \
    "not json at all" fail

  check "audit-service error JSON fails closed (the bug this fixes)" \
    '{"error":{"code":"ENOTFOUND","summary":"getaddrinfo ENOTFOUND registry.npmjs.org"}}' fail

  check "missing advisories key fails closed" \
    '{"metadata":{}}' fail

  check "empty advisories object passes" \
    '{"advisories":{},"metadata":{}}' pass

  check "spikes-only high advisory passes (non-blocking)" \
    '{"advisories":{"1":{"severity":"high","module_name":"x","url":"u","findings":[{"paths":["spikes__foo__ts>bar"]}]}}}' pass

  check "non-spikes critical advisory fails" \
    '{"advisories":{"1":{"severity":"critical","module_name":"x","url":"u","findings":[{"paths":["@warden/core>evil-pkg"]}]}}}' fail

  check "advisory with one spikes path and one non-spikes path fails (any non-spikes path blocks)" \
    '{"advisories":{"1":{"severity":"high","module_name":"x","url":"u","findings":[{"paths":["spikes__foo__ts>bar","@warden/core>bar"]}]}}}' fail

  check "low-severity spikes-external advisory passes (below audit-level=high)" \
    '{"advisories":{"1":{"severity":"low","module_name":"x","url":"u","findings":[{"paths":["@warden/core>bar"]}]}}}' pass

  echo
  if [ "$failures" -gt 0 ]; then
    echo "SELFTEST: $failures assertion(s) FAILED"
    return 1
  fi
  echo "SELFTEST: all assertions passed"
  return 0
}

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=1
elif [ "${1:-}" = "--selftest" ]; then
  run_selftest
  exit $?
fi

status=0

echo "== L9 supply-chain gate =="

echo
echo "-- 1/4: cargo deny --locked check (advisories, bans, sources, licenses) --"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "[dry-run] would run: cargo deny --locked check"
elif ! command -v cargo-deny >/dev/null 2>&1; then
  # A missing cargo-deny is a FAILURE, not a skip: this gate exists precisely
  # so a dependency-provenance regression can't slip through because the
  # checker wasn't there. CI installs a pinned cargo-deny explicitly (see
  # .github/workflows/ci.yml) — a local run without it installed is expected
  # to fail loudly with this message, not pass silently.
  echo "FAIL: cargo-deny is not installed (install with: cargo install cargo-deny --locked --version 0.20.2)"
  status=1
else
  if ! cargo deny --locked check; then
    echo "FAIL: cargo deny --locked check"
    status=1
  fi
fi

echo
echo "-- 2/4: pnpm install --frozen-lockfile (lockfile-in-sync check) --"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "[dry-run] would run: pnpm install --frozen-lockfile"
else
  if ! pnpm install --frozen-lockfile; then
    echo "FAIL: pnpm-lock.yaml is out of sync with package.json (or install failed)"
    status=1
  fi
fi

echo
echo "-- 3/4: pnpm audit --audit-level=high, SCOPED to shipped code (spikes/ excluded from the blocking gate) --"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "[dry-run] would run: pnpm audit --audit-level=high (human-readable log)"
  echo "[dry-run] would run: pnpm audit --json, then evaluate_audit_json (fail-closed scoped gate decision)"
else
  # Human-readable output for the log — informational, not what gates.
  pnpm audit --audit-level=high || true
  echo
  echo "-- scoped gate decision (spikes__* advisories excluded; fails closed on audit errors) --"
  audit_exit=0
  audit_json="$(pnpm audit --json)" || audit_exit=$?
  # pnpm audit --json exits 0 (nothing at/above its own default threshold)
  # or 1 (advisories found) in the normal case. Any OTHER exit code (e.g. a
  # registry/network failure that pnpm itself treats as fatal before even
  # producing JSON) is a signal on its own to fail closed, independent of
  # whatever partial output made it to stdout.
  if [ "$audit_exit" -ne 0 ] && [ "$audit_exit" -ne 1 ]; then
    echo "FAIL: pnpm audit --json exited $audit_exit (expected 0 or 1) — treating as an audit-service failure, failing closed"
    status=1
  elif ! echo "$audit_json" | evaluate_audit_json; then
    status=1
  fi
fi

echo
echo "-- 4/4: TODO/FIXME/XXX report (programs/, packages/ — informational, non-fatal) --"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "[dry-run] would run: git grep -nE \"TODO|FIXME|XXX\" -- programs packages"
else
  if git grep -nE "TODO|FIXME|XXX" -- programs packages; then
    echo "(above hits are informational; they do not fail this gate — see script header)"
  else
    echo "none found"
  fi
fi

echo
if [ "$status" -ne 0 ]; then
  echo "== L9 supply-chain gate: FAIL =="
else
  echo "== L9 supply-chain gate: PASS =="
fi
exit "$status"
