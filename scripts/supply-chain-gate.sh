#!/usr/bin/env bash
# L9 supply-chain gate (spec §17, Task 11).
#
# Runs the dependency-provenance checks CI enforces as failing gates:
#   1. `cargo deny check` (advisories + bans + sources + licenses) against
#      the root workspace (`programs/*`), per `deny.toml`.
#   2. `pnpm install --frozen-lockfile` — fails if `pnpm-lock.yaml` would
#      change, i.e. it is not in sync with `package.json` files.
#   3. `pnpm audit --audit-level=high` across the pnpm workspace.
#   4. A scoped `git grep` for TODO/FIXME/XXX markers under `programs/` and
#      `packages/` — informational only, never fails the gate. (The L7
#      deploy-time gate in `scripts/deploy-gate.sh` has its own, *fatal*,
#      narrower grep for TODO/unimplemented!/#[ignore] — see spec §17 L7
#      and the plan's Task 11 item 3. Keeping that scoped to `programs/` and
#      `packages/` only is deliberate: `docs/`, `spikes/` and the plan itself
#      legitimately contain those strings, and an unscoped grep fails
#      permanently and gets disabled, which is worse than not having it.)
#
# Exit status: non-zero if cargo-deny or pnpm audit fail. The TODO/FIXME/XXX
# report never affects the exit status.
#
# Usage:
#   scripts/supply-chain-gate.sh            # run for real
#   scripts/supply-chain-gate.sh --dry-run  # print what would run, do nothing
set -euo pipefail
cd "$(dirname "$0")/.."

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=1
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
echo "-- 3/4: pnpm audit --audit-level=high --"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "[dry-run] would run: pnpm audit --audit-level=high"
else
  if ! pnpm audit --audit-level=high; then
    echo "FAIL: pnpm audit found high/critical advisories"
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
