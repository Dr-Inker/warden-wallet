#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# WARDEN_SKIP_SPIKES=1 (spec §17 L9, plan Task 11 fix round 1): CI's main
# gate job sets this to skip `spikes/*/ts` — those packages include a
# Playwright suite (spikes/02-webauthn or similar) that needs a Chromium
# install CI's main job does not provision; spikes are throwaway evidence
# (CLAUDE.md), not shipped, so skipping them here is not a coverage loss for
# anything that ships. A separate, non-blocking CI job installs Chromium and
# audits spikes on their own schedule — see .github/workflows/ci.yml. Local
# runs (this var unset) still exercise everything, unchanged.
#
# Cargo already excludes spikes from the root workspace (see Cargo.toml) —
# this only needs to filter the pnpm side.
if [ "${WARDEN_SKIP_SPIKES:-0}" = "1" ]; then
  echo "WARDEN_SKIP_SPIKES=1: running pnpm test with spikes/*/ts excluded"
  pnpm -r --if-present --filter '!./spikes/**' test
else
  pnpm test
fi
# Spikes are excluded from the root workspace (see Cargo.toml), so --workspace
# covers only programs/* once Phase 1 lands the first program crate.
if ls programs/*/Cargo.toml >/dev/null 2>&1; then
  # L0 (spec §17): FEATURE-RESOLUTION evidence for the secp256r1 precompile.
  #
  # `precompiles` is not a default litesvm feature, and `LiteSVM::default()`
  # starts with every runtime feature off. If a dependency bump or a careless
  # edit dropped the feature, `bind_precompile` would become the ONLY gate on
  # the root of trust — the program would still bind key+message, but nothing
  # would verify the ECDSA signature.
  #
  # This check proves the feature RESOLVES. It does NOT prove the runtime
  # verifies signatures — `programs/warden/tests/sigverify_wiring.rs` is the
  # two-direction runtime gate that does, and this check never substitutes for
  # it. Both are required; they fail for different reasons.
  if ! cargo tree -e features -p warden 2>/dev/null | grep -q 'litesvm feature "precompiles"'; then
    echo "L0 FAIL: litesvm's \"precompiles\" feature does not resolve for -p warden."
    echo "         Without it the secp256r1 precompile is never loaded and no test"
    echo "         in this repo verifies a real signature. See programs/warden/Cargo.toml"
    echo "         and programs/warden/tests/sigverify_wiring.rs."
    exit 1
  fi
  # LiteSVM harnesses read target/deploy/*.so at test runtime (gitignored,
  # not committed) — build them first if missing or stale so a clean clone /
  # fresh checkout reproduces green without a manual `anchor build` step.
  # Stale = any source, manifest, lockfile, or Anchor config is newer than the .so.
  # `test-middleman` is the test-only CPI caller the root `stack_height` gate
  # needs (programs/test-middleman); it is built here, never deployed.
  needs_build=0
  for so in target/deploy/warden.so target/deploy/test_middleman.so target/deploy/test_mutator.so target/deploy/test_jup_mock.so; do
    [ -f "$so" ] || needs_build=1
  done
  if [ "$needs_build" -eq 0 ]; then
    for so in target/deploy/warden.so target/deploy/test_middleman.so target/deploy/test_mutator.so target/deploy/test_jup_mock.so; do
      if [ -n "$(find programs -name '*.rs' -newer "$so" | head -1)" ] \
        || [ -n "$(find programs -name 'Cargo.toml' -newer "$so" | head -1)" ] \
        || [ Cargo.toml -nt "$so" ] \
        || [ Cargo.lock -nt "$so" ] \
        || [ Anchor.toml -nt "$so" ]; then
        needs_build=1
      fi
    done
  fi
  # `--features test-jup` (Task 6): points warden's `swap` at `test-jup-mock`
  # instead of real Jupiter v6 so the LiteSVM suite drives the adapter against a
  # real CPI (constants.rs::SWAP_TARGET_PROGRAM). This is a TEST build — the
  # `.so` is gitignored and never deployed; a production deploy builds WITHOUT
  # the feature, and `swap::tests::swap_target_program_is_pinned` verifies the
  # right id in each config. The flag is forwarded to every program (they all
  # declare an inert `test-jup` feature so the forward does not error).
  if [ "$needs_build" -eq 1 ]; then
    if command -v anchor >/dev/null 2>&1; then
      nice -n 10 anchor build -- --features test-jup
    else
      nice -n 10 cargo-build-sbf --manifest-path programs/warden/Cargo.toml --features test-jup
      nice -n 10 cargo-build-sbf --manifest-path programs/test-middleman/Cargo.toml --features test-jup
      nice -n 10 cargo-build-sbf --manifest-path programs/test-mutator/Cargo.toml --features test-jup
      nice -n 10 cargo-build-sbf --manifest-path programs/test-jup-mock/Cargo.toml --features test-jup
    fi
  fi
  # anchor build regenerates target/idl/warden.json from the program source;
  # packages/core/idl/warden.json is the committed copy TS consumers read.
  # Catch drift here rather than downstream in a stale-IDL bug. (The IDL is
  # identical with/without test-jup — SWAP_TARGET_PROGRAM is a constant, not an
  # IDL field.)
  if [ -f target/idl/warden.json ]; then
    cmp -s target/idl/warden.json packages/core/idl/warden.json || { echo "IDL drift: copy target/idl/warden.json to packages/core/idl/"; exit 1; }
  fi
  cargo test --workspace --features test-jup
fi
