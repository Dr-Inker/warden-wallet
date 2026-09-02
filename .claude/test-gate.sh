#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# C6: external GitHub Actions references are executable third-party code. Reject
# mutable tags/branches locally as well as in the workflow's first post-checkout
# step; only full commit SHAs (or Docker sha256 digests) are accepted.
node --test test/github-actions-pins.test.mjs
# WARDEN_SKIP_SPIKES=1 (spec §17 L9, plan Task 11 fix round 1): CI's main
# gate job sets this to skip `spikes/*/ts` — those packages include a
# Playwright suite (spikes/02-webauthn or similar); spikes are throwaway
# evidence (CLAUDE.md), not shipped, so CI audits them in a separate
# non-blocking job. The shipped extension's Chromium lane is different: it is
# mandatory below, and the main CI job provisions its pinned browser. Local
# runs (this var unset) still exercise the spikes too, unchanged.
#
# Cargo already excludes spikes from the root workspace (see Cargo.toml) —
# this only needs to filter the pnpm side.
if [ "${WARDEN_SKIP_SPIKES:-0}" = "1" ]; then
  echo "WARDEN_SKIP_SPIKES=1: running pnpm test with spikes/*/ts excluded"
  pnpm -r --if-present --filter '!./spikes/**' test
else
  pnpm test
fi
# The extension consumes the built package subpath, not a source alias. Build core
# first so this lane proves the package export exists, then prove the MV3 source is
# type-safe and emits a self-contained browser bundle. Unit tests alone transpile
# TypeScript and would not catch either packaging failure.
pnpm --filter @warden/core build
pnpm --filter @warden/extension typecheck
pnpm --filter @warden/extension build
# A Node event-loop check is insufficient here: Chromium's scheduler.yield()
# continuations outrank ordinary queued tasks unless the KDF originates in a
# background postTask. Exercise the exact provisional RFC-profile Argon2 path in
# a real MV3 worker, verify a delayed host task runs before completion, and prove
# signal revocation rejects and wipes the caller-owned password buffer. This is a
# responsiveness/cancellation gate, not evidence that the provisional cost is a
# measured product floor on the slowest supported device.
pnpm --filter @warden/extension bench:argon2
# Unit mocks cannot establish Chrome-owned MessageSender provenance, frame
# isolation, navigation teardown, or MV3 stop/wake behavior. This shipped-code
# lane rebuilds the unpacked extension, runs it in Chromium, closes the live
# worker target, proves its execution global was discarded, and wakes it from a
# new document Port. A missing Playwright browser is a gate failure, not a skip.
pnpm --filter @warden/extension test:browser
# WRDF-0081: the cross-language fixtures under programs/warden/tests/fixtures are
# READ-ONLY golden vectors, written only by `pnpm --filter @warden/core
# gen:fixtures`. The suite asserts wrapForExecute/encode reproduce them; this
# guard fails the gate if a test (or a wrapper regression that a test failed to
# catch) mutated a golden, so a fixture can never silently self-update.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if ! git diff --exit-code -- programs/warden/tests/fixtures >/dev/null 2>&1; then
    echo "FIXTURE DRIFT: a test mutated a committed golden under programs/warden/tests/fixtures."
    echo "  Golden fixtures are written only by 'pnpm --filter @warden/core gen:fixtures'."
    echo "  If the change is intentional, regenerate and commit it; otherwise a wrapper regression"
    echo "  changed the encoded/hashed output. Diff:"
    git --no-pager diff --stat -- programs/warden/tests/fixtures
    exit 1
  fi
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
  # Fable audit R-2 (2026-09-02): these two used to exist ONLY in ci.yml, and
  # CI only runs on push — so on a branch that is hundreds of commits ahead of
  # origin they had silently not run at all. Same commands as ci.yml:196-200.
  cargo clippy -p warden --lib -- -D clippy::arithmetic_side_effects
fi
# L9 supply-chain gate (cargo-deny advisories/bans/sources/licences + frozen
# lockfile + scoped pnpm audit). Cheap, network-free once the advisory DB is
# cached; runs even when the Rust build is skipped because it also covers the
# JS lockfile.
./scripts/supply-chain-gate.sh
