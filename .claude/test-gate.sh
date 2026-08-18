#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
pnpm test
# Spikes are excluded from the root workspace (see Cargo.toml), so --workspace
# covers only programs/* once Phase 1 lands the first program crate.
if ls programs/*/Cargo.toml >/dev/null 2>&1; then
  # LiteSVM harnesses read target/deploy/warden.so at test runtime (gitignored,
  # not committed) — build it first if missing or stale so a clean clone /
  # fresh checkout reproduces green without a manual `anchor build` step.
  # Stale = any source, manifest, lockfile, or Anchor config is newer than the .so.
  if [ ! -f target/deploy/warden.so ] \
    || [ -n "$(find programs/warden/src -newer target/deploy/warden.so -name '*.rs' | head -1)" ] \
    || [ programs/warden/Cargo.toml -nt target/deploy/warden.so ] \
    || [ Cargo.toml -nt target/deploy/warden.so ] \
    || [ Cargo.lock -nt target/deploy/warden.so ] \
    || [ Anchor.toml -nt target/deploy/warden.so ]; then
    if command -v anchor >/dev/null 2>&1; then
      nice -n 10 anchor build
    else
      nice -n 10 cargo-build-sbf --manifest-path programs/warden/Cargo.toml
    fi
  fi
  cargo test --workspace
fi
