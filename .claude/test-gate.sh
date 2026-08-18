#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
pnpm test
# Spikes are excluded from the root workspace (see Cargo.toml), so --workspace
# covers only programs/* once Phase 1 lands the first program crate.
if ls programs/*/Cargo.toml >/dev/null 2>&1; then cargo test --workspace; fi
