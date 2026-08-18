#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
pnpm test
if ls programs/*/Cargo.toml >/dev/null 2>&1; then cargo test --workspace --exclude spike-p256 --exclude spike-conserve; fi
