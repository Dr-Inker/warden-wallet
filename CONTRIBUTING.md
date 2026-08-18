# Contributing

Thanks for looking. A few things that will make a contribution land smoothly:

- **Read the spec first**: `docs/superpowers/specs/2026-08-18-warden-wallet-design.md`. Behaviour changes need a spec change in the same PR.
- **Rust rules**: `checked_*` arithmetic only (`cargo clippy -p warden --lib -- -D clippy::arithmetic_side_effects` must pass); every new instruction test asserts the serialized transaction size ≤ 1,232 bytes and exact error codes (the pinned table lives in `programs/warden/tests/root_verify.rs`); new error variants are appended, never reordered.
- **Never import from `spikes/`** into `packages/` or `programs/` — spikes are evidence, not code.
- **Tests before code**: we keep RED evidence (a failing test log, or a labelled mutation run) in the task report; please include one in your PR description.
- **Gate**: `./.claude/test-gate.sh` must be green (it rebuilds the SBF artifact when needed and runs TS + Rust suites).
- Cargo builds are heavy; run one at a time.
- Commit trailer convention in this repo: `Co-Authored-By:` for any AI assistance used.
