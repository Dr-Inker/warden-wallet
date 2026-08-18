# Toolchain versions

Recorded 2026-08-18 on the /opt/warden dev host. Each version string below is the
verbatim output of the listed command, run in sequence per Step 4 of Task 1
(Rust/Anchor installs and builds are serialized on this host).

| Tool | Version (verbatim output) | How installed |
| --- | --- | --- |
| Node.js | `v22.23.2` (`node -v`) | Pre-installed on host |
| pnpm | `11.12.0` (`pnpm -v`) | Pre-installed on host (corepack) |
| Solana CLI (Agave) | `solana-cli 3.1.10 (src:7bc9c805; feat:1620780344, client:Agave)` (`solana --version`) | Pre-installed on host at `/root/.local/share/solana/install/active_release/bin` |
| rustup | `rustup 1.29.0 (28d1352db 2026-03-05)` (`rustup --version`) | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh -s -- -y --profile minimal` |
| rustc | `rustc 1.97.1 (8bab26f4f 2026-07-14)` (`rustc --version`) | Installed via rustup, `stable` channel (`rustup toolchain install stable && rustup default stable`) |
| cargo | `cargo 1.97.1 (c980f4866 2026-06-30)` (`cargo --version`) | Installed via rustup, `stable` channel |
| cargo-build-sbf | `solana-cargo-build-sbf 3.1.10` / `platform-tools v1.52` (`cargo-build-sbf --version`) | Bundled with the pre-installed Solana CLI (Agave) toolchain |
| avm (Anchor Version Manager) | `avm 1.1.2` (`avm --version`) | `cargo install --git https://github.com/coral-xyz/anchor avm --locked` (built from source, ~2m54s) |
| anchor-cli | `anchor-cli 1.1.2` (`anchor --version`) | `avm install latest && avm use latest` — completed in a few seconds (well under the 25 min budget), no fallback pinning needed |

## Notes

- `avm install latest` resolved to Anchor `1.1.2` and completed almost instantly
  (avm fetched a prebuilt release rather than compiling from source), so the
  controller's fallback pin (`avm install 0.31.1`) was not needed.
- The host's pre-installed Solana CLI reports `3.1.10`, not `3.1.12` as noted in
  the task context; the verbatim printed output above is authoritative.
- All Step 4 commands were run one at a time (no concurrent cargo/avm
  invocations), several under `nice -n 10`, per host stability constraints.

## Spike 2b crates (`spikes/02-webauthn/onchain`)

Recorded 2026-08-18. The task brief suggested `solana-program = "2"` /
`solana-sdk = "2"`; those do **not** line up with the host's Agave 3.1.10
toolchain, so the 3.x line was pinned instead. Everything below is what
`cargo generate-lockfile` actually resolved (`spikes/02-webauthn/onchain/Cargo.lock`),
and the combination builds with `cargo-build-sbf 3.1.10` / platform-tools v1.52
and passes 21/21 tests (6 unit + 15 LiteSVM integration).

| Crate | Requirement in `Cargo.toml` | Resolved version | Notes |
| --- | --- | --- | --- |
| `solana-program` | `"3"` | `3.0.0` | program-side only |
| `solana-sdk` | `"3"` | `3.0.0` | dev-dependency (test harness) |
| `solana-secp256r1-program` | `"3"` | `3.0.0` | dev-dependency; builds the precompile instruction. **Needs OpenSSL dev headers on the host** (`apt-get install libssl-dev` — installed 2026-08-18, `pkg-config --modversion openssl` → `3.0.13`) |
| `litesvm` | `{ version = "0.12", features = ["precompiles"] }` | `0.12.0` | `precompiles` is **not** a default feature; without it the secp256r1 precompile account is never loaded and the transaction fails with `InvalidProgramForExecution`. 0.12.x is the newest litesvm line still on the Agave **3.x** runtime (0.13+ moves to Agave 4.x, which would diverge from the installed CLI) |
| `agave-precompiles` / `agave-feature-set` / `solana-program-runtime` | transitive via litesvm | `3.1.14` | `enable_secp256r1_precompile` (SIMD-0075, `srremy31J5Y25FrAApwVb9kZcfXbusYMMsvTK9aWv5q`) is present in litesvm's mainnet-active feature list (snapshot dated 2026-04-26), so `LiteSVM::new()` activates it |
| `serde_json` / `hex` / `bincode` / `sha2` | `"1"` / `"0.4"` / `"1"` / `"0.10"` | `1.0.151` / `0.4.3` / `1.3.3` / `0.10.9` | dev-dependencies (`bincode` measures tx wire size; `sha2` derives the expected `rpIdHash` independently of `authenticatorData`) |

Build facts:

- `cargo-build-sbf` default `--arch v0`; the produced `spike_p256.so` is
  **27,432 B**, built from `spikes/02-webauthn/onchain/src/lib.rs` as of commit
  `5a0e334` (the round-1 review fixes; `src/lib.rs` is unchanged by round 2, so
  this is also the current size). It was 26,224 B before the round-1 refactor
  that extracted `client_data_check` — update this line whenever the program
  source changes.
- First `cargo-build-sbf` run: **1 m 19 s** wall (18.9 s of actual compile, the
  rest is the one-time platform-tools v1.52 download + rustup toolchain link).
  Subsequent no-op builds: ~0.2 s.
- First `cargo test` (host) build: **~2 m 01 s** (compiles the whole Agave 3.1.14
  runtime + OpenSSL bindings). Test execution itself: 0.4 s.
- `solana_program::hash::hash` is **SHA-256** (`solana-sha256-hasher`, `sol_sha256`
  syscall on-chain), verified by reading the crate source — not keccak.
- Two benign warnings come from `entrypoint!` in `solana-program` 3.0.0
  (`unexpected cfg condition value: custom-heap / custom-panic / solana`); they
  are upstream noise, not a code defect.

**Workspace caveat — RESOLVED (2026-08-18, Phase 0 decision gate).** The repo-root `Cargo.toml`
now resolves on its own: `members = []` (empty until Phase 1 adds `programs/warden`) and
`exclude = ["spikes"]` (spikes are throwaway evidence, each carrying its own `[workspace]` table
by design, not members of the root workspace). `cargo metadata --no-deps` against the root
manifest succeeds. Each spike crate's own empty `[workspace]` table is **intentional and
permanent**, not a stopgap to be deleted later — spike crates remain standalone by design so they
can build independently of whatever the root workspace's `programs/*` glob resolves to. See
`docs/spikes/DECISION.md` ("Phase 1 entry conditions") and the root `Cargo.toml`'s own comments.

## Spike 3b crates (`spikes/03-txbudget/onchain`)

Same toolchain as spike 2b (Agave 3.1.10 / rustc 1.97.1), own empty `[workspace]` table for the
same reason (see that spike's entry above and `spikes/02-webauthn/result.md`).

| Crate | Requirement in `Cargo.toml` | Resolved version | Notes |
| --- | --- | --- | --- |
| `solana-program` | `"3"` | `3.0.0` | program-side |
| `solana-sdk` | `"3"` | `3.0.0` | dev-dependency (test harness) |
| `litesvm` | `"0.12"` | `0.12.0` | `precompiles` feature **not** needed here (no precompile use) |
| `spl-token` | `{ version = "7", features = ["no-entrypoint"] }` | `7.0.0` | declared but **not imported** — see below |
| `spl-token-2022` | `{ version = "7", features = ["no-entrypoint"] }` | `7.0.0` | declared but **not imported** — see below |

**`spl-token`/`spl-token-2022` conflict:** both resolve fine in the dependency *graph* against
`solana-program = "3"`, but they pull a separate `solana-program 2.3.0` instance (via
`solana-pubkey 2.4.0`) — `cargo tree -i solana-program` reports it ambiguous (`2.3.0` / `3.0.0`).
`spl_token::state::Account::owner` is therefore a different, non-interconvertible `Pubkey` type
than the `AccountInfo`/`Pubkey` this crate's program uses. Fell back to the task brief's documented
alternative: hand-parse/pack the 165-byte SPL Token account layout at fixed offsets directly (both
in the program and the LiteSVM test harness), and hardcode the SPL Token / Token-2022 / native-mint
program ids as `pubkey!()` literals instead of importing them. The two crates stay declared in
`Cargo.toml` purely so their resolved majors are on record here.

Build facts:

- `cargo-build-sbf` produced `spike_conserve.so` at **26,160 B** (both the default/`keccak` and
  `sha256-tlv`-feature builds are this size; the two builds are binary-different — different file
  hashes — but same size). Grew from 25,104 B pre-round-1-fix (stricter COption parsing + fuller
  field-by-field invariant comparison in `check_vault_invariants` — see result.md part (b) "Round
  1 fix").
- `cargo test` (host, debug profile, full dependency tree incl. the Agave 3.1.14 BPF loader/runtime
  crates pulled in by `litesvm`): first build ~1 m 38 s wall; incremental re-runs after a feature
  flip: well under a second once cached. 16 tests total post-round-1-fix (12 new `#[cfg(test)]`
  unit tests on `check_vault_invariants` in `src/lib.rs`, no SBF build needed — `cargo test --lib`
  — plus the original 4 LiteSVM integration tests in `tests/cu.rs`).
- See `spikes/03-txbudget/result.md` part (b) for the measured CU numbers (post-fix, authoritative)
  and the keccak-vs-sha256 TLV-hash comparison.

## Verification provenance

For each Rust spike, the exact command that was run and the commit SHA it last passed on:

| Spike | Command | Tests | Commit SHA |
| --- | --- | --- | --- |
| spike-p256 (`spikes/02-webauthn/onchain`) | `cargo test --manifest-path spikes/02-webauthn/onchain/Cargo.toml -- --nocapture` | 21 passed (6 unit + 15 LiteSVM integration) | `c345090` |
| spike-conserve (`spikes/03-txbudget/onchain`) | `cargo test --manifest-path spikes/03-txbudget/onchain/Cargo.toml -- --nocapture` | 16 passed (12 unit on `check_vault_invariants` + 4 LiteSVM integration) | `e0990ea` |

**No Rust runs in the global test gate today.** `.claude/test-gate.sh` (the hook `git commit`/`git push`
check for this repo) only runs `pnpm test` — it does not invoke `cargo test` or `cargo-build-sbf`
for any spike or for the (currently empty) root workspace. The table above is a point-in-time
record from when each spike was last built and tested by hand; re-run the commands above to
re-verify before relying on these numbers, especially after any dependency or toolchain change.
