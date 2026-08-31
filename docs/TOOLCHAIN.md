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

- The shipped-extension release path now treats Node `22.23.2`, pnpm `11.12.0`,
  and esbuild `0.28.2` as exact inputs. The root `package.json`, `.node-version`,
  CI setup, and `apps/extension/scripts/package-release.mjs` agree on those
  pins; release packaging fails rather than accepting a compatible major or a
  dirty tree. This is narrower than complete supply-chain immutability: the CI
  workflow's third-party action references are still mutable major tags.
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

**As of Task 1 (2026-08-18), `.claude/test-gate.sh` runs Rust.** The hook
`git commit`/`git push` check for this repo runs `pnpm test`, then — when
`programs/*/Cargo.toml` exists (true since Task 1) — builds
`target/deploy/warden.so` if it's missing or older than any file under
`programs/warden/src` (`anchor build`, or `cargo-build-sbf` if `anchor` isn't
on PATH; both `nice -n 10`, serialized, never run alongside another
cargo/anchor process), then runs `cargo test --workspace`. This makes the gate
clean-clone reproducible: the LiteSVM harness reads `target/deploy/warden.so`
off disk at test *runtime* (`std::fs::read`, not `include_bytes!`), and that
`.so` is gitignored, so without this rebuild step a fresh checkout would fail
the harness's `.expect("run \`anchor build\` first — see docs/TOOLCHAIN.md")`
rather than reproduce green. Spikes stay outside `--workspace` (see the
`exclude = ["spikes"]` note above) and are not covered by the gate; the
per-spike commands in the table above remain the way to re-verify them by
hand. See docs/PROGRAM-KEYS.md for why none of this needs the program
keypair.

## Phase 1A crates (`programs/warden`, Task 1 — 2026-08-18)

- **Root workspace restored**: `members = ["programs/*"]` now resolves cleanly
  (`cargo metadata --no-deps` → `OK`) now that `programs/warden` exists;
  `exclude = ["spikes"]` unchanged.
- **`anchor init` in this repo**: refuses to run in place because the repo is
  already a git repo. Scaffolded via `anchor init --no-git warden` in a `mktemp -d`
  temp dir, then copied `programs/warden/{Cargo.toml,src/}` and
  `target/deploy/warden-keypair.json` (→ `programs/warden/keypair.json`) into the
  real tree and overwrote `Cargo.toml`/`src/lib.rs`/`src/errors.rs`/`src/constants.rs`
  with the task-1 brief's exact contents. No `Xargo.toml` is generated by
  `anchor init` for this Anchor/Solana toolchain combo — none was needed.
- **Anchor-init's own template Cargo.toml is workspace-inheriting**
  (`edition.workspace = true`, `rust-version.workspace = true`) and assumes a
  `[workspace.package]` table in the root `Cargo.toml` that this repo does not
  define. The brief's Cargo.toml (`edition = "2021"` spelled out directly) was
  used instead, so no root `[workspace.package]` section was needed.
- **`anchor build` keypair-mismatch warning**: `anchor build` looks for the
  program keypair at `target/deploy/<name>-keypair.json` (gitignored, regenerated
  if absent), not at `programs/warden/keypair.json`. **Round-1 fix (2026-08-18):
  the keypair is no longer committed at all** (security review flagged the
  original commit; `git rm --cached` + `.gitignore` now excludes
  `**/keypair.json` and `target/deploy/*-keypair.json` — see
  docs/PROGRAM-KEYS.md for the full policy). A local, gitignored copy of
  `programs/warden/keypair.json` → `target/deploy/warden-keypair.json` still
  silences the mismatch warning during local `anchor build`/`anchor deploy`,
  but nothing in the test gate depends on it: LiteSVM tests load the program
  by id (`warden::ID`) and bytes (`target/deploy/warden.so`), never by
  keypair, so the mismatch warning is cosmetic for `cargo test` and the gate
  (build still succeeds; only `anchor deploy`/`anchor keys sync` would
  actually care) — see docs/PROGRAM-KEYS.md.
- **`anchor_lang::solana_program::hash::hash` does not exist** in this
  anchor-lang 1.1.2 / solana-program 3.x combo (`solana-program` here is
  reassembled from many small crates — `solana-hash`, `solana-sha256-hasher`,
  etc. — and does not re-export a `hash` module at that path; verified by the
  build error `E0433: cannot find hash in solana_program`). The brief's smoke
  test was adjusted to compute the Anchor global-instruction sighash directly
  with the `sha2` crate (already a dev-dependency): `Sha256::digest(b"global:ping")[..8]`
  — same `sha256("global:<ix_name>")[..8]` scheme Anchor 1.x uses, just called
  without going through anchor-lang's re-export.
- **`anchor build` cost**: SBF build (`target/deploy/warden.so`, 57,416 B)
  finished in **48s**; the subsequent host-side IDL-generation build (compiles
  the full dev-dependency tree including `litesvm`'s Agave runtime pull-in and
  `openssl-sys` vendored from source) took the bulk of the wall time — full
  first build (both stages, cold cache) **~5 min**. `cargo test -p warden` run
  standalone afterwards triggered one more `openssl-sys` rebuild (different
  feature-unification hash than the `idl-build`-featured invocation) costing
  **~2 min 04s**; both are one-time costs — fully warm reruns of either command
  are sub-second to a few seconds.
- **Warnings only, not errors**: `#[program]` on `warden` emits `unexpected
  cfg condition value` warnings for `custom-heap`/`custom-panic`/`anchor-debug`
  (anchor-lang 1.1.2's `#[program]` macro references cfgs not declared in this
  crate's `[features]` table — cosmetic, harmless, not addressed since the brief
  specifies the feature list verbatim). `tests/common/mod.rs`'s
  `svm.add_program(...)` also warns `unused Result that must be used` (brief's
  exact code, not `.unwrap()`'d) — left as specified; it will surface loudly as
  a panic-free no-op only if `add_program` ever fails, which the smoke test's
  passing `ping_succeeds` result rules out for this run.

## `spl-token` dev-dependency (`programs/warden`, Task 7 — 2026-08-18)

`transfer` (Task 7) moves SPL balances, so the test suite needs to plant mints
and token accounts. The crate is a **dev-dependency only**.

| Crate | Requirement in `programs/warden/Cargo.toml` | Resolved version | Notes |
| --- | --- | --- | --- |
| `spl-token` | `{ version = "9", features = ["no-entrypoint"] }` (dev-dep) | `9.0.0` | Pulls `spl-token-interface 2.0.0`; both build on the granular `solana-*` **3.x** crates (`solana-pubkey 3.0.0`, the same instance anchor-lang 1.1.2 uses), so `spl_token::ID` and `spl_token::state::Account`'s `Pubkey` are the *same type* as `solana_sdk::pubkey::Pubkey` in the tests. Adding it changed nothing else in `Cargo.lock` — 49 inserted lines, zero modified. |

**Why not v7** (what spike 3b declared): `spl-token` 7.0.0 requires
`solana-program ^2.1`, whose `Pubkey` is a different, non-interconvertible type
from `solana-program 3.x`'s — spike 3b hit exactly this and hand-rolled its
parser rather than fight it (`spikes/03-txbudget/onchain/src/lib.rs`, module
docs). v8 is `solana-* 2.2`; **v9 is the first line on 3.x**.

**The program still does not import it.** `warden::constants::SPL_TOKEN_ID` /
`NATIVE_MINT` are `Pubkey::from_str_const` literals and
`instructions::transfer::parse_token_account` reads the 165-byte SPL layout at
fixed offsets, because a program-side `spl-token` dependency would drag the
token program's own entrypoint machinery into the SBF artifact for the sake of
two struct definitions. The dev-dependency is what *pins* those choices:
`transfer::token_program_id_matches_spl_token` asserts the hardcoded ids equal
`spl_token::ID` / `spl_token::native_mint::ID`, and every fixture in
`tests/common/token.rs` is packed by the real crate's `Account::pack` /
`Mint::pack`, so an SPL layout change breaks the tests loudly instead of
silently drifting from what the program parses.

## Phase 1B Task 0 — the L0 litesvm pin and the `test-middleman` crate (2026-08-19)

**`litesvm` is now an EXACT pin, not a range.**

| Crate | Requirement in `programs/warden/Cargo.toml` | Resolved version | Notes |
| --- | --- | --- | --- |
| `litesvm` | `{ version = "=0.12.0", features = ["precompiles"] }` (dev-dep) | `0.12.0` | Was `"0.12"`. Note that `"0.12"` **already** means `>=0.12, <0.13`, so the change is not about widening or narrowing the major/minor range — it is about pinning the patch. `"=0.12.x"` would be a *wildcard*, not a pin; `Cargo.lock` resolves `0.12.0`, so `=0.12.0` is the correct string. `Cargo.lock` is committed. |

Why the pin and the feature both matter (spec §17, layer L0):

- `precompiles` is **not** a default litesvm feature and `LiteSVM::default()` starts
  with every runtime feature off. Without the feature the secp256r1 precompile
  program account is never loaded, and every root ceremony fails with
  `InvalidProgramForExecution` rather than being verified.
- With the feature, litesvm 0.12's `process_precompile` calls
  `agave-precompiles::…verify(...)`, i.e. the runtime performs the real ECDSA
  check. That is the property the root of trust rests on, and it is now asserted
  in **two independent places**:
  - `programs/warden/tests/sigverify_wiring.rs` — the runtime gate. Both
    directions against one transaction shape: a valid signature succeeds, and a
    forged / bit-flipped / high-S one fails with **exactly**
    `InstructionError(0, Custom(2))` (`PrecompileError::InvalidSignature`), i.e.
    at the precompile instruction, before warden's own instruction runs.
  - `.claude/test-gate.sh` — the feature-resolution gate. Fails the gate if
    `cargo tree -e features -p warden` no longer resolves
    `litesvm feature "precompiles"`. This is **evidence about resolution, not
    about runtime behaviour**, and it never substitutes for the test above.
- 0.13+ moves to Agave 4.x, which would diverge from the installed Agave 3.1.10
  CLI — the same reason spike 2b stayed on the 0.12 line.

**New crate: `programs/test-middleman`** (test-only, never deployed).

| Fact | Value |
| --- | --- |
| Program id | `FHWwDX1az7eAtFsogaRrFcoZkZhBEzSS3QMXPwovSiMN` |
| Derivation | **Nothing-up-my-sleeve**: `sha256("WARDEN/test-middleman/v1")` = `d43ec1db23c08041980a95fb03ef9fdc5b7463e4ac09d9ed74a8b202dced1ed9`, base58-encoded. No keypair for it exists or is committed (docs/PROGRAM-KEYS.md). |
| Dependencies | `anchor-lang = "1.1.2"` only |
| Built by | `anchor build` (workspace member via `members = ["programs/*"]`), and by `.claude/test-gate.sh`'s staleness check |
| Artifact | `target/deploy/test_middleman.so`, 82,152 B at the Task 0 commit |
| Used by | `root_verify::root_instruction_via_cpi_rejected` — it CPIs a complete, valid root ceremony into `rotate_nonce` and warden must refuse it with `RootRequiresTopLevel` (6038) |

`anchor build` emits a keypair-mismatch warning for it, exactly as it does for
`warden`, and for the same reason: LiteSVM loads programs by id + bytes, never
by keypair. Nothing deploys this program.

**`anchor build` cost after Task 0**: `target/deploy/warden.so` grew 382,832 B →
388,208 B (+5,376 B) for the slot checks, the `stack_height` check, the
`RootContext` refactor and three new error variants.
