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

- `cargo-build-sbf` default `--arch v0`; the produced `spike_p256.so` is 26,224 B.
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

⚠ **Workspace caveat (OPEN — deferred to the Task 5/6 decision gate):** the repo-root `Cargo.toml` lists members that do not
exist yet (`programs/*`, `spikes/03-txbudget/onchain`), which makes the root
workspace unresolvable. The spike crate therefore carries its own empty
`[workspace]` table so it can build standalone; that table must be removed (or
the spike moved to the root workspace's `exclude` list) as soon as the root
workspace resolves, otherwise cargo fails with *multiple workspace roots found
in the same workspace*. Per the coordinator the table stays for now and the
layout is settled once Task 5/6 lands `spikes/03-txbudget/onchain`. See
`spikes/02-webauthn/result.md`.
