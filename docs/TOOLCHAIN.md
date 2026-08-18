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
