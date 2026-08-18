# Warden Wallet

**A Solana wallet where the limits are enforced by the chain, not by a warning you can click through.**

Warden is a self-custody, smart-account browser-extension wallet by [drinkerlabs](https://drinkerlabs.info). Funds live in a program-owned account; the account's **root** is a passkey (P-256, verified on-chain), everyday actions are signed by **bounded session keys** with per-transaction, daily and 30-day caps enforced on-chain, larger moves are **timelocked and cancellable**, and recovery is by **guardians** with a delay — no seed phrase in the default path.

The property we build toward, stated exactly (spec §1): *if an attacker obtains everything the extension holds while unlocked — the session key, the unlocked keyring, the ability to prompt the user — the value that can leave the account before the owner or a guardian reacts is bounded by the account's caps; anything larger is delayed and cancellable.*

> **Status: pre-alpha, under active development. Not audited. Not deployed. Do not use with real funds.**
> The on-chain program is being built phase by phase with a two-model review loop (implementation + independent adversarial review of every task); see [Development process](#development-process).

## What exists today

| Area | State |
|---|---|
| **Design spec** (rev 7) | `docs/superpowers/specs/2026-08-18-warden-wallet-design.md` — threat model, key model, on-chain instruction set, conservation rules, recovery, rollout |
| **Phase 0 — spikes** | Done, merged. Evidence-backed answers to the four questions that could have killed the design: passkey root verified on-chain (secp256r1 precompile + Instructions-sysvar binding), transaction byte budget on real Jupiter routes, conservation-snapshot CU cost, dApp compatibility inventory. Roll-up + decision: `docs/spikes/DECISION.md` |
| **Phase 1A — program foundation** | Done, merged to `main` (Codex `sol@max` final review MERGE-READY).  `programs/warden` (Anchor): zero-copy `SmartAccount`, `SessionKey`, bucket accounting, `root_verify` (strict WebAuthn `clientDataJSON` scanner, consumed nonce), `create_account`, `grant_session`/`revoke_session`, root `freeze`/`unfreeze`, `transfer` (session within caps / root bounded, both debiting shared account-wide buckets). 292 Rust tests (LiteSVM + unit) + 50 TS tests; `./.claude/test-gate.sh` exit 0 at `c583dfe`. Measured costs + error ABI (6000–6035): `docs/program/PHASE1A-MEASUREMENTS.md` |
| **Phase 1B** (next, plan committed) | `execute` (allow-listed dApp CPI with before/after conservation checks), adapter registry, staged transactions, `swap` (Jupiter with platform fee), root-bound account address + proof-of-possession at create, and the measured pre-ship gate (end-to-end `execute` CU with real CPI, `is_native`, stage cap). Plan: `docs/superpowers/plans/2026-08-18-warden-phase1b-execute-swap.md` |
| **Phase 1C** (after 1B) | `queue`/pending timelock + `set_policy` policy lattice, guardians / recovery / guardian-freeze |
| **Design system** | Figma tokens + first screens (sign-request/intent, home, dust-only poison screen); CSS tokens in `packages/ui-tokens` — `docs/design/figma.md` |
| **Extension / services** | Not started (Phases 2–4) |

Facts worth knowing before you read the code (all measured, all in the docs):

- The passkey's `rpIdHash` is **SHA-256 of the full `chrome-extension://<id>` origin**, not of the extension id (spike 2b).
- Solana's secp256r1 precompile requires **low-S** signatures; Chrome emits high-S sometimes — the client normalizes.
- LiteSVM does **not** enforce the 1,232-byte transaction limit; every instruction test here asserts serialized transaction size explicitly.
- `execute` payload account indices are **instruction-local**; compute-budget instructions stay top-level.
- Account creation is **unauthenticated in the current code** (a front-runner could squat a client-chosen address); Phase 1B binds the address to the root key and requires proof-of-possession — until then nothing should be funded before a successful root round-trip. Known limitations live in `docs/spikes/DECISION.md`.
- Session caps in 1A are per-transaction + lifetime; **day/30-day limits are account-wide** across all sessions *and* root direct actions.

## Repository layout

```
programs/warden/          Anchor program (Rust) + LiteSVM tests
packages/core/            TypeScript SDK (transcript/challenge mirror, constants, IDL)
packages/ui-tokens/       Design tokens exported from Figma (CSS + JSON, constraint tests)
spikes/                   THROWAWAY Phase-0 evidence (never imported by product code)
docs/superpowers/specs/   Design spec (rev 7)
docs/superpowers/plans/   Phase plans (0, 1A, 1B)
docs/research/            Security-assurance pipeline + Solana wallet landscape research (2026-08-18) + raw reports
docs/spikes/              DECISION.md (Phase-0 gate), Phase-0 + Phase-1A ledgers
docs/program/             Measured CU / byte costs, design notes, error ABI
docs/design/              Figma file map, screenshots
docs/TOOLCHAIN.md         Pinned toolchain + verification provenance
docs/PROGRAM-KEYS.md      Program id / keypair policy (keypair is NOT in this repo)
```

## Build and test

Prerequisites: Node 22 + pnpm 11; Rust stable (1.97 tested); Solana/Agave CLI 3.1.x (`cargo-build-sbf`); Anchor CLI 1.1.2 (`avm`); LiteSVM is a dev-dependency (`precompiles` feature). Exact pins: `docs/TOOLCHAIN.md`.

```bash
pnpm install
pnpm test                       # TS packages
anchor build                    # builds target/deploy/warden.so
cargo test --workspace          # LiteSVM + unit tests (needs the .so)
./.claude/test-gate.sh          # everything above; rebuilds the .so if stale
cargo clippy -p warden --lib -- -D clippy::arithmetic_side_effects
```

## Development process

Every task is planned from the spec, implemented by an isolated worker, and **independently reviewed by a second model (OpenAI Codex) against the brief and the spec** before it counts as done; findings go through fix rounds with scoped re-reviews. Rulings taken along the way are recorded in the published ledgers: [Phase 0](docs/spikes/PHASE0-LEDGER.md) and [Phase 1A](docs/spikes/PHASE1A-LEDGER.md). Security-relevant claims are backed by tests that assert exact error codes and by measured numbers rather than assumptions.

Contributions: see `CONTRIBUTING.md`. Security reports: see `SECURITY.md`.

## Non-goals for v1

Mobile, agent-key UI, quantum-resistant root signer (kept as a typed slot — see the companion study in the drinkerlabs docs), multi-chain, hardware wallets, fiat on-ramp, plain-keypair accounts inside Warden.

## License

MIT — see `LICENSE`.
