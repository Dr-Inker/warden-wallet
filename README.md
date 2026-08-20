# Warden Wallet

**A Solana wallet where the limits are enforced by the chain, not by a warning you can click through.**

Warden is a self-custody, smart-account browser-extension wallet by [drinkerlabs](https://drinkerlabs.info). Funds live in a program-owned account; the account's **root** is a passkey (P-256, verified on-chain), everyday actions are signed by **bounded session keys** with per-transaction, daily and 30-day caps enforced on-chain, larger moves are **timelocked and cancellable**, and recovery is by **guardians** with a delay — no seed phrase in the default path.

The property we build toward, stated exactly (spec §1): *if an attacker obtains everything the extension holds while unlocked — the session key, the unlocked keyring, the ability to prompt the user — the value that can leave the account before the owner or a guardian reacts is bounded by the account's caps; anything larger is delayed and cancellable.*

> **Status: pre-alpha, under active development. Not audited. Not deployed. Do not use with real funds.**
> The on-chain program is being built phase by phase with a two-model review loop (implementation + independent adversarial review of every task); see [Development process](#development-process).

## What exists today

| Area | State |
|---|---|
| **Design spec** (rev 8 + binding 2026-08-19 UI/security erratum) | `docs/superpowers/specs/2026-08-18-warden-wallet-design.md` — threat model, key model, on-chain instruction set, conservation rules, recovery, rollout |
| **Phase 0 — spikes** | Done, merged. Evidence-backed answers to the four questions that could have killed the design: passkey root verified on-chain (secp256r1 precompile + Instructions-sysvar binding), transaction byte budget on real Jupiter routes, conservation-snapshot CU cost, dApp compatibility inventory. Roll-up + decision: `docs/spikes/DECISION.md` |
| **Phase 1A — program foundation** | Done, merged to `main` (Codex `sol@max` final review MERGE-READY).  `programs/warden` (Anchor): zero-copy `SmartAccount`, `SessionKey`, bucket accounting, `root_verify` (strict WebAuthn `clientDataJSON` scanner, consumed nonce), `create_account`, `grant_session`/`revoke_session`, root `freeze`/`unfreeze`, `transfer` (session within caps / root bounded, both debiting shared account-wide buckets). 292 Rust + 50 TS tests at merge (`c583dfe`). Measured costs, executable commands, evidence SHAs, and error ABI (6000–6035): `docs/program/PHASE1A-MEASUREMENTS.md` |
| **Phase 1B — execute / registry / staging / swap** (in progress, branch `phase1b`) | Landed so far (each Codex-reviewed at `sol@max`): L0 harness-fidelity gate (forged-signature tests prove the secp256r1 precompile is live), slot-based root freshness + top-level-only root paths, the `conservation` module (before/after field-by-field compare incl. Mint pre-scan, new-vault-account rejection, duplicate-key rejection, lamport freeze, close-intent identity), root-bound account address + proof-of-possession at create (squatting impossible), the invariant ledger + typed Codex findings schema + prior-art corpus (`docs/security/`), CI workflow + cargo-deny + fail-closed supply-chain gate. A **2026-08-20 assurance pass (A0)** then made the review loop executable end-to-end and, in the process, found and fixed **five RED-verified fund-loss defects in the conservation module** (Token-2022 native-SOL accounting and mint-authority-bypass classes) that earlier review had passed — see [Development process](#development-process). Remaining: test programs, adapter registry, staging, `execute`, `swap`, TS payload builder, deploy-gate RPC checks, close-out. Plan: `docs/superpowers/plans/2026-08-18-warden-phase1b-execute-swap.md` (rev 3); adjudicated campaign order in `docs/superpowers/plans/2026-08-20-warden-research-adjudication-and-campaign-plan.md`. |
| **Phase 1C** (after 1B) | `queue`/pending timelock + `set_policy` policy lattice, guardians / recovery / guardian-freeze |
| **Design system** | Figma tokens + first Home/sign-request studies; current partial-match and dust-override frames are legacy/do-not-ship pending the binding audit in `docs/design/figma.md`. Extension/mobile research: `docs/research/2026-08-19-wallet-ui-extension-mobile.md`; plan: `docs/superpowers/plans/2026-08-19-warden-s-tier-ui-mobile.md` |
| **Extension / services** | Not started (Phases 2–4) |

Claude/session pickup for the complete 2026-08-19 security, vanity, and UI
research campaign:
`docs/OVERNIGHT-HANDOFF-2026-08-19.md`.

Facts worth knowing before you read the code (all measured, all in the docs):

- The passkey's `rpIdHash` is **SHA-256 of the full `chrome-extension://<id>` origin**, not of the extension id (spike 2b).
- Solana's secp256r1 precompile requires **low-S** signatures; Chrome emits high-S sometimes — the client normalizes.
- LiteSVM does **not** enforce the 1,232-byte transaction limit; every instruction test here asserts serialized transaction size explicitly.
- `execute` payload account indices use one **logical** mapping:
  `logical[0]=smart_account`, `logical[1]=signer`,
  `logical[2+k]=remaining_accounts[k]`. They never index the raw physical
  account slice; compute-budget instructions stay top-level.
- Account creation is **root-bound and authenticated** (Phase 1B Task 2b): the address is `["account", Keccak256("WARDEN/seed/v1" ‖ root_pubkey33 ‖ salt)]` and the instruction requires a real passkey ceremony, so a front-runner can neither squat a chosen address nor reach someone else's. The measured cost is `MAX_MINTS_AT_CREATE` = 1 (a create carrying the ceremony fits 1,232 B at one mint, not two); further mints arrive with Phase 1C `set_policy`. Known limitations live in `docs/spikes/DECISION.md`.
- Session caps in 1A are per-transaction + lifetime; **day/30-day limits are account-wide** across all sessions *and* root direct actions.

## Repository layout

```
programs/warden/          Anchor program (Rust) + LiteSVM tests
packages/core/            TypeScript SDK (transcript/challenge mirror, constants, IDL)
packages/ui-tokens/       Design tokens exported from Figma (CSS + JSON, constraint tests)
spikes/                   THROWAWAY Phase-0 evidence (never imported by product code)
docs/superpowers/specs/   Design spec (rev 8 + current binding errata)
docs/superpowers/plans/   Phase and cross-cutting security/vanity/UI plans
docs/security/            Invariant ledger, findings schema, prior-art corpus, release integrity, deploy gate
.github/workflows/ci.yml  Off-host gate: toolchain pins, build, tests, clippy, supply-chain gate
docs/research/            Security/wallet landscape and extension/mobile UI research + raw reports
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

Every task is planned from the spec, implemented by an isolated worker, and **independently reviewed by a second model (OpenAI Codex, `gpt-5.6-sol` at max effort) against the brief and the spec** before it counts as done; findings go through fix rounds with scoped re-reviews. Rulings taken along the way are recorded in the published ledgers: [Phase 0](docs/spikes/PHASE0-LEDGER.md) and [Phase 1A](docs/spikes/PHASE1A-LEDGER.md).

The Phase 1B review loop is **machine-checkable**: an ID-addressable invariant ledger (`docs/security/invariants.jsonl` → `INVARIANTS.md`), a typed findings schema every Codex round is validated against, and a review wrapper (`scripts/review.sh`) that seeds each round with the invariants overlapping the diff plus the prior-art corpus — silence on a seeded invariant is a failure, not a pass. Every round is recorded, **including zero-finding rounds** (`docs/security/REVIEW-RUNS.jsonl`), and every finding with its adjudication (`docs/security/REVIEW-SCORECARD.jsonl`); a model's own claims never auto-promote — only a human ruling or an independent evidence artefact does.

This is not decorative. The 2026-08-20 assurance pass (A0) seeded the conservation invariants and the loop then surfaced **five genuine, previously-unnoticed fund-loss defects** — Token-2022 native-SOL mis-accounting and two mint-authority-bypass classes — each confirmed by a regression test that fails against the pre-fix code and passes against the fix. A follow-on pass seeded the client, vanity-address, and deployment invariants and hardened those task specs *before implementation* — the deployment-gate governance check alone went through seven review iterations peeling back the upgrade-authority trust chain. Both close-outs, with per-finding evidence and the convergence decisions, are in `docs/program/PHASE1B-MEASUREMENTS.md`.

Security-relevant claims are backed by tests that assert exact error codes and by measured numbers rather than assumptions.

Contributions: see `CONTRIBUTING.md`. Security reports: see `SECURITY.md`.

## Non-goals for v1

Native mobile implementation, agent-key UI, quantum-resistant root signer
(kept as a typed slot — see the companion study in the drinkerlabs docs),
multi-chain, hardware wallets, fiat on-ramp, and plain-keypair accounts inside
Warden. Mobile research/prototyping may proceed under its dated plan, but it is
not a v1 implementation commitment.

## License

MIT — see `LICENSE`.
