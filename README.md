# Warden Wallet

**A Solana wallet where the limits are enforced by the chain, not by a warning you can click through.**

Warden is building a self-custody, smart-account browser-extension wallet by [drinkerlabs](https://drinkerlabs.info). The implemented on-chain foundation uses a passkey root (P-256), bounded session keys, and shared per-transaction, daily and 30-day spending limits. Timelocked larger moves and guardian recovery are planned Phase 1C work. The regular development extension supports saving and selecting public account addresses locally; wallet creation, balances, app connections, signing and sending remain unavailable in that build. A [separate devnet test build](docs/DEVNET-TEST.md) implements passkey creation, connection approval and native SOL transfers, with browser verification and live testing still outstanding.

The property we build toward, stated exactly (spec §1): *if an attacker obtains everything the extension holds while unlocked — the session key, the unlocked keyring, the ability to prompt the user — the value that can leave the account before the owner or a guardian reacts is bounded by the account's caps; anything larger is delayed and cancellable.*

> **Status: pre-alpha, under active development. Not audited. Not deployed. Do not use with real funds.**
> The on-chain program campaign used a two-model implementation/adversarial-review loop. Current extension slices record independent second-model review as **UNVERIFIED** until that lane actually runs; see [Development process](#development-process).

## What exists today

| Area | State |
|---|---|
| **Design spec** (rev 9 + binding 2026-08-19 UI/security erratum) | `docs/superpowers/specs/2026-08-18-warden-wallet-design.md` — threat model, key model, on-chain instruction set, conservation rules, recovery, rollout |
| **Phase 0 — spikes** | Done, merged. Evidence-backed answers to the four questions that could have killed the design: passkey root verified on-chain (secp256r1 precompile + Instructions-sysvar binding), transaction byte budget on real Jupiter routes, conservation-snapshot CU cost, dApp compatibility inventory. Roll-up + decision: `docs/spikes/DECISION.md` |
| **Phase 1A — program foundation** | Done, merged to `main` (Codex `sol@max` final review MERGE-READY).  `programs/warden` (Anchor): zero-copy `SmartAccount`, `SessionKey`, bucket accounting, `root_verify` (strict WebAuthn `clientDataJSON` scanner, consumed nonce), `create_account`, `grant_session`/`revoke_session`, root `freeze`/`unfreeze`, `transfer` (session within caps / root bounded, both debiting shared account-wide buckets). 292 Rust + 50 TS tests at merge (`c583dfe`). Measured costs, executable commands, evidence SHAs, and error ABI (6000–6035): `docs/program/PHASE1A-MEASUREMENTS.md` |
| **Phase 1B — execute / registry / staging / swap** | Program implementation complete on `phase1b`: conservation checks, adapter registry, staged execution, session/root execute, Jupiter v6 swap adapter, TypeScript codecs and deployment verification. Current execute caps are **32 total / 28 writable** (`programs/warden/src/constants.rs`). Audit findings and measured limits remain in `docs/program/PHASE1B-MEASUREMENTS.md`; the completed review campaign and exact historical gate command/SHA are in `docs/NEXT-SESSION.md`. External audit, production trust decisions and deployment remain outstanding. |
| **Phase 1C** (after 1B) | `queue`/pending timelock + `set_policy` policy lattice, guardians / recovery / guardian-freeze |
| **Design system** | Figma tokens + first Home/sign-request studies; current partial-match and dust-override frames are legacy/do-not-ship pending the binding audit in `docs/design/figma.md`. Extension/mobile research: `docs/research/2026-08-19-wallet-ui-extension-mobile.md`; plan: `docs/superpowers/plans/2026-08-19-warden-s-tier-ui-mobile.md` |
| **Shipped extension** | MV3 worker/content/popup boundaries, encrypted keyring infrastructure and a request-bound review page. The popup supports local public-account setup: add/name/select/reopen/remove, with storage failures handled through reload. Saved addresses confer no ownership or signing authority; no balances are fetched. The review page displays full origins and separate decoding, simulation and policy evidence. **Creation, app connections, signing and sending remain unavailable.** Browser/full-gate verification and independent review of the latest changes are pending. |
| **Devnet website test (separate build)** | Local passkey creation, verified connection and root-approved native SOL transfer flow with a `/test/` website. Not published or deployed; browser/full-gate and independent review pending. [Run instructions and prerequisites](docs/DEVNET-TEST.md). |
| **Internal extension prototypes** | Durable approval/signing/replay and worker-restart paths have automated component and Chromium contracts. `apps/extension/scripts/build.mjs` deliberately excludes the provider/signing/RPC composition from production bundles; test-harness success is not an enabled wallet feature. |
| **Next product milestones** | Verify the devnet website/extension flow in Chrome, complete independent review and the full gate, obtain an authorized devnet program deployment, then test live creation/transfer and publish `/test/` through the applicable Warden procedure. Existing onboarding/security verification debt remains open. Production KDF policy, extension identity/origin, provider bootstrap, trust material and Wallet Standard registration remain separate requirements. |

Current critique and build evidence: [`docs/CRITIQUE-2026-09-05.md`](docs/CRITIQUE-2026-09-05.md).
Current pickup contract: [`docs/NEXT-SESSION.md`](docs/NEXT-SESSION.md).

Historical pickup for the 2026-08-19 security, vanity, and UI research campaign:
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

The Phase 0/1 program campaign planned tasks from the spec, implemented them in
isolated lanes, and independently reviewed them with a second model against the
brief and spec before counting them done; findings went through fix rounds with
scoped re-reviews. Rulings are recorded in the published ledgers: [Phase
0](docs/spikes/PHASE0-LEDGER.md) and [Phase
1A](docs/spikes/PHASE1A-LEDGER.md). Newer extension trust-boundary work uses the
same evidence discipline but does **not** claim an independent review that has
not run; each handoff and threat-model entry says `UNVERIFIED` explicitly.

The Phase 1B review loop is **machine-checkable**: an ID-addressable invariant ledger (`docs/security/invariants.jsonl` → `INVARIANTS.md`), a typed findings schema every Codex round is validated against, and a review wrapper (`scripts/review.sh`) that seeds each round with the invariants overlapping the diff plus the prior-art corpus — silence on a seeded invariant is a failure, not a pass. Every round is recorded, **including zero-finding rounds** (`docs/security/REVIEW-RUNS.jsonl`), and every finding with its adjudication (`docs/security/REVIEW-SCORECARD.jsonl`); a model's own claims never auto-promote — only a human ruling or an independent evidence artefact does.

This is not decorative. The 2026-08-20 assurance pass (A0) seeded the conservation invariants and the loop then surfaced **five genuine, previously-unnoticed fund-loss defects** — Token-2022 native-SOL mis-accounting and two mint-authority-bypass classes — each confirmed by a regression test that fails against the pre-fix code and passes against the fix. A follow-on pass seeded the client, vanity-address, and deployment invariants and hardened those task specs *before implementation* — the deployment-gate governance check alone went through seven review iterations peeling back the upgrade-authority trust chain. Both close-outs, with per-finding evidence and the convergence decisions, are in `docs/program/PHASE1B-MEASUREMENTS.md`.

The loop is deliberately **not single-provider**. On 2026-08-23 the Codex lane was
blocked three consecutive times by OpenAI's cyber content filter — a documented
false positive triggered by our *own* defensive regression tests, which execute a
token drain to prove a vulnerability was real. `scripts/review-grok.sh` therefore
makes a second provider (xAI `grok-4.3`) a **recorded** reviewer through the
identical machinery: wrapper-computed seeds, an expectations file the validator
checks the model against, and atomic dual-ledger recording with rollback. It is a
fallback, not an equivalent: its first round is recorded with an explicit
calibration note that it produced a materially shallower review than Codex and
missed an invariant the range had changed. A zero-finding round from a weaker
reviewer means *"nothing this reviewer could see"*, never *"this range is clean"*.

Security-relevant claims are backed by tests that assert exact error codes and by measured numbers rather than assumptions. Where a property is only partly true it is recorded as partly true: `WRD-EXEC-09` is half-implemented by design and still reads `unimplemented`; the `WRD-KEY-*` rows stay `unimplemented` even though their crypto primitives are built and tested, because nothing yet produces or consumes them. **A correct primitive is not a satisfied product invariant.**

Contributions: see `CONTRIBUTING.md`. Security reports: see `SECURITY.md`.

## Non-goals for v1

Native mobile implementation, agent-key UI, quantum-resistant root signer
(kept as a typed slot — see the companion study in the drinkerlabs docs),
multi-chain, hardware wallets, fiat on-ramp, and plain-keypair accounts inside
Warden. Mobile research/prototyping may proceed under its dated plan, but it is
not a v1 implementation commitment.

## License

MIT — see `LICENSE`.
