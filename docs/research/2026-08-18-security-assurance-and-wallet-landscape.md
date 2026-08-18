# Warden — security assurance with a second model, and what the Solana wallet landscape teaches

**Date:** 2026-08-18 · **Status:** decision document · **Inputs:** 20 research reports in `docs/research/raw-2026-08-18/` (cited `[R01]`–`[R20]`) and `critic.json` · **Checked against:** spec rev 7, the Phase 1B plan, `docs/spikes/DECISION.md`, `docs/program/PHASE1A-MEASUREMENTS.md`, and `programs/warden/src/` at `a02aaf0`.

**Read this first.** Six of the twenty reports analysed `execute`, the adapter registry and the conservation checks as if they were shipped code. They are not. `programs/warden/src/instructions/` contains exactly `create_account`, `freeze`, `unfreeze`, `grant_session`, `revoke_session`, `rotate_nonce`, `transfer` [R13, critic §contradictions]. Everything those reports say about `execute` is **design input for Phase 1B**, never an audit finding. Every claim below that touches code has been checked against the source.

---

## 0. TL;DR

1. **Fix the test harness before adding any assurance layer.** A live probe proved LiteSVM does verify secp256r1 for real (forged sig → `InstructionError(0, Custom(2))` = `PrecompileError::InvalidSignature`), but **no shipped test exercises a cryptographically invalid signature** — all 33 `root_verify` negatives are honestly-signed [R16]. A dependency bump that drops the `precompiles` feature would silently make `bind_precompile` the only gate on the root of trust. This invalidates the ordering every other assurance report proposed.
2. **The single highest-leverage process change is an ID-addressable invariant ledger** (`docs/security/INVARIANTS.md` + `.jsonl`), because today Codex reviews against nothing but the diff and its own judgement [R15, critic §unanswered "Codex process (1)"].
3. **Every review must be seeded with the prior-art finding corpus** — ACC-C1/C2/H1/H2/M1/M2, TOB-SQUADS-7/8, ND-SQD3-LO-01, Swig ACC-C1/C2, Argent zero-guardian. This is the cheapest counter to shared LLM blind spots on Solana-specific bug classes [R12, critic].
4. **Codex output becomes typed JSON, not prose** (`codex exec --output-schema`), with a hard rule: a `VIOLATED` verdict without a reproducing red test is auto-downgraded to `INCONCLUSIVE` [R03, R15].
5. **Do not restructure the review loop** to Claude-reviews-Codex on the strength of the cited +18.1/−8.6pp asymmetry. It comes from isolated Python tasks; an executed n=1-per-direction pilot found real bugs and real false positives on *both* sides, and the one false positive was caused by **reviewer scope, not model identity** [R19].
6. **Warden's replay design is already best-in-class** — an O(1) scalar `root_nonce` with strict `n+1` equality, matching LazorKit and Swig, not the O(n) "consumed-nonce set" the spec's wording implies. **But its freshness window is 10–25× wider than both peers** (600 s wall-clock vs 150/60 slots) and anchored to `Clock::unix_timestamp` rather than `slot` [R18]. Tighten it.
7. **Warden's conservation-check ambition is genuinely ahead of the field.** Squads v4's `vault_transaction_execute` performs *no* balance or state validation before or after CPI at all [R20]. Nobody else runs before/after field-by-field diffing as the primary control — which also means it is an **unvalidated bet** nobody has audited in production.
8. **Four concrete gaps in the unbuilt `execute` design**: no hard deny-list for `SetAuthority`/`Approve`/`CloseAccount`; Mint accounts not in the snapshot set; net-only accounting has a wash-trade blind spot; non-WSOL rent lamports on `CloseAccount` are invisible to both outflow equations [R20].
9. **Token-2022 confidential-transfer mints break the conservation model outright** (amounts are ZK-hidden) — they cannot be an allow-listable extension, they must be permanently out of scope [R14].
10. **Warden's bucket accounting is already epoch-floored UTC days with correct skipped-slot zeroing** (`buckets.rs:52-66`, verified). [R05]'s "adopt Swig-style epoch-floor" is already satisfied; its rationale was asserted, not argued [critic]. No change.
11. **UV is mandatory in Warden and merely parsed-but-never-called in LazorKit** — a real-world instance of the exact slip, and a genuine Warden advantage [R04, O10 CLOSED].
12. **Licensing constrains what "copy" can mean**: only LazorKit `program-v2` is MIT and vendorable. Swig and Squads v4/v5 are AGPL-3.0, Backpack GPL-3.0 — design reference only, clean-room reimplementation, with a copy-detection item added to the review prompt [R17].
13. **The biggest non-program risk is the release channel, not the code.** Trust Wallet lost $7–8.5M in Dec 2025 to a leaked Chrome Web Store publisher API key harvested by an npm worm — inside all of Google's 2FA rules [R06].
14. **Do not integrate a third-party simulator as a verdict source.** Coinspect showed Blowfish silently missing an `assign` ownership transfer while Phantom displayed "Receive 1 SOL" [R10]. Reputation/blocklist feeds only, advisory, never gating.
15. **Provenance lesson:** [R14] asserted that SIMD-0579/keccak-p1600 "does not exist". Controller re-check (2026-08-18, `gh pr view 579 -R solana-foundation/solana-improvement-documents`): **PR #579 "SIMD-0579: Keccak-p1600 syscall" exists and is OPEN** (its predecessor #563 is CLOSED); it is not a merged proposal in `proposals/`, which is what R14 searched. Both the original claim ("live thread") and the rebuttal ("fabricated") were half-right — status: an open, unmerged PR, not an activated syscall. Provenance discipline is not optional in this pipeline.

---

## 1. Assurance pipeline with Codex — the "watertight" plan

Ordered by dependency. Each layer states what it *proves* and what it costs. Layers 0–3 are prerequisites; skipping to 5 or 6 buys false confidence.

### L0 — Harness fidelity (do this first; blocks everything)

**Proves:** that the substrate the other layers run on actually enforces the cryptography.

`Cargo.toml:40` pins `litesvm = { version = "0.12", features = ["precompiles"] }` and `common::setup` calls `.with_mainnet_features()`; LiteSVM 0.12's `process_precompile` calls `agave-precompiles::get_precompile(...).verify(...)` — real crypto, not a stub, confirmed by live probe [R16]. But `precompiles` is not LiteSVM's default, `LiteSVM::default()` starts with every feature off, and 0.13+ jumps to Agave 4.x. Nothing in the suite would notice a regression.

**Changes:** `programs/warden/tests/sigverify_wiring.rs` — forged-signature test asserting **`InstructionError(0, Custom(2))` specifically**, not "any error", plus a positive control (honest signature over a *different* message, must fail for a different reason). Pin `litesvm = ">=0.12, <0.13"` with a comment naming this chain. Add `.github/workflows/ci.yml` (none exists today): test-gate + clippy + `cargo tree -p litesvm -e features | grep precompiles` as a hard gate.

**Cost:** under a day. **Dependency the reports missed:** [R03] wants PoC-backed findings, but until L0 lands there is no substrate to reproduce a passkey bug on [critic].

### L1 — Invariant ledger (`docs/security/INVARIANTS.md`)

**Proves:** nothing by itself. It makes every later layer addressable — "Codex ruled on WRD-EXEC-07", not "Codex reviewed it".

Precedent: Certora's Squads v4 report publishes named properties (P-02, P-04, `invariant_vault_proposal_approved`) each with Verified/Violated status and a link to the machine-generated rule report [R15]. Same shape: **ID → statement → spec ref → code ref → prior art → proof status → evidence**.

Schema (JSONL is source of truth; the `.md` is generated):

```json
{"id":"WRD-EXEC-07",
 "statement":"No inner instruction of execute may set a delegate on a vault-owned token account.",
 "spec_ref":"docs/superpowers/specs/2026-08-18-warden-wallet-design.md#5.2 rule 3",
 "code_ref":"programs/warden/src/conservation/compare.rs:NN",
 "prior_art":["SWIG-ACC-C1","LZR-ACC-I2"],
 "status":"unimplemented|llm-asserted|test-covered|mutation-tested|proven",
 "evidence":["programs/warden/tests/execute.rs::mutator_set_delegate_rejected"]}
```

Namespaces from Warden's own surface: `WRD-ROOT-*`, `WRD-CD-*` (clientDataJSON), `WRD-NONCE-*`, `WRD-SESS-*`, `WRD-CAP-*` (buckets), `WRD-EXEC-*`, `WRD-REG-*`, `WRD-STAGE-*`, `WRD-TL-*` and `WRD-GRD-*` (1C), `WRD-BUF-*` — pre-seeded now from ND-SQD3-LO-01 *and* Certora H-01, two firms and two methods hitting the same unbounded-uncleanable-buffer-PDA bug, and Warden's `Stage` PDA is that shape [R15].

**Seed `docs/security/PRIOR-ART-FINDINGS.md` in the same commit**, one entry per finding with its primary source and the Warden surface it maps to. Non-negotiable: **TOB-SQUADS-7** (unauthenticated `create_key` front-run) and **TOB-SQUADS-8** (ephemeral signer seeds not per-transaction) — [Trail of Bits, Squads v4](https://github.com/Squads-Protocol/v4/blob/main/audits/trail_of_bits_squads_v4_security_audit.pdf); **ND-SQD3-LO-01** (buffer PDA seeds lacking the creator pubkey); LazorKit **ACC-C1** (accounts bound by *index, not pubkey*), **ACC-C2** (owner-role branch skipping "target belongs to this wallet"), **ACC-H1** (accounts omitted from the signed payload → rent theft), **ACC-H2** (write/read layout drift corrupting `rp_id_hash`), **ACC-M1** (truncated slot index wrapping), **ACC-M2** (no instruction discriminator in the signed payload) — [`audits/…-lazorkit-audit-A26SFR1.pdf`](https://github.com/lazor-kit/program-v2), 14 findings, all fixed; **Swig ACC-C1** (post-CPI field checks without re-checking the token account's *program owner* — close-and-reopen under an attacker program passes every field check) and **ACC-C2** (no restriction on which instructions a limited role may submit); **Argent zero-guardian** (`ceil(0/2)==0` → recovery with no signatures, [OpenZeppelin](https://www.openzeppelin.com/news/argent-vulnerability-report)).

**Cost:** ~1 day to seed, ~15 min per invariant after.

### L2 — Per-task review, restructured

**Proves:** that a second model, seeded with the ledger, could not name a violated invariant it could reproduce.

Today (`CLAUDE.md`): every task implemented by an isolated worker, adversarially reviewed by Codex `gpt-5.6-sol@max` in a fresh thread. Already better than most. Five changes:

1. **Structured output** — `codex exec --profile warden-review --output-schema .codex/schemas/finding.json`. **Gotcha:** `--output-schema` is *silently ignored* when MCP servers/tools are active, so the schema pass must be separate and tool-free, after any context-gathering pass [R03].
2. **Evidence-bound findings.** Schema `{invariant_id, verdict: VIOLATED|HELD|INCONCLUSIVE, severity, file:line, prior_art_cited[], reproducing_test:{path,name,fails_on_HEAD}, confidence, notes}`. **A `VIOLATED` with no red test on `HEAD` is mechanically downgraded to `INCONCLUSIVE`** — the PoCo pattern, the strongest available mitigation for the ~10% invented-vulnerability rate ensembles still show [R03, R15].
3. **Clean tree, always.** `codex review --base <sha>` on a dirty tree repeats *hallucinated* findings unrelated to the diff ([openai/codex#8404](https://github.com/openai/codex/issues/8404)) — precondition check in the review script.
4. **Fix reviewer scope, not model identity.** The pilot's one false positive was Codex flagging `cluster_tag` binding in `create_account.rs`, a property `root_verify/transcript.rs:69-76` already documents as a known deferred client-attested separator — Codex wasn't shown that file [R19]. **Every round must name the sibling files carrying cross-cutting invariants** (`root_verify/transcript.rs`, `state/session.rs`, `errors.rs`, `buckets.rs`) plus the ledger entries whose `code_ref` overlaps the diff. Silence on a seeded invariant is a FAIL.
5. **Blind and anti-rewrite.** Diff + spec section + seeded invariants; withhold author/task framing; instruct explicitly against rewriting working code (the 11.2% regression rate in the one cross-model study came from unnecessary rewrites). Standing checklist item for **dimensional/scaling bugs** (`dimensional-analysis` skill): Moonwell shipped Claude-authored code using a cbETH/ETH ratio as if USD-denominated — 2,000× underpricing, $1.78M, human reviewer missed it [R03]. Structurally invisible to free-form review, and exactly what the conservation checks exist to catch.

**Cost:** unchanged token spend, one afternoon of scripting.

### L3 — Scorecard (`docs/security/REVIEW-SCORECARD.jsonl`)

**Proves:** how often the reviewer is wrong — a question the current process structurally cannot answer.

Four Codex rounds on Phase 1A produced 1 Critical, 4 Important, 6 Minor, **100% adopted** — a survivorship artifact of what gets committed, not an FP rate of 0% [R19]. Log every finding, including disputed and scoped-out ones, with adjudication rationale; monthly, blind-re-review a 1-in-10 sample of `HELD` verdicts, weighting a false negative worse than a false positive. One real regression is already on record: the round-1 fix for the P-256 root check over-corrected and rejected `x = 0`, a valid P-256 point, caught by a *second* Codex round [R19, `4b409f7`]. **Rule: any diff that moves an accept/reject boundary gets a mandatory second-round confirm.**

### L4 — Adversarial test generation + mutation testing

**Proves:** that the tests actually assert what they claim.

- **`cargo-mutants` now.** Operates at the `cargo test` level, needs no Solana-specific integration, works unmodified against the existing 292-test suite [R01]. Targets: `buckets.rs` day/ring rollover and cap comparison operators, `client_data.rs` grammar boundaries, later `conservation/compare.rs`. **Gate CI on a mutation-score floor for these modules, not line coverage.**
- **Codex writes attack tests against mutants.** The protocol that makes generated tests trustworthy: give Codex a `cargo-mutants` survivor plus the invariant statement; it must produce a test that **FAILS against the mutant and PASSES against the real program**, both checked mechanically. This closes the known weakness that LLM-generated properties score far below hand-written ones on mutation (25.99% vs 31.75%) unless mutation-guided [R03].
- **`proptest-state-machine` over a reference model.** Pure-Rust `ReferenceStateMachine` of `SmartAccount`/`SessionKey`/bucket state; random sequences (grant/revoke, boundary-amount transfers, day and 30-day rollovers, freeze/unfreeze, `execute` with CPI) replayed against LiteSVM as SUT with post-state equality asserted [R01]. Doubles as the near-spec that makes L6 affordable.
- **Trident fuzzing on two targets only:** `root_verify/client_data.rs` (attacker-controlled JSON) and, in 1B, the `ExecutePayload` parser (attacker-controlled index/flag encoding) [R01]. Port LazorKit's regression vector verbatim — `{"tokenBinding":{"id":"x}y"},"challenge":"real"}`, where a `}` inside a nested string desynced their brace-depth tracker and mis-located `challenge` [R04]. Warden's depth-0 validator should reject it; prove it does.
- **Independent reimplementation → differential test.** The second-model use nobody proposed [critic]: have Codex reimplement the clientDataJSON scanner and `buckets::debit` from the *spec text alone*, then differential-fuzz the pair. In the pilot, Codex-authored ring-buffer code had a real cap-weakening bug (writing the closed day into `ring[kept-1]` instead of `ring[RING_DAYS-1]`, permanently understating 30-day spend), caught first-pass by *running* it [R19]. Warden's `buckets.rs` does not have that bug — verified — which is the kind of confirmation differential testing gives cheaply.

**Cost:** mutation runs are compute-heavy and must respect this host's serialized-build rule — nightly, not per-commit.

### L5 — Whole-repo weekly sweep + threat-model diff

**Proves:** cross-file interactions diff-scoped review structurally cannot see — the registry × conservation × bucket interaction is exactly that shape.

Weekly, tool-free schema pass at `sol@xhigh`, whole-repo, cross-checked against an independent Claude sweep in a fresh thread. **Promotion rule: only findings both models raise, or that ship with a reproducing test, enter the ledger; singletons go to a `candidates` bucket** [R03]. Per milestone, append to `docs/security/THREATMODEL.md` what changed in the trust surface (passkey verify, precompile introspection, caps/buckets, registry, conservation, timelock, guardians) — SHA-stamped, append-only, sign-off before merge.

### L6 — Formal verification

**Proves:** properties over all reachable states, not sampled ones.

**Certora Solana Prover / CVLR** is the only production-credible option — Squads v4 was its first Solana engagement (Aug 29–Oct 5 2023, "no major security flaws"), with returns through Jan 2025 [R01, [squads.xyz](https://squads.xyz/blog/certora-formal-verification-squads-protocol-v4)]. Its init-establishes / every-method-preserves model matches Warden's account-state arithmetic.

**Prove first, in this order:** (1) **bucket conservation** — `spent_today == Σ` of the day's debits, `Σ(ring) ≤ per_30d`, no slot survives a rollover that should have zeroed it; (2) **cap dominance** — every accepted spend satisfies `amount ≤ min(per_tx, per_day − spent_today, per_30d − Σring)` and, for sessions, `lifetime_spent + amount ≤ lifetime_cap`; (3) **root nonce monotonicity** — `root_nonce` increases by exactly 1 per successful ceremony and never decreases, so no assertion is consumable twice; (4) after 1B, **`execute` creates no value** — no path increases a vault balance without an accounted inflow, and no vault-owned token-account field but `amount` differs before/after.

Do this **after** L4's reference model stabilises: the proptest model is nearly a spec-in-Rust and sharply lowers CVLR-writing cost [R01]. **Caveat:** "public repo likely qualifies for Certora's free OSS tier" is sourced to a CVL rules doc, not a pricing page [critic] — get a written quote first. Budget ~5 weeks of calendar time.

**Kani: watch-list, not adopt.** OtterSec's Kani/`anchor-lang` prototype is a Jan-2023 "mostly working" effort with path explosion and "CPI verification difficult if not impossible" [R01] — but OtterSec *did* use Kani productively in the 2024 Squads audit to prove concrete invariants (≥1 proposer/executor/voter, no duplicate members, `threshold > 0`, `remaining_amount ≤ amount`, transaction non-malleability, signer-seed uniqueness) [R12]. Ask the audit firm to bring it; don't build it. **SseRex** is a 2026 paper with no packaged CLI.

### L7 — Pre-deploy recon, audit, bounty, build integrity

- **Audit-prep artifacts, adopted wholesale from LazorKit** [R09, R12]: tag `audit-frozen-v1`; record the SBF SHA-256 and `solana-verify get-program-hash`; a CI gate that `git grep`s for `TODO`/`unimplemented!`/`#[ignore]` on the audit branch; a `DELTA_BRIEF.md` + `upstream-parity.txt` so re-audits are scoped to the true delta.
- **`solana-verify` as a release gate**, not a verification technique — it proves deployed bytecode matches audited source. Not assurance in itself: Accretion published a defeat of the pipeline [R01].
- **Pre-deploy recon upgraded:** every unproven HIGH-severity ledger entry needs an attempted exploit against a LiteSVM/localnet fork before go/no-go [R03].
- **External audit + public bounty before real funds** (already spec §10/§11). Squads' tiering is the reference shape: theft $300k, fund-freezing $200k, replay $25k, unauthorised config change $10k [R05].
- **Improve on-chain logging** — Trail of Bits rated Squads' "not sufficient for off-chain monitoring to detect an ongoing attack" [R12]. Emit structured events on every bucket debit, cap rejection, freeze and (1C) timelock trigger, so the notifier — the second channel that makes threat T3 survivable — has something to watch.

### L8 — The A/B that decides review-loop shape (run during 1B, don't pre-empt)

Run matched pairs across ~10–15 Phase-1B sub-tasks: each scope reviewed by Claude, by Codex, and by both, blind, scored against a fixed third adjudicator. `execute`, the registry, and the payload parser have plenty of function-scale surface [R19]. Until that returns, the loop stays as it is.

### Repo change list (one commit each)

| Path | What |
|---|---|
| `programs/warden/tests/sigverify_wiring.rs` | L0 forged-signature + positive-control tests |
| `.github/workflows/ci.yml` | test-gate, clippy, litesvm feature assertion, mutation-score floor (nightly) |
| `docs/security/INVARIANTS.md` + `invariants.jsonl` | L1 ledger, generated `.md` |
| `docs/security/PRIOR-ART-FINDINGS.md` | seeded corpus, one entry per audit finding + primary URL |
| `docs/security/REVIEW-SCORECARD.jsonl` | L3 per-finding outcomes |
| `docs/security/THREATMODEL.md` | append-only per-milestone trust-surface diff |
| `.codex/schemas/finding.json`, `.codex/profiles/warden-review.toml` | schema + tool-free review profile |
| `scripts/review.sh` | clean-tree check → seed invariants + sibling files → schema pass → validate → append |
| `THIRD_PARTY_NOTICES.md` | licence provenance ledger (see §2) |
| `.claude/test-gate.sh` | add clippy, IDL parity already present, mutation-floor hook |

---

## 2. Landscape — adopt, avoid, and where Warden is already ahead

**LazorKit `program-v2` (MIT — the one vendorable source) [R04, R09, R12, R17, R18].** Closest comparator: Pinocchio, on-chain WebAuthn via the same precompile + Instructions-sysvar pattern.
- *Adopt — `stack_height` CPI rejection.* LazorKit rejects `get_stack_height() > 1` in its authenticator. **`grep -rn stack_height programs/warden/src/` returns nothing**; Warden's "self-CPI into warden is rejected" is a different property. Add a transaction-level stack-height assertion in `root_verify::verify_root_assertion` — cheap, and it removes a whole class of middleman-program reasoning. → spec §5.1 cross-cutting.
- *Adopt — `TokenAuthoritySnapshot` semantics for 1B.* Their module doc: *"Security model (learned from Swig wallet): balance increases ignored, only outflows count; state mutations only after all checks pass."* They freeze owner/delegate/close_authority pre-CPI, re-verify post-CPI, and use **gross** outflow for per-tx caps specifically to block round-trip-CPI laundering. Warden's 1B plan snapshots those fields but has **no gross figure**. → §5.2 rule 4 + 1B Task 1.
- *Adopt — the delta-brief / upstream-parity practice* → L7.
- *Already ahead:* Warden mandates **UV**; LazorKit parses `is_user_verified()` and never calls it in `authenticate()` [R04]. Warden's `bind_precompile` also enforces `num_signatures == 1` and compares `message_data_size` before the bytes — neither documented in the peers. *Already converged:* `0xFFFF`-only offsets, stored-and-compared `rp_id_hash` (Warden recomputes SHA-256(origin) on-chain at create — stronger), ignoring the hardware sign counter.

**Swig (AGPL-3.0 — design reference only) [R05, R09, R12].**
- *Adopt — destination-scoped sub-limits* (`SolDestinationLimit`/`TokenDestinationLimit` pin a role to a counterparty; Warden's caps are amount-only) → Phase 1C, `SessionKey.destination_allowlist_id`.
- *Adopt as a mandatory 1B test — Swig ACC-C1.* `sign_v1` checked end-state field *values* after CPI but never the token account's actual **program owner**; an attacker transferred out, closed the account, reopened it under a program faking the byte layout, and drained with a 1-lamport role. Warden's 1B `Snap` carries `owner_program`, so the design covers it — but that must be a named negative test, not an inferred property. → 1B Task 5.
- *Reject —* [R05]'s switch to Swig's `floor(slot/window)*window`. Warden already floors to UTC days; the critic is right that epoch alignment arguably *worsens* boundary double-spend, and spec §5.1 already states the honest 2× bound. No change.

**Squads v4 / v5 / Fuse (AGPL-3.0) [R05, R09, R11, R12, R20].**
- *Adopt — TOB-SQUADS-7 as the create-fix template.* Unauthenticated `create_key` let an attacker front-run `multisig_create` and squat the PDA with their own members. **This is precisely Warden's open gap** [R15]. The 1B answer is already stronger (`owner_seed = Keccak256("WARDEN/seed/v1" ‖ root_pubkey33 ‖ salt32)` **plus** a mandatory root ceremony at create) — keep it and keep the squat-race test.
- *Adopt — ND-SQD3-LO-01 for `Stage`.* `TransactionBuffer` PDAs seeded without the creator's pubkey let one member fill all 256 slots with unclosable garbage. Warden's `Stage` is content-addressed, so anyone observing the payload can pre-open that hash. `expiry_ts` + anyone-may-close likely suffices; add `stranger_pre_opens_stage_at_our_hash` and a `WRD-BUF-*` entry rather than assuming.
- *Adopt — the timelock/cancel state machine* for 1C: Approved → time-locked → Executable, cancellable by any voter while pending, **re-validating effects at execution time**. Drift lost ~$270–285M in April 2026 to pre-signed governance intents executed later via durable nonces without re-scrutiny [R02].
- *Reject — the iframe/allowlist connector.* `@sqds/iframe-adapter` needs the dApp to install a package, set `frame-ancestors`, and be manually onboarded over Telegram [R11]. Warden's Wallet-Standard wrapper reaches unmodified dApps. Confirmed keep.
- *Already ahead:* `vault_transaction_execute` does **no** conservation checking — approval alone [R20]. Warden's §5.2 has no peer, which also makes it an unvalidated bet requiring L4/L6, not a settled advantage.
- *Unresolved:* whether the Squads smart-account program ships passkeys at all [critic]. **Do not model 1C guardians on assumed Squads maturity.**

**Backpack (GPL-3.0) [R06, R08, R17].** A conventional password-encrypted HD keyring (PBKDF2-600k → NaCl secretbox), zero on-chain enforcement. *Adopt two UX primitives only:* (1) a **fresh re-auth gate for high-risk actions** — Backpack re-checks the password before mnemonic export even when unlocked; Warden should require a fresh passkey ceremony before guardian changes and policy loosening (→ spec §6, §7); (2) the **`isCold` blocking screen**, generalised to "this session key is being used outside its usual adapter pattern". *Do not build the xNFT runtime* — an app runtime inside the wallet is large surface for phishing resistance the adapter registry already gives [R06]. Backpack's 2023 "source available, not open source" framing cost it credibility; Warden's MIT claim must stay accurate.

**Phantom / Solflare / Glow / Jupiter Mobile / Seed Vault [R10].** All closed or SDK-only cores; Ledger `app-solana` is the one genuinely open (Apache-2.0). *Adopt:* versioned txs + ALTs + a priority-fee UI are table stakes; fork or subscribe to Phantom's community-maintained domain blocklist rather than building one; monitor for clone-drainers (the FoxyWallet campaign forked open-source wallet code, injected drainers, republished — Warden being public makes this near-certain). *Structural win already held:* Warden's no-seed-phrase default eliminates the class that drained ~8–9k wallets via Slope in 2022.

**Wallet Standard / MWA [R11].** `verifySignIn`/`verifyMessageSignature` call `ed25519.verify` directly and `signatureType` is the single literal `'ed25519'`. There is **no Solana ERC-1271 and no SIMD filling the gap**. A PDA is off-curve by construction, so `isOnCurve()` gates (Ledger Live, enKrypt) and `allowOwnerOffCurve`-guarded SPL helpers throw rather than degrade. *Decisions:* SIWS stays explicitly unsupported in v1 **with a clear message rather than a silent failure** (blast radius per Warden's own inventory: 1 firm dApp + 2 subflows of 20); publish an `isOnCurve` compatibility note; work the adapter-registry backlog by the six `root-only` dApps (Tensor, Sanctum, Parcl, Helium, Realms voting, Squads) as cheap wins; build no bespoke SIWS bypass.

**Runtime facts that bind [R14]** (live mainnet RPC, 2026-08-18): **CPI depth is still 4** — SIMD-0268's feature account is `null`, not even queued, so [R02]'s "will be 8 on Agave v3+" must not enter any plan; 1,232 bytes holds (SIMD-0296/0385 have no feature keys); account locks are 128 (Solana's own docs are stale); block CU 60M, per-writable-account 24M; secp256r1 costs **4,800 CU** and is active; the CPI account-info limit 64→255 **is** live. *Adopt:* a small on-chain feature-account poller instead of trusting SIMD status labels, which lag activation both ways.

**Token-2022 [R14, R20].** `permanent_delegate` and `permissioned_burn` are rug-shaped; `transfer_hook` reopens arbitrary CPI per transfer and can exhaust the depth-4 budget mid-transfer; `transfer_fee` makes received < sent, so equality checks false-positive; **`confidential_transfer`/`confidential_mint_burn` hide amounts and break visible-amount conservation entirely.** *Decision:* the first two deny-only, never allow-listable; `transfer_fee` gets `delta ≥ amount − max_fee`; **confidential mints become a permanent non-goal, not a policy toggle** — a correction to spec §5.2 rule 5, which currently implies all three are allow-listable. Pin `spl-token-2022` carefully; v9.1.0 moved extension logic into `spl_token_2022_interface`.

**Drainer landscape [R06, R13].** The most Solana-specific and damaging pattern is **SetAuthority / account-authority transfer**, irreversible even with the right key — Warden's PDA custody blocks it *unless the registry ever allow-lists it*, which is why the deny-list must be hard-coded above the registry. Instruction stuffing is real (the "Crypto Copilot" extension inserted extra `SystemProgram.transfer` instructions into Raydium swaps, skimming 0.05%), which is why conservation must be **multi-mint**, not primary-asset. Address poisoning and clipboard hijack are UI-truth problems caps cannot touch. The largest single loss in this corpus was a **library** compromise (`@solana/web3.js` 1.95.6/1.95.7, [GHSA-jcxm-7wvp-g6p5](https://github.com/solana-labs/solana-web3.js/security/advisories/GHSA-jcxm-7wvp-g6p5)) — and Warden's `SECURITY.md` says nothing about lockfile pinning or CI provenance.

**Extension supply chain [R06]** — the highest-value 2026 lesson, and it isn't about code. Trust Wallet, Dec 24 2025: a leaked Chrome Web Store publisher API key (harvested by the Shai-Hulud 2.0 npm worm) pushed a malicious v2.68 that exfiltrated decrypted mnemonics — $7–8.5M, ~2,500 wallets, entirely within Google's 2FA rules. *Adopt before any store listing exists:* CWS publisher credentials on a separate human-gated release path, never in CI env vars reachable by `npm install`; SES/LavaMoat capability attenuation (cheap now, a retrofit MetaMask never finished); reproducible builds from v1; no broad `webRequest`/`declarativeNetRequestWithHostAccess` permissions (QuickLens used exactly that to strip CSP). Treat the MV3 service worker as untrusted-for-secrets — it idles at ~30s, so session material re-derives from `chrome.storage.session` and auto-lock is wall-clock, not worker-liveness.

**Simulation vendors — the contradiction the reports left open [critic].** [R06] recommends Blowfish/Blockaid; [R10] documents Blowfish silently missing an `assign` while Phantom displayed "Receive 1 SOL"; [R08] shows Backpack depending on it. **Resolution: on-chain conservation is the verdict; third-party simulation is never a gate.** Take only what Warden's architecture cannot cover — pre-connect dApp reputation and token blocklists, rendered advisory — plus Backpack's *presentation* (normalised colourised balance diffs, plain-language warnings) over Warden's own simulation instead of a raw instruction dump.

**Licences [R17] — what "copy" may mean.** Verified against each `LICENSE`: **LazorKit `program-v2` = MIT** (vendorable with a `THIRD_PARTY_NOTICES.md` entry); **Swig, Squads v4 and `smart-account-program` = AGPL-3.0**; **Backpack = GPL-3.0** — design reference only, clean-room reimplementation from a written spec with the source closed. Warden is MIT. Copyleft attaches to the *combined work* and extension distribution unambiguously triggers GPL §5; whether AGPL §13 network-use reaches on-chain program execution is untested — **do not rely on it not applying.** The two Squads v4 Apache/MIT carve-out files are generic utility code of no value here. *Action:* create `THIRD_PARTY_NOTICES.md` now, and add a standing review-prompt item — *"does this diff reproduce structure, naming, or comments recognisably from Swig/Squads/Backpack?"* Substantial similarity, not just verbatim copying, creates exposure. Don't reuse the names or marks either way.

---

## 3. Concrete deltas

### (a) Spec rev 8 edits

1. **§4 (replay):** rename "consumed nonce"/"consumed-nonce set" to **"root nonce (odometer)"** and state O(1) storage — today's wording invites a future engineer to "fix" a rent-growth problem that doesn't exist [R18].
2. **§4 + §5.1:** add a **slot-relative freshness check** alongside `expiry_ts`. The 600 s wall-clock window is 10–25× LazorKit's 150 slots and Swig's 60, and is anchored to `Clock::unix_timestamp` (a stake-weighted estimate) rather than `slot`. Set **N ≈ 150–300 slots (~60–120 s)** on the default path; keep the wide wall-clock deadline only for 1C's deferred/timelocked flow [R18].
3. **§5.1 cross-cutting:** transaction-level `stack_height` requirement for root instructions [R04, R09].
4. **§5.2 rule 1:** a **hard-coded deny-list in the fixed ABI-decode path, above and outside the registry** — Token/Token-2022 `SetAuthority(6)`, `Approve(4)`, `ApproveChecked(13)` unconditionally; `CloseAccount(9)` unless the lamport destination resolves to the vault PDA. §5.4 says loosening *extends* the registry, so a deny living only in the registry is not a floor [R13, R20]. Verify the discriminator values against SPL source — UNVERIFIED in the report.
5. **§5.2 rule 2:** extend the snapshot set to **Mint accounts** the vault has authority over (`mint_authority`, `freeze_authority`, T22 `TransferFeeConfig` authorities), byte-compared; only token *accounts* are named today [R20].
6. **§5.2 rule 4:** add a **gross-turnover bucket** per mint per session per day, independent of the net caps, with a looser ceiling — net-only accounting lets a session round-trip X→Y→X through an allow-listed DEX, bleeding value to fees and slippage at near-zero net debit [R20]. Also fold **non-WSOL rent lamports from `CloseAccount`** into the SOL outflow sum. And state that **per-tx caps enforce on gross outflow, day/30-day/lifetime on net** [R09].
7. **§5.2 rule 5 + §13:** split Token-2022 policy three ways — `permanent_delegate`/`permissioned_burn`/`transfer_hook` **deny, never allow-listable**; `transfer_fee` allowed with `delta ≥ amount − max_fee`; **confidential-transfer mints a permanent non-goal**, since hidden amounts make conservation unverifiable [R14].
8. **§4 / §5.1 (sessions):** an **expired session's caps are exhausted, not absent** [R09].
9. **§2 (threat model):** add a **synced-passkey extraction** row — three disclosed 2026 attacks (SpecterOps/Entra replay, Unit 42's Chrome Security Domain Secret extraction recovering all synced GPM passkeys, Windows Hello session hijack) mean a compromised endpoint can, in some ecosystems, forge assertions without a fresh biometric [R04]. Mandatory UV mitigates but does not eliminate this; decide and document whether synced passkeys may be roots.
10. **§10 / §16:** name the assurance pipeline (L0–L8), point at `docs/security/INVARIANTS.md`, log this document as a rev-8 input.

### (b) Phase 1B plan edits

- **Task 0:** add rulings for the hard deny-list (a.4), Mint snapshots (a.5), gross-turnover bucket (a.6), T22 three-way split (a.7) — all cheaper to decide before Task 1 than to retrofit.
- **Task 1 (`conservation`):** `Snap` gains a `Mint` variant; `compare_and_account` returns `{net_outflow, gross_turnover}`; unit tests for the wash-trade and `CloseAccount`-rent cases.
- **Task 2 (`test-mutator`):** add `wash_round_trip` and `close_zero_balance_ata_to_stranger` modes.
- **Task 3 (`registry`):** enforce the deny-list **before** `registry_allows`; test that a registry entry cannot re-enable a denied discriminator.
- **Task 5 (`execute`):** named negatives for **Swig ACC-C1** (close-and-reopen under a fake-layout program between snapshots) and **LazorKit ACC-C1** (reorder accounts under a captured root assertion — `accounts_hash` should already stop it; write the test anyway).
- **Task 2b:** add the **ND-SQD3-LO-01 negative** for `Stage` (stranger pre-opens a stage at our content hash).
- **Task 9:** add `sigverify_wiring.rs`, the CI workflow, a first `cargo-mutants` run over `buckets.rs`/`client_data.rs`/`conservation/`, and the L8 A/B log.
- **Global constraints:** CPI depth 4 as a hard floor [R14]; budget the 4,800 CU precompile cost explicitly.

### (c) Phase 1C plan items (seeds)

- Timelock as an explicit state machine (Approved → locked → Executable), cancellable by root *and* any guardian, **re-validating effects at execution time** (Drift) [R02, R05].
- **Hard-revert on `threshold == 0 || guardian_count == 0`** in every freeze/recovery instruction — the Argent bug closed at the type level, not in onboarding UX [R07].
- Guardian approvals get the root path's clientDataJSON rigour plus a canonical action summary (Bybit WYSIWYS) [R07].
- **Round-robin freeze rate limit across distinct guardians** — the 7-day cooldown bounds one guardian, not a rotating set [R07].
- Guardian liveness pings; multi-channel notification of any freeze/recovery event; onboarding guidance against correlated guardian sets; discourage threshold-1-with-recovery-key-as-sole-guardian (Coinbase's single point of failure) [R07]; document freeze as an explicit **duress response** ("freeze, don't sign").
- Per-session day buckets (needs the bucket PDA), destination allowlists [R05, R09], `set_policy` + the §5.4 lattice, T22 allow-list policy.

### (d) Phase 2 extension checklist seeds

Split CWS publishing credentials from CI · SES/LavaMoat capability attenuation · reproducible builds · lockfile pinning + CI provenance · MV3 service worker holds no secrets across idle; wall-clock auto-lock · isolated-world/main-world bridge with origin validation · address-poisoning UI (never autofill from tx history; saved contacts; first/last-4 typed confirmation) · SIWS-unsupported messaging and the `isOnCurve` compatibility note · advisory-only reputation/blocklist feed (fork Phantom's) · Backpack-style normalised diff rendering · fresh-passkey re-auth gate for high-risk actions · KU Leuven privacy classes (address linking, disconnect that doesn't revoke, cross-frame exposure) — fixing these where MetaMask/Backpack/Rabby/OKX declined is a real differentiator · clone-drainer monitoring of store listings · re-derive **all** adapter discriminators from IDLs (only Meteora `swap` and Pump.fun `buy` are ground truth today; **Jupiter v6 `route`, which §5.2.7 pins, is not**).

### (e) Considered and rejected

| Rejected | Reason |
|---|---|
| Switch buckets to Swig-style slot-epoch floors | Already epoch-floored to UTC days with correct skipped-slot zeroing; [R05]'s rationale was asserted, not argued [critic] |
| Restructure the loop to Claude-reviews-Codex | One narrow Python benchmark; the executed pilot showed reviewer *scope* dominates FP rate. Decide via L8's matched pairs [R19] |
| Third-party simulator as a signing gate | Blowfish missed `assign`; simulation is bypassable by block-context-dependent contracts [R10] |
| xNFT-style in-wallet app runtime | Large surface for phishing resistance the adapter registry already gives [R06] |
| WebAuthn hardware sign counter for clone detection | Synced passkeys return 0 or non-monotonic; LazorKit and Swig both deliberately ignore it [R04, R18] |
| Kani / SseRex as an adopt-now dependency | Prototype (2023, CPI "difficult if not impossible") and a paper with no CLI. Ask the auditor to bring Kani [R01] |
| `sol_big_mod_exp` on-curve check at create | Already tried and reverted in 1A — the syscall isn't in litesvm's mainnet snapshot; PoP at create supersedes it |
| Bespoke SIWS bypass / non-Ed25519 signature scheme | No standard exists; be first to implement one if Wallet Standard ships it [R11] |
| Squads-style iframe/allowlist connector | Requires per-dApp onboarding; Wallet-Standard wrapping reaches unmodified dApps [R11] |
| Vendoring Swig / Squads / Backpack code | AGPL-3.0 / GPL-3.0 attach to the combined work; extension distribution triggers it unambiguously [R17] |
| Planning against CPI depth 8 or a 4,096-byte tx | Neither feature is activated; SIMD-0268's feature account is `null` on mainnet [R14] |

---

## 4. Contradictions and unverified claims, carried forward

1. **Six reports analysed unbuilt code.** [R01, R02, R04, R05, R09, R12] treat `execute`/registry/conservation as shipped. They are Phase 1B design input only.
2. **Cross-model asymmetry (+18.1/−8.6pp).** From isolated Python LiveCodeBench tasks; the figure's own definition and denominator could not be located [R19]. Read literally it says Warden's current loop is net-harmful — too strong for one narrow benchmark. **UNVERIFIED.**
3. **Certora OSS tier.** "Public repo likely qualifies" is sourced to a CVL rules doc, not pricing. **UNVERIFIED** — get a quote.
4. **LazorKit audit status.** [R04] says no named auditor; [R09, R12] cite the Accretion/Solana-Foundation PDF with 14 findings. The critic verified the PDF exists at `audits/` (not `docs/audits/`). [R04] is wrong; the findings are usable.
5. **Squads passkey support.** Three reports disagree; nobody confirmed it. **Do not model 1C guardians on assumed Squads maturity** [critic].
6. **Framework/Anchor version advice.** Several reports gave Anchor-version-dependent advice without establishing the version. It is `anchor-lang = "1.1.2"` — so the pre-0.30 close-account/discriminator advice in [R01, R02] is moot.
7. **A protocol-status claim was contested inside this research round** — [R14] said SIMD-0579/keccak-p1600 does not exist; controller re-check shows it is an OPEN, unmerged PR (#579; #563 closed), not an activated feature. Neither "live syscall" nor "fabricated" is right. Treat any protocol claim not backed by a source-pinned fetch or RPC call as suspect.
8. **Self-flagged figures still uncited downstream:** the $713M Chainalysis wallet-compromise total, "Chrome 147" PRF support [R06], the May-2025 $1.5M Phantom blind-signing incident and the Murphy v. Phantom memory-resident-key allegation (an allegation, not adjudicated) [R10], and dollar figures from the AI-compiled `haveibeendrained` doc [R13]. None is load-bearing for any decision above.
9. **Trident's current fuzzing backend** (honggfuzz vs TridentSVM) — sources conflict; likely both across versions [R01].
10. **AGPL §13 applied to on-chain program execution is legally untested** [R17]. Do not rely on it not applying; get an attorney opinion before any AGPL-derived code ships.
11. **[R07] compares Warden's guardian design to shipped systems** — but Phase 1C is not started. The comparison is spec-to-shipped [critic].
12. **`is_native`, end-to-end `execute` CU, the reject-on-mutation branch through a real CPI, and the `stage_chunk` payload cap remain unmeasured** (O5, O11, O3). The 40-account cap and the 985-byte stage cap stay PROVISIONAL.
13. **Real-device WebAuthn PRF is still UNVERIFIED** (O1, virtual authenticator only) — the Argon2id fallback stays mandatory.
14. **SPL discriminator values** used in §3a.4 (`SetAuthority(6)`, `Approve(4)`, `ApproveChecked(13)`, `CloseAccount(9)`) are standard-layout but UNVERIFIED against source in [R20].

---

## 5. Sources

| # | Report | Strongest primary sources |
|---|---|---|
| R01 | Formal verification & advanced testing | docs.certora.com/solana; osec.io Kani case study; github.com/Ackee-Blockchain/trident; mutants.rs; solana.com/docs/programs/verified-builds |
| R02 | Anchor vulnerability classes → threat map | coral-xyz/sealevel-attacks; blog.neodyme.io/posts/solana_common_pitfalls; SIMD-0075; blog.asymmetric.re; TRM/CoinDesk on Drift |
| R03 | Codex + multi-model adversarial review | openai/codex#8404; codex.danielvaughan.com (schema/MCP gotcha); arXiv 2607.21656; anthropic.com/research/smart-contracts; `/opt/docs/CODEX-USAGE-DOCTRINE.md` §3 |
| R04 | Passkey/WebAuthn/secp256r1 in practice | lazor-kit/program-v2 source (`auth/secp256r1/webauthn.rs`); SIMD-0075; thehackernews.com Aug 2026 synced-passkey attacks |
| R05 | Session-key & smart-account designs | anagrambuild/swig-wallet `state/src/action`; Squads-Protocol/v4 `spending_limit.rs`; docs.squads.so time-locks; neodyme.io Squads PDF |
| R06 | Browser-extension wallet security (MV3) | MetaMask #16075/#15503; EIP-6963; microsoft.com Shai-Hulud 2.0; thehackernews.com Trust Wallet; developer.chrome.com CWS policy 2026 |
| R07 | Recovery & guardian designs | openzeppelin.com Argent report; docs.candide.dev social recovery; NCC Group + Sygnia on Bybit; arXiv 2608.07104 (SoK) |
| R08 | Backpack technical read | coral-xyz/backpack `KeyringStore/crypto.ts`, `provider-injection/index.ts`, `SvmSignTransactionRequest` |
| R09 | Prior-art deep dive (v4/v5, Swig, LazorKit) | four audit PDFs extracted with `pdftotext`; LazorKit `state/action.rs`, `docs/audit/DELTA_BRIEF.md` |
| R10 | Solana wallet landscape & incidents | walletbeat.eth.limo; leastauthority.com Phantom PDF; solana.com 8-2-2022 incident; coinspect.com simulation challenges; koi.ai FoxyWallet |
| R11 | Wallet Standard / adapter / MWA vs smart accounts | anza-xyz/wallet-standard `signIn.ts`/`signMessage.ts`; MWA spec; Squads iframe-adapter README; Warden's own `spikes/04-compat/inventory.md` |
| R12 | Audit landscape & readiness checklist | ottersec/trail_of_bits/neodyme/certora Squads PDFs; Accretion LazorKit A26SFR1 PDF (14 findings) |
| R13 | Warden vs real-world drain techniques | GHSA-jcxm-7wvp-g6p5 (web3.js); SlowMist handbook; TxShield risk utils; Warden's own instruction listing |
| R14 | Solana runtime facts, 2026 | live mainnet RPC feature-account queries (slot ≈440.13M); agave `execution_budget.rs`, `block_cost_limits.rs`; solana-program/token-2022 extension listing; litesvm/mollusk source |
| R15 | Codex review protocol on an invariant ledger | Certora Squads v4 property report; TOB-SQUADS-7/8; ND-SQD3-LO-01 + Certora H-01 corroboration |
| R16 | Does LiteSVM verify secp256r1? | LiteSVM v0.12.0 `callback.rs`/`message_processor.rs`; live probe against `/opt/warden` (`InstructionError(0, Custom(2))`); Warden `TOOLCHAIN.md:43` |
| R17 | Licensing & portability of prior art | each repo's `LICENSE`/README + GitHub API license metadata; GPL §5 / AGPL §13 |
| R18 | Replay-design adjudication | Warden `root_verify/mod.rs`, `constants.rs`; LazorKit `auth/secp256r1/mod.rs`; Swig `authority/secp256r1.rs` |
| R19 | Review-loop A/B at repo scale | Warden `git log` on `programs/warden/`; two executed live Codex probes (threads `01a016ba`, `01a016bb`); compiled-and-run reverse-direction bug |
| R20 | `execute`/conservation design spec review | Token-2022 CPI Guard processor source; Squads v4 `vault_transaction_execute.rs`; Warden spec §5.2/§5.3 |
