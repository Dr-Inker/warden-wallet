# Phase 1B — measured costs and recorded design withdrawals

Companion to `docs/program/PHASE1A-MEASUREMENTS.md`. Task 9 folds the Task 0
re-measurements recorded there into this file; everything below is added by the
task named in the heading.

---

## Task 1 — `conservation`

### `Outflow` has no `gross_turnover` field, and must not grow one

Recorded here so that a later reader who finds only the code does not "restore"
a field that was deliberately withdrawn (research §3(a).6; spec §5.2 rule 4b and
§5.3). Two independent, permanent reasons:

1. **There is no prior art to copy.** LazorKit's "gross" accounting is *SOL
   summed between outer CPIs*; its **token** per-transaction limit is an
   ordinary before/after **net** diff. `SWIG-GROSS-OUTFLOW` in
   `docs/security/PRIOR-ART-FINDINGS.md` says so explicitly. The first draft of
   the rev-8 research proposed a persistent gross-turnover bucket on the false
   premise that such a precedent existed, and withdrew it when the premise did
   not survive checking.
2. **No snapshot granularity can observe the quantity it would hold.** A single
   CPI that moves 100 SOL of vault value out and returns 99.5 SOL *within its
   own execution* presents a net delta of 0.5 SOL. Per-inner-instruction
   snapshots do not help: the round trip completes below the boundary at which
   the caller regains control. A `gross_turnover` field would therefore report a
   number the program cannot measure — worse than an honest gap, because it
   would read as a bound.

What 1B enforces instead (spec §5.2 rule 4b): the **adapter-decoded `max_in`**,
parsed out of the inner instruction's own data rather than inferred from
balances, plus a **pinned source ATA**, both checked before the CPI runs
(Task 6). That is a bound on the value the program can see being *authorised*.
It is an explicit **design bet**, not a proof, and the product statement must not
claim that a conservation check bounds intra-CPI turnover.

`conservation::tests::outflow_has_no_gross_turnover_field` destructures
`Outflow` exhaustively, so adding a field breaks that test.

### Token / Token-2022 layout constants: provenance

Every constant in `constants.rs`'s conservation block was re-derived from
vendored crate source at the versions this repo resolves — not from memory:

| Fact | Source |
|---|---|
| `Account::LEN == 165`, `Mint::LEN == 82`, `Multisig::LEN == 355` | `spl-token 9` (dev-dependency), asserted at runtime by `conservation::tests::spl_crate_layout_lengths_are_pinned` |
| `BASE_ACCOUNT_LENGTH == 165`; `AccountType` byte at absolute offset 165; TLV tail from absolute offset 166, for **both** mints and token accounts; a mint's bytes 82..165 must be zero padding; a buffer of exactly `Multisig::LEN` is never extensible | `spl-token-2022 7.0.0`, `src/extension/mod.rs` — `type_and_tlv_indices`, `unpack_tlv_data`, `check_min_len_and_not_multisig` |
| TLV entry = `type: u16 LE ‖ length: u16 LE ‖ value[length]`; a `type` of `Uninitialized (0)` terminates the walk | same file — `get_tlv_indices`, `get_extension_indices` |
| `AccountType::{Uninitialized = 0, Mint = 1, Account = 2}` | same file |
| `ExtensionType` discriminants: `TransferFeeConfig 1`, `ConfidentialTransferMint 4`, `ConfidentialTransferAccount 5`, `PermanentDelegate 12`, `TransferHook 14`, `ConfidentialTransferFeeConfig 16`, `ConfidentialTransferFeeAmount 17`, `ConfidentialMintBurn 24` | same file — `pub enum ExtensionType` |
| `TransferFeeConfig` = `transfer_fee_config_authority[0..32] ‖ withdraw_withheld_authority[32..64] ‖ withheld_amount[64..72] ‖ older_transfer_fee[72..90] ‖ newer_transfer_fee[90..108]`, each `TransferFee` = `{epoch u64, maximum_fee u64, bps u16}`; the two authorities are `OptionalNonZeroPubkey` (a bare 32-byte key, all-zeros = `None`, **no tag**) | `src/extension/transfer_fee/mod.rs` |

The deny-list instruction tags (§5.2 rule 1a) are **not** in this table — they
are Task 5's to derive and pin, with its own unit test against the `spl-token`
crate's `TokenInstruction` encoding.

### Deliberate tightenings beyond the spec's letter (each can only reject more)

- **`DANGER_CONFIDENTIAL` covers extensions 4, 5, 16, 17 and 24**, where spec
  §5.2 rule 5 names 4/5. Every one of them hides an amount behind a ZK
  ciphertext, which is the property that makes conservation *unverifiable*
  rather than merely hard. Widening a permanent deny cannot open a hole.
- **Mint authority fields are compared for every required mint**, where the
  spec compares them only "if the vault holds any authority on M". The spec's
  condition is a CU optimisation; comparing unconditionally is a superset and
  no legitimate 1B flow changes a mint authority.
- **A `CloseIntent` must agree with the snapshot** (`amount_before` equal to the
  BEFORE balance, the account actually gone, every intent consumed exactly
  once). A decoder/comparison desync fails loudly instead of silently passing.

### Round-1 review fixes (Codex sol@max, thread `01a018fa`) — recorded rulings

Four fail-open paths and one parsing weakness, each now with a regression:

| # | Hole | Fix |
|---|---|---|
| C1 | Vault-**controlled** mints were only checked when reached through a vault token account, and that check ran *after* the `CloseIntent` branch | `compare::prescan_vault_mints` validates every mint whose `mint_authority` / `freeze_authority` / T22 fee authority is the PDA, independently of any token account and before anything else; the token-account-driven mint checks moved ahead of the close branch |
| C2 | Classification was BEFORE-driven, so an account that *became* the vault's mid-instruction was never examined | anything vault-owned in the AFTER snapshot must have been the same vault-owned token account of the same mint under the same program BEFORE — else `NewVaultAccountRejected` (6051) |
| C3 | Positional comparison under-counts when one account is listed twice | duplicate pubkeys rejected up front (`PayloadInvalid`) |
| C4 | Token-2022 `WithdrawExcessLamports` (tag 38) drains rent with every compared field unchanged | lamports must be unchanged on **non-native** vault token accounts; `is_native.is_some()` (not the mint key) is the exemption |
| C5 | Token-**account** TLV tails were hashed but never walked; `classify` was program-agnostic | tails are walked with bounded, fail-closed parsing; classic SPL Token accepts **only** exactly 165 B (account) / 82 B (mint) — it has no extension mechanism |

**The presence rule is no longer gated on `is_writable`** (round-1 adjudication).
Gating on writable let a caller opt out of the danger-extension check and the
mint-authority comparison by passing the vault ATA read-only. Spec §5.2 rule 2a
was amended to match.

**One deliberate false positive, scheduled for 1C.** `prescan_vault_mints`
compares the TLV **tail hash** for a vault-controlled mint, where `check_mint`
(mints reached through a vault token account) deliberately does not. The
false positive §5.2 rule 2a warns about — a legitimate `transfer_fee` accrual
mutating `withheld_amount` in the tail — can only occur on a fee mint, and a fee
mint backing a vault token account already rejects outright in 1B
(`TransferFeeMintUnsupported`). The residue is a **vault-controlled fee mint
with no vault token account in the list**: its withheld-fee accrual rejects in
1B and must become a field-wise comparison in 1C, when fee mints become legal.

**`supply` stays uncompared** in both paths — re-confirmed in the round-1
adjudication against spec §5.2 rule 2a.

---

## A0 — assurance-record repair (campaign plan 2026-08-20)

A0 began as assurance-record repair so Task 9's close-out is auditable (campaign
plan gaps G1/G2/G7/G10/G11). It grew: seeding the conservation invariants made
the review loop surface five real Task-1 fund-loss defects, so A0 also carries
their program fixes. See the A0 close-out at the end of this file for the full
list and the convergence decision.

**What changed:**

- `docs/security/REVIEW-RUNS.jsonl` (new) — one line per completed review
  round, **including zero-finding rounds**; `scripts/review.sh` now appends a
  run record via `scripts/append-review-run.mjs` (step 8), which re-validates
  the artefact independently and appends nothing for a failed round. 15
  `baseline-not-recorded` entries record the pre-A0 rounds honestly: fix-commit
  or citing-doc evidence only, no invented finding counts, thread ids only
  where a committed doc retained them.
- `docs/security/THREATMODEL.md` — retrospective milestone deltas appended for
  Tasks 0, 1, 2b, 11 (append-only; the stale unauthenticated-create baseline
  paragraph is superseded by the Task 2b delta, not rewritten).
- `docs/security/invariants.jsonl` — `WRD-CONS-01`..`-06` unit-layer rows added
  at `test-covered` with named tests at `d394b74` (campaign plan G7); the
  end-to-end `WRD-EXEC-*` rows stay `unimplemented` until Task 5.
- `docs/superpowers/plans/2026-08-18-warden-phase1b-execute-swap.md` — per-task
  status/SHA/review table added; Task 11 marked **PARTIAL** pending Task 11R.
- `packages/core/test/review-runs.test.ts` (new) — pins the run-record contract:
  a validated zero-finding round appends exactly one run; a failed/invalid
  round appends none; live runs carry full provenance; baseline entries must
  say `retrospective`/`UNVERIFIED` and source any finding count they claim.

**Task 11 gate evidence, rerun at the A0 SHA (campaign plan: record only what
actually passes; the deployment gate stays partial until Task 11R):**

Run at `41806e4ecbf087cfce48b10f4f3f9c3bc37f4a81` (2026-08-20):

```
$ node scripts/gen-invariants.mjs --check
INVARIANTS.md is up to date (59 invariants).
$ scripts/review.sh --selftest        # codex CLI contract
selftest OK
$ pnpm --filter @warden/core test
 Test Files  5 passed (5)
      Tests  95 passed (95)
$ ./scripts/supply-chain-gate.sh
== L9 supply-chain gate: PASS ==
$ git diff --check b008190..41806e4
(clean)
```

NOT rerun here and still owned elsewhere: the deployment gate
(`scripts/deploy-gate.sh`) remains SPEC + partial dry-run (Task 11R); cargo /
anchor builds and the Rust suite were not part of A0's lease (no Rust source
changed; the serialized-build rule reserves them for Task 2).

**A0 round-1 fix evidence (WRDF-0004):** `cargo test -p warden --lib` at
`d2c6a01e1a631af394107dc231e71c0973a06472` → `248 passed; 0 failed` — the
executable gate behind every `WRD-CONS-*` `test-covered` row; their evidence
SHAs cite this run. Review round 1 (wrapper thread in REVIEW-RUNS.jsonl):
5 findings, all adopted; rulings in REVIEW-SCORECARD.jsonl.

**A0 round-3 fix evidence (WRDF-0008):** `cargo test -p warden --lib` at
`7bf6b2f2c2c1f87db58a36e25425098d2a5f54f0` → `250 passed; 0 failed` (RED
verified: `t22_native_account_delta_is_counted_in_sol_not_by_mint` fails
against the pre-fix mint-key-only classification). `NATIVE_MINT_2022`
provenance: vendored `spl-token-2022 7.0.0` `src/native_mint.rs`
`declare_id!("9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP")`.

**A0 round-6 fix evidence (WRDF-0011/-0012):** `cargo test -p warden --lib` at
`d515db669fd6a360b0670826636099dbf20650ee` (where these tests land) →
`254 passed; 0 failed`. RED verified separately by a manual temp-patch attestation
this session (not a committed reproducer): `sync_native_then_transfer_of_a_donation_is_counted_as_sol_outflow`
fails when native value is measured by `amount` instead of lamports;
`a_required_mint_with_an_unmodeled_extension_is_rejected` fails without the
unmodeled-extension gate. Evidence SHAs pinned to the round-6 fix commit.

**A0 round-7 fix evidence (WRDF-0011/-0012/-0013):** `cargo test -p warden --lib`
at `23d6eaa0a2e536d20ab3385741d71fff35f72e28` → `256 passed; 0 failed`. RED
verified: `a_standalone_writable_mint_with_an_unmodeled_extension_is_rejected`
fails without the pre-scan gate. WRDF-0013: mis-pinned round-6 evidence
(2170973 → the actual landing SHA d515db6) corrected, and
`packages/core/test/security-ledger.test.ts` now resolves every evidence SHA in
its git object rather than trusting HEAD.

**A0 round-8 fix evidence (WRDF-0011/-0012/-0013):** `cargo test -p warden --lib`
at `7fae2d530f358af44671c35023e884b8cca81f28` → `257 passed; 0 failed`. RED
verified: `a_standalone_writable_mint_with_a_recognized_danger_extension_is_rejected`
fails when the pre-scan gate rejects only unrecognized (not recognized-danger)
extensions. Spec §5.2 rule 4/4a and the Phase-1B plan pseudocode corrected to the
native-account lamport SOL equation; the evidence-at-SHA ledger test now fails
closed on a present-but-mismatched commit and requires a real #[test].

## A0 consolidated final verification (WRDF-0004) — SHA-bound

Every A0 evidence block above cites the SHA its run happened at. This block
binds the FINAL A0 state, re-run on the committed HEAD so no count is a floating
claim:

```
# at 8225d073077a924bf72ee1d4b9d68e3a44f812fa
$ cargo test -p warden --lib            -> 258 passed; 0 failed
$ pnpm --filter @warden/core test       -> 103 passed
$ node scripts/gen-invariants.mjs --check-> INVARIANTS.md up to date (59)
$ ./scripts/supply-chain-gate.sh         -> L9 supply-chain gate: PASS
```

The per-round RED/GREEN directions (WRDF-0008/-0011/-0012) were each verified at
their own fix commit, recorded in the round blocks above; those are the
authoritative RED attestations. Earlier round blocks' pass counts are the counts
at THAT round's fix commit, not this HEAD (the suite grew as regressions landed).

**Accepted residual (WRDF-0013 round 10):** the ledger's evidence-at-SHA test
(`packages/core/test/security-ledger.test.ts`) skips a cited commit only in a
genuinely shallow clone. CI (`.github/workflows/ci.yml`) does not fetch full
history, so historical evidence objects take the shallow-skip path there. To make
the at-SHA check load-bearing in CI, set the checkout `fetch-depth: 0` (or fetch
the cited objects). **Owner/CI action — not a fund-loss issue:** the program
suite and HEAD-side ledger checks run fully in CI regardless.

## A0 close-out (2026-08-20)

**A0 is complete.** 11 adversarial review rounds (Codex `gpt-5.6-sol@max`, all
recorded in `docs/security/REVIEW-RUNS.jsonl` + `REVIEW-SCORECARD.jsonl`).

**What A0 delivered beyond its charter.** A0 was scoped as assurance-record
repair (campaign plan G1/G2/G7/G10/G11). Seeding the `WRD-CONS-*` invariants did
its job: the review loop surfaced **five genuine, previously-unnoticed fund-loss
defects** in the Task-1 conservation module that Phase 1B review had passed —
each CONFIRMED by a RED-verified regression:
- WRDF-0008: Token-2022 native SOL mis-laned into `by_mint` (double-bucket).
- WRDF-0011: native value measured by the `SyncNative`-updated `amount` cache —
  a `SyncNative`+`Transfer` pair could drain a donated balance invisibly.
- WRDF-0012 (rounds 7+8): standalone mints controlled via an unmodeled OR a
  recognized-danger extension bypassed the authority pre-scan.
Plus the spec §5.2 / plan SOL equation was corrected to match (WRDF-0011 r8).
The warden lib suite grew 248 → 258 tests over these fixes.

**Convergence decision.** Rounds 10 and 11 produced ZERO program-security
findings — only assurance-tooling refinements (digest canonicalization, scorecard
self-sufficiency, evidence-at-SHA CI depth). That is the security-relevant
convergence signal: two consecutive rounds with no fund-loss issue. A0 is closed
here on judgment, not exhaustion; further rounds would keep polishing the review
harness at diminishing return.

**Accepted residuals (owner/CI, not fund-loss):**
- The evidence-at-SHA ledger test needs CI `fetch-depth: 0` to be load-bearing in
  CI (WRDF-0013); it is correct and load-bearing locally.
- Raw review artefacts under `.superpowers/reviews` are session-local by policy;
  the committed scorecard is self-sufficient and `artefact_sha256` authenticates a
  locally-retained artefact (WRDF-0015).
- A Task-5 real-CPI regression for the native-lamport SOL equation and the
  through-CPI standalone-mint case is owed when `execute` is wired (the unit layer
  is proven; the end-to-end `WRD-EXEC-*` rows stay `unimplemented` until Task 5).

## C0+V0 tranche close-out (2026-08-20)

**C0+V0 is complete.** 9 adversarial docs-review rounds (Codex `gpt-5.6-sol@max`,
all in `REVIEW-RUNS.jsonl` + `REVIEW-SCORECARD.jsonl`).

**What it delivered.** 26 seeded invariant rows at honest `unimplemented` status
(client `WRD-KEY/EXT/APR/TXI/SIM/EXP/REL`, vanity `WRD-VAN`, and new
`WRD-ORG-01`/`WRD-SIG-01`/`WRD-QTE-01`/`WRD-DEP-01`/`WRD-DEP-02`/`WRD-EVT-01`) with
a required-id presence test; C0/V0 threat-model rows; a spec §6.1 vanity-onboarding
section; and the campaign-plan tasks written into their source plans (C1a, C2a,
C4b, Task 5E, Task 11R, the Task 2 split) with corrected V4/U7/V2 gating.

**Seeding worked — the review hardened the specs before any code exists.** As with
A0's conservation seeding, seeding these invariants let the loop find real design
gaps in the *task definitions*: the deploy-gate governance check went through
**seven critical iterations** (WRDF-0017) — expected-authority vs derived Squads
vault PDA → pinned multisig identity + member set → `member_count`/discriminator →
`configAuthority == default` → ProgramData authentication chain → Squads code hash
+ trust-root terminus → per-member permission masks — plus distinct new classes:
the stale pre-approved Squads proposal (WRDF-0028/-0029), origin-vs-cluster_tag
(WRDF-0016), a mode-dependent swap-divergence counterexample (WRDF-0019),
cross-cluster keyring and recovery-envelope AAD (WRDF-0023/-0026), UI-port
origin+path vs id-only (WRDF-0021), and event finalized-status + idempotence
(WRDF-0022). All adopted; none is program code (all target unimplemented specs).

**Convergence + the terminus device.** To stop an infinite "one more Squads field"
regress on WRDF-0017, `WRD-DEP-01`/`WRD-DEP-02` now state a *completeness*
requirement — "attest the COMPLETE reviewed config" — and explicitly scope the
byte-level field inventory to the implementation task (Task 11R / Task 3) against
the pinned IDL. That terminus held: round 8 stopped mining Squads fields, and the
final rounds moved to adjacent invariants and single peripheral items. C0+V0 is
closed here on judgment; the acceptance criterion (seeded, addressable, honest
`unimplemented`, `gen-invariants --check` green, required-id test) was met at the
first commit and the rounds hardened the specs far beyond it.

**Owed to the implementing tasks:** the byte-level Squads-config and Registry-config
attestation field lists (Task 11R / Task 3), and every invariant here moves off
`unimplemented` only when its named task lands executable evidence.

## Task 2 close-out (2026-08-20)

**Task 2 (2A + 2B) is complete.** Two never-deployed test programs plus their
LiteSVM harnesses:
- `programs/test-mutator` (2A, `204a118`) — 10 adversarial instructions, each
  attempting one mutation §5.2 must catch; 11 harness smoke tests
  (`mutator_harness.rs`) drive each with a payer authority.
- `programs/test-jup-mock` (2B, `4c8575a`) — Jupiter v6-shaped `route` /
  `shared_accounts_route`; 7 harness smoke tests (`jup_mock_harness.rs`).

Program ids are nothing-up-my-sleeve (`sha256("WARDEN/test-mutator/v1")` /
`…/test-jup-mock/v1`); no keypairs committed. `.claude/test-gate.sh` builds and
freshness-checks both new `.so`.

**Review: 4 rounds (Codex sol@max), converged at round 4 with zero findings.**
Findings adopted along the way (all in `REVIEW-SCORECARD.jsonl`):
- WRDF-0031: the mock now speaks Jupiter v6's real argument field order
  (empty-`route_plan` case); full RoutePlanStep + optional-account + non-empty-plan
  fidelity against the pinned IDL is scoped to Task 6 (its plan checkbox).
- WRDF-0032: the negative smokes (drain, re-enter) assert the handler actually
  RAN (Anchor instruction-name log) and failed on the specific path, not any
  pre-handler failure.
- WRDF-0033: the mock always pays the passed `platform_fee_account`; the
  "fee to a non-treasury account" case is a caller account-substitution warden's
  pre-CPI meta check rejects — there is no mock divert branch, because an
  external-to-external divert is invisible to both the meta check and vault-only
  conservation.

**Gate at the final SHA:** `./.claude/test-gate.sh` green (all workspace suites +
both new `.so` built); `cargo clippy` clean on both new crates;
`node scripts/gen-invariants.mjs --check` green; supply-chain gate PASS.
Next: Task 3 (`Registry` + `init_registry` + `grant_session` allowlist ids).

## Task 3 (registry) — gate evidence + review

**Gate at `dd60d129` (2026-08-20):** `./.claude/test-gate.sh` green (all workspace
suites + all `.so`); `cargo test -p warden --lib` → 279 passed; `cargo clippy -p
warden --lib -- -D clippy::arithmetic_side_effects` clean; `node scripts/
gen-invariants.mjs --check` green; supply-chain gate PASS; `pnpm --filter
@warden/core test` → 104 passed. Integration: `tests/registry.rs` 7 tests
(init_registry upgrade-auth-gated + rejections + defaults + TS/Rust parity +
create-stores-registry).

**Review: WRDF-0034..0038 (Codex sol@max), all adopted.** WRDF-0035 (SPL role
authority-position, closing a multisig-cosigner bypass) and WRDF-0034 (the create
ceremony now binds the stored registry — wire format 183→215 B, pinned Rust+TS
vectors regenerated) were the important ones; WRDF-0037 (new errors 6052-6055 in
the append-only pin table), WRDF-0036 (worst-case registry-bearing packet
measured), WRDF-0038 (this evidence block) the minor/info.

**Known residual:** `registry_allows`' role validators do the STRUCTURAL half
(authority position, token-program presence). The VALUE half — a source is *the
vault's own* ATA, and conservation — is `execute`/`conservation`'s (Task 5), by
design; Jupiter's validator is Task 6's.

**Gate at `2b8ac40` (after review rounds 1-3):** `./.claude/test-gate.sh` green;
`cargo test -p warden --lib` → 281 passed; clippy clean; `pnpm --filter
@warden/core test` → 104 passed. Rounds 2-3 adopted WRDF-0039 (honest
create-records-registry claim), WRDF-0040 (parity gate rejects out-of-range +
version), WRDF-0041 ((program,selector) authority dispatch, fail closed).

**This was NOT the final gate.** Rounds 4-5 (threads `5aa1e637`, `dca7168b`,
`7da30756`) raised three findings that `2b8ac40` did not resolve — the
authoritative record is `docs/security/REVIEW-SCORECARD.jsonl`, and an earlier
version of this block mislabeled them:

- **WRDF-0044 (important)** — `grant_session` accepted a structurally-valid but
  UNALLOCATED `program_allowlist_id`. Round-4 added the `allocated_lists` bitmask
  + documented a 1C prerequisite; round 5 rejected that deferral and required the
  real gate: `grant_session` now loads the account's `Registry` and enforces
  `is_allocated_list`. On-chain RED/GREEN `grant_with_{unallocated,allocated}_
  allowlist_id_*`; `WRD-SESS-07` inverted to "must resolve to an allocated list".
- **WRDF-0042 (important)** — the published `@warden/core` `CreateBody` contract
  still documented 183 B / `policy_hash`-last after the ceremony grew the 32-byte
  `registry` word. Fixed by exporting a canonical `encodeCreateBody` (215 B) and
  correcting the doc; the pinned action-hash vector now validates the API.
- **WRDF-0043 (info)** — Task 3 was marked DONE against the `2b8ac40` gate while
  later commits changed program state; the close-out cited only library tests.

**Task 3 final gate (`3361d2c`, after review rounds 1-5):** `./.claude/test-gate.sh`
green (all workspace suites + all `.so`); `cargo test -p warden --lib` → 282
passed; 42 integration (sessions/transfer/freeze/registry); `cargo clippy -p
warden --all-targets` clean of `arithmetic_side_effects`; `pnpm --filter
@warden/core test` → 104 passed. **Round 7 confirmation = 0 findings at `300face`** — Task 3 DONE (round 6's lone
info finding WRDF-0043 fixed; round 7 over the corrected docs returned nothing).

## Task 4 (staging) — measured payload cap + gate evidence

**MEASURED `stage_chunk` payload cap** (replaces the PROVISIONAL 985 B, spec
§5.1 / §12.3). `stage::stage_chunk_payload_cap_is_measured` binary-searches the
largest payload a single `stage_chunk` transaction carries under the fixed
3-account layout (`disc(8) ‖ offset:u32 ‖ len:u32 ‖ payload`) against the 1,232 B
packet, for **both serializers**: legacy `Transaction` fits **979 B**; the v0
`VersionedTransaction` the production client compiles is 2 B larger and fits
**977 B**. `STAGE_CHUNK_PAYLOAD_CAP = 977` is the **v0/client contract** (the
conservative of the two); the test pins both exactly. Chunk count = `ceil(len /
977)`. `MAX_DATA_LEN` (4,096 B) therefore stages in at most 5 chunks.

**Gate at `d47d8ce` (2026-08-20):** `./.claude/test-gate.sh` green (all workspace
suites + all `.so`); `cargo test -p warden --lib` → 283 passed (incl.
`state::stage::header_len_matches_layout`, which pins `Stage::HEADER_LEN = 139`);
`tests/stage.rs` → 21 integration tests; `cargo clippy -p warden --lib -- -D
clippy::arithmetic_side_effects` clean; `pnpm --filter @warden/core test` → 104
passed. `Stage::space(n)` uses `saturating_add` for the lint — `n` is bounded by
`MAX_DATA_LEN` at the call site, so it can never saturate.

**Squat class (ND-SQD3-LO-01 / Certora H-01) proved, not assumed.** The address
binds the creator (`["stage", account, creator, hash]`), so a stranger and the
victim occupy different addresses and the ND-SQD3 squat is closed by
construction (round-1 finding WRDF-0045; superseded the earlier
content-address-only shape). Tests hold the two prior-art mechanisms as separate
regressions: ND-SQD3 — `stranger_cannot_occupy_the_victims_stage_address`,
`two_creators_stage_same_content_at_distinct_addresses`,
`stranger_cannot_chunk_or_early_close_victims_stage` (creator-only chunk/
early-close), `open_rejects_expiry_beyond_max_ttl` (TTL bound); Certora H-01
lifecycle GC — `unfinalized_stage_closed_by_anyone_after_expiry`,
`finalized_stage_closed_by_anyone_after_expiry` (rent to creator). Invariants
`WRD-BUF-01`/`WRD-BUF-02` are `test-covered`; `WRD-STAGE-01` (finalize records
generation/policy_version + hash check, and its re-derivation is reached by
`finalize_rejects_noncanonical_smart_account`) is `test-covered`; the consume
half is split out as `WRD-STAGE-02`, `unimplemented`, owned by Task 5.

**Review round 1 (Codex sol@max, WRDF-0045..0048 adopted).** The important
finding WRDF-0045 (raised in both runs): the content-addressed seed `["stage",
account, hash]` let a squatter renew the block each cycle (permissionless
re-open after any close). Fixed as the prior art (ND-SQD3-LO-01) prescribes —
**the seed now binds the creator**, `["stage", account, creator, hash]`, so a
stranger and the victim occupy different addresses and the victim's `stage_open`
always succeeds; the squat is closed by construction, not merely time-boxed. The
two prior-art mechanisms are now separate regressions (ND-SQD3 vs Certora H-01
lifecycle GC). WRDF-0046: `finalize_rejects_noncanonical_smart_account` plants a
Warden-owned copy at a non-canonical address and proves finalize's stored-seed
re-derivation actually rejects it (previously unreached by any test). WRDF-0047:
the cap test now pins BOTH `legacy_cap == 979` and `v0_cap == 977`
(`== STAGE_CHUNK_PAYLOAD_CAP`, the exported client constant) with
`measure_v0(977) == 1232` / `measure_v0(978) > 1232` — no silent drift, and the
client contract is the v0 number (WRDF-0047, round 3).
WRDF-0048 (info): the full gate is re-run on the final merged SHA below.

**Whole-task review not yet converged** — round 1 raised findings, so Task 4 is
not DONE until a subsequent review returns 0.

### Task 4 gate — command, result, SHA (WRDF-0048)

Executable run against an **exact committed SHA**, not prose:
`08a8b56cb6a42b4fbcd74f7f39323e7173ef9121` (WRDF-0045..0049 applied; WRDF-0050
carried as the release-blocker below). Reviewers reproduce by `git checkout
08a8b56 && ./.claude/test-gate.sh`.

```
$ git rev-parse HEAD
08a8b56cb6a42b4fbcd74f7f39323e7173ef9121
$ ./.claude/test-gate.sh
# exit 0 — all pnpm workspaces + every .so:
#   warden --lib            283 passed
#   tests/stage.rs           23 passed   (pins legacy-979 AND v0-977 caps)
#   tests/sessions.rs        45 passed
#   tests/transfer.rs        35 passed
#   registry/freeze/create/create_pop/root_verify/sigverify/smoke  all ok
#   @warden/core (TS)       105 passed   (security-ledger 40/40; incl. the
#                                         STAGE_CHUNK_PAYLOAD_CAP=977 assertion)
$ cargo clippy -p warden --lib -- -D clippy::arithmetic_side_effects
# clean (exit 0)
```

This record is committed as a child of `08a8b56`, so its own delta is only this
prose (which the gate's suites do not exercise); the certified state is
`08a8b56`. Rounds 3–5 converged the engineering findings — WRDF-0047 (legacy-979
/ v0-client-977 distinguished across code, Rust + TS constants, and every doc),
WRDF-0049 (all seed references swept to the four-seed address), WRDF-0048 (this
artifact). WRDF-0050 is **not** fixed — it is the owner/counsel release-blocker
below, which the reviewer confirms is correctly carried and which no engineering
action can close.

### RELEASE-BLOCKER — WRDF-0050 (non-MIT prior-art provenance), carried UNRESOLVED

Not a fix. The Task-4 anti-squat design binds the creator into the Stage PDA
seeds — the standard Anchor per-owner PDA-namespacing pattern, which I am
confident is generic Solana practice and independently derivable. But the
prior-art corpus's licensing rule (spec §5.3 licensing note) is explicit that
**whether a reimplementation avoids non-MIT reuse is a claim for counsel, not an
engineering conclusion**, and Squads v4 (source of ND-SQD3-LO-01) is AGPL-3.0,
reference-only. The round-2 comment rewording removed the "reproduces Squads'
remedy" lineage and states no code is reused; that reduces exposure but does not
discharge the requirement.

**Status: open, release-blocking.** Owner/counsel must record a reuse/provenance
ruling in durable release evidence before Task 4 ships. Until then WRDF-0050 is
`deferred` in REVIEW-SCORECARD.jsonl (comment rewording done; clearance
outstanding), NOT adopted-as-fixed. Task 4 whole-task review cannot converge to
"DONE-shippable" on this item by engineering action alone; it converges to
"code-complete, one owner/counsel gate open."
