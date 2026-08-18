# Warden Wallet — Phase 1B: `execute`, Adapter Registry, Staging, `swap`, Proof-of-Possession — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a bounded session key drive real dApp transactions and Jupiter swaps through `programs/warden` with on-chain conservation checks (before/after, field-by-field, incl. `is_native`), a registry of allowed `(program, discriminator)` adapters, staged multi-transaction payloads, and close the three Phase-1A pre-ship gate items: proof-of-possession at creation, `is_native` (O5), end-to-end `execute` CU + CPI mutation rejection + measured stage cap (O11).

**Architecture:** New modules on top of the 1A foundation (branch `main` @080f07b): `conservation` (snapshot/compare/value-accounting over the instruction's writable accounts), `registry` (a `Registry` PDA holding curated `(program_id, discriminator, role_rules)` entries; `SessionKey.program_allowlist_id` references a list id inside it), `stage` (chunk-uploaded, content-addressed, consume-once payloads bound to `generation` + `policy_version`), instructions `execute`, `swap`, `stage_open/chunk/finalize/close`, `create_account` gains a mandatory root proof-of-possession, and `grant_session` accepts registry ids. Tests are LiteSVM with **real inner CPIs** (SPL Token transfers, a purpose-built `mutator` test program that tries to set delegate/close-authority/owner/realloc/close, and a Jupiter-shaped mock program) — the spike's "no CPI" gap must not recur. Phase 1C adds queue/pending/timelock, `set_policy` + policy lattice, guardians/recovery/guardian-freeze.

**Tech Stack:** as Phase 1A (Anchor 1.1.2, solana-* 3.x, LiteSVM 0.12 `precompiles` + `with_mainnet_features()`, spl-token 9 dev-dep, clippy `arithmetic_side_effects` deny). Additional test programs live under `programs/test-mutator` and `programs/test-jup-mock` (built by `anchor build` as workspace members; never deployed).

**Spec:** `docs/superpowers/specs/2026-08-18-warden-wallet-design.md` (rev 7) — §5.1 rows `execute`/`swap`/`stage_*`, §5.2 (payload contract, rules 1–7), §5.3, §5.4. **Facts that bind (measured in Phase 0/1A):** instruction-local payload indices (`[0]=SmartAccount, [1]=session, [2..]=remaining`); compute-budget ixs stay top-level; conservation snapshot ≈ 900 CU/account (spike, no CPI) → **must be re-measured end-to-end here**; 40-writable-account session cap is PROVISIONAL; `stage_chunk` cap 985 B PROVISIONAL (assumed layout, spec §5.1 fixes the layout: payer, Stage PDA, System; data = disc ‖ offset u32 ‖ len u32 ‖ payload); Jupiter routes 604–1,235 B (some need 1 chunk); LiteSVM does not enforce 1,232 B → assert tx sizes; error ABI is append-only from 6036; SmartAccount zero-copy has `registry: Pubkey` and 256 reserved bytes; creation is unauthenticated today (front-run/squat risk) → PoP here.

## Global Constraints

- Everything in Phase 1A's Global Constraints still applies (checked arithmetic + clippy deny; authorize-then-validate; PDAs re-derived; `frozen` gates all outflow; tx-size assertions on every new instruction; pinned literal error codes appended 6036+ with the drift-guard test extended; RED evidence per task; serialized builds; commit trailer; Codex reviews every task at **`gpt-5.6-sol` @ `max`**).
- **Conservation is before/after, field-by-field, on every writable account in the instruction** (spec §5.2 rule 2/3/4): for token accounts `(mint, owner, amount, delegate, delegated_amount, close_authority, state, is_native)` + Token-2022 TLV hash; runtime owner program, lamports, data_len for all. Vault-owned token accounts: no field but `amount` may change, `amount` may only decrease by what the session/root is allowed, closed/realloc'd ⇒ reject. The SmartAccount PDA is never writable to a CPI target. Non-token vault-owned writable accounts ⇒ reject. Value accounting per §5.2.4 incl. the SOL equation `(pda_lamports_before − after) + Σ vault-WSOL decreases`; no rent exemption; outer payer funds creation.
- **Session `execute` may CPI only to registry entries `(program_id, discriminator)`** in its list; **self-CPI into warden is rejected**; ComputeBudget program is rejected inside `execute` (must be top-level); Token-2022 mints with transfer-hook / permanent-delegate / confidential extensions ⇒ reject unless allow-listed (1B: reject always; allow-list is 1C policy).
- **`execute` outflow debits the same account-wide buckets** as `transfer` (session: per_tx + lifetime + account buckets; root: large_threshold + account buckets); a mint with no cap ⇒ outflow must be 0.
- **Payload contract**: `ExecutePayload { n_ixs: u8, ixs: [ { program_idx: u8, n_accts: u8, accts: [(idx: u8, flags: u8 /*bit0 signer, bit1 writable*/)], data_len: u16 LE, data } ] }`; indices instruction-local; `program_idx` must point at an executable account that is not warden/ComputeBudget; a `signer` flag is honoured only for `[0]` (PDA via `invoke_signed`) and `[1]` (session, already an outer signer); any other signer flag ⇒ reject.
- **Stage accounts**: PDA `["stage", account, hash]`, content-addressed (`hash = Keccak256(payload)`), chunk-uploaded, `finalize` verifies the hash and records `generation` + `policy_version` + `expiry_ts`, consume-once (closed by `execute`), anyone may close after expiry (rent to `creator`). Account layout for `stage_chunk` exactly as spec §5.1.
- **`swap`** = `execute` specialised (spec §5.2.7): Jupiter v6 program id pinned (`JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4`), discriminators for `route` and `shared_accounts_route` (derive from Jupiter's public IDL — record provenance; a wrong discriminator is a test failure not a guess), source/destination vault ATAs, `platform_fee_account` = treasury ATA, `out_mint ∈ allowed_out_mints` for sessions unless a cap exists, swap buckets (separate `swap_caps` — 1B adds a `SwapCaps` array to `Policy`'s reserved bytes? NO — reserved bytes are 256 B; 8 MintCaps = 448 B. Ruling: swap input debits the SAME per-mint account buckets as transfer in 1B (spec §4 defaults are per-mint per-day either way) and a `swap_ops`-specific ceiling is deferred to 1C with `set_policy`; document in spec §5.2.7 as a 1B simplification).
- **Proof-of-possession at create**: `create_account` REQUIRES a root ceremony over `action_hash(0x06, borsh(CreateBody{ owner_seed, rp_id_hash, origin, cluster_tag, policy_hash }))` in the same transaction — the transcript uses `generation=0, policy_version=1, root_nonce=0` and the (not-yet-existing) account address derived from `owner_seed`; on success `root_nonce = 1`. A creator without the passkey cannot squat the PDA. Byte budget: create (2 mints) was 808 B; + ~330 B for the assertion+precompile ⇒ MUST be measured; if a 2-mint create no longer fits, `MAX_MINTS_AT_CREATE` drops (mints added via 1C `set_policy`).
- **Measured hard gate before Phase 1C** (carried verbatim from DECISION.md O11 + PoP): real inner CPI through `execute` (SPL transfer, mutator program) with mutation rejection proven through CPI; `is_native` compared; end-to-end `execute` CU for 10/20/30/40 writable accounts recorded; the writable-account cap for session execute set from measurement (replace the PROVISIONAL 40); `stage_chunk` payload cap measured with the real instruction (replace PROVISIONAL 985); PoP-at-create tx size ≤ 1,232 measured.

## File structure (this plan)

```
programs/warden/src/
├── conservation/{mod.rs,snapshot.rs,compare.rs,accounting.rs}   (Snap, snapshot_all, check_vault_invariants, outflow_by_mint incl. SOL equation)
├── registry.rs                    (Registry PDA: entries + lists; lookup(list_id, program, disc))
├── state/{stage.rs,registry.rs}   (Stage account; Registry account)
├── instructions/{execute.rs,swap.rs,stage.rs (open/chunk/finalize/close),registry_admin.rs (init_registry — dev/multisig only in 1B),create_account.rs (PoP), grant_session.rs (allowlist id lookup)}
programs/test-mutator/             (test program: on request sets delegate / close_authority / owner change via SPL SetAuthority CPI, closes, reallocs — each behind an arg)
programs/test-jup-mock/            (test program mimicking Jupiter `route`/`shared_accounts_route` account roles: moves in_mint out of the vault ATA and out_mint into it, optionally misbehaves)
programs/warden/tests/{execute.rs,stage.rs,swap.rs,registry.rs,create_pop.rs,common/{payload.rs,mutator.rs,jup.rs}}
packages/core/src/execute/{payload.ts,wrap.ts}   (productionised from spikes/03-txbudget/ts/src/wrap.ts — instruction-local indices, compute-budget hoist, stage split; MUST NOT import from spikes/)
docs/program/PHASE1B-MEASUREMENTS.md
```

---

### Task 1: `conservation` module (snapshot / compare / accounting) with unit tests

**Files:** `programs/warden/src/conservation/{mod.rs,snapshot.rs,compare.rs,accounting.rs}`, `src/lib.rs` (mod), `src/errors.rs` (append `ConservationViolated`, `UnsupportedAccountKind`, `PayloadInvalid`, `RegistryDenied`, `StageInvalid`, `StageExpired`, `SelfCpiRejected`, `ComputeBudgetInExecute`, `Token2022ExtensionRejected` — one per distinct failure; codes 6036+ appended; drift table extended in tests/root_verify.rs).

**Interfaces:**
```rust
pub struct TokenSnap { pub mint: Pubkey, pub owner: Pubkey, pub amount: u64, pub delegate: Option<Pubkey>, pub delegated_amount: u64, pub close_authority: Option<Pubkey>, pub state: u8, pub is_native: Option<u64>, pub tlv_hash: [u8;32], pub program: u8 /*0 spl,1 t22*/ }
pub struct Snap { pub key: Pubkey, pub exists: bool, pub owner_program: Pubkey, pub lamports: u64, pub data_len: usize, pub token: Option<TokenSnap>, pub is_writable: bool }
pub fn snapshot(accts: &[AccountInfo], vault: &Pubkey) -> Result<Vec<Snap>>;   // token parse strict (165 B / T22 base + TLV); COption strict 0/1; unparseable token-program-owned ⇒ token None but flagged `token_parse_failed` (add field) so compare can reject if BEFORE was vault-owned
pub struct Outflow { pub sol: u64, pub by_mint: Vec<(Pubkey, u64)> }
pub fn compare_and_account(before: &[Snap], after: &[Snap], vault: &Pubkey, allow_t22: bool) -> Result<Outflow>;
// rules: same length/order; for each i: key equal; if before.vault_owned_token: after must parse as token, all fields except amount equal (incl. is_native, tlv_hash, owner_program, data_len), state Initialized, delegate None (policy) — but ALSO before.delegate must be None else reject; amount decrease → outflow[mint] += dec (checked); if before.owner_program == vault (data account owned by PDA) ⇒ reject unless key == vault PDA itself and NOT writable; PDA lamports: sol_out = before.lamports − after.lamports (checked_sub, floor 0 → inflow) ; WSOL vault accounts add to sol_out; any account with is_writable && owner_program==warden ⇒ reject (self-CPI/state) except the SmartAccount when passed read-only.
```
- [ ] Unit tests (RED first; pure, no SVM): unchanged→zero outflow; amount decrease→outflow; delegate set→Err; delegate cleared (before Some)→Err(before must be None); close_authority set→Err; owner change→Err; data_len change→Err; TLV change→Err; is_native change→Err; account disappears (exists→false)→Err; non-vault token account changes→ignored; WSOL decrease counted in sol; PDA lamport decrease counted; PDA lamport increase→0; unparseable-after when before vault-owned→Err; T22 with allow_t22=false ⇒ Err(Token2022ExtensionRejected) when extensions present (parse TLV types: transfer-hook 14, permanent-delegate 12, confidential 4/5 — reject those; others allowed); overflow guards.
- [ ] Implement; `cargo test -p warden --lib`; commit `feat(program): conservation snapshot/compare/accounting`.

---

### Task 2: Test programs `test-mutator` and `test-jup-mock` + LiteSVM fixtures

**Files:** `programs/test-mutator/{Cargo.toml,src/lib.rs}`, `programs/test-jup-mock/{Cargo.toml,src/lib.rs}`, `Anchor.toml` (programs.localnet entries with generated ids — keypairs NOT committed; ids in `declare_id!`), `programs/warden/tests/common/{mutator.rs,jup.rs}` (load .so, build ixs).

- `test-mutator` instructions (each CPI into SPL Token as the passed authority — the warden PDA signs via `execute`'s invoke_signed): `noop`, `transfer_out(amount)`, `set_delegate(delegate, amount)`, `set_close_authority(new)`, `set_owner(new)`, `close_account(dest)`, `realloc_self(new_len)` (on its own state account), `drain_lamports(dest, amount)` (attempts `**src.lamports -= amount` on the passed vault PDA — must fail at runtime since only the owner program can debit; still test), `reenter_warden(ix bytes)` (attempts CPI into warden — must be rejected by warden's self-CPI rule before it even runs: the payload rejects program_idx == warden).
- `test-jup-mock`: `route(in_amount, min_out, misbehave: u8)` with account roles mirroring Jupiter (`token_program, user_transfer_authority(signer), user_source_ata, user_destination_ata, destination_mint, platform_fee_account, …`); misbehave modes: 0 honest (moves in_amount out, credits ≥ min_out), 1 credit less than min_out, 2 also debit a second vault ATA, 3 send fee to a non-treasury account, 4 set delegate on source. It mints out_mint tokens to the destination from a mock pool ATA it controls.
- [ ] Build both (`anchor build`, serialized); LiteSVM fixtures load their .so; smoke tests that each mutator op works when the payer is the authority (outside warden).
- [ ] Commit `test(program): mutator + jup-mock test programs`.

---

### Task 3: `Registry` account + `init_registry` + `grant_session` allowlist ids

**Files:** `src/state/registry.rs`, `src/registry.rs`, `src/instructions/registry_admin.rs`, modify `src/instructions/grant_session.rs`, tests `tests/registry.rs`.

**Interfaces:**
```rust
#[account(zero_copy)] #[repr(C)] pub struct Registry { pub version: u8, pub bump: u8, pub _pad: [u8;6], pub authority: Pubkey /*dev multisig in 1B*/, pub n_entries: u16, pub _pad2: [u8;6], pub entries: [RegistryEntry; 64], pub lists: [ListMask; 8] /*list id 1..8: bitmask over entries; id 0 = "no registry"*/ , pub _reserved: [u8; 256] }
#[zero_copy] #[repr(C)] pub struct RegistryEntry { pub program_id: Pubkey, pub discriminator: [u8; 8], pub disc_len: u8 /*8 anchor, 1 spl-token tag, 4 system*/, pub role_rules: u8 /*bitflags: 1 = vault PDA may be passed as signer, 2 = requires token program in accts*/, pub _pad: [u8;6] }
#[zero_copy] #[repr(C)] pub struct ListMask { pub bits: [u64; 1] }  // 64 entries
pub fn registry_allows(reg: &Registry, list_id: u16, program: &Pubkey, ix_data: &[u8]) -> bool;
```
Global singleton PDA `["registry"]`; `init_registry(entries, lists)` by `authority` (payer == authority at init; 1B: a dev keypair recorded in Anchor.toml provider — mainnet: the multisig); entries immutable in 1B (no update ix; 1C adds timelocked update). Default entries shipped as data in `packages/core/src/registry-default.json` AND mirrored in a Rust const for tests: SPL Token `Transfer`(3), `TransferChecked`(12), Associated Token `Create`(0/1), System `Transfer`(2), Memo, Jupiter `route`/`shared_accounts_route` (discriminators derived from the Jupiter IDL — Task 6 verifies), test-mutator `noop`/`transfer_out` (test-only list). `SmartAccount.registry` set at create if the registry exists (1B: `create_account` takes an optional registry account and stores its key). `grant_session`: `program_allowlist_id` must be 0 or an existing list id in the account's registry (`RegistryDenied` if not).
- [ ] Tests: init ok / twice fails / non-authority fails; lookup positive/negative; grant with id 1 ok when registry set; grant with id 9 rejected; account without registry rejects non-zero ids.
- [ ] Commit.

---

### Task 4: `stage_open` / `stage_chunk` / `stage_finalize` / `stage_close`

**Files:** `src/state/stage.rs`, `src/instructions/stage.rs`, tests `tests/stage.rs`.
```rust
#[account] pub struct Stage { pub version: u8, pub bump: u8, pub account: Pubkey, pub creator: Pubkey, pub hash: [u8;32], pub len: u32, pub written: u32, pub finalized: bool, pub generation: u64, pub policy_version: u32, pub expiry_ts: i64, pub data: Vec<u8> }
```
`stage_open(hash, len ≤ 4096, expiry_ts ≤ now + 1h)` init PDA `["stage", account, hash]` space = header + len; `stage_chunk(offset, bytes)` (creator only, must be exactly the spec's 3-account layout, `offset+len ≤ len`, no overlap rule: sequential `offset == written` required); `stage_finalize` checks `written == len` and `Keccak256(data) == hash`, records `generation`/`policy_version` at finalize; `stage_close` by creator anytime before finalize, or anyone after `expiry_ts`, or by `execute` on consume; rent → creator.
- [ ] Tests incl. **measured payload cap**: build a real `stage_chunk` tx (payer, Stage PDA, System; disc + 8 B header + payload) and binary-search the largest payload with `serialize().len() ≤ 1232`; assert and record in PHASE1B-MEASUREMENTS.md (replaces PROVISIONAL 985); wrong-hash finalize fails; non-sequential chunk fails; expiry close by stranger works; consume-once (Task 5).
- [ ] Commit.

---

### Task 5: `execute` (inline + staged) with conservation and buckets

**Files:** `src/instructions/execute.rs`, `src/payload.rs` (parse `ExecutePayload`, index validation), tests `tests/execute.rs`, `tests/common/payload.rs`.
Rules: accounts = `[smart_account (mut, AccountLoader), signer (session Signer | payer for root), session (Option), ix_sysvar (Option), stage (Option, mut), registry (Option), remaining…]`; payload from args or from `stage.data` (stage must be finalized, `generation`/`policy_version` current, not expired; closed on success — and on failure the tx reverts so it stays); frozen ⇒ reject; session checks as in transfer + `OP_EXECUTE`; parse payload; for each inner ix: `program_idx` account executable, ≠ warden id (`SelfCpiRejected`), ≠ ComputeBudget (`ComputeBudgetInExecute`); session path: `registry_allows(list, program, data)` else `RegistryDenied` (list id 0 ⇒ every CPI denied — session `execute` requires a registry list); root path (action 0x07 over `borsh(ExecuteBody{ payload_hash: Keccak256(payload) })`) skips the registry but everything else applies; snapshot ALL writable remaining accounts BEFORE (`conservation::snapshot`), run CPIs with `invoke_signed` for the PDA when flagged, snapshot AFTER, `compare_and_account`; SESSION: `outflow.sol` and each `by_mint` ≤ session per_tx (mint-keyed; missing ⇒ must be 0), lifetime, and `buckets::debit` on account caps; ROOT: ≤ `large_threshold` + `buckets::debit`; cap on writable remaining accounts = `MAX_EXECUTE_ACCOUNTS` (start 40, PROVISIONAL until Task 8 measures).
- [ ] Tests (LiteSVM, real CPIs): `session_execute_spl_transfer_within_caps` (registry list contains SPL Transfer; outflow debited); `execute_over_per_tx_rejected`; `execute_unknown_mint_outflow_rejected`; `execute_program_not_in_registry_rejected`; `execute_self_cpi_rejected`; `execute_compute_budget_inside_rejected`; **mutator suite through CPI**: set_delegate → ConservationViolated; set_close_authority → Err; set_owner → Err; close_account → Err; realloc of vault-owned data account → Err (unsupported writable vault-owned non-token account rejected up front); drain_lamports → runtime error; reenter_warden → SelfCpiRejected; `execute_debits_same_buckets_as_transfer` (execute then transfer exceeds day cap); `root_execute_bounded_by_threshold_and_buckets`; `staged_execute_ok_and_consumes_stage`; `staged_execute_wrong_generation_rejected` (bump generation via raw helper); `staged_execute_expired_rejected`; `execute_frozen_rejected`; `execute_with_other_signer_flag_rejected`; tx-size assertions for inline execute (SPL transfer) and staged execute; **CU measurement** at 10/20/30/40 writable accounts (mix of vault token accounts) with one real inner CPI → PHASE1B-MEASUREMENTS.md; set `MAX_EXECUTE_ACCOUNTS` from the measurement (keep ≥ 40 only if ≤ 400k CU incl. CPI).
- [ ] Commit `feat(program): execute — inline+staged, registry, conservation, buckets`.

---

### Task 6: `swap` (Jupiter-pinned adapter) with the jup-mock

**Files:** `src/instructions/swap.rs`, `src/constants.rs` (JUP id + discriminators with provenance comment: derived from Jupiter v6 IDL `route` / `shared_accounts_route` — implementer fetches the IDL from Jupiter's public repo/on-chain and records the source URL + sha256 of the IDL file in PHASE1B-MEASUREMENTS.md; test asserts the constants equal `sha256("global:route")[..8]` etc.), tests `tests/swap.rs`.
Rules (spec §5.2.7): program must be the pinned Jupiter id (test env: `test-jup-mock` id via a `cfg(feature = "test-jup")` constant switch — document; production build has the real id); discriminator ∈ {route, shared_accounts_route}; `user_transfer_authority` == PDA (signer via invoke_signed); source ATA = vault ATA(in_mint), destination = vault ATA(out_mint), `platform_fee_account` == treasury ATA (treasury pubkey in policy? — 1B: a `treasury: Pubkey` constant per build (drinkerlabs treasury smart account) stored in `Registry.authority`? NO — add `treasury: Pubkey` field to `Registry` (it has 256 reserved bytes) so it is on-chain data, set at init); post-state: exactly one vault token account decreases (in_mint, ≤ `max_in` arg ≤ caps), out ATA increases ≥ `min_out` arg, all other vault accounts unchanged; sessions: `out_mint` must have a cap in session caps OR be in `ALLOWED_OUT_MINTS_DEFAULT` (SOL/USDC/USDT constants in 1B; policy list in 1C); buckets debited by in_mint outflow (account-wide) + session per_tx/lifetime.
- [ ] Tests with jup-mock: honest swap ok + buckets debited; misbehave 1 (min_out) rejected; misbehave 2 (second ATA debit) rejected; misbehave 3 (fee to wrong account) rejected; misbehave 4 (delegate) rejected; wrong program id rejected; wrong discriminator rejected; session out_mint not allowed rejected; over cap rejected; root swap ok bounded; tx-size assertion for a Jupiter-shaped account list (30 accounts) inline and staged; CU recorded.
- [ ] Commit.

---

### Task 7: Proof-of-possession at `create_account`

**Files:** `src/instructions/create_account.rs`, `src/root_verify/transcript.rs` (op 0x06 `CreateBody`), tests `tests/create_pop.rs` (+ update every existing test helper that creates accounts to perform the ceremony), `packages/core` (mirror `OP_CREATE`, `CreateBody` doc).
Rules: `CreateAccountArgs` gains `root: RootArgs`; the transcript's `account` = PDA derived from `owner_seed` (computed before init), `generation 0`, `policy_version 1`, `root_nonce 0`, `cluster_tag` = args.cluster_tag; `action_hash(0x06, borsh(CreateBody{ owner_seed, rp_id_hash, origin, cluster_tag, policy_hash: Keccak256(borsh(PolicyArgs)) }))`; verify with the args' root pubkey (not stored yet), then init and set `root_nonce = 1`. Update the create_account.rs/DECISION/spec wording: creation now authenticated; front-run squatting impossible (a squatter cannot produce the assertion); the extension still verifies root readback.
- [ ] Tests: create without ceremony rejected; wrong pubkey rejected; substituted owner_seed/policy rejected (ChallengeMismatch); replay of the same assertion for a second seed rejected (account differs → mismatch); **tx size** for 2-mint and 4-mint create measured — if 4 mints no longer fit, lower `MAX_MINTS_AT_CREATE` and update spec/docs; all 1A suites still green.
- [ ] Commit `feat(program): proof-of-possession at create_account`.

---

### Task 8: `packages/core` execute payload builder + wrap (productionised) 

**Files:** `packages/core/src/execute/{payload.ts,wrap.ts}`, tests. Port `wrapForExecute` from `spikes/03-txbudget/ts/src/wrap.ts` (instruction-local indices, dedup of account/session, ComputeBudget hoist + default `setComputeUnitLimit`, u8 guards) — rewrite in `packages/core` (no import from spikes), add `splitForStage(payload, capBytes)` using the measured cap from Task 4, and `encodeExecutePayload`/`decodeExecutePayload` matching the Rust parser byte-for-byte (pin a vector: encode in TS, decode in a Rust unit test — write the bytes to a fixture file `programs/warden/tests/fixtures/payload_vector.bin` generated by the TS test and consumed by a Rust test).
- [ ] Tests: round-trip; Rust decodes the TS vector; ComputeBudget hoisted; stage split counts.
- [ ] Commit.

---

### Task 9: Measurements, spec rev 8, DECISION close-out, Codex milestone (sol@max), handoff to 1C

- `docs/program/PHASE1B-MEASUREMENTS.md`: execute CU per N (with real CPI), swap CU, stage cap (measured), PoP create sizes, error ABI 6036+, design notes (swap buckets simplification, registry immutability in 1B, treasury field, MAX_EXECUTE_ACCOUNTS final), verification provenance.
- Spec → rev 8: §5.1 create (authenticated), grant (registry ids), execute/swap/stage rows updated with measured numbers; §5.2 payload contract confirmed; §12 "Phase 1B measured"; §16 milestone log.
- DECISION.md: O5, O11, PoP CLOSED with evidence links; remaining 1C items listed (per-session day buckets decision, set_policy semantics, guardians).
- Codex milestone security review (`gpt-5.6-sol` @ `max`), fix loop, then final whole-branch review; merge to main; push; then write the Phase 1C plan.

## Self-review (at authoring)
- Spec coverage (1B scope): §5.2 rules 1–7 (T1, T5, T6), §5.1 execute/swap/stage rows (T4–T6), payload contract (T5, T8), PoP (T7), O5/O11 gate (T1/T5/T4), registry (T3). Deferred to 1C: queue/pending/set_policy/policy lattice/guardians/recovery/guardian freeze/allowed_out_mints policy list/swap-specific caps/T22 allow-list.
- Rulings recorded here: swap debits per-mint account buckets (no separate swap caps in 1B); registry immutable in 1B; treasury pubkey in Registry; ALLOWED_OUT_MINTS default constants; MAX_EXECUTE_ACCOUNTS/stage cap set by measurement.
- Uncertainties named: Jupiter discriminators (verify from IDL), create tx budget after PoP, CU with real CPI.
