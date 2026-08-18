# Warden Wallet — Phase 1A: On-chain Program Foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `programs/warden` (Anchor) far enough that a passkey-rooted smart account can be created, grant/revoke bounded session keys, transfer SOL/SPL under account-wide day + rolling-30-day buckets, and be frozen — with every rule proven by LiteSVM tests including adversarial ones, and the root-verify path measured end to end.

**Architecture:** Anchor 1.1.2 program with a `state` module (typed accounts, `checked_*` arithmetic only), a `root_verify` module (Instructions-sysvar introspection of the secp256r1 precompile + strict `clientDataJSON` scanner + consumed `root_nonce`), a `buckets` module (per-mint day + rolling-30-day accounting shared by sessions and root), and thin instruction handlers. Tests are LiteSVM (`precompiles` feature) with helpers that build real WebAuthn-shaped assertions from a test P-256 key. Phase 1B adds `execute`/adapters/stage/swap, pending/timelock/policy lattice, guardians/recovery on top of these interfaces.

**Tech Stack:** Rust 1.97 stable, Anchor CLI 1.1.2 (`anchor build` → SBF via Agave 3.1.10 `cargo-build-sbf`), `solana-program`/`solana-sdk` 3.x, `litesvm = "0.12"` (features `["precompiles"]`), `p256` + `sha2` (dev-only) for test signing, `spl-token`/`spl-token-2022` state via the hand-rolled 165-B parser pattern from spike 3b (crate majors that resolve are recorded in `docs/TOOLCHAIN.md`).

**Spec:** `/opt/warden/docs/superpowers/specs/2026-08-18-warden-wallet-design.md` (rev 6) — §4, §5.1, §5.2, §5.4. **Decision doc:** `/opt/warden/docs/spikes/DECISION.md` (C1–C8, O5, O6, O10, O11). **Prior art to copy from (read before Task 2/3):** `spikes/02-webauthn/onchain/src/lib.rs` (precompile introspection, proven bounds checks) and `spikes/03-txbudget/onchain/src/lib.rs` (`check_vault_invariants`, strict COption parsing) — copy the *patterns*, not the files; the spikes are throwaway.

## Global Constraints

- **Checked arithmetic everywhere**: no `+ - * /` on `u64` amounts/timestamps; `checked_*` returning `WardenError::Overflow`. `#![deny(clippy::arithmetic_side_effects)]` on the crate.
- **Root verify** (spec §4/C1–C3): secp256r1 precompile ix in the same tx; exact match of `(pubkey33, message = authenticatorData ‖ SHA-256(clientDataJSON), sig64)` via Instructions sysvar with all three instruction indices == `0xFFFF` and `num_signatures == 1`; `authenticatorData[0..32] == account.rp_id_hash` (stored per account, set at creation, = SHA-256 of the full extension origin — **never** a compiled-in literal); flags UP|UV (`0x05`) required in v1 (O10 decision: UV mandatory for root); `clientDataJSON` ≤ `MAX_CLIENT_DATA_LEN = 512` and parsed by the **strict top-level scanner** (depth-0 keys only; exactly one `type`/`challenge`/`origin`; duplicate top-level key ⇒ reject; escapes `\" \\ \/ \uXXXX` decoded or reject; `crossOrigin` absent or `false`; `type == "webauthn.get"`; `origin == account.origin`; `challenge == base64url(transcript_hash)` no padding).
- **Transcript** (spec §4): `Keccak256("WARDEN/root/v1" ‖ genesis_hash ‖ program_id ‖ account ‖ generation:u64LE ‖ policy_version:u32LE ‖ root_nonce:u64LE ‖ expiry_ts:i64LE ‖ action_hash)`; `now ≤ expiry_ts ≤ now + 600`; `root_nonce` incremented on every successful root instruction; `action_hash = Keccak256(op_type:u8 ‖ borsh(args))` recomputed on-chain from the executing instruction's args.
- **Root payload budget** (C7): root instructions carry ≤ 400 B of instruction data beyond the transcript inputs (the precompile ix already costs ~788 B of the 1,232-B tx).
- **Buckets** (spec §4/§5.2.4): per mint, account-wide across all sessions **and** root direct actions: `per_tx`, UTC-day bucket (`day_start = ts - ts % 86400`), rolling-30-day as **30 daily sub-buckets** (ring of 30 `u64` with `day_index`), lifetime per session; every outflow path debits the same structures.
- **Time source**: `Clock::get()?.unix_timestamp` (i64), never slots.
- **PDAs**: `["account", owner_seed]`, `["session", account, session_pubkey]`; every handler re-derives PDAs from seeds; `frozen` gates every outflow and session use.
- **Anchor**: `anchor_version = "1.1.2"` in `Anchor.toml`; program id from `programs/warden/keypair` generated once and committed to `Anchor.toml`/`declare_id!`; root `Cargo.toml` `members = ["programs/*"]` restored (Task 1).
- Builds serialized on this host (`nice -n 10`, never two cargo processes); every task ends with `cargo test -p warden` green + `pnpm test` green + commit with trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`; Codex reviews every task (controller dispatches).
- **Do not copy spike code verbatim** — the spikes carry known holes (substring matcher, token-only conservation).

---

## File structure (this plan)

```
programs/warden/
├── Cargo.toml                    (name = "warden", anchor-lang, dev-deps litesvm/p256/sha2/solana-sdk)
├── Xargo.toml (if anchor needs)  
├── src/
│   ├── lib.rs                    (declare_id!, #[program] with instruction fns delegating to handlers)
│   ├── errors.rs                 (WardenError enum)
│   ├── constants.rs              (seeds, MAX_CLIENT_DATA_LEN, limits)
│   ├── state/
│   │   ├── mod.rs
│   │   ├── smart_account.rs      (SmartAccount, Policy, MintCap, Buckets)
│   │   └── session.rs            (SessionKey)
│   ├── root_verify/
│   │   ├── mod.rs                (verify_root_assertion(...) entry)
│   │   ├── precompile.rs         (Instructions-sysvar binding)
│   │   ├── client_data.rs        (strict top-level scanner)
│   │   ├── auth_data.rs          (rpIdHash/flags parse)
│   │   └── transcript.rs         (transcript + action_hash)
│   ├── buckets.rs                (debit(): per_tx/day/30d/lifetime with checked math)
│   └── instructions/
│       ├── mod.rs
│       ├── create_account.rs
│       ├── grant_session.rs / revoke_session.rs
│       ├── transfer.rs
│       └── freeze.rs / unfreeze.rs (root freeze only in 1A; guardian freeze in 1B)
└── tests/                        (LiteSVM integration; one file per area)
    ├── common/mod.rs             (svm setup, program load, passkey test-signer, assertion builder, token account fixtures)
    ├── create_account.rs
    ├── root_verify.rs            (positive + all negatives incl. the six flipped "hole" tests)
    ├── sessions.rs
    ├── transfer.rs               (buckets, day/30d rollovers, root bounded)
    └── freeze.rs
packages/core/src/webauthn/       (TS mirror of transcript + challenge encoding for the extension — small)
docs/program/PHASE1A-MEASUREMENTS.md
```

---

### Task 1: Anchor program skeleton, workspace, CI gate

**Files:**
- Create: `programs/warden/Cargo.toml`, `programs/warden/src/lib.rs`, `programs/warden/src/errors.rs`, `programs/warden/src/constants.rs`, `programs/warden/tests/common/mod.rs`, `programs/warden/tests/smoke.rs`
- Modify: `Cargo.toml` (root: `members = ["programs/*"]`, keep `exclude = ["spikes"]`), `Anchor.toml` (program id), `.claude/test-gate.sh` (already runs cargo when programs exist — verify)

**Interfaces:**
- Produces: program id constant `WARDEN_PROGRAM_ID` (from `declare_id!`); `WardenError` enum (`Overflow`, `Frozen`, `Unauthorized`, `InvalidRootAssertion`, `NonceMismatch`, `Expired`, `CapExceeded`, `SessionExpired`, `OpNotAllowed`, `InvalidAccountData`, `BadInstructionLayout`); test helper `common::setup() -> (LiteSVM, Keypair /*payer*/)` that loads `target/deploy/warden.so`.

- [ ] **Step 1: Generate the program keypair and scaffold**

```bash
source ~/.cargo/env; export PATH=/root/.local/share/solana/install/active_release/bin:$PATH
cd /opt/warden && mkdir -p programs && cd programs
anchor init --no-git warden 2>&1 | tail -2 || true   # if anchor init insists on a fresh dir, run it in a temp dir and copy programs/warden + tests skeleton in
```
If `anchor init` layout differs from ours, keep only `programs/warden/{Cargo.toml,Xargo.toml,src/lib.rs}` and the generated `target/deploy/warden-keypair.json`; move the keypair to `programs/warden/keypair.json` (commit it — devnet/localnet id only; mainnet id is generated later under the multisig) and reference it in `Anchor.toml`:
```toml
[programs.localnet]
warden = "<pubkey printed by: solana-keygen pubkey programs/warden/keypair.json>"
```
`programs/warden/Cargo.toml`:
```toml
[package] name = "warden" version = "0.1.0" edition = "2021"
[lib] crate-type = ["cdylib", "lib"] name = "warden"
[features] default = [] cpi = ["no-entrypoint"] no-entrypoint = [] no-idl = [] no-log-ix-name = [] idl-build = ["anchor-lang/idl-build"]
[dependencies]
anchor-lang = "1.1.2"
[dev-dependencies]
litesvm = { version = "0.12", features = ["precompiles"] }
solana-sdk = "3"
solana-secp256r1-program = "3"
p256 = { version = "0.13", features = ["ecdsa"] }
sha2 = "0.10"
sha3 = "0.10"
base64 = "0.22"
```
`src/lib.rs`:
```rust
#![deny(clippy::arithmetic_side_effects)]
use anchor_lang::prelude::*;
pub mod constants; pub mod errors;
declare_id!("<same pubkey as Anchor.toml>");
#[program]
pub mod warden {
    use super::*;
    pub fn ping(_ctx: Context<Ping>) -> Result<()> { Ok(()) }
}
#[derive(Accounts)] pub struct Ping {}
```
`src/errors.rs`:
```rust
use anchor_lang::prelude::*;
#[error_code]
pub enum WardenError {
    #[msg("arithmetic overflow")] Overflow,
    #[msg("account is frozen")] Frozen,
    #[msg("unauthorized signer")] Unauthorized,
    #[msg("invalid root assertion")] InvalidRootAssertion,
    #[msg("root nonce mismatch")] NonceMismatch,
    #[msg("expired")] Expired,
    #[msg("cap exceeded")] CapExceeded,
    #[msg("session expired")] SessionExpired,
    #[msg("operation not allowed for this signer")] OpNotAllowed,
    #[msg("invalid account data")] InvalidAccountData,
    #[msg("bad instruction layout")] BadInstructionLayout,
}
```
`src/constants.rs`:
```rust
pub const ACCOUNT_SEED: &[u8] = b"account";
pub const SESSION_SEED: &[u8] = b"session";
pub const MAX_CLIENT_DATA_LEN: usize = 512;
pub const MAX_ROOT_EXPIRY_SECS: i64 = 600;
pub const MAX_MINT_CAPS: usize = 8;
pub const MAX_SESSIONS_LISTED: usize = 0; // sessions are separate PDAs; no list on the account
pub const DAY_SECS: i64 = 86_400;
pub const RING_DAYS: usize = 30;
```

- [ ] **Step 2: Test harness + smoke test (RED → GREEN)**

`tests/common/mod.rs`:
```rust
use litesvm::LiteSVM;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
pub fn program_id() -> Pubkey { warden::ID }
pub fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    let so = include_bytes!("../../../../target/deploy/warden.so");
    svm.add_program(program_id(), so);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    (svm, payer)
}
```
`tests/smoke.rs`:
```rust
mod common;
use solana_sdk::{instruction::Instruction, message::Message, transaction::Transaction, signer::Signer};
#[test]
fn ping_succeeds() {
    let (mut svm, payer) = common::setup();
    let disc = anchor_lang::solana_program::hash::hash(b"global:ping").to_bytes()[..8].to_vec();
    let ix = Instruction { program_id: common::program_id(), accounts: vec![], data: disc };
    let tx = Transaction::new(&[&payer], Message::new(&[ix], Some(&payer.pubkey())), svm.latest_blockhash());
    assert!(svm.send_transaction(tx).is_ok());
}
```
Run (serialized): `cd /opt/warden && nice -n 10 anchor build 2>&1 | tail -5 && nice -n 10 cargo test -p warden -- --nocapture 2>&1 | tail -15` → expect `ping_succeeds ... ok`. If `anchor build` fails on the toolchain, use `nice -n 10 cargo-build-sbf --manifest-path programs/warden/Cargo.toml` and record it in `docs/TOOLCHAIN.md`.

- [ ] **Step 3: Root workspace + gate**

Root `Cargo.toml` → `members = ["programs/*"]`, `exclude = ["spikes"]`; run `cargo metadata --no-deps >/dev/null && echo OK`. Confirm `.claude/test-gate.sh` now runs `cargo test --workspace --exclude spike-p256 --exclude spike-conserve` (spikes are excluded from the workspace, so drop the `--exclude` flags if cargo complains). Run `./.claude/test-gate.sh` → exit 0.

- [ ] **Step 4: Commit**

```bash
git add programs Cargo.toml Cargo.lock Anchor.toml .claude/test-gate.sh docs/TOOLCHAIN.md && git commit -m "feat(program): warden Anchor skeleton, LiteSVM harness, workspace restored"
```

---

### Task 2: State layouts (SmartAccount, Policy, Buckets, SessionKey) + unit tests

**Files:**
- Create: `programs/warden/src/state/mod.rs`, `state/smart_account.rs`, `state/session.rs`, `programs/warden/src/buckets.rs`
- Modify: `src/lib.rs` (mod state; mod buckets)

**Interfaces (exact — later tasks depend on these names):**
```rust
// state/smart_account.rs
#[account] pub struct SmartAccount {
    pub version: u8,
    pub bump: u8,
    pub owner_seed: [u8; 32],
    pub root: RootKey,               // enum below
    pub rp_id_hash: [u8; 32],        // == SHA-256(origin[..origin_len]) — enforced at create (Task 4)
    pub origin: [u8; 64], pub origin_len: u8,   // canonical full origin "chrome-extension://<32 chars>"; bytes beyond origin_len are zero; no NULs
    pub cluster_tag: [u8; 32],       // client-attested domain separator (genesis hash by convention) — NOT verified on-chain; bound into every root transcript
    pub generation: u64,
    pub root_nonce: u64,
    pub policy: Policy,
    pub frozen: FrozenState,         // enum { None, Root, Guardian{idx:u8, until:i64} }
    pub frozen_at: i64,
    pub buckets: [MintBuckets; MAX_MINT_CAPS],  // parallel to policy.caps
    pub guardians_config: Pubkey,    // 1B: PDA of the guardians/recovery config (Pubkey::default() until set) — reserved now so no realloc later
    pub registry: Pubkey,            // 1B: adapter-registry PDA (default until set)
    pub _reserved: [u8; 256],        // forward-compat headroom; 1B/1C fields are carved from here without realloc; `version` bumps document each carve
}
// v1 product limit, deliberate: 8 mint cap slots (SOL + up to 7 SPL/Token-2022 mints). Extensible policy beyond that moves to a PDA in a later version.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub enum RootKey { P256Passkey { pubkey: [u8; 33] }, Ed25519 { pubkey: Pubkey } }
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub enum FrozenState { None, Root, Guardian { idx: u8, until: i64 } }
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct Policy {
    pub version: u32,
    pub caps: [MintCap; MAX_MINT_CAPS],  // mint == Pubkey::default() ⇒ unused slot; SOL uses native mint id
    pub session_ceiling: [MintCap; MAX_MINT_CAPS],
    pub large_threshold: [MintCap; MAX_MINT_CAPS], // per_tx only used
    pub timelock_secs: i64, pub recovery_delay_secs: i64,
    pub max_session_life_secs: i64,
    pub session_ops_ceiling: u16,
    pub _reserved: [u8; 64],
}
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Default)]
pub struct MintCap { pub mint: Pubkey, pub per_tx: u64, pub per_day: u64, pub per_30d: u64 }
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default)]
pub struct MintBuckets { pub day_start: i64, pub spent_today: u64, pub ring_day_index: i64, pub ring: [u64; 30] }
// state/session.rs
#[account] pub struct SessionKey {
    pub version: u8, pub bump: u8, pub account: Pubkey, pub pubkey: Pubkey, pub kind: u8 /*0=Ed25519*/,
    pub expiry_ts: i64, pub ops_mask: u16, pub generation_at_grant: u64,
    pub caps: [MintCap; MAX_MINT_CAPS], pub lifetime_cap: [u64; MAX_MINT_CAPS], pub lifetime_spent: [u64; MAX_MINT_CAPS],
    pub program_allowlist_id: u16,   // spec §5.1: adapter-registry list id (0 = none; 1B defines the registry)
    pub label: [u8; 16],
    pub _reserved: [u8; 64],
}
// Both accounts are created at their FINAL 1A size (LEN includes the reserved bytes) so 1B never needs realloc; a unit test asserts LEN and that `_reserved` is all-zero after create/grant.
pub const OP_TRANSFER: u16 = 1 << 0; pub const OP_EXECUTE: u16 = 1 << 1; pub const OP_SWAP: u16 = 1 << 2; pub const OP_SIGN_MESSAGE: u16 = 1 << 3;
// buckets.rs
pub fn debit(b: &mut MintBuckets, cap: &MintCap, amount: u64, now: i64) -> Result<()>;
// rules: require now ≥ 0 else Err(InvalidAccountData) (no negative timestamps; use i64::rem_euclid/div_euclid anyway); amount ≤ cap.per_tx; roll day bucket if now ≥ day_start+DAY_SECS (spent_today=0, day_start = now - now.rem_euclid(DAY_SECS));
// ring: day_number = now.div_euclid(DAY_SECS); advance ring_day_index → day_number zeroing skipped slots (min(30, gap)); slot = day_number % 30;
// require spent_today+amount ≤ per_day and Σring+amount ≤ per_30d (checked_add), then write both. cap.per_* == 0 ⇒ that limit disabled? NO: 0 means zero allowed (a mint with no cap must not be spendable). Unused slot (mint == default) ⇒ Err(CapExceeded).
pub fn find_cap<'a>(caps: &'a [MintCap; MAX_MINT_CAPS], mint: &Pubkey) -> Option<(usize, &'a MintCap)>;
```

- [ ] **Step 1: Write unit tests for `buckets::debit` (RED)** — in `buckets.rs` `#[cfg(test)]`: `within_all_caps_ok`, `per_tx_exceeded_err`, `day_cap_exceeded_err`, `day_rolls_over_at_utc_midnight` (spend to cap at t, then at t + remaining-to-midnight succeed), `ring_30d_cap_enforced_across_days` (spend per_day each day for 30 days until per_30d hit → Err on day k), `ring_zeroes_skipped_days` (spend, jump 45 days, spend full again OK), `unknown_mint_err`, `zero_cap_means_no_spend`, `overflow_guard` (spent near u64::MAX → Overflow, no panic), `exact_midnight_boundary` (spend at 86399 then at 86400 → new day), `negative_timestamp_rejected`, `ring_slot_index_at_day_29_30_31` (wraparound), `len_constants_match_serialized_size_and_reserved_zeroed`.
- [ ] **Step 2: Implement state + buckets** exactly per Interfaces; `#[account]` sizes computed via `InitSpace` derive or manual `LEN` consts (add `pub const LEN: usize` on both accounts and a unit test asserting `LEN == 8 + try_to_vec(default).len()`).
- [ ] **Step 3: Run** `cargo test -p warden buckets` → all pass; `cargo test -p warden` (whole crate) → pass.
- [ ] **Step 4: Commit** `git add programs && git commit -m "feat(program): state layouts + bucket accounting with checked math"`.

---

### Task 3: root_verify module — precompile binding, authenticatorData, strict clientDataJSON scanner, transcript

**Files:**
- Create: `programs/warden/src/root_verify/{mod.rs,precompile.rs,auth_data.rs,client_data.rs,transcript.rs}`, `programs/warden/tests/root_verify.rs`, `programs/warden/tests/common/passkey.rs`
- Modify: `src/lib.rs` (mod root_verify; a test-only instruction `verify_root_only` behind `#[cfg(feature = "test-ix")]`? — NO: instead Task 4's `create_account` + Task 5's `grant_session` are the real root instructions; for Task 3 add a permanent minimal instruction `root_noop(args: RootArgs)` that only verifies and bumps `root_nonce` — kept in the program as `rotate_nonce` (useful in prod to invalidate an outstanding challenge). 

**Interfaces:**
```rust
// root_verify/mod.rs
pub struct RootArgs { pub precompile_ix_index: u8, pub authenticator_data: Vec<u8>, pub client_data_json: Vec<u8>, pub expiry_ts: i64 }
pub fn verify_root_assertion(
    account: &mut SmartAccount, ix_sysvar: &AccountInfo, args: &RootArgs, program_id: &Pubkey, account_key: &Pubkey,
    action_hash: [u8; 32], now: i64,
) -> Result<()>;   // on success: account.root_nonce += 1 (checked)
// transcript.rs
pub fn transcript_hash(genesis: &[u8;32], program_id: &Pubkey, account: &Pubkey, generation: u64, policy_version: u32, root_nonce: u64, expiry_ts: i64, action_hash: &[u8;32]) -> [u8;32];
pub fn action_hash(op_type: u8, borsh_args: &[u8]) -> [u8;32];   // Keccak256
pub fn b64url_no_pad(bytes: &[u8]) -> Vec<u8>;
// client_data.rs
pub struct ClientData<'a> { pub typ: &'a [u8] /*decoded*/, pub challenge: Vec<u8>, pub origin: Vec<u8>, pub cross_origin_true: bool }
pub fn parse_strict(cdj: &[u8]) -> Result<ClientData>;  // rules in Global Constraints (depth-0 only, exactly-one keys, dup ⇒ Err, escapes decoded (\" \\ \/ \uXXXX BMP only; surrogates ⇒ Err), other keys skipped by a depth-aware skipper for strings/numbers/objects/arrays/true/false/null)
// auth_data.rs
pub fn check_auth_data(auth: &[u8], expected_rp_id_hash: &[u8;32]) -> Result<()>; // len ≥ 37; [0..32]==expected; flags & 0x05 == 0x05
// precompile.rs
pub fn bind_precompile(ix_sysvar: &AccountInfo, ix_index: u8, expected_pubkey33: &[u8;33], expected_message: &[u8]) -> Result<()>; // program id == secp256r1; d[0]==1; all three ix indices 0xFFFF; bounds-checked offsets; pubkey and message equal exactly (msg_size == expected len)
```
Genesis hash: LiteSVM/localnet differ from mainnet — read it as `sysvar::instructions`-independent constant? No: obtain via `solana_program::sysvar::slot_hashes`? Not available. **Ruling in plan:** the on-chain program cannot read the genesis hash. `SmartAccount.cluster_tag` (Task 2 layout) is set at creation from a client-supplied value (the extension fills it with `getGenesisHash()` by convention) and is bound into every root transcript. It is a **client-attested domain separator, not a verified genesis binding** — an assertion produced for an account with a different stored tag fails; two accounts with the same seed on two clusters have different tags only if the client set them so. Document this in code and in spec §4 (Task 9 edits the wording "genesis_hash" → "cluster_tag (client-attested)").

- [ ] **Step 1: Test-side passkey signer** `tests/common/passkey.rs`: `struct TestPasskey { sk: p256::ecdsa::SigningKey }` with `new()`, `pubkey33() -> [u8;33]` (compressed SEC1), `assert(challenge_b64url: &[u8], origin: &str, rp_id_hash: [u8;32], flags: u8) -> Assertion { authenticator_data: Vec<u8> (rpIdHash ‖ flags ‖ counter u32 BE = 0), client_data_json: Vec<u8> ("{\"type\":\"webauthn.get\",\"challenge\":\"…\",\"origin\":\"…\",\"crossOrigin\":false}"), signature64_low_s: [u8;64], message: Vec<u8> }` using `p256::ecdsa` with `normalize_s()`; plus `precompile_ix(&assertion, pubkey33) -> Instruction` via `solana_secp256r1_program::new_secp256r1_instruction_with_signature`.
- [ ] **Step 2: Unit tests for `client_data::parse_strict` (RED)** in `client_data.rs`: `accepts_canonical_chrome_json`, `rejects_nested_origin_object` (the spike hole — must now FAIL to verify), `rejects_duplicate_top_level_origin`, `rejects_missing_type`, `accepts_escaped_slash_in_origin` (`chrome-extension:\/\/abc` decodes equal), `accepts_unicode_escape_bmp`, `rejects_surrogate_escape`, `rejects_cross_origin_true`, `accepts_extra_unknown_keys_and_nested_junk` (`"foo":{"origin":"x"},"bar":[1,{"type":"y"}]` ignored), `rejects_over_512_bytes`, `rejects_truncated_json`, `rejects_challenge_with_padding_chars`.
- [ ] **Step 3: Unit tests for `auth_data`, `transcript`, `precompile` (RED)**: flags 0x01 only ⇒ Err; rpIdHash mismatch ⇒ Err; transcript vectors: fixed inputs → fixed hex (compute once with the same crate in a test and pin it — and mirror the same vector in TS in Task 7); `b64url_no_pad` known vector.
- [ ] **Step 4: Implement the module** (copy the *bounds-checking discipline* of `spikes/02-webauthn/onchain/src/lib.rs` for `precompile.rs`; write `client_data.rs` fresh as a small recursive-descent skipper: `skip_value`, `parse_string_decoded`, top-level loop counting `type/challenge/origin/crossOrigin` occurrences).
- [ ] **Step 5: `rotate_nonce` instruction** (`instructions/rotate_nonce.rs`): accounts `{ smart_account (mut), ix_sysvar }`, args `RootArgs`; `action_hash = action_hash(0x00, &[])`; calls `verify_root_assertion`. Wire in `lib.rs`.
- [ ] **Step 6: LiteSVM tests `tests/root_verify.rs`** (need a created account — temporarily create via a test-only direct `svm.set_account` with a serialized `SmartAccount` until Task 4 lands; then switch to `create_account`): `rotate_nonce_ok_and_nonce_increments`, `replay_same_assertion_rejected` (NonceMismatch), `expired_rejected`, `future_expiry_beyond_600s_rejected`, `wrong_origin_rejected`, `wrong_rp_id_hash_rejected`, `up_only_rejected`, `wrong_pubkey_rejected`, `two_signature_precompile_rejected`, `foreign_ix_index_rejected`, `message_mismatch_rejected` (different clientDataJSON in our ix), `nested_origin_rejected_on_chain`, `duplicate_origin_rejected_on_chain`, `precompile_after_our_ix_rejected` (require the precompile index < current index — get current via `load_current_index_checked`), `two_precompile_ixs_only_named_one_binds` (a decoy secp256r1 ix with another key at index 0, real one at 1, ours names 1 → OK; names 0 → rejected), `origin_with_trailing_nul_rejected_at_create` (Task 4) ; assert exact `InstructionError(1, Custom(<WardenError code>))` and print CU of the positive case; write CU to `docs/program/PHASE1A-MEASUREMENTS.md` ("root_verify: N CU").
- [ ] **Step 7: Run all, commit** `git commit -m "feat(program): root_verify — precompile binding, strict clientDataJSON scanner, transcript + nonce"`.

---

### Task 4: `create_account`

**Files:** `instructions/create_account.rs`, `tests/create_account.rs`; modify `lib.rs`.

**Interfaces:**
```rust
pub struct CreateAccountArgs { pub owner_seed: [u8;32], pub root: RootKey, pub rp_id_hash: [u8;32], pub origin: Vec<u8> /*≤64*/, pub cluster_tag: [u8;32], pub policy: Policy }
#[derive(Accounts)] pub struct CreateAccount<'info> { #[account(mut)] payer: Signer, #[account(init, payer = payer, space = SmartAccount::LEN, seeds = [ACCOUNT_SEED, args.owner_seed.as_ref()], bump)] smart_account: Account<SmartAccount>, system_program }
```
Rules: **`args.rp_id_hash == SHA-256(args.origin)` (recompute with `solana_program::hash::hashv`) else `InvalidRootAssertion`**; origin: 1..=64 bytes, must start with `chrome-extension://` in v1, no `\0` bytes, no trailing whitespace; stored zero-padded, compared using `origin_len` exactly; `cluster_tag` stored as given (non-zero required); `frozen_at = 0`; `guardians_config = registry = Pubkey::default()`; `_reserved` zeroed; `policy.version` set to 1 regardless of input; `generation = 0`, `root_nonce = 0`, `frozen = None`; validate `policy` (timelock ≥ 3600, recovery_delay ≥ 3600, max_session_life ≤ 30 d, caps: `per_tx ≤ per_day ≤ per_30d` for each used slot; session_ceiling ≤ caps? NO — ceiling bounds *grants*, caps bound *spend*: require `session_ceiling[i].per_* ≤ caps[i].per_*`); origin length ≤ 64 and non-empty. No root signature required to create (payer funds it; the root is what the client says — an attacker creating accounts for a victim's passkey is harmless).

- [ ] Tests (RED): `creates_with_defaults`, `rejects_bad_policy_ordering`, `rejects_origin_too_long`, `rejects_rp_id_hash_not_sha256_of_origin`, `rejects_origin_with_embedded_or_trailing_nul`, `rejects_zero_cluster_tag`, `stored_origin_zero_padded_and_len_exact`, `pda_is_hash_of_seed_not_root` (same root, different seeds ⇒ different addresses), `double_create_fails`.
- [ ] Implement, run, commit `feat(program): create_account`.
- [ ] Refactor `tests/root_verify.rs` to use `create_account` instead of `set_account`; re-run; commit.

---

### Task 5: Sessions — `grant_session`, `revoke_session`

**Files:** `instructions/grant_session.rs`, `instructions/revoke_session.rs`, `tests/sessions.rs`.

**Interfaces:**
```rust
pub struct GrantSessionArgs { pub root: RootArgs, pub expiry_ts: i64, pub session_pubkey: Pubkey, pub kind: u8, pub ops_mask: u16, pub caps: Vec<MintCap> /*≤8*/, pub lifetime_cap: Vec<u64>, pub label: [u8;16] }
// action_hash = action_hash(0x01, &borsh(GrantSessionArgsWithoutRoot))  — define `GrantBody` struct = all fields except `root`, borsh-serialized
#[derive(Accounts)] pub struct GrantSession<'info> { #[account(mut)] payer: Signer, #[account(mut, seeds=[ACCOUNT_SEED, smart_account.owner_seed.as_ref()], bump=smart_account.bump)] smart_account, #[account(init_if_needed, payer=payer, space=SessionKey::LEN, seeds=[SESSION_SEED, smart_account.key().as_ref(), args.session_pubkey.as_ref()], bump)] session, ix_sysvar (address = sysvar::instructions::ID), system_program }
```
Rules: root verify with `expiry_ts` from `args.root`; `frozen == None` else `Frozen`; each cap ≤ `policy.session_ceiling` for that mint (mint must exist in ceiling) else `CapExceeded`; `ops_mask & !policy.session_ops_ceiling == 0` else `OpNotAllowed`; `expiry_ts ≤ now + max_session_life`; sets `generation_at_grant = generation`; upsert resets `lifetime_spent` only if the session did not exist (re-grant keeps spent). `revoke_session`: signer is root (RootArgs, action 0x02 over `session_pubkey`) **or** the session key itself (Ed25519 signer == session.pubkey); closes the PDA (rent to payer/root-payer).
Root payload budget: `MintCap` = 32+8+8+8 = 56 B; `GrantBody` with 4 caps ≈ 4×56 + 4×8 (lifetime) + 32 (pubkey) + 8+2+1+16 ≈ 315 B; `RootArgs` adds authenticatorData 37 B + clientDataJSON (Chrome canonical ≈ 130–160 B; hard cap 512) + 9 B ⇒ instruction data ≈ 490–560 B canonical. With the ~788-B precompile+envelope baseline this does **not** fit 1,232 B for 4 caps. **Therefore: `MAX_CAPS_PER_GRANT = 2`** (≈ 200 B less) and the test `grant_tx_fits_1232_bytes` builds the REAL transaction (precompile ix + grant ix, canonical Chrome clientDataJSON of 160 B) with 2 caps and asserts `serialize().len() ≤ 1232`; a second test asserts a 3-cap grant is REJECTED by the program (`BadInstructionLayout`) so the limit is enforced, not just advised. If even 2 caps do not fit, the implementer reports BLOCKED (design change: staged grants). Grant semantics: caps vector and lifetime vector must have equal length ≤ 2 and distinct mints (duplicate ⇒ `InvalidAccountData`); upsert **merges by mint** into the existing session's 8 slots (replace slot with same mint, else first empty slot, else `CapExceeded`); `lifetime_spent` is preserved on re-grant and a re-grant that sets `lifetime_cap < lifetime_spent` is rejected; `expiry_ts`/`ops_mask` are replaced.

- [ ] Tests (RED): `grant_ok_and_readback`, `grant_needs_fresh_nonce` (reuse ⇒ NonceMismatch), `grant_over_ceiling_rejected`, `grant_ops_over_ceiling_rejected`, `grant_expiry_too_long_rejected`, `grant_frozen_rejected` (written in Task 6), `revoke_by_session_self_ok`, `revoke_by_root_ok`, `revoke_by_stranger_rejected`, `grant_tx_fits_1232_bytes_with_2_caps` (real tx incl. precompile), `grant_with_3_caps_rejected`, `regrant_merges_by_mint_and_preserves_spent`, `regrant_lower_lifetime_than_spent_rejected`, `duplicate_mint_in_grant_rejected`, `revoke_close_then_regrant_gets_current_generation` (revoke, bump generation (Task 7's `set_account` helper), grant again → `generation_at_grant` == new generation).
- [ ] Implement, run, commit `feat(program): grant/revoke session`.

---

### Task 6: `freeze` / `unfreeze` (root) — 1A scope

**Files:** `instructions/freeze.rs`, `instructions/unfreeze.rs`, `tests/freeze.rs`.

Rules: `freeze` by root (RootArgs, action 0x03) sets `frozen = Root`; `unfreeze` by root (action 0x04) allowed only if `now ≥ frozen_at + policy.timelock_secs` — add `frozen_at: i64` to `SmartAccount` (Task 2 layout gains the field; bump `LEN` test). Guardian freeze arrives in 1B (`FrozenState::Guardian` variant already exists).
- [ ] Tests: `root_freeze_blocks_transfer_and_grant` (needs Task 7's transfer — implement transfer first? Order Tasks 6→7 as written and put the transfer-blocked test into Task 7's suite; here test `freeze_sets_state`, `unfreeze_before_timelock_rejected`, `unfreeze_after_timelock_ok`, `grant_frozen_rejected` (belongs here now)).
- [ ] Implement, run, commit `feat(program): root freeze/unfreeze with timelock`.

---

### Task 7: `transfer` — SOL and SPL, session and root, shared buckets

**Files:** `instructions/transfer.rs`, `tests/transfer.rs`, `tests/common/token.rs` (fixtures: create mint/ATA via `set_account` with packed SPL state as in spike 3b's tests).

**Interfaces:**
```rust
pub struct TransferArgs { pub root: Option<RootArgs>, pub mint: Option<Pubkey> /*None = SOL*/, pub amount: u64 }
// Root action binding: `TransferBody { native: bool, mint: Pubkey /*default for SOL*/, destination: Pubkey /*the destination ACCOUNT key (SystemAccount or token account)*/, amount: u64 }` borsh-serialized; action_hash = action_hash(0x05, &borsh(TransferBody)) recomputed on-chain from the accounts actually passed — a substituted destination fails verification.
// accounts: smart_account (mut), signer (Signer: session pubkey OR any payer when root path), session (Option<Account<SessionKey>> — required when root is None), ix_sysvar (Option, required when root is Some), destination (mut; SystemAccount for SOL, or TokenAccount for SPL), source_ata (Option, vault ATA for SPL), token_program (Option), system_program
```
Rules: `frozen == None`; **session path**: `session.account == smart_account.key()`, `session.generation_at_grant == generation`, `now < expiry_ts`, `ops_mask & OP_TRANSFER != 0`, `signer == session.pubkey`; cap lookup in `session.caps` for mint (missing ⇒ `CapExceeded`) AND account-wide `policy.caps` (missing ⇒ `CapExceeded`); `buckets::debit(account.buckets[i], policy.caps[i], amount, now)`; per-session lifetime `lifetime_spent + amount ≤ lifetime_cap`; **root path**: `verify_root_assertion` with action 0x05 over `borsh(TransferBody)` built from the passed accounts; `amount ≤ policy.large_threshold[mint].per_tx` else `CapExceeded` (→ Phase 1B `queue`), and **the same `buckets::debit`** against `policy.caps` (root is bounded like a session — spec §5.2.4). Destination for SPL must not be a vault-owned token account (`destination.owner != smart_account`) — spec §5.1. SOL transfer via `invoke_signed(system_instruction::transfer(vault, dest))`? The vault PDA is a data account (Anchor `#[account]`), so use direct lamport arithmetic with checked ops only: `let src = smart_account.to_account_info(); let new_src = src.lamports().checked_sub(amount).ok_or(Overflow)?; require!(new_src >= Rent::get()?.minimum_balance(SmartAccount::LEN), CapExceeded); let new_dst = dest.lamports().checked_add(amount).ok_or(Overflow)?; **src.try_borrow_mut_lamports()? = new_src; **dest.try_borrow_mut_lamports()? = new_dst;` and reject `dest.key() == smart_account.key()` (`InvalidAccountData`). SPL via `token::transfer` CPI with `signer_seeds = [ACCOUNT_SEED, owner_seed, [bump]]`; ATA creation is the client's job (outer payer), never the vault.

- [ ] Tests (RED): `session_sol_transfer_within_caps`, `session_sol_over_per_tx_rejected`, `session_day_cap_across_two_txs`, `two_sessions_share_account_day_cap`, `session_expired_rejected`, `session_wrong_generation_rejected` (bump generation via `set_account` for now), `session_without_transfer_op_rejected`, `session_spl_transfer_ok` (mint fixture; balances move), `spl_to_vault_owned_ata_rejected`, `sol_transfer_cannot_breach_rent_floor`, `root_transfer_within_threshold_debits_buckets` (then a session transfer that would exceed the day cap fails — proves shared buckets), `root_transfer_over_threshold_rejected`, `frozen_blocks_transfer`, `root_transfer_with_substituted_destination_rejected` (same assertion, different destination account ⇒ InvalidRootAssertion), `transfer_to_self_rejected`, `destination_lamport_overflow_rejected` (dest preloaded near u64::MAX via set_account), `rolling_30d_cap_enforced_end_to_end` (advance `svm` clock with `warp_to_slot`/set Clock sysvar via `svm.set_sysvar`), plus **CU measurement**: print CU for session SOL, session SPL, root SOL; record in `docs/program/PHASE1A-MEASUREMENTS.md`.
- [ ] Implement, run, commit `feat(program): transfer with account-wide buckets (session + bounded root)`.

---

### Task 8: TS mirror of the root transcript/challenge + IDL export

**Files:** `packages/core/src/webauthn/transcript.ts`, `packages/core/test/transcript.test.ts`, `packages/core/src/index.ts` (export), `packages/core/idl/warden.json` (from `anchor build`), `packages/core/package.json` (add `@noble/hashes`).

**Interfaces:** `transcriptHash(input: { clusterTag: Uint8Array; programId: Uint8Array; account: Uint8Array; generation: bigint; policyVersion: number; rootNonce: bigint; expiryTs: bigint; actionHash: Uint8Array }): Uint8Array` (keccak_256), `actionHash(opType: number, borshArgs: Uint8Array): Uint8Array`, `challengeB64Url(hash: Uint8Array): string` (no padding). Test: pin the SAME test vector as the Rust `transcript.rs` test (copy the hex from the Rust test output into both tests) — cross-language parity is the point.
- [ ] Write test with the pinned vector (RED) → implement → `pnpm test` green → copy IDL → commit `feat(core): transcript/challenge mirror + IDL`.

---

### Task 9: Measurements + Codex milestone review + handoff to 1B

**Files:** `docs/program/PHASE1A-MEASUREMENTS.md` (finalize: root_verify CU, transfer CU ×3, grant tx bytes, `.so` size, LEN of both accounts), `docs/superpowers/specs/…` §12 (append "Phase 1A measured:" line), `docs/spikes/DECISION.md` O10 (record UV-mandatory decision as implemented).
- [ ] Run the full gate: `./.claude/test-gate.sh` → exit 0; record command + SHA in the measurements doc.
- [ ] Codex milestone review (`mcp__codex__codex`, `gpt-5.6-sol` @ `xhigh`, on-request, no sandbox param, read-only, no subagents): "Security review of programs/warden at <SHA>: root_verify (replay, binding, scanner), bucket accounting (rollover, ring, overflow), transfer (rent floor, vault-owned dest, shared buckets, root bound), session checks. Rank findings; end SHIP-1A / REVISE." Fix findings via the SDD loop; record thread ids in the measurements doc.
- [ ] Also edit spec §4: "genesis_hash" → "cluster_tag (client-attested domain separator, stored at creation)", and record in DECISION.md that **O11 is NOT closed by 1A** — the 1B plan MUST carry, verbatim, this pre-ship gate: real inner CPI through `execute`, mutation rejection exercised through a CPI, `is_native` compared, corrected account metrics, and the measured stage cap.
- [ ] Commit `docs(program): Phase 1A measurements + Codex milestone`; then write the Phase 1B plan (`execute` + adapter registry + stage, `swap`, `queue`/pending/timelock + policy lattice, guardians/recovery/guardian-freeze, `set_policy`) with writing-plans, using 1A's measured CU/bytes as constraints.

---

## Self-review (at authoring)

- **Spec coverage (1A scope):** §4 root verify (T3), rpIdHash/origin per-account (T4), transcript/nonce/expiry (T3), sessions + ceilings + ops mask + generation (T5), buckets day/30d/lifetime shared by root (T2, T7), transfer rules incl. rent floor + vault-owned dest (T7), root freeze/unfreeze (T6), root payload budget (T5 test), UV-mandatory decision O10 (T3/T9), TS parity (T8). Deferred to 1B: `execute`/`swap`/stage/adapters, `queue`/pending/policy lattice/`set_policy`, guardians/recovery/guardian freeze, `is_native`+conservation (with `execute`).
- **Placeholders:** none; where the plan defers a test to a later task it names the task.
- **Codex plan review (thread 01a0152a, terra@high): REVISE → applied:** forward-compatible layouts with reserved bytes + guardians/registry pubkeys + `frozen_at` + `cluster_tag` + `program_allowlist_id` from Task 2 (no realloc in 1B); `rp_id_hash == SHA-256(origin)` enforced at create with canonical-origin rules; MAX_CAPS_PER_GRANT reduced to 2 with a real-tx byte assertion and an enforced reject at 3; `TransferBody` binds destination; checked lamport ops; extra adversarial tests (precompile ordering/decoys, re-grant semantics, generation on recreate, negative timestamps, midnight/ring boundaries); O11 carried verbatim into 1B's pre-ship gate.
- **Type consistency:** `RootArgs`, `verify_root_assertion`, `MintCap`, `MintBuckets`, `buckets::debit`, `SessionKey` field names, op-type bytes (0x00 rotate, 0x01 grant, 0x02 revoke, 0x03 freeze, 0x04 unfreeze, 0x05 transfer) used identically across tasks; `frozen_at` added in T6 to the T2 layout (LEN test updated there).
- **Known uncertainties named:** Anchor 1.1.2 + solana-program 3 build path (T1 fallback), genesis hash unavailable on-chain → stored `cluster_tag` (T3 ruling, documented), LiteSVM clock manipulation API (T7 uses `set_sysvar`/`warp_to_slot` — implementer verifies which exists in 0.12).
