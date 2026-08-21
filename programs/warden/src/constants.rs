use anchor_lang::prelude::Pubkey;

pub const ACCOUNT_SEED: &[u8] = b"account";
pub const SESSION_SEED: &[u8] = b"session";
pub const REGISTRY_SEED: &[u8] = b"registry";
/// PDA seed prefix for a `Stage` (Task 4): `["stage", account, creator, hash]`.
pub const STAGE_SEED: &[u8] = b"stage";
/// Largest payload a single `Stage` may hold (spec §5.1). A staged payload is
/// instruction-data relief only — the account list still rides in the `execute`
/// transaction — so 4 KiB is comfortably above any real compiled payload while
/// bounding the PDA's rent and the `stage_open` allocation.
pub const STAGE_MAX_DATA_LEN: usize = 4096;
/// Longest a `Stage` may live from `stage_open` (spec §5.1). Bounds how long an
/// abandoned or GC'd stage sits before anyone may close it (Certora H-01
/// lifecycle GC). The ND-SQD3-LO-01 squat itself is closed by binding the
/// `creator` into the PDA seeds, not by this bound.
pub const STAGE_MAX_TTL_SECS: i64 = 3600;
/// The client contract for the largest payload a single `stage_chunk`
/// transaction may carry under the fixed 3-account layout (spec §5.1).
///
/// This is the **v0 (`VersionedTransaction`) cap = 977 B** — the format the
/// production client compiles (`compileToV0Message`), which carries a version
/// byte + an address-table-lookups length that a legacy transaction does not, so
/// it is 2 B larger on the wire and thus 2 B stricter. It is the CONSERVATIVE of
/// the two formats (legacy fits 979), so a client that splits a payload into
/// `ceil(len / STAGE_CHUNK_PAYLOAD_CAP)` chunks lands under either serializer.
/// MEASURED against the built program and pinned exactly by
/// `stage::stage_chunk_payload_cap_is_measured` (the v0 tx at this cap is exactly
/// 1,232 B; one more byte overflows) — a wire contract, not a soft estimate.
pub const STAGE_CHUNK_PAYLOAD_CAP: usize = 977;
pub const MAX_CLIENT_DATA_LEN: usize = 512;
pub const MAX_ROOT_EXPIRY_SECS: i64 = 600;
/// Maximum age, **in slots**, of a root passkey ceremony (spec §4, rev 8).
///
/// `Clock::unix_timestamp` is a stake-weighted *estimate* that can drift from
/// wall clock by minutes, so `expiry_ts` alone is not the freshness control.
/// `slot` is the consensus-native clock every peer anchors to, and the
/// transcript therefore carries a client-signed `signed_slot`. The rule is one
/// chained inequality, and both halves are load-bearing:
///
/// ```text
/// signed_slot <= Clock::slot < signed_slot + MAX_ROOT_SLOT_AGE
/// ```
///
/// - the left half rejects a **future** `signed_slot` outright
///   (`RootSlotInFuture`) — without it a client buys itself an arbitrarily
///   long window simply by signing ahead;
/// - the right half is **strict** (`RootSlotStale`): an age of exactly
///   `MAX_ROOT_SLOT_AGE` is rejected, `MAX_ROOT_SLOT_AGE - 1` is accepted.
///
/// 150 slots is ≈60 s at 400 ms/slot — the same order as LazorKit (150) and
/// Swig (60), and 10–25× tighter than the 600 s `MAX_ROOT_EXPIRY_SECS`
/// window Phase 1A relied on alone. `expiry_ts` stays as the **secondary**
/// bound (spec §5.1's two-clock rule): its long tail exists only for Phase
/// 1C's deferred/timelocked flow, and on the default path both checks must
/// pass.
pub const MAX_ROOT_SLOT_AGE: u64 = 150;
pub const MAX_MINT_CAPS: usize = 8;
pub const MAX_SESSIONS_LISTED: usize = 0; // sessions are separate PDAs; no list on the account
pub const DAY_SECS: i64 = 86_400;
pub const RING_DAYS: usize = 30;
/// Cap on how many distinct mints `create_account` may configure in a single
/// instruction — **a measured packet bound, not a design preference**.
///
/// A `create_account` transaction must fit Solana's 1,232 B packet. Since
/// Phase 1B Task 2b it also carries a proof-of-possession ceremony: a 182 B
/// secp256r1 precompile instruction, a 226 B `RootArgs`, and the Instructions
/// sysvar account — **+477 B** over the Phase-1A shape. Measured on the real
/// wire by `create_pop::create_with_pop_transaction_sizes_are_measured_and_bounded`
/// (which asserts this constant equals the largest count that actually fits,
/// so it can never drift from the measurement):
///
/// | mints | tx bytes | fits 1,232 B |
/// | ----: | -------: | --- |
/// |     0 |      949 | yes |
/// |     1 |    1,117 | yes |
/// |     2 |    1,285 | **no** (53 B over) |
/// |     4 |    1,621 | no |
///
/// Each mint costs 168 B (cap + session ceiling + large threshold, 56 B each).
/// **Phase 1A allowed 4; the ceremony costs three of them.** That is the price
/// of an unsquattable address, and it is the right trade: an account whose
/// caps are configured one mint at a time is a nuisance, an account someone
/// else's passkey can own is a loss. Mints 2..8 are added after creation by a
/// root-authorized `set_policy` (Phase 1C) — never by raising this constant.
///
/// The 2-mint shape misses by only 53 B, so a future wire trim (the redundant
/// `rp_id_hash` argument is 32 B of it) could restore it. Raise this constant
/// only against a fresh measurement; the test above will refuse a guess.
///
/// Independent of `MAX_MINT_CAPS`, which is the on-chain `Policy`'s fixed
/// array width and stays 8. `PolicyArgs::expand` is bounded by *that* — this
/// bound is enforced in `create_account`'s handler, where the packet is.
pub const MAX_MINTS_AT_CREATE: usize = 1;

/// Cap on how many `MintCap`s a single `grant_session` may carry (Task 5).
///
/// A root-authorized instruction shares its 1,232 B transaction with the
/// secp256r1 precompile instruction (182 B of data, measured) and with
/// `RootArgs`, which is **226 B** on the wire for a canonical Chrome-shaped
/// ceremony: 1 B `precompile_ix_index` + (4 B borsh length + 37 B)
/// `authenticatorData` + (4 B borsh length + 164 B) `clientDataJSON` + 8 B
/// `expiry_ts` + 8 B `signed_slot` = 226 B. That leaves only a few hundred
/// bytes for the instruction's own arguments. Each `MintCap` is 56 B on the
/// wire and each parallel lifetime cap another 8 B, so every extra cap costs
/// 64 B. The plan (rev 2) estimated 4 caps would NOT fit and fixed the limit
/// at 2; the measured 2-cap grant transaction is **984 B** (see
/// docs/program/PHASE1A-MEASUREMENTS.md), asserted by
/// `sessions::grant_tx_fits_1232_bytes_with_2_caps`.
///
/// Both figures are post-Phase-1B-Task-0: `RootArgs` was 218 B and the grant
/// transaction 976 B before `signed_slot` added 8 B to every root path. (The
/// 944 B this comment carried before that was older still — it predated the
/// `prior_authority_hash` field added by the 1A milestone review.)
///
/// Independent of `MAX_MINT_CAPS` (8), which is the `SessionKey`'s fixed slot
/// count and stays 8: a session accumulates more than
/// `MAX_CAPS_PER_GRANT` mints across *several* grants, because `grant_session`
/// merges by mint into the existing slots rather than replacing them.
pub const MAX_CAPS_PER_GRANT: usize = 2;

/// The only `SessionKey::kind` Phase 1A supports: an Ed25519 delegate signer.
pub const SESSION_KIND_ED25519: u8 = 0;

// ---------------------------------------------------------------------------
// Token constants (Task 7, `transfer`)
// ---------------------------------------------------------------------------

/// SPL Token program id (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`) — the
/// ONLY token program Phase 1A's `transfer` will CPI into. Token-2022
/// (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`) lands in Phase 1B, where
/// the transfer-fee / transfer-hook / confidential-transfer extensions each
/// need their own rule before the vault may move a balance under them.
///
/// Hardcoded rather than imported: `spl-token` (v7) resolves
/// `solana-program 2.3.x`, whose `Pubkey` is a different, non-interconvertible
/// type from the `solana-program 3.x` one Anchor 1.1.2 uses — the same
/// finding spike 3b recorded. `transfer::token_program_id_matches_spl_token`
/// (a test, with the real `spl-token` crate as a dev-dependency) pins this
/// literal against `spl_token::ID`.
pub const SPL_TOKEN_ID: Pubkey = Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

/// SPL Token-2022 program id — declared only so `transfer` can reject it with
/// an honest error instead of "not the token program".
pub const SPL_TOKEN_2022_ID: Pubkey = Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Program ids for the default registry adapters (Task 3). The System program's
/// id is the all-zeros pubkey — a real key, not an "unused" sentinel (see
/// `state::registry::find_entry`).
pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);
pub const MEMO_PROGRAM_ID: Pubkey = Pubkey::from_str_const("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
pub const ATA_PROGRAM_ID: Pubkey = Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
/// Jupiter aggregator v6 — the pinned swap program (Task 6 verifies its route
/// discriminators against the IDL).
pub const JUPITER_V6_ID: Pubkey = Pubkey::from_str_const("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
/// Test-only program ids (mirrored from `programs/test-mutator` and
/// `programs/test-jup-mock`), used only by the registry's test list.
pub const TEST_MUTATOR_ID: Pubkey = Pubkey::from_str_const("An3yCfK4dXet5wEHRYT23gyS1CJbeGD5E2enchQLo49W");
pub const TEST_JUP_MOCK_ID: Pubkey = Pubkey::from_str_const("3dxuCX7mnVEse9PD1WSDdXYXgwFpECkJTfwsXBbPbzWU");

/// Wrapped-SOL mint (`So11111111111111111111111111111111111111112`) — the key
/// a native-SOL transfer looks its caps up under.
///
/// `Policy.caps` / `SessionKey.caps` are keyed by mint and `Pubkey::default()`
/// is `buckets::find_cap`'s unused-slot sentinel, so native SOL needs *some*
/// real key: the native mint is the conventional one (it is what every Solana
/// client already uses to mean "SOL" in a mint-keyed table). Note this is the
/// **cap lookup key only** — a native transfer moves lamports directly and
/// never touches the wrapped-SOL mint account.
pub const NATIVE_MINT: Pubkey = Pubkey::from_str_const("So11111111111111111111111111111111111111112");

/// Token-2022's DISTINCT native mint (`spl-token-2022 7.0.0`,
/// `src/native_mint.rs: declare_id!("9pan…")` — verified against the vendored
/// crate, WRDF-0008). Conservation must treat a wrapped-SOL account under
/// either program as SOL: `by_mint` may never carry a native mint key, or one
/// SOL movement would straddle two cap/bucket keys.
pub const NATIVE_MINT_2022: Pubkey =
    Pubkey::from_str_const("9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP");

/// Fixed-layout length of an SPL Token `Account`.
pub const TOKEN_ACCOUNT_LEN: usize = 165;
/// `spl_token::state::AccountState::Initialized` discriminant.
pub const TOKEN_STATE_INITIALIZED: u8 = 1;
/// `spl_token::instruction::TokenInstruction::Transfer` tag.
pub const TOKEN_IX_TRANSFER: u8 = 3;

// The fixed deny-list tags (spec §5.2 rule 1a). SPL Token AND Token-2022 share
// the same `TokenInstruction` tag byte for each of these. Re-derived from the
// pinned `spl-token` crate's `TokenInstruction` encoding and pinned exactly by
// `payload::tests::deny_list_tags_match_spl_token` — a wrong tag here is a
// silent hole, not a compile error, so it is asserted against the crate.
/// `TokenInstruction::Approve` — delegates spending authority. Denied.
pub const TOKEN_IX_APPROVE: u8 = 4;
/// `TokenInstruction::Revoke` — clears a delegate. Denied (a session must not
/// touch delegation at all).
pub const TOKEN_IX_REVOKE: u8 = 5;
/// `TokenInstruction::SetAuthority` — reassigns owner/close/mint/freeze
/// authority. Denied.
pub const TOKEN_IX_SET_AUTHORITY: u8 = 6;
/// `TokenInstruction::CloseAccount` — reclaims rent. NOT unconditionally denied:
/// permitted only as the vault-sweep exception the handler proves (spec §5.2
/// rule 1a), otherwise denied.
pub const TOKEN_IX_CLOSE_ACCOUNT: u8 = 9;
/// `TokenInstruction::ApproveChecked` — decimal-checked `Approve`. Denied.
pub const TOKEN_IX_APPROVE_CHECKED: u8 = 13;

// ---------------------------------------------------------------------------
// Conservation (Phase 1B Task 1) — SPL Token / Token-2022 layout constants.
//
// Every value below was re-derived from the vendored crate sources at the
// versions this repo resolves, NOT from memory:
//   - `spl-token 9` (dev-dependency, `state.rs`): `Account::LEN == 165`,
//     `Mint::LEN == 82`, `Multisig::LEN == 355`.
//   - `spl-token-2022 7.0.0` (`~/.cargo/registry/.../src/extension/mod.rs`):
//     `BASE_ACCOUNT_LENGTH == Account::LEN == 165`; `type_and_tlv_indices`
//     puts the `AccountType` byte at absolute offset 165 and starts the TLV
//     tail at absolute offset 166 for BOTH mints and token accounts (for a
//     mint, bytes 82..165 are zero padding that the crate checks); a TLV entry
//     is `type: u16 LE ‖ length: u16 LE ‖ value[length]`; `AccountType` is
//     `Uninitialized = 0, Mint = 1, Account = 2`.
// `conservation::snapshot`'s unit tests pin the ones a fixture can express.
// ---------------------------------------------------------------------------

/// Fixed-layout length of an SPL Token `Mint` (`spl_token::state::Mint::LEN`).
pub const MINT_ACCOUNT_LEN: usize = 82;
/// `spl_token::state::Multisig::LEN`. A multisig is owned by the token program
/// and is neither a mint nor a token account; Token-2022 refuses to treat an
/// account of exactly this length as extensible, and so do we.
pub const TOKEN_MULTISIG_LEN: usize = 355;
/// Absolute offset of the Token-2022 `AccountType` discriminator byte, for
/// both mints and token accounts (`BASE_ACCOUNT_LENGTH`).
pub const T22_ACCOUNT_TYPE_OFFSET: usize = 165;
/// Absolute offset at which the Token-2022 TLV tail begins.
pub const T22_TLV_OFFSET: usize = 166;
/// `spl_token_2022::extension::AccountType::Mint`.
pub const T22_ACCOUNT_TYPE_MINT: u8 = 1;
/// `spl_token_2022::extension::AccountType::Account`.
pub const T22_ACCOUNT_TYPE_ACCOUNT: u8 = 2;
/// `spl_token::state::AccountState::Frozen` discriminant.
pub const TOKEN_STATE_FROZEN: u8 = 2;

/// `TokenSnap::program` / `MintSnap::program` tag: classic SPL Token.
pub const PROGRAM_SPL: u8 = 0;
/// `TokenSnap::program` / `MintSnap::program` tag: SPL Token-2022.
pub const PROGRAM_T22: u8 = 1;

// `spl_token_2022::extension::ExtensionType` discriminants (u16 LE in the TLV
// `type` field). Only the ones conservation rules on are named.
/// `ExtensionType::Uninitialized` — a zero type terminates the TLV walk;
/// the crate writes nothing after it.
pub const EXT_UNINITIALIZED: u16 = 0;
/// `ExtensionType::TransferFeeConfig` (mint).
pub const EXT_TRANSFER_FEE_CONFIG: u16 = 1;
/// `ExtensionType::ConfidentialTransferMint`.
pub const EXT_CONFIDENTIAL_TRANSFER_MINT: u16 = 4;
/// `ExtensionType::ConfidentialTransferAccount`.
pub const EXT_CONFIDENTIAL_TRANSFER_ACCOUNT: u16 = 5;
/// `ExtensionType::PermanentDelegate` (mint).
pub const EXT_PERMANENT_DELEGATE: u16 = 12;
/// `ExtensionType::TransferHook` (mint).
pub const EXT_TRANSFER_HOOK: u16 = 14;
/// `ExtensionType::ConfidentialTransferFeeConfig`.
pub const EXT_CONFIDENTIAL_TRANSFER_FEE_CONFIG: u16 = 16;
/// `ExtensionType::ConfidentialTransferFeeAmount`.
pub const EXT_CONFIDENTIAL_TRANSFER_FEE_AMOUNT: u16 = 17;
/// `ExtensionType::ConfidentialMintBurn`.
pub const EXT_CONFIDENTIAL_MINT_BURN: u16 = 24;

// `MintSnap::dangerous_ext` bit flags (spec §5.2 rule 5). All four reject in
// 1B; the bits are separate so 1C can lift exactly one of them (transfer fee)
// without touching the other three, which are never allow-listable.
/// `TransferFeeConfig` (1). Class (ii): allowed in 1C with an inequality,
/// rejected in 1B because the allow-list machinery is 1C.
pub const DANGER_TRANSFER_FEE: u8 = 1 << 0;
/// Confidential-transfer family. Class (iii): a permanent non-goal.
///
/// The spec names extensions **4/5**. This bit deliberately covers a **wider**
/// set — 4, 5, 16 (`ConfidentialTransferFeeConfig`), 17
/// (`ConfidentialTransferFeeAmount`) and 24 (`ConfidentialMintBurn`) — because
/// every one of them hides an amount behind a ZK ciphertext, which is the
/// exact property that makes conservation *unverifiable* rather than merely
/// hard. Widening a permanent deny can only reject more, never allow more, so
/// it cannot open a hole; it is recorded here (and in the Task 1 report) as a
/// deliberate tightening beyond the spec's literal enumeration.
pub const DANGER_CONFIDENTIAL: u8 = 1 << 1;
/// `PermanentDelegate` (12). Class (i): never allow-listable.
pub const DANGER_PERMANENT_DELEGATE: u8 = 1 << 2;
/// `TransferHook` (14). Class (i): never allow-listable.
pub const DANGER_TRANSFER_HOOK: u8 = 1 << 3;
/// The class-(i)/(iii) bits: rejected with `Token2022ExtensionRejected`, and
/// no policy path ever enables them. `DANGER_TRANSFER_FEE` is deliberately
/// NOT in this mask — it gets its own error so 1C can lift it alone.
pub const DANGER_NEVER_ALLOWLISTABLE: u8 =
    DANGER_CONFIDENTIAL | DANGER_PERMANENT_DELEGATE | DANGER_TRANSFER_HOOK;
