//! Conservation — the load-bearing control of `execute` and `swap`.
//!
//! Three pure steps, deliberately kept apart so each can be unit-tested with
//! no SVM and no CPI in the loop:
//!
//! 1. [`snapshot`] — a **pure decode** of every account the instruction can
//!    touch (spec §5.2 rule 2: *every* `remaining_account`, writable or not,
//!    plus every required Mint; the SmartAccount PDA's own lamports travel
//!    separately as two `u64`s). It never decides who owns what and it never
//!    fails on malformed account data — a token-program-owned account that
//!    does not parse comes back with `token: None` and
//!    `token_parse_failed: true`, so the *comparison* can reject it if and
//!    only if it mattered.
//! 2. [`compare_and_account`] — the field-by-field before/after comparison
//!    (spec §5.2 rules 2, 2a, 3, 5) and the value accounting (rules 4, 4a).
//! 3. [`Outflow`] — what leaves the vault, per mint plus one merged SOL
//!    number, ready for `buckets::debit`.
//!
//! ## Why before/after, and not after-only
//!
//! Spec §5.2 rule 2, and `SWIG-ACC-C1` / `LZR-ACC-C2` in
//! `docs/security/PRIOR-ART-FINDINGS.md`. An after-only inspection passes a
//! *pre-existing* delegate that the CPI **clears**, and silently skips an
//! account that became unparseable. Both are checked here in both directions:
//! a delegate must be `None` **before** as well as after, and a vault-owned
//! token account that stops parsing is a reject, never a skip.
//!
//! ## Why the runtime program owner is compared first
//!
//! `SWIG-ACC-C1`: Swig compared end-state *values* (balance, mint, the token
//! account's `owner` field) but never the account's actual **program owner**,
//! so transfer-out → close → reopen under an attacker program that fakes the
//! SPL byte layout passed every check. Here, `Snap::owner_program` is captured
//! before any layout-dependent decode, `snapshot` only ever decodes token /
//! mint layouts for accounts owned by SPL Token or Token-2022, and
//! `owner_program` is part of the byte-identical set.
//!
//! ## There is deliberately NO `gross_turnover` field on [`Outflow`]
//!
//! It was proposed and **withdrawn** (research §3(a).6; spec §5.2 rule 4b,
//! §5.3). Two independent reasons, both permanent:
//!
//! - **No precedent to copy.** LazorKit's "gross" accounting is *SOL summed
//!   between outer CPIs*; its token per-transaction limit is an ordinary
//!   before/after **net** diff. There is no prior art for token gross-turnover
//!   accounting.
//! - **No snapshot granularity can observe it.** A single CPI that moves 100
//!   SOL of vault value out and 99.5 SOL back *within its own execution*
//!   presents a net delta of 0.5 SOL. Per-inner-instruction snapshots do not
//!   help: the round trip completes below the boundary at which the caller
//!   regains control. This is a **semantic boundary of the whole approach**,
//!   stated in §5.3 beside "cannot verify external program logic".
//!
//! What 1B enforces instead is Task 6's adapter-decoded `max_in` (parsed out
//! of the inner instruction's **own data**, never inferred from balances) plus
//! a pinned source ATA. **Do not re-add a gross field here** — it would be a
//! number the program cannot measure, which is worse than an honest gap.
//! Recorded again in `docs/program/PHASE1B-MEASUREMENTS.md`.

use anchor_lang::prelude::*;

pub mod accounting;
pub mod compare;
pub mod snapshot;

#[cfg(test)]
mod tests;

pub use accounting::Outflow;
pub use compare::{compare_and_account, reject_unsupported_writable_owners};
pub use snapshot::{snapshot, snapshot_one};

/// The fields of an SPL Token / Token-2022 token account that conservation
/// rules on. Every one of them except `amount` must be byte-identical before
/// and after the inner CPIs (spec §5.2 rule 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenSnap {
    pub mint: Pubkey,
    /// The **token-level** authority. `owner == vault` is what makes an
    /// account "the vault's" for every rule in this module; it is not the same
    /// thing as `Snap::owner_program`, which is the runtime owner (the token
    /// program).
    pub owner: Pubkey,
    pub amount: u64,
    pub delegate: Option<Pubkey>,
    pub delegated_amount: u64,
    pub close_authority: Option<Pubkey>,
    pub state: u8,
    pub is_native: Option<u64>,
    /// keccak-256 over the Token-2022 TLV tail (`data[166..]`), or `[0; 32]`
    /// when there is no tail. For **token accounts** a whole-tail hash is the
    /// right control: no legitimate CPI mutates a token account's extension
    /// bytes. (Mints are the opposite case — see [`MintSnap::tlv_hash`].)
    pub tlv_hash: [u8; 32],
    /// `PROGRAM_SPL` (0) or `PROGRAM_T22` (1).
    pub program: u8,
}

/// The fields of a Mint that conservation rules on (spec §5.2 rule 2a).
///
/// Snapshotting only token accounts leaves the *mint* — where `mint_authority`,
/// `freeze_authority` and, on Token-2022, the fee authorities live — entirely
/// unobserved, so a CPI that hands itself the mint authority of a mint the
/// vault holds would pass every rule-2 check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintSnap {
    pub mint_authority: Option<Pubkey>,
    pub freeze_authority: Option<Pubkey>,
    /// Snapshotted and carried for the intent view, and **deliberately not
    /// compared**: spec §5.2 rule 2a is explicit that `supply` is not an
    /// authority field, because a legitimate mint/burn through an allow-listed
    /// adapter (an LP mint on an add-liquidity route, say) changes it. A
    /// supply change on its own is not a reject.
    pub supply: u64,
    pub decimals: u8,
    pub is_initialized: bool,
    /// `TransferFeeConfig.transfer_fee_config_authority`, extracted **by TLV
    /// type and offset**, not by hashing the tail — see [`Self::tlv_hash`].
    pub transfer_fee_config_authority: Option<Pubkey>,
    /// `TransferFeeConfig.withdraw_withheld_authority`, same extraction.
    pub withdraw_withheld_authority: Option<Pubkey>,
    /// `PermanentDelegate.delegate` (Token-2022 extension type 12), same
    /// extraction — a single `OptionalNonZeroPubkey`.
    ///
    /// WRDF-0105 round 3: this is an **authority** field, not a curiosity. The
    /// permanent delegate may transfer or burn from *every* token account of
    /// the mint, forever, without the holder's consent — the strongest of the
    /// five roles. Before round 3 `scan_extensions` recognised the extension
    /// only by setting `DANGER_PERMANENT_DELEGATE` and threw this pubkey away,
    /// which left it invisible to [`Self::holds_authority`].
    pub permanent_delegate: Option<Pubkey>,
    /// `max(older_transfer_fee.maximum_fee, newer_transfer_fee.maximum_fee)`.
    ///
    /// Recorded for Phase 1C's `delta ≥ amount − max_fee` inequality only; 1B
    /// rejects transfer-fee mints outright, so nothing reads it yet. **1C must
    /// re-derive it per epoch** (`TransferFeeConfig::get_epoch_fee`: the newer
    /// fee applies once `current_epoch >= newer.epoch`) rather than take this
    /// max, which is the conservative-for-*liveness* choice, not the
    /// conservative-for-*safety* one.
    pub max_fee: u64,
    /// keccak-256 over the mint's TLV tail. **Captured, never compared.**
    ///
    /// Spec §5.2 rule 2a is explicit: a whole-tail hash is NOT sufficient as a
    /// mint's authority control and must not be used as one. A legitimate
    /// `transfer_fee` accrual mutates `withheld_amount` **inside the same
    /// tail**, so a tail-hash comparison would reject the happy path while the
    /// field extraction above gives the true answer. The hash is kept only as
    /// a diagnostic / future-proofing hook. `tlv_hash_is_never_compared_for_mints`
    /// is the regression test that keeps a later reader from "fixing" this.
    pub tlv_hash: [u8; 32],
    /// Bit flags over `DANGER_*` (spec §5.2 rule 5).
    pub dangerous_ext: u8,
    /// The tail carries an extension type the scan does not explicitly model
    /// (WRDF-0012). Several such extensions hold REASSIGNABLE authorities
    /// (`MintCloseAuthority`, `InterestBearingConfig`, `MetadataPointer`,
    /// group/member pointers, `ScaledUiAmountConfig`, `PausableConfig`) that
    /// no compared field would see change — so in 1B a required mint carrying
    /// one is rejected outright. Fail closed now; 1C may widen with per-type
    /// authority extraction.
    pub has_unrecognized_ext: bool,
    /// `PROGRAM_SPL` (0) or `PROGRAM_T22` (1).
    pub program: u8,
}

impl MintSnap {
    /// Does `key` hold **any** authority on this mint?
    ///
    /// Round 1 (Codex C1): this is what makes a mint the vault's own concern
    /// independently of whether the vault happens to hold a token account of
    /// it.
    ///
    /// **All FIVE modelled roles**, and adding a sixth belongs here and nowhere
    /// else — every caller (`prescan_vault_mints`, `execute`'s
    /// vault-controlled-mint gate) goes through this one predicate precisely so
    /// a role cannot be dropped by a hand-rolled subset again:
    ///
    /// 1. `mint_authority` — classic SPL.
    /// 2. `freeze_authority` — classic SPL.
    /// 3. `transfer_fee_config_authority` — Token-2022 `TransferFeeConfig` TLV.
    /// 4. `withdraw_withheld_authority` — Token-2022 `TransferFeeConfig` TLV.
    /// 5. `permanent_delegate` — Token-2022 `PermanentDelegate` TLV.
    ///
    /// WRDF-0105 round 3 added (5). It was the third time this finding was
    /// raised, and the second time a partial fix shipped: round 1 modelled
    /// roles 1–2, round 2 added 3–4 by switching to this predicate, and both
    /// missed the permanent delegate — the *strongest* role of the five, since
    /// it moves or burns tokens from any account of the mint at will. The
    /// demonstrated hole was a Token-2022 `TransferChecked` (tag 12, which
    /// `classify_spl_token_op` maps to `Other`, so `deny_scan` never names it)
    /// taking the mint READ-ONLY — so `prescan_vault_mints`'s writable-only
    /// danger rule did not fire — between two THIRD-PARTY token accounts under
    /// the PDA's propagated signer. Conservation skips both accounts, `outflow`
    /// is zero, and no bucket is debited.
    pub fn holds_authority(&self, key: &Pubkey) -> bool {
        let k = Some(*key);
        self.mint_authority == k
            || self.freeze_authority == k
            || self.transfer_fee_config_authority == k
            || self.withdraw_withheld_authority == k
            || self.permanent_delegate == k
    }
}

/// One account's before- (or after-) state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snap {
    pub key: Pubkey,
    /// `lamports != 0 || data_len != 0`. A closed account is zero-lamport,
    /// zero-length and owned by the system program, so this is false for it;
    /// a live account is rent-exempt, so it is true.
    pub exists: bool,
    /// The **runtime** owner (the program that may write this account) — the
    /// field `SWIG-ACC-C1` was missing.
    pub owner_program: Pubkey,
    pub lamports: u64,
    pub data_len: usize,
    pub token: Option<TokenSnap>,
    pub mint: Option<MintSnap>,
    /// The account is owned by SPL Token or Token-2022 but decoded as neither
    /// a token account nor a mint (wrong length, a bad `COption` tag, a bad
    /// `AccountType` byte, a malformed TLV tail). `snapshot` never fails on
    /// this — a dApp is free to pass a token multisig — but the comparison
    /// rejects the account if it was a vault-owned token account BEFORE.
    pub token_parse_failed: bool,
    pub is_writable: bool,
}

/// A close the **payload decoder** proved legal and is telling the comparison
/// about (spec §5.2 rule 1a, the vault-sweep exception).
///
/// Decoded from **direct** SPL / Token-2022 `CloseAccount` inner instructions
/// of the `execute` payload only — a close nested inside another program's CPI
/// is invisible to the decoder and therefore is *not* exempt. Nothing
/// downstream may INFER a close from a disappearance: `compare_and_account`
/// must be **told**, or it rejects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseIntent {
    pub account: Pubkey,
    /// The rent destination, decoded from the instruction's account list
    /// (`[0] account, [1] destination, [2] authority`).
    pub destination: Pubkey,
    /// The token balance the decoder saw in the BEFORE snapshot. Re-checked
    /// against the snapshot here: a decoder/comparison desync must fail loudly.
    pub amount_before: u64,
}
