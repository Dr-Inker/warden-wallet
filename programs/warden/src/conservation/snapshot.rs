//! Pure decode of an account's bytes into a [`Snap`] (spec §5.2 rules 2, 2a).
//!
//! ## Two rules that shape every function here
//!
//! 1. **Nothing in this file decides ownership.** It reads bytes. Every
//!    "is this the vault's?" question lives in [`super::compare`], so there is
//!    exactly one place that defines what a vault account is.
//! 2. **A malformed account is not an instruction failure.** A dApp may pass a
//!    token multisig, an uninitialized buffer, or an account owned by a program
//!    that fakes the SPL layout. Failing the whole instruction on any of those
//!    would be a liveness footgun. So the parsers return `None` and the caller
//!    records `token_parse_failed`; the comparison turns that into a reject
//!    **only** when the account was a vault-owned token account BEFORE.
//!
//! ## Layout, re-derived from source (not from memory)
//!
//! `spl-token 9` `state.rs`, and `spl-token-2022 7.0.0`
//! `src/extension/mod.rs` (`type_and_tlv_indices`, `unpack_tlv_data`,
//! `get_tlv_indices`, `check_min_len_and_not_multisig`,
//! `src/extension/transfer_fee/mod.rs`):
//!
//! ```text
//! token account (165 B base)
//!   mint             0..32
//!   owner           32..64
//!   amount          64..72    u64 LE
//!   delegate        72..108   COption<Pubkey>  (u32 LE tag @72, key @76)
//!   state          108        u8
//!   is_native      109..121   COption<u64>     (u32 LE tag @109, val @113)
//!   delegated_amt  121..129   u64 LE
//!   close_auth     129..165   COption<Pubkey>  (u32 LE tag @129, key @133)
//!
//! mint (82 B base)
//!   mint_authority   0..36    COption<Pubkey>
//!   supply          36..44    u64 LE
//!   decimals        44        u8
//!   is_initialized  45        bool
//!   freeze_auth     46..82    COption<Pubkey>
//!
//! Token-2022 tail (BOTH kinds)
//!   [82..165]                 zero padding — mints only, crate-checked
//!   [165]                     AccountType: 1 = Mint, 2 = Account
//!   [166..]                   TLV: type u16 LE ‖ length u16 LE ‖ value[len]
//!
//! TransferFeeConfig value (108 B)
//!   transfer_fee_config_authority   0..32   OptionalNonZeroPubkey
//!   withdraw_withheld_authority    32..64   OptionalNonZeroPubkey
//!   withheld_amount                64..72   u64 LE
//!   older_transfer_fee             72..90   { epoch u64, maximum_fee u64, bps u16 }
//!   newer_transfer_fee             90..108  same
//! ```
//!
//! `OptionalNonZeroPubkey` is **not** a `COption`: it is a bare 32-byte key
//! where all-zeros means `None`. Getting that wrong would read a `None`
//! authority as `Some(Pubkey::default())`, which compares equal to itself and
//! so would not be caught by a before/after test — hence it is spelled out.

use anchor_lang::prelude::*;

use crate::constants::{
    DANGER_CONFIDENTIAL, DANGER_PERMANENT_DELEGATE, DANGER_TRANSFER_FEE, DANGER_TRANSFER_HOOK,
    EXT_CONFIDENTIAL_MINT_BURN, EXT_CONFIDENTIAL_TRANSFER_ACCOUNT,
    EXT_CONFIDENTIAL_TRANSFER_FEE_AMOUNT, EXT_CONFIDENTIAL_TRANSFER_FEE_CONFIG,
    EXT_CONFIDENTIAL_TRANSFER_MINT, EXT_PERMANENT_DELEGATE, EXT_TRANSFER_FEE_CONFIG,
    EXT_TRANSFER_HOOK, EXT_UNINITIALIZED, MINT_ACCOUNT_LEN, PROGRAM_SPL, PROGRAM_T22,
    SPL_TOKEN_2022_ID, SPL_TOKEN_ID, T22_ACCOUNT_TYPE_ACCOUNT, T22_ACCOUNT_TYPE_MINT,
    T22_ACCOUNT_TYPE_OFFSET, T22_TLV_OFFSET, TOKEN_ACCOUNT_LEN, TOKEN_MULTISIG_LEN,
};

use super::{MintSnap, Snap, TokenSnap};

/// Snapshot every account in `accts`, in order.
///
/// `vault` is part of the pinned interface but is deliberately **unused**:
/// this function is a pure decode, and every vault-ownership decision lives in
/// [`super::compare::compare_and_account`] so that exactly one place defines
/// what "the vault's account" means (see the module docs, rule 1).
///
/// Fails only if an account's data cannot be borrowed — i.e. it is already
/// mutably borrowed elsewhere in this instruction, which is a programming
/// error in the caller, not attacker-controlled account content.
pub fn snapshot(accts: &[AccountInfo], vault: &Pubkey) -> Result<Vec<Snap>> {
    let _ = vault;
    let mut out = Vec::with_capacity(accts.len());
    for ai in accts {
        let data = ai.try_borrow_data()?;
        out.push(snapshot_one(
            ai.key,
            ai.owner,
            ai.lamports(),
            &data,
            ai.is_writable,
        ));
    }
    Ok(out)
}

/// The pure half of [`snapshot`]: everything except borrowing an
/// `AccountInfo`. Split out so the whole decode is unit-testable with plain
/// byte buffers and no SVM.
pub fn snapshot_one(
    key: &Pubkey,
    owner_program: &Pubkey,
    lamports: u64,
    data: &[u8],
    is_writable: bool,
) -> Snap {
    let is_token_program = *owner_program == SPL_TOKEN_ID || *owner_program == SPL_TOKEN_2022_ID;
    let program = if *owner_program == SPL_TOKEN_2022_ID { PROGRAM_T22 } else { PROGRAM_SPL };

    let mut token = None;
    let mut mint = None;
    let mut token_parse_failed = false;

    if is_token_program {
        match classify(data, program) {
            Some(Kind::Token(tlv)) => {
                token = parse_token_fields(data, tlv, program);
                token_parse_failed = token.is_none();
            }
            Some(Kind::Mint(tlv)) => {
                mint = parse_mint_fields(data, tlv, program);
                token_parse_failed = mint.is_none();
            }
            None => token_parse_failed = true,
        }
    }

    Snap {
        key: *key,
        exists: lamports != 0 || !data.is_empty(),
        owner_program: *owner_program,
        lamports,
        data_len: data.len(),
        token,
        mint,
        token_parse_failed,
        is_writable,
    }
}

/// What a token-program-owned buffer is, plus the byte range of its TLV tail.
enum Kind {
    /// A token account; the range is its TLV tail (empty for classic SPL).
    Token(core::ops::Range<usize>),
    /// A mint; same.
    Mint(core::ops::Range<usize>),
}

/// Decide mint vs token account vs neither, exactly as `spl-token-2022` does —
/// and, since round 1, **the owner program decides which layouts are even
/// legal**.
///
/// Classic SPL Token has no extension mechanism at all, so an SPL-owned buffer
/// is a token account at *exactly* 165 B and a mint at *exactly* 82 B, and
/// nothing else. Before round 1 this function was program-agnostic, so an
/// SPL-owned buffer carrying a Token-2022-shaped `AccountType` byte and tail
/// decoded happily — an attacker-controlled shape the real token program would
/// never produce, decoded by us as if it had.
///
/// The length checks are **equalities**, never `>=` — a multisig (355 B) and a
/// mint (82 B) are both owned by the token program, and a `>=` check would
/// happily read a multisig's first 64 bytes as a mint/owner pair (the same
/// argument `transfer::parse_token_account` records).
fn classify(data: &[u8], program: u8) -> Option<Kind> {
    let len = data.len();
    // `check_min_len_and_not_multisig`: an account of exactly `Multisig::LEN`
    // is never extensible and is never a mint or a token account.
    if len == TOKEN_MULTISIG_LEN {
        return None;
    }
    if len == TOKEN_ACCOUNT_LEN {
        return Some(Kind::Token(0..0));
    }
    if len == MINT_ACCOUNT_LEN {
        return Some(Kind::Mint(0..0));
    }
    if program == PROGRAM_SPL {
        // Classic SPL Token: exact lengths only. No tail exists to decode.
        return None;
    }
    // Anything with a Token-2022 tail: the `AccountType` byte sits at 165 and
    // the TLV starts at 166, so the buffer must be strictly longer than 166
    // (`type_and_tlv_indices` errors on `rest.len() <= tlv_start_index`).
    if len <= T22_TLV_OFFSET {
        return None;
    }
    match *data.get(T22_ACCOUNT_TYPE_OFFSET)? {
        T22_ACCOUNT_TYPE_ACCOUNT => Some(Kind::Token(T22_TLV_OFFSET..len)),
        T22_ACCOUNT_TYPE_MINT => {
            // The crate requires the mint's 82..165 padding to be all zeroes;
            // a non-zero byte there is a different account shape wearing a
            // mint's hat.
            let padding = data.get(MINT_ACCOUNT_LEN..T22_ACCOUNT_TYPE_OFFSET)?;
            if padding.iter().any(|b| *b != 0) {
                return None;
            }
            Some(Kind::Mint(T22_TLV_OFFSET..len))
        }
        _ => None,
    }
}

fn parse_token_fields(
    data: &[u8],
    tlv: core::ops::Range<usize>,
    program: u8,
) -> Option<TokenSnap> {
    let tail = data.get(tlv)?;
    // Round 1 (Codex C5): the tail is WALKED, not merely hashed. A tail whose
    // declared lengths do not fit is not a token account we will reason about,
    // and `compare` turns that into a reject when the account was the vault's.
    // Unknown extension types are allowed — the set grows over time — but every
    // entry must be structurally sound. (Per-extension account-KIND validation
    // is not attempted: it would need the full `ExtensionType -> AccountType`
    // map. The `AccountType` byte `classify` already checks is the crate's own
    // mint-vs-account separator, and the danger decision is made on the MINT's
    // TLV per spec 5.2 rule 5.)
    scan_extensions(tail)?;
    Some(TokenSnap {
        mint: read_pubkey(data, 0..32)?,
        owner: read_pubkey(data, 32..64)?,
        amount: read_u64(data, 64..72)?,
        delegate: read_coption_pubkey(data, 72)?,
        state: *data.get(108)?,
        is_native: read_coption_u64(data, 109)?,
        delegated_amount: read_u64(data, 121..129)?,
        close_authority: read_coption_pubkey(data, 129)?,
        tlv_hash: hash_tail(tail),
        program,
    })
}

fn parse_mint_fields(data: &[u8], tlv: core::ops::Range<usize>, program: u8) -> Option<MintSnap> {
    let tail = data.get(tlv)?;
    let is_initialized = match *data.get(45)? {
        0 => false,
        1 => true,
        // `bool` is a one-byte 0/1 on the wire. Anything else is not a mint
        // this program will reason about — decoded strictly, exactly like the
        // `COption` tags.
        _ => return None,
    };
    let ext = scan_extensions(tail)?;
    Some(MintSnap {
        mint_authority: read_coption_pubkey(data, 0)?,
        supply: read_u64(data, 36..44)?,
        decimals: *data.get(44)?,
        is_initialized,
        freeze_authority: read_coption_pubkey(data, 46)?,
        transfer_fee_config_authority: ext.transfer_fee_config_authority,
        withdraw_withheld_authority: ext.withdraw_withheld_authority,
        max_fee: ext.max_fee,
        tlv_hash: hash_tail(tail),
        dangerous_ext: ext.dangerous_ext,
        program,
    })
}

#[derive(Default)]
struct ExtensionScan {
    dangerous_ext: u8,
    transfer_fee_config_authority: Option<Pubkey>,
    withdraw_withheld_authority: Option<Pubkey>,
    max_fee: u64,
}

/// Walk the TLV tail once, recording the danger flags and extracting the
/// transfer-fee authorities **by type**.
///
/// Returns `None` on a malformed tail (a truncated header, a length that runs
/// off the end). A `type` of `Uninitialized` (0) terminates the walk: the
/// crate writes nothing after an uninitialized slot.
fn scan_extensions(tlv: &[u8]) -> Option<ExtensionScan> {
    let mut out = ExtensionScan::default();
    let mut cursor: usize = 0;
    while cursor < tlv.len() {
        let header_end = cursor.checked_add(4)?;
        let header = tlv.get(cursor..header_end)?;
        let [t0, t1, l0, l1] = *<&[u8; 4]>::try_from(header).ok()?;
        let ext_type = u16::from_le_bytes([t0, t1]);
        if ext_type == EXT_UNINITIALIZED {
            break;
        }
        let value_len = usize::from(u16::from_le_bytes([l0, l1]));
        let value_end = header_end.checked_add(value_len)?;
        let value = tlv.get(header_end..value_end)?;

        match ext_type {
            EXT_TRANSFER_FEE_CONFIG => {
                out.dangerous_ext |= DANGER_TRANSFER_FEE;
                // Best-effort: a short/garbled value leaves the authorities
                // `None` and `max_fee` 0. It cannot open a hole — 1B rejects
                // the mint outright on the flag above, and the before/after
                // comparison is symmetric either way.
                out.transfer_fee_config_authority = read_optional_nonzero_pubkey(value, 0..32);
                out.withdraw_withheld_authority = read_optional_nonzero_pubkey(value, 32..64);
                let older = read_u64(value, 80..88).unwrap_or(0);
                let newer = read_u64(value, 98..106).unwrap_or(0);
                out.max_fee = older.max(newer);
            }
            EXT_PERMANENT_DELEGATE => out.dangerous_ext |= DANGER_PERMANENT_DELEGATE,
            EXT_TRANSFER_HOOK => out.dangerous_ext |= DANGER_TRANSFER_HOOK,
            EXT_CONFIDENTIAL_TRANSFER_MINT
            | EXT_CONFIDENTIAL_TRANSFER_ACCOUNT
            | EXT_CONFIDENTIAL_TRANSFER_FEE_CONFIG
            | EXT_CONFIDENTIAL_TRANSFER_FEE_AMOUNT
            | EXT_CONFIDENTIAL_MINT_BURN => out.dangerous_ext |= DANGER_CONFIDENTIAL,
            _ => {}
        }
        cursor = value_end;
    }
    Some(out)
}

/// keccak-256 over the TLV tail, or `[0; 32]` when there is none.
///
/// keccak, not SHA-256: spike §12.3 measured them CU-identical at a ~100 B
/// tail and keccak is the recorded default. The `[0; 32]` shortcut for an
/// empty tail saves a syscall on every classic SPL account; it cannot collide
/// with a real tail's hash (that would be a keccak preimage of zero) and
/// `data_len` is compared independently anyway.
fn hash_tail(tail: &[u8]) -> [u8; 32] {
    if tail.is_empty() {
        [0u8; 32]
    } else {
        solana_keccak_hasher::hashv(&[tail]).to_bytes()
    }
}

fn read_pubkey(data: &[u8], range: core::ops::Range<usize>) -> Option<Pubkey> {
    let bytes: [u8; 32] = data.get(range)?.try_into().ok()?;
    Some(Pubkey::from(bytes))
}

fn read_u64(data: &[u8], range: core::ops::Range<usize>) -> Option<u64> {
    let bytes: [u8; 8] = data.get(range)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// `COption<Pubkey>`: a 4-byte LE tag followed by the key. The tag is decoded
/// **strictly** — `0` is `None`, `1` is `Some`, and anything else is a parse
/// failure, never `tag != 0` (spec §5.2 rule 2). A permissive `tag != 0` would
/// let a crafted account present the same logical value under two different
/// byte patterns.
fn read_coption_pubkey(data: &[u8], tag_off: usize) -> Option<Option<Pubkey>> {
    let key_start = tag_off.checked_add(4)?;
    let key_end = key_start.checked_add(32)?;
    let tag: [u8; 4] = data.get(tag_off..key_start)?.try_into().ok()?;
    match u32::from_le_bytes(tag) {
        0 => Some(None),
        1 => Some(Some(read_pubkey(data, key_start..key_end)?)),
        _ => None,
    }
}

/// `COption<u64>` (`is_native`), same strict tag rule.
fn read_coption_u64(data: &[u8], tag_off: usize) -> Option<Option<u64>> {
    let val_start = tag_off.checked_add(4)?;
    let val_end = val_start.checked_add(8)?;
    let tag: [u8; 4] = data.get(tag_off..val_start)?.try_into().ok()?;
    match u32::from_le_bytes(tag) {
        0 => Some(None),
        1 => Some(Some(read_u64(data, val_start..val_end)?)),
        _ => None,
    }
}

/// `spl_pod::optional_keys::OptionalNonZeroPubkey`: a bare 32-byte key where
/// all-zeros means `None`. There is **no tag** — reading it as a `COption`
/// would silently shift every field after it.
fn read_optional_nonzero_pubkey(
    data: &[u8],
    range: core::ops::Range<usize>,
) -> Option<Pubkey> {
    let key = read_pubkey(data, range)?;
    if key == Pubkey::default() {
        None
    } else {
        Some(key)
    }
}
