//! Unit tests for `conservation` — pure, no SVM, no CPI.
//!
//! Fixtures are built from the **real `spl-token` crate** wherever the layout
//! is classic SPL (`Account::pack` / `Mint::pack`), so a layout change in SPL
//! Token breaks these loudly rather than drifting silently from what the
//! program parses. `spl-token-2022` is not a dependency (its `solana-program`
//! major would conflict), so the T22 tails are assembled by hand from the
//! offsets re-derived in `snapshot.rs`'s module docs, and
//! `spl_crate_layout_lengths_are_pinned` pins the three lengths the real crate
//! does define.

use super::*;
use crate::constants::*;
use crate::errors::WardenError;
use solana_sdk::program_option::COption;
use solana_sdk::program_pack::Pack;
use spl_token::state::{Account as SplAccount, AccountState, Mint as SplMint};

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn pk(n: u8) -> Pubkey {
    Pubkey::new_from_array([n; 32])
}
fn vault() -> Pubkey {
    pk(0xAA)
}

fn err(e: WardenError) -> anchor_lang::error::Error {
    anchor_lang::error::Error::from(e)
}

fn opt(p: Option<Pubkey>) -> COption<Pubkey> {
    match p {
        Some(k) => COption::Some(k),
        None => COption::None,
    }
}

/// A classic 165-byte SPL token account, built by the real crate.
#[allow(clippy::too_many_arguments)]
fn token_bytes(
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    delegate: Option<Pubkey>,
    delegated_amount: u64,
    close_authority: Option<Pubkey>,
    state: AccountState,
    is_native: Option<u64>,
) -> Vec<u8> {
    let a = SplAccount {
        mint,
        owner,
        amount,
        delegate: opt(delegate),
        state,
        is_native: match is_native {
            Some(v) => COption::Some(v),
            None => COption::None,
        },
        delegated_amount,
        close_authority: opt(close_authority),
    };
    let mut data = vec![0u8; SplAccount::LEN];
    a.pack_into_slice(&mut data);
    data
}

/// The common case: an initialized, undelegated, non-native token account.
fn plain_token_bytes(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
    token_bytes(mint, owner, amount, None, 0, None, AccountState::Initialized, None)
}

/// A classic 82-byte SPL mint, built by the real crate.
fn mint_bytes(
    mint_authority: Option<Pubkey>,
    supply: u64,
    decimals: u8,
    freeze_authority: Option<Pubkey>,
) -> Vec<u8> {
    let m = SplMint {
        mint_authority: opt(mint_authority),
        supply,
        decimals,
        is_initialized: true,
        freeze_authority: opt(freeze_authority),
    };
    let mut data = vec![0u8; SplMint::LEN];
    m.pack_into_slice(&mut data);
    data
}

/// `type u16 LE ‖ length u16 LE ‖ value`, concatenated.
fn tlv(entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (t, v) in entries {
        out.extend_from_slice(&t.to_le_bytes());
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

/// A `TransferFeeConfig` extension value (108 B).
fn transfer_fee_value(
    config_authority: Option<Pubkey>,
    withdraw_authority: Option<Pubkey>,
    withheld_amount: u64,
    older_max_fee: u64,
    newer_max_fee: u64,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(108);
    v.extend_from_slice(&config_authority.unwrap_or_default().to_bytes());
    v.extend_from_slice(&withdraw_authority.unwrap_or_default().to_bytes());
    v.extend_from_slice(&withheld_amount.to_le_bytes());
    // older_transfer_fee { epoch, maximum_fee, bps }
    v.extend_from_slice(&1u64.to_le_bytes());
    v.extend_from_slice(&older_max_fee.to_le_bytes());
    v.extend_from_slice(&50u16.to_le_bytes());
    // newer_transfer_fee
    v.extend_from_slice(&2u64.to_le_bytes());
    v.extend_from_slice(&newer_max_fee.to_le_bytes());
    v.extend_from_slice(&50u16.to_le_bytes());
    assert_eq!(v.len(), 108);
    v
}

/// base(165) ‖ AccountType::Account ‖ tlv
fn t22_token_bytes(base: Vec<u8>, tail: &[u8]) -> Vec<u8> {
    let mut d = base;
    assert_eq!(d.len(), TOKEN_ACCOUNT_LEN);
    d.push(T22_ACCOUNT_TYPE_ACCOUNT);
    d.extend_from_slice(tail);
    d
}

/// base(82) ‖ 83 zero padding bytes ‖ AccountType::Mint ‖ tlv
fn t22_mint_bytes(base: Vec<u8>, tail: &[u8]) -> Vec<u8> {
    let mut d = base;
    assert_eq!(d.len(), MINT_ACCOUNT_LEN);
    d.resize(T22_ACCOUNT_TYPE_OFFSET, 0);
    d.push(T22_ACCOUNT_TYPE_MINT);
    d.extend_from_slice(tail);
    d
}

const RENT: u64 = 2_039_280;

fn snap_token(key: Pubkey, data: &[u8], writable: bool) -> Snap {
    snapshot_one(&key, &SPL_TOKEN_ID, RENT, data, writable)
}
fn snap_t22(key: Pubkey, data: &[u8], writable: bool) -> Snap {
    snapshot_one(&key, &SPL_TOKEN_2022_ID, RENT, data, writable)
}
/// The AFTER shape of a closed account: zero lamports, zero data, system-owned.
fn snap_closed(key: Pubkey) -> Snap {
    snapshot_one(&key, &Pubkey::default(), 0, &[], true)
}

/// A vault-owned token account of `mint` holding `amount`, writable.
fn vault_ata(key: Pubkey, mint: Pubkey, amount: u64) -> Snap {
    snap_token(key, &plain_token_bytes(mint, vault(), amount), true)
}
/// The matching classic mint snapshot.
fn plain_mint(mint: Pubkey) -> Snap {
    snap_token(mint, &mint_bytes(None, 1_000_000, 6, None), false)
}

/// A REAL wrapped-SOL vault account: `is_native = Some(RENT)` and
/// `lamports = RENT + amount`, the only shape the token program produces
/// (WRDF-0011: native value is measured by LAMPORTS; `amount` is a cache).
fn native_ata(key: Pubkey, amount: u64) -> Snap {
    let d = token_bytes(
        NATIVE_MINT,
        vault(),
        amount,
        None,
        0,
        None,
        AccountState::Initialized,
        Some(RENT),
    );
    snapshot_one(&key, &SPL_TOKEN_ID, RENT.saturating_add(amount), &d, true)
}

fn cmp(before: &[Snap], after: &[Snap], closes: &[CloseIntent]) -> Result<Outflow> {
    compare_and_account(before, after, &vault(), closes, 0, 0)
}

// ---------------------------------------------------------------------------
// parsing
// ---------------------------------------------------------------------------

#[test]
fn spl_crate_layout_lengths_are_pinned() {
    assert_eq!(SplAccount::LEN, TOKEN_ACCOUNT_LEN);
    assert_eq!(SplMint::LEN, MINT_ACCOUNT_LEN);
    assert_eq!(spl_token::state::Multisig::LEN, TOKEN_MULTISIG_LEN);
    // Token-2022 puts the `AccountType` byte immediately after the token
    // account base and the TLV one byte later.
    assert_eq!(T22_ACCOUNT_TYPE_OFFSET, TOKEN_ACCOUNT_LEN);
    assert_eq!(T22_TLV_OFFSET, 166);
}

#[test]
fn classic_82_byte_mint_parses() {
    let auth = pk(9);
    let s = snap_token(pk(1), &mint_bytes(Some(auth), 42, 6, Some(pk(8))), false);
    let m = s.mint.expect("mint parses");
    assert_eq!(m.mint_authority, Some(auth));
    assert_eq!(m.freeze_authority, Some(pk(8)));
    assert_eq!(m.supply, 42);
    assert_eq!(m.decimals, 6);
    assert!(m.is_initialized);
    assert_eq!(m.dangerous_ext, 0);
    assert_eq!(m.program, PROGRAM_SPL);
    assert_eq!(m.tlv_hash, [0u8; 32]);
    assert!(s.token.is_none());
    assert!(!s.token_parse_failed);
}

#[test]
fn mint_buffer_of_81_or_83_bytes_does_not_parse() {
    let base = mint_bytes(None, 1, 0, None);
    for len in [81usize, 83, 100, 164, 166] {
        let mut d = base.clone();
        d.resize(len, 0);
        let s = snap_token(pk(1), &d, false);
        assert!(s.mint.is_none(), "len {len} must not parse as a mint");
        assert!(s.token.is_none(), "len {len} must not parse as a token account");
        assert!(s.token_parse_failed, "len {len} must be flagged");
    }
}

#[test]
fn coption_tag_two_is_a_parse_error_never_tag_not_zero() {
    // mint_authority tag = 2
    let mut d = mint_bytes(Some(pk(9)), 1, 0, None);
    d[0] = 2;
    let s = snap_token(pk(1), &d, false);
    assert!(s.mint.is_none());
    assert!(s.token_parse_failed);

    // token account delegate tag = 2 (@72)
    let mut t = plain_token_bytes(pk(2), vault(), 5);
    t[72] = 2;
    let s = snap_token(pk(3), &t, true);
    assert!(s.token.is_none());
    assert!(s.token_parse_failed);

    // is_native tag = 2 (@109)
    let mut t = plain_token_bytes(pk(2), vault(), 5);
    t[109] = 2;
    assert!(snap_token(pk(3), &t, true).token.is_none());

    // close_authority tag = 2 (@129)
    let mut t = plain_token_bytes(pk(2), vault(), 5);
    t[129] = 2;
    assert!(snap_token(pk(3), &t, true).token.is_none());
}

#[test]
fn classic_165_byte_token_account_parses_every_field() {
    let d = token_bytes(
        pk(2),
        vault(),
        77,
        Some(pk(5)),
        11,
        Some(pk(6)),
        AccountState::Frozen,
        Some(RENT),
    );
    let t = snap_token(pk(3), &d, true).token.expect("parses");
    assert_eq!(t.mint, pk(2));
    assert_eq!(t.owner, vault());
    assert_eq!(t.amount, 77);
    assert_eq!(t.delegate, Some(pk(5)));
    assert_eq!(t.delegated_amount, 11);
    assert_eq!(t.close_authority, Some(pk(6)));
    assert_eq!(t.state, TOKEN_STATE_FROZEN);
    assert_eq!(t.is_native, Some(RENT));
    assert_eq!(t.tlv_hash, [0u8; 32]);
    assert_eq!(t.program, PROGRAM_SPL);
}

#[test]
fn multisig_length_is_neither_mint_nor_token_account() {
    let d = vec![1u8; TOKEN_MULTISIG_LEN];
    let s = snap_token(pk(1), &d, true);
    assert!(s.token.is_none() && s.mint.is_none());
    assert!(s.token_parse_failed);
}

#[test]
fn t22_account_type_byte_selects_mint_or_token_account() {
    let tail = tlv(&[(EXT_TRANSFER_HOOK, vec![0u8; 64])]);
    let m = t22_mint_bytes(mint_bytes(None, 1, 0, None), &tail);
    let s = snap_t22(pk(1), &m, false);
    assert!(s.mint.is_some() && s.token.is_none());
    assert_eq!(s.mint.unwrap().dangerous_ext, DANGER_TRANSFER_HOOK);

    let a = t22_token_bytes(plain_token_bytes(pk(2), vault(), 1), &tail);
    let s = snap_t22(pk(3), &a, true);
    assert!(s.token.is_some() && s.mint.is_none());
    assert_eq!(s.token.unwrap().program, PROGRAM_T22);

    // an unknown AccountType byte is neither
    let mut bad = a.clone();
    bad[T22_ACCOUNT_TYPE_OFFSET] = 7;
    let s = snap_t22(pk(3), &bad, true);
    assert!(s.token.is_none() && s.mint.is_none() && s.token_parse_failed);
}

#[test]
fn t22_mint_padding_must_be_all_zero() {
    let tail = tlv(&[(EXT_TRANSFER_FEE_CONFIG, transfer_fee_value(None, None, 0, 0, 0))]);
    let mut d = t22_mint_bytes(mint_bytes(None, 1, 0, None), &tail);
    d[100] = 1; // inside the 82..165 padding
    let s = snap_t22(pk(1), &d, false);
    assert!(s.mint.is_none());
    assert!(s.token_parse_failed);
}

#[test]
fn t22_malformed_tlv_does_not_parse() {
    // a length that runs off the end of the tail
    let mut tail = Vec::new();
    tail.extend_from_slice(&EXT_TRANSFER_HOOK.to_le_bytes());
    tail.extend_from_slice(&999u16.to_le_bytes());
    tail.extend_from_slice(&[0u8; 4]);
    let d = t22_mint_bytes(mint_bytes(None, 1, 0, None), &tail);
    assert!(snap_t22(pk(1), &d, false).mint.is_none());

    // a truncated header (2 bytes)
    let d = t22_mint_bytes(mint_bytes(None, 1, 0, None), &[1u8, 0]);
    assert!(snap_t22(pk(1), &d, false).mint.is_none());
}

#[test]
fn tlv_walk_stops_at_an_uninitialized_slot() {
    let mut tail = tlv(&[(EXT_UNINITIALIZED, vec![0u8; 0])]);
    tail.extend_from_slice(&tlv(&[(EXT_TRANSFER_HOOK, vec![0u8; 64])]));
    let d = t22_mint_bytes(mint_bytes(None, 1, 0, None), &tail);
    let m = snap_t22(pk(1), &d, false).mint.expect("parses");
    assert_eq!(m.dangerous_ext, 0, "nothing is written after Uninitialized");
}

#[test]
fn transfer_fee_authorities_are_extracted_by_tlv_type() {
    let cfg = pk(0x31);
    let wd = pk(0x32);
    let tail = tlv(&[(
        EXT_TRANSFER_FEE_CONFIG,
        transfer_fee_value(Some(cfg), Some(wd), 500, 7, 9),
    )]);
    let d = t22_mint_bytes(mint_bytes(None, 1, 0, None), &tail);
    let m = snap_t22(pk(1), &d, false).mint.expect("parses");
    assert_eq!(m.transfer_fee_config_authority, Some(cfg));
    assert_eq!(m.withdraw_withheld_authority, Some(wd));
    assert_eq!(m.max_fee, 9, "max of older/newer maximum_fee");
    assert_eq!(m.dangerous_ext, DANGER_TRANSFER_FEE);
}

#[test]
fn optional_nonzero_pubkey_all_zeroes_is_none_not_some_default() {
    let tail = tlv(&[(EXT_TRANSFER_FEE_CONFIG, transfer_fee_value(None, None, 0, 0, 0))]);
    let d = t22_mint_bytes(mint_bytes(None, 1, 0, None), &tail);
    let m = snap_t22(pk(1), &d, false).mint.expect("parses");
    assert_eq!(m.transfer_fee_config_authority, None);
    assert_eq!(m.withdraw_withheld_authority, None);
}

#[test]
fn every_danger_extension_sets_its_bit() {
    for (ext, bit) in [
        (EXT_TRANSFER_FEE_CONFIG, DANGER_TRANSFER_FEE),
        (EXT_CONFIDENTIAL_TRANSFER_MINT, DANGER_CONFIDENTIAL),
        (EXT_CONFIDENTIAL_TRANSFER_ACCOUNT, DANGER_CONFIDENTIAL),
        (EXT_CONFIDENTIAL_TRANSFER_FEE_CONFIG, DANGER_CONFIDENTIAL),
        (EXT_CONFIDENTIAL_TRANSFER_FEE_AMOUNT, DANGER_CONFIDENTIAL),
        (EXT_CONFIDENTIAL_MINT_BURN, DANGER_CONFIDENTIAL),
        (EXT_PERMANENT_DELEGATE, DANGER_PERMANENT_DELEGATE),
        (EXT_TRANSFER_HOOK, DANGER_TRANSFER_HOOK),
    ] {
        let value = if ext == EXT_TRANSFER_FEE_CONFIG {
            transfer_fee_value(None, None, 0, 0, 0)
        } else {
            vec![0u8; 32]
        };
        let d = t22_mint_bytes(mint_bytes(None, 1, 0, None), &tlv(&[(ext, value)]));
        let m = snap_t22(pk(1), &d, false).mint.expect("parses");
        assert_eq!(m.dangerous_ext, bit, "extension {ext}");
    }
    // a benign extension (MetadataPointer = 18) sets nothing
    let d = t22_mint_bytes(mint_bytes(None, 1, 0, None), &tlv(&[(18, vec![0u8; 64])]));
    assert_eq!(snap_t22(pk(1), &d, false).mint.unwrap().dangerous_ext, 0);
}

#[test]
fn accounts_owned_by_a_non_token_program_are_never_flagged() {
    let s = snapshot_one(&pk(1), &pk(0x77), 10, &[1, 2, 3], true);
    assert!(!s.token_parse_failed);
    assert!(s.token.is_none() && s.mint.is_none());
    assert!(s.exists);
    assert_eq!(s.data_len, 3);
}

#[test]
fn a_closed_account_snapshot_does_not_exist() {
    assert!(!snap_closed(pk(1)).exists);
}

// ---------------------------------------------------------------------------
// comparison — the happy path and the amount lane
// ---------------------------------------------------------------------------

#[test]
fn unchanged_vault_token_account_yields_zero_outflow() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100), plain_mint(m)];
    let after = before.clone();
    let out = cmp(&before, &after, &[]).expect("ok");
    assert_eq!(out, Outflow::default());
}

#[test]
fn amount_decrease_becomes_outflow() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100), plain_mint(m)];
    let after = vec![vault_ata(pk(3), m, 40), plain_mint(m)];
    let out = cmp(&before, &after, &[]).expect("ok");
    assert_eq!(out.by_mint, vec![(m, 60)]);
    assert_eq!(out.sol, 0);
}

#[test]
fn two_vault_atas_of_one_mint_coalesce_into_a_single_entry() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100), vault_ata(pk(4), m, 50), plain_mint(m)];
    let after = vec![vault_ata(pk(3), m, 40), vault_ata(pk(4), m, 20), plain_mint(m)];
    let out = cmp(&before, &after, &[]).expect("ok");
    assert_eq!(out.by_mint, vec![(m, 90)], "one entry per mint");
}

#[test]
fn intra_vault_rebalance_nets_to_zero() {
    // 60 moves from one vault ATA to another vault ATA of the same mint. That
    // is not an outflow and must not be charged to any cap.
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100), vault_ata(pk(4), m, 0), plain_mint(m)];
    let after = vec![vault_ata(pk(3), m, 40), vault_ata(pk(4), m, 60), plain_mint(m)];
    assert_eq!(cmp(&before, &after, &[]).expect("ok"), Outflow::default());
}

#[test]
fn inflow_floors_to_zero_and_drops_the_mint_entry() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 10), plain_mint(m)];
    let after = vec![vault_ata(pk(3), m, 999), plain_mint(m)];
    let out = cmp(&before, &after, &[]).expect("ok");
    assert!(out.by_mint.is_empty());
}

#[test]
fn wsol_decrease_is_counted_in_sol_and_never_in_by_mint() {
    let before = vec![native_ata(pk(3), 5_000), plain_mint(NATIVE_MINT)];
    let after = vec![native_ata(pk(3), 1_000), plain_mint(NATIVE_MINT)];
    let out = cmp(&before, &after, &[]).expect("ok");
    assert_eq!(out.sol, 4_000);
    assert!(
        out.by_mint.is_empty(),
        "NATIVE_MINT is the SOL cap key; a by_mint entry would debit the same bucket twice"
    );
}

#[test]
fn t22_native_account_delta_is_counted_in_sol_not_by_mint() {
    // WRDF-0008: Token-2022 wraps SOL under its OWN native mint
    // (`NATIVE_MINT_2022`, spl-token-2022 7.0.0 `src/native_mint.rs`), so a
    // mint-key-only native test would send this delta to
    // `by_mint[9pan…]` — one SOL movement split across two cap/bucket keys.
    let acct = |amount: u64| {
        t22_token_bytes(
            token_bytes(
                NATIVE_MINT_2022,
                vault(),
                amount,
                None,
                0,
                None,
                AccountState::Initialized,
                Some(RENT),
            ),
            // A 166-byte buffer (type byte, empty tail) is not a valid T22
            // shape — `classify` mirrors the crate's `type_and_tlv_indices`
            // there — so carry one benign zero-length entry (ImmutableOwner).
            &tlv(&[(7, vec![])]),
        )
    };
    // An 82-byte classic-shape mint under the T22 program: extension-free, the
    // only mint shape 1B accepts (an unmodeled mint extension now rejects).
    let mint = mint_bytes(None, 0, 9, None);
    let before = vec![
        snapshot_one(&pk(3), &SPL_TOKEN_2022_ID, RENT + 5_000, &acct(5_000), true),
        snap_t22(NATIVE_MINT_2022, &mint, false),
    ];
    let after = vec![
        snapshot_one(&pk(3), &SPL_TOKEN_2022_ID, RENT + 1_000, &acct(1_000), true),
        snap_t22(NATIVE_MINT_2022, &mint, false),
    ];
    let out = cmp(&before, &after, &[]).expect("ok");
    assert_eq!(out.sol, 4_000);
    assert!(out.by_mint.is_empty(), "a native mint key must never appear in by_mint");
}

#[test]
fn an_is_native_flag_on_a_non_native_mint_is_rejected() {
    // Under either real token program, `is_native` is set IFF the mint is that
    // program's native mint. A mismatch either way is an impossible-on-chain
    // shape wearing a token account's layout — rejected, never measured.
    let m = pk(9);
    let acct = token_bytes(m, vault(), 700, None, 0, None, AccountState::Initialized, Some(RENT));
    let before = vec![
        snapshot_one(&pk(3), &SPL_TOKEN_ID, RENT.saturating_add(700), &acct, true),
        plain_mint(m),
    ];
    assert_eq!(
        cmp(&before, &before, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn a_native_mint_key_without_is_native_is_rejected() {
    // The mirror mismatch: mint == the native mint but `is_native` None.
    // The real token program never creates this; measuring its `amount`
    // (or its lamports) would be reasoning about a forgery.
    let before = vec![vault_ata(pk(3), NATIVE_MINT, 5_000), plain_mint(NATIVE_MINT)];
    assert_eq!(
        cmp(&before, &before, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn wsol_and_pda_lamport_delta_merge_into_one_sol_number() {
    let before = vec![native_ata(pk(3), 5_000), plain_mint(NATIVE_MINT)];
    let after = vec![native_ata(pk(3), 1_000), plain_mint(NATIVE_MINT)];
    let out = compare_and_account(&before, &after, &vault(), &[], 10_000, 9_500).expect("ok");
    assert_eq!(out.sol, 4_500, "4_000 WSOL + 500 PDA lamports, one number");
    assert!(out.by_mint.is_empty());
}

#[test]
fn pda_lamport_decrease_is_counted() {
    let out = compare_and_account(&[], &[], &vault(), &[], 10_000, 7_000).expect("ok");
    assert_eq!(out.sol, 3_000);
}

#[test]
fn pda_lamport_increase_floors_to_zero() {
    let out = compare_and_account(&[], &[], &vault(), &[], 7_000, 10_000).expect("ok");
    assert_eq!(out.sol, 0);
}

#[test]
fn a_pda_inflow_offsets_a_wsol_outflow_before_the_floor() {
    // The floor is applied ONCE to the merged number, not to the PDA term on
    // its own — spec 5.2 rule 4a's "the SOL equation already sees it".
    let before = vec![native_ata(pk(3), 5_000), plain_mint(NATIVE_MINT)];
    let after = vec![native_ata(pk(3), 4_000), plain_mint(NATIVE_MINT)];
    let out = compare_and_account(&before, &after, &vault(), &[], 0, 400).expect("ok");
    assert_eq!(out.sol, 600);
}

#[test]
fn non_vault_token_accounts_may_change_freely() {
    let m = pk(2);
    let stranger = pk(0x55);
    let before = vec![
        snap_token(pk(3), &plain_token_bytes(m, stranger, 100), true),
        // a stranger's account may even acquire a delegate and a close authority
        plain_mint(m),
    ];
    let after = vec![
        snap_token(
            pk(3),
            &token_bytes(m, stranger, 0, Some(pk(7)), 5, Some(pk(8)), AccountState::Frozen, None),
            true,
        ),
        plain_mint(m),
    ];
    assert_eq!(cmp(&before, &after, &[]).expect("ok"), Outflow::default());
}

#[test]
fn outflow_overflow_is_rejected() {
    let m = pk(2);
    let before = vec![
        vault_ata(pk(3), m, u64::MAX),
        vault_ata(pk(4), m, u64::MAX),
        plain_mint(m),
    ];
    let after = vec![vault_ata(pk(3), m, 0), vault_ata(pk(4), m, 0), plain_mint(m)];
    assert_eq!(cmp(&before, &after, &[]).unwrap_err(), err(WardenError::Overflow));
}

// ---------------------------------------------------------------------------
// comparison — field identity and policy
// ---------------------------------------------------------------------------

fn expect_violation(after_bytes: Vec<u8>) {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100), plain_mint(m)];
    let after = vec![snap_token(pk(3), &after_bytes, true), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn delegate_set_by_the_cpi_is_rejected() {
    expect_violation(token_bytes(
        pk(2),
        vault(),
        100,
        Some(pk(7)),
        10,
        None,
        AccountState::Initialized,
        None,
    ));
}

#[test]
fn close_authority_set_by_the_cpi_is_rejected() {
    expect_violation(token_bytes(
        pk(2),
        vault(),
        100,
        None,
        0,
        Some(pk(7)),
        AccountState::Initialized,
        None,
    ));
}

#[test]
fn token_owner_change_is_rejected() {
    expect_violation(plain_token_bytes(pk(2), pk(0x55), 100));
}

#[test]
fn mint_field_change_is_rejected() {
    // Since round 1 (Codex C2) this reports `NewVaultAccountRejected` rather
    // than `ConservationViolated`: an account whose `mint` differs is not the
    // account we snapshotted, so the "did it BECOME the vault's?" check fires
    // before the field-identity diff. Same verdict, more precise cause.
    let before = vec![vault_ata(pk(3), pk(2), 100), plain_mint(pk(2))];
    let after = vec![
        snap_token(pk(3), &plain_token_bytes(pk(0x66), vault(), 100), true),
        plain_mint(pk(2)),
    ];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::NewVaultAccountRejected)
    );
}

#[test]
fn state_frozen_is_rejected() {
    expect_violation(token_bytes(
        pk(2),
        vault(),
        100,
        None,
        0,
        None,
        AccountState::Frozen,
        None,
    ));
}

#[test]
fn is_native_change_is_rejected() {
    expect_violation(token_bytes(
        pk(2),
        vault(),
        100,
        None,
        0,
        None,
        AccountState::Initialized,
        Some(RENT),
    ));
}

#[test]
fn delegated_amount_change_alone_is_rejected() {
    // delegate stays None but delegated_amount moves: byte-identity catches it
    // even though the policy check would not.
    let mut d = plain_token_bytes(pk(2), vault(), 100);
    d[121..129].copy_from_slice(&7u64.to_le_bytes());
    expect_violation(d);
}

#[test]
fn a_pre_existing_delegate_is_rejected_even_if_unchanged() {
    // Byte-identical before and after; only the BEFORE-side policy check can
    // catch this (LZR-ACC-C2: a missing record must reject, not be skipped).
    let m = pk(2);
    let d = token_bytes(m, vault(), 100, Some(pk(7)), 10, None, AccountState::Initialized, None);
    let before = vec![snap_token(pk(3), &d, true), plain_mint(m)];
    let after = before.clone();
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn a_delegate_cleared_by_the_cpi_is_rejected() {
    // The exact defect an after-only inspection misses: AFTER reads `None`, so
    // nothing "looks" wrong unless before is compared too.
    let m = pk(2);
    let b = token_bytes(m, vault(), 100, Some(pk(7)), 10, None, AccountState::Initialized, None);
    let before = vec![snap_token(pk(3), &b, true), plain_mint(m)];
    let after = vec![vault_ata(pk(3), m, 100), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn a_pre_existing_close_authority_is_rejected_even_if_unchanged() {
    let m = pk(2);
    let d = token_bytes(m, vault(), 100, None, 0, Some(pk(8)), AccountState::Initialized, None);
    let before = vec![snap_token(pk(3), &d, true), plain_mint(m)];
    let after = before.clone();
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn runtime_program_owner_change_is_rejected() {
    // SWIG-ACC-C1: transfer out, close, reopen under a program that fakes the
    // SPL byte layout. The bytes parse; the runtime owner does not match.
    let m = pk(2);
    let d = plain_token_bytes(m, vault(), 100);
    let before = vec![snap_token(pk(3), &d, true), plain_mint(m)];
    let after = vec![snapshot_one(&pk(3), &pk(0x99), RENT, &d, true), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn data_len_and_tlv_tail_changes_are_rejected() {
    let m = pk(2);
    let base = plain_token_bytes(m, vault(), 100);
    let b = t22_token_bytes(base.clone(), &tlv(&[(2, vec![0u8; 8])]));
    let before = vec![snap_t22(pk(3), &b, true), snap_t22(m, &mint_bytes(None, 1, 0, None), false)];

    // (a) the tail changes value but not length
    let a = t22_token_bytes(base.clone(), &tlv(&[(2, vec![9u8; 8])]));
    let after = vec![snap_t22(pk(3), &a, true), before[1].clone()];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated),
        "TLV tail change"
    );

    // (b) the tail grows: data_len differs too
    let a = t22_token_bytes(base, &tlv(&[(2, vec![0u8; 8]), (3, vec![0u8; 8])]));
    let after = vec![snap_t22(pk(3), &a, true), before[1].clone()];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated),
        "data_len change"
    );
}

#[test]
fn unparseable_after_when_before_was_vault_owned_is_rejected() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100), plain_mint(m)];
    let mut garbage = plain_token_bytes(m, vault(), 100);
    garbage[72] = 3; // malformed COption tag
    let after = vec![snap_token(pk(3), &garbage, true), plain_mint(m)];
    assert!(after[0].token_parse_failed);
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn disappearance_without_a_close_intent_is_rejected() {
    // The nested-close case: a CloseAccount reached the token program inside
    // some other program's CPI, so the decoder never saw it.
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 0), plain_mint(m)];
    let after = vec![snap_closed(pk(3)), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn positional_mismatches_are_rejected() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100), plain_mint(m)];
    assert_eq!(
        cmp(&before, &before[..1], &[]).unwrap_err(),
        err(WardenError::ConservationViolated),
        "length"
    );
    let after = vec![vault_ata(pk(4), m, 100), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated),
        "key at index"
    );
}

// ---------------------------------------------------------------------------
// comparison — account kinds
// ---------------------------------------------------------------------------

#[test]
fn a_writable_account_owned_by_the_warden_program_is_rejected() {
    let s = snapshot_one(&pk(0x40), &crate::ID, 10, &[0u8; 8], true);
    let before = vec![s.clone()];
    assert_eq!(
        cmp(&before, &before, &[]).unwrap_err(),
        err(WardenError::SelfCpiRejected)
    );
}

#[test]
fn the_smart_account_pda_passed_read_only_is_allowed() {
    let s = snapshot_one(&vault(), &crate::ID, 10, &[0u8; 8], false);
    let before = vec![s.clone()];
    assert_eq!(cmp(&before, &before, &[]).expect("ok"), Outflow::default());
}

#[test]
fn a_writable_vault_owned_non_token_account_is_rejected() {
    let v = vault();
    let s = snapshot_one(&pk(0x41), &v, 10, &[0u8; 8], true);
    let before = vec![s.clone()];
    assert_eq!(
        cmp(&before, &before, &[]).unwrap_err(),
        err(WardenError::UnsupportedAccountKind)
    );
}

#[test]
fn a_read_only_vault_owned_non_token_account_is_ignored() {
    let v = vault();
    let s = snapshot_one(&pk(0x41), &v, 10, &[0u8; 8], false);
    let before = vec![s.clone()];
    assert_eq!(cmp(&before, &before, &[]).expect("ok"), Outflow::default());
}

// ---------------------------------------------------------------------------
// comparison — mints (spec 5.2 rule 2a)
// ---------------------------------------------------------------------------

#[test]
fn a_writable_vault_token_account_whose_mint_is_absent_is_rejected() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100)];
    let after = vec![vault_ata(pk(3), m, 90)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::MintMissing)
    );
}

#[test]
fn the_presence_rule_covers_token_2022_mints_too() {
    let m = pk(2);
    let base = plain_token_bytes(m, vault(), 100);
    let b = t22_token_bytes(base, &tlv(&[(2, vec![0u8; 8])]));
    let before = vec![snap_t22(pk(3), &b, true)];
    assert_eq!(
        cmp(&before, &before, &[]).unwrap_err(),
        err(WardenError::MintMissing)
    );
}

#[test]
fn an_account_at_the_mints_address_that_is_not_a_mint_counts_as_missing() {
    let m = pk(2);
    // a token account planted at the mint's address
    let impostor = snap_token(m, &plain_token_bytes(pk(9), pk(9), 1), false);
    let before = vec![vault_ata(pk(3), m, 100), impostor];
    assert_eq!(
        cmp(&before, &before, &[]).unwrap_err(),
        err(WardenError::MintMissing)
    );
}

#[test]
fn the_mint_is_required_even_for_a_read_only_vault_token_account() {
    // Round 1 (Codex C1): the presence rule is NOT gated on `is_writable`.
    // "Read-only" is a property of THIS instruction's account list, and the
    // mint is what the danger-extension and authority checks read; gating on
    // writable let a caller opt out of both by passing the ATA read-only.
    let m = pk(2);
    let s = snap_token(pk(3), &plain_token_bytes(m, vault(), 100), false);
    let before = vec![s.clone()];
    assert_eq!(
        cmp(&before, &before, &[]).unwrap_err(),
        err(WardenError::MintMissing)
    );
}

#[test]
fn mint_authority_change_is_a_reject_not_an_accounting_entry() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100), snap_token(m, &mint_bytes(None, 1, 6, None), true)];
    let after = vec![
        vault_ata(pk(3), m, 100),
        snap_token(m, &mint_bytes(Some(pk(0x99)), 1, 6, None), true),
    ];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn freeze_authority_set_from_none_is_rejected() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100), snap_token(m, &mint_bytes(None, 1, 6, None), true)];
    let after = vec![
        vault_ata(pk(3), m, 100),
        snap_token(m, &mint_bytes(None, 1, 6, Some(pk(0x99))), true),
    ];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn freeze_authority_cleared_from_some_is_rejected() {
    let m = pk(2);
    let before = vec![
        vault_ata(pk(3), m, 100),
        snap_token(m, &mint_bytes(None, 1, 6, Some(pk(0x99))), true),
    ];
    let after = vec![vault_ata(pk(3), m, 100), snap_token(m, &mint_bytes(None, 1, 6, None), true)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn mint_decimals_change_is_rejected() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100), snap_token(m, &mint_bytes(None, 1, 6, None), true)];
    let after = vec![vault_ata(pk(3), m, 100), snap_token(m, &mint_bytes(None, 1, 9, None), true)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn mint_supply_change_alone_is_ok() {
    // Spec 5.2 rule 2a: `supply` is not an authority field. A legitimate
    // mint/burn through an allow-listed adapter changes it.
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100), snap_token(m, &mint_bytes(None, 1, 6, None), true)];
    let after = vec![
        vault_ata(pk(3), m, 100),
        snap_token(m, &mint_bytes(None, 9_999_999, 6, None), true),
    ];
    assert_eq!(cmp(&before, &after, &[]).expect("ok"), Outflow::default());
}

/// A T22 vault token account of a transfer-fee mint, before and after.
fn fee_mint_case(
    before_value: Vec<u8>,
    after_value: Vec<u8>,
) -> (Vec<Snap>, Vec<Snap>) {
    let m = pk(2);
    let acct = plain_token_bytes(m, vault(), 100);
    let acct = t22_token_bytes(acct, &tlv(&[(2, vec![0u8; 8])]));
    let bm = t22_mint_bytes(mint_bytes(None, 1, 6, None), &tlv(&[(EXT_TRANSFER_FEE_CONFIG, before_value)]));
    let am = t22_mint_bytes(mint_bytes(None, 1, 6, None), &tlv(&[(EXT_TRANSFER_FEE_CONFIG, after_value)]));
    (
        vec![snap_t22(pk(3), &acct, true), snap_t22(m, &bm, true)],
        vec![snap_t22(pk(3), &acct, true), snap_t22(m, &am, true)],
    )
}

#[test]
fn a_transfer_fee_mint_has_its_own_error_so_1c_can_lift_it_alone() {
    let (before, after) = fee_mint_case(
        transfer_fee_value(Some(pk(0x31)), Some(pk(0x32)), 0, 7, 9),
        transfer_fee_value(Some(pk(0x31)), Some(pk(0x32)), 0, 7, 9),
    );
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::TransferFeeMintUnsupported)
    );
}

#[test]
fn never_allowlistable_extensions_reject_with_token2022extensionrejected() {
    for ext in [
        EXT_TRANSFER_HOOK,
        EXT_PERMANENT_DELEGATE,
        EXT_CONFIDENTIAL_TRANSFER_MINT,
        EXT_CONFIDENTIAL_TRANSFER_ACCOUNT,
        EXT_CONFIDENTIAL_TRANSFER_FEE_CONFIG,
        EXT_CONFIDENTIAL_TRANSFER_FEE_AMOUNT,
        EXT_CONFIDENTIAL_MINT_BURN,
    ] {
        let m = pk(2);
        let acct = t22_token_bytes(plain_token_bytes(m, vault(), 100), &tlv(&[(2, vec![0u8; 8])]));
        let mb = t22_mint_bytes(mint_bytes(None, 1, 6, None), &tlv(&[(ext, vec![0u8; 32])]));
        let before = vec![snap_t22(pk(3), &acct, true), snap_t22(m, &mb, true)];
        assert_eq!(
            cmp(&before, &before, &[]).unwrap_err(),
            err(WardenError::Token2022ExtensionRejected),
            "extension {ext}"
        );
    }
}

#[test]
fn a_required_mint_with_an_unmodeled_extension_is_rejected() {
    // WRDF-0012: MetadataPointer, MintCloseAuthority, InterestBearingConfig,
    // group/member pointers, ScaledUiAmountConfig and PausableConfig all carry
    // REASSIGNABLE authority fields the snapshot does not model, and the mint
    // tail hash is deliberately never compared. 1B fails closed: a required
    // mint carrying ANY unmodeled extension rejects, unchanged or not.
    // (Type 18 here = a MetadataPointer-shaped entry.)
    let m = pk(2);
    let mint = t22_mint_bytes(mint_bytes(None, 0, 6, None), &tlv(&[(18, vec![0u8; 64])]));
    let base = t22_token_bytes(plain_token_bytes(m, vault(), 5), &tlv(&[(7, vec![])]));
    let before = vec![snap_t22(pk(3), &base, true), snap_t22(m, &mint, false)];
    assert_eq!(
        cmp(&before, &before, &[]).unwrap_err(),
        err(WardenError::Token2022ExtensionRejected)
    );
}

#[test]
fn a_standalone_writable_mint_with_an_unmodeled_extension_is_rejected() {
    // WRDF-0012 round 7: a mint whose ONLY vault-held authority lives in an
    // unmodeled extension reads as uncontrolled to `holds_authority`, so the
    // `check_mint` gate (reached only via a vault token account) never sees it.
    // A writable such mint standing alone in the snapshot set must still reject
    // — a PDA-signed Pause/authority transition on it is otherwise invisible.
    // (Type 18 = a MetadataPointer-shaped entry; no vault ATA in the set.)
    let m = pk(7);
    let mint = t22_mint_bytes(mint_bytes(None, 0, 6, None), &tlv(&[(18, vec![0u8; 64])]));
    let before = vec![snap_t22(m, &mint, true)];
    assert_eq!(
        cmp(&before, &before, &[]).unwrap_err(),
        err(WardenError::Token2022ExtensionRejected)
    );
}

#[test]
fn a_standalone_writable_mint_with_a_recognized_danger_extension_is_rejected() {
    // WRDF-0012 round 8: `PermanentDelegate` (type 12) is a RECOGNIZED danger
    // extension, so `has_unrecognized_ext` is false — and `holds_authority`
    // does not inspect the permanent delegate. A standalone writable mint
    // controlled by the vault solely through it would otherwise bypass the
    // pre-scan entirely (no vault ATA ⇒ `check_mint`'s danger gate never runs).
    let m = pk(7);
    let mint = t22_mint_bytes(mint_bytes(None, 0, 6, None), &tlv(&[(12, vec![0u8; 32])]));
    let before = vec![snap_t22(m, &mint, true)];
    assert_eq!(
        cmp(&before, &before, &[]).unwrap_err(),
        err(WardenError::Token2022ExtensionRejected)
    );
}

#[test]
fn a_read_only_stranger_mint_with_an_unmodeled_extension_is_ignored() {
    // The mirror: a mint passed READ-ONLY cannot be mutated in this tx, so a
    // normal swap through a token carrying a metadata pointer must NOT reject.
    let m = pk(7);
    let mint = t22_mint_bytes(mint_bytes(None, 0, 6, None), &tlv(&[(18, vec![0u8; 64])]));
    let before = vec![snap_t22(m, &mint, false)];
    assert_eq!(cmp(&before, &before, &[]).expect("ok"), Outflow::default());
}

#[test]
fn a_danger_extension_added_mid_instruction_is_rejected() {
    let m = pk(2);
    let acct = t22_token_bytes(plain_token_bytes(m, vault(), 100), &tlv(&[(2, vec![0u8; 8])]));
    let clean = t22_mint_bytes(mint_bytes(None, 1, 6, None), &tlv(&[(18, vec![0u8; 32])]));
    let hooked = t22_mint_bytes(mint_bytes(None, 1, 6, None), &tlv(&[(EXT_TRANSFER_HOOK, vec![0u8; 32])]));
    let before = vec![snap_t22(pk(3), &acct, true), snap_t22(m, &clean, true)];
    let after = vec![snap_t22(pk(3), &acct, true), snap_t22(m, &hooked, true)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::Token2022ExtensionRejected)
    );
}

#[test]
fn t22_transfer_fee_config_authority_change_is_rejected() {
    let (before, after) = fee_mint_case(
        transfer_fee_value(Some(pk(0x31)), Some(pk(0x32)), 0, 7, 9),
        transfer_fee_value(Some(pk(0x99)), Some(pk(0x32)), 0, 7, 9),
    );
    // The transfer-fee rejection fires first (both mints carry the extension),
    // so this asserts the authority extraction differs, not the error path.
    assert_ne!(
        before[1].mint.as_ref().unwrap().transfer_fee_config_authority,
        after[1].mint.as_ref().unwrap().transfer_fee_config_authority
    );
    let bm = before[1].mint.clone().unwrap();
    let am = after[1].mint.clone().unwrap();
    assert_eq!(
        super::compare::check_mint(&strip_fee(&bm), &strip_fee(&am)).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn t22_withdraw_withheld_authority_change_is_rejected() {
    let (before, after) = fee_mint_case(
        transfer_fee_value(Some(pk(0x31)), Some(pk(0x32)), 0, 7, 9),
        transfer_fee_value(Some(pk(0x31)), Some(pk(0x99)), 0, 7, 9),
    );
    let bm = before[1].mint.clone().unwrap();
    let am = after[1].mint.clone().unwrap();
    assert_eq!(
        super::compare::check_mint(&strip_fee(&bm), &strip_fee(&am)).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

/// Clear the transfer-fee danger bit so `check_mint` reaches the authority
/// comparison — 1B rejects fee mints outright, and these two tests are about
/// the *extraction*, which 1C will depend on.
fn strip_fee(m: &MintSnap) -> MintSnap {
    let mut m = m.clone();
    m.dangerous_ext &= !DANGER_TRANSFER_FEE;
    m
}

#[test]
fn withheld_amount_accrual_with_unchanged_authorities_is_ok() {
    // THE case a whole-tail hash would wrongly reject: `withheld_amount` moves
    // inside the same TLV tail on the happy path. `tlv_hash` must differ and
    // the comparison must still pass.
    let (before, after) = fee_mint_case(
        transfer_fee_value(Some(pk(0x31)), Some(pk(0x32)), 0, 7, 9),
        transfer_fee_value(Some(pk(0x31)), Some(pk(0x32)), 5_000, 7, 9),
    );
    let bm = strip_fee(&before[1].mint.clone().unwrap());
    let am = strip_fee(&after[1].mint.clone().unwrap());
    assert_ne!(bm.tlv_hash, am.tlv_hash, "the tail really did change");
    super::compare::check_mint(&bm, &am).expect("authorities unchanged => ok");
}

// ---------------------------------------------------------------------------
// close intents (spec 5.2 rules 1a and 4a)
// ---------------------------------------------------------------------------

fn intent(account: Pubkey, destination: Pubkey, amount_before: u64) -> CloseIntent {
    CloseIntent { account, destination, amount_before }
}

#[test]
fn a_vault_sweep_close_is_legal_and_is_not_double_counted() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 0), plain_mint(m)];
    let after = vec![snap_closed(pk(3)), plain_mint(m)];
    // The rent came home: the PDA's own lamports rose by exactly RENT.
    let out = compare_and_account(
        &before,
        &after,
        &vault(),
        &[intent(pk(3), vault(), 0)],
        1_000_000,
        1_000_000u64.saturating_add(RENT),
    )
    .expect("ok");
    assert_eq!(out.sol, 0, "an inflow, and counted exactly once");
    assert!(out.by_mint.is_empty());
}

#[test]
fn a_close_intent_with_a_non_zero_balance_is_rejected() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 5), plain_mint(m)];
    let after = vec![snap_closed(pk(3)), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[intent(pk(3), vault(), 5)]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn a_close_intent_whose_amount_disagrees_with_the_snapshot_is_rejected() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 0), plain_mint(m)];
    let after = vec![snap_closed(pk(3)), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[intent(pk(3), vault(), 7)]).unwrap_err(),
        err(WardenError::ConservationViolated),
        "decoder/comparison desync must fail loudly"
    );
}

#[test]
fn a_close_intent_for_an_account_that_survived_is_rejected() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 0), plain_mint(m)];
    assert_eq!(
        cmp(&before, &before, &[intent(pk(3), vault(), 0)]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn a_close_to_a_stranger_charges_the_rent_as_sol_outflow() {
    // The rule-4a BACKSTOP, exercised with the decoder out of the loop so it
    // is proven independently of the deny-list floor.
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 0), plain_mint(m)];
    let after = vec![snap_closed(pk(3)), plain_mint(m)];
    let out = cmp(&before, &after, &[intent(pk(3), pk(0x55), 0)]).expect("ok");
    assert_eq!(out.sol, RENT);
}

#[test]
fn an_unconsumed_close_intent_is_rejected() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100), plain_mint(m)];
    assert_eq!(
        cmp(&before, &before, &[intent(pk(0xAB), vault(), 0)]).unwrap_err(),
        err(WardenError::ConservationViolated),
        "an intent naming an account outside the snapshot set"
    );
}

#[test]
fn a_duplicate_close_intent_is_rejected() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 0), plain_mint(m)];
    let after = vec![snap_closed(pk(3)), plain_mint(m)];
    let closes = [intent(pk(3), vault(), 0), intent(pk(3), vault(), 0)];
    assert_eq!(
        cmp(&before, &after, &closes).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn a_close_intent_naming_the_smart_account_pda_is_rejected() {
    // Rule 1a condition 4. Contrived (the PDA is not a token account), but the
    // guard must exist rather than rely on that.
    let m = pk(2);
    let v = vault();
    let before = vec![snap_token(v, &plain_token_bytes(m, v, 0), true), plain_mint(m)];
    let after = vec![snap_closed(v), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[intent(v, v, 0)]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

// ---------------------------------------------------------------------------
// structural guarantees
// ---------------------------------------------------------------------------

#[test]
fn outflow_has_no_gross_turnover_field() {
    // Research 3(a).6: withdrawn permanently. No snapshot granularity can
    // observe a round trip inside one CPI, and there is no prior art for token
    // gross accounting. This test is the tripwire for a later "restore".
    let out = Outflow::default();
    let Outflow { sol, by_mint } = out; // exhaustive destructure: adding a
                                        // field breaks this line.
    assert_eq!(sol, 0);
    assert!(by_mint.is_empty());
}

// ---------------------------------------------------------------------------
// Round 1 regressions — Codex review (sol@max, thread 01a018fa)
// ---------------------------------------------------------------------------

/// A mint the vault holds `mint_authority` on, as a writable snapshot.
fn vault_controlled_mint(key: Pubkey, supply: u64, freeze: Option<Pubkey>) -> Snap {
    snap_token(key, &mint_bytes(Some(vault()), supply, 6, freeze), true)
}

// --- C1: vault-controlled mints are validated independently of any token
//         account, and required/dangerous mints are validated BEFORE the
//         close branch.

#[test]
fn c1_a_standalone_vault_controlled_mint_authority_change_is_rejected() {
    // No vault token account anywhere in the set: the ONLY thing that can
    // catch this is the independent mint pre-scan.
    let m = pk(2);
    let before = vec![vault_controlled_mint(m, 1, None)];
    let after = vec![snap_token(m, &mint_bytes(Some(pk(0x99)), 1, 6, None), true)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn c1_a_standalone_vault_controlled_mint_freeze_authority_change_is_rejected() {
    let m = pk(2);
    let before = vec![vault_controlled_mint(m, 1, None)];
    let after = vec![vault_controlled_mint(m, 1, Some(pk(0x99)))];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn c1_a_standalone_vault_controlled_mint_supply_change_is_still_ok() {
    // Adjudication (1), re-confirmed: `supply` is not an authority field.
    let m = pk(2);
    let before = vec![vault_controlled_mint(m, 1, None)];
    let after = vec![vault_controlled_mint(m, 9_999, None)];
    assert_eq!(cmp(&before, &after, &[]).expect("ok"), Outflow::default());
}

#[test]
fn c1_a_vault_controlled_mint_tlv_tail_change_is_rejected() {
    // A writable mint carrying an UNMODELED extension (type 18) now rejects at
    // the WRDF-0012 gate — earlier than, and superseding, the tail-hash
    // comparison it used to hit. Both are rejects; the earlier gate is the
    // stronger statement (it does not even depend on the tail CHANGING). The
    // whole-tail-hash comparison for controlled mints remains in
    // `prescan_vault_mints` as defense in depth for any future modeled-only
    // tail; here the more specific error is the correct verdict.
    let m = pk(2);
    let b = t22_mint_bytes(
        mint_bytes(Some(vault()), 1, 6, None),
        &tlv(&[(18, vec![0u8; 32])]),
    );
    let a = t22_mint_bytes(
        mint_bytes(Some(vault()), 1, 6, None),
        &tlv(&[(18, vec![7u8; 32])]),
    );
    let before = vec![snap_t22(m, &b, true)];
    let after = vec![snap_t22(m, &a, true)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::Token2022ExtensionRejected)
    );
}

#[test]
fn c1_a_vault_controlled_mint_that_disappears_is_rejected() {
    let m = pk(2);
    let before = vec![vault_controlled_mint(m, 1, None)];
    let after = vec![snap_closed(m)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn c1_a_mint_change_is_caught_even_when_its_token_account_is_closed() {
    // The close branch used to `continue` before any mint validation ran, so a
    // CPI could close the (zero-balance) vault ATA and rewrite the mint in the
    // same instruction.
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 0), vault_controlled_mint(m, 1, None)];
    let after = vec![snap_closed(pk(3)), vault_controlled_mint(m, 1, Some(pk(0x99)))];
    assert_eq!(
        cmp(&before, &after, &[intent(pk(3), vault(), 0)]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn c1_a_dangerous_mint_is_rejected_even_when_its_token_account_is_closed() {
    let m = pk(2);
    let acct = t22_token_bytes(plain_token_bytes(m, vault(), 0), &tlv(&[(2, vec![0u8; 8])]));
    let mb = t22_mint_bytes(mint_bytes(None, 1, 6, None), &tlv(&[(EXT_TRANSFER_HOOK, vec![0u8; 32])]));
    let before = vec![snap_t22(pk(3), &acct, true), snap_t22(m, &mb, true)];
    let after = vec![snap_closed(pk(3)), snap_t22(m, &mb, true)];
    assert_eq!(
        cmp(&before, &after, &[intent(pk(3), vault(), 0)]).unwrap_err(),
        err(WardenError::Token2022ExtensionRejected)
    );
}

#[test]
fn c1_a_missing_mint_is_rejected_even_when_its_token_account_is_closed() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 0)];
    let after = vec![snap_closed(pk(3))];
    assert_eq!(
        cmp(&before, &after, &[intent(pk(3), vault(), 0)]).unwrap_err(),
        err(WardenError::MintMissing)
    );
}

// --- C2: an account that BECOMES the vault's is rejected.

#[test]
fn c2_a_vault_token_account_created_by_the_cpi_is_rejected() {
    // BEFORE: nothing at this address. AFTER: a vault-owned ATA carrying an
    // attacker delegate. A BEFORE-driven classification never looks at it.
    let m = pk(2);
    let created = token_bytes(
        m,
        vault(),
        0,
        Some(pk(0x99)),
        u64::MAX,
        None,
        AccountState::Initialized,
        None,
    );
    let before = vec![snap_closed(pk(3)), plain_mint(m)];
    let after = vec![snap_token(pk(3), &created, true), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::NewVaultAccountRejected)
    );
}

#[test]
fn c2_an_account_converted_into_a_vault_token_account_is_rejected() {
    let m = pk(2);
    let before = vec![
        snap_token(pk(3), &plain_token_bytes(m, pk(0x55), 100), true),
        plain_mint(m),
    ];
    let after = vec![vault_ata(pk(3), m, 100), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::NewVaultAccountRejected)
    );
}

#[test]
fn c2_a_non_token_account_that_becomes_a_vault_ata_is_rejected() {
    let m = pk(2);
    let before = vec![snapshot_one(&pk(3), &pk(0x77), RENT, &[0u8; 40], true), plain_mint(m)];
    let after = vec![vault_ata(pk(3), m, 1_000), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::NewVaultAccountRejected)
    );
}

#[test]
fn c2_a_vault_controlled_mint_appearing_only_in_after_is_rejected() {
    let m = pk(2);
    let before = vec![snapshot_one(&m, &pk(0x77), RENT, &[0u8; 40], true)];
    let after = vec![vault_controlled_mint(m, 1, None)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

// --- C3: duplicate keys.

#[test]
fn c3_duplicate_account_keys_are_rejected() {
    // The exact undercount: the same vault ATA listed twice. Slot 0 sees
    // 100 -> 0 (-100) and slot 1 sees 100 -> 150 (+50), so the signed net
    // reports 50 for a movement of 100.
    let m = pk(2);
    let ata = pk(3);
    let before = vec![vault_ata(ata, m, 100), vault_ata(ata, m, 100), plain_mint(m)];
    let after = vec![vault_ata(ata, m, 0), vault_ata(ata, m, 150), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::PayloadInvalid)
    );
}

#[test]
fn c3_a_duplicated_mint_key_is_rejected() {
    let m = pk(2);
    let before = vec![vault_ata(pk(3), m, 100), plain_mint(m), plain_mint(m)];
    assert_eq!(
        cmp(&before, &before, &[]).unwrap_err(),
        err(WardenError::PayloadInvalid)
    );
}

// --- C4: lamports on non-native vault token accounts.

#[test]
fn c4_excess_lamports_drained_from_a_non_native_vault_token_account_is_rejected() {
    // Token-2022 `WithdrawExcessLamports` (tag 38): every compared field is
    // byte-identical and only the account's lamport balance moves.
    let m = pk(2);
    let d = plain_token_bytes(m, vault(), 100);
    let before = vec![snapshot_one(&pk(3), &SPL_TOKEN_ID, RENT.saturating_add(9_000), &d, true), plain_mint(m)];
    let after = vec![snapshot_one(&pk(3), &SPL_TOKEN_ID, RENT, &d, true), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn c4_a_lamport_donation_to_a_non_native_vault_token_account_is_also_rejected() {
    let m = pk(2);
    let d = plain_token_bytes(m, vault(), 100);
    let before = vec![snapshot_one(&pk(3), &SPL_TOKEN_ID, RENT, &d, true), plain_mint(m)];
    let after = vec![snapshot_one(&pk(3), &SPL_TOKEN_ID, RENT.saturating_add(1), &d, true), plain_mint(m)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn a_native_lamport_drain_with_unchanged_amount_is_sol_outflow() {
    // WRDF-0011, superseding the earlier `c4_a_native_account_may_move_
    // lamports_because_the_amount_covers_them`, whose premise WAS the bug:
    // `amount` is a cached view that only moves on `SyncNative`, so a
    // lamport-only drain with amount unchanged is real value leaving. It must
    // be COUNTED (the caps decide), never zero.
    let d = token_bytes(
        NATIVE_MINT,
        vault(),
        5_000,
        None,
        0,
        None,
        AccountState::Initialized,
        Some(RENT),
    );
    let before = vec![
        snapshot_one(&pk(3), &SPL_TOKEN_ID, RENT.saturating_add(5_000), &d, true),
        plain_mint(NATIVE_MINT),
    ];
    let after = vec![
        snapshot_one(&pk(3), &SPL_TOKEN_ID, RENT, &d, true),
        plain_mint(NATIVE_MINT),
    ];
    let out = cmp(&before, &after, &[]).expect("ok");
    assert_eq!(out.sol, 5_000);
    assert!(out.by_mint.is_empty());
}

#[test]
fn sync_native_then_transfer_of_a_donation_is_counted_as_sol_outflow() {
    // The WRDF-0011 exploit shape end to end: a legal unsynced donation
    // (amount 0, lamports RENT+X), then inner `SyncNative` (amount <- X) and
    // `Transfer X` (amount -X, lamports -X). Every compared token field ends
    // exactly where it began; only the lamports show the theft.
    let acct = |amount: u64| {
        token_bytes(NATIVE_MINT, vault(), amount, None, 0, None, AccountState::Initialized, Some(RENT))
    };
    let before = vec![
        snapshot_one(&pk(3), &SPL_TOKEN_ID, RENT.saturating_add(9_000), &acct(0), true),
        plain_mint(NATIVE_MINT),
    ];
    let after = vec![
        snapshot_one(&pk(3), &SPL_TOKEN_ID, RENT, &acct(0), true),
        plain_mint(NATIVE_MINT),
    ];
    let out = cmp(&before, &after, &[]).expect("ok");
    assert_eq!(out.sol, 9_000, "the drained donation is SOL outflow, not zero");
}

#[test]
fn sync_native_alone_moves_no_value_and_counts_nothing() {
    // `SyncNative` recomputes the cache; lamports do not move, so neither
    // does the SOL equation.
    let before = vec![
        snapshot_one(
            &pk(3),
            &SPL_TOKEN_ID,
            RENT.saturating_add(9_000),
            &token_bytes(NATIVE_MINT, vault(), 0, None, 0, None, AccountState::Initialized, Some(RENT)),
            true,
        ),
        plain_mint(NATIVE_MINT),
    ];
    let after = vec![
        snapshot_one(
            &pk(3),
            &SPL_TOKEN_ID,
            RENT.saturating_add(9_000),
            &token_bytes(NATIVE_MINT, vault(), 9_000, None, 0, None, AccountState::Initialized, Some(RENT)),
            true,
        ),
        plain_mint(NATIVE_MINT),
    ];
    assert_eq!(cmp(&before, &after, &[]).expect("ok"), Outflow::default());
}

// --- C5: strict, program-aware parsing.

#[test]
fn c5_classic_spl_token_accepts_only_exact_lengths() {
    // A buffer that WOULD decode as a Token-2022 extended account, but owned
    // by classic SPL Token, which has no extensions at all.
    let d = t22_token_bytes(plain_token_bytes(pk(2), vault(), 1), &tlv(&[(2, vec![0u8; 8])]));
    let s = snapshot_one(&pk(3), &SPL_TOKEN_ID, RENT, &d, true);
    assert!(s.token.is_none() && s.mint.is_none());
    assert!(s.token_parse_failed);

    let m = t22_mint_bytes(mint_bytes(None, 1, 0, None), &tlv(&[(18, vec![0u8; 8])]));
    let s = snapshot_one(&pk(4), &SPL_TOKEN_ID, RENT, &m, false);
    assert!(s.mint.is_none());
    assert!(s.token_parse_failed);
}

#[test]
fn c5_a_token_2022_account_tlv_tail_is_walked_not_just_hashed() {
    // A length that runs past the end of the tail.
    let mut tail = Vec::new();
    tail.extend_from_slice(&2u16.to_le_bytes());
    tail.extend_from_slice(&999u16.to_le_bytes());
    tail.extend_from_slice(&[0u8; 4]);
    let d = t22_token_bytes(plain_token_bytes(pk(2), vault(), 1), &tail);
    let s = snap_t22(pk(3), &d, true);
    assert!(s.token.is_none(), "an overlong TLV length must not parse");
    assert!(s.token_parse_failed);

    // A truncated header.
    let d = t22_token_bytes(plain_token_bytes(pk(2), vault(), 1), &[2u8, 0]);
    assert!(snap_t22(pk(3), &d, true).token.is_none());

    // A well-formed unknown extension type is allowed, as long as it fits.
    let d = t22_token_bytes(
        plain_token_bytes(pk(2), vault(), 1),
        &tlv(&[(9_999, vec![0u8; 16])]),
    );
    assert!(snap_t22(pk(3), &d, true).token.is_some());
}

#[test]
fn c5_a_vault_owned_t22_account_whose_tail_becomes_truncated_is_rejected() {
    let m = pk(2);
    let good = t22_token_bytes(plain_token_bytes(m, vault(), 100), &tlv(&[(2, vec![0u8; 8])]));
    let mut bad = good.clone();
    let n = bad.len().saturating_sub(4);
    bad.truncate(n); // the value no longer fits its declared length
    let mb = snap_t22(m, &mint_bytes(None, 1, 0, None), false);
    let before = vec![snap_t22(pk(3), &good, true), mb.clone()];
    let after = vec![snap_t22(pk(3), &bad, true), mb];
    assert!(after[0].token_parse_failed);
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

// ---------------------------------------------------------------------------
// Round 2 regressions — Codex re-review (thread 01a0190f)
// ---------------------------------------------------------------------------

/// A vault-owned token account of `mint` holding `amount`, with an explicit
/// lamport balance (the round-1 `vault_ata` helper pins lamports to `RENT`).
fn vault_ata_with_lamports(key: Pubkey, mint: Pubkey, amount: u64, lamports: u64) -> Snap {
    snapshot_one(&key, &SPL_TOKEN_ID, lamports, &plain_token_bytes(mint, vault(), amount), true)
}

#[test]
fn r2_drain_excess_lamports_then_close_is_rejected() {
    // The C4 bypass: `WithdrawExcessLamports` (tag 38) sends the over-funded
    // rent to an attacker, then the *permitted* zero-balance `CloseAccount` to
    // the PDA returns only the true rent. Every field the close path compared
    // was fine, and the close branch exited before the lamport check.
    let m = pk(2);
    let before = vec![
        vault_ata_with_lamports(pk(3), m, 0, RENT.saturating_add(9_000)),
        plain_mint(m),
    ];
    let after = vec![snap_closed(pk(3)), plain_mint(m)];
    assert_eq!(
        compare_and_account(
            &before,
            &after,
            &vault(),
            &[intent(pk(3), vault(), 0)],
            1_000_000,
            1_000_000u64.saturating_add(RENT), // only the true rent came home
        )
        .unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn r2_an_honest_close_credits_the_pda_by_lamports_before() {
    // The same shape, honest: the PDA is credited the FULL `lamports_before`.
    let m = pk(2);
    let over = RENT.saturating_add(9_000);
    let before = vec![vault_ata_with_lamports(pk(3), m, 0, over), plain_mint(m)];
    let after = vec![snap_closed(pk(3)), plain_mint(m)];
    let out = compare_and_account(
        &before,
        &after,
        &vault(),
        &[intent(pk(3), vault(), 0)],
        1_000_000,
        1_000_000u64.saturating_add(over),
    )
    .expect("ok");
    assert_eq!(out.sol, 0, "debit lamports_before, credit the PDA delta, net zero");
    assert!(out.by_mint.is_empty());
}

#[test]
fn r2_a_close_to_a_stranger_charges_the_whole_lamports_before() {
    // The rule-4a backstop now charges the FULL balance, over-funding included
    // — not just whatever a rent-exempt minimum would have been.
    let m = pk(2);
    let over = RENT.saturating_add(9_000);
    let before = vec![vault_ata_with_lamports(pk(3), m, 0, over), plain_mint(m)];
    let after = vec![snap_closed(pk(3)), plain_mint(m)];
    let out = cmp(&before, &after, &[intent(pk(3), pk(0x55), 0)]).expect("ok");
    assert_eq!(out.sol, over);
}

#[test]
fn r2_a_partially_credited_close_is_rejected_even_with_other_sol_movement() {
    // The shortfall must not be laundered through an unrelated WSOL inflow.
    let m = pk(2);
    let before = vec![
        vault_ata_with_lamports(pk(3), m, 0, RENT.saturating_add(9_000)),
        plain_mint(m),
        native_ata(pk(4), 0),
        plain_mint(NATIVE_MINT),
    ];
    let after = vec![
        snap_closed(pk(3)),
        plain_mint(m),
        native_ata(pk(4), 50_000),
        plain_mint(NATIVE_MINT),
    ];
    assert_eq!(
        compare_and_account(
            &before,
            &after,
            &vault(),
            &[intent(pk(3), vault(), 0)],
            0,
            RENT,
        )
        .unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn r2_vault_controlled_mint_lamports_must_not_move() {
    // Tag 38 drains excess lamports from MINTS too, and the pre-scan compared
    // every field except the one that moved.
    let m = pk(2);
    let bytes = mint_bytes(Some(vault()), 1, 6, None);
    let before = vec![snapshot_one(&m, &SPL_TOKEN_ID, RENT.saturating_add(9_000), &bytes, true)];
    let after = vec![snapshot_one(&m, &SPL_TOKEN_ID, RENT, &bytes, true)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn r2_a_lamport_donation_to_a_vault_controlled_mint_is_also_rejected() {
    let m = pk(2);
    let bytes = mint_bytes(None, 1, 6, Some(vault()));
    let before = vec![snapshot_one(&m, &SPL_TOKEN_ID, RENT, &bytes, true)];
    let after = vec![snapshot_one(&m, &SPL_TOKEN_ID, RENT.saturating_add(1), &bytes, true)];
    assert_eq!(
        cmp(&before, &after, &[]).unwrap_err(),
        err(WardenError::ConservationViolated)
    );
}

#[test]
fn r2_a_mint_the_vault_does_not_control_may_move_lamports() {
    // The freeze is scoped to mints the PDA holds an authority on; a stranger's
    // mint passed through the instruction is none of our business.
    let m = pk(2);
    let bytes = mint_bytes(Some(pk(0x99)), 1, 6, None);
    let before = vec![snapshot_one(&m, &SPL_TOKEN_ID, RENT.saturating_add(9_000), &bytes, true)];
    let after = vec![snapshot_one(&m, &SPL_TOKEN_ID, RENT, &bytes, true)];
    assert_eq!(cmp(&before, &after, &[]).expect("ok"), Outflow::default());
}
