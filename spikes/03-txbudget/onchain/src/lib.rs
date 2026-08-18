//! Spike 3b: measure the CU cost of a conservation-snapshot pass over N
//! writable **token** accounts — one piece of the core safety mechanism
//! Phase 1's `execute` instruction needs, not the whole thing. This spike
//! snapshots every writable vault-owned SPL Token / Token-2022 account
//! before/after the inner CPI and rejects the transaction if one was mutated
//! (owner changed, delegate/close-authority set, or — for Token-2022 — any
//! TLV extension byte changed). **Scope, stated plainly (docs review, round
//! 5, 2026-08-18): this spike is TOKEN-ACCOUNT-ONLY and CU-ONLY.** It does
//! NOT implement PDA-lamport (SOL) conservation — spec §5.2's SOL/lamport
//! equation (`outflow[SOL] = (pda_lamports_before − pda_lamports_after) +
//! Σ_vault-WSOL(amount_before − amount_after)`) has no code path here:
//! `Snap.lamports` is captured per-account below but is **never compared**
//! before vs after, and the vault authority marker account passed in
//! `accounts[0]` — the account whose *own* lamport balance the SOL equation
//! needs — is itself never snapshotted at all (it is read-only and never
//! initialized on-chain in this spike; see `process()` below). A vault could
//! lose SOL directly (not via a token account) between the two passes and
//! this program would not notice.
//!
//! ⚠ **DO NOT COPY THIS FILE AS-IS INTO PHASE 1.** Phase 1's real `execute`
//! must additionally (a) snapshot the vault PDA's own `lamports` before and
//! after the inner CPI and (b) implement spec §5.2's full SOL/lamport
//! equation, not just the token-account field comparison this spike proves
//! out. Copying this program unmodified would ship a wallet with no SOL
//! conservation check at all.
//!
//! ## Dependency note (record for docs/TOOLCHAIN.md)
//! `spl-token = "7"` and `spl-token-2022 = "7"` both resolve cleanly against
//! `solana-program = "3"` in Cargo's dependency *graph* (`cargo tree` is
//! happy) — but they pull `solana-program 2.3.0` (via `solana-pubkey 2.4.0`),
//! a semver-major-incompatible instance from the `solana-program 3.0.0` this
//! crate uses for `AccountInfo`. `cargo tree -i solana-program` reports it as
//! ambiguous (`2.3.0` / `3.0.0`), and `spl_token::state::Account::owner` is a
//! *different, non-interconvertible* `Pubkey` type than the one on
//! `AccountInfo`. Per the task brief's documented fallback, this program does
//! NOT depend on `spl_token`/`spl_token_2022` types at all: the SPL Token and
//! Token-2022 program ids are hardcoded `pubkey!()` constants (both are
//! long-stable, publicly documented addresses) and the 165-byte account body
//! is parsed by hand at the fixed offsets from the SPL Token source layout
//! (also reproduced in the task brief). `spl-token`/`spl-token-2022` remain
//! declared `[dependencies]` below purely so `cargo tree` records the majors
//! that resolve (7.0.0 / 7.0.0); nothing in this crate imports them.
use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg, program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process);

/// SPL Token program id (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`).
pub const SPL_TOKEN_ID: Pubkey = solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
/// SPL Token-2022 program id (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`).
pub const SPL_TOKEN_2022_ID: Pubkey = solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
/// Native (wrapped SOL) mint (`So11111111111111111111111111111111111111112`).
pub const NATIVE_MINT_ID: Pubkey = solana_program::pubkey!("So11111111111111111111111111111111111111112");

/// Fixed-layout length of the base SPL Token `Account` struct (also the
/// prefix Token-2022 accounts share before any TLV extension bytes).
const TOKEN_ACCOUNT_LEN: usize = 165;
/// AccountState::Initialized discriminant (spl_token::state::AccountState).
const STATE_INITIALIZED: u8 = 1;

/// A byte-for-byte view of the fields the SPL Token `Account` layout packs,
/// read directly at fixed offsets (see the module doc for why this is
/// hand-rolled instead of using `spl_token::state::Account::unpack`):
///   mint            0..32
///   owner           32..64
///   amount          64..72   (u64 LE)
///   delegate        72..108  (COption<Pubkey>: tag u32 LE @72..76, key @76..108)
///   state           108      (u8)
///   is_native       109..121 (COption<u64>: tag u32 LE @109..113, val @113..121) — not read, unused
///   delegated_amount 121..129 (u64 LE)
///   close_authority 129..165 (COption<Pubkey>: tag u32 LE @129..133, key @133..165)
#[derive(Clone, PartialEq, Eq, Debug)]
struct TokenFields {
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    delegate: Option<Pubkey>,
    delegated_amount: u64,
    close_authority: Option<Pubkey>,
    state: u8,
}

fn read_pubkey(b: &[u8], off: usize) -> Pubkey {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&b[off..off + 32]);
    Pubkey::from(buf)
}

/// Strictly decodes a `COption<Pubkey>` at `tag_off`: a 4-byte LE tag
/// followed (only when the tag is `1`) by the 32-byte pubkey. Any tag other
/// than `0` (None) or `1` (Some) is malformed on-chain data and is a hard
/// parse error, not silently treated as either variant.
fn read_coption_pubkey(b: &[u8], tag_off: usize) -> Result<Option<Pubkey>, ProgramError> {
    let tag = u32::from_le_bytes(b[tag_off..tag_off + 4].try_into().map_err(|_| ProgramError::InvalidAccountData)?);
    match tag {
        0 => Ok(None),
        1 => Ok(Some(read_pubkey(b, tag_off + 4))),
        _ => Err(ProgramError::InvalidAccountData),
    }
}

/// Returns `Ok(None)` when `data` is too short to be a token account at all
/// (structurally not a token account — not itself an error), `Err` when it is
/// full-length but contains a malformed `COption` tag, else `Ok(Some(..))`.
fn parse_token_fields(data: &[u8]) -> Result<Option<TokenFields>, ProgramError> {
    if data.len() < TOKEN_ACCOUNT_LEN {
        return Ok(None);
    }
    let amount = u64::from_le_bytes(data[64..72].try_into().map_err(|_| ProgramError::InvalidAccountData)?);
    let delegate = read_coption_pubkey(data, 72)?;
    let state = data[108];
    let delegated_amount =
        u64::from_le_bytes(data[121..129].try_into().map_err(|_| ProgramError::InvalidAccountData)?);
    let close_authority = read_coption_pubkey(data, 129)?;
    Ok(Some(TokenFields {
        mint: read_pubkey(data, 0),
        owner: read_pubkey(data, 32),
        amount,
        delegate,
        delegated_amount,
        close_authority,
        state,
    }))
}

/// Chosen TLV-tail hash syscall. See result.md part (b) for the keccak vs
/// sha256 CU comparison; default is the cheaper one found empirically.
#[cfg(feature = "sha256-tlv")]
fn tlv_hash(data: &[u8]) -> [u8; 32] {
    solana_program::hash::hash(data).to_bytes()
}
#[cfg(not(feature = "sha256-tlv"))]
fn tlv_hash(data: &[u8]) -> [u8; 32] {
    solana_program::keccak::hash(data).to_bytes()
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Snap {
    owner: Pubkey,
    lamports: u64,
    data_len: usize,
    token: Option<TokenFields>,
    tlv_hash: [u8; 32],
}

fn snap(a: &AccountInfo) -> Result<Snap, ProgramError> {
    let data = a.try_borrow_data()?;
    let token =
        if *a.owner == SPL_TOKEN_ID || *a.owner == SPL_TOKEN_2022_ID { parse_token_fields(&data)? } else { None };
    let tlv_hash = if data.len() > TOKEN_ACCOUNT_LEN { tlv_hash(&data[TOKEN_ACCOUNT_LEN..]) } else { [0; 32] };
    Ok(Snap { owner: *a.owner, lamports: a.lamports(), data_len: data.len(), token, tlv_hash })
}

/// Checks one candidate vault-owned token account's before/after snapshots
/// and returns the token amount that left it (pre `amount` minus post
/// `amount`, floored at 0), or an error if the account was mutated.
///
/// If `before.token` is not `Some` with its token-level `owner` equal to
/// `vault`, this account isn't the vault's concern at all: returns `Ok(0)`.
/// Otherwise:
///   - `after.token` must still be `Some` — an account that becomes too
///     short/corrupted to parse as a token account is a hard error, not a
///     silent skip (this was the exact defect this function replaces: the
///     old code's `if let (Some(tb), Some(ta)) = ..` pattern-matched away a
///     `None` `after` with no error at all).
///   - EVERY field except `amount` must be byte-identical before vs after:
///     runtime (program) owner, token-level owner, mint, delegate (full
///     value, not just presence), delegated_amount, close_authority (full
///     value), state, data_len, and the TLV-tail hash. Any difference is a
///     mutation and is rejected.
///   - Independently of whether anything changed, the account's `after`
///     state must satisfy policy: state must be Initialized, delegate must
///     be `None`, close_authority must be `None`. This is deliberately
///     separate from the unchanged-check above: a vault token account that
///     already had a delegate/close_authority set *before* this instruction
///     (and keeps it byte-for-byte unchanged) still fails here — the old
///     code only ever inspected the AFTER booleans, which is exactly why a
///     pre-existing delegate that got CLEARED during the call slipped
///     through the old check (its `after` boolean read `false`, so nothing
///     looked "mutated" — even though before ≠ after, which the unchanged
///     diff below now catches on its own).
fn check_vault_invariants(vault: &Pubkey, before: &Snap, after: &Snap) -> Result<u64, ProgramError> {
    let tb = match &before.token {
        Some(t) if t.owner == *vault => t,
        _ => return Ok(0),
    };
    let ta = after.token.as_ref().ok_or(ProgramError::InvalidAccountData)?;

    let unchanged = after.owner == before.owner
        && ta.owner == tb.owner
        && ta.mint == tb.mint
        && ta.delegate == tb.delegate
        && ta.delegated_amount == tb.delegated_amount
        && ta.close_authority == tb.close_authority
        && ta.state == tb.state
        && after.data_len == before.data_len
        && after.tlv_hash == before.tlv_hash;
    if !unchanged {
        return Err(ProgramError::InvalidAccountData);
    }

    if ta.state != STATE_INITIALIZED || ta.delegate.is_some() || ta.close_authority.is_some() {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(tb.amount.checked_sub(ta.amount).unwrap_or(0))
}

/// accounts[0] = vault authority pubkey (read-only marker); rest = writable
/// accounts to snapshot. data[0] = 1 -> return Custom(99) after snapshotting.
/// This is a SYNTHETIC control path only (a caller-declared "something went
/// wrong" flag, not a real detected mutation) — it exists purely to measure
/// the reject-after-successful-snapshot CU cost in LiteSVM; the actual
/// reject-on-mutation logic lives in `check_vault_invariants` and is unit
/// tested directly (see `tests` module below), since producing a real
/// mutation requires an inner CPI this spike deliberately doesn't have.
pub fn process(_pid: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let vault = accounts[0].key;
    let before: Vec<Snap> = accounts[1..].iter().map(snap).collect::<Result<_, _>>()?;
    // (a real `execute` would CPI into the target program here)
    let after: Vec<Snap> = accounts[1..].iter().map(snap).collect::<Result<_, _>>()?;
    let mut sol_out: u64 = 0;
    for (b, a) in before.iter().zip(after.iter()) {
        let dec = check_vault_invariants(vault, b, a).map_err(|e| {
            msg!("vault token account mutated");
            e
        })?;
        if dec > 0 {
            if let Some(tb) = &b.token {
                if tb.mint == NATIVE_MINT_ID {
                    sol_out = sol_out.checked_add(dec).ok_or(ProgramError::ArithmeticOverflow)?;
                }
            }
        }
    }
    msg!("snapshots ok, sol_out={}", sol_out);
    if data.first() == Some(&1) {
        return Err(ProgramError::Custom(99));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> Pubkey {
        Pubkey::from([seed; 32])
    }

    fn base_fields(owner: Pubkey, amount: u64) -> TokenFields {
        TokenFields { mint: pk(1), owner, amount, delegate: None, delegated_amount: 0, close_authority: None, state: STATE_INITIALIZED }
    }

    fn base_snap(owner_program: Pubkey, token: Option<TokenFields>, data_len: usize) -> Snap {
        Snap { owner: owner_program, lamports: 1, data_len, token, tlv_hash: [0; 32] }
    }

    #[test]
    fn unchanged_is_ok_zero() {
        let vault = pk(9);
        let s = base_snap(SPL_TOKEN_ID, Some(base_fields(vault, 1_000)), TOKEN_ACCOUNT_LEN);
        assert_eq!(check_vault_invariants(&vault, &s, &s).unwrap(), 0);
    }

    #[test]
    fn amount_decrease_is_ok_delta() {
        let vault = pk(9);
        let before = base_snap(SPL_TOKEN_ID, Some(base_fields(vault, 1_000)), TOKEN_ACCOUNT_LEN);
        let after = base_snap(SPL_TOKEN_ID, Some(base_fields(vault, 400)), TOKEN_ACCOUNT_LEN);
        assert_eq!(check_vault_invariants(&vault, &before, &after).unwrap(), 600);
    }

    #[test]
    fn delegate_cleared_is_err() {
        // The critical bug this closes: a pre-existing delegate that gets
        // CLEARED during the call used to slip through (old code only
        // inspected the AFTER boolean, which reads "no delegate" either way).
        let vault = pk(9);
        let mut before_fields = base_fields(vault, 1_000);
        before_fields.delegate = Some(pk(2));
        let before = base_snap(SPL_TOKEN_ID, Some(before_fields), TOKEN_ACCOUNT_LEN);
        let after = base_snap(SPL_TOKEN_ID, Some(base_fields(vault, 1_000)), TOKEN_ACCOUNT_LEN);
        assert!(check_vault_invariants(&vault, &before, &after).is_err());
    }

    #[test]
    fn delegate_set_is_err() {
        let vault = pk(9);
        let before = base_snap(SPL_TOKEN_ID, Some(base_fields(vault, 1_000)), TOKEN_ACCOUNT_LEN);
        let mut after_fields = base_fields(vault, 1_000);
        after_fields.delegate = Some(pk(2));
        let after = base_snap(SPL_TOKEN_ID, Some(after_fields), TOKEN_ACCOUNT_LEN);
        assert!(check_vault_invariants(&vault, &before, &after).is_err());
    }

    #[test]
    fn close_authority_set_is_err() {
        let vault = pk(9);
        let before = base_snap(SPL_TOKEN_ID, Some(base_fields(vault, 1_000)), TOKEN_ACCOUNT_LEN);
        let mut after_fields = base_fields(vault, 1_000);
        after_fields.close_authority = Some(pk(3));
        let after = base_snap(SPL_TOKEN_ID, Some(after_fields), TOKEN_ACCOUNT_LEN);
        assert!(check_vault_invariants(&vault, &before, &after).is_err());
    }

    #[test]
    fn preexisting_delegate_unchanged_still_rejected_by_policy() {
        // A delegate present BOTH before and after (unchanged) must still be
        // rejected — policy is enforced on the after-state independently of
        // the unchanged-diff, closing the other half of the critical bug.
        let vault = pk(9);
        let mut fields = base_fields(vault, 1_000);
        fields.delegate = Some(pk(2));
        let snap = base_snap(SPL_TOKEN_ID, Some(fields), TOKEN_ACCOUNT_LEN);
        assert!(check_vault_invariants(&vault, &snap, &snap).is_err());
    }

    #[test]
    fn data_len_shrink_is_err() {
        let vault = pk(9);
        let before = base_snap(SPL_TOKEN_ID, Some(base_fields(vault, 1_000)), TOKEN_ACCOUNT_LEN + 100);
        let after = base_snap(SPL_TOKEN_ID, Some(base_fields(vault, 1_000)), TOKEN_ACCOUNT_LEN);
        assert!(check_vault_invariants(&vault, &before, &after).is_err());
    }

    #[test]
    fn runtime_owner_change_is_err() {
        let vault = pk(9);
        let before = base_snap(SPL_TOKEN_ID, Some(base_fields(vault, 1_000)), TOKEN_ACCOUNT_LEN);
        let after = base_snap(SPL_TOKEN_2022_ID, Some(base_fields(vault, 1_000)), TOKEN_ACCOUNT_LEN);
        assert!(check_vault_invariants(&vault, &before, &after).is_err());
    }

    #[test]
    fn tlv_hash_change_is_err() {
        let vault = pk(9);
        let mut before = base_snap(SPL_TOKEN_2022_ID, Some(base_fields(vault, 1_000)), TOKEN_ACCOUNT_LEN + 100);
        before.tlv_hash = [1; 32];
        let mut after = before.clone();
        after.tlv_hash = [2; 32];
        assert!(check_vault_invariants(&vault, &before, &after).is_err());
    }

    #[test]
    fn after_none_is_err() {
        // The other half of the critical bug: an account that becomes too
        // short/corrupted to parse must be a hard error, not a silent skip.
        let vault = pk(9);
        let before = base_snap(SPL_TOKEN_ID, Some(base_fields(vault, 1_000)), TOKEN_ACCOUNT_LEN);
        let after = base_snap(SPL_TOKEN_ID, None, 10);
        assert!(check_vault_invariants(&vault, &before, &after).is_err());
    }

    #[test]
    fn non_vault_owner_is_ignored() {
        let vault = pk(9);
        let other = pk(10);
        let before = base_snap(SPL_TOKEN_ID, Some(base_fields(other, 1_000)), TOKEN_ACCOUNT_LEN);
        let mut after_fields = base_fields(other, 1_000);
        after_fields.close_authority = Some(pk(4)); // would trip the mutation check IF vault-owned
        let after = base_snap(SPL_TOKEN_ID, Some(after_fields), TOKEN_ACCOUNT_LEN);
        assert_eq!(check_vault_invariants(&vault, &before, &after).unwrap(), 0);
    }

    #[test]
    fn malformed_coption_tag_is_parse_err() {
        let mut data = [0u8; TOKEN_ACCOUNT_LEN];
        data[108] = STATE_INITIALIZED;
        data[72..76].copy_from_slice(&7u32.to_le_bytes()); // invalid delegate tag: not 0 or 1
        assert!(parse_token_fields(&data).is_err());
    }
}
