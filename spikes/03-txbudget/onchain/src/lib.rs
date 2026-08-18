//! Spike 3b: measure the CU cost of a conservation-snapshot pass over N
//! writable token accounts — the core of Phase 1's `execute` instruction,
//! which snapshots every writable vault-owned token account before/after the
//! inner CPI and rejects the transaction if one was mutated (owner changed,
//! delegate/close-authority set, or — for Token-2022 — any TLV extension byte
//! changed) or if SOL left the vault without being accounted for.
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
///   is_native       109..121 (COption<u64>: tag u32 LE @109..113, val @113..121)
///   delegated_amount 121..129 (u64 LE)
///   close_authority 129..165 (COption<Pubkey>: tag u32 LE @129..133, key @133..165)
struct TokenFields {
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    has_delegate: bool,
    state: u8,
    has_close_authority: bool,
}

fn read_pubkey(b: &[u8], off: usize) -> Pubkey {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&b[off..off + 32]);
    Pubkey::from(buf)
}

fn parse_token_fields(data: &[u8]) -> Option<TokenFields> {
    if data.len() < TOKEN_ACCOUNT_LEN {
        return None;
    }
    let amount = u64::from_le_bytes(data[64..72].try_into().ok()?);
    let delegate_tag = u32::from_le_bytes(data[72..76].try_into().ok()?);
    let state = data[108];
    let close_authority_tag = u32::from_le_bytes(data[129..133].try_into().ok()?);
    Some(TokenFields {
        mint: read_pubkey(data, 0),
        owner: read_pubkey(data, 32),
        amount,
        has_delegate: delegate_tag != 0,
        state,
        has_close_authority: close_authority_tag != 0,
    })
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
    token: Option<(Pubkey, Pubkey, u64, bool, bool, u8)>,
    tlv_hash: [u8; 32],
}

fn snap(a: &AccountInfo) -> Result<Snap, ProgramError> {
    let data = a.try_borrow_data()?;
    let token = if *a.owner == SPL_TOKEN_ID || *a.owner == SPL_TOKEN_2022_ID {
        parse_token_fields(&data).map(|t| (t.mint, t.owner, t.amount, t.has_delegate, t.has_close_authority, t.state))
    } else {
        None
    };
    let tlv_hash = if data.len() > TOKEN_ACCOUNT_LEN {
        tlv_hash(&data[TOKEN_ACCOUNT_LEN..])
    } else {
        [0; 32]
    };
    Ok(Snap { owner: *a.owner, lamports: a.lamports(), data_len: data.len(), token, tlv_hash })
}

/// accounts[0] = vault authority pubkey (read-only marker); rest = writable
/// accounts to snapshot. data[0] = 1 -> return Custom(99) after snapshotting
/// (test negative path: caller-declared "something went wrong").
pub fn process(_pid: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let vault = accounts[0].key;
    let before: Vec<Snap> = accounts[1..].iter().map(snap).collect::<Result<_, _>>()?;
    // (a real `execute` would CPI into the target program here)
    let after: Vec<Snap> = accounts[1..].iter().map(snap).collect::<Result<_, _>>()?;
    let mut sol_out: u64 = 0;
    for (b, a) in before.iter().zip(after.iter()) {
        if b.owner != SPL_TOKEN_ID && b.owner != SPL_TOKEN_2022_ID {
            continue; // not a token account owned by an SPL program; ignore
        }
        if let (Some(tb), Some(ta)) = (&b.token, &a.token) {
            if tb.1 != *vault {
                continue; // not vault-owned; a mutation here is not our concern
            }
            let mutated = ta.1 != tb.1
                || ta.3
                || ta.4
                || ta.5 != STATE_INITIALIZED
                || a.tlv_hash != b.tlv_hash
                || a.data_len != b.data_len;
            if mutated {
                msg!("vault token account mutated");
                return Err(ProgramError::InvalidAccountData);
            }
            let dec = tb.2.checked_sub(ta.2).unwrap_or(0);
            if tb.0 == NATIVE_MINT_ID {
                sol_out = sol_out.checked_add(dec).ok_or(ProgramError::ArithmeticOverflow)?;
            }
        }
    }
    msg!("snapshots ok, sol_out={}", sol_out);
    if data.first() == Some(&1) {
        return Err(ProgramError::Custom(99));
    }
    Ok(())
}
