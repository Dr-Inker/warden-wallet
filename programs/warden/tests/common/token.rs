//! SPL Token fixtures: plant a mint and token accounts directly with
//! `svm.set_account`, rather than driving `spl_token`'s
//! `InitializeMint`/`InitializeAccount` instructions.
//!
//! Planting is deliberate. What `tests/transfer.rs` needs is a *vault ATA
//! holding a balance* and a *destination token account*, in whatever
//! configuration the test under examination calls for — including
//! configurations no honest sequence of SPL instructions produces (a
//! destination owned by the vault itself, a token account of the wrong mint).
//! Driving the real instructions would cost several transactions per fixture
//! and still could not build the adversarial shapes.
//!
//! The *bytes* are produced by the real `spl_token` crate
//! (`state::Account::pack` / `state::Mint::pack`), not hand-rolled, so a
//! layout change in SPL Token would break these fixtures loudly rather than
//! silently drift from what the on-chain program parses. `spl-token` is a
//! **dev-dependency only** — the program itself hardcodes the program id and
//! parses the 165-byte body at fixed offsets (see
//! `warden::instructions::transfer`, and spike 3b's finding on why the crate
//! cannot be imported program-side).

#![allow(dead_code)]

use litesvm::LiteSVM;
use solana_sdk::{account::Account, program_option::COption, program_pack::Pack, pubkey::Pubkey};
use spl_token::state::{Account as SplAccount, AccountState, Mint};

/// `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`, from the crate itself.
pub fn token_program_id() -> Pubkey {
    spl_token::ID
}

/// The Associated Token Account program id — used only to derive realistic
/// ATA addresses. `warden::transfer` does NOT require the vault's token
/// account to be an ATA (any token account owned by the vault authority
/// works); the tests use real ATA addresses because that is what the
/// extension will actually pass.
pub fn ata_program_id() -> Pubkey {
    Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
}

pub fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program_id().as_ref(), mint.as_ref()],
        &ata_program_id(),
    )
    .0
}

/// Plant an initialized mint with no mint/freeze authority.
pub fn set_mint(svm: &mut LiteSVM, mint: &Pubkey, decimals: u8, supply: u64) {
    let m = Mint {
        mint_authority: COption::None,
        supply,
        decimals,
        is_initialized: true,
        freeze_authority: COption::None,
    };
    let mut data = vec![0u8; Mint::LEN];
    m.pack_into_slice(&mut data);
    svm.set_account(
        *mint,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(Mint::LEN),
            data,
            owner: token_program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account (mint)");
}

/// Plant an initialized token account holding `amount` of `mint`, owned (at
/// the token level) by `owner`.
pub fn set_token_account(svm: &mut LiteSVM, address: &Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) {
    let a = SplAccount {
        mint: *mint,
        owner: *owner,
        amount,
        delegate: COption::None,
        state: AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    };
    let mut data = vec![0u8; SplAccount::LEN];
    a.pack_into_slice(&mut data);
    svm.set_account(
        *address,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(SplAccount::LEN),
            data,
            owner: token_program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account (token account)");
}

/// Read a token account's balance back out of the SVM through the real
/// `spl_token` unpacker.
pub fn token_amount(svm: &LiteSVM, address: &Pubkey) -> u64 {
    let raw = svm.get_account(address).expect("token account exists").data;
    SplAccount::unpack(&raw).expect("valid token account").amount
}
