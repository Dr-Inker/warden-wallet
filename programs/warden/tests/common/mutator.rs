//! Harness for the test-only `test-mutator` program (Phase 1B Task 2A).
//!
//! Loads its `.so` and builds each instruction. The mutator's whole purpose is
//! to attempt a mutation `execute`'s conservation checks must catch; these
//! helpers let the Task 2A smoke tests drive each op directly (payer as the SPL
//! authority, no warden) and let Task 5 build the same instructions to feed
//! through `execute`.
#![allow(dead_code)]

use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use litesvm::LiteSVM;
use solana_sdk::pubkey::Pubkey;

use super::token::token_program_id;

/// Program id of `test-mutator` — nothing-up-my-sleeve
/// `sha256("WARDEN/test-mutator/v1")`, pinned so the suite needs no dep on it.
pub fn mutator_program_id() -> Pubkey {
    Pubkey::from_str_const("An3yCfK4dXet5wEHRYT23gyS1CJbeGD5E2enchQLo49W")
}

pub fn add_mutator(svm: &mut LiteSVM) -> Pubkey {
    let so = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/deploy/test_mutator.so"
    ))
    .expect("run `anchor build` first — see docs/TOOLCHAIN.md");
    let id = mutator_program_id();
    svm.add_program(id, &so).expect("add_program(test_mutator)");
    id
}

/// Anchor's 8-byte instruction discriminator, `sha256("global:<name>")[..8]`.
fn disc(name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"global:");
    h.update(name.as_bytes());
    let out = h.finalize();
    let mut d = [0u8; 8];
    d.copy_from_slice(&out[..8]);
    d
}

fn ix(name: &str, args: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = disc(name).to_vec();
    data.extend_from_slice(args);
    Instruction { program_id: mutator_program_id(), accounts, data }
}

pub fn noop() -> Instruction {
    ix("noop", &[], vec![])
}

pub fn transfer_out(source: Pubkey, destination: Pubkey, authority: Pubkey, amount: u64) -> Instruction {
    ix(
        "transfer_out",
        &amount.to_le_bytes(),
        vec![
            AccountMeta::new(source, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(token_program_id(), false),
        ],
    )
}

pub fn set_delegate(source: Pubkey, delegate: Pubkey, authority: Pubkey, amount: u64) -> Instruction {
    ix(
        "set_delegate",
        &amount.to_le_bytes(),
        vec![
            AccountMeta::new(source, false),
            AccountMeta::new_readonly(delegate, false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(token_program_id(), false),
        ],
    )
}

fn set_authority_ix(name: &str, account: Pubkey, new_authority: Pubkey, authority: Pubkey) -> Instruction {
    ix(
        name,
        &[],
        vec![
            AccountMeta::new(account, false),
            AccountMeta::new_readonly(new_authority, false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(token_program_id(), false),
        ],
    )
}

pub fn set_close_authority(account: Pubkey, new_authority: Pubkey, authority: Pubkey) -> Instruction {
    set_authority_ix("set_close_authority", account, new_authority, authority)
}

pub fn set_owner(account: Pubkey, new_owner: Pubkey, authority: Pubkey) -> Instruction {
    set_authority_ix("set_owner", account, new_owner, authority)
}

fn close_ix(name: &str, account: Pubkey, destination: Pubkey, authority: Pubkey) -> Instruction {
    ix(
        name,
        &[],
        vec![
            AccountMeta::new(account, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(token_program_id(), false),
        ],
    )
}

pub fn close_account(account: Pubkey, destination: Pubkey, authority: Pubkey) -> Instruction {
    close_ix("close_account", account, destination, authority)
}

pub fn close_zero_balance_ata_to_stranger(account: Pubkey, destination: Pubkey, authority: Pubkey) -> Instruction {
    close_ix("close_zero_balance_ata_to_stranger", account, destination, authority)
}

pub fn realloc_self(state: Pubkey, new_len: u64) -> Instruction {
    ix("realloc_self", &new_len.to_le_bytes(), vec![AccountMeta::new(state, false)])
}

pub fn drain_lamports(source: Pubkey, destination: Pubkey, amount: u64) -> Instruction {
    ix(
        "drain_lamports",
        &amount.to_le_bytes(),
        vec![AccountMeta::new(source, false), AccountMeta::new(destination, false)],
    )
}

/// `reenter_warden(data)` — the named `warden_program` account plus every
/// account the forwarded warden instruction needs as `remaining_accounts`.
pub fn reenter_warden(warden_program: Pubkey, data: Vec<u8>, remaining: Vec<AccountMeta>) -> Instruction {
    let mut accounts = vec![AccountMeta::new_readonly(warden_program, false)];
    accounts.extend(remaining);
    // Borsh `Vec<u8>` = u32 len + bytes.
    let mut args = (data.len() as u32).to_le_bytes().to_vec();
    args.extend_from_slice(&data);
    ix("reenter_warden", &args, accounts)
}

/// Anchor discriminator (`sha256("global:<name>")[..8]`), exposed so Task 5 can
/// also reach it if needed.
pub fn instruction_discriminator(name: &str) -> [u8; 8] {
    disc(name)
}
