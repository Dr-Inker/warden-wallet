//! Harness for the test-only `test-jup-mock` program (Phase 1B Task 2B).
//!
//! Loads its `.so`, exposes the pool PDA + its ATAs, and builds the two
//! Jupiter-shaped instructions (`route`, `shared_accounts_route`) with a
//! `misbehave` selector. The Task 2B smoke tests drive these with a payer
//! authority; Task 6 feeds the same instructions through `swap`.
#![allow(dead_code)]

use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use litesvm::LiteSVM;
use solana_sdk::pubkey::Pubkey;

use super::token::token_program_id;

/// Program id of `test-jup-mock` — `sha256("WARDEN/test-jup-mock/v1")`.
pub fn jup_program_id() -> Pubkey {
    Pubkey::from_str_const("3dxuCX7mnVEse9PD1WSDdXYXgwFpECkJTfwsXBbPbzWU")
}

/// The mock's pool authority PDA (seeds `["pool"]`) — owner of the pool ATAs.
pub fn pool_authority() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"pool"], &jup_program_id())
}

pub fn add_jup_mock(svm: &mut LiteSVM) -> Pubkey {
    let so = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/deploy/test_jup_mock.so"
    ))
    .expect("run `anchor build` first — see docs/TOOLCHAIN.md");
    let id = jup_program_id();
    svm.add_program(id, &so).expect("add_program(test_jup_mock)");
    id
}

fn disc(name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"global:");
    h.update(name.as_bytes());
    let mut d = [0u8; 8];
    d.copy_from_slice(&h.finalize()[..8]);
    d
}

/// The accounts a route needs, in the mock's `route` order.
pub struct RouteAccounts {
    pub user_transfer_authority: Pubkey,
    pub user_source_ata: Pubkey,
    pub user_destination_ata: Pubkey,
    pub destination_mint: Pubkey,
    pub platform_fee_account: Pubkey,
    pub pool_out_ata: Pubkey,
    pub pool_in_sink: Pubkey,
    /// misbehave 2: a second source ATA; misbehave 4: the delegate. Ignored otherwise.
    pub extra: Option<Pubkey>,
}

fn args(in_amount: u64, min_out: u64, misbehave: u8) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(&in_amount.to_le_bytes());
    a.extend_from_slice(&min_out.to_le_bytes());
    a.push(misbehave);
    a
}

fn base_metas(a: &RouteAccounts) -> Vec<AccountMeta> {
    let (pool, _) = pool_authority();
    let mut m = vec![
        AccountMeta::new_readonly(token_program_id(), false),
        AccountMeta::new_readonly(a.user_transfer_authority, true),
        AccountMeta::new(a.user_source_ata, false),
        AccountMeta::new(a.user_destination_ata, false),
        AccountMeta::new_readonly(a.destination_mint, false),
        AccountMeta::new(a.platform_fee_account, false),
        AccountMeta::new_readonly(pool, false),
        AccountMeta::new(a.pool_out_ata, false),
        AccountMeta::new(a.pool_in_sink, false),
    ];
    if let Some(extra) = a.extra {
        // misbehave 2 (second source, mut) / misbehave 4 (delegate, readonly) —
        // pass mut so either use is satisfiable in one shape.
        m.push(AccountMeta::new(extra, false));
    }
    m
}

pub fn route(a: &RouteAccounts, in_amount: u64, min_out: u64, misbehave: u8) -> Instruction {
    let mut data = disc("route").to_vec();
    data.extend_from_slice(&args(in_amount, min_out, misbehave));
    Instruction { program_id: jup_program_id(), accounts: base_metas(a), data }
}

pub fn shared_accounts_route(a: &RouteAccounts, in_amount: u64, min_out: u64, misbehave: u8) -> Instruction {
    let (pool, _) = pool_authority();
    let mut metas = vec![
        AccountMeta::new_readonly(token_program_id(), false),
        // shared program authority (unused by the mock) — pool PDA stands in.
        AccountMeta::new_readonly(pool, false),
        AccountMeta::new_readonly(a.user_transfer_authority, true),
        AccountMeta::new(a.user_source_ata, false),
        AccountMeta::new(a.user_destination_ata, false),
        AccountMeta::new_readonly(a.destination_mint, false),
        AccountMeta::new(a.platform_fee_account, false),
        AccountMeta::new_readonly(pool, false),
        AccountMeta::new(a.pool_out_ata, false),
        AccountMeta::new(a.pool_in_sink, false),
    ];
    if let Some(extra) = a.extra {
        metas.push(AccountMeta::new(extra, false));
    }
    let mut data = disc("shared_accounts_route").to_vec();
    data.extend_from_slice(&args(in_amount, min_out, misbehave));
    Instruction { program_id: jup_program_id(), accounts: metas, data }
}

pub fn instruction_discriminator(name: &str) -> [u8; 8] {
    disc(name)
}
