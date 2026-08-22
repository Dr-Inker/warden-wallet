//! Harness for the test-only `test-jup-mock` program (Task 2B smoke + Task 6
//! swap). Builds the `route` / `shared_accounts_route` instructions at Jupiter
//! v6's REAL account positions and argument layout, with the misbehave selector
//! riding in `slippage_bps` (see the mock's module docs). The Task 2B smoke
//! tests drive these directly with a payer authority; Task 6 feeds the same
//! account/data shape through warden's `swap`.
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

/// The Jupiter-role accounts a route needs; fillers are supplied by the builder.
pub struct RouteAccounts {
    pub user_transfer_authority: Pubkey,
    pub user_source_ata: Pubkey,
    pub user_destination_ata: Pubkey,
    pub destination_mint: Pubkey,
    pub platform_fee_account: Pubkey,
    pub pool_out_ata: Pubkey,
    pub pool_in_sink: Pubkey,
    /// misbehave 2: a second source ATA; misbehave 4: the delegate; misbehave
    /// 6: the MINT. Ignored otherwise. Lands at `remaining[2]`.
    pub extra: Option<Pubkey>,
    /// misbehave 6: the MintTo destination. Lands at `remaining[3]`.
    pub extra2: Option<Pubkey>,
    /// Override for the optional `destinationTokenAccount` slot (route [4]);
    /// `None` ⇒ a read-only filler. `Some((key, writable))` plants that meta.
    pub opt_dest: Option<(Pubkey, bool)>,
}

/// Jupiter v6 tail (WRDF-0031): empty `route_plan` (`u32` 0), `in_amount`,
/// `quoted_out_amount`, `slippage_bps` (= the misbehave selector), then
/// `platform_fee_bps`. **No trailing byte** — byte-identical to a real
/// empty-`route_plan` Jupiter call, which is what lets warden decode the fixed
/// tail from the END. `platform_fee_bps` is 85 to match warden's requirement.
fn route_tail(in_amount: u64, quoted_out_amount: u64, misbehave: u8) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(&0u32.to_le_bytes()); // route_plan: empty Vec
    a.extend_from_slice(&in_amount.to_le_bytes());
    a.extend_from_slice(&quoted_out_amount.to_le_bytes());
    a.extend_from_slice(&(misbehave as u16).to_le_bytes()); // slippage_bps = misbehave
    a.push(85u8); // platform_fee_bps (warden requires 85)
    a
}

/// A filler account for an optional/unused Jupiter slot (`destinationTokenAccount`,
/// `eventAuthority`, `program`, etc.) — a fresh key warden snapshots and ignores.
fn filler() -> Pubkey {
    Pubkey::new_unique()
}

/// `route` account metas at the REAL v6 positions 0..=8, then the mock's
/// `pool_authority` (9), then `remaining` (pool_out, pool_in, extra?).
pub fn route_metas(a: &RouteAccounts) -> Vec<AccountMeta> {
    let (pool, _) = pool_authority();
    let mut m = vec![
        AccountMeta::new_readonly(token_program_id(), false), // 0
        AccountMeta::new_readonly(a.user_transfer_authority, true), // 1
        AccountMeta::new(a.user_source_ata, false), // 2
        AccountMeta::new(a.user_destination_ata, false), // 3
        match a.opt_dest {
            Some((k, w)) => AccountMeta { pubkey: k, is_signer: false, is_writable: w },
            None => AccountMeta::new_readonly(filler(), false), // 4 destinationTokenAccount (opt)
        },
        AccountMeta::new_readonly(a.destination_mint, false), // 5
        AccountMeta::new(a.platform_fee_account, false), // 6
        AccountMeta::new_readonly(filler(), false), // 7 eventAuthority
        AccountMeta::new_readonly(jup_program_id(), false), // 8 program
        AccountMeta::new_readonly(pool, false), // 9 pool_authority
        AccountMeta::new(a.pool_out_ata, false), // remaining[0]
        AccountMeta::new(a.pool_in_sink, false), // remaining[1]
    ];
    if let Some(extra) = a.extra {
        m.push(AccountMeta::new(extra, false)); // remaining[2]
    }
    if let Some(extra2) = a.extra2 {
        m.push(AccountMeta::new(extra2, false)); // remaining[3]
    }
    m
}

/// `shared_accounts_route` metas at the REAL v6 positions 0..=12, then
/// `pool_authority` (13), then remaining.
pub fn shared_route_metas(a: &RouteAccounts) -> Vec<AccountMeta> {
    let (pool, _) = pool_authority();
    let mut m = vec![
        AccountMeta::new_readonly(token_program_id(), false), // 0
        AccountMeta::new_readonly(filler(), false), // 1 programAuthority
        AccountMeta::new_readonly(a.user_transfer_authority, true), // 2
        AccountMeta::new(a.user_source_ata, false), // 3 sourceTokenAccount
        AccountMeta::new(filler(), false), // 4 programSource
        AccountMeta::new(filler(), false), // 5 programDestination
        AccountMeta::new(a.user_destination_ata, false), // 6 destinationTokenAccount
        AccountMeta::new_readonly(filler(), false), // 7 sourceMint
        AccountMeta::new_readonly(a.destination_mint, false), // 8 destinationMint
        AccountMeta::new(a.platform_fee_account, false), // 9 platformFeeAccount
        AccountMeta::new_readonly(filler(), false), // 10 token2022
        AccountMeta::new_readonly(filler(), false), // 11 eventAuthority
        AccountMeta::new_readonly(jup_program_id(), false), // 12 program
        AccountMeta::new_readonly(pool, false), // 13 pool_authority
        AccountMeta::new(a.pool_out_ata, false), // remaining[0]
        AccountMeta::new(a.pool_in_sink, false), // remaining[1]
    ];
    if let Some(extra) = a.extra {
        m.push(AccountMeta::new(extra, false));
    }
    if let Some(extra2) = a.extra2 {
        m.push(AccountMeta::new(extra2, false));
    }
    m
}

pub fn route_data(in_amount: u64, quoted_out_amount: u64, misbehave: u8) -> Vec<u8> {
    let mut data = disc("route").to_vec();
    data.extend_from_slice(&route_tail(in_amount, quoted_out_amount, misbehave));
    data
}

pub fn shared_route_data(in_amount: u64, quoted_out_amount: u64, misbehave: u8) -> Vec<u8> {
    let mut data = disc("shared_accounts_route").to_vec();
    data.push(0u8); // id:u8
    data.extend_from_slice(&route_tail(in_amount, quoted_out_amount, misbehave));
    data
}

pub fn route(a: &RouteAccounts, in_amount: u64, quoted_out_amount: u64, misbehave: u8) -> Instruction {
    Instruction {
        program_id: jup_program_id(),
        accounts: route_metas(a),
        data: route_data(in_amount, quoted_out_amount, misbehave),
    }
}

pub fn shared_accounts_route(a: &RouteAccounts, in_amount: u64, quoted_out_amount: u64, misbehave: u8) -> Instruction {
    Instruction {
        program_id: jup_program_id(),
        accounts: shared_route_metas(a),
        data: shared_route_data(in_amount, quoted_out_amount, misbehave),
    }
}

pub fn instruction_discriminator(name: &str) -> [u8; 8] {
    disc(name)
}
