//! **Test-only Jupiter-mock program. Never deployed to any cluster.**
//!
//! Phase 1B Task 2B + Task 6. Mimics Jupiter v6's `route` /
//! `shared_accounts_route` **byte-for-byte in argument order AND in account
//! position** (against the pinned v6 IDL — provenance in
//! `docs/program/PHASE1B-MEASUREMENTS.md` §"Task 6 Jupiter IDL provenance"), so
//! warden's `swap` adapter validates against exactly the layout it will meet on
//! mainnet. It takes `in_amount` of the source mint out of the caller's source
//! ATA and credits the destination ATA with the output mint from a pool it
//! controls, plus a platform fee.
//!
//! ## The `misbehave` selector rides in `slippage_bps` (Task 6)
//!
//! Warden decodes the fixed 19-byte argument TAIL (`in_amount ‖ quoted_out ‖
//! slippage_bps ‖ platform_fee_bps`) from the END of the instruction data —
//! `route_plan` is variable-length and comes first, so the fields warden reads
//! are all at fixed negative offsets. For that decode to be exact the mock's
//! bytes must equal a real Jupiter call's with NO trailing extra. So the mock
//! carries no trailing byte: the misbehaviour selector is the low byte of
//! **`slippage_bps`**, a field warden deliberately does not check (price sanity
//! is the extension's job, spec §5.2.7). The data is therefore byte-identical to
//! a genuine empty-`route_plan` Jupiter instruction.
//!
//! - `0` honest — moves `in_amount` out, credits `quoted_out`, fee to the passed
//!   `platform_fee_account`.
//! - `1` credits **less** than `quoted_out` (fails `min_out`).
//! - `2` also debits a **second** source ATA (passed as a remaining account).
//! - `3` (plan) "fee to a non-treasury account" — realised by the CALLER
//!   passing a non-treasury account in the fee slot; the mock honestly pays
//!   whatever it is given and warden's pre-CPI meta check rejects it. No mock
//!   branch (WRDF-0033).
//! - `4` sets a **delegate** (SPL `Approve`) on the source ATA.
//! - `5` (GROK-EXP-01) pays only **1 base unit** of platform fee instead of the
//!   85 bps the honest path pays — the "existence-only fee" shape.
//! - `6` (GROK-EXP-05) additionally **`MintTo`s** `remaining[3]` from the mint
//!   at `remaining[2]`, signed by `user_transfer_authority` (the vault PDA,
//!   which warden forwards as a signer) — the nested-issuance shape a hop
//!   program could perform if the PDA is that mint's authority.
//!
//! ## Account positions (real Jupiter v6, IDL-pinned)
//!
//! `route`: `[0 tokenProgram, 1 userTransferAuthority(signer), 2
//! userSourceTokenAccount, 3 userDestinationTokenAccount, 4
//! destinationTokenAccount(opt), 5 destinationMint, 6 platformFeeAccount(opt),
//! 7 eventAuthority, 8 program]`, then AMM remaining accounts. The mock puts its
//! `pool_authority` PDA at index 9 and `pool_out`/`pool_in` (+ a misbehave
//! extra) in `remaining_accounts` — mirroring how Jupiter's real per-AMM
//! accounts ride after the fixed prefix. `shared_accounts_route` adds a leading
//! `programAuthority` and splits source/destination mints (see `SharedRoute`).
//!
//! The pool ATAs are owned by `["pool"]`; the mock signs their debits with
//! `invoke_signed`. Program id is nothing-up-my-sleeve —
//! `sha256("WARDEN/test-jup-mock/v1")` =
//! `3dxuCX7mnVEse9PD1WSDdXYXgwFpECkJTfwsXBbPbzWU`.
#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::{invoke, invoke_signed};

declare_id!("3dxuCX7mnVEse9PD1WSDdXYXgwFpECkJTfwsXBbPbzWU");

/// Seed of the PDA that owns the mock's pool ATAs.
pub const POOL_SEED: &[u8] = b"pool";
/// The platform-fee rate the honest path pays, as Jupiter does: `floor(quoted
/// × bps / 10_000)` of the OUTPUT leg, taken from the pool on top of the
/// user's credit. Warden requires exactly this rate (GROK-EXP-01 made the
/// realised-fee floor load-bearing, so the mock must pay a realistic fee).
const PLATFORM_FEE_BPS: u64 = 85;

#[program]
pub mod test_jup_mock {
    use super::*;

    /// Jupiter v6 `route`: variable `route_plan` first, then the fixed tail.
    /// `slippage_bps` carries the misbehave selector (module docs).
    #[allow(clippy::too_many_arguments)]
    pub fn route<'info>(
        ctx: Context<'info, Route<'info>>,
        _route_plan: Vec<u8>,
        in_amount: u64,
        quoted_out_amount: u64,
        slippage_bps: u16,
        _platform_fee_bps: u8,
    ) -> Result<()> {
        let c = Common {
            token_program: ctx.accounts.token_program.as_ref(),
            user_transfer_authority: ctx.accounts.user_transfer_authority.as_ref(),
            user_source_ata: ctx.accounts.user_source_ata.as_ref(),
            user_destination_ata: ctx.accounts.user_destination_ata.as_ref(),
            platform_fee_account: ctx.accounts.platform_fee_account.as_ref(),
            pool_authority: ctx.accounts.pool_authority.as_ref(),
        };
        do_route(&c, ctx.remaining_accounts, in_amount, quoted_out_amount, slippage_bps as u8, ctx.bumps.pool_authority)
    }

    /// Jupiter v6 `shared_accounts_route` — leading `id:u8`, a leading
    /// `programAuthority`, split source/destination mints; same fixed tail.
    #[allow(clippy::too_many_arguments)]
    pub fn shared_accounts_route<'info>(
        ctx: Context<'info, SharedRoute<'info>>,
        _id: u8,
        _route_plan: Vec<u8>,
        in_amount: u64,
        quoted_out_amount: u64,
        slippage_bps: u16,
        _platform_fee_bps: u8,
    ) -> Result<()> {
        let c = Common {
            token_program: ctx.accounts.token_program.as_ref(),
            user_transfer_authority: ctx.accounts.user_transfer_authority.as_ref(),
            user_source_ata: ctx.accounts.source_token_account.as_ref(),
            user_destination_ata: ctx.accounts.destination_token_account.as_ref(),
            platform_fee_account: ctx.accounts.platform_fee_account.as_ref(),
            pool_authority: ctx.accounts.pool_authority.as_ref(),
        };
        do_route(&c, ctx.remaining_accounts, in_amount, quoted_out_amount, slippage_bps as u8, ctx.bumps.pool_authority)
    }
}

/// The accounts both variants share, gathered so `do_route` is layout-agnostic.
/// `pool_out`/`pool_in` (and any misbehave extra) come from `remaining_accounts`.
struct Common<'a, 'info> {
    token_program: &'a AccountInfo<'info>,
    user_transfer_authority: &'a AccountInfo<'info>,
    user_source_ata: &'a AccountInfo<'info>,
    user_destination_ata: &'a AccountInfo<'info>,
    platform_fee_account: &'a AccountInfo<'info>,
    pool_authority: &'a AccountInfo<'info>,
}

fn spl_transfer<'info>(
    token_program: &AccountInfo<'info>,
    source: &AccountInfo<'info>,
    destination: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    amount: u64,
    signer_seeds: Option<&[&[&[u8]]]>,
) -> Result<()> {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    let ix = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(*source.key, false),
            AccountMeta::new(*destination.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
        data,
    };
    let infos = [source.clone(), destination.clone(), authority.clone()];
    match signer_seeds {
        Some(seeds) => invoke_signed(&ix, &infos, seeds)?,
        None => invoke(&ix, &infos)?,
    }
    Ok(())
}

fn do_route<'info>(
    c: &Common<'_, 'info>,
    remaining: &[AccountInfo<'info>],
    in_amount: u64,
    quoted_out_amount: u64,
    misbehave: u8,
    pool_bump: u8,
) -> Result<()> {
    let pool_seeds: &[&[&[u8]]] = &[&[POOL_SEED, &[pool_bump]]];
    // remaining = [pool_out_ata, pool_in_sink, (misbehave extra)?]
    let pool_out = remaining.first().expect("pool_out_ata");
    let pool_in = remaining.get(1).expect("pool_in_sink");

    // (1) Take the input: user_source_ata -> pool_in, signed by the caller.
    spl_transfer(c.token_program, c.user_source_ata, pool_in, c.user_transfer_authority, in_amount, None)?;

    // (misbehave 2) also debit a second source ATA passed as a remaining account.
    if misbehave == 2 {
        let second = remaining.get(2).expect("misbehave 2 needs a second source ATA");
        spl_transfer(c.token_program, second, pool_in, c.user_transfer_authority, 1, None)?;
    }

    // (misbehave 4) set a delegate on the source ATA (SPL Approve).
    if misbehave == 4 {
        let delegate = remaining.get(2).expect("misbehave 4 needs a delegate account");
        let mut data = vec![4u8];
        data.extend_from_slice(&1u64.to_le_bytes());
        let ix = Instruction {
            program_id: *c.token_program.key,
            accounts: vec![
                AccountMeta::new(*c.user_source_ata.key, false),
                AccountMeta::new_readonly(*delegate.key, false),
                AccountMeta::new_readonly(*c.user_transfer_authority.key, true),
            ],
            data,
        };
        invoke(&ix, &[c.user_source_ata.clone(), delegate.clone(), c.user_transfer_authority.clone()])?;
    }

    // (2) Credit the output from the pool, signed by the pool PDA.
    let out_amount = if misbehave == 1 { quoted_out_amount.saturating_sub(1) } else { quoted_out_amount };
    spl_transfer(c.token_program, pool_out, c.user_destination_ata, c.pool_authority, out_amount, Some(pool_seeds))?;

    // (misbehave 6) nested MintTo under the forwarded user authority: mint at
    // remaining[2], destination at remaining[3]. A real hop with the PDA as
    // `mint_authority` could do exactly this; warden must reject it.
    if misbehave == 6 {
        let mint = remaining.get(2).expect("misbehave 6 needs the mint");
        let dest = remaining.get(3).expect("misbehave 6 needs a destination");
        let mut data = vec![7u8]; // TokenInstruction::MintTo
        data.extend_from_slice(&42_000u64.to_le_bytes());
        let ix = Instruction {
            program_id: *c.token_program.key,
            accounts: vec![
                AccountMeta::new(*mint.key, false),
                AccountMeta::new(*dest.key, false),
                AccountMeta::new_readonly(*c.user_transfer_authority.key, true),
            ],
            data,
        };
        invoke(&ix, &[mint.clone(), dest.clone(), c.user_transfer_authority.clone()])?;
    }

    // (3) Platform fee (output mint) — ALWAYS to the passed `platform_fee_account`
    // (WRDF-0033); the "wrong fee account" case is a caller-side substitution the
    // mock does not model, because warden's pre-CPI meta check owns it.
    // Honest: floor(quoted × 85 / 10_000). (misbehave 5) 1 base unit only.
    let fee = if misbehave == 5 {
        1
    } else {
        quoted_out_amount.saturating_mul(PLATFORM_FEE_BPS) / 10_000
    };
    spl_transfer(c.token_program, pool_out, c.platform_fee_account, c.pool_authority, fee, Some(pool_seeds))?;

    Ok(())
}

// All Jupiter-role accounts are `UncheckedAccount`: this is a test CPI target,
// so warden's checks are the ones under test. Fillers mirror Jupiter's fixed
// positions so warden validates against the real index map. `pool_authority`
// (the one constrained account) signs the pool debits.
#[derive(Accounts)]
pub struct Route<'info> {
    /// CHECK: [0] SPL Token program
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: [1] user_transfer_authority — the signer (payer or vault PDA)
    pub user_transfer_authority: UncheckedAccount<'info>,
    /// CHECK: [2] user_source_token_account = vault ATA(in_mint)
    #[account(mut)]
    pub user_source_ata: UncheckedAccount<'info>,
    /// CHECK: [3] user_destination_token_account = vault ATA(out_mint)
    #[account(mut)]
    pub user_destination_ata: UncheckedAccount<'info>,
    /// CHECK: [4] destinationTokenAccount (optional in v6) — filler, unused
    pub destination_token_account: UncheckedAccount<'info>,
    /// CHECK: [5] destination_mint = out_mint
    pub destination_mint: UncheckedAccount<'info>,
    /// CHECK: [6] platform_fee_account = treasury ATA
    #[account(mut)]
    pub platform_fee_account: UncheckedAccount<'info>,
    /// CHECK: [7] eventAuthority — filler, unused
    pub event_authority: UncheckedAccount<'info>,
    /// CHECK: [8] program — filler, unused
    pub program: UncheckedAccount<'info>,
    /// CHECK: [9] pool authority PDA (seeds ["pool"]) — AMM remaining in real v6
    #[account(seeds = [POOL_SEED], bump)]
    pub pool_authority: UncheckedAccount<'info>,
    // remaining_accounts: [pool_out_ata, pool_in_sink, (misbehave extra)?]
}

#[derive(Accounts)]
pub struct SharedRoute<'info> {
    /// CHECK: [0] SPL Token program
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: [1] programAuthority — filler, unused
    pub program_authority: UncheckedAccount<'info>,
    /// CHECK: [2] user_transfer_authority — signer
    pub user_transfer_authority: UncheckedAccount<'info>,
    /// CHECK: [3] source_token_account = vault ATA(in_mint)
    #[account(mut)]
    pub source_token_account: UncheckedAccount<'info>,
    /// CHECK: [4] program_source_token_account — filler mut
    #[account(mut)]
    pub program_source: UncheckedAccount<'info>,
    /// CHECK: [5] program_destination_token_account — filler mut
    #[account(mut)]
    pub program_destination: UncheckedAccount<'info>,
    /// CHECK: [6] destination_token_account = vault ATA(out_mint)
    #[account(mut)]
    pub destination_token_account: UncheckedAccount<'info>,
    /// CHECK: [7] source_mint — filler
    pub source_mint: UncheckedAccount<'info>,
    /// CHECK: [8] destination_mint = out_mint
    pub destination_mint: UncheckedAccount<'info>,
    /// CHECK: [9] platform_fee_account = treasury ATA
    #[account(mut)]
    pub platform_fee_account: UncheckedAccount<'info>,
    /// CHECK: [10] token2022 program (optional) — filler
    pub token_2022_program: UncheckedAccount<'info>,
    /// CHECK: [11] eventAuthority — filler
    pub event_authority: UncheckedAccount<'info>,
    /// CHECK: [12] program — filler
    pub program: UncheckedAccount<'info>,
    /// CHECK: [13] pool authority PDA (seeds ["pool"])
    #[account(seeds = [POOL_SEED], bump)]
    pub pool_authority: UncheckedAccount<'info>,
    // remaining_accounts: [pool_out_ata, pool_in_sink, (misbehave extra)?]
}
