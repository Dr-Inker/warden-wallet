//! **Test-only Jupiter-mock program. Never deployed to any cluster.**
//!
//! Phase 1B Task 2B. Mimics Jupiter v6's `route` / `shared_accounts_route`
//! account roles closely enough that warden's `swap` adapter (Task 6) can
//! validate against it: it takes `in_amount` of the source mint out of the
//! caller's source ATA and credits the destination ATA with the output mint
//! from a pool it controls, plus a platform fee. A `misbehave: u8` argument
//! makes it deviate in exactly the ways the adapter must catch:
//!
//! - `0` honest — moves `in_amount` out, credits ≥ `min_out`, fee to the passed
//!   `platform_fee_account`.
//! - `1` credits **less** than `min_out`.
//! - `2` also debits a **second** source ATA (passed as a remaining account).
//! - `3` (plan) "fee to a non-treasury account" — realised by the CALLER
//!   passing a non-treasury account in the `platform_fee_account` slot; the mock
//!   honestly pays whatever it is given, and warden's pre-CPI meta check
//!   (`platform_fee_account == Registry.treasury`) is what rejects it. There is
//!   deliberately no mock branch for it (WRDF-0033).
//! - `4` sets a **delegate** (SPL `Approve`) on the source ATA.
//!
//! The pool ATAs are owned by a program PDA (`["pool"]`); the mock signs their
//! debits with `invoke_signed`, exactly as Jupiter's program authority does.
//! In Task 2B the smoke tests drive it with an ordinary payer as
//! `user_transfer_authority` (no warden); Task 6 drives it through `swap` with
//! the vault PDA as the authority and asserts each misbehaviour is rejected.
//!
//! SPL Token instructions are hand-encoded (Transfer 3, Approve 4) so the crate
//! stays a single `anchor-lang` dep. Program id is nothing-up-my-sleeve —
//! `sha256("WARDEN/test-jup-mock/v1")` =
//! `3dxuCX7mnVEse9PD1WSDdXYXgwFpECkJTfwsXBbPbzWU` — no keypair committed.
#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::{invoke, invoke_signed};

declare_id!("3dxuCX7mnVEse9PD1WSDdXYXgwFpECkJTfwsXBbPbzWU");

/// Seed of the PDA that owns the mock's pool ATAs.
pub const POOL_SEED: &[u8] = b"pool";
/// Fixed platform fee (output-mint base units) the mock skims — enough to be
/// observable; the exact value is not what the adapter checks (it checks the
/// fee *destination*).
const FEE: u64 = 1;

// The mock speaks Jupiter v6's REAL argument FIELD ORDER (WRDF-0031), so
// warden's `swap` adapter (Task 6) decodes `in_amount` at the same offsets it
// will on-chain, rather than against a private ABI:
//
//   route:                route_plan:Vec || in_amount:u64 || quoted_out_amount:u64 || slippage_bps:u16 || platform_fee_bps:u8
//   shared_accounts_route:  id:u8 || <the same tail>
//
// Two deliberate mock-only simplifications, neither of which shifts a Jupiter
// field warden reads: `route_plan` is modelled as an empty `Vec<u8>` (an empty
// vec is a bare `u32` zero regardless of element type, so the bytes up to
// `in_amount` are byte-identical to a real empty-route_plan Jupiter call — the
// only shape the adapter needs to decode deterministically), and the
// misbehaviour selector rides as a **trailing** `u8` AFTER every Jupiter field,
// where the real Jupiter program and warden both ignore it. The IDL provenance
// (repo commit + SHA-256) is pinned in PHASE1B-MEASUREMENTS.md by Task 6, which
// owns the byte/account fixtures generated from it.
//
// SCOPE (WRDF-0031, Task-2 terminus): this mock is faithful to Jupiter v6 in
// FIELD ORDER for the empty-`route_plan` case only. Full fidelity — modelling
// `Vec<RoutePlanStep>` (a variable-size `Swap` enum + percent/input/output),
// non-empty-plan fixtures, and the exact optional account positions
// (`destinationTokenAccount` on `route`; the program source/destination token
// accounts on `sharedAccountsRoute`) — is **Task 6's** deliverable, assembled
// independently from the pinned IDL, not this test program's. Task 2 needs a
// working, honestly-shaped CPI target; Task 6 needs the byte-exact one.
#[program]
pub mod test_jup_mock {
    use super::*;

    /// Jupiter `route` argument + account layout.
    #[allow(clippy::too_many_arguments)]
    pub fn route<'info>(
        ctx: Context<'info, Route<'info>>,
        _route_plan: Vec<u8>,
        in_amount: u64,
        quoted_out_amount: u64,
        _slippage_bps: u16,
        _platform_fee_bps: u8,
        misbehave: u8,
    ) -> Result<()> {
        do_route(&ctx.accounts.common(), ctx.remaining_accounts, in_amount, quoted_out_amount, misbehave, ctx.bumps.pool_authority)
    }

    /// Jupiter `shared_accounts_route` — a leading `id:u8`, the same argument
    /// tail, and a leading `program_authority` account the mock does not use.
    #[allow(clippy::too_many_arguments)]
    pub fn shared_accounts_route<'info>(
        ctx: Context<'info, SharedRoute<'info>>,
        _id: u8,
        _route_plan: Vec<u8>,
        in_amount: u64,
        quoted_out_amount: u64,
        _slippage_bps: u16,
        _platform_fee_bps: u8,
        misbehave: u8,
    ) -> Result<()> {
        do_route(&ctx.accounts.common(), ctx.remaining_accounts, in_amount, quoted_out_amount, misbehave, ctx.bumps.pool_authority)
    }
}

/// The accounts both variants share, gathered so `do_route` is layout-agnostic.
struct Common<'a, 'info> {
    token_program: &'a AccountInfo<'info>,
    user_transfer_authority: &'a AccountInfo<'info>,
    user_source_ata: &'a AccountInfo<'info>,
    user_destination_ata: &'a AccountInfo<'info>,
    platform_fee_account: &'a AccountInfo<'info>,
    pool_authority: &'a AccountInfo<'info>,
    pool_out_ata: &'a AccountInfo<'info>,
    pool_in_sink: &'a AccountInfo<'info>,
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

    // (1) Take the input: user_source_ata -> pool_in_sink, signed by the caller.
    spl_transfer(
        c.token_program,
        c.user_source_ata,
        c.pool_in_sink,
        c.user_transfer_authority,
        in_amount,
        None,
    )?;

    // (misbehave 2) also debit a second source ATA passed as a remaining account.
    if misbehave == 2 {
        let second = remaining.first().expect("misbehave 2 needs a second source ATA");
        spl_transfer(c.token_program, second, c.pool_in_sink, c.user_transfer_authority, 1, None)?;
    }

    // (misbehave 4) set a delegate on the source ATA (SPL Approve).
    if misbehave == 4 {
        let delegate = remaining.first().expect("misbehave 4 needs a delegate account");
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
    spl_transfer(
        c.token_program,
        c.pool_out_ata,
        c.user_destination_ata,
        c.pool_authority,
        out_amount,
        Some(pool_seeds),
    )?;

    // (3) Platform fee (output mint) — ALWAYS to the passed `platform_fee_account`
    // (WRDF-0033). The mock never diverts the fee itself: a real Jupiter route
    // pays the platform-fee account it is given, and warden's control is a
    // pre-CPI check that that account == `Registry.treasury`. The "fee to a
    // non-treasury account" case (plan misbehave 3) is therefore realised by the
    // CALLER substituting a non-treasury account into this validated slot, not by
    // a mock branch — an internal divert between two external accounts would be
    // invisible to both warden's meta check and its vault-only conservation, so
    // it would model a threat warden does not (and need not) defend against.
    let _ = misbehave; // 3 is a caller-side account substitution, not a mock branch
    spl_transfer(c.token_program, c.pool_out_ata, c.platform_fee_account, c.pool_authority, FEE, Some(pool_seeds))?;

    Ok(())
}

// All accounts are `UncheckedAccount` on purpose: this is a test program that
// forwards accounts to SPL Token, so warden's checks are the ones under test.
// `pool_authority` is the one constrained account — its PDA-ness is what lets
// the mock sign the pool debits.
#[derive(Accounts)]
pub struct Route<'info> {
    /// CHECK: SPL Token program
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: the authority that signs the source debit (payer or vault PDA)
    pub user_transfer_authority: UncheckedAccount<'info>,
    /// CHECK: vault ATA of in_mint
    #[account(mut)]
    pub user_source_ata: UncheckedAccount<'info>,
    /// CHECK: vault ATA of out_mint
    #[account(mut)]
    pub user_destination_ata: UncheckedAccount<'info>,
    /// CHECK: out_mint
    pub destination_mint: UncheckedAccount<'info>,
    /// CHECK: treasury ATA the fee should go to
    #[account(mut)]
    pub platform_fee_account: UncheckedAccount<'info>,
    /// CHECK: PDA that owns the pool ATAs; seeds ["pool"]
    #[account(seeds = [POOL_SEED], bump)]
    pub pool_authority: UncheckedAccount<'info>,
    /// CHECK: pool ATA of out_mint (mock credits from here)
    #[account(mut)]
    pub pool_out_ata: UncheckedAccount<'info>,
    /// CHECK: pool ATA of in_mint (mock deposits the input here)
    #[account(mut)]
    pub pool_in_sink: UncheckedAccount<'info>,
}

impl<'info> Route<'info> {
    fn common(&self) -> Common<'_, 'info> {
        Common {
            token_program: self.token_program.as_ref(),
            user_transfer_authority: self.user_transfer_authority.as_ref(),
            user_source_ata: self.user_source_ata.as_ref(),
            user_destination_ata: self.user_destination_ata.as_ref(),
            platform_fee_account: self.platform_fee_account.as_ref(),
            pool_authority: self.pool_authority.as_ref(),
            pool_out_ata: self.pool_out_ata.as_ref(),
            pool_in_sink: self.pool_in_sink.as_ref(),
        }
    }
}

#[derive(Accounts)]
pub struct SharedRoute<'info> {
    /// CHECK: SPL Token program
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: Jupiter's shared program authority — unused by the mock, present
    /// so warden validates the shared layout's extra leading account.
    pub program_authority: UncheckedAccount<'info>,
    /// CHECK: the authority that signs the source debit
    pub user_transfer_authority: UncheckedAccount<'info>,
    /// CHECK: vault ATA of in_mint
    #[account(mut)]
    pub user_source_ata: UncheckedAccount<'info>,
    /// CHECK: vault ATA of out_mint
    #[account(mut)]
    pub user_destination_ata: UncheckedAccount<'info>,
    /// CHECK: out_mint
    pub destination_mint: UncheckedAccount<'info>,
    /// CHECK: treasury ATA
    #[account(mut)]
    pub platform_fee_account: UncheckedAccount<'info>,
    /// CHECK: PDA that owns the pool ATAs
    #[account(seeds = [POOL_SEED], bump)]
    pub pool_authority: UncheckedAccount<'info>,
    /// CHECK: pool ATA of out_mint
    #[account(mut)]
    pub pool_out_ata: UncheckedAccount<'info>,
    /// CHECK: pool ATA of in_mint
    #[account(mut)]
    pub pool_in_sink: UncheckedAccount<'info>,
}

impl<'info> SharedRoute<'info> {
    fn common(&self) -> Common<'_, 'info> {
        Common {
            token_program: self.token_program.as_ref(),
            user_transfer_authority: self.user_transfer_authority.as_ref(),
            user_source_ata: self.user_source_ata.as_ref(),
            user_destination_ata: self.user_destination_ata.as_ref(),
            platform_fee_account: self.platform_fee_account.as_ref(),
            pool_authority: self.pool_authority.as_ref(),
            pool_out_ata: self.pool_out_ata.as_ref(),
            pool_in_sink: self.pool_in_sink.as_ref(),
        }
    }
}
