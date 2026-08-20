//! **Test-only mutator program. Never deployed to any cluster.**
//!
//! Phase 1B Task 2. Warden's `execute` (Task 5) drives dApp instructions by
//! CPI-ing into a middleman program that then CPIs SPL Token as the vault PDA
//! authority (the PDA's signer privilege, granted by warden's `invoke_signed`,
//! propagates down the plain `invoke` here). This program is that middleman for
//! the *adversarial* cases: every instruction attempts exactly one mutation the
//! conservation checks (§5.2) must catch when it is reached through `execute` —
//! setting a delegate, changing an owner/close-authority, closing an account,
//! reallocating a vault-owned non-token account, draining raw lamports, or
//! re-entering warden. In Task 2 the smoke tests here drive each op with an
//! ordinary payer as the authority (no warden in the loop) to prove the CPI
//! plumbing itself works; Task 5 drives the same ops *through* `execute` and
//! asserts each is rejected.
//!
//! SPL Token instructions are constructed by hand from their stable on-wire
//! encodings (Transfer 3, Approve 4, SetAuthority 6, CloseAccount 9) rather
//! than through a crate dependency, so this test crate stays a single
//! `anchor-lang` dep like `test-middleman` and never risks an SBF
//! dependency-version mismatch with warden's pinned `spl-token`.
//!
//! Program id is nothing-up-my-sleeve — `sha256("WARDEN/test-mutator/v1")` =
//! `An3yCfK4dXet5wEHRYT23gyS1CJbeGD5E2enchQLo49W` — so no keypair exists or is
//! committed (docs/PROGRAM-KEYS.md). LiteSVM loads programs by id + bytes.

// Anchor's `#[program]`/`#[derive(Accounts)]` macros emit `cfg(custom-heap)` /
// `cfg(solana)` checks that recent rustc flags as `unexpected_cfgs`; they are
// macro-internal, not our configuration, so silence just that lint here.
#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke;

declare_id!("An3yCfK4dXet5wEHRYT23gyS1CJbeGD5E2enchQLo49W");

/// SPL Token `AuthorityType` discriminants (stable ABI).
const AUTH_TYPE_ACCOUNT_OWNER: u8 = 2;
const AUTH_TYPE_CLOSE_ACCOUNT: u8 = 3;

/// `Some(pubkey)` in SPL Token's `COption<Pubkey>` wire form: tag 1 then 32 bytes.
fn coption_some(key: &Pubkey) -> Vec<u8> {
    let mut v = Vec::with_capacity(33);
    v.push(1);
    v.extend_from_slice(key.as_ref());
    v
}

#[program]
pub mod test_mutator {
    use super::*;

    /// Do nothing — the "honest inner instruction" baseline.
    pub fn noop(_ctx: Context<Noop>) -> Result<()> {
        Ok(())
    }

    /// SPL Token `Transfer(amount)` from `source` to `destination`.
    pub fn transfer_out(ctx: Context<TransferOut>, amount: u64) -> Result<()> {
        let mut data = vec![3u8];
        data.extend_from_slice(&amount.to_le_bytes());
        let ix = Instruction {
            program_id: ctx.accounts.token_program.key(),
            accounts: vec![
                AccountMeta::new(ctx.accounts.source.key(), false),
                AccountMeta::new(ctx.accounts.destination.key(), false),
                AccountMeta::new_readonly(ctx.accounts.authority.key(), true),
            ],
            data,
        };
        invoke(
            &ix,
            &[
                ctx.accounts.source.to_account_info(),
                ctx.accounts.destination.to_account_info(),
                ctx.accounts.authority.to_account_info(),
            ],
        )?;
        Ok(())
    }

    /// SPL Token `Approve(amount)` — sets `delegate` on `source`.
    pub fn set_delegate(ctx: Context<SetDelegate>, amount: u64) -> Result<()> {
        let mut data = vec![4u8];
        data.extend_from_slice(&amount.to_le_bytes());
        let ix = Instruction {
            program_id: ctx.accounts.token_program.key(),
            accounts: vec![
                AccountMeta::new(ctx.accounts.source.key(), false),
                AccountMeta::new_readonly(ctx.accounts.delegate.key(), false),
                AccountMeta::new_readonly(ctx.accounts.authority.key(), true),
            ],
            data,
        };
        invoke(
            &ix,
            &[
                ctx.accounts.source.to_account_info(),
                ctx.accounts.delegate.to_account_info(),
                ctx.accounts.authority.to_account_info(),
            ],
        )?;
        Ok(())
    }

    /// SPL Token `SetAuthority(CloseAccount, Some(new))` on `account`.
    pub fn set_close_authority(ctx: Context<SetAuthorityIx>) -> Result<()> {
        set_authority(&ctx, AUTH_TYPE_CLOSE_ACCOUNT)
    }

    /// SPL Token `SetAuthority(AccountOwner, Some(new))` on `account`.
    pub fn set_owner(ctx: Context<SetAuthorityIx>) -> Result<()> {
        set_authority(&ctx, AUTH_TYPE_ACCOUNT_OWNER)
    }

    /// SPL Token `CloseAccount` — closes `account`, rent to `destination`.
    pub fn close_account(ctx: Context<CloseAccountIx>) -> Result<()> {
        close(&ctx)
    }

    /// SPL Token `CloseAccount` to a non-vault `destination`. Semantically
    /// distinct from `close_account` only so Task 5 can name the "close a
    /// zero-balance vault ATA, send the rent to a stranger" case; the CPI is
    /// the same. Through `execute` the payload decoder never sees this nested
    /// close, so it emits no `CloseIntent` and conservation rejects the
    /// unexplained disappearance (spec §5.2 rules 2/3), NOT the deny-list.
    pub fn close_zero_balance_ata_to_stranger(ctx: Context<CloseAccountIx>) -> Result<()> {
        close(&ctx)
    }

    /// Grow the mutator-owned `state` account. Through `execute` this is a
    /// writable vault-owned NON-token account, which warden rejects up front
    /// (spec §5.2). Here (smoke) the account is owned by this program, so the
    /// realloc succeeds.
    pub fn realloc_self(ctx: Context<ReallocSelf>, new_len: u64) -> Result<()> {
        ctx.accounts
            .state
            .to_account_info()
            .resize(new_len as usize)?;
        Ok(())
    }

    /// Attempt to debit raw lamports from `source` directly. Only the account's
    /// owner program may reduce its lamports, and `source` is not owned by this
    /// program, so the runtime rejects the write — the point of the test.
    pub fn drain_lamports(ctx: Context<DrainLamports>, amount: u64) -> Result<()> {
        let src = ctx.accounts.source.to_account_info();
        let dest = ctx.accounts.destination.to_account_info();
        **src.try_borrow_mut_lamports()? = src
            .lamports()
            .checked_sub(amount)
            .ok_or(ProgramError::InsufficientFunds)?;
        **dest.try_borrow_mut_lamports()? = dest
            .lamports()
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        Ok(())
    }

    /// CPI the given `data` into warden. Through `execute` warden's payload
    /// rejects `program_idx == warden` (`SelfCpiRejected`) before this runs; as
    /// a top-level call warden's own guards reject the forged input. Either
    /// way the assertion is that warden cannot be re-entered.
    pub fn reenter_warden(ctx: Context<ReenterWarden>, data: Vec<u8>) -> Result<()> {
        let accounts: Vec<AccountMeta> = ctx
            .remaining_accounts
            .iter()
            .map(|a| AccountMeta {
                pubkey: *a.key,
                is_signer: a.is_signer,
                is_writable: a.is_writable,
            })
            .collect();
        let ix = Instruction {
            program_id: ctx.accounts.warden_program.key(),
            accounts,
            data,
        };
        invoke(&ix, ctx.remaining_accounts)?;
        Ok(())
    }
}

fn set_authority(ctx: &Context<SetAuthorityIx>, authority_type: u8) -> Result<()> {
    let mut data = vec![6u8, authority_type];
    data.extend_from_slice(&coption_some(&ctx.accounts.new_authority.key()));
    let ix = Instruction {
        program_id: ctx.accounts.token_program.key(),
        accounts: vec![
            AccountMeta::new(ctx.accounts.account.key(), false),
            AccountMeta::new_readonly(ctx.accounts.authority.key(), true),
        ],
        data,
    };
    invoke(
        &ix,
        &[
            ctx.accounts.account.to_account_info(),
            ctx.accounts.authority.to_account_info(),
        ],
    )?;
    Ok(())
}

fn close(ctx: &Context<CloseAccountIx>) -> Result<()> {
    let ix = Instruction {
        program_id: ctx.accounts.token_program.key(),
        accounts: vec![
            AccountMeta::new(ctx.accounts.account.key(), false),
            AccountMeta::new(ctx.accounts.destination.key(), false),
            AccountMeta::new_readonly(ctx.accounts.authority.key(), true),
        ],
        data: vec![9u8],
    };
    invoke(
        &ix,
        &[
            ctx.accounts.account.to_account_info(),
            ctx.accounts.destination.to_account_info(),
            ctx.accounts.authority.to_account_info(),
        ],
    )?;
    Ok(())
}

// All accounts are `UncheckedAccount` on purpose: this is a test program whose
// whole job is to pass whatever accounts it is handed to SPL Token, so warden's
// checks (not this program's) are the ones under test.
#[derive(Accounts)]
pub struct Noop {}

#[derive(Accounts)]
pub struct TransferOut<'info> {
    /// CHECK: test-only, forwarded to SPL Token
    #[account(mut)]
    pub source: UncheckedAccount<'info>,
    /// CHECK: test-only
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    /// CHECK: test-only; the SPL Token authority (payer in smoke, vault PDA in execute)
    pub authority: UncheckedAccount<'info>,
    /// CHECK: SPL Token program
    pub token_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct SetDelegate<'info> {
    /// CHECK: test-only
    #[account(mut)]
    pub source: UncheckedAccount<'info>,
    /// CHECK: test-only
    pub delegate: UncheckedAccount<'info>,
    /// CHECK: test-only
    pub authority: UncheckedAccount<'info>,
    /// CHECK: SPL Token program
    pub token_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct SetAuthorityIx<'info> {
    /// CHECK: test-only
    #[account(mut)]
    pub account: UncheckedAccount<'info>,
    /// CHECK: test-only
    pub new_authority: UncheckedAccount<'info>,
    /// CHECK: test-only
    pub authority: UncheckedAccount<'info>,
    /// CHECK: SPL Token program
    pub token_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct CloseAccountIx<'info> {
    /// CHECK: test-only
    #[account(mut)]
    pub account: UncheckedAccount<'info>,
    /// CHECK: test-only
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    /// CHECK: test-only
    pub authority: UncheckedAccount<'info>,
    /// CHECK: SPL Token program
    pub token_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReallocSelf<'info> {
    /// CHECK: an account owned by this program, reallocated in place
    #[account(mut)]
    pub state: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct DrainLamports<'info> {
    /// CHECK: test-only; not owned by this program, so the debit must fail
    #[account(mut)]
    pub source: UncheckedAccount<'info>,
    /// CHECK: test-only
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReenterWarden<'info> {
    /// CHECK: the warden program, CPI target
    pub warden_program: UncheckedAccount<'info>,
}
