//! `freeze` — root-authorized emergency stop (spec §5.1, Task 6, 1A scope:
//! root freeze only; `FrozenState::Guardian` is a Phase 1B instruction).
//!
//! Sets `frozen = Root` and records `frozen_at = now`. Every outflow-enabling
//! path (`grant_session` already; Phase 1B's `transfer`/`execute`/`swap`) is
//! gated on `frozen == None`, so this alone blocks every future spend and
//! every future delegation until `unfreeze` lifts it. `rotate_nonce` and
//! session self-revocation are deliberately NOT gated by `frozen` (see their
//! own module docs) — a frozen account must still be able to invalidate a
//! stale ceremony and let a delegate walk away on its own.
//!
//! ## Re-freezing is rejected, not idempotent
//!
//! Freezing an account already frozen by root is rejected (`AlreadyFrozen`)
//! rather than silently re-stamping `frozen_at`. Unfreeze's timelock is
//! measured from `frozen_at`, so letting a second successful `freeze`
//! ceremony reset it would let a root key extend the freeze indefinitely by
//! re-issuing the same instruction just before the timelock elapses —
//! `frozen_at` is meant to be the moment the account WAS frozen, once, not a
//! watermark. An account already frozen by a guardian (1B) is also rejected
//! here for the same reason: this instruction can only ever write `Root`, and
//! there is no meaningful "root freeze on top of a guardian freeze" state for
//! it to enter.
//!
//! ## Ordering: authorize, then check state
//!
//! Root proves *who* is asking before the handler decides *whether the
//! request is valid* — the same "authorize first, then validate" ordering
//! `grant_session` uses for its own post-ceremony checks (see that module's
//! docs), so that a tampered/replayed ceremony always fails on the ceremony
//! itself rather than leaking "already frozen" to an unauthenticated caller.

use anchor_lang::prelude::*;

use crate::constants::ACCOUNT_SEED;
use crate::errors::WardenError;
use crate::root_verify::transcript::{action_hash, OP_FREEZE};
use crate::root_verify::{verify_and_consume, RootArgs};
use crate::state::{FrozenState, SmartAccount};

#[derive(Accounts)]
pub struct Freeze<'info> {
    #[account(mut)]
    pub smart_account: AccountLoader<'info, SmartAccount>,
    /// CHECK: constrained to the Instructions sysvar address; read only via
    /// `load_instruction_at_checked` / `load_current_index_checked`, which
    /// re-check the address themselves.
    #[account(address = solana_instructions_sysvar::ID @ WardenError::BadInstructionLayout)]
    pub ix_sysvar: UncheckedAccount<'info>,
}

// Not `pub`: only `lib.rs`'s `#[program]` module calls this, by full path —
// see the matching note on `create_account::handler`.
pub(crate) fn handler(ctx: Context<Freeze>, args: RootArgs) -> Result<()> {
    let clock = Clock::get()?;
    let now = clock.unix_timestamp;
    let slot = clock.slot;
    let account_key = ctx.accounts.smart_account.key();
    let ix_sysvar = ctx.accounts.ix_sysvar.to_account_info();
    let mut account = ctx.accounts.smart_account.load_mut()?;

    // Re-derive the PDA from the seeds the account itself stores (same
    // argument as `rotate_nonce::handler`).
    let expected = Pubkey::create_program_address(
        &[ACCOUNT_SEED, account.owner_seed.as_ref(), &[account.bump]],
        ctx.program_id,
    )
    .map_err(|_| WardenError::Unauthorized)?;
    require_keys_eq!(account_key, expected, WardenError::Unauthorized);

    // `freeze` has no arguments of its own beyond `RootArgs` — same shape as
    // `rotate_nonce`.
    verify_and_consume(
        &mut account,
        &ix_sysvar,
        &args,
        ctx.program_id,
        &account_key,
        action_hash(OP_FREEZE, &[]),
        now,
        slot,
    )?;

    // AUTHORIZE FIRST, then validate state (see module docs).
    require!(matches!(account.frozen()?, FrozenState::None), WardenError::AlreadyFrozen);
    account.set_frozen(&FrozenState::Root);
    account.frozen_at = now;
    Ok(())
}
