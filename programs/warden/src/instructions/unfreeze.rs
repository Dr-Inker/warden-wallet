//! `unfreeze` — root-authorized lift of a root-issued `freeze` (spec §5.1,
//! Task 6, 1A scope).
//!
//! Allowed only if the account is frozen by ROOT (`FrozenState::Root`) and
//! the account's own `policy.timelock_secs` has elapsed since `frozen_at`.
//! On success `frozen` returns to `None` and `frozen_at` resets to `0`.
//!
//! ## Why a timelock at all
//!
//! `freeze` is meant to be a fast, unilateral emergency stop a compromised
//! (or merely panicking) root key can pull instantly. If the same root key
//! could `unfreeze` just as instantly, freeze would offer no protection
//! against the exact threat model it exists for: an attacker who has already
//! captured the root passkey could freeze-then-immediately-unfreeze to no
//! effect, or — more realistically — a legitimate owner who freezes in a
//! panic gets a mandatory cooling-off window (`policy.timelock_secs`, the
//! same field `create_account` enforces a ≥ 1 hour floor on) before root
//! alone can reverse it. Guardian intervention (1B) is the intended
//! fast-path around the timelock; root alone never gets one in 1A.
//!
//! ## Guardian-frozen state cannot be lifted here
//!
//! `FrozenState::Guardian` is out of scope for this instruction — 1B defines
//! how a guardian freeze is lifted (by guardians, on their own timelock/quorum
//! rules), and letting THIS root-only instruction lift it would let a root key
//! bypass whatever guardians decided. It is rejected with `Frozen`, the same
//! error every other outflow-gate uses for "the account is currently frozen
//! and this action cannot proceed."
//!
//! Calling `unfreeze` when the account is not frozen at all
//! (`FrozenState::None`) is likewise rejected — there is nothing to lift —
//! with `InvalidAccountData`, matching the same "well-formed request, but the
//! state it presupposes doesn't hold" error class `PolicyArgs::expand` uses
//! elsewhere in this crate.
//!
//! ## Ordering
//!
//! Root proves *who* is asking before the handler decides *whether the
//! request is valid*, same as `freeze` — see that module's docs.

use anchor_lang::prelude::*;

use crate::constants::ACCOUNT_SEED;
use crate::errors::WardenError;
use crate::root_verify::transcript::{action_hash, OP_UNFREEZE};
use crate::root_verify::{verify_root_assertion, RootArgs};
use crate::state::{FrozenState, SmartAccount};

#[derive(Accounts)]
pub struct Unfreeze<'info> {
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
pub(crate) fn handler(ctx: Context<Unfreeze>, args: RootArgs) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
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

    // `unfreeze` has no arguments of its own beyond `RootArgs` — same shape
    // as `rotate_nonce`/`freeze`.
    verify_root_assertion(
        &mut account,
        &ix_sysvar,
        &args,
        ctx.program_id,
        &account_key,
        action_hash(OP_UNFREEZE, &[]),
        now,
    )?;

    // AUTHORIZE FIRST, then validate state (see module docs).
    match account.frozen()? {
        FrozenState::Root => {
            // `account.policy.timelock_secs` is read LIVE, at lift time, not
            // the value that was in force when `freeze` ran — deliberate: no
            // instruction in 1A ever changes it after `create_account`, so
            // today the two are always the same value, but this is the
            // policy field a future `set_policy` (1B) would touch. If 1B
            // shortens `timelock_secs` after a freeze is already in effect,
            // that shorter window applies to unfreezing it too, because
            // nothing here snapshotted the duration at freeze time. See
            // docs/program/PHASE1A-MEASUREMENTS.md ("Design notes") for the
            // decision `set_policy` owes this invariant.
            let unlock_at = account
                .frozen_at
                .checked_add(account.policy.timelock_secs)
                .ok_or(WardenError::Overflow)?;
            require!(now >= unlock_at, WardenError::TimelockNotElapsed);
        }
        // 1B lifts a guardian freeze through its own instruction/rules; root
        // alone may not bypass it here.
        FrozenState::Guardian { .. } => return Err(WardenError::Frozen.into()),
        // Nothing to lift.
        FrozenState::None => return Err(WardenError::InvalidAccountData.into()),
    }

    account.set_frozen(&FrozenState::None);
    account.frozen_at = 0;
    Ok(())
}
