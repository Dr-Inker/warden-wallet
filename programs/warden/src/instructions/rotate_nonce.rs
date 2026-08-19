//! `rotate_nonce` — the minimal root-authorized instruction.
//!
//! It verifies a root passkey assertion and does nothing else; the nonce bump
//! is `verify_root_assertion`'s own side effect. In production this is how a
//! user invalidates an outstanding challenge — a ceremony that was started,
//! signed, and then not submitted (a lost or intercepted assertion) becomes
//! unusable the moment any other root instruction lands, and `rotate_nonce` is
//! the way to make that happen deliberately, without moving funds or changing
//! policy.
//!
//! It is also the smallest possible harness for the root-verify path, which is
//! why it exists before `create_account` (Task 4) does.

use anchor_lang::prelude::*;

use crate::constants::ACCOUNT_SEED;
use crate::errors::WardenError;
use crate::root_verify::transcript::{action_hash, OP_ROTATE_NONCE};
use crate::root_verify::{verify_and_consume, RootArgs};
use crate::state::SmartAccount;

#[derive(Accounts)]
pub struct RotateNonce<'info> {
    #[account(mut)]
    pub smart_account: AccountLoader<'info, SmartAccount>,
    /// CHECK: constrained to the Instructions sysvar address; read only via
    /// `load_instruction_at_checked` / `load_current_index_checked`, which
    /// re-check the address themselves.
    #[account(address = solana_instructions_sysvar::ID @ WardenError::BadInstructionLayout)]
    pub ix_sysvar: UncheckedAccount<'info>,
}

// Not `pub`: only `lib.rs`'s `#[program]` module calls this, by full path —
// see the matching note on `create_account::handler` for why a bare `pub`
// here would collide across the glob re-export in `instructions::mod.rs`.
pub(crate) fn handler(ctx: Context<RotateNonce>, args: RootArgs) -> Result<()> {
    let clock = Clock::get()?;
    let now = clock.unix_timestamp;
    let slot = clock.slot;
    let account_key = ctx.accounts.smart_account.key();
    let ix_sysvar = ctx.accounts.ix_sysvar.to_account_info();
    let mut account = ctx.accounts.smart_account.load_mut()?;

    // Re-derive the PDA from the seeds the account itself stores. Anchor has
    // already proven ownership and discriminator; this proves the address is
    // the canonical one for `owner_seed`, so a hand-crafted account at some
    // other address cannot stand in. `create_program_address` (not
    // `find_program_address`) because the bump is stored.
    let expected = Pubkey::create_program_address(
        &[ACCOUNT_SEED, account.owner_seed.as_ref(), &[account.bump]],
        ctx.program_id,
    )
    .map_err(|_| WardenError::Unauthorized)?;
    require_keys_eq!(account_key, expected, WardenError::Unauthorized);

    // `rotate_nonce` has no arguments of its own beyond `RootArgs`, so the
    // action encoding is the op byte with an empty borsh payload.
    verify_and_consume(
        &mut account,
        &ix_sysvar,
        &args,
        ctx.program_id,
        &account_key,
        action_hash(OP_ROTATE_NONCE, &[]),
        now,
        slot,
    )
}
