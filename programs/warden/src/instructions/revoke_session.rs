//! `revoke_session_root` / `revoke_session_self` — close a `SessionKey` PDA.
//!
//! ## Why two instructions rather than one with an enum argument
//!
//! The two authorization paths need genuinely different account lists: the
//! root path needs the Instructions sysvar (to bind the secp256r1 precompile)
//! and a mutable `SmartAccount` (the ceremony consumes `root_nonce`); the
//! self path needs the session key present as a real Ed25519 `Signer` and
//! touches no root state at all. Folding them into one instruction would mean
//! carrying both shapes at once — an `UncheckedAccount` standing in for the
//! session signer with a hand-rolled `is_signer` check, and a sysvar account
//! that one of the two paths never reads. Two instructions keep each account
//! list exactly as tight as its own path requires, and Anchor's own
//! constraints (rather than handler code) do the signer check on the self
//! path.
//!
//! ## Revocation is not gated by `frozen`
//!
//! Every *outflow-enabling* action is (`grant_session` is). Revocation only
//! removes authority, so blocking it while an account is frozen would mean a
//! user who just froze their account in response to a compromise could not
//! also cut the compromised session loose — the freeze would protect the
//! attacker's delegate from being revoked. Both paths therefore work while
//! frozen, deliberately.
//!
//! ## Rent
//!
//! Both paths close to `payer` (the fee payer of the transaction), never to
//! an arbitrary account: the rent is a refund to whoever is paying to submit
//! the close, and letting the caller name a third-party destination would add
//! a value-carrying account for no benefit in Phase 1A.

use anchor_lang::prelude::*;

use crate::constants::{ACCOUNT_SEED, SESSION_SEED};
use crate::errors::WardenError;
use crate::root_verify::transcript::{action_hash, OP_REVOKE_SESSION};
use crate::root_verify::{verify_root_assertion, RootArgs};
use crate::state::{SessionKey, SmartAccount};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct RevokeSessionRootArgs {
    pub root: RootArgs,
    /// The session's delegate pubkey — the PDA seed, and the whole of the
    /// signed action payload (`Keccak256(0x02 ‖ borsh(session_pubkey))`,
    /// i.e. the bare 32 pubkey bytes).
    pub session_pubkey: Pubkey,
}

#[derive(Accounts)]
pub struct RevokeSessionRoot<'info> {
    /// Rent destination and fee payer.
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut)]
    pub smart_account: AccountLoader<'info, SmartAccount>,
    /// The PDA address is re-derived in the handler (see `handler_root`),
    /// not by a `seeds` constraint, because the derivation needs the bump
    /// this very account stores.
    #[account(mut, close = payer)]
    pub session: Account<'info, SessionKey>,
    /// CHECK: constrained to the Instructions sysvar address; read only via
    /// `load_instruction_at_checked` / `load_current_index_checked`, which
    /// re-check the address themselves.
    #[account(address = solana_instructions_sysvar::ID @ WardenError::BadInstructionLayout)]
    pub ix_sysvar: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct RevokeSessionSelf<'info> {
    /// Rent destination and fee payer. May be the session signer itself, but
    /// need not be — a session key with no lamports can still revoke itself
    /// if someone else pays.
    #[account(mut)]
    pub payer: Signer<'info>,
    /// The session's own Ed25519 delegate key, signing this transaction.
    pub session_signer: Signer<'info>,
    pub smart_account: AccountLoader<'info, SmartAccount>,
    #[account(
        mut,
        close = payer,
        constraint = session.pubkey == session_signer.key() @ WardenError::Unauthorized
    )]
    pub session: Account<'info, SessionKey>,
}

// Not `pub`: see the note on `create_account::handler`.
pub(crate) fn handler_root(
    ctx: Context<RevokeSessionRoot>,
    args: RevokeSessionRootArgs,
) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let account_key = ctx.accounts.smart_account.key();
    let session_key = ctx.accounts.session.key();
    let ix_sysvar = ctx.accounts.ix_sysvar.to_account_info();

    // Bind the named session to this account and to the signed payload BEFORE
    // the ceremony is checked: the assertion authorizes revoking exactly
    // `args.session_pubkey`, so an attacker who swaps in a different session
    // account must be turned away regardless of how valid the assertion is.
    require_keys_eq!(
        ctx.accounts.session.pubkey,
        args.session_pubkey,
        WardenError::Unauthorized
    );
    check_session_pda(
        &ctx.accounts.session,
        &session_key,
        &account_key,
        ctx.program_id,
    )?;

    let mut account = ctx.accounts.smart_account.load_mut()?;
    let expected = Pubkey::create_program_address(
        &[ACCOUNT_SEED, account.owner_seed.as_ref(), &[account.bump]],
        ctx.program_id,
    )
    .map_err(|_| WardenError::Unauthorized)?;
    require_keys_eq!(account_key, expected, WardenError::Unauthorized);

    let mut payload = Vec::new();
    args.session_pubkey.serialize(&mut payload)?;
    verify_root_assertion(
        &mut account,
        &ix_sysvar,
        &args.root,
        ctx.program_id,
        &account_key,
        action_hash(OP_REVOKE_SESSION, &payload),
        now,
    )
    // `close = payer` runs after the handler returns Ok.
}

// Not `pub`: see the note on `create_account::handler`.
pub(crate) fn handler_self(ctx: Context<RevokeSessionSelf>) -> Result<()> {
    let account_key = ctx.accounts.smart_account.key();
    let session_key = ctx.accounts.session.key();

    {
        let account = ctx.accounts.smart_account.load()?;
        let expected = Pubkey::create_program_address(
            &[ACCOUNT_SEED, account.owner_seed.as_ref(), &[account.bump]],
            ctx.program_id,
        )
        .map_err(|_| WardenError::Unauthorized)?;
        require_keys_eq!(account_key, expected, WardenError::Unauthorized);
    }

    // `session.pubkey == session_signer.key()` is enforced by the account
    // constraint; this proves the session belongs to the named account.
    check_session_pda(
        &ctx.accounts.session,
        &session_key,
        &account_key,
        ctx.program_id,
    )?;
    Ok(())
}

/// Prove `session_key` is the canonical `["session", account, pubkey]` PDA for
/// the values the account itself stores, and that it names `account_key`.
///
/// Anchor has already proven program ownership and the discriminator; this is
/// what stops a `SessionKey` belonging to smart account A from being closed in
/// a transaction that names smart account B.
fn check_session_pda(
    session: &SessionKey,
    session_key: &Pubkey,
    account_key: &Pubkey,
    program_id: &Pubkey,
) -> Result<()> {
    require_keys_eq!(session.account, *account_key, WardenError::Unauthorized);
    let expected = Pubkey::create_program_address(
        &[
            SESSION_SEED,
            account_key.as_ref(),
            session.pubkey.as_ref(),
            &[session.bump],
        ],
        program_id,
    )
    .map_err(|_| WardenError::Unauthorized)?;
    require_keys_eq!(*session_key, expected, WardenError::Unauthorized);
    Ok(())
}
