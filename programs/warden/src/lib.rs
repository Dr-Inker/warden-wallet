#![deny(clippy::arithmetic_side_effects)]
use anchor_lang::prelude::*;
pub mod buckets;
pub mod constants;
pub mod errors;
pub mod instructions;
pub mod root_verify;
pub mod state;

// `#[program]` derives its generated client-accounts module name from the
// path written in `Context<...>`, so the accounts structs must be in scope
// unqualified at the crate root.
pub use crate::instructions::*;
use crate::root_verify::RootArgs;
declare_id!("6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2");
#[program]
pub mod warden {
    use super::*;
    pub fn ping(_ctx: Context<Ping>) -> Result<()> {
        Ok(())
    }

    /// Create a passkey- (or Ed25519-) rooted `SmartAccount` PDA. No root
    /// signature required — see `instructions::create_account` for why.
    pub fn create_account(ctx: Context<CreateAccount>, args: CreateAccountArgs) -> Result<()> {
        instructions::create_account::handler(ctx, args)
    }

    /// Consume the account's `root_nonce` under a root passkey assertion,
    /// invalidating any outstanding (signed but unsubmitted) challenge.
    pub fn rotate_nonce(ctx: Context<RotateNonce>, args: RootArgs) -> Result<()> {
        instructions::rotate_nonce::handler(ctx, args)
    }

    /// Mint (or re-bless) a bounded, expiring session key under a root
    /// passkey ceremony. Upserts the `["session", account, pubkey]` PDA,
    /// merging caps by mint — see `instructions::grant_session`.
    pub fn grant_session(ctx: Context<GrantSession>, args: GrantSessionArgs) -> Result<()> {
        instructions::grant_session::handler(ctx, args)
    }

    /// Close a session PDA under a root passkey ceremony.
    pub fn revoke_session_root(
        ctx: Context<RevokeSessionRoot>,
        args: RevokeSessionRootArgs,
    ) -> Result<()> {
        instructions::revoke_session::handler_root(ctx, args)
    }

    /// Close a session PDA on the authority of the session key itself,
    /// signing as a plain Ed25519 signer. No root ceremony involved.
    pub fn revoke_session_self(ctx: Context<RevokeSessionSelf>) -> Result<()> {
        instructions::revoke_session::handler_self(ctx)
    }

    /// Root-authorized emergency stop: sets `frozen = Root`, blocking every
    /// outflow-enabling action until `unfreeze` lifts it. 1A scope — see
    /// `instructions::freeze`.
    pub fn freeze(ctx: Context<Freeze>, args: RootArgs) -> Result<()> {
        instructions::freeze::handler(ctx, args)
    }

    /// Move SOL or an SPL balance out of the vault — session key (within its
    /// caps) or bounded passkey root. See `instructions::transfer`.
    pub fn transfer(ctx: Context<Transfer>, args: TransferArgs) -> Result<()> {
        instructions::transfer::handler(ctx, args)
    }

    /// Root-authorized lift of a root-issued freeze, gated by
    /// `policy.timelock_secs` since `frozen_at`. See `instructions::unfreeze`.
    pub fn unfreeze(ctx: Context<Unfreeze>, args: RootArgs) -> Result<()> {
        instructions::unfreeze::handler(ctx, args)
    }
}
#[derive(Accounts)]
pub struct Ping {}
