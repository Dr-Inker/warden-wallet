#![deny(clippy::arithmetic_side_effects)]
use anchor_lang::prelude::*;
pub mod buckets;
pub mod conservation;
pub mod constants;
pub mod errors;
pub mod instructions;
pub mod registry;
pub mod registry_default;
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

    /// Create a passkey-rooted `SmartAccount` PDA at an address DERIVED from
    /// the root key (`["account", Keccak256("WARDEN/seed/v1" ‖ root_pubkey33
    /// ‖ salt)]`), under a mandatory root ceremony proving possession of that
    /// passkey — so the address cannot be squatted by a front-runner. See
    /// `instructions::create_account`.
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

    /// Create the global adapter registry, authorised by warden's on-chain
    /// upgrade authority — see `instructions::registry_admin`. Singleton;
    /// immutable in 1B.
    pub fn init_registry(ctx: Context<InitRegistry>) -> Result<()> {
        instructions::registry_admin::handler(ctx)
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

    /// Open a content-addressed `Stage` for a large `execute`/`swap` payload
    /// (Phase 1B Task 4). See `instructions::stage`.
    pub fn stage_open(ctx: Context<StageOpen>, args: StageOpenArgs) -> Result<()> {
        instructions::stage::open(ctx, args)
    }

    /// Append one sequential slice to an open `Stage` (creator only).
    pub fn stage_chunk(ctx: Context<StageChunk>, args: StageChunkArgs) -> Result<()> {
        instructions::stage::chunk(ctx, args)
    }

    /// Seal a fully-uploaded `Stage`, checking `Keccak256(data) == hash` and
    /// recording the account's `generation`/`policy_version` (creator only).
    pub fn stage_finalize(ctx: Context<StageFinalize>) -> Result<()> {
        instructions::stage::finalize(ctx)
    }

    /// Close a `Stage` and refund its rent to the creator: the creator before
    /// finalize, or anyone after `expiry_ts`.
    pub fn stage_close(ctx: Context<StageClose>) -> Result<()> {
        instructions::stage::close(ctx)
    }
}
#[derive(Accounts)]
pub struct Ping {}
