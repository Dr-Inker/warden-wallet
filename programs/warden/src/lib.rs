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

    /// Consume the account's `root_nonce` under a root passkey assertion,
    /// invalidating any outstanding (signed but unsubmitted) challenge.
    pub fn rotate_nonce(ctx: Context<RotateNonce>, args: RootArgs) -> Result<()> {
        instructions::rotate_nonce::handler(ctx, args)
    }
}
#[derive(Accounts)]
pub struct Ping {}
