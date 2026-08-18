#![deny(clippy::arithmetic_side_effects)]
use anchor_lang::prelude::*;
pub mod constants;
pub mod errors;
declare_id!("6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2");
#[program]
pub mod warden {
    use super::*;
    pub fn ping(_ctx: Context<Ping>) -> Result<()> {
        Ok(())
    }
}
#[derive(Accounts)]
pub struct Ping {}
