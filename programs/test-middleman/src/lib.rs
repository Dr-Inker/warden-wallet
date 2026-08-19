//! **Test-only middleman program. Never deployed to any cluster.**
//!
//! It exists for exactly one assertion: that warden's root-authorized
//! instructions refuse to run when they are reached through a CPI rather than
//! as a top-level instruction (`WardenError::RootRequiresTopLevel`, spec §5.1;
//! `root_verify::require_top_level`).
//!
//! `forward` takes the target program as its one named account, the target's
//! full instruction data as its argument, and every account the target needs
//! as `remaining_accounts`. It reconstructs the instruction verbatim —
//! preserving each account's `is_signer` / `is_writable` flags — and `invoke`s
//! it. From the target's point of view the only difference from a top-level
//! call is the stack height, which is precisely the property under test: if
//! the middleman check ever regressed, this program would successfully drive a
//! complete, valid root ceremony from inside a CPI.
//!
//! Deliberately generic (it forwards *any* instruction to *any* program)
//! rather than hard-coded to `rotate_nonce`, so Phase 1B's later root paths
//! (`execute`, `swap`, PoP-at-create) can reuse it without a new program.
//!
//! The program id is a **nothing-up-my-sleeve** value — `sha256("WARDEN/test-middleman/v1")`
//! = `d43ec1db23c08041980a95fb03ef9fdc5b7463e4ac09d9ed74a8b202dced1ed9`,
//! base58 `FHWwDX1az7eAtFsogaRrFcoZkZhBEzSS3QMXPwovSiMN` — so no keypair for it
//! exists or needs to be committed (repo policy: docs/PROGRAM-KEYS.md). LiteSVM
//! loads programs by id + bytes, never by keypair; `anchor build`'s
//! keypair-mismatch warning for this crate is cosmetic and expected.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke;

declare_id!("FHWwDX1az7eAtFsogaRrFcoZkZhBEzSS3QMXPwovSiMN");

#[program]
pub mod test_middleman {
    use super::*;

    /// CPI `data` into `target_program`, passing `remaining_accounts` through
    /// unchanged.
    pub fn forward(ctx: Context<Forward>, data: Vec<u8>) -> Result<()> {
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
            program_id: ctx.accounts.target_program.key(),
            accounts,
            data,
        };
        invoke(&ix, ctx.remaining_accounts)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Forward<'info> {
    /// CHECK: the program to CPI into; test-only, deliberately unconstrained
    /// so the same middleman can target any program.
    pub target_program: UncheckedAccount<'info>,
}
