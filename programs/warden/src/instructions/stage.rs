//! `stage_open` / `stage_chunk` / `stage_finalize` / `stage_close` — the
//! chunk-upload lifecycle for a `Stage` (Phase 1B Task 4).
//!
//! A root `execute`/`swap` whose compiled payload does not fit the 1,232 B
//! packet uploads its instruction data here first (spec §5.1, §12.2), then
//! references it by hash. The four instructions are a small state machine:
//!
//! ```text
//!   stage_open ──▶ [written < len] ──stage_chunk──▶ … ──▶ [written == len]
//!        │                                                      │
//!        │                                                 stage_finalize
//!        ▼                                                      │
//!   stage_close (creator, pre-finalize)                        ▼
//!        ▲                                              [finalized]
//!        └── anyone, after expiry_ts ◀──────────────── execute consumes
//! ```
//!
//! **Authorization is deliberately thin.** Any payer may `stage_open` (a stage
//! is not an authorization, it is a byte buffer — the root ceremony in
//! `execute` is what authorizes). Only the recorded `creator` may `stage_chunk`
//! or `stage_finalize` (so a third party cannot corrupt an in-flight upload),
//! and only the creator may `stage_close` before finalize; after `expiry_ts`
//! anyone may close it. Every close refunds the `creator`, which is what makes
//! the content-address squat (ND-SQD3-LO-01 / Certora H-01) cost the attacker
//! and pay the victim nothing — see `state::stage` for the full argument.
//!
//! **Staging relieves instruction-data size, not the account list.** Every CPI
//! program, account and LUT still rides in the `execute` transaction.

use anchor_lang::prelude::*;

use crate::constants::{STAGE_MAX_TTL_SECS, STAGE_SEED};
use crate::errors::WardenError;
use crate::state::{SmartAccount, Stage};

// ---------------------------------------------------------------------------
// stage_open
// ---------------------------------------------------------------------------

/// Everything `stage_open` fixes about a stage. `account` and `hash` are the
/// two variable PDA seeds, so they are arguments rather than passed accounts:
/// a stage may be opened for an account that is not itself passed (the binding
/// is checked when `execute` consumes it), and the payload need not exist
/// on-chain anywhere else.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub struct StageOpenArgs {
    /// The SmartAccount this payload is destined for (PDA seed).
    pub account: Pubkey,
    /// `Keccak256(payload)` (PDA seed); `stage_finalize` re-hashes and checks.
    pub hash: [u8; 32],
    /// Total payload length. `data` is allocated to exactly this size.
    pub len: u32,
    /// Absolute unix seconds after which anyone may close the stage.
    pub expiry_ts: i64,
}

#[derive(Accounts)]
#[instruction(args: StageOpenArgs)]
pub struct StageOpen<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,
    #[account(
        init,
        payer = creator,
        // Reject an oversized `len` BEFORE `space` tries to allocate it, so a
        // hostile `len` fails cheaply rather than as an allocation error.
        constraint = (args.len as usize) <= Stage::MAX_DATA_LEN @ WardenError::StageInvalid,
        space = Stage::space(args.len as usize),
        seeds = [STAGE_SEED, args.account.as_ref(), args.hash.as_ref()],
        bump
    )]
    pub stage: Account<'info, Stage>,
    pub system_program: Program<'info, System>,
}

pub(crate) fn open(ctx: Context<StageOpen>, args: StageOpenArgs) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    // A stage must live for a positive, bounded window: an expiry in the past
    // (or now) would be closable-by-anyone the instant it is created, and one
    // further out than the TTL widens the squat window past the spec bound.
    require!(args.expiry_ts > now, WardenError::StageInvalid);
    let max_expiry = now
        .checked_add(STAGE_MAX_TTL_SECS)
        .ok_or(WardenError::Overflow)?;
    require!(args.expiry_ts <= max_expiry, WardenError::StageInvalid);
    // A zero-length payload is nothing to stage; `MAX_DATA_LEN` is enforced by
    // the account constraint above (before allocation).
    require!(args.len > 0, WardenError::StageInvalid);

    let stage = &mut ctx.accounts.stage;
    stage.version = 1;
    stage.bump = ctx.bumps.stage;
    stage.account = args.account;
    stage.creator = ctx.accounts.creator.key();
    stage.hash = args.hash;
    stage.len = args.len;
    stage.written = 0;
    stage.finalized = false;
    stage.generation = 0;
    stage.policy_version = 0;
    stage.expiry_ts = args.expiry_ts;
    // Empty now; `stage_chunk` grows it. The account already carries space for
    // `len` bytes, so no reallocation ever happens.
    stage.data = Vec::new();
    Ok(())
}

// ---------------------------------------------------------------------------
// stage_chunk
// ---------------------------------------------------------------------------

/// One sequential slice of the payload. Serialized as `offset: u32 LE ‖
/// bytes.len(): u32 LE ‖ bytes` — exactly the `offset ‖ len ‖ payload` wire
/// layout spec §5.1 fixes (borsh's `Vec<u8>` prefix supplies the length word).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub struct StageChunkArgs {
    pub offset: u32,
    pub bytes: Vec<u8>,
}

/// Exactly the three accounts spec §5.1 fixes, in this order, so the payload
/// cap is deterministically measurable: (0) creator, signer + writable;
/// (1) the Stage PDA, writable; (2) System program, read-only.
#[derive(Accounts)]
pub struct StageChunk<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,
    #[account(
        mut,
        seeds = [STAGE_SEED, stage.account.as_ref(), stage.hash.as_ref()],
        bump = stage.bump
    )]
    pub stage: Account<'info, Stage>,
    pub system_program: Program<'info, System>,
}

pub(crate) fn chunk(ctx: Context<StageChunk>, args: StageChunkArgs) -> Result<()> {
    let stage = &mut ctx.accounts.stage;
    require!(stage.version == 1, WardenError::StageInvalid);
    // A finalized stage is immutable; only `execute` (consume) or expiry ends it.
    require!(!stage.finalized, WardenError::StageInvalid);
    // Creator-only: a third party may not corrupt an in-flight upload.
    require_keys_eq!(
        ctx.accounts.creator.key(),
        stage.creator,
        WardenError::Unauthorized
    );

    // Strictly sequential: `offset == written` (no gaps, no overwrite, no
    // reorder), and the slice must land inside `len`. An empty chunk is a
    // malformed no-op.
    require!(!args.bytes.is_empty(), WardenError::StageInvalid);
    require!(args.offset == stage.written, WardenError::StageInvalid);
    let end = args
        .offset
        .checked_add(args.bytes.len() as u32)
        .ok_or(WardenError::Overflow)?;
    require!(end <= stage.len, WardenError::StageInvalid);

    stage.data.extend_from_slice(&args.bytes);
    stage.written = end;
    Ok(())
}

// ---------------------------------------------------------------------------
// stage_finalize
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct StageFinalize<'info> {
    pub creator: Signer<'info>,
    #[account(
        mut,
        seeds = [STAGE_SEED, stage.account.as_ref(), stage.hash.as_ref()],
        bump = stage.bump
    )]
    pub stage: Account<'info, Stage>,
    /// The SmartAccount this stage is bound to, read for its live `generation`
    /// and `policy_version`. Its key must equal `stage.account`, and its PDA is
    /// re-derived from the seed it stores so a byte-identical planted copy
    /// cannot supply a different generation.
    #[account(constraint = smart_account.key() == stage.account @ WardenError::StageInvalid)]
    pub smart_account: AccountLoader<'info, SmartAccount>,
}

pub(crate) fn finalize(ctx: Context<StageFinalize>) -> Result<()> {
    let account_key = ctx.accounts.smart_account.key();
    let account = ctx.accounts.smart_account.load()?;

    // Re-derive the SmartAccount PDA from the seed it stores (same argument as
    // `rotate_nonce`/`grant_session`): a copy planted at another address, with
    // a stale or forged generation, cannot stand in for the real account whose
    // state this stage is being bound to.
    let expected = Pubkey::create_program_address(
        &[
            crate::constants::ACCOUNT_SEED,
            account.owner_seed.as_ref(),
            &[account.bump],
        ],
        ctx.program_id,
    )
    .map_err(|_| WardenError::Unauthorized)?;
    require_keys_eq!(account_key, expected, WardenError::Unauthorized);

    let generation = account.generation;
    let policy_version = account.policy.version;
    drop(account);

    let stage = &mut ctx.accounts.stage;
    require!(stage.version == 1, WardenError::StageInvalid);
    require!(!stage.finalized, WardenError::StageInvalid);
    require_keys_eq!(
        ctx.accounts.creator.key(),
        stage.creator,
        WardenError::Unauthorized
    );
    // The upload must be complete and its bytes must hash to the address they
    // were staged under — the content-address is only meaningful if it is
    // verified.
    require!(stage.written == stage.len, WardenError::StageInvalid);
    let digest = solana_keccak_hasher::hashv(&[&stage.data]).to_bytes();
    require!(digest == stage.hash, WardenError::StageInvalid);

    // Bind the finalized content to the exact account state it targets;
    // `execute` requires both to still be current (spec §5.3 item 6).
    stage.generation = generation;
    stage.policy_version = policy_version;
    stage.finalized = true;
    Ok(())
}

// ---------------------------------------------------------------------------
// stage_close
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct StageClose<'info> {
    #[account(mut)]
    pub closer: Signer<'info>,
    #[account(
        mut,
        close = creator,
        seeds = [STAGE_SEED, stage.account.as_ref(), stage.hash.as_ref()],
        bump = stage.bump
    )]
    pub stage: Account<'info, Stage>,
    /// CHECK: the rent-refund destination. Required to equal `stage.creator`
    /// in the handler, so the rent always returns to whoever opened the stage
    /// no matter who submits the close (this is what makes squatting cost the
    /// squatter). `close = creator` above transfers the lamports on exit.
    #[account(mut)]
    pub creator: UncheckedAccount<'info>,
}

pub(crate) fn close(ctx: Context<StageClose>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let stage = &ctx.accounts.stage;

    // Rent goes to the recorded creator, always.
    require_keys_eq!(
        ctx.accounts.creator.key(),
        stage.creator,
        WardenError::StageInvalid
    );

    if now < stage.expiry_ts {
        // Before expiry, only the creator may close, and only while the stage
        // is still open: a finalized-but-unexpired stage is committed for
        // consumption and cannot be pulled out from under `execute`.
        require_keys_eq!(
            ctx.accounts.closer.key(),
            stage.creator,
            WardenError::Unauthorized
        );
        require!(!stage.finalized, WardenError::StageInvalid);
    }
    // At or after expiry, anyone may close it (GC / squat reclaim); the
    // `close = creator` constraint still refunds the creator.
    Ok(())
}
