//! `swap` — `execute` specialised to Jupiter v6 (Phase 1B Task 6, spec §5.2.7).
//!
//! One inner CPI, pinned to the Jupiter aggregator (`SWAP_TARGET_PROGRAM`), with
//! the adapter preflight generic `execute` cannot do. It is the **intended,
//! preflight-gated** path to Jupiter: generic `execute` fails closed on a
//! DIRECT Jupiter inner instruction (WRDF-0051), steering the common client
//! mistake here. It is NOT the *only* reachable path — a forwarding program can
//! still CPI into Jupiter nested from generic `execute`, bounded there only by
//! net conservation and the caps (the accepted §5.3 boundary); this adapter is
//! the path that adds `max_in`/source-pin/treasury-fee on top.
//!
//! ## The adapter-decoded source limit (spec §5.2 rule 4b) — a design BET
//!
//! A before/after snapshot measures what a route LEFT BEHIND, not what it MOVED:
//! a route that takes 100 out and returns 99.5 within its own execution nets to
//! 0.5, and no snapshot granularity sees the 100. So the net diff is not the
//! only control. **Before the CPI runs** this adapter also:
//!
//! 1. **Decodes the route's declared `in_amount` from the instruction's own
//!    bytes** — the fixed 19-byte argument tail (`in_amount ‖ quoted_out ‖
//!    slippage_bps ‖ platform_fee_bps`) sits at the END of the data, after the
//!    variable `route_plan`, so it is read at a fixed negative offset with no
//!    `route_plan` parsing — and requires it `≤ max_in`, the authorized bound,
//!    which is itself checked against the caps BEFORE any CPI.
//! 2. **Pins the source.** `user_source_token_account` must be a vault-owned
//!    token account of `in_mint`, and `user_transfer_authority` the vault PDA.
//!    The value at risk is then bounded by an account the program NAMED.
//!
//! The net before/after check still runs afterwards and still applies — the two
//! are redundant on purpose (`max_in` bounds authorised input; the net diff
//! bounds realised outflow; the debit is taken on the net so an honest partial
//! fill is not overcharged). **This bounds the value the program can see being
//! authorised; it does NOT close the intra-CPI blind spot, because nothing
//! does** (research §4 item 15). Price sanity (Jupiter quote vs a second source)
//! is the extension's job, not the program's.
//!
//! ## Fee, mints, caps
//!
//! `platform_fee_bps` must be exactly `SWAP_PLATFORM_FEE_BPS` (85) so a route
//! cannot skip the treasury fee, and `platform_fee_account` must be a token
//! account owned by `Registry.treasury` of `in_mint` or `out_mint`. Session:
//! `out_mint` must have a session cap OR be in `ALLOWED_OUT_MINTS_DEFAULT`;
//! the `in_mint` outflow debits the session per_tx/lifetime + the account-wide
//! buckets. Root: bounded by `large_threshold` + the same buckets. Root binds
//! `SwapBody{ in_mint, out_mint, max_in, min_out, discriminator, accounts_hash }`
//! (the same `accounts_hash` construction as `ExecuteBody`).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::AccountsClose;

use crate::buckets::{self, find_cap};
use crate::constants::{
    ACCOUNT_SEED, ALLOWED_OUT_MINTS_DEFAULT, ATA_PROGRAM_ID, JUP_ROUTE_DISC, JUP_SHARED_ROUTE_DISC,
    MAX_EXECUTE_ACCOUNTS_TOTAL, MAX_EXECUTE_WRITABLE, NATIVE_MINT, NATIVE_MINT_2022,
    SWAP_PLATFORM_FEE_BPS, SWAP_TARGET_PROGRAM, STAGE_SEED,
};
use crate::conservation::{self, compare_and_account, Snap, TokenSnap};
use crate::errors::WardenError;
use crate::instructions::transfer::authorize_session;
use crate::payload::{compute_accounts_hash, LogicalAccount};
use crate::root_verify::transcript::{action_hash, OP_SWAP_ACTION};
use crate::root_verify::{verify_and_consume, RootArgs};
use crate::state::{FrozenState, MintCap, Registry, SessionKey, SmartAccount, Stage, OP_SWAP};

/// `variant`: 0 = `route`, 1 = `shared_accounts_route`.
pub const SWAP_VARIANT_ROUTE: u8 = 0;
pub const SWAP_VARIANT_SHARED: u8 = 1;

/// Jupiter's fixed 19-byte argument tail — `in_amount(8) ‖ quoted_out(8) ‖
/// slippage_bps(2) ‖ platform_fee_bps(1)` — read from the END of the route data
/// so the variable `route_plan` (which comes first) never has to be parsed.
const SWAP_TAIL_LEN: usize = 8 + 8 + 2 + 1;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SwapArgs {
    /// `Some` = root path (requires `ix_sysvar`), `None` = session path.
    pub root: Option<RootArgs>,
    /// `SWAP_VARIANT_ROUTE` or `SWAP_VARIANT_SHARED`.
    pub variant: u8,
    pub in_mint: Pubkey,
    pub out_mint: Pubkey,
    /// The authorized maximum input, in `in_mint` base units. The route's
    /// decoded `in_amount` must be `≤ max_in`, and `max_in ≤ caps`.
    pub max_in: u64,
    /// The minimum the vault out ATA must gain (inclusive).
    pub min_out: u64,
    /// The compiled Jupiter instruction data (inline). `None` ⇒ consume `stage`.
    pub route_data: Option<Vec<u8>>,
}

/// Exactly what the passkey signs on the ROOT path (spec §5.2.7). Every field is
/// rebuilt on-chain; `accounts_hash` uses the same logical-list construction
/// `ExecuteBody` binds.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SwapBody {
    pub in_mint: Pubkey,
    pub out_mint: Pubkey,
    pub max_in: u64,
    pub min_out: u64,
    /// The 8-byte Jupiter route selector (`route` or `shared_accounts_route`).
    pub discriminator: [u8; 8],
    /// `Keccak256` of the EXACT route bytes executed (WRDF-0058). Without this a
    /// captured root assertion could authorize a different route_plan /
    /// quoted_out / slippage — or different staged content — sharing the same
    /// mints, bound, discriminator and accounts. Rebuilt on-chain from the bytes
    /// actually run, so the route cannot be substituted after signing.
    pub route_hash: [u8; 32],
    pub accounts_hash: [u8; 32],
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub smart_account: AccountLoader<'info, SmartAccount>,
    pub signer: Signer<'info>,
    #[account(mut)]
    pub session: Option<Account<'info, SessionKey>>,
    /// CHECK: Instructions sysvar (root path). Address-constrained; read only via
    /// the checked loaders.
    #[account(address = solana_instructions_sysvar::ID @ WardenError::BadInstructionLayout)]
    pub ix_sysvar: Option<UncheckedAccount<'info>>,
    /// The staged route data to consume (`args.route_data == None`).
    #[account(mut)]
    pub stage: Option<Account<'info, Stage>>,
    /// THE account's adapter registry — REQUIRED: `Registry.treasury` is the
    /// swap-fee destination owner, so a swap without a bound registry has no
    /// treasury to validate the fee against.
    pub registry: AccountLoader<'info, Registry>,
    /// CHECK: the stage creator — rent destination for the consume-close.
    #[account(mut)]
    pub stage_creator: Option<UncheckedAccount<'info>>,
    // remaining_accounts = the Jupiter route's account list, in v6 order.
}

// Not `pub`: called only by `lib.rs`'s `#[program]` module, by full path.
pub(crate) fn handler<'info>(
    ctx: Context<'info, Swap<'info>>,
    args: SwapArgs,
) -> Result<()> {
    let clock = Clock::get()?;
    let now = clock.unix_timestamp;
    let slot = clock.slot;
    let program_id = ctx.program_id;
    let account_key = ctx.accounts.smart_account.key();
    let signer_key = ctx.accounts.signer.key();

    // Exactly one auth shape and one data source, checked before loading.
    require!(
        args.root.is_some() != ctx.accounts.session.is_some(),
        WardenError::BadInstructionLayout
    );
    require!(
        args.route_data.is_some() != ctx.accounts.stage.is_some(),
        WardenError::BadInstructionLayout
    );
    require!(
        args.variant == SWAP_VARIANT_ROUTE || args.variant == SWAP_VARIANT_SHARED,
        WardenError::SwapBadDiscriminator
    );
    // GROK-EXP-05 (2026-08-22): on the SESSION path only `shared_accounts_route`
    // is accepted. Jupiter's `route` forwards `userTransferAuthority` — the
    // vault PDA, which this handler signs for — as the signer of every AMM hop
    // it CPIs, and the session path binds neither the route bytes nor the
    // account list (root binds both via `route_hash` + `accounts_hash`, so a
    // root `route` is what the user signed). Conservation bounds what a hop
    // can do with vault TOKEN accounts and (since GROK-EXP-03/-02) refuses
    // writable Stake/Vote/ProgramData accounts and freezes vault-controlled
    // mints — but it cannot enumerate every program-specific authority the
    // PDA might hold, so a bearer session key must not be able to point the
    // PDA signer at arbitrary hop programs. `shared_accounts_route` signs the
    // AMM hops with Jupiter's own `programAuthority`; the vault signs only the
    // transfer out of its pinned source ATA. A route the API only offers as
    // `route` needs a root ceremony in 1B.
    require!(
        args.root.is_some() || args.variant == SWAP_VARIANT_SHARED,
        WardenError::SwapRouteVariantSessionDenied
    );
    // WRDF-0061: native (wrapped-SOL) swaps are NOT supported in 1B. A native
    // token account's value is its lamports, not its `amount` cache (WRDF-0011),
    // and the merged native/SOL accounting a swap would need — bounded by
    // `max_in` and both native-mint program variants canonicalized — is a 1C
    // item. Fail closed here rather than ship the amount-cache-based checks the
    // rest of this handler uses for non-native mints.
    require!(
        args.in_mint != NATIVE_MINT && args.in_mint != NATIVE_MINT_2022
            && args.out_mint != NATIVE_MINT && args.out_mint != NATIVE_MINT_2022,
        WardenError::SwapNativeUnsupported
    );

    let mut account = ctx.accounts.smart_account.load_mut()?;
    let expected = Pubkey::create_program_address(
        &[ACCOUNT_SEED, account.owner_seed.as_ref(), &[account.bump]],
        program_id,
    )
    .map_err(|_| WardenError::Unauthorized)?;
    require_keys_eq!(account_key, expected, WardenError::Unauthorized);
    require!(matches!(account.frozen()?, FrozenState::None), WardenError::Frozen);

    // ---- route data (inline or staged) -----------------------------------
    let route_data: Vec<u8> = match &args.route_data {
        Some(bytes) => bytes.clone(),
        None => {
            let stage = ctx.accounts.stage.as_ref().ok_or(WardenError::BadInstructionLayout)?;
            let expected_stage = Pubkey::create_program_address(
                &[STAGE_SEED, stage.account.as_ref(), stage.creator.as_ref(), stage.hash.as_ref(), &[stage.bump]],
                program_id,
            )
            .map_err(|_| WardenError::StageInvalid)?;
            require_keys_eq!(stage.key(), expected_stage, WardenError::StageInvalid);
            require!(stage.version == 1, WardenError::StageInvalid);
            require_keys_eq!(stage.account, account_key, WardenError::StageInvalid);
            require!(stage.finalized, WardenError::StageInvalid);
            require!(now < stage.expiry_ts, WardenError::StageExpired);
            require!(stage.generation == account.generation, WardenError::StageInvalid);
            require!(stage.policy_version == account.policy.version, WardenError::StageInvalid);
            let creator = ctx.accounts.stage_creator.as_ref().ok_or(WardenError::BadInstructionLayout)?;
            require_keys_eq!(creator.key(), stage.creator, WardenError::StageInvalid);
            stage.data.clone()
        }
    };

    // ---- discriminator + fixed-tail decode -------------------------------
    // The disc is the first 8 bytes; the tail is the LAST 19 (module docs).
    require!(route_data.len() >= 8, WardenError::SwapDataTooShort);
    let disc: [u8; 8] = route_data[..8].try_into().map_err(|_| WardenError::SwapDataTooShort)?;
    let expected_disc = match args.variant {
        SWAP_VARIANT_ROUTE => JUP_ROUTE_DISC,
        _ => JUP_SHARED_ROUTE_DISC,
    };
    require!(disc == expected_disc, WardenError::SwapBadDiscriminator);

    let len = route_data.len();
    let tail_start = len.checked_sub(SWAP_TAIL_LEN).ok_or(WardenError::SwapDataTooShort)?;
    // The tail must not overlap the discriminator (a degenerate tiny payload).
    require!(tail_start >= 8, WardenError::SwapDataTooShort);
    let tail = &route_data[tail_start..];
    let declared_in = u64::from_le_bytes(tail[0..8].try_into().unwrap());
    let platform_fee_bps = tail[SWAP_TAIL_LEN - 1];
    // ADVISORY pre-check (WRDF-0059): the fixed tail is read from the END of the
    // data, which a trailing suffix could decouple from Jupiter's front-parsed
    // args. So these are NOT the security boundary — the REALIZED bound is
    // post-CPI net conservation (in_mint outflow ≤ max_in) plus the post-CPI
    // proof that the treasury actually received a fee. On the root path the
    // exact bytes are additionally frozen by `route_hash` in `SwapBody`, so no
    // suffix can be injected at all. A byte-exact `route_plan` parse (WRDF-0031)
    // is owed before mainnet to make this pre-check a hard guarantee too.
    require!(platform_fee_bps == SWAP_PLATFORM_FEE_BPS, WardenError::SwapPlatformFeeBps);
    require!(declared_in <= args.max_in, WardenError::SwapMaxInExceeded);

    // WRDF-0058: the EXACT bytes about to execute, bound into the root ceremony.
    let route_hash = solana_keccak_hasher::hashv(&[&route_data]).to_bytes();

    // ---- account-position map (real Jupiter v6 IDL, fixed positions) ------
    // route:  auth 1, source 2, dest 3, destMint 5, fee 6
    // shared: auth 2, source 3, dest 6, destMint 8, fee 9
    let (authority_idx, source_idx, dest_idx, dest_mint_idx, fee_idx) = match args.variant {
        SWAP_VARIANT_ROUTE => (1usize, 2, 3, 5, 6),
        _ => (2usize, 3, 6, 8, 9),
    };

    let remaining = ctx.remaining_accounts;
    // Same provisional account caps as `execute` (heap-bound; the wrapper injects
    // the heap frame for Jupiter-scale routes — PHASE1B-MEASUREMENTS §Task 6).
    require!(remaining.len() <= MAX_EXECUTE_ACCOUNTS_TOTAL, WardenError::TooManyExecuteAccounts);
    let writable_count = remaining.iter().filter(|ai| ai.is_writable).count();
    require!(writable_count <= MAX_EXECUTE_WRITABLE, WardenError::TooManyExecuteWritable);

    let account_at = |idx: usize| -> Result<&AccountInfo> {
        remaining.get(idx).ok_or(WardenError::SwapDataTooShort.into())
    };
    // Authority must be the vault PDA.
    require_keys_eq!(account_at(authority_idx)?.key(), account_key, WardenError::SwapAuthorityNotVault);
    // destination_mint account must be out_mint.
    require_keys_eq!(account_at(dest_mint_idx)?.key(), args.out_mint, WardenError::SwapDestNotVaultAta);

    // ---- root ceremony / session authorization ---------------------------
    // Build the logical list [smart_account, signer] ++ remaining for the hash.
    let sa_info = ctx.accounts.smart_account.to_account_info();
    let mut logical_infos: Vec<AccountInfo> = Vec::with_capacity(remaining.len().saturating_add(2));
    logical_infos.push(sa_info.clone());
    logical_infos.push(ctx.accounts.signer.to_account_info());
    logical_infos.extend_from_slice(remaining);

    if let Some(root) = &args.root {
        let ix_sysvar = ctx.accounts.ix_sysvar.as_ref().ok_or(WardenError::BadInstructionLayout)?.to_account_info();
        let logical_hash: Vec<LogicalAccount> = logical_infos
            .iter()
            .map(|ai| LogicalAccount { key: *ai.key, is_signer: ai.is_signer, is_writable: ai.is_writable })
            .collect();
        let body = SwapBody {
            in_mint: args.in_mint,
            out_mint: args.out_mint,
            max_in: args.max_in,
            min_out: args.min_out,
            discriminator: disc,
            route_hash,
            accounts_hash: compute_accounts_hash(&logical_hash),
        };
        let mut body_bytes = Vec::new();
        body.serialize(&mut body_bytes)?;
        verify_and_consume(&mut account, &ix_sysvar, root, program_id, &account_key, action_hash(OP_SWAP_ACTION, &body_bytes), now, slot)?;
    } else {
        let session_account_key = ctx.accounts.session.as_ref().ok_or(WardenError::BadInstructionLayout)?.key();
        let session = ctx.accounts.session.as_ref().ok_or(WardenError::BadInstructionLayout)?;
        authorize_session(session, &session_account_key, &signer_key, &account_key, account.generation, program_id, now, OP_SWAP)?;
    }

    // ---- the AUTHORIZED input (max_in) against EVERY cap, BEFORE the CPI ---
    // (spec §5.2.7 step 1, WRDF-0062). The realized net outflow (≤ max_in) is
    // what is actually committed AFTER the CPI, so a partial fill is not
    // overcharged — but the FULL `max_in` must clear per_tx, lifetime AND the
    // account-wide day/30-day buckets before Jupiter ever receives the PDA
    // signer, or an intra-CPI round trip could pass on net while the buckets
    // had no room for the authorized amount. The bucket check is a
    // non-committing probe on a local copy.
    {
        let (bucket_idx, account_cap) =
            find_cap(&account.policy.caps, &args.in_mint).ok_or(WardenError::CapExceeded)?;
        let account_cap: MintCap = *account_cap;
        let mut probe = *account.buckets.get(bucket_idx).ok_or(WardenError::InvalidAccountData)?;
        buckets::debit(&mut probe, &account_cap, args.max_in, now)?; // probe (discarded)
    }
    if args.root.is_some() {
        let (_, threshold) = find_cap(&account.policy.large_threshold, &args.in_mint).ok_or(WardenError::CapExceeded)?;
        require!(args.max_in <= threshold.per_tx, WardenError::CapExceeded);
    } else {
        let session = ctx.accounts.session.as_ref().ok_or(WardenError::BadInstructionLayout)?;
        let (slot_idx, cap) = find_cap(&session.caps, &args.in_mint).ok_or(WardenError::CapExceeded)?;
        require!(args.max_in <= cap.per_tx, WardenError::CapExceeded);
        // Session lifetime headroom for the FULL authorized amount.
        let spent = *session.lifetime_spent.get(slot_idx).ok_or(WardenError::InvalidAccountData)?;
        let lifetime = *session.lifetime_cap.get(slot_idx).ok_or(WardenError::InvalidAccountData)?;
        require!(spent.checked_add(args.max_in).ok_or(WardenError::Overflow)? <= lifetime, WardenError::CapExceeded);
        // out_mint must have a session cap OR be a default-allowed out mint.
        let out_allowed = find_cap(&session.caps, &args.out_mint).is_some()
            || ALLOWED_OUT_MINTS_DEFAULT.contains(&args.out_mint);
        require!(out_allowed, WardenError::SwapOutMintNotAllowed);
    }

    // Seeds for the CPI, captured before the borrow is released.
    let owner_seed = account.owner_seed;
    let bump = account.bump;
    let account_registry = account.registry;
    drop(account);

    // THE account's registry — required and matched, for the treasury.
    require_keys_eq!(ctx.accounts.registry.key(), account_registry, WardenError::SwapFeeAccountNotTreasury);
    let treasury = ctx.accounts.registry.load()?.treasury;

    // ---- BEFORE snapshot + position validation ---------------------------
    let before = conservation::snapshot(remaining, &account_key)?;
    let pda_lamports_before = sa_info.lamports();
    // GROK-EXP-03 / -05: writable Stake / Vote / ProgramData accounts in the
    // route list are refused BEFORE Jupiter ever receives the PDA signer (and
    // again in `compare_and_account`).
    conservation::reject_unsupported_writable_owners(&before)?;

    // Source: the CANONICAL vault ATA of in_mint (WRDF-0070). Owner==PDA +
    // mint alone would accept any vault-owned in_mint account (an escrow /
    // auxiliary account); the caller declared "the vault ATA of in_mint", so
    // require exactly the associated-token address derived from the vault, the
    // mint, and this account's actual token program.
    let src = vault_token(&before, source_idx, &account_key)?;
    require_keys_eq!(src.mint, args.in_mint, WardenError::SwapSourceNotVaultAta);
    let src_before_amount = src.amount;
    let src_key = *account_at(source_idx)?.key;
    let src_snap = before.get(source_idx).ok_or(WardenError::SwapSourceNotVaultAta)?;
    require_keys_eq!(
        src_key,
        canonical_ata(&account_key, &src_snap.owner_program, &args.in_mint),
        WardenError::SwapSourceNotVaultAta
    );
    // Destination: the CANONICAL vault ATA of out_mint.
    let dst = vault_token(&before, dest_idx, &account_key)?;
    require_keys_eq!(dst.mint, args.out_mint, WardenError::SwapDestNotVaultAta);
    let dst_before_amount = dst.amount;
    let dst_key = *account_at(dest_idx)?.key;
    let dst_snap = before.get(dest_idx).ok_or(WardenError::SwapDestNotVaultAta)?;
    require_keys_eq!(
        dst_key,
        canonical_ata(&account_key, &dst_snap.owner_program, &args.out_mint),
        WardenError::SwapDestNotVaultAta
    );
    // GROK-EXP-05 item 3: `route`'s OPTIONAL `destinationTokenAccount` (index
    // 4; the program id is Jupiter's "None" placeholder) is where Jupiter pays
    // the output when it is present. A WRITABLE account in that slot must be
    // the pinned vault destination; read-only cannot be credited and is
    // ignored. (`shared_accounts_route` has no optional destination — index 6
    // IS the destination and is pinned above.)
    if args.variant == SWAP_VARIANT_ROUTE {
        let opt_dest = account_at(4)?;
        if opt_dest.is_writable {
            require_keys_eq!(*opt_dest.key, dst_key, WardenError::SwapDestNotVaultAta);
        }
    }
    // Platform fee: the CANONICAL treasury ATA of in_mint or out_mint.
    let fee = before.get(fee_idx).ok_or(WardenError::SwapFeeAccountNotTreasury)?;
    let fee_tok = fee.token.as_ref().ok_or(WardenError::SwapFeeAccountNotTreasury)?;
    require_keys_eq!(fee_tok.owner, treasury, WardenError::SwapFeeAccountNotTreasury);
    require!(
        fee_tok.mint == args.in_mint || fee_tok.mint == args.out_mint,
        WardenError::SwapFeeAccountNotTreasury
    );
    let fee_mint = fee_tok.mint;
    require_keys_eq!(
        *account_at(fee_idx)?.key,
        canonical_ata(&treasury, &fee.owner_program, &fee_mint),
        WardenError::SwapFeeAccountNotTreasury
    );
    // WRDF-0059: the decoded `platform_fee_bps` is suffix-attackable, so the
    // treasury fee is proven AFTER the CPI by requiring this account's balance
    // to have INCREASED — a route that skipped the fee (front-parsed 0 bps
    // under a fake tail) is caught regardless of what the tail claimed.
    let fee_before = fee_tok.amount;
    let fee_key = *account_at(fee_idx)?.key;

    // WRDF-0065: pin the WRITABLE vault set to EXACTLY {source, destination}.
    // Every route account is forwarded to Jupiter carrying the PDA signer, so a
    // writable vault-owned token account other than the two swap roles could be
    // round-tripped inside the CPI (drain a second vault account and return all
    // but max_in before control comes back) — a manipulation net accounting and
    // the source-local bound both miss. With no other writable vault token
    // account reachable, the only vault value the route can move is the source
    // (bounded by net ≤ max_in) and the destination; this is also what bounds
    // the WRDF-0059 suffix residual on the session path. A vault account passed
    // READ-ONLY is harmless (the CPI cannot debit it), so only writable ones are
    // rejected.
    for (i, snap) in before.iter().enumerate() {
        let is_vault_token = snap.token.as_ref().is_some_and(|t| t.owner == account_key);
        if is_vault_token && snap.is_writable {
            require!(snap.key == src_key || snap.key == dst_key, WardenError::SwapExtraWritableVault);
        }
        let _ = i;
    }

    // ---- CPI: pinned Jupiter, PDA-signed ---------------------------------
    // The authority position is the vault PDA: it SIGNS (via invoke_signed) but
    // is passed read-only to Jupiter (it is the `smart_account` named account,
    // writable there for the bucket update, but Jupiter never writes the
    // authority — forcing it read-only in the CPI keeps the PDA's message-level
    // writability from leaking into the route).
    let metas: Vec<AccountMeta> = remaining
        .iter()
        .enumerate()
        .map(|(i, ai)| AccountMeta {
            pubkey: *ai.key,
            is_signer: i == authority_idx,
            is_writable: ai.is_writable && i != authority_idx,
        })
        .collect();
    // The program account itself must be present among the infos for invoke.
    require!(
        remaining.iter().any(|ai| *ai.key == SWAP_TARGET_PROGRAM),
        WardenError::SwapProgramNotPinned
    );
    // Move `route_data` into the instruction (no clone) and pass `remaining`
    // directly as the infos — SBF heap is the swap account cap's binding
    // constraint (Task 6 sweep), so the handler avoids every superfluous
    // allocation.
    let ix = Instruction { program_id: SWAP_TARGET_PROGRAM, accounts: metas, data: route_data };
    invoke_signed(&ix, remaining, &[&[ACCOUNT_SEED, owner_seed.as_ref(), &[bump]]])?;

    // ---- AFTER snapshot + conservation -----------------------------------
    let mut before = before;
    let mut after = conservation::snapshot(remaining, &account_key)?;
    let pda_lamports_after = sa_info.lamports();
    // The vault PDA sits at the authority position of the route account list;
    // its own lamports are tracked separately (`pda_lamports_*`). At the message
    // level it is the WRITABLE `smart_account`, so its snapshot carries
    // `is_writable = true`, which would trip conservation's warden-owned-writable
    // reject. Neutralize that in place (it is not a token account, so once
    // read-only it is simply ignored) rather than cloning the whole slice.
    for s in before.iter_mut().chain(after.iter_mut()) {
        if s.key == account_key {
            s.is_writable = false;
        }
    }
    let outflow = compare_and_account(&before, &after, &account_key, &[], pda_lamports_before, pda_lamports_after)?;

    // Source decreased by the ACTUAL input; must be ≤ max_in.
    let src_after = find_token(&after, &src_key).ok_or(WardenError::ConservationViolated)?;
    let actual_in = src_before_amount.checked_sub(src_after.amount).ok_or(WardenError::SwapUnexpectedOutflow)?;
    require!(actual_in <= args.max_in, WardenError::SwapMaxInExceeded);

    // WRDF-0060: `min_out` is the NET gain of out_mint across EVERY vault-owned
    // out_mint token account, not just the declared destination's local
    // increase. Otherwise a route could debit a second vault out_mint account
    // and credit the declared one by the same amount — the local delta clears
    // min_out while the vault gained nothing net. Summed with signed math.
    let net_out_gain = net_vault_mint_delta(&before, &after, &args.out_mint, &account_key)?;
    require!(net_out_gain >= i128::from(args.min_out), WardenError::SwapMinOutNotMet);
    let _ = dst_before_amount; // superseded by the net-gain check
    let _ = dst_key;

    // WRDF-0059: the treasury fee must actually have been paid (balance up)…
    let fee_after = find_token(&after, &fee_key).ok_or(WardenError::SwapFeeNotTaken)?;
    let fee_delta = fee_after.amount.checked_sub(fee_before).ok_or(WardenError::SwapFeeNotTaken)?;
    require!(fee_delta >= 1, WardenError::SwapFeeNotTaken);
    // …and GROK-EXP-01 (2026-08-22): paid at the 85 bps RATE, not merely
    // "some". "Balance increased" accepted 1 base unit as proof of an 85 bps
    // fee, so a route front-parsed at `platform_fee_bps = 0` under a suffixed
    // tail claiming 85 (WRDF-0059) kept the protocol's fee. Jupiter computes its
    // fee by integer division of the GROSS leg: `fee = floor(gross × 85 /
    // 10_000)`. The realised floor must therefore be taken over that gross leg.
    //
    // WRDF-0106 (2026-08-23): the out-mint branch previously used the NET
    // out-gain as the basis, on the mistaken reasoning that "net = gross − fee
    // so a floor over net is strictly ≤ the honest fee and never rejects one".
    // That is wrong: Jupiter's quoted `outAmount` — which becomes the vault's
    // net gain — is ALREADY net of the platform fee, so the gross leg the fee
    // was taken on is `net + fee`, not `net`. Basing the floor on net undercharges
    // (accepts `floor(net × 85 / 10_000) < floor(gross × 85 / 10_000)`). Rebuild
    // the gross leg as `net_out_gain + fee_delta` and take the floor over THAT.
    // The in-mint branch is unaffected: `actual_in` is the gross input leg
    // already (the fee there is taken from the input the vault paid in full).
    // This does NOT replace the byte-exact `route_plan` parse still owed before
    // mainnet (WRDF-0031/0059); it is the realised-fee bound those findings
    // assumed was here.
    let fee_floor = if fee_mint == args.in_mint {
        platform_fee_floor(actual_in)?
    } else {
        let net_u64 = u64::try_from(net_out_gain).map_err(|_| WardenError::SwapUnexpectedOutflow)?;
        let gross = net_u64.checked_add(fee_delta).ok_or(WardenError::Overflow)?;
        platform_fee_floor(gross)?
    };
    require!(fee_delta >= fee_floor, WardenError::SwapFeeNotTaken);

    // The ONLY net vault outflow may be `in_mint` (≤ max_in). Any other mint
    // leaving — or any raw SOL (native is rejected up front) — is value the
    // adapter did not authorize.
    for (mint, amt) in &outflow.by_mint {
        require!(*mint == args.in_mint, WardenError::SwapUnexpectedOutflow);
        require!(*amt <= args.max_in, WardenError::SwapMaxInExceeded);
    }
    require!(outflow.sol == 0, WardenError::SwapUnexpectedOutflow);

    // ---- commit the caps on the NET in_mint outflow ----------------------
    let in_charge = outflow.by_mint.iter().find(|(m, _)| *m == args.in_mint).map(|(_, a)| *a).unwrap_or(0);

    let mut account = ctx.accounts.smart_account.load_mut()?;
    if args.root.is_none() {
        let session = ctx.accounts.session.as_mut().ok_or(WardenError::BadInstructionLayout)?;
        let (slot_idx, cap) = find_cap(&session.caps, &args.in_mint).ok_or(WardenError::CapExceeded)?;
        require!(in_charge <= cap.per_tx, WardenError::CapExceeded);
        let spent = *session.lifetime_spent.get(slot_idx).ok_or(WardenError::InvalidAccountData)?;
        let lifetime = *session.lifetime_cap.get(slot_idx).ok_or(WardenError::InvalidAccountData)?;
        let new_spent = spent.checked_add(in_charge).ok_or(WardenError::Overflow)?;
        require!(new_spent <= lifetime, WardenError::CapExceeded);
        *session.lifetime_spent.get_mut(slot_idx).ok_or(WardenError::InvalidAccountData)? = new_spent;
    }
    // Account-wide buckets — every outflow path converges here.
    let (idx, account_cap) = find_cap(&account.policy.caps, &args.in_mint).ok_or(WardenError::CapExceeded)?;
    let account_cap: MintCap = *account_cap;
    let bucket = account.buckets.get_mut(idx).ok_or(WardenError::InvalidAccountData)?;
    buckets::debit(bucket, &account_cap, in_charge, now)?;
    drop(account);

    // ---- consume the stage on success ------------------------------------
    if args.route_data.is_none() {
        let stage = ctx.accounts.stage.as_ref().ok_or(WardenError::BadInstructionLayout)?;
        let creator = ctx.accounts.stage_creator.as_ref().ok_or(WardenError::BadInstructionLayout)?;
        stage.close(creator.to_account_info())?;
    }

    Ok(())
}

/// `floor(base × SWAP_PLATFORM_FEE_BPS / 10_000)` — the smallest treasury fee
/// an honest 85 bps route can have paid on a leg of `base` units (GROK-EXP-01).
/// Checked math only; `checked_div` by a non-zero constant cannot fail but is
/// written checked so the arithmetic lint stays silent without a proof comment.
pub(crate) fn platform_fee_floor(base: u64) -> Result<u64> {
    base.checked_mul(u64::from(SWAP_PLATFORM_FEE_BPS))
        .and_then(|x| x.checked_div(10_000))
        .ok_or_else(|| WardenError::Overflow.into())
}

/// The `TokenSnap` at `remaining[idx]`, required to be a vault-owned token
/// account (owner == the PDA). The mint is checked by the caller.
fn vault_token<'a>(before: &'a [Snap], idx: usize, vault: &Pubkey) -> Result<&'a TokenSnap> {
    let snap = before.get(idx).ok_or(WardenError::SwapSourceNotVaultAta)?;
    let tok = snap.token.as_ref().ok_or(WardenError::SwapSourceNotVaultAta)?;
    require_keys_eq!(tok.owner, *vault, WardenError::SwapSourceNotVaultAta);
    Ok(tok)
}

/// Find a token account by key in a snapshot slice.
fn find_token<'a>(snaps: &'a [Snap], key: &Pubkey) -> Option<&'a TokenSnap> {
    snaps.iter().find(|s| s.key == *key).and_then(|s| s.token.as_ref())
}

/// The canonical Associated Token Account address for `(owner, token_program,
/// mint)` (WRDF-0070). `find_program_address` over the ATA program's fixed
/// seeds `[owner, token_program, mint]`. `token_program` is the account's actual
/// runtime owner (SPL Token or Token-2022), so a T22 ATA derives under the T22
/// program id, matching what the account really is.
fn canonical_ata(owner: &Pubkey, token_program: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ATA_PROGRAM_ID,
    )
    .0
}

/// Signed NET amount delta of `mint` across EVERY vault-owned token account of
/// it (positive = the vault gained). `before`/`after` are the same accounts in
/// the same order (two passes over `remaining`), so each account is matched
/// positionally. Uses `i128` so a net loss is representable (WRDF-0060).
fn net_vault_mint_delta(before: &[Snap], after: &[Snap], mint: &Pubkey, vault: &Pubkey) -> Result<i128> {
    let mut delta: i128 = 0;
    for (i, b) in before.iter().enumerate() {
        let is_vault_mint = |t: Option<&TokenSnap>| t.is_some_and(|t| t.owner == *vault && t.mint == *mint);
        let b_amt = if is_vault_mint(b.token.as_ref()) {
            b.token.as_ref().map(|t| t.amount).unwrap_or(0)
        } else {
            0
        };
        let a = after.get(i).ok_or(WardenError::ConservationViolated)?;
        let a_amt = if is_vault_mint(a.token.as_ref()) {
            a.token.as_ref().map(|t| t.amount).unwrap_or(0)
        } else {
            0
        };
        delta = delta
            .checked_add(i128::from(a_amt))
            .and_then(|d| d.checked_sub(i128::from(b_amt)))
            .ok_or(WardenError::Overflow)?;
    }
    Ok(delta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_target_program_is_pinned() {
        #[cfg(feature = "test-jup")]
        assert_eq!(SWAP_TARGET_PROGRAM, crate::constants::TEST_JUP_MOCK_ID);
        #[cfg(not(feature = "test-jup"))]
        assert_eq!(SWAP_TARGET_PROGRAM, crate::constants::JUPITER_V6_ID);
    }

    /// GROK-EXP-01: the fee floor is floor(base × 85 / 10_000), checked.
    #[test]
    fn platform_fee_floor_is_floor_of_85_bps() {
        assert_eq!(platform_fee_floor(0).unwrap(), 0);
        assert_eq!(platform_fee_floor(117).unwrap(), 0); // 117 × 85 = 9945 < 10_000
        assert_eq!(platform_fee_floor(118).unwrap(), 1); // 118 × 85 = 10_030
        assert_eq!(platform_fee_floor(1_000_000).unwrap(), 8_500);
        assert_eq!(platform_fee_floor(900_000).unwrap(), 7_650);
        assert_eq!(platform_fee_floor(999_999).unwrap(), 8_499); // 84_999.915 → floor
        assert_eq!(platform_fee_floor(u64::MAX / 85).unwrap(), (u64::MAX / 85) * 85 / 10_000);
        assert!(platform_fee_floor(u64::MAX).is_err(), "overflow is an error, never a wrap");
    }

    #[test]
    fn jup_discriminators_match_anchor_sighash() {
        use sha2::{Digest, Sha256};
        let sighash = |n: &str| {
            let mut h = Sha256::new();
            h.update(b"global:");
            h.update(n.as_bytes());
            let mut d = [0u8; 8];
            d.copy_from_slice(&h.finalize()[..8]);
            d
        };
        assert_eq!(JUP_ROUTE_DISC, sighash("route"));
        assert_eq!(JUP_SHARED_ROUTE_DISC, sighash("shared_accounts_route"));
    }

    /// Cross-language pin: `action_hash(OP_SWAP_ACTION, borsh(SwapBody))` must
    /// equal the TS mirror's value (`packages/core/test/transcript.test.ts`).
    #[test]
    fn swap_action_hash_matches_pinned_vector() {
        let body = SwapBody {
            in_mint: Pubkey::new_from_array([0x11; 32]),
            out_mint: Pubkey::new_from_array([0x22; 32]),
            max_in: 7,
            min_out: 3,
            discriminator: [0x09; 8],
            route_hash: [0xCC; 32],
            accounts_hash: [0xBB; 32],
        };
        let mut buf = Vec::new();
        body.serialize(&mut buf).unwrap();
        assert_eq!(
            hex::encode(action_hash(OP_SWAP_ACTION, &buf)),
            "1dc529b694012bbcfe50b10dff494ab093fbc0295494ed8f5d9b2555e8d61891"
        );
    }

    // -- net_vault_mint_delta (pure) — proves the WRDF-0060 net rule directly,
    //    independent of the WRDF-0065 writable-vault pinning that also guards it.
    fn tok_snap(key: Pubkey, owner: Pubkey, mint: Pubkey, amount: u64) -> Snap {
        Snap {
            key,
            exists: true,
            owner_program: crate::constants::SPL_TOKEN_ID,
            lamports: 2_039_280,
            data_len: 165,
            token: Some(TokenSnap {
                mint,
                owner,
                amount,
                delegate: None,
                delegated_amount: 0,
                close_authority: None,
                state: 1,
                is_native: None,
                tlv_hash: [0; 32],
                program: crate::constants::PROGRAM_SPL,
            }),
            mint: None,
            token_parse_failed: false,
            is_writable: true,
        }
    }

    #[test]
    fn net_vault_mint_delta_sums_across_vault_accounts_and_offsets() {
        let vault = Pubkey::new_unique();
        let out = Pubkey::new_unique();
        let stranger = Pubkey::new_unique();
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();
        let s = Pubkey::new_unique();
        // Account a: vault out, +100. Account b: vault out, -100 (offset).
        // Account s: a STRANGER's out account, +1000 (ignored — not the vault's).
        let before = vec![
            tok_snap(a, vault, out, 0),
            tok_snap(b, vault, out, 100),
            tok_snap(s, stranger, out, 0),
        ];
        let after = vec![
            tok_snap(a, vault, out, 100),
            tok_snap(b, vault, out, 0),
            tok_snap(s, stranger, out, 1000),
        ];
        // Net vault gain of `out` = (+100) + (-100) = 0 — the offset nets out.
        assert_eq!(net_vault_mint_delta(&before, &after, &out, &vault).unwrap(), 0);
        // A single honest gain sums positively.
        let before2 = vec![tok_snap(a, vault, out, 0)];
        let after2 = vec![tok_snap(a, vault, out, 250)];
        assert_eq!(net_vault_mint_delta(&before2, &after2, &out, &vault).unwrap(), 250);
        // A net loss is representable (i128, negative).
        let after3 = vec![tok_snap(a, vault, out, 0)];
        let before3 = vec![tok_snap(a, vault, out, 40)];
        assert_eq!(net_vault_mint_delta(&before3, &after3, &out, &vault).unwrap(), -40);
    }

    #[test]
    fn swap_body_borsh_layout_is_pinned() {
        let b = SwapBody {
            in_mint: Pubkey::new_from_array([1u8; 32]),
            out_mint: Pubkey::new_from_array([2u8; 32]),
            max_in: 7,
            min_out: 3,
            discriminator: [9u8; 8],
            route_hash: [0xCD; 32],
            accounts_hash: [0xAB; 32],
        };
        let mut buf = Vec::new();
        b.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), 32 + 32 + 8 + 8 + 8 + 32 + 32);
        assert_eq!(&buf[..32], &[1u8; 32]);
        assert_eq!(&buf[32..64], &[2u8; 32]);
        assert_eq!(&buf[64..72], &7u64.to_le_bytes());
        assert_eq!(&buf[72..80], &3u64.to_le_bytes());
        assert_eq!(&buf[80..88], &[9u8; 8]);
        assert_eq!(&buf[88..120], &[0xCD; 32]);
        assert_eq!(&buf[120..152], &[0xAB; 32]);
    }
}
