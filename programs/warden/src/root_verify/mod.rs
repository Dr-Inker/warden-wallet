//! Passkey (P-256 / WebAuthn) root-key verification — the security core every
//! root-authorized instruction depends on.
//!
//! One successful call proves, for the currently executing instruction:
//!
//! 0. the instruction is running at **transaction level** — no middleman
//!    program CPI'd into it (`RootRequiresTopLevel`, spec §5.1);
//! 1. the account's stored root key is a P-256 passkey (`root_kind == 0`);
//! 2. `authenticatorData` carries the account's stored `rp_id_hash` and both
//!    UP and UV flags (`auth_data`);
//! 3. `clientDataJSON` is a single, well-formed JSON object no larger than
//!    `MAX_CLIENT_DATA_LEN` whose **depth-0** `type`/`challenge`/`origin` are
//!    unique and decoded (`client_data`);
//! 4. `type == "webauthn.get"`, `crossOrigin` absent or `false`, and `origin`
//!    equals the account's stored origin byte-for-byte;
//! 5. `now <= expiry_ts <= now + MAX_ROOT_EXPIRY_SECS` **and**
//!    `signed_slot <= slot < signed_slot + MAX_ROOT_SLOT_AGE` — the two-clock
//!    rule (spec §4/§5.1): the wall clock is the secondary bound, the slot is
//!    the primary one;
//! 6. `challenge == base64url_nopad(transcript_hash(...))` over the account's
//!    *current* `generation`, `policy.version` and `root_nonce`, the account
//!    address, the program id, the stored `cluster_tag`, `expiry_ts`,
//!    `signed_slot` and the caller-recomputed `action_hash` (`transcript`);
//! 7. a secp256r1 precompile instruction earlier in this same transaction
//!    verified exactly `(root_pubkey33, authenticatorData ‖
//!    SHA-256(clientDataJSON))` with all three instruction indices set to
//!    "this instruction" (`precompile`).
//!
//! What it deliberately does **not** do: verify the ECDSA signature (the
//! runtime's precompile does that, and it cannot be CPI'd — `tests/sigverify_wiring.rs`
//! is the L0 gate proving the runtime really is doing it), enforce the
//! WebAuthn sign counter (synced passkeys make it meaningless), or check
//! `frozen` (freeze/unfreeze are themselves root instructions — gating is the
//! caller's job, per spec §5.1). It also does **not** consume the nonce —
//! see `RootContext` below.
//!
//! ## Why the inputs arrive as a `RootContext` and not as `&mut SmartAccount`
//!
//! Phase 1B's proof-of-possession at `create_account` must run this exact
//! ceremony **before the `SmartAccount` exists**: the transcript is over
//! `generation = 0`, `policy_version = 1`, `root_nonce = 0` and the
//! about-to-be-created address, with the root key, origin and `cluster_tag`
//! coming from the instruction's own arguments. So the verifier takes the
//! eight signed values it actually needs (`RootContext`) rather than a loaded
//! account, and nonce consumption — which only makes sense for an account
//! that already exists — moves to the caller. `verify_and_consume` is the
//! one-call wrapper the six Phase-1A callers use, and it is where "verify,
//! then increment" stays a single atomic step for them.

pub mod auth_data;
pub mod client_data;
pub mod precompile;
pub mod transcript;

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT};

use crate::constants::{MAX_ROOT_EXPIRY_SECS, MAX_ROOT_SLOT_AGE};
use crate::errors::WardenError;
use crate::state::{RootKey, SmartAccount};

/// Instruction-argument payload every root-authorized instruction carries, in
/// addition to its own arguments (which are hashed into `action_hash`).
///
/// Budget (C7): `authenticator_data` is 37 B for a platform passkey and
/// `client_data_json` is capped at `MAX_CLIENT_DATA_LEN` = 512 B, so the worst
/// case is ~570 B on top of the ~180 B precompile instruction.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct RootArgs {
    /// Index, within this transaction, of the secp256r1 precompile
    /// instruction that verified the assertion. Must be < our own index.
    pub precompile_ix_index: u8,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    /// Absolute unix seconds; the ceremony is valid for at most
    /// `MAX_ROOT_EXPIRY_SECS` into the future. Secondary bound — see
    /// `signed_slot`.
    pub expiry_ts: i64,
    /// The slot the client observed when it built the ceremony (spec §4,
    /// rev 8). PRIMARY freshness bound: the ceremony is valid only while
    /// `signed_slot <= Clock::slot < signed_slot + MAX_ROOT_SLOT_AGE`.
    ///
    /// It is part of the signed transcript, so it cannot be edited after the
    /// fact to stretch or move the window — bending it here only produces a
    /// `ChallengeMismatch`.
    pub signed_slot: u64,
}

/// Everything `verify_root_assertion` needs about the *identity being
/// authenticated*, decoupled from where those values are stored.
///
/// For the six Phase-1A root instructions this is built from a loaded
/// `SmartAccount` by [`RootContext::from_account`]. For Phase 1B's
/// proof-of-possession at `create_account` (Task 2b) it is built from the
/// instruction's own arguments, because the account does not exist yet.
///
/// `origin` is a borrowed slice rather than an owned buffer so neither caller
/// has to copy up to 64 bytes onto the SBF stack; the borrow ends when the
/// context is dropped, which is before any caller mutates the account.
pub struct RootContext<'a> {
    /// Compressed SEC1 P-256 point (`SmartAccount.root_pubkey`).
    pub root_pubkey33: [u8; 33],
    pub rp_id_hash: [u8; 32],
    /// The expected `clientDataJSON.origin`, exactly `origin_len` bytes — NOT
    /// the fixed 64-byte field with its zero padding.
    pub origin: &'a [u8],
    pub cluster_tag: [u8; 32],
    /// The `SmartAccount` address the transcript is bound to.
    pub account: Pubkey,
    pub generation: u64,
    pub policy_version: u32,
    /// The nonce value the transcript must name. Consuming it is the caller's
    /// job (see the module docs).
    pub root_nonce: u64,
}

impl<'a> RootContext<'a> {
    /// Build the context from an already-loaded, already-address-checked
    /// `SmartAccount`.
    ///
    /// Rejects an Ed25519 root here rather than inside the verifier: those
    /// accounts are authenticated by a real transaction signature, not by this
    /// path, and misreading 32 of the 33 stored bytes as a compressed point
    /// must never be possible. This is the same check, in the same position
    /// (first, before any instruction data is touched), that Phase 1A ran as
    /// step 1 of `verify_root_assertion`.
    pub fn from_account(account: &'a SmartAccount, account_key: &Pubkey) -> Result<Self> {
        let root_pubkey33 = match account.root()? {
            RootKey::P256Passkey { pubkey } => pubkey,
            RootKey::Ed25519 { .. } => return Err(WardenError::RootKindUnsupported.into()),
        };
        let origin = account
            .origin
            .get(..usize::from(account.origin_len))
            .ok_or(WardenError::InvalidAccountData)?;
        Ok(Self {
            root_pubkey33,
            rp_id_hash: account.rp_id_hash,
            origin,
            cluster_tag: account.cluster_tag,
            account: *account_key,
            generation: account.generation,
            policy_version: account.policy.version,
            root_nonce: account.root_nonce,
        })
    }
}

/// Reject any root-authorized instruction that is not running at transaction
/// level (spec §5.1, adopted from LazorKit, MIT).
///
/// A root path invoked through a middleman program would have that program
/// sitting between the user and the ceremony, and — more concretely — would
/// make every "which instruction am I, and what is at index N" question the
/// Instructions sysvar answers refer to the *outer* transaction rather than
/// to the call actually executing. Rather than reason about what an
/// intermediate program could do with that gap, the gap is closed.
///
/// This is **distinct** from the existing self-CPI rule, which only blocks
/// warden → warden.
///
/// ## Where it sits, and what that means for the error a CPI'd call sees
///
/// It is the FIRST thing `verify_root_assertion` does, so it is a single choke
/// point every root path passes through and no future root instruction can
/// forget it. It is *not* the first thing the enclosing handler does, though:
/// the handler has already loaded the account and re-derived its PDA, and
/// `RootContext::from_account` has already rejected a non-passkey root. So a
/// CPI'd call that ALSO has a bad account address or an Ed25519 root surfaces
/// `Unauthorized` / `RootKindUnsupported` rather than `RootRequiresTopLevel`.
/// Every one of those is a rejection, and the ordering is deliberate — those
/// checks are about the state being addressed, this one is about the call —
/// but it means the error code alone does not tell a client "you were CPI'd"
/// unless everything else was well-formed.
pub fn require_top_level() -> Result<()> {
    require!(
        get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT,
        WardenError::RootRequiresTopLevel
    );
    Ok(())
}

/// Verify a root passkey assertion. **Does not consume the nonce** — see
/// `verify_and_consume`, which is what the six Phase-1A callers use.
///
/// `action_hash` must be recomputed by the caller from the *executing*
/// instruction's own arguments (`transcript::action_hash(op_type,
/// &args.try_to_vec()?)`), never taken from instruction data — that is what
/// stops an attacker from re-pointing a signed ceremony at different
/// arguments.
///
/// `now` is `Clock::unix_timestamp` and `slot` is `Clock::slot`; both are read
/// by the caller from the same `Clock::get()`.
pub fn verify_root_assertion(
    ctx: &RootContext<'_>,
    ix_sysvar: &AccountInfo,
    args: &RootArgs,
    program_id: &Pubkey,
    action_hash: [u8; 32],
    now: i64,
    slot: u64,
) -> Result<()> {
    // 0. Top-level only. First, because it is a property of the *call*, not of
    //    anything the caller supplied, and nothing below is meaningful if a
    //    middleman is standing in the way.
    require_top_level()?;

    // 1. Root must be a passkey — proven when the context was built
    //    (`RootContext::from_account`, or Task 2b's args-built context).

    // 2. authenticatorData: rpIdHash from STATE (never from instruction data), UP|UV.
    auth_data::check_auth_data(&args.authenticator_data, &ctx.rp_id_hash)?;

    // 3./4. clientDataJSON: strict depth-0 scan, then the semantic comparisons.
    let cd = client_data::parse_strict(&args.client_data_json)?;
    require!(
        cd.typ.as_slice() == b"webauthn.get".as_slice(),
        WardenError::ClientDataTypeMismatch
    );
    require!(!cd.cross_origin_true, WardenError::CrossOriginNotAllowed);
    require!(cd.origin.as_slice() == ctx.origin, WardenError::OriginMismatch);

    // 5. Freshness, on BOTH clocks (spec §5.1 two-clock rule). Both values are
    //    signed into the transcript, so neither window can be stretched by
    //    editing instruction data.
    //
    //    a) Wall clock — the secondary bound. Its long tail exists for Phase
    //       1C's deferred/timelocked flow.
    require!(now <= args.expiry_ts, WardenError::Expired);
    require!(
        args.expiry_ts
            <= now
                .checked_add(MAX_ROOT_EXPIRY_SECS)
                .ok_or(WardenError::Overflow)?,
        WardenError::Expired
    );
    //    b) Slot — the PRIMARY bound, `signed_slot <= slot < signed_slot +
    //       MAX_ROOT_SLOT_AGE`. The left half rejects a future slot outright
    //       (otherwise a client buys a longer window by signing ahead); the
    //       right half is strict, so an age of exactly MAX_ROOT_SLOT_AGE is
    //       rejected and MAX_ROOT_SLOT_AGE - 1 is accepted.
    require!(args.signed_slot <= slot, WardenError::RootSlotInFuture);
    require!(
        slot < args
            .signed_slot
            .checked_add(MAX_ROOT_SLOT_AGE)
            .ok_or(WardenError::Overflow)?,
        WardenError::RootSlotStale
    );

    // 6. Challenge == base64url(transcript over the account's CURRENT state).
    let expected_challenge =
        transcript::b64url_no_pad(&transcript_for(ctx, program_id, ctx.root_nonce, args, &action_hash));
    if cd.challenge != expected_challenge {
        // Diagnostic only, on the failure path: if the assertion matches the
        // *previous* nonce it is a replay of an already-consumed ceremony, and
        // saying so is far more actionable than a bare challenge mismatch.
        if let Some(prev) = ctx.root_nonce.checked_sub(1) {
            let replayed =
                transcript::b64url_no_pad(&transcript_for(ctx, program_id, prev, args, &action_hash));
            require!(cd.challenge != replayed, WardenError::NonceMismatch);
        }
        return Err(WardenError::ChallengeMismatch.into());
    }

    // 7. The precompile in this transaction verified exactly this key over
    //    exactly `authenticatorData ‖ SHA-256(clientDataJSON)`.
    let cdj_hash = solana_sha256_hasher::hash(&args.client_data_json).to_bytes();
    let mut message = Vec::with_capacity(args.authenticator_data.len().saturating_add(32));
    message.extend_from_slice(&args.authenticator_data);
    message.extend_from_slice(&cdj_hash);
    precompile::bind_precompile(
        ix_sysvar,
        args.precompile_ix_index,
        &ctx.root_pubkey33,
        &message,
    )?;

    Ok(())
}

/// `verify_root_assertion` against a loaded `SmartAccount`, followed by
/// consuming its `root_nonce` — the shape all six Phase-1A root instructions
/// want.
///
/// The nonce is incremented only on success, so a rejected assertion never
/// costs a ceremony. Anything that reads `root_nonce` after this returns sees
/// the new value, which is correct: one ceremony, one action.
#[allow(clippy::too_many_arguments)]
pub fn verify_and_consume(
    account: &mut SmartAccount,
    ix_sysvar: &AccountInfo,
    args: &RootArgs,
    program_id: &Pubkey,
    account_key: &Pubkey,
    action_hash: [u8; 32],
    now: i64,
    slot: u64,
) -> Result<()> {
    {
        let ctx = RootContext::from_account(account, account_key)?;
        verify_root_assertion(&ctx, ix_sysvar, args, program_id, action_hash, now, slot)?;
    }
    account.root_nonce = account
        .root_nonce
        .checked_add(1)
        .ok_or(WardenError::Overflow)?;
    Ok(())
}

fn transcript_for(
    ctx: &RootContext<'_>,
    program_id: &Pubkey,
    root_nonce: u64,
    args: &RootArgs,
    action_hash: &[u8; 32],
) -> [u8; 32] {
    transcript::transcript_hash(
        &ctx.cluster_tag,
        program_id,
        &ctx.account,
        ctx.generation,
        ctx.policy_version,
        root_nonce,
        args.expiry_ts,
        args.signed_slot,
        action_hash,
    )
}
