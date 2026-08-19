//! `create_account` — initializes a passkey-rooted `SmartAccount` PDA.
//!
//! **Creation is authenticated and root-bound** (Phase 1B Task 2b). Two
//! properties, and both are needed — either alone is squattable:
//!
//! 1. **The address is derived from the root key.** The PDA seed is not a
//!    client-chosen blob any more; it is computed on-chain as
//!    `owner_seed = Keccak256("WARDEN/seed/v1" ‖ root_pubkey33 ‖ salt32)` and
//!    the account lives at `["account", owner_seed]`. A front-runner who
//!    copies the victim's `salt` out of the mempool and substitutes their own
//!    root key therefore lands a *different* address — the victim's is
//!    untouched.
//! 2. **A real root ceremony is required.** The instruction carries a
//!    `root_assertion` over `action_hash(0x06, borsh(CreateBody))`, verified
//!    against the root key in the arguments (the account does not exist yet,
//!    so the verifier runs on a `RootContext` built from those arguments at
//!    `generation = 0`, `policy_version = 1`, `root_nonce = 0`, with the
//!    derived address as the transcript's `account`). A front-runner who
//!    keeps the victim's root key so as to hit the victim's address cannot
//!    produce that assertion — they do not hold the passkey. On success the
//!    account is written with `root_nonce = 1`: the creating ceremony is
//!    consumed like any other.
//!
//! Two Phase-1A gaps close as a side effect. The precompile does the P-256
//! **on-curve** validation for free (an `x` that is a well-formed encoding but
//! not a point on the curve cannot produce a signature the runtime accepts),
//! which is the complete form of the check `validate_root` can only approximate
//! — see the note above `validate_root`. And because `verify_root_assertion`
//! starts with `require_top_level`, `create_account` is now **top-level only**,
//! like every other root path (spec §5.1).
//!
//! The extension MUST still read the account back and verify `root == its
//! passkey` before showing a receive address — that is cheap, and it is the
//! only client-side check that also covers a buggy client. What it is no
//! longer *mitigating* is a live attack: there is no longer a window in which
//! someone else's root can end up at the address this instruction creates.

use anchor_lang::prelude::*;

use crate::constants::{ACCOUNT_SEED, DAY_SECS, MAX_MINTS_AT_CREATE, MAX_MINT_CAPS};
use crate::errors::WardenError;
use crate::root_verify::transcript::{action_hash, OP_CREATE};
use crate::root_verify::{verify_root_assertion, RootArgs, RootContext};
use crate::state::session::OPS_MASK_KNOWN;
use crate::state::{FrozenState, Policy, PolicyArgs, RootKey, SmartAccount};

/// Matches `SmartAccount.origin`'s fixed storage width.
pub const MAX_ORIGIN_LEN: usize = 64;
/// v1 requires every origin to be a Chrome extension origin (spec §4).
pub const ORIGIN_PREFIX: &[u8] = b"chrome-extension://";
/// A Chrome extension id is exactly 32 characters drawn from `a..=p`
/// (Chromium renders the id as base-16 over that alphabet), so the ONLY
/// canonical origin shape is `chrome-extension://` + 32 such bytes.
pub const EXTENSION_ID_LEN: usize = 32;
/// `ORIGIN_PREFIX.len() + EXTENSION_ID_LEN` — the exact length every accepted
/// origin has. `MAX_ORIGIN_LEN` (64) stays the *storage* width, deliberately
/// wider so a future scheme can be admitted without a realloc.
pub const CANONICAL_ORIGIN_LEN: usize = 19 + EXTENSION_ID_LEN;
/// The secp256r1 (P-256) field prime `p`, big-endian — the bound a compressed
/// point's x-coordinate must sit strictly below.
pub const P256_FIELD_PRIME_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
/// Policy bound: root/guardian timelocks must be at least one hour.
pub const MIN_TIMELOCK_SECS: i64 = 3600;
/// Policy bound: `max_session_life_secs` may not exceed 30 days.
pub const MAX_SESSION_LIFE_SECS: i64 = 30 * DAY_SECS; // 2_592_000 — both factors are compile-time literals, not runtime arithmetic on account data.

/// Domain separator for the PDA seed derivation. Bumping the `/v1` suffix
/// moves every future account to a different address; existing accounts are
/// unaffected, because the seed they were created under is stored in
/// `SmartAccount.owner_seed` and every root path re-derives from *that*.
pub const OWNER_SEED_DOMAIN: &[u8] = b"WARDEN/seed/v1";

/// `owner_seed = Keccak256("WARDEN/seed/v1" ‖ root_pubkey33 ‖ salt32)` — the
/// PDA seed, computed ON-CHAIN from the root key and a client-chosen salt
/// (spec §4/§5.1, Phase 1B).
///
/// The salt is what keeps one passkey able to hold several independent
/// accounts, and what keeps the address un-derivable by an observer who knows
/// only the root key. The root key is what makes the address **un-squattable**:
/// a front-runner who copies the salt but substitutes their own root lands a
/// different address entirely.
///
/// Keccak (not SHA-256) because it is the hash the transcript already uses, so
/// the SBF binary and the `packages/core` mirror carry one hash function for
/// this instruction rather than two.
pub fn derive_owner_seed(root_pubkey33: &[u8; 33], salt: &[u8; 32]) -> [u8; 32] {
    solana_keccak_hasher::hashv(&[OWNER_SEED_DOMAIN, root_pubkey33, salt]).to_bytes()
}

/// The 33 bytes `derive_owner_seed` hashes for a given root kind.
///
/// `RootKey::Ed25519` is refused by `validate_root`, so no account is ever
/// created under this branch — but the seeds constraint runs BEFORE the
/// handler, so the function has to be total. Encoding an Ed25519 key as
/// `0x00 ‖ pubkey32` keeps it total *and* collision-free against the P-256
/// branch: `0x00` is never a valid compressed-point prefix (`validate_root`
/// requires `0x02`/`0x03`), so no Ed25519 key can ever derive the same seed as
/// some P-256 key.
fn root_seed_bytes(root: &RootKey) -> [u8; 33] {
    match root {
        RootKey::P256Passkey { pubkey } => *pubkey,
        RootKey::Ed25519 { pubkey } => {
            let mut b = [0u8; 33];
            b[1..33].copy_from_slice(pubkey.as_ref());
            b
        }
    }
}

/// `derive_owner_seed` over an *unvalidated* `RootKey` — what the `seeds`
/// constraint calls, before the handler has had a chance to reject anything.
pub fn owner_seed_for(root: &RootKey, salt: &[u8; 32]) -> [u8; 32] {
    derive_owner_seed(&root_seed_bytes(root), salt)
}

// No `Debug`: `PolicyArgs` embeds `MintCap` (`#[zero_copy]`), which doesn't
// derive it — see the note on `PolicyArgs` itself.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub struct CreateAccountArgs {
    /// The passkey this account is rooted to. Renamed from 1A's `root`: it is
    /// now an *input to the address*, not merely a stored field, and the name
    /// says so.
    pub root_key: RootKey,
    /// The proof of possession — a real WebAuthn assertion by `root_key` over
    /// `action_hash(OP_CREATE, borsh(CreateBody))`, verified against the
    /// secp256r1 precompile instruction it names.
    pub root_assertion: RootArgs,
    /// 32 client-chosen random bytes. Together with `root_key` they derive
    /// `owner_seed` (see `derive_owner_seed`) and therefore the address.
    /// **`owner_seed` is no longer an argument**: an attacker who could name
    /// the seed directly could name any address, which is exactly the 1A hole.
    pub salt: [u8; 32],
    /// Recomputed on-chain as SHA-256(origin) and compared — this field only
    /// lets the client show its work; the caller cannot short-circuit the
    /// check by lying here (`rejects_rp_id_hash_not_sha256_of_origin`).
    pub rp_id_hash: [u8; 32],
    /// Exactly `chrome-extension://` + a 32-char `a..=p` extension id
    /// (`CANONICAL_ORIGIN_LEN` = 51 bytes). Stored in a 64-byte
    /// (`MAX_ORIGIN_LEN`) field, zero-padded.
    pub origin: Vec<u8>,
    pub cluster_tag: [u8; 32],
    pub policy: PolicyArgs,
}

/// The signed document for `OP_CREATE` (0x06) — everything the passkey is
/// asked to approve when it authorizes its own account's creation.
///
/// It carries **`salt`, never `owner_seed`**: the seed is derived on-chain
/// from `salt` and the root key, so signing it too would be redundant and
/// would let the two drift. It carries `policy_hash` rather than the policy
/// itself, so the signed body stays fixed-width-ish regardless of how many
/// mints are configured; `PolicyArgs`'s borsh encoding is canonical, so the
/// hash is a faithful stand-in.
///
/// The root key is not a field either, and does not need to be: the assertion
/// is *verified under* that key by the precompile, and the transcript's
/// `account` is the address that key and this salt derive. Substituting either
/// one produces a different challenge, not a valid one.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreateBody {
    pub salt: [u8; 32],
    pub rp_id_hash: [u8; 32],
    pub origin: Vec<u8>,
    pub cluster_tag: [u8; 32],
    /// `Keccak256(borsh(PolicyArgs))`.
    pub policy_hash: [u8; 32],
}

#[derive(Accounts)]
#[instruction(args: CreateAccountArgs)]
pub struct CreateAccount<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    // The seed EXPRESSION is what makes the address root-bound: Anchor
    // re-derives it from the instruction's own arguments and refuses any other
    // address (`ConstraintSeeds`). Nothing the caller passes as an account can
    // steer it.
    //
    // **The IDL cannot express this seed**, and that is deliberate. Anchor's
    // IDL seed parser understands constants, plain instruction arguments and
    // account fields; a Keccak of two arguments is none of those, so it
    // silently omits the `pda` block for this account (`parse_seed`'s
    // catch-all returns `Err`, and `get_pda` degrades to `None`). The
    // consequence is only that a TS client cannot *auto*-derive the address
    // from the IDL — `packages/core`'s `deriveOwnerSeed` is the supported
    // derivation, pinned against this program by a shared golden vector. The
    // alternative (carrying the seed as an argument so the IDL could name it)
    // is exactly the hole this task closes.
    #[account(
        init,
        payer = payer,
        space = SmartAccount::LEN,
        seeds = [ACCOUNT_SEED, &owner_seed_for(&args.root_key, &args.salt)],
        bump
    )]
    pub smart_account: AccountLoader<'info, SmartAccount>,
    /// CHECK: constrained to the Instructions sysvar address; read only via
    /// `load_instruction_at_checked` / `load_current_index_checked`, which
    /// re-check the address themselves.
    #[account(address = solana_instructions_sysvar::ID @ WardenError::BadInstructionLayout)]
    pub ix_sysvar: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

// Not `pub`: only `lib.rs`'s `#[program]` module calls this, by full path
// (`instructions::create_account::handler`) — a bare `pub` here is what
// makes `instructions::mod.rs`'s glob re-export of this module collide with
// `rotate_nonce`'s own `handler` (both would otherwise land in the crate
// root's namespace under the same name).
//
// `#[inline(never)]` is REQUIRED, not cosmetic. Inlined into `#[program]`'s
// generated dispatcher, this handler's frame (a whole `Policy`, 1,448 B) plus
// the dispatcher's own deserialized `CreateAccountArgs` and `Context`
// overflows SBF's 4 KB stack frame — `cargo-build-sbf` reports "Stack offset
// of 4760 exceeded max offset of 4096" and the program dies at runtime with
// "Access violation in stack frame 5". Phase 1A fitted; the `RootArgs` that
// proof of possession adds to the argument struct is what tipped it over.
#[inline(never)]
pub(crate) fn handler(ctx: Context<CreateAccount>, args: CreateAccountArgs) -> Result<()> {
    let clock = Clock::get()?;
    let now = clock.unix_timestamp;
    let slot = clock.slot;

    // ---- Inputs the ceremony itself is built from ------------------------
    //
    // These four run BEFORE the assertion is checked, not because
    // authorize-then-validate has been abandoned, but because each one is an
    // *input to the transcript*: the root key is the key the assertion is
    // verified under, `rp_id_hash` is what `authenticatorData` must carry, and
    // `origin`/`cluster_tag` are compared field-for-field inside the verifier.
    // Checking them first turns "your client built a malformed request" into
    // its own error instead of an unhelpful `ChallengeMismatch`. Everything
    // that is merely *stored* (the policy) is validated after the ceremony.
    let root_pubkey33 = validate_root(&args.root_key)?;
    validate_origin(&args.origin)?;
    require!(args.cluster_tag != [0u8; 32], WardenError::ZeroClusterTag);

    // `rp_id_hash` must be exactly SHA-256 of the FULL origin string — never
    // a client-asserted value taken on faith (spec §4; the same rule
    // `root_verify` depends on at every subsequent root ceremony). Reuses
    // `solana-sha256-hasher`, already a direct dependency (see
    // `root_verify::verify_root_assertion`'s `clientDataJSON` digest) — the
    // same `sol_sha256` syscall the brief's `solana_program::hash::hashv`
    // names; `solana-program` itself is only a transitive dependency here
    // (via anchor-lang) and isn't re-exported by `anchor_lang::solana_program`
    // in 1.1.2, so pulling it in directly would just be a second SHA-256
    // wrapper for the one already in use.
    let computed_rp_id_hash = solana_sha256_hasher::hash(&args.origin).to_bytes();
    require!(computed_rp_id_hash == args.rp_id_hash, WardenError::InvalidRootAssertion);

    // ---- Proof of possession ---------------------------------------------
    //
    // Deliberately in its OWN (`#[inline(never)]`) frame: this handler's frame
    // already holds a whole `Policy` (1,448 B of a 4 KB SBF stack frame), and
    // folding the ceremony's `CreateBody` + borsh buffers in beside it
    // overflows the frame — observed as "Access violation in stack frame N"
    // rather than as a compile error, so the split is load-bearing, not
    // stylistic.
    prove_possession(
        &args,
        root_pubkey33,
        computed_rp_id_hash,
        ctx.accounts.smart_account.key(),
        &ctx.accounts.ix_sysvar.to_account_info(),
        ctx.program_id,
        now,
        slot,
    )?;

    // ---- Validate what is merely stored ----------------------------------
    //
    // The packet bound is checked HERE, not inside `PolicyArgs::expand`: it is
    // a property of the transaction that carries the policy (a create with
    // more than `MAX_MINTS_AT_CREATE` mints cannot fit 1,232 B once the
    // ceremony is aboard), not of the sparse→fixed transform, which is bounded
    // by the destination array width. `set_policy` (Phase 1C) adds the rest,
    // one root ceremony at a time.
    require!(
        args.policy.caps.len() <= MAX_MINTS_AT_CREATE,
        WardenError::InvalidAccountData
    );
    require!(
        args.policy.session_ceiling.len() <= MAX_MINTS_AT_CREATE,
        WardenError::InvalidAccountData
    );
    require!(
        args.policy.large_threshold.len() <= MAX_MINTS_AT_CREATE,
        WardenError::InvalidAccountData
    );

    let mut account = ctx.accounts.smart_account.load_init()?;
    // `init` allocates the account via `system_program::create_account`,
    // which always zero-fills the new data — every field this handler does
    // not touch below (`generation`, `frozen_at`, `guardians_config`,
    // `registry`, `_reserved`, `_pad_align8`) is already 0/`Pubkey::default()`.
    // Fields are still assigned explicitly where the brief calls them out, so
    // the invariant is visible here rather than resting solely on "the runtime
    // happens to zero new accounts".
    account.version = 1;
    account.bump = ctx.bumps.smart_account;
    // Stored, not re-derived, by every later root path: `rotate_nonce` and
    // friends re-derive the PDA from `owner_seed` + `bump`, which keeps them
    // independent of how the seed was produced (and keeps a future seed-domain
    // bump from orphaning existing accounts).
    account.owner_seed = derive_owner_seed(&root_pubkey33, &args.salt);
    account.set_root(&args.root_key);
    account.rp_id_hash = computed_rp_id_hash;
    account.origin[..args.origin.len()].copy_from_slice(&args.origin);
    account.origin_len = args.origin.len() as u8;
    account.cluster_tag = args.cluster_tag;
    account.generation = 0;
    // The creating ceremony is CONSUMED, exactly like every other one: the
    // account starts life at nonce 1, so the assertion that created it can
    // never be replayed against it.
    account.root_nonce = 1;
    account.set_frozen(&FrozenState::None);
    account.frozen_at = 0;

    // Expanded straight into the account rather than via a stack `Policy` —
    // 1,448 B does not fit beside everything else in this frame (see the
    // `#[inline(never)]` note on the handler). A validation failure below
    // reverts every byte written here, so "write then validate" is safe.
    args.policy.expand_into(&mut account.policy)?;
    validate_policy(&account.policy)?;
    account.policy.version = 1; // forced regardless of the caller's PolicyArgs.version

    Ok(())
}

/// Verify the creating root ceremony: rebuild the signed `CreateBody` from
/// the executing instruction's own arguments, build the transcript context a
/// newborn account would have, and hand both to the shared verifier.
///
/// The account does not exist yet, so the context is built from `args` at the
/// values `create_account` is about to write — `generation = 0`,
/// `policy_version = 1`, `root_nonce = 0` — and from `account_key`, which
/// Anchor has already proven is
/// `["account", Keccak256(domain ‖ root_pubkey33 ‖ salt)]`.
///
/// Nothing here is read out of the assertion: every byte of the body comes
/// from the arguments being executed, which is what stops a signed ceremony
/// from being re-pointed at a different salt, origin, cluster or policy.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn prove_possession(
    args: &CreateAccountArgs,
    root_pubkey33: [u8; 33],
    rp_id_hash: [u8; 32],
    account_key: Pubkey,
    ix_sysvar: &AccountInfo,
    program_id: &Pubkey,
    now: i64,
    slot: u64,
) -> Result<()> {
    let mut policy_bytes = Vec::new();
    args.policy.serialize(&mut policy_bytes)?;
    let body = CreateBody {
        salt: args.salt,
        rp_id_hash,
        origin: args.origin.clone(),
        cluster_tag: args.cluster_tag,
        policy_hash: solana_keccak_hasher::hashv(&[&policy_bytes]).to_bytes(),
    };
    let mut body_bytes = Vec::new();
    body.serialize(&mut body_bytes)?;

    let root_ctx = RootContext {
        root_pubkey33,
        rp_id_hash,
        origin: &args.origin,
        cluster_tag: args.cluster_tag,
        account: account_key,
        generation: 0,
        policy_version: 1,
        root_nonce: 0,
    };
    verify_root_assertion(
        &root_ctx,
        ix_sysvar,
        &args.root_assertion,
        program_id,
        action_hash(OP_CREATE, &body_bytes),
        now,
        slot,
    )
}

// ---------------------------------------------------------------------------
// secp256r1 (P-256) root-key encoding
// ---------------------------------------------------------------------------
//
// **Why there is still no on-curve check HERE, and why that is now fine.**
//
// Deciding "is `x³ - 3x + b` a quadratic residue mod p" needs 256-bit field
// arithmetic. Phase 1A tried twice and shipped neither: `sol_big_mod_exp`
// (Euler's criterion) is gated behind `enable_big_mod_exp_syscall`, which
// litesvm 0.12's mainnet-active feature snapshot (2026-04-26) does not list —
// the program aborted with "unsupported BPF instruction" even under
// `with_mainnet_features()` — and hand-rolled 256-bit modular arithmetic was
// rejected on risk.
//
// **Phase 1B Task 2b closes the gap without either of them.** `create_account`
// now requires a real root ceremony, and the secp256r1 precompile verifies an
// ECDSA signature under the compressed point in `args.root_key`. A point that
// is not on the curve cannot be decompressed, so no signature under it can
// ever verify: the runtime rejects the transaction at the precompile
// instruction, before this program runs at all. The precompile does the curve
// validation for free, which is exactly what the 1A deferral note predicted.
//
// So `validate_root` stays an ENCODING check on purpose — a cheap, precise
// early rejection with its own error code (`InvalidRootKey`) for the shapes a
// confused client actually produces (an Ed25519 key with a junk prefix byte,
// an uncompressed `0x04` point, all-`0xff` filler). It is no longer the last
// line of defence, and the unit test that documented the gap
// (`root_encoding_check_alone_still_admits_an_off_curve_x`) now says so, with
// `create_pop::off_curve_root_cannot_be_created_because_no_assertion_verifies`
// proving the end-to-end rejection.

/// Root-key rules, returning the compressed point every later step needs.
///
/// - `RootKey::Ed25519` is refused (`RootKindUnsupported`, the same error
///   `verify_root_assertion` raises for it). The kind exists in the layout for
///   hardware/advanced users (spec §4) and a later phase may implement its
///   signature path; until then, storing it would create an account whose
///   every root instruction aborts.
/// - A P-256 root must be a well-formed compressed point ENCODING: prefix
///   `0x02`/`0x03` and `x < p`. On-curve-ness is proven by the precompile
///   during the creation ceremony — see the note above.
///
/// **Any future instruction that SETS a root (recovery) must call
/// `validate_root` too, and must require a ceremony under the NEW key for the
/// same reason this one does.**
fn validate_root(root: &RootKey) -> Result<[u8; 33]> {
    let pubkey = match root {
        RootKey::P256Passkey { pubkey } => pubkey,
        RootKey::Ed25519 { .. } => return Err(WardenError::RootKindUnsupported.into()),
    };
    require!(pubkey[0] == 0x02 || pubkey[0] == 0x03, WardenError::InvalidRootKey);
    // x must be a field element. `x == 0` is deliberately NOT excluded:
    // P-256 has a valid point at x = 0, and the first fix pass rejected it
    // wrongly (re-review finding).
    require!(pubkey[1..33] < P256_FIELD_PRIME_BE[..], WardenError::InvalidRootKey);
    Ok(*pubkey)
}

/// Origin rules (spec §4 / task-4 brief): the origin must be **exactly**
/// `chrome-extension://` followed by a 32-character extension id drawn from
/// `a..=p`, with no NUL and no whitespace anywhere.
///
/// Milestone-review finding (Important): the first pass only checked a prefix
/// and a length range, so `chrome-extension://abc` — which no Chrome build can
/// ever produce, and therefore no passkey can ever assert against — created a
/// permanently unusable account. `rp_id_hash` is derived from this string and
/// compared against what the authenticator signs, so an origin Chrome cannot
/// emit is an account no assertion can satisfy.
fn validate_origin(origin: &[u8]) -> Result<()> {
    require!(origin.len() == CANONICAL_ORIGIN_LEN, WardenError::InvalidOrigin);
    require!(origin.starts_with(ORIGIN_PREFIX), WardenError::InvalidOrigin);
    // Subsumes the NUL / whitespace / control-byte checks the length-range
    // version made separately: `a..=p` admits none of them.
    let id = origin.get(ORIGIN_PREFIX.len()..).ok_or(WardenError::InvalidOrigin)?;
    require!(
        id.iter().all(|c| (b'a'..=b'p').contains(c)),
        WardenError::InvalidOrigin
    );
    Ok(())
}

/// Policy rules (spec §4 / task-4 brief):
/// - `timelock_secs >= MIN_TIMELOCK_SECS`, `recovery_delay_secs >=
///   MIN_TIMELOCK_SECS`, `max_session_life_secs <= MAX_SESSION_LIFE_SECS`.
/// - For each *used* cap slot (`caps[i].mint != Pubkey::default()`):
///   `per_tx <= per_day <= per_30d`, and the same-index `session_ceiling[i]`
///   is bounded by `caps[i]` field-for-field (ceilings bound what a session
///   may be *granted*; caps bound what it may *spend* — the ceiling can never
///   exceed the spend limit it will eventually be checked against).
/// - An unused slot (`caps[i].mint == Pubkey::default()`) carries no ordering
///   requirement: `buckets::debit`/`buckets::find_cap` already refuse to
///   spend against a default-mint slot outright, so whatever garbage sits in
///   its `per_*` fields is permanently unreachable.
fn validate_policy(p: &Policy) -> Result<()> {
    require!(p.timelock_secs >= MIN_TIMELOCK_SECS, WardenError::InvalidPolicy);
    require!(p.recovery_delay_secs >= MIN_TIMELOCK_SECS, WardenError::InvalidPolicy);
    // Milestone-review finding (Minor): only the upper bound was checked, so
    // a zero or negative `max_session_life_secs` created an account for which
    // `grant_session` can never accept any `expiry_ts` (it requires
    // `now < expiry_ts <= now + max_session_life_secs`) — an account that can
    // never delegate anything.
    require!(p.max_session_life_secs > 0, WardenError::InvalidPolicy);
    require!(p.max_session_life_secs <= MAX_SESSION_LIFE_SECS, WardenError::InvalidPolicy);
    // Milestone-review finding (Important): an unassigned `ops_mask` bit in
    // the ceiling is a forward-activation hazard — see `OPS_MASK_KNOWN`.
    require!(
        (p.session_ops_ceiling & !OPS_MASK_KNOWN) == 0,
        WardenError::InvalidPolicy
    );

    for i in 0..MAX_MINT_CAPS {
        let c = p.caps[i];
        if c.mint == Pubkey::default() {
            continue; // unused slot — no ordering requirement (see doc comment).
        }
        require!(c.per_tx <= c.per_day, WardenError::InvalidPolicy);
        require!(c.per_day <= c.per_30d, WardenError::InvalidPolicy);

        let sc = p.session_ceiling[i];
        require!(sc.per_tx <= c.per_tx, WardenError::InvalidPolicy);
        require!(sc.per_day <= c.per_day, WardenError::InvalidPolicy);
        require!(sc.per_30d <= c.per_30d, WardenError::InvalidPolicy);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root_verify::transcript::OP_ROTATE_NONCE;
    use crate::state::MintCap;

    fn err(e: WardenError) -> anchor_lang::error::Error {
        e.into()
    }

    fn valid_policy() -> Policy {
        Policy {
            version: 1,
            _pad_version: [0; 4],
            caps: [MintCap::default(); MAX_MINT_CAPS],
            session_ceiling: [MintCap::default(); MAX_MINT_CAPS],
            large_threshold: [MintCap::default(); MAX_MINT_CAPS],
            timelock_secs: MIN_TIMELOCK_SECS,
            recovery_delay_secs: MIN_TIMELOCK_SECS,
            max_session_life_secs: MAX_SESSION_LIFE_SECS,
            session_ops_ceiling: 0,
            _pad_ceiling: [0; 6],
            _reserved: [0; 64],
        }
    }

    // -- owner_seed derivation (Phase 1B Task 2b) ------------------------

    /// The P-256 GENERATOR's x-coordinate, big-endian — reused from the
    /// `validate_root` block below so the pinned vector's input is a point
    /// that indisputably exists rather than a filler pattern.
    fn generator_pubkey33() -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        pk[1..33].copy_from_slice(&GX_BE);
        pk
    }

    /// Pinned against an **INDEPENDENT** from-spec pure-Python Keccak-f[1600]
    /// (self-tested against the published `keccak256("")`, `keccak256("abc")`
    /// and `keccak256("testing")` digests, and re-checked to reproduce this
    /// repo's existing `transcript_hash_matches_pinned_vector` digest before
    /// this vector was taken) — not against this function's own output. See
    /// task-2b-report.md.
    ///
    /// Inputs: `root_pubkey33 = 0x02 ‖ Gx`, `salt = [0x44; 32]`.
    ///
    /// **This is an ABI vector, not a convenience test.** The seed decides the
    /// account's ADDRESS; a mirror (`packages/core`) that disagreed on the
    /// domain string, the field order or the hash function would compute a
    /// different address and every ceremony it built would fail with
    /// `ChallengeMismatch` — or, worse, a future change here would orphan
    /// every account already created.
    #[test]
    fn owner_seed_matches_pinned_vector() {
        let seed = derive_owner_seed(&generator_pubkey33(), &[0x44u8; 32]);
        assert_eq!(
            hex::encode(seed),
            "794e590e0ff775f60fe3a1ebd85d9c1be8e5653c417018a63063f461e095b092"
        );
    }

    /// The two security properties of the derivation, stated as assertions:
    /// the same salt under a different root is a different address (that is
    /// what makes squatting impossible), and the same root under a different
    /// salt is a different address (that is what lets one passkey hold several
    /// independent accounts).
    #[test]
    fn owner_seed_changes_with_both_root_and_salt() {
        let a = generator_pubkey33();
        let mut b = a;
        b[0] = 0x03; // the other parity — a different point, same x
        let s1 = [0x44u8; 32];
        let mut s2 = s1;
        s2[31] ^= 1;
        assert_ne!(derive_owner_seed(&a, &s1), derive_owner_seed(&b, &s1), "root must bind");
        assert_ne!(derive_owner_seed(&a, &s1), derive_owner_seed(&a, &s2), "salt must bind");
    }

    /// An Ed25519 root (refused by `validate_root`, so unreachable in
    /// practice) can never collide with a P-256 derivation, because its
    /// encoding carries a `0x00` prefix byte that no accepted compressed point
    /// may have.
    #[test]
    fn ed25519_seed_encoding_cannot_collide_with_a_p256_one() {
        let ed = RootKey::Ed25519 { pubkey: Pubkey::new_from_array([0x02u8; 32]) };
        assert_eq!(root_seed_bytes(&ed)[0], 0x00);
        // The nearest P-256 shape: same 32 trailing bytes, a valid prefix.
        let p256 = RootKey::P256Passkey { pubkey: compressed([0x02u8; 32], 0x02) };
        assert_ne!(
            owner_seed_for(&ed, &[9u8; 32]),
            owner_seed_for(&p256, &[9u8; 32])
        );
    }

    // -- CreateBody / action hash ----------------------------------------

    /// Pinned with the same INDEPENDENT Keccak provenance as the seed vector
    /// above, over the exact borsh encoding of `CreateBody`:
    /// `salt(32) ‖ rp_id_hash(32) ‖ len(u32 LE) ‖ origin ‖ cluster_tag(32) ‖
    /// policy_hash(32)` = 183 B for the canonical 51-byte origin, hashed as
    /// `Keccak256(0x06 ‖ body)`.
    ///
    /// Mirrored verbatim in `packages/core/test/transcript.test.ts`; if the
    /// two disagree, the extension is signing a document the program will not
    /// reproduce and no account can be created at all.
    #[test]
    fn create_body_action_hash_matches_pinned_vector() {
        let body = CreateBody {
            salt: [0x44u8; 32],
            rp_id_hash: [0x55u8; 32],
            origin: b"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi".to_vec(),
            cluster_tag: [0x5Au8; 32],
            policy_hash: [0x66u8; 32],
        };
        let mut encoded = Vec::new();
        body.serialize(&mut encoded).unwrap();
        assert_eq!(encoded.len(), 183, "borsh layout of CreateBody");
        assert_eq!(
            hex::encode(action_hash(OP_CREATE, &encoded)),
            "d833a9c4d6dae3169175caadc86f1d1308996eacc2918b4af5465dc6be4a4020"
        );
    }

    /// Every `CreateBody` field must reach the digest — a field silently
    /// dropped from the signed document would be a field an attacker could
    /// swap after the ceremony.
    #[test]
    fn every_create_body_field_changes_the_action_hash() {
        let base = CreateBody {
            salt: [1u8; 32],
            rp_id_hash: [2u8; 32],
            origin: b"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi".to_vec(),
            cluster_tag: [3u8; 32],
            policy_hash: [4u8; 32],
        };
        let enc = |b: &CreateBody| {
            let mut v = Vec::new();
            b.serialize(&mut v).unwrap();
            v
        };
        let h = |b: &CreateBody| action_hash(OP_CREATE, &enc(b));
        let base_h = h(&base);
        let mut variants = Vec::new();
        let mut v = base.clone();
        v.salt[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.rp_id_hash[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.origin[19] = b'b';
        variants.push(v);
        let mut v = base.clone();
        v.cluster_tag[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.policy_hash[0] ^= 1;
        variants.push(v);
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(base_h, h(v), "CreateBody field {i} does not affect the digest");
        }
        // And the op byte itself is not absorbable into the body.
        assert_ne!(base_h, action_hash(OP_ROTATE_NONCE, &enc(&base)));
    }

    // -- validate_origin -----------------------------------------------

    #[test]
    fn origin_accepts_the_canonical_shape() {
        let o = b"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi";
        assert_eq!(o.len(), CANONICAL_ORIGIN_LEN);
        assert!(validate_origin(o).is_ok());
    }

    #[test]
    fn origin_rejects_empty() {
        assert_eq!(validate_origin(b"").unwrap_err(), err(WardenError::InvalidOrigin));
    }

    #[test]
    fn origin_rejects_too_long() {
        let mut o = b"chrome-extension://".to_vec();
        o.extend(std::iter::repeat(b'a').take(MAX_ORIGIN_LEN)); // > 64 total
        assert_eq!(validate_origin(&o).unwrap_err(), err(WardenError::InvalidOrigin));
    }

    /// Milestone-review finding: a 64-byte origin is not a Chrome origin. The
    /// storage field is 64 B wide, but the only ACCEPTED length is 51.
    #[test]
    fn origin_rejects_a_64_byte_origin_that_is_not_an_extension_id() {
        let mut o = b"chrome-extension://".to_vec();
        o.extend(std::iter::repeat(b'a').take(MAX_ORIGIN_LEN - o.len()));
        assert_eq!(o.len(), MAX_ORIGIN_LEN);
        assert_eq!(validate_origin(&o).unwrap_err(), err(WardenError::InvalidOrigin));
    }

    /// The whole point of the finding: `chrome-extension://abc` used to be
    /// accepted and produces an account no assertion can ever satisfy.
    #[test]
    fn origin_rejects_a_short_extension_id() {
        assert_eq!(
            validate_origin(b"chrome-extension://abc").unwrap_err(),
            err(WardenError::InvalidOrigin)
        );
    }

    /// Chromium ids are base-16 over `a..=p`; anything else (digits, `q..z`,
    /// uppercase, `-`) is not an id Chrome can emit.
    #[test]
    fn origin_rejects_ids_outside_the_a_to_p_alphabet() {
        for bad in [b'q', b'z', b'A', b'0', b'-', b'.'] {
            let mut o = b"chrome-extension://".to_vec();
            o.extend(std::iter::repeat(b'a').take(EXTENSION_ID_LEN - 1));
            o.push(bad);
            assert_eq!(o.len(), CANONICAL_ORIGIN_LEN);
            assert_eq!(
                validate_origin(&o).unwrap_err(),
                err(WardenError::InvalidOrigin),
                "byte {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn origin_rejects_missing_prefix() {
        // Same length as the canonical shape, wrong scheme.
        let o = b"https://xxxxx//maikadpaobbjkmaomnpnhjglpabllaoi.io";
        assert_eq!(validate_origin(o).unwrap_err(), err(WardenError::InvalidOrigin));
    }

    #[test]
    fn origin_rejects_embedded_nul() {
        let mut o = b"chrome-extension://".to_vec();
        o.extend(std::iter::repeat(b'a').take(EXTENSION_ID_LEN - 1));
        o.insert(20, 0u8);
        assert_eq!(o.len(), CANONICAL_ORIGIN_LEN);
        assert_eq!(validate_origin(&o).unwrap_err(), err(WardenError::InvalidOrigin));
    }

    #[test]
    fn origin_rejects_trailing_whitespace() {
        let mut o = b"chrome-extension://".to_vec();
        o.extend(std::iter::repeat(b'a').take(EXTENSION_ID_LEN - 1));
        o.push(b' ');
        assert_eq!(o.len(), CANONICAL_ORIGIN_LEN);
        assert_eq!(validate_origin(&o).unwrap_err(), err(WardenError::InvalidOrigin));
    }

    // -- validate_root ---------------------------------------------------

    fn p256_root(pubkey: [u8; 33]) -> RootKey {
        RootKey::P256Passkey { pubkey }
    }

    /// The x-coordinate of the P-256 GENERATOR — a point that indisputably
    /// exists, unlike a hand-picked small integer (fix re-review finding: the
    /// first pass "accepted" x = 1 and x = p-1, both of which are OFF the
    /// curve and would have been rejected by the precompile).
    const GX_BE: [u8; 32] = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ];

    fn compressed(x: [u8; 32], prefix: u8) -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = prefix;
        pk[1..33].copy_from_slice(&x);
        pk
    }

    #[test]
    fn root_accepts_the_generator_under_both_parities() {
        for prefix in [0x02u8, 0x03] {
            let pk = compressed(GX_BE, prefix);
            assert_eq!(validate_root(&p256_root(pk)).unwrap(), pk, "returns the point it validated");
        }
    }

    /// x = 0 IS on P-256 (`0³ - 0 + b` is a quadratic residue — verified
    /// independently). The first fix pass rejected it out of caution and was
    /// wrong to; re-review finding.
    #[test]
    fn root_accepts_x_zero_which_is_a_real_point() {
        assert!(validate_root(&p256_root(compressed([0u8; 32], 0x02))).is_ok());
    }

    /// **Renamed from `root_accepts_an_off_curve_x_phase_1a_gap`, and it is no
    /// longer a gap.** x = 1 is a well-formed encoding of a point that is NOT
    /// on P-256, and `validate_root` — an encoding check by design (see the
    /// note above it) — still admits it. What changed in Phase 1B Task 2b is
    /// that admitting it here no longer creates anything: `create_account`
    /// requires a root ceremony, and the secp256r1 precompile cannot verify a
    /// signature under a point it cannot decompress, so the transaction dies
    /// at the precompile instruction. The end-to-end proof is
    /// `create_pop::off_curve_root_cannot_be_created_because_no_assertion_verifies`;
    /// this test exists to pin the DIVISION OF LABOUR, so that a future reader
    /// does not "fix" `validate_root` by bolting on unaudited field arithmetic
    /// the precompile already does correctly.
    #[test]
    fn root_encoding_check_alone_still_admits_an_off_curve_x() {
        let mut x = [0u8; 32];
        x[31] = 1; // off-curve, independently verified
        assert!(
            validate_root(&p256_root(compressed(x, 0x02))).is_ok(),
            "validate_root is an ENCODING check; the precompile rejects off-curve points"
        );
    }

    #[test]
    fn root_rejects_ed25519_in_phase_1a() {
        let r = RootKey::Ed25519 { pubkey: Pubkey::new_unique() };
        assert_eq!(validate_root(&r).unwrap_err(), err(WardenError::RootKindUnsupported));
    }

    #[test]
    fn root_rejects_a_non_compressed_prefix() {
        for prefix in [0x00u8, 0x01, 0x04, 0x05, 0xff] {
            assert_eq!(
                validate_root(&p256_root(compressed(GX_BE, prefix))).unwrap_err(),
                err(WardenError::InvalidRootKey),
                "prefix {prefix:#04x} must be rejected"
            );
        }
    }

    #[test]
    fn root_rejects_x_at_or_above_the_field_prime() {
        // x == p, and x == all-ones (> p).
        let mut above = [0xffu8; 32];
        above[31] = 0xff;
        for x in [P256_FIELD_PRIME_BE, above] {
            assert_eq!(
                validate_root(&p256_root(compressed(x, 0x02))).unwrap_err(),
                err(WardenError::InvalidRootKey)
            );
        }
    }

    // -- validate_policy -------------------------------------------------

    #[test]
    fn policy_accepts_the_all_defaults_shape() {
        assert!(validate_policy(&valid_policy()).is_ok());
    }

    #[test]
    fn policy_rejects_timelock_below_minimum() {
        let mut p = valid_policy();
        p.timelock_secs = MIN_TIMELOCK_SECS - 1;
        assert_eq!(validate_policy(&p).unwrap_err(), err(WardenError::InvalidPolicy));
    }

    #[test]
    fn policy_rejects_recovery_delay_below_minimum() {
        let mut p = valid_policy();
        p.recovery_delay_secs = MIN_TIMELOCK_SECS - 1;
        assert_eq!(validate_policy(&p).unwrap_err(), err(WardenError::InvalidPolicy));
    }

    #[test]
    fn policy_rejects_max_session_life_above_30_days() {
        let mut p = valid_policy();
        p.max_session_life_secs = MAX_SESSION_LIFE_SECS + 1;
        assert_eq!(validate_policy(&p).unwrap_err(), err(WardenError::InvalidPolicy));
    }

    /// Milestone-review finding (Minor): a non-positive session life is an
    /// account that can never grant a session at all.
    #[test]
    fn policy_rejects_non_positive_max_session_life() {
        for life in [0i64, -1, i64::MIN] {
            let mut p = valid_policy();
            p.max_session_life_secs = life;
            assert_eq!(
                validate_policy(&p).unwrap_err(),
                err(WardenError::InvalidPolicy),
                "max_session_life_secs = {life} must be rejected"
            );
        }
    }

    /// Milestone-review finding (Important): an unassigned `ops_mask` bit
    /// stored in the ceiling silently becomes authority the day a later
    /// program version assigns that bit.
    #[test]
    fn policy_rejects_unknown_ops_ceiling_bits() {
        for bit in [1u16 << 4, 1 << 15] {
            let mut p = valid_policy();
            p.session_ops_ceiling = OPS_MASK_KNOWN | bit;
            assert_eq!(
                validate_policy(&p).unwrap_err(),
                err(WardenError::InvalidPolicy),
                "bit {bit:#06x} must be rejected"
            );
        }
    }

    #[test]
    fn policy_accepts_every_assigned_ops_ceiling_bit() {
        let mut p = valid_policy();
        p.session_ops_ceiling = OPS_MASK_KNOWN;
        assert!(validate_policy(&p).is_ok());
    }

    #[test]
    fn policy_rejects_per_tx_above_per_day() {
        let mut p = valid_policy();
        p.caps[0] = MintCap { mint: Pubkey::new_unique(), per_tx: 200, per_day: 100, per_30d: 1000 };
        assert_eq!(validate_policy(&p).unwrap_err(), err(WardenError::InvalidPolicy));
    }

    #[test]
    fn policy_rejects_per_day_above_per_30d() {
        let mut p = valid_policy();
        p.caps[0] = MintCap { mint: Pubkey::new_unique(), per_tx: 50, per_day: 2000, per_30d: 1000 };
        assert_eq!(validate_policy(&p).unwrap_err(), err(WardenError::InvalidPolicy));
    }

    #[test]
    fn policy_rejects_session_ceiling_above_cap() {
        let mut p = valid_policy();
        let mint = Pubkey::new_unique();
        p.caps[0] = MintCap { mint, per_tx: 100, per_day: 200, per_30d: 1000 };
        p.session_ceiling[0] = MintCap { mint, per_tx: 101, per_day: 200, per_30d: 1000 };
        assert_eq!(validate_policy(&p).unwrap_err(), err(WardenError::InvalidPolicy));
    }

    #[test]
    fn policy_accepts_session_ceiling_equal_to_cap() {
        let mut p = valid_policy();
        let mint = Pubkey::new_unique();
        p.caps[0] = MintCap { mint, per_tx: 100, per_day: 200, per_30d: 1000 };
        p.session_ceiling[0] = MintCap { mint, per_tx: 100, per_day: 200, per_30d: 1000 };
        assert!(validate_policy(&p).is_ok());
    }

    #[test]
    fn policy_ignores_garbage_in_unused_slots() {
        let mut p = valid_policy();
        // mint == default (unused) but with an inverted, otherwise-invalid
        // ordering — must not be reachable via `buckets::debit`, so it must
        // not be rejected here either.
        p.caps[3] = MintCap { mint: Pubkey::default(), per_tx: 999, per_day: 1, per_30d: 0 };
        assert!(validate_policy(&p).is_ok());
    }
}
