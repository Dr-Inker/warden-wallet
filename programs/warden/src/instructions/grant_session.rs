//! `grant_session` — mint or re-bless a bounded, expiring delegate signer for
//! a `SmartAccount`, under a live root passkey ceremony.
//!
//! Everything a session may ever do is fixed here and nowhere else: which
//! mints it may move and how much of each (`caps` + `lifetime_cap`), which
//! operations it may perform (`ops_mask`), when it stops working
//! (`expiry_ts`), and which account generation blessed it
//! (`generation_at_grant`). Phase 1B's `execute`/`swap` paths read those
//! fields; they never widen them.
//!
//! ## Why the arguments are nested (`GrantSessionArgs { root, body }`)
//!
//! The root transcript binds `action_hash = Keccak256(0x01 ‖ borsh(body))`.
//! If the signed body were re-assembled on-chain field-by-field from a flat
//! argument struct, the hashed bytes and the wire bytes would be two
//! independently-maintained encodings, and any drift between them (a field
//! added to one, a reordering in the other) would silently break — or worse,
//! silently *not* break, leaving a field outside the signature. Nesting makes
//! `borsh(body)` literally the bytes that arrived, re-serialized from the
//! deserialized struct: one encoding, no second source of truth.
//!
//! ## What a session cap bounds (Phase 1A)
//!
//! `per_tx` and `lifetime_cap`, and nothing else. A grant carrying a non-zero
//! `per_day`/`per_30d` is REJECTED (`SessionDayCapsUnsupported`): day and
//! rolling-30-day limits are account-wide (spec §4), shared by every session
//! and by the root, and `SessionKey` has nowhere to accumulate a per-session
//! day total. So the bound a session gives you is
//! `per_tx x (number of calls) <= lifetime_cap`, under the account's day/30d
//! ceiling. See `instructions::transfer` and
//! docs/program/PHASE1A-MEASUREMENTS.md.
//!
//! ## Upsert semantics (`init_if_needed`)
//!
//! A grant for a session PDA that does not exist yet creates it. A grant for
//! one that does exist **merges**:
//!
//! - `caps`/`lifetime_cap` are merged **by mint** into the session's
//!   `MAX_MINT_CAPS` (8) slots — a slot already holding that mint is replaced
//!   in place, otherwise the first empty slot is taken. Mints the new grant
//!   does not mention keep their existing caps: a grant is additive, not a
//!   wholesale replacement, which is what lets a session accumulate more than
//!   `MAX_CAPS_PER_GRANT` (2) mints across several ceremonies.
//! - `lifetime_spent` is **preserved** per slot. A re-grant is not a reset:
//!   raising a lifetime cap gives the session more headroom, it does not
//!   forgive what it already spent. A re-grant that sets `lifetime_cap`
//!   *below* what that mint has already spent is rejected (`CapExceeded`)
//!   rather than silently clamped, because the alternative — accepting it —
//!   would leave the session in a state where `spent > cap` and every later
//!   comparison would have to decide what that means.
//! - `expiry_ts`, `ops_mask`, `label`, `program_allowlist_id` and `kind` are
//!   **replaced** outright.
//! - `generation_at_grant` is **refreshed** to the account's current
//!   `generation`, on re-grant as much as on first creation. A live root
//!   ceremony is exactly the act of re-blessing a session, so a session that
//!   was invalidated by a generation bump (key rotation / recovery) becomes
//!   valid again the moment the *new* root signs for it — which is the only
//!   way to re-authorize a delegate without first tearing its accounting
//!   down.
//!
//! ## The merge is bound to the state it merges into (`prior_authority_hash`)
//!
//! Milestone-review finding (Important). Merge + generation refresh together
//! meant the passkey could sign a one-mint body and produce a session that
//! still holds every mint granted before it — authority that appears nowhere
//! in the signed document. After a 1B generation bump (rotation / recovery),
//! a minimal re-grant would have silently revived every capability of a
//! session the bump had just invalidated.
//!
//! `GrantBody.prior_authority_hash` closes it: it is
//! `SessionKey::authority_hash()` of the session **as it stands before this
//! instruction** (all-zero for a PDA that does not exist yet), and the handler
//! rejects a mismatch with `SessionPriorStateMismatch`. The merge is a pure
//! function of `(pre-state, body)`, so signing both is signing the result.
//! It is also a natural anti-TOCTOU guard: a grant prepared against a state
//! another grant has since changed no longer applies.

use anchor_lang::prelude::*;

use crate::buckets::find_cap;
use crate::constants::{
    ACCOUNT_SEED, MAX_CAPS_PER_GRANT, MAX_MINT_CAPS, SESSION_KIND_ED25519, SESSION_SEED,
};
use crate::errors::WardenError;
use crate::root_verify::transcript::{action_hash, OP_GRANT_SESSION};
use crate::root_verify::{verify_root_assertion, RootArgs};
use crate::state::session::OPS_MASK_KNOWN;
use crate::state::{FrozenState, MintCap, SessionKey, SmartAccount};

/// Everything the passkey signs for, and nothing else: `action_hash =
/// Keccak256(OP_GRANT_SESSION ‖ borsh(GrantBody))`.
///
/// `caps[i]` and `lifetime_cap[i]` are parallel — same length, same mint
/// order — rather than one vector of `(MintCap, u64)` pairs, because
/// `MintCap` is the shared zero-copy type used by `Policy` and `SessionKey`
/// and the lifetime cap is a session-only concept that has no place in it.
// No `Debug`: `MintCap` (`#[zero_copy]`) doesn't derive it — same reason as
// `PolicyArgs`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub struct GrantBody {
    /// When the *session* stops working (absolute unix seconds). Unrelated to
    /// `root.expiry_ts`, which is the ≤ 600 s freshness window of the passkey
    /// ceremony itself.
    pub expiry_ts: i64,
    pub session_pubkey: Pubkey,
    /// `SESSION_KIND_ED25519` (0) is the only value Phase 1A accepts.
    pub kind: u8,
    pub ops_mask: u16,
    /// At most `MAX_CAPS_PER_GRANT` entries, each with a distinct, non-default
    /// mint that the account's `policy.session_ceiling` configures.
    pub caps: Vec<MintCap>,
    /// Exactly as long as `caps`; `lifetime_cap[i]` bounds total lifetime
    /// spend for `caps[i].mint`.
    pub lifetime_cap: Vec<u64>,
    /// spec §5.1 adapter-registry list id (0 = none until Phase 1B defines the
    /// registry).
    pub program_allowlist_id: u16,
    /// Free-form display label; not interpreted on-chain.
    pub label: [u8; 16],
    /// `SessionKey::authority_hash()` of the session PDA **before** this
    /// instruction runs, or `[0u8; 32]` when it does not exist yet. Binds the
    /// caps this grant does not mention but keeps — see the module docs.
    pub prior_authority_hash: [u8; 32],
}

// No `Debug`: see `GrantBody`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub struct GrantSessionArgs {
    pub root: RootArgs,
    pub body: GrantBody,
}

#[derive(Accounts)]
#[instruction(args: GrantSessionArgs)]
pub struct GrantSession<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// Canonicality of this PDA is re-proven in the handler from the
    /// `owner_seed`/`bump` the account itself stores (same as `rotate_nonce`),
    /// not by a `seeds` constraint here — a `seeds` expression would have to
    /// `load()` the account a second time inside the generated constraint
    /// code.
    #[account(mut)]
    pub smart_account: AccountLoader<'info, SmartAccount>,
    #[account(
        init_if_needed,
        payer = payer,
        space = SessionKey::LEN,
        seeds = [SESSION_SEED, smart_account.key().as_ref(), args.body.session_pubkey.as_ref()],
        bump
    )]
    pub session: Account<'info, SessionKey>,
    /// CHECK: constrained to the Instructions sysvar address; read only via
    /// `load_instruction_at_checked` / `load_current_index_checked`, which
    /// re-check the address themselves.
    #[account(address = solana_instructions_sysvar::ID @ WardenError::BadInstructionLayout)]
    pub ix_sysvar: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

// Not `pub`: only `lib.rs`'s `#[program]` module calls this, by full path —
// see the matching note on `create_account::handler`.
pub(crate) fn handler(ctx: Context<GrantSession>, args: GrantSessionArgs) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let account_key = ctx.accounts.smart_account.key();
    let ix_sysvar = ctx.accounts.ix_sysvar.to_account_info();
    let session_bump = ctx.bumps.session;
    let mut account = ctx.accounts.smart_account.load_mut()?;

    // Re-derive the account PDA from the seeds the account itself stores, so
    // a byte-identical copy planted at some other address cannot stand in
    // (see `rotate_nonce::handler` for the full argument).
    let expected = Pubkey::create_program_address(
        &[ACCOUNT_SEED, account.owner_seed.as_ref(), &[account.bump]],
        ctx.program_id,
    )
    .map_err(|_| WardenError::Unauthorized)?;
    require_keys_eq!(account_key, expected, WardenError::Unauthorized);

    // Granting authority is an outflow-enabling action, so it is gated by
    // `frozen` exactly like a transfer would be (spec §5.1). Revocation
    // deliberately is NOT — see `revoke_session`.
    require!(matches!(account.frozen()?, FrozenState::None), WardenError::Frozen);

    // AUTHORIZE FIRST, then validate. The ceremony binds every byte of
    // `GrantBody` through `action_hash`, so running argument validation before
    // it would mean a *tampered* body could surface a validation error instead
    // of the challenge mismatch that actually describes what went wrong — and
    // would let an unauthenticated caller probe the validation logic for free.
    // Round-1 review fix: `grant_body_tamper_rejected_field_by_field` asserts
    // exactly one failure mode (`ChallengeMismatch`) for a change to ANY field,
    // which is only true with this ordering.
    //
    // The passkey signed `Keccak256(0x01 ‖ borsh(body))` — re-serialized here
    // from the deserialized struct, never taken from raw instruction data.
    let mut body_bytes = Vec::new();
    args.body.serialize(&mut body_bytes)?;
    verify_root_assertion(
        &mut account,
        &ix_sysvar,
        &args.root,
        ctx.program_id,
        &account_key,
        action_hash(OP_GRANT_SESSION, &body_bytes),
        now,
    )?;

    validate_shape(&args.body)?;
    validate_against_policy(&account, &args.body, now)?;

    // ---- upsert -----------------------------------------------------------
    let generation = account.generation;
    let session = &mut ctx.accounts.session;

    // `init_if_needed` leaves a freshly created account zero-filled, so
    // `version == 0` is exactly "this PDA did not exist before this
    // instruction" — `version` is set to 1 below and no other code path ever
    // writes a `SessionKey` back with `version == 0`.
    // The signed body names the state this merge is allowed to merge INTO.
    // Computed before any field below is written, and compared against the
    // all-zero sentinel for a PDA `init_if_needed` has just created.
    let prior = if session.version == 0 {
        [0u8; 32]
    } else {
        session.authority_hash()
    };
    require!(
        prior == args.body.prior_authority_hash,
        WardenError::SessionPriorStateMismatch
    );

    if session.version == 0 {
        session.version = 1;
        session.bump = session_bump;
        session.account = account_key;
        session.pubkey = args.body.session_pubkey;
        // Redundant against a zero-filled new account, but written explicitly
        // so the "a new session starts with no caps and no spend history"
        // invariant lives here rather than resting on the runtime's
        // zero-fill.
        session.caps = [MintCap::default(); MAX_MINT_CAPS];
        session.lifetime_cap = [0u64; MAX_MINT_CAPS];
        session.lifetime_spent = [0u64; MAX_MINT_CAPS];
    } else {
        // Both are already implied by the PDA seeds; asserting them keeps the
        // invariant local to the code that depends on it.
        require_keys_eq!(session.account, account_key, WardenError::Unauthorized);
        require_keys_eq!(session.pubkey, args.body.session_pubkey, WardenError::Unauthorized);
    }

    session.kind = args.body.kind;
    session.expiry_ts = args.body.expiry_ts;
    session.ops_mask = args.body.ops_mask;
    session.program_allowlist_id = args.body.program_allowlist_id;
    session.label = args.body.label;
    // Refreshed on re-grant too: a live root ceremony re-blesses the session
    // against the account's current generation (see the module docs).
    session.generation_at_grant = generation;

    merge_caps(session, &args.body)?;

    Ok(())
}

/// Pure argument validation — no account state consulted. Runs AFTER the root
/// ceremony (see the ordering note in `handler`).
///
/// Error choice: "too many caps" / "the two parallel vectors disagree" are
/// malformed *instruction layout* (`BadInstructionLayout`), while a
/// well-shaped instruction carrying nonsense *values* (kind, default pubkey,
/// duplicate mint) is `InvalidAccountData` — the same split
/// `PolicyArgs::expand` uses.
fn validate_shape(b: &GrantBody) -> Result<()> {
    require!(b.caps.len() <= MAX_CAPS_PER_GRANT, WardenError::BadInstructionLayout);
    require!(b.lifetime_cap.len() == b.caps.len(), WardenError::BadInstructionLayout);
    require!(b.kind == SESSION_KIND_ED25519, WardenError::InvalidAccountData);
    // `Pubkey::default()` is `find_cap`'s unused-slot sentinel and can never
    // be a real Ed25519 signer, so a session keyed on it would be a slot that
    // nothing can ever sign for.
    require!(b.session_pubkey != Pubkey::default(), WardenError::InvalidAccountData);
    for (i, c) in b.caps.iter().enumerate() {
        require!(c.mint != Pubkey::default(), WardenError::InvalidAccountData);
        let dup = b.caps[..i].iter().any(|other| other.mint == c.mint);
        require!(!dup, WardenError::InvalidAccountData);
        // A session cap is `per_tx` + `lifetime_cap`, and NOTHING else, in
        // Phase 1A. Day and rolling-30-day limits are ACCOUNT-WIDE (spec §4):
        // they live in `SmartAccount.buckets` and every session plus the root
        // debits the same ones (`instructions::transfer`). `SessionKey` has no
        // bucket fields at all — no `day_start`, no ring — so a non-zero
        // `per_day`/`per_30d` here would be stored, displayed to the user as
        // if it bounded anything, and enforced by nothing. Rejecting is the
        // only honest option: a cap that does not cap is worse than no cap.
        //
        // 1B: per-session day buckets need a bucket PDA (a 30-slot ring is
        // 248 B — it does not fit `SessionKey._reserved`'s 64 B), at which
        // point this check is replaced by real enforcement rather than
        // relaxed.
        require!(
            c.per_day == 0 && c.per_30d == 0,
            WardenError::SessionDayCapsUnsupported
        );
    }
    Ok(())
}

/// Checks that need the account's policy.
///
/// - `expiry_ts` must be strictly in the future (`Expired`) and no further out
///   than `policy.max_session_life_secs` (`InvalidPolicy` — the same error
///   `create_account::validate_policy` raises for a session-life bound
///   violation).
/// - every bit set in `ops_mask` must be set in `policy.session_ops_ceiling`
///   (`OpNotAllowed`).
/// - `program_allowlist_id` must be 0 (`ProgramAllowlistUnsupported`). It
///   names an entry in the adapter registry that Phase 1B introduces; until
///   that registry exists there is no id to name, and storing a non-zero one
///   would persist a dangling reference that 1B would then have to guess the
///   meaning of. Round-1 review finding.
/// - every cap's mint must have a `policy.session_ceiling` entry — looked up
///   **by mint**, since `Policy`'s arrays are keyed by the `caps` slot index,
///   not by wire position — and every `per_*` must be at or below it
///   (`CapExceeded`). A mint with no ceiling entry is not grantable at all:
///   an absent ceiling means "sessions may not touch this mint", not
///   "unlimited". (The `per_day`/`per_30d` comparisons are unreachable while
///   `validate_shape` forces both to 0 — they are kept because the ceiling is
///   what 1B's real per-session day buckets will be validated against.)
fn validate_against_policy(account: &SmartAccount, b: &GrantBody, now: i64) -> Result<()> {
    require!(b.expiry_ts > now, WardenError::Expired);
    let max_expiry = now
        .checked_add(account.policy.max_session_life_secs)
        .ok_or(WardenError::Overflow)?;
    require!(b.expiry_ts <= max_expiry, WardenError::InvalidPolicy);

    // Unassigned bits are refused outright, not merely bounded by the
    // ceiling: an `ops_mask` holding `1 << 7` would silently gain whatever a
    // later version assigns to `1 << 7`, with no second ceremony
    // (milestone-review finding — see `OPS_MASK_KNOWN`). `create_account`
    // refuses them in the ceiling too, so this is belt-and-braces for an
    // account created by a future version with a wider constant.
    require!((b.ops_mask & !OPS_MASK_KNOWN) == 0, WardenError::OpNotAllowed);
    require!(
        (b.ops_mask & !account.policy.session_ops_ceiling) == 0,
        WardenError::OpNotAllowed
    );

    // 1B: policy lookup — replace this with a check that the id names a live
    // entry in the account's adapter registry (`SmartAccount.registry`), and
    // that the registry is the one the policy points at.
    require!(
        b.program_allowlist_id == 0,
        WardenError::ProgramAllowlistUnsupported
    );

    for c in b.caps.iter() {
        let (_, ceiling) =
            find_cap(&account.policy.session_ceiling, &c.mint).ok_or(WardenError::CapExceeded)?;
        require!(c.per_tx <= ceiling.per_tx, WardenError::CapExceeded);
        require!(c.per_day <= ceiling.per_day, WardenError::CapExceeded);
        require!(c.per_30d <= ceiling.per_30d, WardenError::CapExceeded);
    }
    Ok(())
}

/// Merge this grant's caps into the session's fixed slots, by mint.
///
/// The `CapExceeded` on "no empty slot" is unreachable in Phase 1A —
/// `MAX_MINTS_AT_CREATE` (4) bounds how many mints a policy can have
/// `session_ceiling` entries for, and `validate_against_policy` refuses any
/// mint without one, so at most 4 of the 8 slots can ever be filled until
/// Phase 1B's `set_policy` lands. It is written anyway because the bound it
/// enforces (`MAX_MINT_CAPS`) is the array's, not the policy's, and the two
/// are deliberately independent constants.
fn merge_caps(session: &mut SessionKey, b: &GrantBody) -> Result<()> {
    for (i, c) in b.caps.iter().enumerate() {
        let lifetime = *b
            .lifetime_cap
            .get(i)
            .ok_or(WardenError::BadInstructionLayout)?;
        let slot = match find_cap(&session.caps, &c.mint) {
            Some((idx, _)) => idx,
            None => session
                .caps
                .iter()
                .position(|s| s.mint == Pubkey::default())
                .ok_or(WardenError::CapExceeded)?,
        };
        // An empty slot carries no spend history by construction; zeroing it
        // is belt-and-braces against a slot that was somehow left dirty.
        if session.caps[slot].mint == Pubkey::default() {
            session.lifetime_spent[slot] = 0;
        }
        // A re-grant may raise or lower a lifetime cap, but never below what
        // the session already spent (module docs).
        require!(lifetime >= session.lifetime_spent[slot], WardenError::CapExceeded);
        session.caps[slot] = *c;
        session.lifetime_cap[slot] = lifetime;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(e: WardenError) -> anchor_lang::error::Error {
        e.into()
    }

    /// A Phase-1A-shaped session cap: `per_tx` only, day/30-day zeroed (see
    /// `validate_shape`'s `SessionDayCapsUnsupported` rule).
    fn cap(mint: Pubkey, per_tx: u64) -> MintCap {
        MintCap { mint, per_tx, per_day: 0, per_30d: 0 }
    }

    fn body() -> GrantBody {
        GrantBody {
            expiry_ts: 1_000,
            session_pubkey: Pubkey::new_unique(),
            kind: SESSION_KIND_ED25519,
            ops_mask: 0,
            caps: vec![],
            lifetime_cap: vec![],
            program_allowlist_id: 0,
            label: [0u8; 16],
            prior_authority_hash: [0u8; 32],
        }
    }

    fn empty_session() -> SessionKey {
        SessionKey {
            version: 1,
            bump: 255,
            account: Pubkey::new_unique(),
            pubkey: Pubkey::new_unique(),
            kind: 0,
            expiry_ts: 0,
            ops_mask: 0,
            generation_at_grant: 0,
            caps: [MintCap::default(); MAX_MINT_CAPS],
            lifetime_cap: [0; MAX_MINT_CAPS],
            lifetime_spent: [0; MAX_MINT_CAPS],
            program_allowlist_id: 0,
            label: [0; 16],
            _reserved: [0; 64],
        }
    }

    // -- validate_shape ---------------------------------------------------

    #[test]
    fn shape_accepts_the_empty_grant() {
        assert!(validate_shape(&body()).is_ok());
    }

    #[test]
    fn shape_rejects_more_than_max_caps_per_grant() {
        let mut b = body();
        for _ in 0..=MAX_CAPS_PER_GRANT {
            b.caps.push(cap(Pubkey::new_unique(), 1));
            b.lifetime_cap.push(1);
        }
        assert_eq!(validate_shape(&b).unwrap_err(), err(WardenError::BadInstructionLayout));
    }

    #[test]
    fn shape_rejects_mismatched_vector_lengths() {
        let mut b = body();
        b.caps.push(cap(Pubkey::new_unique(), 1));
        assert_eq!(validate_shape(&b).unwrap_err(), err(WardenError::BadInstructionLayout));
    }

    #[test]
    fn shape_rejects_non_ed25519_kind() {
        let mut b = body();
        b.kind = 1;
        assert_eq!(validate_shape(&b).unwrap_err(), err(WardenError::InvalidAccountData));
    }

    #[test]
    fn shape_rejects_default_session_pubkey() {
        let mut b = body();
        b.session_pubkey = Pubkey::default();
        assert_eq!(validate_shape(&b).unwrap_err(), err(WardenError::InvalidAccountData));
    }

    #[test]
    fn shape_rejects_default_cap_mint() {
        let mut b = body();
        b.caps.push(cap(Pubkey::default(), 1));
        b.lifetime_cap.push(1);
        assert_eq!(validate_shape(&b).unwrap_err(), err(WardenError::InvalidAccountData));
    }

    #[test]
    fn shape_rejects_non_zero_session_day_caps() {
        for (per_day, per_30d) in [(1u64, 0u64), (0, 1), (5, 5)] {
            let mut b = body();
            b.caps.push(MintCap { mint: Pubkey::new_unique(), per_tx: 1, per_day, per_30d });
            b.lifetime_cap.push(1);
            assert_eq!(
                validate_shape(&b).unwrap_err(),
                err(WardenError::SessionDayCapsUnsupported),
                "per_day={per_day} per_30d={per_30d} must be rejected"
            );
        }
    }

    #[test]
    fn shape_accepts_a_per_tx_only_cap() {
        let mut b = body();
        b.caps.push(cap(Pubkey::new_unique(), 5));
        b.lifetime_cap.push(50);
        assert!(validate_shape(&b).is_ok());
    }

    #[test]
    fn shape_rejects_duplicate_mint() {
        let m = Pubkey::new_unique();
        let mut b = body();
        b.caps.push(cap(m, 1));
        b.caps.push(cap(m, 2));
        b.lifetime_cap.push(1);
        b.lifetime_cap.push(2);
        assert_eq!(validate_shape(&b).unwrap_err(), err(WardenError::InvalidAccountData));
    }

    // -- merge_caps -------------------------------------------------------

    #[test]
    fn merge_takes_the_first_empty_slot() {
        let mut s = empty_session();
        let m = Pubkey::new_unique();
        let mut b = body();
        b.caps.push(cap(m, 5));
        b.lifetime_cap.push(50);
        merge_caps(&mut s, &b).unwrap();
        assert_eq!(s.caps[0].mint, m);
        assert_eq!(s.lifetime_cap[0], 50);
        assert_eq!(s.caps[1].mint, Pubkey::default());
    }

    #[test]
    fn merge_replaces_the_same_mint_slot_and_keeps_spent() {
        let mut s = empty_session();
        let a = Pubkey::new_unique();
        let z = Pubkey::new_unique();
        s.caps[0] = cap(a, 5);
        s.lifetime_cap[0] = 50;
        s.lifetime_spent[0] = 30;
        s.caps[1] = cap(z, 7);
        s.lifetime_cap[1] = 70;
        s.lifetime_spent[1] = 7;

        let mut b = body();
        b.caps.push(cap(a, 9));
        b.lifetime_cap.push(90);
        merge_caps(&mut s, &b).unwrap();

        assert_eq!(s.caps[0].per_tx, 9);
        assert_eq!(s.lifetime_cap[0], 90);
        assert_eq!(s.lifetime_spent[0], 30, "spend history survives a re-grant");
        // The untouched mint keeps everything.
        assert_eq!(s.caps[1].mint, z);
        assert_eq!(s.lifetime_cap[1], 70);
        assert_eq!(s.lifetime_spent[1], 7);
    }

    #[test]
    fn merge_rejects_lifetime_below_spent() {
        let mut s = empty_session();
        let a = Pubkey::new_unique();
        s.caps[0] = cap(a, 5);
        s.lifetime_cap[0] = 50;
        s.lifetime_spent[0] = 30;

        let mut b = body();
        b.caps.push(cap(a, 5));
        b.lifetime_cap.push(29);
        assert_eq!(merge_caps(&mut s, &b).unwrap_err(), err(WardenError::CapExceeded));
    }

    #[test]
    fn merge_accepts_lifetime_exactly_equal_to_spent() {
        let mut s = empty_session();
        let a = Pubkey::new_unique();
        s.caps[0] = cap(a, 5);
        s.lifetime_spent[0] = 30;
        let mut b = body();
        b.caps.push(cap(a, 5));
        b.lifetime_cap.push(30);
        assert!(merge_caps(&mut s, &b).is_ok());
        assert_eq!(s.lifetime_cap[0], 30);
    }

    #[test]
    fn merge_rejects_when_every_slot_is_taken() {
        let mut s = empty_session();
        for slot in s.caps.iter_mut() {
            *slot = cap(Pubkey::new_unique(), 1);
        }
        let mut b = body();
        b.caps.push(cap(Pubkey::new_unique(), 1));
        b.lifetime_cap.push(1);
        assert_eq!(merge_caps(&mut s, &b).unwrap_err(), err(WardenError::CapExceeded));
    }

    #[test]
    fn merge_of_a_fresh_slot_zeroes_spent() {
        let mut s = empty_session();
        // A dirty slot: no mint, but stale spend left behind.
        s.lifetime_spent[0] = 999;
        let mut b = body();
        b.caps.push(cap(Pubkey::new_unique(), 1));
        b.lifetime_cap.push(1);
        assert!(merge_caps(&mut s, &b).is_ok());
        assert_eq!(s.lifetime_spent[0], 0);
    }
}
