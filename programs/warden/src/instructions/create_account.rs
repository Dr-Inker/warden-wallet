//! `create_account` — initializes a passkey-rooted `SmartAccount` PDA.
//!
//! No root signature is required to create an account: `payer` funds the PDA
//! and every other field is exactly what the caller asserts. This is safe —
//! an attacker who "creates" an account for someone else's passkey harms no
//! one, since the PDA is derived from `owner_seed` (a value the real owner
//! chooses) and every root-authorized instruction thereafter (Task 3's
//! `root_verify`) demands a live, freshly signed passkey assertion regardless
//! of who paid to bring the account into existence (spec §4, task-4 brief).

use anchor_lang::prelude::*;

use crate::constants::{ACCOUNT_SEED, DAY_SECS, MAX_MINT_CAPS};
use crate::errors::WardenError;
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

// No `Debug`: `PolicyArgs` embeds `MintCap` (`#[zero_copy]`), which doesn't
// derive it — see the note on `PolicyArgs` itself.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub struct CreateAccountArgs {
    pub owner_seed: [u8; 32],
    pub root: RootKey,
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

#[derive(Accounts)]
#[instruction(args: CreateAccountArgs)]
pub struct CreateAccount<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = SmartAccount::LEN,
        seeds = [ACCOUNT_SEED, args.owner_seed.as_ref()],
        bump
    )]
    pub smart_account: AccountLoader<'info, SmartAccount>,
    pub system_program: Program<'info, System>,
}

// Not `pub`: only `lib.rs`'s `#[program]` module calls this, by full path
// (`instructions::create_account::handler`) — a bare `pub` here is what
// makes `instructions::mod.rs`'s glob re-export of this module collide with
// `rotate_nonce`'s own `handler` (both would otherwise land in the crate
// root's namespace under the same name).
pub(crate) fn handler(ctx: Context<CreateAccount>, args: CreateAccountArgs) -> Result<()> {
    validate_root(&args.root)?;
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

    let policy: Policy = args.policy.expand()?;
    validate_policy(&policy)?;

    let mut account = ctx.accounts.smart_account.load_init()?;
    // `init` allocates the account via `system_program::create_account`,
    // which always zero-fills the new data — every field this handler does
    // not touch below (`generation`, `root_nonce`, `frozen_at`,
    // `guardians_config`, `registry`, `_reserved`, `_pad_align8`) is already
    // 0/`Pubkey::default()`. Fields are still assigned explicitly where the
    // brief calls them out, so the invariant is visible here rather than
    // resting solely on "the runtime happens to zero new accounts".
    account.version = 1;
    account.bump = ctx.bumps.smart_account;
    account.owner_seed = args.owner_seed;
    account.set_root(&args.root);
    account.rp_id_hash = computed_rp_id_hash;
    account.origin[..args.origin.len()].copy_from_slice(&args.origin);
    account.origin_len = args.origin.len() as u8;
    account.cluster_tag = args.cluster_tag;
    account.generation = 0;
    account.root_nonce = 0;
    account.set_frozen(&FrozenState::None);
    account.frozen_at = 0;
    account.policy = policy;
    account.policy.version = 1; // forced regardless of the caller's PolicyArgs.version

    Ok(())
}

// ---------------------------------------------------------------------------
// secp256r1 (P-256) root-key encoding
// ---------------------------------------------------------------------------
//
// **Why there is no on-curve check here, and what is carried to 1B.**
//
// The fix re-review (Codex thread 01a0164f) is right that an ENCODING check
// is weaker than the property that matters: roughly half of all x values
// below `p` are not on the curve, the secp256r1 precompile rejects every one
// of them, and an account created around such a key is unusable.
//
// Deciding "is `x³ - 3x + b` a quadratic residue mod p" needs 256-bit field
// arithmetic. Two ways to get it were tried and rejected, in this order:
//
// 1. `sol_big_mod_exp` (Euler's criterion in two syscalls, ~30 lines of
//    modular add/sub around it). IMPLEMENTED AND THEN REVERTED: the syscall
//    is gated behind `enable_big_mod_exp_syscall`, which litesvm 0.12's
//    mainnet-active feature snapshot (2026-04-26) does NOT list — the
//    program aborted with "unsupported BPF instruction" even under
//    `with_mainnet_features()`. Shipping a program that calls a syscall whose
//    activation on the target cluster cannot be verified would turn EVERY
//    `create_account` into a hard failure: strictly worse than the defect it
//    closes.
// 2. Hand-rolled 256-bit modular multiplication in the program. Rejected on
//    risk: new, unaudited field arithmetic written at the close of a
//    milestone is a more likely source of a real defect than the one it
//    removes.
//
// The complete property is **proof of possession at creation** — a real root
// ceremony over `generation = 0`, `root_nonce = 0`, which makes the
// precompile itself do the curve validation for free. It does not fit 1A's
// packet budget (`RootArgs` + the precompile instruction are ~400 B, against
// a `MAX_MINTS_AT_CREATE` transaction already at 1,144 B of 1,232), so it is
// carried into Phase 1B's pre-ship gate alongside O11 — see
// docs/spikes/DECISION.md and docs/program/PHASE1A-MEASUREMENTS.md.
//
// Residual risk, stated plainly: this is a self-inflicted-loss vector, not a
// theft vector. A root nobody can sign for is a dead account, not a stolen
// one, and reaching it requires a client that invents a root pubkey instead
// of reading it out of the authenticator's SPKI. The client mitigation is
// mandatory and documented: round-trip one real root instruction
// (`rotate_nonce`) against a newly created account BEFORE funding it.

/// Root-key rules. **Milestone-review finding (Important): creation used to
/// accept a root that no root-authorized instruction can ever use**, which
/// turns a funded account into a permanent loss.
///
/// - `RootKey::Ed25519` is refused (`RootKindUnsupported`, the same error
///   `verify_root_assertion` raises for it). The kind exists in the layout for
///   hardware/advanced users (spec §4) and 1B may implement its signature
///   path; until then, storing it would create an account whose every root
///   instruction aborts.
/// - A P-256 root must be a well-formed compressed point ENCODING: prefix
///   `0x02`/`0x03` and `x < p`. This catches the shapes a confused client
///   actually produces (a 32-byte Ed25519 key with a junk prefix byte, an
///   uncompressed `0x04` point, an all-`0xff` filler) but NOT an x that is
///   simply off the curve — see the long note above this function for why
///   the on-curve check is deferred to 1B and what the client must do
///   meanwhile.
///
/// **1B: any instruction that SETS a root (recovery) must call
/// `validate_root` too.**
fn validate_root(root: &RootKey) -> Result<()> {
    let pubkey = match root {
        RootKey::P256Passkey { pubkey } => pubkey,
        RootKey::Ed25519 { .. } => return Err(WardenError::RootKindUnsupported.into()),
    };
    require!(pubkey[0] == 0x02 || pubkey[0] == 0x03, WardenError::InvalidRootKey);
    // x must be a field element. `x == 0` is deliberately NOT excluded:
    // P-256 has a valid point at x = 0, and the first fix pass rejected it
    // wrongly (re-review finding).
    require!(pubkey[1..33] < P256_FIELD_PRIME_BE[..], WardenError::InvalidRootKey);
    Ok(())
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
            assert!(validate_root(&p256_root(compressed(GX_BE, prefix))).is_ok());
        }
    }

    /// x = 0 IS on P-256 (`0³ - 0 + b` is a quadratic residue — verified
    /// independently). The first fix pass rejected it out of caution and was
    /// wrong to; re-review finding.
    #[test]
    fn root_accepts_x_zero_which_is_a_real_point() {
        assert!(validate_root(&p256_root(compressed([0u8; 32], 0x02))).is_ok());
    }

    /// **This test states the KNOWN GAP, it does not paper over it.** x = 1
    /// is a well-formed encoding of a point that is NOT on P-256, and 1A
    /// accepts it — see the deferral note above `validate_root`. When 1B adds
    /// proof of possession (or an on-curve check), this test must flip to
    /// asserting rejection.
    #[test]
    fn root_accepts_an_off_curve_x_phase_1a_gap() {
        let mut x = [0u8; 32];
        x[31] = 1; // off-curve, independently verified
        assert!(
            validate_root(&p256_root(compressed(x, 0x02))).is_ok(),
            "1A checks the ENCODING only; flip this when 1B closes the gap"
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
