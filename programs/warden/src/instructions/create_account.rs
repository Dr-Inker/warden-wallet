//! `create_account` — initializes a passkey- (or Ed25519-) rooted
//! `SmartAccount` PDA.
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
use crate::state::{FrozenState, Policy, PolicyArgs, RootKey, SmartAccount};

/// Matches `SmartAccount.origin`'s fixed storage width.
pub const MAX_ORIGIN_LEN: usize = 64;
/// v1 requires every origin to be a Chrome extension origin (spec §4).
pub const ORIGIN_PREFIX: &[u8] = b"chrome-extension://";
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
    /// `chrome-extension://…`, 1..=64 bytes (`MAX_ORIGIN_LEN`).
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

    let policy: Policy = args.policy.clone().into();
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

/// Origin rules (spec §4 / task-4 brief): 1..=64 bytes, must start with
/// `chrome-extension://`, no embedded NUL, no trailing whitespace.
fn validate_origin(origin: &[u8]) -> Result<()> {
    require!(!origin.is_empty() && origin.len() <= MAX_ORIGIN_LEN, WardenError::InvalidOrigin);
    require!(origin.starts_with(ORIGIN_PREFIX), WardenError::InvalidOrigin);
    require!(!origin.contains(&0u8), WardenError::InvalidOrigin);
    // `origin` is bytes, not a decoded string — trailing whitespace is
    // judged on the raw ASCII whitespace byte set, matching the JSON
    // scanner's own definition of a well-formed value.
    let last = *origin.last().expect("non-empty, checked above");
    require!(!last.is_ascii_whitespace(), WardenError::InvalidOrigin);
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
    require!(p.max_session_life_secs <= MAX_SESSION_LIFE_SECS, WardenError::InvalidPolicy);

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
        assert!(validate_origin(b"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi").is_ok());
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

    #[test]
    fn origin_accepts_exactly_64_bytes() {
        let mut o = b"chrome-extension://".to_vec();
        o.extend(std::iter::repeat(b'a').take(MAX_ORIGIN_LEN - o.len()));
        assert_eq!(o.len(), MAX_ORIGIN_LEN);
        assert!(validate_origin(&o).is_ok());
    }

    #[test]
    fn origin_rejects_missing_prefix() {
        assert_eq!(
            validate_origin(b"https://maikadpaobbjkmaomnpnhjglpabllaoi").unwrap_err(),
            err(WardenError::InvalidOrigin)
        );
    }

    #[test]
    fn origin_rejects_embedded_nul() {
        let o = b"chrome-extension://abc\0def".to_vec();
        assert_eq!(validate_origin(&o).unwrap_err(), err(WardenError::InvalidOrigin));
    }

    #[test]
    fn origin_rejects_trailing_nul() {
        let o = b"chrome-extension://abcdef\0".to_vec();
        assert_eq!(validate_origin(&o).unwrap_err(), err(WardenError::InvalidOrigin));
    }

    #[test]
    fn origin_rejects_trailing_whitespace() {
        let o = b"chrome-extension://abcdef ".to_vec();
        assert_eq!(validate_origin(&o).unwrap_err(), err(WardenError::InvalidOrigin));
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

    // -- PolicyArgs -> Policy ---------------------------------------------

    #[test]
    fn policy_args_conversion_zero_fills_padding_and_reserved() {
        let a = PolicyArgs {
            version: 7,
            caps: [MintCap::default(); MAX_MINT_CAPS],
            session_ceiling: [MintCap::default(); MAX_MINT_CAPS],
            large_threshold: [MintCap::default(); MAX_MINT_CAPS],
            timelock_secs: MIN_TIMELOCK_SECS,
            recovery_delay_secs: MIN_TIMELOCK_SECS,
            max_session_life_secs: MAX_SESSION_LIFE_SECS,
            session_ops_ceiling: 3,
        };
        let p: Policy = a.into();
        assert_eq!(p.version, 7);
        assert_eq!(p._pad_version, [0u8; 4]);
        assert_eq!(p._pad_ceiling, [0u8; 6]);
        assert_eq!(p._reserved, [0u8; 64]);
        assert_eq!(p.timelock_secs, MIN_TIMELOCK_SECS);
        assert_eq!(p.session_ops_ceiling, 3);
    }
}
