use anchor_lang::prelude::*;

use crate::constants::{DAY_SECS, MAX_MINT_CAPS, RING_DAYS};
use crate::errors::WardenError;
use crate::state::{MintBuckets, MintCap};

/// Debit `amount` from `b` against `cap`, enforcing per_tx / UTC-day /
/// rolling-30-day caps with checked math only. Account-wide, shared by every
/// outflow path (root direct actions and every session) for this mint.
///
/// Rules (spec §4/§5.2.4):
/// - `now` must be non-negative (no negative timestamps).
/// - `amount <= cap.per_tx`.
/// - the UTC-day bucket rolls (spent_today = 0, day_start snapped to the
///   start of `now`'s UTC day) once `now >= day_start + DAY_SECS`.
/// - the 30-day ring rolls forward to `now`'s day number, zeroing every slot
///   it skips over (capped at 30 — a wider gap is equivalent to zeroing the
///   whole ring since it only has 30 slots).
/// - `spent_today + amount <= cap.per_day` and `sum(ring) + amount <=
///   cap.per_30d`, both via `checked_add` (never silently wrapping).
/// - `cap.per_* == 0` means zero allowed, not "uncapped" — a mint with no
///   configured cap must not be spendable. An unused slot (`cap.mint ==
///   Pubkey::default()`) is rejected outright as `CapExceeded`.
pub fn debit(b: &mut MintBuckets, cap: &MintCap, amount: u64, now: i64) -> Result<()> {
    require!(now >= 0, WardenError::InvalidAccountData);
    require!(cap.mint != Pubkey::default(), WardenError::CapExceeded);
    require!(amount <= cap.per_tx, WardenError::CapExceeded);

    let day_secs = DAY_SECS;
    let ring_days = RING_DAYS as i64;

    // Roll the UTC-day bucket.
    let day_end = b.day_start.checked_add(day_secs).ok_or(WardenError::Overflow)?;
    if now >= day_end {
        b.spent_today = 0;
        b.day_start = now.checked_sub(now.rem_euclid(day_secs)).ok_or(WardenError::Overflow)?;
    }

    // Roll the 30-day ring forward, zeroing every day it skips over.
    let day_number = now.div_euclid(day_secs);
    let gap = day_number.checked_sub(b.ring_day_index).ok_or(WardenError::Overflow)?;
    if gap > 0 {
        let zero_count = core::cmp::min(ring_days, gap);
        for i in 0..zero_count {
            let d = day_number.checked_sub(i).ok_or(WardenError::Overflow)?;
            let slot = d.rem_euclid(ring_days) as usize;
            b.ring[slot] = 0;
        }
        b.ring_day_index = day_number;
    }
    let slot = day_number.rem_euclid(ring_days) as usize;

    let new_spent_today = b.spent_today.checked_add(amount).ok_or(WardenError::Overflow)?;
    require!(new_spent_today <= cap.per_day, WardenError::CapExceeded);

    let mut ring_sum: u64 = 0;
    for v in b.ring.iter() {
        ring_sum = ring_sum.checked_add(*v).ok_or(WardenError::Overflow)?;
    }
    let new_ring_sum = ring_sum.checked_add(amount).ok_or(WardenError::Overflow)?;
    require!(new_ring_sum <= cap.per_30d, WardenError::CapExceeded);

    b.spent_today = new_spent_today;
    b.ring[slot] = b.ring[slot].checked_add(amount).ok_or(WardenError::Overflow)?;

    Ok(())
}

/// Linear scan of the fixed cap slots for `mint`. `MAX_MINT_CAPS` (8) is
/// small enough that this is cheap; unused slots have `mint ==
/// Pubkey::default()` and simply never match a real mint.
pub fn find_cap<'a>(caps: &'a [MintCap; MAX_MINT_CAPS], mint: &Pubkey) -> Option<(usize, &'a MintCap)> {
    caps.iter().enumerate().find(|(_, c)| c.mint == *mint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{FrozenState, Policy, RootKey, SessionKey, SmartAccount};

    fn mint() -> Pubkey {
        Pubkey::new_unique()
    }

    fn cap(mint: Pubkey, per_tx: u64, per_day: u64, per_30d: u64) -> MintCap {
        MintCap { mint, per_tx, per_day, per_30d }
    }

    fn err(e: WardenError) -> anchor_lang::error::Error {
        e.into()
    }

    /// `borsh` 1.x dropped the old `try_to_vec()` inherent-trait method;
    /// `AnchorSerialize::serialize` writes into any `io::Write`.
    fn borsh_len<T: AnchorSerialize>(v: &T) -> usize {
        let mut buf = Vec::new();
        v.serialize(&mut buf).unwrap();
        buf.len()
    }

    #[test]
    fn within_all_caps_ok() {
        let m = mint();
        let c = cap(m, 100, 200, 1000);
        let mut b = MintBuckets::default();
        let now = 1_000_000_i64;
        assert!(debit(&mut b, &c, 50, now).is_ok());
        assert_eq!(b.spent_today, 50);
        let slot = now.div_euclid(DAY_SECS).rem_euclid(RING_DAYS as i64) as usize;
        assert_eq!(b.ring[slot], 50);
    }

    #[test]
    fn per_tx_exceeded_err() {
        let c = cap(mint(), 100, 200, 1000);
        let mut b = MintBuckets::default();
        assert_eq!(debit(&mut b, &c, 101, 1_000_000).unwrap_err(), err(WardenError::CapExceeded));
    }

    #[test]
    fn day_cap_exceeded_err() {
        let c = cap(mint(), 1000, 150, 1000);
        let mut b = MintBuckets::default();
        let now = 1_000_000_i64;
        assert!(debit(&mut b, &c, 100, now).is_ok());
        assert_eq!(debit(&mut b, &c, 100, now).unwrap_err(), err(WardenError::CapExceeded));
    }

    #[test]
    fn day_rolls_over_at_utc_midnight() {
        let c = cap(mint(), 1000, 100, 10_000);
        let mut b = MintBuckets::default();
        let day = 100_i64;
        let t1 = day.checked_mul(DAY_SECS).unwrap().checked_add(500).unwrap();
        assert!(debit(&mut b, &c, 100, t1).is_ok());
        assert_eq!(debit(&mut b, &c, 1, t1).unwrap_err(), err(WardenError::CapExceeded));

        // Advance to exactly the remaining time until the next UTC midnight.
        let day_start = day.checked_mul(DAY_SECS).unwrap();
        let t2 = day_start.checked_add(DAY_SECS).unwrap();
        assert!(debit(&mut b, &c, 100, t2).is_ok());
        assert_eq!(b.spent_today, 100);
    }

    #[test]
    fn ring_30d_cap_enforced_across_days() {
        let c = cap(mint(), 1000, 100, 250);
        let mut b = MintBuckets::default();
        // day 0, day 1: 100 + 100 = 200 <= 250, ok. day 2: 300 > 250, err.
        for day in 0..2_i64 {
            let now = day.checked_mul(DAY_SECS).unwrap();
            assert!(debit(&mut b, &c, 100, now).is_ok(), "day {day} should succeed");
        }
        let now = 2_i64.checked_mul(DAY_SECS).unwrap();
        assert_eq!(debit(&mut b, &c, 100, now).unwrap_err(), err(WardenError::CapExceeded));
    }

    #[test]
    fn ring_zeroes_skipped_days() {
        let c = cap(mint(), 1000, 1000, 1000);
        let mut b = MintBuckets::default();
        assert!(debit(&mut b, &c, 500, 0).is_ok());
        // Jump 45 days forward — gap > 30, so the whole ring must clear.
        let now = 45_i64.checked_mul(DAY_SECS).unwrap();
        assert!(debit(&mut b, &c, 1000, now).is_ok(), "ring must have been zeroed to allow a fresh 1000");
    }

    #[test]
    fn unknown_mint_err() {
        let c = MintCap::default(); // mint == Pubkey::default(): unused slot
        let mut b = MintBuckets::default();
        assert_eq!(debit(&mut b, &c, 1, 1_000_000).unwrap_err(), err(WardenError::CapExceeded));
        assert!(find_cap(&[MintCap::default(); MAX_MINT_CAPS], &mint()).is_none());
    }

    #[test]
    fn zero_cap_means_no_spend() {
        let c = cap(mint(), 0, 0, 0);
        let mut b = MintBuckets::default();
        assert_eq!(debit(&mut b, &c, 1, 1_000_000).unwrap_err(), err(WardenError::CapExceeded));
    }

    #[test]
    fn overflow_guard() {
        let c = cap(mint(), u64::MAX, u64::MAX, u64::MAX);
        let now = 1_000_000_i64;
        let day_start = now.checked_sub(now.rem_euclid(DAY_SECS)).unwrap();
        let day_number = now.div_euclid(DAY_SECS);
        let mut b = MintBuckets {
            day_start,
            spent_today: u64::MAX - 1,
            ring_day_index: day_number,
            ring: [0; RING_DAYS],
        };
        // No day/ring roll happens (already on `now`'s day), so spent_today
        // keeps its near-MAX value and checked_add must overflow, not panic.
        assert_eq!(debit(&mut b, &c, 10, now).unwrap_err(), err(WardenError::Overflow));
    }

    #[test]
    fn exact_midnight_boundary() {
        let c = cap(mint(), 1000, 1000, 100_000);
        let mut b = MintBuckets::default();
        assert!(debit(&mut b, &c, 10, 86_399).is_ok());
        assert_eq!(b.day_start, 0);
        assert!(debit(&mut b, &c, 10, 86_400).is_ok());
        assert_eq!(b.day_start, 86_400);
        assert_eq!(b.spent_today, 10, "new day, spent_today reset then re-spent");
    }

    #[test]
    fn negative_timestamp_rejected() {
        let c = cap(mint(), 1000, 1000, 1000);
        let mut b = MintBuckets::default();
        assert_eq!(debit(&mut b, &c, 1, -1).unwrap_err(), err(WardenError::InvalidAccountData));
    }

    #[test]
    fn ring_slot_index_at_day_29_30_31() {
        let c = cap(mint(), 1000, 1000, 100_000);
        let mut b = MintBuckets::default();
        for day in 0..=31_i64 {
            let now = day.checked_mul(DAY_SECS).unwrap();
            assert!(debit(&mut b, &c, 1, now).is_ok(), "day {day}");
        }
        // day 31's slot (31 % 30 == 1) must hold only day 31's contribution:
        // day 1 (slot 1, 30 days earlier) was zeroed on day 31's roll.
        assert_eq!(b.ring[1], 1);
        // day 30's slot (30 % 30 == 0) must hold only day 30's contribution:
        // day 0 (slot 0) was zeroed on day 30's roll.
        assert_eq!(b.ring[0], 1);
        // day 29's slot (29 % 30 == 29) was never revisited.
        assert_eq!(b.ring[29], 1);
        assert_eq!(b.ring_day_index, 31);
    }

    #[test]
    fn len_constants_match_serialized_size_and_reserved_zeroed() {
        let policy = Policy {
            version: 0,
            caps: [MintCap::default(); MAX_MINT_CAPS],
            session_ceiling: [MintCap::default(); MAX_MINT_CAPS],
            large_threshold: [MintCap::default(); MAX_MINT_CAPS],
            timelock_secs: 0,
            recovery_delay_secs: 0,
            max_session_life_secs: 0,
            session_ops_ceiling: 0,
            _reserved: [0; 64],
        };
        assert!(policy._reserved.iter().all(|b| *b == 0));

        // Size the account for the largest variant of each enum field, since
        // Borsh serializes only the active variant's bytes (no padding) and
        // the account is allocated once at creation with no realloc.
        let account = SmartAccount {
            version: 0,
            bump: 0,
            owner_seed: [0; 32],
            root: RootKey::P256Passkey { pubkey: [0; 33] },
            rp_id_hash: [0; 32],
            origin: [0; 64],
            origin_len: 0,
            cluster_tag: [0; 32],
            generation: 0,
            root_nonce: 0,
            policy,
            frozen: FrozenState::Guardian { idx: 0, until: 0 },
            frozen_at: 0,
            buckets: [MintBuckets::default(); MAX_MINT_CAPS],
            guardians_config: Pubkey::default(),
            registry: Pubkey::default(),
            _reserved: [0; 256],
        };
        assert!(account._reserved.iter().all(|b| *b == 0));
        assert_eq!(
            SmartAccount::LEN,
            8 + borsh_len(&account),
            "SmartAccount::LEN must equal discriminator + max-variant serialized size"
        );

        let session = SessionKey {
            version: 0,
            bump: 0,
            account: Pubkey::default(),
            pubkey: Pubkey::default(),
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
        };
        assert!(session._reserved.iter().all(|b| *b == 0));
        assert_eq!(SessionKey::LEN, 8 + borsh_len(&session));

        // The Ed25519 root variant is smaller (33 B vs 34 B) — confirm it
        // still fits comfortably within the space reserved for the larger
        // variant (never larger than LEN).
        let policy2 = Policy {
            version: 0,
            caps: [MintCap::default(); MAX_MINT_CAPS],
            session_ceiling: [MintCap::default(); MAX_MINT_CAPS],
            large_threshold: [MintCap::default(); MAX_MINT_CAPS],
            timelock_secs: 0,
            recovery_delay_secs: 0,
            max_session_life_secs: 0,
            session_ops_ceiling: 0,
            _reserved: [0; 64],
        };
        let smaller_root = SmartAccount {
            version: 0,
            bump: 0,
            owner_seed: [0; 32],
            root: RootKey::Ed25519 { pubkey: Pubkey::default() },
            rp_id_hash: [0; 32],
            origin: [0; 64],
            origin_len: 0,
            cluster_tag: [0; 32],
            generation: 0,
            root_nonce: 0,
            policy: policy2,
            frozen: FrozenState::None,
            frozen_at: 0,
            buckets: [MintBuckets::default(); MAX_MINT_CAPS],
            guardians_config: Pubkey::default(),
            registry: Pubkey::default(),
            _reserved: [0; 256],
        };
        assert!(8 + borsh_len(&smaller_root) <= SmartAccount::LEN);
    }
}
