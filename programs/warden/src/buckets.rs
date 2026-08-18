use anchor_lang::prelude::*;

use crate::constants::{DAY_SECS, MAX_MINT_CAPS, RING_DAYS};
use crate::errors::WardenError;
use crate::state::{MintBuckets, MintCap};

/// Debit `amount` from `b` against `cap`, enforcing per_tx / UTC-day /
/// rolling-30-day caps with checked math only. Account-wide, shared by every
/// outflow path (root direct actions and every session) for this mint.
///
/// Atomicity: all rollover bookkeeping (day roll, ring roll) and cap checks
/// happen on a local copy (`cand`); `*b` is only overwritten once every
/// check has passed. A rejected debit (`CapExceeded`/`Overflow`/
/// `InvalidAccountData`) leaves `*b` byte-identical to how it was before the
/// call — including the day/ring bookkeeping fields — even if `now` crossed
/// a day boundary. (Solana's runtime already discards all account writes on
/// a failed transaction, but `debit` shouldn't rely on that: a caller that
/// invokes it more than once per instruction, or that inspects `*b` after a
/// caught error, must see no partial effect.)
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

    // Work on a local copy so a rejected debit can never mutate `*b`.
    let mut cand: MintBuckets = *b;

    // Roll the UTC-day bucket.
    let day_end = cand.day_start.checked_add(day_secs).ok_or(WardenError::Overflow)?;
    if now >= day_end {
        cand.spent_today = 0;
        cand.day_start = now.checked_sub(now.rem_euclid(day_secs)).ok_or(WardenError::Overflow)?;
    }

    // Roll the 30-day ring forward, zeroing every day it skips over.
    let day_number = now.div_euclid(day_secs);
    let gap = day_number.checked_sub(cand.ring_day_index).ok_or(WardenError::Overflow)?;
    if gap > 0 {
        let zero_count = core::cmp::min(ring_days, gap);
        for i in 0..zero_count {
            let d = day_number.checked_sub(i).ok_or(WardenError::Overflow)?;
            let slot = d.rem_euclid(ring_days) as usize;
            cand.ring[slot] = 0;
        }
        cand.ring_day_index = day_number;
    }
    let slot = day_number.rem_euclid(ring_days) as usize;

    let new_spent_today = cand.spent_today.checked_add(amount).ok_or(WardenError::Overflow)?;
    require!(new_spent_today <= cap.per_day, WardenError::CapExceeded);

    let mut ring_sum: u64 = 0;
    for v in cand.ring.iter() {
        ring_sum = ring_sum.checked_add(*v).ok_or(WardenError::Overflow)?;
    }
    let new_ring_sum = ring_sum.checked_add(amount).ok_or(WardenError::Overflow)?;
    require!(new_ring_sum <= cap.per_30d, WardenError::CapExceeded);

    cand.spent_today = new_spent_today;
    cand.ring[slot] = cand.ring[slot].checked_add(amount).ok_or(WardenError::Overflow)?;

    *b = cand;
    Ok(())
}

/// Linear scan of the fixed cap slots for `mint`. `MAX_MINT_CAPS` (8) is
/// small enough that this is cheap. `Pubkey::default()` never matches, even
/// if queried directly: it's the unused-slot sentinel, never a real mint —
/// an all-empty `caps` array must not accidentally "find" a slot when asked
/// about the zero pubkey.
pub fn find_cap<'a>(caps: &'a [MintCap; MAX_MINT_CAPS], mint: &Pubkey) -> Option<(usize, &'a MintCap)> {
    caps.iter().enumerate().find(|(_, c)| c.mint != Pubkey::default() && c.mint == *mint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{SessionKey, SmartAccount};

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
        // per_30d = 1000, spending 100/day: cumulative = 100*(day+1), so day
        // index 9 (the 10th spend) reaches exactly 1000 (ok) and day index
        // 10 (the 11th spend) would reach 1100 — the first to exceed.
        let c = cap(mint(), 1000, 1000, 1000);
        let mut b = MintBuckets::default();
        for day in 0..10_i64 {
            let now = day.checked_mul(DAY_SECS).unwrap();
            assert!(debit(&mut b, &c, 100, now).is_ok(), "day {day} should succeed");
        }
        let now10 = 10_i64.checked_mul(DAY_SECS).unwrap();
        assert_eq!(
            debit(&mut b, &c, 100, now10).unwrap_err(),
            err(WardenError::CapExceeded),
            "day 10 must be the first day to exceed per_30d"
        );

        // Day 31 frees capacity again: the ring roll from day 9's committed
        // state (the last successful debit) to day 31 has a gap of 22,
        // zeroing days 10..=31's slots — which wrap onto (and clear) days 0
        // and 1's 30-days-stale contributions, leaving only days 2..=9 (800)
        // in the window, so a fresh 100 fits under 1000 again.
        let now31 = 31_i64.checked_mul(DAY_SECS).unwrap();
        assert!(debit(&mut b, &c, 100, now31).is_ok(), "day 31 should have freed capacity");
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
    fn find_cap_never_matches_default_mint() {
        let mut caps = [MintCap::default(); MAX_MINT_CAPS];
        caps[0] = cap(mint(), 1, 1, 1);
        // Even though `caps` has (unused) default-mint slots, querying for
        // the default pubkey itself must never "find" one.
        assert!(find_cap(&caps, &Pubkey::default()).is_none());
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
    fn debit_atomic_on_cap_exceeded_after_day_boundary() {
        let c = cap(mint(), 1000, 50, 1000);
        let mut b = MintBuckets::default();
        assert!(debit(&mut b, &c, 50, 0).is_ok()); // day 0, fills per_day exactly
        let before = b;

        // Crosses into day 1; 60 > per_day(50) even on a freshly-rolled day,
        // so this must fail — and leave `b` (incl. day_start/ring_day_index)
        // exactly as it was, not partially rolled.
        let now_day1 = DAY_SECS;
        assert_eq!(debit(&mut b, &c, 60, now_day1).unwrap_err(), err(WardenError::CapExceeded));
        assert!(b == before, "a rejected debit must not roll the day/ring bookkeeping either");
    }

    #[test]
    fn debit_atomic_on_overflow_after_day_boundary() {
        let c = cap(mint(), 1000, u64::MAX, u64::MAX);
        // 29 of the 30 ring slots survive a 1-day roll (only the current
        // day's slot gets zeroed), and 29 * (u64::MAX / 2) overflows u64 —
        // the ring-sum `checked_add` chain must catch it.
        let v = u64::MAX / 2;
        let mut b = MintBuckets { day_start: 0, spent_today: 0, ring_day_index: 0, ring: [v; RING_DAYS] };
        let before = b;

        let now_day1 = DAY_SECS; // crosses the day boundary
        assert_eq!(debit(&mut b, &c, 10, now_day1).unwrap_err(), err(WardenError::Overflow));
        assert!(b == before, "a rejected debit must not roll the day/ring bookkeeping either");
    }

    #[test]
    fn len_constants_match_serialized_size_and_reserved_zeroed() {
        // SmartAccount/Policy/MintCap/MintBuckets are zero-copy `Pod` now;
        // their `LEN`/padding assertions live next to the struct
        // definitions in `state/smart_account.rs` (`core::mem::size_of`
        // checks, e.g. `smart_account_len_matches_size_of`). This test
        // keeps the SessionKey (still plain-Borsh) LEN + reserved-zero
        // check, plus a sanity cross-check on `SmartAccount::LEN`.
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

        assert_eq!(SmartAccount::LEN, 8 + core::mem::size_of::<SmartAccount>());
    }
}
