//! `Stage` — a chunk-uploaded, content-addressed, consume-once payload buffer
//! (Phase 1B Task 4).
//!
//! A root `execute`/`swap` whose compiled instruction data does not fit the
//! 1,232 B packet is uploaded here first, one `stage_chunk` transaction at a
//! time, then referenced by hash from a single root instruction (spec §5.1,
//! §12.2). Staging relieves **instruction-data** size only: every CPI program,
//! account and LUT still rides in the `execute` transaction's own account list.
//!
//! ## Content-addressed, and why that is both the point and a hazard
//!
//! The PDA is `["stage", account, hash]` where `hash == Keccak256(data)`. That
//! makes a stage tamper-evident (finalize re-hashes the bytes and rejects a
//! mismatch) and lets the root ceremony bind only the 32-byte hash instead of
//! the whole payload. But a content address is *predictable*: anyone who sees a
//! payload can compute its hash and open the PDA first, and the victim's own
//! `stage_open` then fails on an already-initialised account — the exact
//! Squads v3 buffer-squat shape (Neodyme `ND-SQD3-LO-01`, Certora `H-01`).
//!
//! Two properties defuse it, and both are tested rather than assumed:
//! - **`creator` owns the rent.** Whoever opened the stage is recorded, and
//!   every close refunds *them*. Squatting therefore costs the attacker and
//!   pays the victim nothing.
//! - **`expiry_ts ≤ now + `[`STAGE_MAX_TTL_SECS`]. After it, *anyone* may
//!   close the stage and free the address, so the grief is time-boxed to at
//!   most an hour, never permanent.
//!
//! ## Bound to the state it was staged against
//!
//! `stage_finalize` records the SmartAccount's `generation` and
//! `policy_version` at finalize time; `execute` (Task 5) requires both to still
//! equal the account's current values and closes the stage on use. So staged
//! content is single-use and cannot survive a key rotation / recovery
//! (generation bump) or a policy change — the same invalidation that voids an
//! outstanding session voids an outstanding stage.

use anchor_lang::prelude::*;

use crate::constants::STAGE_MAX_DATA_LEN;

#[account]
pub struct Stage {
    /// Schema version; `1` for the only shape Phase 1B writes. `0` is exactly
    /// "this PDA has not been initialised", mirroring `SessionKey`.
    pub version: u8,
    /// The canonical bump for `["stage", account, hash]`, stored so a later
    /// instruction re-derives the address from the account itself rather than
    /// trusting a passed bump.
    pub bump: u8,
    /// The SmartAccount this payload is destined for (bound into the PDA seeds).
    pub account: Pubkey,
    /// Who opened the stage. The rent-refund destination on every close, so the
    /// cost of a content-address squat lands on the squatter (module docs).
    pub creator: Pubkey,
    /// `Keccak256(data)`, also the third PDA seed. `stage_finalize` re-hashes
    /// `data` and rejects a mismatch.
    pub hash: [u8; 32],
    /// Total payload length agreed at `stage_open`. `data` is allocated to
    /// exactly this size; `written` walks up to it.
    pub len: u32,
    /// Bytes written so far. `stage_chunk` requires `offset == written`
    /// (strictly sequential, no gaps, no overwrite); finalize requires
    /// `written == len`.
    pub written: u32,
    /// Set by `stage_finalize` once `written == len` and the hash matches.
    /// Only a finalized stage may be consumed by `execute`.
    pub finalized: bool,
    /// The account `generation` captured at finalize. `execute` requires it to
    /// still be current (spec §5.3 item 6). `0` until finalize.
    pub generation: u64,
    /// The account `policy_version` captured at finalize; same consume rule.
    /// `0` until finalize.
    pub policy_version: u32,
    /// Absolute unix seconds after which anyone may close the stage. `≤ now +
    /// STAGE_MAX_TTL_SECS`, checked at open.
    pub expiry_ts: i64,
    /// The staged payload bytes. Grows by chunk; its final `Keccak256` equals
    /// `hash`.
    pub data: Vec<u8>,
}

impl Stage {
    /// Serialized size of everything before `data`'s contents, INCLUDING the
    /// 8-byte account discriminator and `data`'s 4-byte borsh length prefix.
    /// Pinned by `stage::header_len_matches_layout` so a field edit that
    /// changes the layout fails a test rather than silently mis-sizing the PDA.
    ///
    /// 8 (disc) + 1 (version) + 1 (bump) + 32 (account) + 32 (creator)
    /// + 32 (hash) + 4 (len) + 4 (written) + 1 (finalized) + 8 (generation)
    /// + 4 (policy_version) + 8 (expiry_ts) + 4 (Vec len prefix) = 139.
    pub const HEADER_LEN: usize = 8 + 1 + 1 + 32 + 32 + 32 + 4 + 4 + 1 + 8 + 4 + 8 + 4;

    /// The `space` an `init` must allocate for a stage holding `data_len` bytes.
    /// `data_len` is bounded by [`Self::MAX_DATA_LEN`] at the call site, so the
    /// `saturating_add` (present only to satisfy the crate's
    /// `arithmetic_side_effects` lint) can never actually saturate.
    pub const fn space(data_len: usize) -> usize {
        Self::HEADER_LEN.saturating_add(data_len)
    }

    /// The largest payload a stage may hold ([`STAGE_MAX_DATA_LEN`]).
    pub const MAX_DATA_LEN: usize = STAGE_MAX_DATA_LEN;
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::AccountSerialize;

    #[test]
    fn header_len_matches_layout() {
        // The serialized size of a stage with no payload — discriminator + all
        // fixed fields + the empty `Vec`'s 4-byte length prefix — is exactly
        // HEADER_LEN, so `space(n)` allocates precisely header + n.
        let s = Stage {
            version: 1,
            bump: 255,
            account: Pubkey::default(),
            creator: Pubkey::default(),
            hash: [0u8; 32],
            len: 0,
            written: 0,
            finalized: false,
            generation: 0,
            policy_version: 0,
            expiry_ts: 0,
            data: Vec::new(),
        };
        let mut buf = Vec::new();
        s.try_serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), Stage::HEADER_LEN, "empty-data stage is exactly HEADER_LEN");
        assert_eq!(Stage::space(100), Stage::HEADER_LEN + 100);
    }
}
