use anchor_lang::prelude::*;

use crate::constants::{MAX_MINT_CAPS, RING_DAYS};

/// The passkey-rooted smart account. Layout is FINAL for Phase 1B: every
/// 1B/1C field (`guardians_config`, `registry`, `_reserved`) is present now,
/// carved from `_reserved` in later versions without a realloc. `version`
/// documents each carve.
#[account]
pub struct SmartAccount {
    pub version: u8,
    pub bump: u8,
    pub owner_seed: [u8; 32],
    /// Passkey (P-256) or Ed25519 root signer.
    pub root: RootKey,
    /// == SHA-256(origin[..origin_len]) — enforced at create (Task 4).
    pub rp_id_hash: [u8; 32],
    /// Canonical full origin "chrome-extension://<32 chars>"; bytes beyond
    /// `origin_len` are zero; no NULs.
    pub origin: [u8; 64],
    pub origin_len: u8,
    /// Client-attested domain separator (genesis hash by convention) — NOT
    /// verified on-chain; bound into every root transcript.
    pub cluster_tag: [u8; 32],
    pub generation: u64,
    pub root_nonce: u64,
    pub policy: Policy,
    pub frozen: FrozenState,
    pub frozen_at: i64,
    /// Parallel to `policy.caps`.
    pub buckets: [MintBuckets; MAX_MINT_CAPS],
    /// 1B: PDA of the guardians/recovery config (`Pubkey::default()` until
    /// set) — reserved now so no realloc later.
    pub guardians_config: Pubkey,
    /// 1B: adapter-registry PDA (default until set).
    pub registry: Pubkey,
    /// Forward-compat headroom; 1B/1C fields are carved from here without
    /// realloc.
    pub _reserved: [u8; 256],
}

impl SmartAccount {
    /// 8-byte Anchor discriminator + fields. `root`/`frozen` are Borsh enums
    /// whose serialized size depends on the active variant (Borsh has no
    /// per-field padding), so the account must be sized for the LARGEST
    /// variant of each (`RootKey::P256Passkey` = 34 B, `FrozenState::Guardian`
    /// = 10 B) — a smaller-variant instance simply leaves trailing bytes of
    /// its allocated space unused. See `len_constants_match_serialized_size_and_reserved_zeroed`
    /// in `buckets.rs` for the check that this constant is not an
    /// underestimate.
    pub const LEN: usize = 8
        + 1 // version
        + 1 // bump
        + 32 // owner_seed
        + ROOT_KEY_MAX_LEN // root
        + 32 // rp_id_hash
        + 64 // origin
        + 1 // origin_len
        + 32 // cluster_tag
        + 8 // generation
        + 8 // root_nonce
        + Policy::LEN // policy
        + FROZEN_STATE_MAX_LEN // frozen
        + 8 // frozen_at
        + MintBuckets::LEN * MAX_MINT_CAPS // buckets
        + 32 // guardians_config
        + 32 // registry
        + 256; // _reserved
}

/// Borsh: 1-byte variant tag + `[u8; 33]` (the larger of the two variants;
/// `Ed25519 { pubkey: Pubkey }` is 1 + 32 = 33 B).
const ROOT_KEY_MAX_LEN: usize = 1 + 33;
/// Borsh: 1-byte variant tag + `idx: u8` + `until: i64` (the largest of the
/// three variants; `None`/`Root` are 1 B).
const FROZEN_STATE_MAX_LEN: usize = 1 + 1 + 8;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub enum RootKey {
    P256Passkey { pubkey: [u8; 33] },
    Ed25519 { pubkey: Pubkey },
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub enum FrozenState {
    None,
    Root,
    Guardian { idx: u8, until: i64 },
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct Policy {
    pub version: u32,
    /// `mint == Pubkey::default()` => unused slot; SOL uses the native mint id.
    pub caps: [MintCap; MAX_MINT_CAPS],
    pub session_ceiling: [MintCap; MAX_MINT_CAPS],
    /// per_tx only used.
    pub large_threshold: [MintCap; MAX_MINT_CAPS],
    pub timelock_secs: i64,
    pub recovery_delay_secs: i64,
    pub max_session_life_secs: i64,
    pub session_ops_ceiling: u16,
    pub _reserved: [u8; 64],
}

impl Policy {
    pub const LEN: usize = 4 // version
        + MintCap::LEN * MAX_MINT_CAPS // caps
        + MintCap::LEN * MAX_MINT_CAPS // session_ceiling
        + MintCap::LEN * MAX_MINT_CAPS // large_threshold
        + 8 // timelock_secs
        + 8 // recovery_delay_secs
        + 8 // max_session_life_secs
        + 2 // session_ops_ceiling
        + 64; // _reserved
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Default)]
pub struct MintCap {
    pub mint: Pubkey,
    pub per_tx: u64,
    pub per_day: u64,
    pub per_30d: u64,
}

impl MintCap {
    pub const LEN: usize = 32 + 8 + 8 + 8;
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default)]
pub struct MintBuckets {
    pub day_start: i64,
    pub spent_today: u64,
    pub ring_day_index: i64,
    pub ring: [u64; RING_DAYS],
}

impl MintBuckets {
    pub const LEN: usize = 8 + 8 + 8 + 8 * RING_DAYS;
}
