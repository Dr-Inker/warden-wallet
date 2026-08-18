use anchor_lang::prelude::*;

use crate::constants::MAX_MINT_CAPS;
use crate::state::smart_account::MintCap;

/// A bounded, expiring delegate signer for a `SmartAccount`. Layout is FINAL
/// for Phase 1B (`_reserved` carved without realloc).
#[account]
pub struct SessionKey {
    pub version: u8,
    pub bump: u8,
    pub account: Pubkey,
    pub pubkey: Pubkey,
    /// 0 = Ed25519.
    pub kind: u8,
    pub expiry_ts: i64,
    pub ops_mask: u16,
    pub generation_at_grant: u64,
    pub caps: [MintCap; MAX_MINT_CAPS],
    pub lifetime_cap: [u64; MAX_MINT_CAPS],
    pub lifetime_spent: [u64; MAX_MINT_CAPS],
    /// spec §5.1: adapter-registry list id (0 = none; 1B defines the registry).
    pub program_allowlist_id: u16,
    pub label: [u8; 16],
    pub _reserved: [u8; 64],
}

impl SessionKey {
    /// No enum fields here (`kind` is a plain tagged u8), so this is an exact
    /// fixed-size sum — see `len_constants_match_serialized_size_and_reserved_zeroed`
    /// in `buckets.rs` for the assertion against a real `try_to_vec`.
    pub const LEN: usize = 8
        + 1 // version
        + 1 // bump
        + 32 // account
        + 32 // pubkey
        + 1 // kind
        + 8 // expiry_ts
        + 2 // ops_mask
        + 8 // generation_at_grant
        + MintCap::LEN * MAX_MINT_CAPS // caps
        + 8 * MAX_MINT_CAPS // lifetime_cap
        + 8 * MAX_MINT_CAPS // lifetime_spent
        + 2 // program_allowlist_id
        + 16 // label
        + 64; // _reserved
}

pub const OP_TRANSFER: u16 = 1 << 0;
pub const OP_EXECUTE: u16 = 1 << 1;
pub const OP_SWAP: u16 = 1 << 2;
pub const OP_SIGN_MESSAGE: u16 = 1 << 3;
