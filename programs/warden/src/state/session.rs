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

/// Every `ops_mask` bit this program has ASSIGNED A MEANING TO.
///
/// Milestone-review finding (Important): an `ops_mask` — or a
/// `policy.session_ops_ceiling` — carrying a bit outside this set is rejected
/// at `create_account` and at `grant_session`, because an unassigned bit is a
/// **forward-activation hazard**: a session (or ceiling) that stores `1 << 7`
/// today silently gains whatever operation a later program version assigns to
/// `1 << 7`, without a second root ceremony ever taking place. This is the
/// same hazard `program_allowlist_id != 0` is already refused for
/// (`ProgramAllowlistUnsupported`). Any version that assigns a new bit must
/// widen this constant AND decide, deliberately, what happens to accounts
/// created before it (the intended answer being: nothing — the bit could not
/// have been stored).
pub const OPS_MASK_KNOWN: u16 = OP_TRANSFER | OP_EXECUTE | OP_SWAP | OP_SIGN_MESSAGE;

/// Domain separator for [`SessionKey::authority_hash`]. Distinct from the root
/// transcript domain so the two digests can never be confused for one another.
pub const SESSION_AUTHORITY_DOMAIN: &[u8] = b"WARDEN/session-authority/v1";

impl SessionKey {
    /// Keccak-256 over the session's **retained authority** — the state a
    /// re-grant does NOT replace, and which therefore survives a ceremony
    /// without appearing in the signed `GrantBody`.
    ///
    /// Milestone-review finding (Important): `grant_session` merges by mint,
    /// so a one-mint re-grant leaves every previously granted mint's cap in
    /// place while refreshing `generation_at_grant`. Without this hash, the
    /// passkey would be signing a document that does not describe the
    /// authority the instruction actually produces — and after a 1B
    /// generation bump (key rotation / recovery), a minimal re-grant could
    /// silently revive every capability a compromised session used to hold.
    /// `GrantBody.prior_authority_hash` binds the pre-state, and the merge is
    /// a pure function of (pre-state, body), so binding both binds the result.
    ///
    /// **Covered:** identity (`account`, `pubkey`) and, for all
    /// `MAX_MINT_CAPS` slots in index order, `caps[i]` (mint + all three
    /// `per_*` fields) and `lifetime_cap[i]`.
    ///
    /// **Deliberately NOT covered:**
    /// - `expiry_ts`, `ops_mask`, `kind`, `program_allowlist_id`, `label` —
    ///   every one of them is REPLACED outright from the signed body, so they
    ///   are already bound by `action_hash` and their pre-value grants
    ///   nothing.
    /// - `generation_at_grant` — likewise overwritten by this instruction.
    /// - `lifetime_spent` — usage, not authority. Retained headroom is
    ///   `lifetime_cap - lifetime_spent`, which only ever SHRINKS as the
    ///   session spends, so omitting it can only make the signer's picture of
    ///   retained authority *conservative*. Including it would make a
    ///   prepared ceremony race every concurrent transfer the session makes.
    /// - `version`, `bump`, `_reserved` — not authority.
    pub fn authority_hash(&self) -> [u8; 32] {
        // Fixed-width, so the concatenation is unambiguous without length
        // prefixes (the same argument the root transcript rests on).
        let mut buf = Vec::with_capacity(32 * MAX_MINT_CAPS + 8 * MAX_MINT_CAPS + 64);
        buf.extend_from_slice(self.account.as_ref());
        buf.extend_from_slice(self.pubkey.as_ref());
        for i in 0..MAX_MINT_CAPS {
            let c = self.caps[i];
            buf.extend_from_slice(c.mint.as_ref());
            buf.extend_from_slice(&c.per_tx.to_le_bytes());
            buf.extend_from_slice(&c.per_day.to_le_bytes());
            buf.extend_from_slice(&c.per_30d.to_le_bytes());
            buf.extend_from_slice(&self.lifetime_cap[i].to_le_bytes());
        }
        solana_keccak_hasher::hashv(&[SESSION_AUTHORITY_DOMAIN, &buf]).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> SessionKey {
        SessionKey {
            version: 1,
            bump: 255,
            account: Pubkey::new_from_array([1u8; 32]),
            pubkey: Pubkey::new_from_array([2u8; 32]),
            kind: 0,
            expiry_ts: 1_000,
            ops_mask: OP_TRANSFER,
            generation_at_grant: 4,
            caps: [MintCap { mint: Pubkey::new_from_array([3u8; 32]), per_tx: 5, per_day: 0, per_30d: 0 };
                MAX_MINT_CAPS],
            lifetime_cap: [50; MAX_MINT_CAPS],
            lifetime_spent: [7; MAX_MINT_CAPS],
            program_allowlist_id: 0,
            label: [0; 16],
            _reserved: [0; 64],
        }
    }

    #[test]
    fn ops_mask_known_is_exactly_the_four_assigned_bits() {
        assert_eq!(OPS_MASK_KNOWN, 0b1111);
    }

    #[test]
    fn client_intent_decoder_offsets_match_borsh_serialization() {
        // SessionKey is Borsh, not zero-copy: pin serialized BODY offsets. The
        // browser account decoder adds Anchor's 8-byte discriminator to each.
        assert_eq!(
            SessionKey::DISCRIMINATOR,
            [93, 186, 163, 139, 160, 255, 81, 112]
        );
        let value = session();
        let mut bytes = Vec::new();
        value.serialize(&mut bytes).unwrap();
        assert_eq!(bytes.len(), SessionKey::LEN - 8);
        assert_eq!(bytes[0], 1); // absolute 8: version
        assert_eq!(bytes[1], 255); // absolute 9: bump
        assert_eq!(&bytes[2..34], &[1u8; 32]); // absolute 10: account
        assert_eq!(&bytes[34..66], &[2u8; 32]); // absolute 42: signer
        assert_eq!(bytes[66], 0); // absolute 74: kind
        assert_eq!(&bytes[67..75], &1_000i64.to_le_bytes()); // absolute 75: expiry
        assert_eq!(&bytes[75..77], &OP_TRANSFER.to_le_bytes()); // absolute 83: ops
        assert_eq!(&bytes[77..85], &4u64.to_le_bytes()); // absolute 85: generation
        assert_eq!(&bytes[661..663], &0u16.to_le_bytes()); // absolute 669: allowlist
        assert_eq!(&bytes[663..679], &[0u8; 16]); // absolute 671: label
        assert_eq!(&bytes[679..743], &[0u8; 64]); // absolute 687: reserved
    }

    /// Every field the hash claims to cover must actually change it —
    /// otherwise a re-grant could retain authority the signer never saw.
    #[test]
    fn authority_hash_covers_identity_caps_and_lifetime_caps() {
        let base = session().authority_hash();
        let mut a = session();
        a.account = Pubkey::new_from_array([9u8; 32]);
        let mut b = session();
        b.pubkey = Pubkey::new_from_array([9u8; 32]);
        let mut c = session();
        c.caps[7].mint = Pubkey::new_from_array([9u8; 32]);
        let mut d = session();
        d.caps[3].per_tx += 1;
        let mut e = session();
        e.caps[3].per_day += 1;
        let mut f = session();
        f.caps[3].per_30d += 1;
        let mut g = session();
        g.lifetime_cap[5] += 1;
        for (i, v) in [a, b, c, d, e, f, g].iter().enumerate() {
            assert_ne!(base, v.authority_hash(), "covered field {i} does not affect the digest");
        }
    }

    /// The fields a re-grant replaces outright (already bound by
    /// `action_hash`) and the session's spend history must NOT change it —
    /// binding them would only make a prepared ceremony race the session.
    #[test]
    fn authority_hash_ignores_replaced_fields_and_spend_history() {
        let base = session().authority_hash();
        let mut a = session();
        a.expiry_ts += 1;
        let mut b = session();
        b.ops_mask = OP_SWAP;
        let mut c = session();
        c.generation_at_grant += 1;
        let mut d = session();
        d.lifetime_spent[0] += 1;
        let mut e = session();
        e.label[0] = 1;
        let mut f = session();
        f.program_allowlist_id = 3;
        let mut g = session();
        g.kind = 1;
        for (i, v) in [a, b, c, d, e, f, g].iter().enumerate() {
            assert_eq!(base, v.authority_hash(), "ignored field {i} must not affect the digest");
        }
    }

    /// A slot's contents must be bound to its INDEX: swapping two slots is a
    /// different authority layout and must not hash the same.
    #[test]
    fn authority_hash_is_position_sensitive() {
        let mut a = session();
        a.caps[0].per_tx = 1;
        a.caps[1].per_tx = 2;
        let mut b = session();
        b.caps[0].per_tx = 2;
        b.caps[1].per_tx = 1;
        assert_ne!(a.authority_hash(), b.authority_hash());
    }
}
