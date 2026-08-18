//! The root ceremony transcript: the exact bytes the passkey signs over, and
//! the base64url encoding the browser puts in `clientDataJSON.challenge`.
//!
//! Spec §4:
//! ```text
//! transcript = Keccak256(
//!     "WARDEN/root/v1"
//!   ‖ genesis_hash        (32 B)   <- see the note on `genesis` below
//!   ‖ program_id          (32 B)
//!   ‖ account             (32 B)
//!   ‖ generation          u64 LE
//!   ‖ policy_version      u32 LE
//!   ‖ root_nonce          u64 LE
//!   ‖ expiry_ts           i64 LE
//!   ‖ action_hash         (32 B)
//! )
//! action_hash = Keccak256(op_type:u8 ‖ borsh(op_args))
//! challenge   = base64url_nopad(transcript)
//! ```
//!
//! Every field is fixed-width, so the concatenation is unambiguous without
//! length prefixes; `action_hash` is itself a hash of a borsh encoding, which
//! is canonical for a fixed argument type.
//!
//! No `blockhash` is included, deliberately: a program cannot authenticate the
//! outer message's blockhash, so binding one would be security theatre. Replay
//! is prevented by `root_nonce` (consumed on every successful root
//! instruction) plus the `expiry_ts` window.

use anchor_lang::prelude::*;

/// Domain separator. Bumping the `/v1` suffix invalidates every outstanding
/// assertion, which is the intended migration mechanism.
pub const TRANSCRIPT_DOMAIN: &[u8] = b"WARDEN/root/v1";

/// `op_type` byte for `rotate_nonce` (Task 3). Task 4+ append further ops;
/// the byte is part of the signed transcript, so values are permanent.
pub const OP_ROTATE_NONCE: u8 = 0x00;

/// Keccak256 over the canonical transcript encoding.
///
/// `genesis` is `SmartAccount.cluster_tag`. **It is a client-attested domain
/// separator, not a verified genesis binding**: a Solana program cannot read
/// the cluster's genesis hash, so the value is whatever the extension wrote at
/// `create_account` (by convention `getGenesisHash()`). What it *does*
/// guarantee is that an assertion produced against one stored tag cannot be
/// replayed against an account holding a different tag. What it does *not*
/// guarantee is that the tag names the cluster the transaction lands on. Spec
/// §4 wording is corrected in Task 9.
pub fn transcript_hash(
    genesis: &[u8; 32],
    program_id: &Pubkey,
    account: &Pubkey,
    generation: u64,
    policy_version: u32,
    root_nonce: u64,
    expiry_ts: i64,
    action_hash: &[u8; 32],
) -> [u8; 32] {
    solana_keccak_hasher::hashv(&[
        TRANSCRIPT_DOMAIN,
        genesis,
        program_id.as_ref(),
        account.as_ref(),
        &generation.to_le_bytes(),
        &policy_version.to_le_bytes(),
        &root_nonce.to_le_bytes(),
        &expiry_ts.to_le_bytes(),
        action_hash,
    ])
    .to_bytes()
}

/// Keccak256(`op_type` ‖ `borsh_args`). The caller re-serializes the
/// *executing* instruction's arguments, so no argument can be swapped between
/// the passkey ceremony and submission.
pub fn action_hash(op_type: u8, borsh_args: &[u8]) -> [u8; 32] {
    solana_keccak_hasher::hashv(&[&[op_type], borsh_args]).to_bytes()
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// RFC 4648 §5 base64url **without** padding — the encoding WebAuthn uses for
/// `clientDataJSON.challenge`. Hand-rolled rather than pulled from a crate so
/// the SBF binary carries no extra dependency and the byte-exact behaviour is
/// pinned by the vectors below.
pub fn b64url_no_pad(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(4).saturating_div(3).saturating_add(3));
    let mut chunks = bytes.chunks_exact(3);
    for c in &mut chunks {
        let n = u32::from(c[0]).wrapping_shl(16) | u32::from(c[1]).wrapping_shl(8) | u32::from(c[2]);
        out.push(B64URL[(n.wrapping_shr(18) & 0x3f) as usize]);
        out.push(B64URL[(n.wrapping_shr(12) & 0x3f) as usize]);
        out.push(B64URL[(n.wrapping_shr(6) & 0x3f) as usize]);
        out.push(B64URL[(n & 0x3f) as usize]);
    }
    match chunks.remainder() {
        [a] => {
            let n = u32::from(*a).wrapping_shl(16);
            out.push(B64URL[(n.wrapping_shr(18) & 0x3f) as usize]);
            out.push(B64URL[(n.wrapping_shr(12) & 0x3f) as usize]);
        }
        [a, b] => {
            let n = u32::from(*a).wrapping_shl(16) | u32::from(*b).wrapping_shl(8);
            out.push(B64URL[(n.wrapping_shr(18) & 0x3f) as usize]);
            out.push(B64URL[(n.wrapping_shr(12) & 0x3f) as usize]);
            out.push(B64URL[(n.wrapping_shr(6) & 0x3f) as usize]);
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-for-byte inputs of the pinned vector below. Task 7 mirrors this
    /// exact vector in TypeScript; if the two ever disagree, one of them has
    /// drifted and every root ceremony breaks.
    fn vector_inputs() -> ([u8; 32], Pubkey, Pubkey, u64, u32, u64, i64, [u8; 32]) {
        (
            [0x11u8; 32],
            crate::ID,
            Pubkey::new_from_array([0x22u8; 32]),
            7,
            3,
            42,
            1_760_000_000,
            [0x33u8; 32],
        )
    }

    /// The program id is half the vector's input, so pin its raw bytes too —
    /// otherwise a future `declare_id!` change would silently invalidate the
    /// pinned digest instead of failing here.
    #[test]
    fn program_id_bytes_are_pinned() {
        assert_eq!(
            hex::encode(crate::ID.to_bytes()),
            "017b5f72e2c074fa8555206db7ccf465c1db513c725913ca7ce685f135f8bd51"
        );
    }

    /// Pinned against an INDEPENDENT Keccak-256 implementation (a from-spec
    /// pure-Python Keccak-f[1600], self-tested against the published
    /// `keccak256("")` and `keccak256("abc")` vectors), not against this
    /// function's own output. See task-3-report.md.
    #[test]
    fn transcript_hash_matches_pinned_vector() {
        let (g, pid, acct, gen, pv, nonce, exp, ah) = vector_inputs();
        let t = transcript_hash(&g, &pid, &acct, gen, pv, nonce, exp, &ah);
        assert_eq!(
            hex::encode(t),
            "2c4b76f055b282523ccbad5287ffdd1516ca9faba4f0f626a3ca7b243a5276ce"
        );
        assert_eq!(
            String::from_utf8(b64url_no_pad(&t)).unwrap(),
            "LEt28FWyglI8y61Sh__dFRbKn6uk8PYmo8p7JDpSds4"
        );
    }

    /// Every transcript input must actually change the digest — a field that
    /// is silently dropped from the preimage would be undetectable otherwise.
    #[test]
    fn every_transcript_field_changes_the_hash() {
        let (g, pid, acct, gen, pv, nonce, exp, ah) = vector_inputs();
        let base = transcript_hash(&g, &pid, &acct, gen, pv, nonce, exp, &ah);
        let mut g2 = g;
        g2[0] ^= 1;
        let mut ah2 = ah;
        ah2[31] ^= 1;
        let variants = [
            transcript_hash(&g2, &pid, &acct, gen, pv, nonce, exp, &ah),
            transcript_hash(&g, &Pubkey::new_from_array([0x99u8; 32]), &acct, gen, pv, nonce, exp, &ah),
            transcript_hash(&g, &pid, &Pubkey::new_from_array([0x99u8; 32]), gen, pv, nonce, exp, &ah),
            transcript_hash(&g, &pid, &acct, gen.wrapping_add(1), pv, nonce, exp, &ah),
            transcript_hash(&g, &pid, &acct, gen, pv.wrapping_add(1), nonce, exp, &ah),
            transcript_hash(&g, &pid, &acct, gen, pv, nonce.wrapping_add(1), exp, &ah),
            transcript_hash(&g, &pid, &acct, gen, pv, nonce, exp.wrapping_add(1), &ah),
            transcript_hash(&g, &pid, &acct, gen, pv, nonce, exp, &ah2),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(base, *v, "transcript field {i} does not affect the digest");
        }
    }

    #[test]
    fn action_hash_matches_pinned_vectors() {
        assert_eq!(
            hex::encode(action_hash(5, b"hello")),
            "2beb245583b000d9052c7c9e84130b33accc05ab47ac43180743e302047ea29b"
        );
        assert_eq!(
            hex::encode(action_hash(OP_ROTATE_NONCE, &[])),
            "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a"
        );
    }

    /// `op_type` must not be absorbable into the argument bytes: hashing
    /// `(1, [2])` and `(1, [])`-with-a-different-op must differ.
    #[test]
    fn action_hash_separates_op_type_from_args() {
        assert_ne!(action_hash(1, &[2]), action_hash(2, &[1]));
        assert_ne!(action_hash(0, &[]), action_hash(1, &[]));
    }

    /// RFC 4648 §10 test vectors, minus padding, plus a value exercising both
    /// URL-safe alphabet substitutions (`-` for `+`, `_` for `/`).
    #[test]
    fn b64url_no_pad_matches_rfc4648_vectors() {
        let cases: [(&[u8], &str); 8] = [
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
            (&[0xfb, 0xff, 0xbe], "-_--"),
        ];
        for (input, want) in cases {
            assert_eq!(String::from_utf8(b64url_no_pad(input)).unwrap(), want, "input {input:?}");
        }
    }

    /// A 32-byte digest always encodes to exactly 43 unpadded characters.
    #[test]
    fn b64url_no_pad_of_32_bytes_is_43_chars_and_never_padded() {
        for b in [0u8, 1, 0x7f, 0xff] {
            let e = b64url_no_pad(&[b; 32]);
            assert_eq!(e.len(), 43);
            assert!(!e.contains(&b'='));
        }
    }
}
