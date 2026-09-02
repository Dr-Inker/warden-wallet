//! The root ceremony transcript: the exact bytes the passkey signs over, and
//! the base64url encoding the browser puts in `clientDataJSON.challenge`.
//!
//! Spec §4:
//! ```text
//! transcript = Keccak256(
//!     "WARDEN/root/v1"
//!   ‖ cluster_tag         (32 B)   <- see the note on `genesis` below
//!   ‖ program_id          (32 B)
//!   ‖ account             (32 B)
//!   ‖ generation          u64 LE
//!   ‖ policy_version      u32 LE
//!   ‖ root_nonce          u64 LE
//!   ‖ expiry_ts           i64 LE
//!   ‖ signed_slot         u64 LE   <- Phase 1B: freshness is slot-based
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
//! **`signed_slot` sits between `expiry_ts` and `action_hash`, and the
//! position is part of the ABI** (spec §4, rev 8), not an implementation
//! detail: Rust, the `packages/core` TypeScript mirror and the IDL must agree
//! on it byte-for-byte or every ceremony either forges or bricks — prior-art
//! finding `LZR-ACC-H2` (write/read layout drift). The golden vectors at the
//! bottom of this file, mirrored verbatim in
//! `packages/core/test/transcript.test.ts`, are what pin it.
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
/// `op_type` byte for `grant_session` (Task 5); hashed over
/// `borsh(GrantBody)` — every `grant_session` argument except `root`.
pub const OP_GRANT_SESSION: u8 = 0x01;
/// `op_type` byte for the root path of session revocation (Task 5); hashed
/// over `borsh(RevokeBody { session_pubkey, refund_to })` — 64 bytes, see
/// `instructions/revoke_session.rs` for why the rent destination is in the
/// signed body (an earlier revision hashed only the bare session pubkey).
/// The session-self path carries no root assertion and therefore no action
/// hash.
pub const OP_REVOKE_SESSION: u8 = 0x02;
/// `op_type` byte for `freeze` (Task 6). Like `rotate_nonce`, it has no
/// arguments of its own beyond `RootArgs`, so it is hashed over an empty
/// borsh payload (`action_hash(OP_FREEZE, &[])`) — the op byte alone still
/// binds the ceremony to exactly this action, which is all "empty body" ever
/// needs.
pub const OP_FREEZE: u8 = 0x03;
/// `op_type` byte for `unfreeze` (Task 6); same empty-payload shape as
/// `OP_FREEZE`.
pub const OP_UNFREEZE: u8 = 0x04;
/// `op_type` byte for the ROOT path of `transfer` (Task 7); hashed over
/// `borsh(TransferBody)` — see `instructions::transfer::TransferBody`, which
/// the handler rebuilds from the accounts actually passed rather than from
/// instruction data, so a substituted destination cannot ride a valid
/// ceremony.
///
/// Deliberately named `OP_TRANSFER_ACTION`, not `OP_TRANSFER`:
/// `state::session::OP_TRANSFER` is the `ops_mask` BIT (1 << 0) a session
/// needs to transfer at all, an unrelated number in an unrelated namespace,
/// and the two are imported side by side in `instructions::transfer`.
pub const OP_TRANSFER_ACTION: u8 = 0x05;

/// `op_type` byte for `create_account`'s proof-of-possession ceremony (Phase
/// 1B Task 2b); hashed over `borsh(CreateBody)` — see
/// `instructions::create_account::CreateBody`, which the handler rebuilds
/// from its own arguments.
///
/// **`CreateBody` carries `salt`, never `owner_seed`.** The seed is *derived*
/// on-chain as `Keccak256("WARDEN/seed/v1" ‖ root_pubkey33 ‖ salt)`, so
/// carrying it in the signed body would be redundant and would let the two
/// drift. The root key itself is likewise absent from the body: it is bound
/// far more strongly than a hash could bind it, because the assertion is
/// verified *against* it (the precompile checks the signature under exactly
/// that key, and the transcript's `account` field is the address that key and
/// salt derive).
///
/// The transcript for this one op is built from the INSTRUCTION ARGUMENTS
/// rather than from stored state — the account does not exist yet — at the
/// fixed values a newborn account has: `generation = 0`, `policy_version = 1`,
/// `root_nonce = 0`. On success the account is written with `root_nonce = 1`,
/// so the creating ceremony is consumed exactly like every other one.
pub const OP_CREATE: u8 = 0x06;

/// `op_type` byte for the ROOT path of `execute` (Phase 1B Task 5); hashed
/// over `borsh(ExecuteBody)` — see `instructions::execute::ExecuteBody`:
/// `payload_hash = Keccak256(payload bytes)` and `accounts_hash =
/// Keccak256(logical list: pubkey ‖ is_signer ‖ is_writable per account)`.
/// Both hashes are rebuilt on-chain from the bytes and accounts actually
/// passed, never read from instruction data, so a bearer assertion cannot
/// substitute the payload or reorder/replace any account after signing
/// (`LZR-ACC-C1`/`LZR-ACC-H1`). The SAME `accounts_hash` construction is
/// what root `swap` (Task 6) binds via `SwapBody`.
///
/// Named `OP_EXECUTE_ACTION` for the same reason as [`OP_TRANSFER_ACTION`]:
/// `state::session::OP_EXECUTE` is the session `ops_mask` BIT (1 << 1), an
/// unrelated number in an unrelated namespace, and the two are imported side
/// by side in `instructions::execute`.
pub const OP_EXECUTE_ACTION: u8 = 0x07;

/// `op_type` byte for the ROOT path of `swap` (Phase 1B Task 6); hashed over
/// `borsh(SwapBody)` — see `instructions::swap::SwapBody`: `in_mint`,
/// `out_mint`, `max_in`, `min_out`, `discriminator` (the 8-byte Jupiter route
/// selector), and `accounts_hash` (the SAME logical-list construction root
/// `execute` binds via `ExecuteBody`). Every field is rebuilt on-chain from the
/// args and accounts actually passed, so a bearer assertion cannot substitute
/// the route, the mints, the bound, or any account after signing.
pub const OP_SWAP_ACTION: u8 = 0x08;

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
// The argument list is the spec's transcript field list, one parameter per
// signed field; bundling them into a struct would only move the same nine
// values behind a name and make the call sites less obviously exhaustive.
#[allow(clippy::too_many_arguments)]
pub fn transcript_hash(
    genesis: &[u8; 32],
    program_id: &Pubkey,
    account: &Pubkey,
    generation: u64,
    policy_version: u32,
    root_nonce: u64,
    expiry_ts: i64,
    signed_slot: u64,
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
        &signed_slot.to_le_bytes(),
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

    /// Byte-for-byte inputs of the pinned vectors below. The TypeScript mirror
    /// (`packages/core/test/transcript.test.ts`) uses these exact values; if
    /// the two ever disagree, one of them has drifted and every root ceremony
    /// breaks.
    ///
    /// `signed_slot` (Phase 1B Task 0) is `314_159_265` — a realistic
    /// mainnet-scale slot number chosen so its little-endian encoding has
    /// several distinct non-zero bytes; `transcript_hash_matches_pinned_max_slot_vector`
    /// pins the all-`0xff` end of the `u64` range as well, so a mirror that
    /// encoded the field big-endian, as a `u32`, or in the wrong position
    /// cannot reproduce all three digests.
    const VECTOR_SIGNED_SLOT: u64 = 314_159_265;

    fn vector_inputs() -> ([u8; 32], Pubkey, Pubkey, u64, u32, u64, i64, u64, [u8; 32]) {
        (
            [0x11u8; 32],
            crate::ID,
            Pubkey::new_from_array([0x22u8; 32]),
            7,
            3,
            42,
            1_760_000_000,
            VECTOR_SIGNED_SLOT,
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
    /// `keccak256("")`, `keccak256("abc")` and `keccak256("testing")` vectors
    /// AND re-checked to reproduce the Phase-1A digests before `signed_slot`
    /// was inserted), not against this function's own output. See
    /// task-0-report.md (Phase 1B).
    ///
    /// **This vector REPLACES the Phase-1A one** (`2c4b76f0…`): inserting
    /// `signed_slot` changes the preimage, so the old digest is not merely
    /// stale, it is wrong, and keeping it would pin a preimage no code
    /// produces.
    #[test]
    fn transcript_hash_matches_pinned_vector() {
        let (g, pid, acct, gen, pv, nonce, exp, slot, ah) = vector_inputs();
        let t = transcript_hash(&g, &pid, &acct, gen, pv, nonce, exp, slot, &ah);
        assert_eq!(
            hex::encode(t),
            "d22ba4187c3788fd7328593cff176b160b82910a6af3cc9e1ba32c1122b9e59b"
        );
        assert_eq!(
            String::from_utf8(b64url_no_pad(&t)).unwrap(),
            "0iukGHw3iP1zKFk8_xdrFguCkQpq88yeG6MsESK55Zs"
        );
    }

    /// Companion vector with a NEGATIVE `expiry_ts`, pinned so the
    /// TypeScript mirror can prove it encodes `i64` as two's-complement
    /// little-endian rather than, say, a sign-magnitude or unsigned
    /// reinterpretation — a bug the positive vector cannot catch, and one
    /// that would only ever surface as an unverifiable ceremony against a
    /// clock-skewed or pre-epoch timestamp. Inputs are `vector_inputs()`
    /// with `expiry_ts = -1` (all bytes 0xff) and nothing else changed.
    ///
    /// Same INDEPENDENT from-spec Keccak-256 provenance as the positive
    /// vector above.
    #[test]
    fn transcript_hash_matches_pinned_negative_expiry_vector() {
        let (g, pid, acct, gen, pv, nonce, _exp, slot, ah) = vector_inputs();
        let t = transcript_hash(&g, &pid, &acct, gen, pv, nonce, -1i64, slot, &ah);
        assert_eq!(
            hex::encode(t),
            "ce70570590fa61713d351480103bd85de57db23843dae12a3328a39060d56a6f"
        );
        assert_eq!(
            String::from_utf8(b64url_no_pad(&t)).unwrap(),
            "znBXBZD6YXE9NRSAEDvYXeV9sjhD2uEqMyijkGDVam8"
        );
    }

    /// Companion vector with `signed_slot = u64::MAX` (all bytes 0xff),
    /// pinned for the same reason the negative-`expiry_ts` vector exists: the
    /// realistic slot number in the positive vector only exercises four
    /// non-zero bytes, so on its own it cannot distinguish a `u64` LE
    /// encoding from a `u32` one that silently truncates the high half.
    ///
    /// Same INDEPENDENT from-spec Keccak-256 provenance.
    #[test]
    fn transcript_hash_matches_pinned_max_slot_vector() {
        let (g, pid, acct, gen, pv, nonce, exp, _slot, ah) = vector_inputs();
        let t = transcript_hash(&g, &pid, &acct, gen, pv, nonce, exp, u64::MAX, &ah);
        assert_eq!(
            hex::encode(t),
            "87822c4c2c26c21ec09a7f4d3cd8b992e897b0899fea27a2ffd1c3234eebdf5c"
        );
        assert_eq!(
            String::from_utf8(b64url_no_pad(&t)).unwrap(),
            "h4IsTCwmwh7Amn9NPNi5kuiXsImf6iei_9HDI07r31w"
        );
    }

    /// Every transcript input must actually change the digest — a field that
    /// is silently dropped from the preimage would be undetectable otherwise.
    #[test]
    fn every_transcript_field_changes_the_hash() {
        let (g, pid, acct, gen, pv, nonce, exp, slot, ah) = vector_inputs();
        let base = transcript_hash(&g, &pid, &acct, gen, pv, nonce, exp, slot, &ah);
        let mut g2 = g;
        g2[0] ^= 1;
        let mut ah2 = ah;
        ah2[31] ^= 1;
        let variants = [
            transcript_hash(&g2, &pid, &acct, gen, pv, nonce, exp, slot, &ah),
            transcript_hash(&g, &Pubkey::new_from_array([0x99u8; 32]), &acct, gen, pv, nonce, exp, slot, &ah),
            transcript_hash(&g, &pid, &Pubkey::new_from_array([0x99u8; 32]), gen, pv, nonce, exp, slot, &ah),
            transcript_hash(&g, &pid, &acct, gen.wrapping_add(1), pv, nonce, exp, slot, &ah),
            transcript_hash(&g, &pid, &acct, gen, pv.wrapping_add(1), nonce, exp, slot, &ah),
            transcript_hash(&g, &pid, &acct, gen, pv, nonce.wrapping_add(1), exp, slot, &ah),
            transcript_hash(&g, &pid, &acct, gen, pv, nonce, exp.wrapping_add(1), slot, &ah),
            transcript_hash(&g, &pid, &acct, gen, pv, nonce, exp, slot.wrapping_add(1), &ah),
            transcript_hash(&g, &pid, &acct, gen, pv, nonce, exp, slot, &ah2),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(base, *v, "transcript field {i} does not affect the digest");
        }
    }

    /// `signed_slot` and `expiry_ts` are adjacent fixed-width integers, so a
    /// mirror that emitted them in the WRONG ORDER would still produce a
    /// preimage of the right length. This pins the ordering directly: swapping
    /// the two values must change the digest.
    ///
    /// The two chosen values are both representable in `i64` and `u64`, so the
    /// swap is a pure ordering change, not a range artefact.
    #[test]
    fn signed_slot_and_expiry_ts_are_not_interchangeable() {
        let (g, pid, acct, gen, pv, nonce, _exp, _slot, ah) = vector_inputs();
        let a = transcript_hash(&g, &pid, &acct, gen, pv, nonce, 1_000, 2_000, &ah);
        let b = transcript_hash(&g, &pid, &acct, gen, pv, nonce, 2_000, 1_000, &ah);
        assert_ne!(a, b, "expiry_ts and signed_slot must not be order-interchangeable");
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
