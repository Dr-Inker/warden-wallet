//! A deterministic stand-in for a real WebAuthn platform authenticator.
//!
//! It produces exactly the four artefacts a browser assertion yields —
//! `authenticatorData`, `clientDataJSON`, a low-S P-256 signature, and the
//! signed message `authenticatorData ‖ SHA-256(clientDataJSON)` — plus the
//! matching secp256r1 precompile instruction.
//!
//! Keys are derived from a fixed seed rather than an RNG so every failure is
//! reproducible and the pinned transcript vectors stay stable.
//!
//! **Low-S is applied here on purpose.** The precompile rejects high-S
//! signatures outright (`PrecompileError::InvalidSignature`), and Chrome
//! emitted a high-S signature on the very first real sample in spike 2b, so
//! normalisation is the extension's job in production — the program neither
//! can nor should repair it. Mirroring that here keeps the tests honest about
//! where the responsibility lives.

#![allow(dead_code)]

use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use sha2::{Digest, Sha256};
use solana_sdk::instruction::Instruction;

/// The dev-loaded extension origin measured in spike 2b. `rp_id_hash` is
/// SHA-256 of this FULL string, not of the bare extension id.
pub const TEST_ORIGIN: &str = "chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi";

/// User Present | User Verified — what v1 requires of a root assertion.
pub const FLAGS_UP_UV: u8 = 0x05;

pub fn rp_id_hash(origin: &str) -> [u8; 32] {
    Sha256::digest(origin.as_bytes()).into()
}

pub struct Assertion {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature64_low_s: [u8; 64],
    /// `authenticator_data ‖ SHA-256(client_data_json)` — the precompile's message.
    pub message: Vec<u8>,
}

pub struct TestPasskey {
    sk: SigningKey,
}

impl TestPasskey {
    /// Deterministic key from a one-byte seed. The scalar is `[seed; 32]`,
    /// which is a valid, non-zero P-256 private key for every seed in 1..=254.
    pub fn new(seed: u8) -> Self {
        assert!(seed != 0, "scalar must be non-zero");
        let sk = SigningKey::from_bytes(&[seed; 32].into()).expect("valid P-256 scalar");
        Self { sk }
    }

    /// Compressed SEC1 point — exactly what `SmartAccount.root_pubkey` stores
    /// and what the precompile expects.
    pub fn pubkey33(&self) -> [u8; 33] {
        let p = self.sk.verifying_key().to_encoded_point(true);
        p.as_bytes().try_into().expect("compressed SEC1 point is 33 bytes")
    }

    /// RFC 6979 deterministic ECDSA, normalised to low-S.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sig: Signature = self.sk.sign(message);
        let sig = sig.normalize_s().unwrap_or(sig);
        sig.to_bytes().into()
    }

    /// The canonical Chrome-shaped `clientDataJSON` for a challenge.
    pub fn assert_(
        &self,
        challenge_b64url: &[u8],
        origin: &str,
        rp_id_hash: [u8; 32],
        flags: u8,
    ) -> Assertion {
        let cdj = client_data_json(challenge_b64url, origin);
        self.assert_with_client_data(cdj, rp_id_hash, flags)
    }

    /// Sign an arbitrary `clientDataJSON` — how the adversarial tests produce
    /// a *genuinely signed* nested/duplicate/oversized document instead of
    /// merely asserting about one.
    pub fn assert_with_client_data(
        &self,
        client_data_json: Vec<u8>,
        rp_id_hash: [u8; 32],
        flags: u8,
    ) -> Assertion {
        let authenticator_data = authenticator_data(rp_id_hash, flags);
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&Sha256::digest(&client_data_json));
        let signature64_low_s = self.sign(&message);
        Assertion {
            authenticator_data,
            client_data_json,
            signature64_low_s,
            message,
        }
    }
}

/// The P-256 group order `n` (SEC 2 §2.4.2), big-endian.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// `floor(n / 2)`, big-endian — the secp256r1 precompile's accept/reject
/// boundary: a signature is "low-S" iff `s <= n/2`.
const P256_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// Whether `sig64`'s `s` component is in the high half (`s > n/2`), i.e. the
/// form the precompile rejects. Exact big-endian comparison against
/// `floor(n/2)` rather than a "top bit set" shortcut, so the boundary case is
/// classified correctly.
pub fn is_high_s(sig64: &[u8; 64]) -> bool {
    for i in 0..32 {
        let (a, b) = (sig64[32 + i], P256_HALF_ORDER[i]);
        if a != b {
            return a > b;
        }
    }
    false // s == n/2 exactly is still low-S
}

/// `(r, s)` → `(r, n - s)`: the **high-S** (malleated) form of the same
/// signature.
///
/// It is still a mathematically valid ECDSA signature over the same message
/// and key — that is exactly the point. The secp256r1 precompile rejects it
/// anyway (`PrecompileError::InvalidSignature`), which is why low-S
/// normalization is the extension's job in production (spec §4) and why
/// `sigverify_wiring::high_s_signature_rejected_by_precompile` is part of the
/// L0 gate: a substrate that accepted this one would not be doing the
/// precompile's checks.
///
/// The subtraction is done by hand on big-endian bytes rather than through the
/// `p256` crate's scalar arithmetic, so this helper depends on no API beyond
/// the byte encoding the precompile itself consumes.
pub fn to_high_s(sig64: &[u8; 64]) -> [u8; 64] {
    let mut s_be = [0u8; 32];
    s_be.copy_from_slice(&sig64[32..]);
    // n - s, 256-bit borrow subtraction. `0 < s < n`, so the result never
    // borrows out of the top byte.
    let mut neg = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let d = i16::from(P256_ORDER[i]) - i16::from(s_be[i]) - borrow;
        if d < 0 {
            neg[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            neg[i] = d as u8;
            borrow = 0;
        }
    }
    assert_eq!(borrow, 0, "s must be < n");
    let mut out = *sig64;
    out[32..].copy_from_slice(&neg);
    assert_ne!(out, *sig64, "nothing was malleated");
    // Negation must flip which half of the scalar range `s` lives in —
    // otherwise this helper did not produce the malleated form at all. Stated
    // as a flip rather than "the output is high-S" because the function is its
    // own inverse and the tests apply it twice.
    assert_ne!(
        is_high_s(&out),
        is_high_s(sig64),
        "n - s must land in the opposite half of the scalar range"
    );
    out
}

/// `rpIdHash(32) ‖ flags(1) ‖ signCount(4 BE)`.
pub fn authenticator_data(rp_id_hash: [u8; 32], flags: u8) -> Vec<u8> {
    let mut v = rp_id_hash.to_vec();
    v.push(flags);
    v.extend_from_slice(&0u32.to_be_bytes());
    v
}

pub fn client_data_json(challenge_b64url: &[u8], origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        std::str::from_utf8(challenge_b64url).unwrap(),
        origin
    )
    .into_bytes()
}

/// The honest precompile instruction, built by the official crate.
pub fn precompile_ix(a: &Assertion, pubkey33: &[u8; 33]) -> Instruction {
    solana_secp256r1_program::new_secp256r1_instruction_with_signature(
        &a.message,
        &a.signature64_low_s,
        pubkey33,
    )
}

/// Hand-built precompile instruction so negative tests can bend the fields the
/// official builder hard-codes. `hand_built_precompile_ix_matches_crate`
/// pins this against the crate's output for the honest case.
///
/// Layout: `[num_signatures u8][padding u8][14-byte offsets] * n` then
/// `pubkey(33) ‖ signature(64) ‖ message(n)`.
pub fn precompile_ix_custom(
    pubkey33: &[u8; 33],
    signature: &[u8; 64],
    message: &[u8],
    num_signatures: u8,
    entry_instruction_index: u16,
) -> Instruction {
    let offsets_start = 2usize;
    let data_start = offsets_start + 14 * num_signatures as usize;
    let pk_off = data_start;
    let sig_off = pk_off + 33;
    let msg_off = sig_off + 64;
    let mut d = vec![num_signatures, 0u8];
    for _ in 0..num_signatures {
        d.extend_from_slice(&(sig_off as u16).to_le_bytes());
        d.extend_from_slice(&entry_instruction_index.to_le_bytes());
        d.extend_from_slice(&(pk_off as u16).to_le_bytes());
        d.extend_from_slice(&entry_instruction_index.to_le_bytes());
        d.extend_from_slice(&(msg_off as u16).to_le_bytes());
        d.extend_from_slice(&(message.len() as u16).to_le_bytes());
        d.extend_from_slice(&entry_instruction_index.to_le_bytes());
    }
    d.extend_from_slice(pubkey33);
    d.extend_from_slice(signature);
    d.extend_from_slice(message);
    Instruction {
        program_id: solana_secp256r1_program::ID,
        accounts: vec![],
        data: d,
    }
}
