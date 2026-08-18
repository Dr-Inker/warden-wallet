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
