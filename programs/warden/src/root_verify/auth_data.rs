//! WebAuthn `authenticatorData` checks (spec §4).
//!
//! Layout (WebAuthn L2 §6.1): `rpIdHash(32) ‖ flags(1) ‖ signCount(4 BE)` and
//! then optional attested-credential/extension data. Only the fixed 37-byte
//! head is interpreted; trailing extension bytes are permitted (they are
//! covered by the signature via the precompile message binding, so they cannot
//! be altered) but never parsed.
//!
//! `rpIdHash` is **SHA-256 of the full extension origin string**, not of the
//! bare extension id (measured, spike 2b — see `docs/spikes/DECISION.md`). It
//! is read from `SmartAccount.rp_id_hash`, which `create_account` sets from
//! the account's own stored origin — never from a compiled-in literal and
//! never from caller-supplied instruction data.
//!
//! The sign counter is deliberately ignored: synced (multi-device) passkeys
//! report 0 or a non-monotonic value, so enforcing it would lock users out.

use anchor_lang::prelude::*;

use crate::errors::WardenError;

/// Minimum `authenticatorData`: rpIdHash(32) + flags(1) + signCount(4).
pub const AUTH_DATA_MIN_LEN: usize = 37;

/// User Present.
pub const FLAG_UP: u8 = 0x01;
/// User Verified.
pub const FLAG_UV: u8 = 0x04;
/// v1 requires both for the root key (decision O10: UV is mandatory for root).
pub const FLAGS_REQUIRED: u8 = FLAG_UP | FLAG_UV;

pub fn check_auth_data(auth: &[u8], expected_rp_id_hash: &[u8; 32]) -> Result<()> {
    let head = auth.get(..AUTH_DATA_MIN_LEN).ok_or(WardenError::AuthDataTooShort)?;
    let rp = head.get(..32).ok_or(WardenError::AuthDataTooShort)?;
    require!(rp == expected_rp_id_hash.as_slice(), WardenError::RpIdHashMismatch);
    let flags = *head.get(32).ok_or(WardenError::AuthDataTooShort)?;
    require!(
        flags & FLAGS_REQUIRED == FLAGS_REQUIRED,
        WardenError::UserVerificationRequired
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RP: [u8; 32] = [0xAB; 32];

    fn auth(flags: u8, extra: usize) -> Vec<u8> {
        let mut v = RP.to_vec();
        v.push(flags);
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend(std::iter::repeat(0x5Au8).take(extra));
        v
    }

    fn code(e: anchor_lang::error::Error) -> anchor_lang::error::Error {
        e
    }

    #[test]
    fn accepts_up_and_uv() {
        check_auth_data(&auth(FLAGS_REQUIRED, 0), &RP).unwrap();
    }

    /// Backup-eligible / backup-state / attested-credential bits are set by
    /// real authenticators and must not matter.
    #[test]
    fn accepts_extra_flag_bits_and_trailing_extension_bytes() {
        check_auth_data(&auth(0xFF, 64), &RP).unwrap();
    }

    #[test]
    fn rejects_up_only() {
        assert_eq!(
            check_auth_data(&auth(FLAG_UP, 0), &RP).unwrap_err(),
            code(WardenError::UserVerificationRequired.into())
        );
    }

    #[test]
    fn rejects_uv_only() {
        assert_eq!(
            check_auth_data(&auth(FLAG_UV, 0), &RP).unwrap_err(),
            code(WardenError::UserVerificationRequired.into())
        );
    }

    #[test]
    fn rejects_no_flags() {
        assert_eq!(
            check_auth_data(&auth(0x00, 0), &RP).unwrap_err(),
            code(WardenError::UserVerificationRequired.into())
        );
    }

    #[test]
    fn rejects_rp_id_hash_mismatch() {
        let mut other = RP;
        other[0] ^= 0x01;
        assert_eq!(
            check_auth_data(&auth(FLAGS_REQUIRED, 0), &other).unwrap_err(),
            code(WardenError::RpIdHashMismatch.into())
        );
    }

    #[test]
    fn rejects_short_auth_data() {
        for n in 0..AUTH_DATA_MIN_LEN {
            let a = auth(FLAGS_REQUIRED, 0);
            assert_eq!(
                check_auth_data(&a[..n], &RP).unwrap_err(),
                code(WardenError::AuthDataTooShort.into()),
                "len {n} must be rejected"
            );
        }
    }
}
