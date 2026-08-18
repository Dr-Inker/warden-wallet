//! Spike 2b: prove that a native Solana program can bind a *real* WebAuthn
//! assertion to a secp256r1 precompile instruction in the same transaction.
//!
//! The program itself never verifies the ECDSA signature — the
//! `Secp256r1SigVerify1111111111111111111111111` precompile does that as part of
//! transaction processing. What this program does is the part the precompile
//! cannot do: prove that the *thing the precompile verified* is the WebAuthn
//! assertion we care about, i.e. that
//!   * the signing key is the expected root passkey (33-byte compressed P-256),
//!   * the signed message is `authenticatorData || SHA256(clientDataJSON)`,
//!   * `authenticatorData` carries the expected rpIdHash and UP+UV flags,
//!   * `clientDataJSON` says `webauthn.get`, over our challenge, from our origin.
//!
//! Pattern intended to be reused by Phase 1's `root_verify` module.
use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::instructions::{load_instruction_at_checked, ID as IX_SYSVAR},
};

pub const SECP256R1_ID: Pubkey = solana_program::pubkey!("Secp256r1SigVerify1111111111111111111111111");

/// WebAuthn authenticator-data flags: User Present (0x01) | User Verified (0x04).
const FLAG_UP_UV: u8 = 0x05;

entrypoint!(process);

/// Instruction data layout (all little-endian):
/// `expected_pubkey(33) || rp_id_hash(32) || expected_origin_len(u16) || expected_origin`
/// `|| challenge_b64url_len(u16) || challenge_b64url || precompile_ix_index(u8)`
/// `|| authenticator_data_len(u16) || authenticator_data || client_data_json`
pub fn process(_pid: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let sysvar = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    if *sysvar.key != IX_SYSVAR {
        return Err(ProgramError::InvalidArgument);
    }

    let mut o = 0usize;
    let take = |o: &mut usize, n: usize| -> Result<&[u8], ProgramError> {
        let s = data
            .get(*o..o.checked_add(n).ok_or(ProgramError::InvalidInstructionData)?)
            .ok_or(ProgramError::InvalidInstructionData)?;
        *o += n;
        Ok(s)
    };
    let take_u16 = |o: &mut usize, d: &[u8]| -> Result<usize, ProgramError> {
        let s = d
            .get(*o..o.checked_add(2).ok_or(ProgramError::InvalidInstructionData)?)
            .ok_or(ProgramError::InvalidInstructionData)?;
        *o += 2;
        Ok(u16::from_le_bytes([s[0], s[1]]) as usize)
    };

    let pk = take(&mut o, 33)?;
    let rp = take(&mut o, 32)?;
    let ol = take_u16(&mut o, data)?;
    let origin = take(&mut o, ol)?;
    let cl = take_u16(&mut o, data)?;
    let chal = take(&mut o, cl)?;
    let ix_index = take(&mut o, 1)?[0];
    let al = take_u16(&mut o, data)?;
    let auth = take(&mut o, al)?;
    let cdj = data.get(o..).ok_or(ProgramError::InvalidInstructionData)?;

    // 1) authenticatorData checks: rpIdHash, flags UP (0x01) and UV (0x04).
    if auth.len() < 37 {
        msg!("authenticatorData too short");
        return Err(ProgramError::InvalidInstructionData);
    }
    if &auth[..32] != rp {
        msg!("rpIdHash mismatch");
        return Err(ProgramError::InvalidArgument);
    }
    if auth[32] & FLAG_UP_UV != FLAG_UP_UV {
        msg!("UP/UV not set");
        return Err(ProgramError::InvalidArgument);
    }

    // 2) clientDataJSON checks by byte-substring (no JSON parser on-chain).
    //    NOT PRODUCTION-SAFE — see `client_data_check` and result.md.
    match client_data_check(cdj, chal, origin) {
        ClientDataCheck::Ok => {}
        ClientDataCheck::TypeMismatch => {
            msg!("type mismatch");
            return Err(ProgramError::InvalidArgument);
        }
        ClientDataCheck::ChallengeMismatch => {
            msg!("challenge mismatch");
            return Err(ProgramError::InvalidArgument);
        }
        ClientDataCheck::OriginMismatch => {
            msg!("origin mismatch");
            return Err(ProgramError::InvalidArgument);
        }
    }

    // 3) the secp256r1 precompile instruction must be in this tx and bind
    //    exactly (pubkey, message).
    let ix = load_instruction_at_checked(ix_index as usize, sysvar)?;
    if ix.program_id != SECP256R1_ID {
        msg!("not the secp256r1 precompile");
        return Err(ProgramError::InvalidArgument);
    }
    // layout: [num_sigs u8][pad u8][offsets 14B] then payload; offsets are
    // sig_off u16, sig_ix u16, pk_off u16, pk_ix u16, msg_off u16, msg_size u16, msg_ix u16
    let d = &ix.data;
    if d.len() < 16 || d[0] != 1 {
        msg!("unexpected precompile instruction shape");
        return Err(ProgramError::InvalidArgument);
    }
    let u = |i: usize| u16::from_le_bytes([d[i], d[i + 1]]) as usize;
    let (sig_off, sig_ix, pk_off, pk_ix, msg_off, msg_sz, msg_ix) =
        (u(2), u(4), u(6), u(8), u(10), u(12), u(14));
    let same = u16::MAX as usize; // 0xFFFF = "this instruction"
    if sig_ix != same || pk_ix != same || msg_ix != same {
        msg!("precompile references another instruction");
        return Err(ProgramError::InvalidArgument);
    }
    let pk_bytes = d
        .get(pk_off..pk_off.saturating_add(33))
        .ok_or(ProgramError::InvalidArgument)?;
    if pk_bytes != pk {
        msg!("pubkey mismatch");
        return Err(ProgramError::InvalidArgument);
    }
    let mut expected_msg = auth.to_vec();
    expected_msg.extend_from_slice(&solana_program::hash::hash(cdj).to_bytes()); // SHA-256
    let msg_bytes = d
        .get(msg_off..msg_off.saturating_add(msg_sz))
        .ok_or(ProgramError::InvalidArgument)?;
    if msg_bytes != expected_msg.as_slice() {
        msg!("message mismatch");
        return Err(ProgramError::InvalidArgument);
    }
    // Signature validity is enforced by the precompile itself; we only bind identity.
    let _sig = d
        .get(sig_off..sig_off.saturating_add(64))
        .ok_or(ProgramError::InvalidArgument)?;

    msg!("webauthn root assertion bound OK");
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClientDataCheck {
    Ok,
    TypeMismatch,
    ChallengeMismatch,
    OriginMismatch,
}

/// Byte-substring "parse" of `clientDataJSON`.
///
/// # THIS IS NOT PRODUCTION-SAFE — DO NOT REUSE VERBATIM
///
/// It is extracted as a pure function purely so the spike can *demonstrate* its
/// holes in unit tests (see the `substring_match_holes` module below) rather
/// than merely assert them in prose. Known defects:
/// * a `origin` key nested inside another object satisfies the check;
/// * a duplicate top-level `origin`/`challenge` key satisfies the check even
///   when the first occurrence is attacker-chosen;
/// * a legitimately escaped value (`\/` or `\u002f`) is falsely rejected;
/// * `crossOrigin` is not examined at all;
/// * cost is O(haystack x needle) with no length cap on `clientDataJSON`.
///
/// Phase 1 MUST replace this with a top-level, duplicate-rejecting,
/// escape-aware scanner, or bind a canonical `clientDataJSON` template.
pub fn client_data_check(cdj: &[u8], challenge_b64url: &[u8], origin: &[u8]) -> ClientDataCheck {
    if !contains(cdj, b"\"type\":\"webauthn.get\"") {
        return ClientDataCheck::TypeMismatch;
    }
    let mut cpat = b"\"challenge\":\"".to_vec();
    cpat.extend_from_slice(challenge_b64url);
    cpat.push(b'"');
    if !contains(cdj, &cpat) {
        return ClientDataCheck::ChallengeMismatch;
    }
    let mut opat = b"\"origin\":\"".to_vec();
    opat.extend_from_slice(origin);
    opat.push(b'"');
    if !contains(cdj, &opat) {
        return ClientDataCheck::OriginMismatch;
    }
    ClientDataCheck::Ok
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    n.len() <= h.len() && h.windows(n.len()).any(|w| w == n)
}

/// Executable documentation of the substring matcher's holes.
///
/// These are unit tests rather than LiteSVM transactions on purpose: an
/// end-to-end version would need a signature over the crafted
/// `clientDataJSON` under the *root* passkey, which is exactly what an attacker
/// cannot produce. The hole being demonstrated lives entirely in the string
/// check, so that is where it is demonstrated. Phase 1's stricter parser must
/// flip the `_passes_` tests below to rejections.
#[cfg(test)]
mod substring_match_holes {
    use super::*;

    const ORIGIN: &[u8] = b"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi";
    const CHAL: &[u8] = b"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q";

    #[test]
    fn accepts_the_real_client_data_json() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi","crossOrigin":false}"#;
        assert_eq!(client_data_check(cdj, CHAL, ORIGIN), ClientDataCheck::Ok);
    }

    /// KNOWN HOLE (Phase 1 must flip this to a rejection): the *real* origin is
    /// an attacker's, and ours only appears inside a nested object.
    #[test]
    fn documents_nested_origin_hole_passes_substring_match() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"https://evil.example","crossOrigin":true,"unknownExtension":{"origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi"}}"#;
        assert_eq!(
            client_data_check(cdj, CHAL, ORIGIN),
            ClientDataCheck::Ok,
            "the substring matcher is known to accept a nested origin — Phase 1 must reject it"
        );
    }

    /// KNOWN HOLE: duplicate top-level key; a real parser resolves one of the
    /// two (implementation-defined), the substring matcher sees both.
    #[test]
    fn documents_duplicate_origin_key_passes_substring_match() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"https://evil.example","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi","crossOrigin":false}"#;
        assert_eq!(client_data_check(cdj, CHAL, ORIGIN), ClientDataCheck::Ok);
    }

    /// KNOWN HOLE: `crossOrigin` is never examined.
    #[test]
    fn documents_cross_origin_true_passes_substring_match() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi","crossOrigin":true}"#;
        assert_eq!(client_data_check(cdj, CHAL, ORIGIN), ClientDataCheck::Ok);
    }

    /// KNOWN FALSE REJECTION: a UA is free to escape `/` as `\/`; the value is
    /// semantically identical and a real parser accepts it. We lock the user out.
    #[test]
    fn documents_escaped_origin_falsely_rejected() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension:\/\/maikadpaobbjkmaomnpnhjglpabllaoi","crossOrigin":false}"#;
        assert_eq!(client_data_check(cdj, CHAL, ORIGIN), ClientDataCheck::OriginMismatch);
    }

    /// Sanity: a genuinely wrong origin with no nesting trick is still rejected.
    #[test]
    fn rejects_plain_wrong_origin() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"https://evil.example","crossOrigin":false}"#;
        assert_eq!(client_data_check(cdj, CHAL, ORIGIN), ClientDataCheck::OriginMismatch);
    }
}
