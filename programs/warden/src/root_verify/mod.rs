//! Passkey (P-256 / WebAuthn) root-key verification — the security core every
//! root-authorized instruction depends on.
//!
//! One successful call proves, for the currently executing instruction:
//!
//! 1. the account's stored root key is a P-256 passkey (`root_kind == 0`);
//! 2. `authenticatorData` carries the account's stored `rp_id_hash` and both
//!    UP and UV flags (`auth_data`);
//! 3. `clientDataJSON` is a single, well-formed JSON object no larger than
//!    `MAX_CLIENT_DATA_LEN` whose **depth-0** `type`/`challenge`/`origin` are
//!    unique and decoded (`client_data`);
//! 4. `type == "webauthn.get"`, `crossOrigin` absent or `false`, and `origin`
//!    equals the account's stored origin byte-for-byte;
//! 5. `now <= expiry_ts <= now + MAX_ROOT_EXPIRY_SECS`;
//! 6. `challenge == base64url_nopad(transcript_hash(...))` over the account's
//!    *current* `generation`, `policy.version` and `root_nonce`, the account
//!    address, the program id, the stored `cluster_tag`, `expiry_ts` and the
//!    caller-recomputed `action_hash` (`transcript`);
//! 7. a secp256r1 precompile instruction earlier in this same transaction
//!    verified exactly `(root_pubkey33, authenticatorData ‖
//!    SHA-256(clientDataJSON))` with all three instruction indices set to
//!    "this instruction" (`precompile`).
//!
//! On success `root_nonce` is incremented (consumed), so the same assertion
//! can never be replayed.
//!
//! What it deliberately does **not** do: verify the ECDSA signature (the
//! runtime's precompile does that, and it cannot be CPI'd), enforce the
//! WebAuthn sign counter (synced passkeys make it meaningless), or check
//! `frozen` (freeze/unfreeze are themselves root instructions — gating is the
//! caller's job, per spec §5.1).

pub mod auth_data;
pub mod client_data;
pub mod precompile;
pub mod transcript;

use anchor_lang::prelude::*;

use crate::constants::MAX_ROOT_EXPIRY_SECS;
use crate::errors::WardenError;
use crate::state::{RootKey, SmartAccount};

/// Instruction-argument payload every root-authorized instruction carries, in
/// addition to its own arguments (which are hashed into `action_hash`).
///
/// Budget (C7): `authenticator_data` is 37 B for a platform passkey and
/// `client_data_json` is capped at `MAX_CLIENT_DATA_LEN` = 512 B, so the worst
/// case is ~570 B on top of the ~180 B precompile instruction.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct RootArgs {
    /// Index, within this transaction, of the secp256r1 precompile
    /// instruction that verified the assertion. Must be < our own index.
    pub precompile_ix_index: u8,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    /// Absolute unix seconds; the ceremony is valid for at most
    /// `MAX_ROOT_EXPIRY_SECS` into the future.
    pub expiry_ts: i64,
}

/// Verify a root passkey assertion and consume the account's `root_nonce`.
///
/// `action_hash` must be recomputed by the caller from the *executing*
/// instruction's own arguments (`transcript::action_hash(op_type,
/// &args.try_to_vec()?)`), never taken from instruction data — that is what
/// stops an attacker from re-pointing a signed ceremony at different
/// arguments.
pub fn verify_root_assertion(
    account: &mut SmartAccount,
    ix_sysvar: &AccountInfo,
    args: &RootArgs,
    program_id: &Pubkey,
    account_key: &Pubkey,
    action_hash: [u8; 32],
    now: i64,
) -> Result<()> {
    // 1. Root must be a passkey. Ed25519 roots (hardware/advanced users) are
    //    authenticated by a real transaction signature, not by this path.
    let root_pubkey33 = match account.root()? {
        RootKey::P256Passkey { pubkey } => pubkey,
        RootKey::Ed25519 { .. } => return Err(WardenError::RootKindUnsupported.into()),
    };

    // 2. authenticatorData: rpIdHash from STATE (never from instruction data), UP|UV.
    auth_data::check_auth_data(&args.authenticator_data, &account.rp_id_hash)?;

    // 3./4. clientDataJSON: strict depth-0 scan, then the semantic comparisons.
    let cd = client_data::parse_strict(&args.client_data_json)?;
    require!(
        cd.typ.as_slice() == b"webauthn.get".as_slice(),
        WardenError::ClientDataTypeMismatch
    );
    require!(!cd.cross_origin_true, WardenError::CrossOriginNotAllowed);
    let expected_origin = account
        .origin
        .get(..usize::from(account.origin_len))
        .ok_or(WardenError::InvalidAccountData)?;
    require!(cd.origin.as_slice() == expected_origin, WardenError::OriginMismatch);

    // 5. Freshness window. `expiry_ts` is signed into the transcript, so a
    //    stale ceremony cannot be stretched by editing instruction data.
    require!(now <= args.expiry_ts, WardenError::Expired);
    require!(
        args.expiry_ts
            <= now
                .checked_add(MAX_ROOT_EXPIRY_SECS)
                .ok_or(WardenError::Overflow)?,
        WardenError::Expired
    );

    // 6. Challenge == base64url(transcript over the account's CURRENT state).
    let expected_challenge = transcript::b64url_no_pad(&transcript_for(
        account,
        program_id,
        account_key,
        account.root_nonce,
        args.expiry_ts,
        &action_hash,
    ));
    if cd.challenge != expected_challenge {
        // Diagnostic only, on the failure path: if the assertion matches the
        // *previous* nonce it is a replay of an already-consumed ceremony, and
        // saying so is far more actionable than a bare challenge mismatch.
        if let Some(prev) = account.root_nonce.checked_sub(1) {
            let replayed = transcript::b64url_no_pad(&transcript_for(
                account,
                program_id,
                account_key,
                prev,
                args.expiry_ts,
                &action_hash,
            ));
            require!(cd.challenge != replayed, WardenError::NonceMismatch);
        }
        return Err(WardenError::ChallengeMismatch.into());
    }

    // 7. The precompile in this transaction verified exactly this key over
    //    exactly `authenticatorData ‖ SHA-256(clientDataJSON)`.
    let cdj_hash = solana_sha256_hasher::hash(&args.client_data_json).to_bytes();
    let mut message = Vec::with_capacity(args.authenticator_data.len().saturating_add(32));
    message.extend_from_slice(&args.authenticator_data);
    message.extend_from_slice(&cdj_hash);
    precompile::bind_precompile(ix_sysvar, args.precompile_ix_index, &root_pubkey33, &message)?;

    // Consume the nonce. Anything that reads `root_nonce` after this point in
    // the same instruction sees the new value, which is correct: one ceremony,
    // one action.
    account.root_nonce = account
        .root_nonce
        .checked_add(1)
        .ok_or(WardenError::Overflow)?;
    Ok(())
}

fn transcript_for(
    account: &SmartAccount,
    program_id: &Pubkey,
    account_key: &Pubkey,
    root_nonce: u64,
    expiry_ts: i64,
    action_hash: &[u8; 32],
) -> [u8; 32] {
    transcript::transcript_hash(
        &account.cluster_tag,
        program_id,
        account_key,
        account.generation,
        account.policy.version,
        root_nonce,
        expiry_ts,
        action_hash,
    )
}
