//! Binding the assertion to the secp256r1 precompile instruction (spec §4).
//!
//! The secp256r1 precompile (SIMD-0075) is a **transaction-level** instruction
//! and cannot be CPI'd, so the signature itself is verified by the runtime,
//! outside this program, before any instruction runs. What is left for us —
//! and what this module does — is prove that the thing the runtime verified is
//! *our* assertion: same key, same message, and self-contained within that one
//! instruction.
//!
//! Precompile instruction data layout (confirmed against
//! `solana-secp256r1-program` 3.0.0, and pinned by
//! `hand_built_precompile_ix_matches_crate` in `tests/root_verify.rs`):
//!
//! ```text
//! [0]      num_signatures : u8
//! [1]      padding        : u8
//! [2..16]  offsets        : signature_offset u16, signature_instruction_index u16,
//!                           public_key_offset u16, public_key_instruction_index u16,
//!                           message_data_offset u16, message_data_size u16,
//!                           message_instruction_index u16          (all little-endian)
//! [16..]   payload        : public_key(33) ‖ signature(64) ‖ message(n)
//! ```
//!
//! Every `*_instruction_index` must be `0xFFFF` ("this instruction"). Without
//! that check a precompile instruction could verify a key or message that
//! lives in a *different* instruction of the same transaction — one this
//! program never inspects — and the binding would prove nothing.
//!
//! The named instruction must also come strictly **before** the currently
//! executing one. It has therefore already been verified by the runtime when
//! we read it; a precompile instruction placed after ours would fail the
//! transaction, but only *after* our state write, and reasoning about that
//! ordering is not worth the risk.

use anchor_lang::prelude::*;
use solana_instructions_sysvar::{load_current_index_checked, load_instruction_at_checked};

use crate::errors::WardenError;

/// `Secp256r1SigVerify1111111111111111111111111` — pinned as a literal so the
/// SBF binary carries no extra dependency; `secp256r1_id_matches_the_crate` in
/// `tests/root_verify.rs` asserts it equals `solana_secp256r1_program::ID`.
pub const SECP256R1_ID: Pubkey = anchor_lang::prelude::pubkey!("Secp256r1SigVerify1111111111111111111111111");

/// Offsets block starts at byte 2; payload starts at byte 16 for one signature.
const OFFSETS_START: usize = 2;
const DATA_START: usize = 16;
const PUBKEY_LEN: usize = 33;
const SIG_LEN: usize = 64;
/// `0xFFFF` in a `*_instruction_index` field means "this same instruction".
const SAME_INSTRUCTION: usize = u16::MAX as usize;

pub fn bind_precompile(
    ix_sysvar: &AccountInfo,
    ix_index: u8,
    expected_pubkey33: &[u8; 33],
    expected_message: &[u8],
) -> Result<()> {
    let current = load_current_index_checked(ix_sysvar).map_err(|_| WardenError::BadInstructionLayout)?;
    require!(u16::from(ix_index) < current, WardenError::PrecompileNotFound);

    let ix = load_instruction_at_checked(usize::from(ix_index), ix_sysvar)
        .map_err(|_| WardenError::PrecompileNotFound)?;
    require_keys_eq!(ix.program_id, SECP256R1_ID, WardenError::PrecompileNotFound);

    let d = ix.data.as_slice();
    require!(d.len() >= DATA_START, WardenError::BadInstructionLayout);
    // Exactly one signature entry. More than one would leave a second,
    // unexamined (key, message) pair verified by the runtime inside the very
    // instruction we are treating as the proof of a single assertion.
    require!(*d.first().ok_or(WardenError::BadInstructionLayout)? == 1, WardenError::BadInstructionLayout);

    let u16_at = |off: usize| -> Result<usize> {
        let end = off.checked_add(2).ok_or(WardenError::Overflow)?;
        let s = d.get(off..end).ok_or(WardenError::BadInstructionLayout)?;
        let (a, b) = (
            *s.first().ok_or(WardenError::BadInstructionLayout)?,
            *s.get(1).ok_or(WardenError::BadInstructionLayout)?,
        );
        Ok(usize::from(u16::from_le_bytes([a, b])))
    };
    let sig_off = u16_at(OFFSETS_START)?;
    let sig_ix = u16_at(OFFSETS_START.saturating_add(2))?;
    let pk_off = u16_at(OFFSETS_START.saturating_add(4))?;
    let pk_ix = u16_at(OFFSETS_START.saturating_add(6))?;
    let msg_off = u16_at(OFFSETS_START.saturating_add(8))?;
    let msg_size = u16_at(OFFSETS_START.saturating_add(10))?;
    let msg_ix = u16_at(OFFSETS_START.saturating_add(12))?;

    require!(
        sig_ix == SAME_INSTRUCTION && pk_ix == SAME_INSTRUCTION && msg_ix == SAME_INSTRUCTION,
        WardenError::PrecompileBindingMismatch
    );

    let pk = slice_at(d, pk_off, PUBKEY_LEN)?;
    require!(pk == expected_pubkey33.as_slice(), WardenError::PrecompileBindingMismatch);

    // Compare the length first: a shorter `message_data_size` with a matching
    // prefix must never pass.
    require!(msg_size == expected_message.len(), WardenError::PrecompileBindingMismatch);
    let msg = slice_at(d, msg_off, msg_size)?;
    require!(msg == expected_message, WardenError::PrecompileBindingMismatch);

    // The signature bytes themselves are verified by the runtime; we only
    // prove they are present and in bounds, so a truncated instruction cannot
    // masquerade as a verified one.
    let _sig = slice_at(d, sig_off, SIG_LEN)?;
    Ok(())
}

fn slice_at(d: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    let end = off.checked_add(len).ok_or(WardenError::Overflow)?;
    d.get(off..end).ok_or_else(|| WardenError::BadInstructionLayout.into())
}
