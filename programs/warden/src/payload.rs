//! `ExecutePayload` — the wire format `execute` (and, later, `swap`) decodes a
//! set of inner instructions from (Phase 1B Task 5).
//!
//! This module is the **pure** half: it decodes the bytes and enforces every
//! rule that needs only the payload itself (structural shape, flag bits, the
//! signer/writable rules on the two privileged logical slots, duplicate account
//! indices). The rules that need the transaction's account list — an index is
//! in range, `program_idx` is executable and is neither the warden program nor
//! ComputeBudget, the fixed deny-list, `accounts_hash` — live in the handler,
//! which owns the accounts. Keeping the byte decode pure lets it be
//! exhaustively unit-tested with no SVM.
//!
//! ## Wire format (spec §5.2, fixed)
//!
//! ```text
//! ExecutePayload := n_ixs: u8, InnerIx * n_ixs
//! InnerIx        := program_idx: u8,
//!                   n_accts: u8,
//!                   (idx: u8, flags: u8) * n_accts,
//!                   data_len: u16 LE,
//!                   data: u8 * data_len
//! ```
//!
//! `flags`: bit 0 = signer, bit 1 = writable; **any other bit set is a reject**
//! (an unknown flag must never be silently honoured or silently dropped).
//!
//! ## Account indices are LOGICAL (Global Constraints ABI)
//!
//! Every `idx` names a slot of the **logical** account list the handler builds:
//! `logical[0] = smart_account`, `logical[1] = signer`, `logical[2 + k] =
//! remaining_accounts[k]`. The physical account slice is never indexed. Two
//! rules therefore live here, because they are pure functions of `(idx,
//! flags)`:
//!
//! - **The SmartAccount PDA (`idx 0`) may never be passed writable to a CPI.**
//!   A writable PDA handed to an arbitrary program is a blank cheque; the vault
//!   is moved only by the instructions warden itself constructs, never by a
//!   dApp CPI. `flags` bit 1 on `idx 0` ⇒ reject.
//! - **A signer flag is honoured only on `idx 0` and `idx 1`.** `idx 0` is the
//!   PDA, signed by `invoke_signed`; `idx 1` is the session/root signer. Any
//!   other `idx` carrying the signer bit ⇒ reject — a payload cannot conjure a
//!   third signer it does not have.

use anchor_lang::prelude::*;

use crate::errors::WardenError;

/// `flags` bit 0 — the account is a signer of the inner instruction.
pub const FLAG_SIGNER: u8 = 1 << 0;
/// `flags` bit 1 — the account is writable in the inner instruction.
pub const FLAG_WRITABLE: u8 = 1 << 1;
const FLAG_KNOWN: u8 = FLAG_SIGNER | FLAG_WRITABLE;

/// The logical index of the SmartAccount PDA — never writable, always signable.
pub const LOGICAL_SMART_ACCOUNT: u8 = 0;
/// The logical index of the session/root signer.
pub const LOGICAL_SIGNER: u8 = 1;

/// One decoded inner instruction. `accounts` are `(logical_idx, flags)` pairs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InnerIx {
    /// Logical index of the account to invoke as the program.
    pub program_idx: u8,
    /// `(logical_idx, flags)` for each account the inner instruction takes.
    pub accounts: Vec<(u8, u8)>,
    /// The inner instruction's own data (its own discriminator/tag + args).
    pub data: Vec<u8>,
}

/// A fully-decoded, structurally-valid execute payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutePayload {
    pub ixs: Vec<InnerIx>,
}

/// A forward-only byte cursor with fail-closed reads (never panics, never uses
/// unchecked arithmetic — the crate denies `arithmetic_side_effects`).
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn u8(&mut self) -> Result<u8> {
        let b = *self.bytes.get(self.pos).ok_or(WardenError::PayloadInvalid)?;
        self.pos = self.pos.checked_add(1).ok_or(WardenError::Overflow)?;
        Ok(b)
    }

    fn u16_le(&mut self) -> Result<u16> {
        let lo = self.u8()? as u16;
        let hi = self.u8()? as u16;
        Ok(lo | (hi << 8))
    }

    fn take(&mut self, n: usize) -> Result<Vec<u8>> {
        let end = self.pos.checked_add(n).ok_or(WardenError::Overflow)?;
        let slice = self.bytes.get(self.pos..end).ok_or(WardenError::PayloadInvalid)?;
        self.pos = end;
        Ok(slice.to_vec())
    }

    fn done(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

/// Decode and structurally validate an `ExecutePayload`. Enforces the wire
/// shape, the flag-bit rules, the signer/writable rules on the privileged
/// logical slots, and rejects a duplicate `(idx)` within one inner instruction.
/// It deliberately does NOT check indices against a concrete account list or
/// touch the deny-list — those need the handler's accounts.
///
/// **Strict:** trailing bytes after the last inner instruction are a reject, so
/// a payload cannot smuggle unparsed data past the hash.
pub fn parse_payload(bytes: &[u8]) -> Result<ExecutePayload> {
    let mut c = Cursor::new(bytes);
    let n_ixs = c.u8()?;
    let mut ixs = Vec::with_capacity(n_ixs as usize);
    for _ in 0..n_ixs {
        let program_idx = c.u8()?;
        let n_accts = c.u8()?;
        let mut accounts: Vec<(u8, u8)> = Vec::with_capacity(n_accts as usize);
        for _ in 0..n_accts {
            let idx = c.u8()?;
            let flags = c.u8()?;
            // Unknown flag bits are never silently honoured or dropped.
            require!(flags & !FLAG_KNOWN == 0, WardenError::PayloadInvalid);
            // The SmartAccount PDA may never be writable to a CPI.
            require!(
                !(idx == LOGICAL_SMART_ACCOUNT && flags & FLAG_WRITABLE != 0),
                WardenError::PayloadInvalid
            );
            // A signer flag is honoured only on the PDA (0) and the signer (1).
            require!(
                !(flags & FLAG_SIGNER != 0 && idx != LOGICAL_SMART_ACCOUNT && idx != LOGICAL_SIGNER),
                WardenError::PayloadInvalid
            );
            // A duplicate account index within one inner instruction shifts
            // every later reference and is refused up front.
            require!(
                !accounts.iter().any(|(prev, _)| *prev == idx),
                WardenError::PayloadInvalid
            );
            accounts.push((idx, flags));
        }
        let data_len = c.u16_le()?;
        let data = c.take(data_len as usize)?;
        ixs.push(InnerIx { program_idx, accounts, data });
    }
    require!(c.done(), WardenError::PayloadInvalid);
    Ok(ExecutePayload { ixs })
}

/// How an inner instruction targeting SPL Token / Token-2022 is classified
/// against the fixed deny-list (spec §5.2 rule 1a). The classification is a pure
/// function of the instruction data's tag byte; the handler applies it only when
/// the resolved program is SPL Token or Token-2022, on BOTH the session and root
/// paths, before any registry lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplTokenOp {
    /// `Approve` / `Revoke` / `SetAuthority` / `ApproveChecked` — refused
    /// unconditionally (`DenyListed`); no registry entry and no policy can
    /// re-enable them.
    DeniedUnconditional,
    /// `CloseAccount` — permitted ONLY as the vault-sweep exception the handler
    /// proves against the snapshot (`amount_before == 0`, decoded destination is
    /// the SmartAccount PDA, direct payload instruction); otherwise denied.
    CloseAccount,
    /// Anything else (e.g. `Transfer`, `TransferChecked`) — the deny-list does
    /// not apply; it proceeds to the registry / conservation checks.
    Other,
}

/// Classify an SPL Token / Token-2022 inner instruction by its tag byte. Empty
/// data (no tag) is `Other` — a malformed token instruction the CPI itself
/// rejects, not a deny-list case.
pub fn classify_spl_token_op(data: &[u8]) -> SplTokenOp {
    use crate::constants::{
        TOKEN_IX_APPROVE, TOKEN_IX_APPROVE_CHECKED, TOKEN_IX_CLOSE_ACCOUNT, TOKEN_IX_REVOKE,
        TOKEN_IX_SET_AUTHORITY,
    };
    match data.first().copied() {
        Some(TOKEN_IX_APPROVE)
        | Some(TOKEN_IX_REVOKE)
        | Some(TOKEN_IX_SET_AUTHORITY)
        | Some(TOKEN_IX_APPROVE_CHECKED) => SplTokenOp::DeniedUnconditional,
        Some(TOKEN_IX_CLOSE_ACCOUNT) => SplTokenOp::CloseAccount,
        _ => SplTokenOp::Other,
    }
}

/// One entry of the logical account list, as `accounts_hash` sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogicalAccount {
    pub key: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// `Keccak256` over the logical account list in logical order — for each entry,
/// `pubkey ‖ (is_signer as u8) ‖ (is_writable as u8)` (spec §5.2 / §4.3). The
/// root ceremony binds this via `ExecuteBody`/`SwapBody`, so a bearer assertion
/// cannot substitute program/source/destination accounts after signing. The
/// TS SDK reconstructs the same list the same way before comparing.
pub fn compute_accounts_hash(logical: &[LogicalAccount]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(logical.len().saturating_mul(34));
    for a in logical {
        buf.extend_from_slice(a.key.as_ref());
        buf.push(a.is_signer as u8);
        buf.push(a.is_writable as u8);
    }
    solana_keccak_hasher::hashv(&[&buf]).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(e: WardenError) -> anchor_lang::error::Error {
        e.into()
    }

    /// Encode a payload the way a client would, for round-trip tests.
    fn encode(ixs: &[(u8, &[(u8, u8)], &[u8])]) -> Vec<u8> {
        let mut out = vec![ixs.len() as u8];
        for (program_idx, accts, data) in ixs {
            out.push(*program_idx);
            out.push(accts.len() as u8);
            for (idx, flags) in *accts {
                out.push(*idx);
                out.push(*flags);
            }
            out.extend_from_slice(&(data.len() as u16).to_le_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn round_trips_a_two_ix_payload() {
        let bytes = encode(&[
            (2, &[(0, FLAG_SIGNER), (3, FLAG_WRITABLE)], &[9, 9, 9]),
            (4, &[(1, FLAG_SIGNER), (5, 0)], &[]),
        ]);
        let p = parse_payload(&bytes).unwrap();
        assert_eq!(p.ixs.len(), 2);
        assert_eq!(p.ixs[0], InnerIx { program_idx: 2, accounts: vec![(0, FLAG_SIGNER), (3, FLAG_WRITABLE)], data: vec![9, 9, 9] });
        assert_eq!(p.ixs[1], InnerIx { program_idx: 4, accounts: vec![(1, FLAG_SIGNER), (5, 0)], data: vec![] });
    }

    #[test]
    fn empty_payload_is_zero_ixs() {
        assert_eq!(parse_payload(&[0]).unwrap().ixs, vec![]);
    }

    #[test]
    fn truncated_payload_rejected() {
        // Claims 1 ix but no ix bytes follow.
        assert_eq!(parse_payload(&[1]).unwrap_err(), err(WardenError::PayloadInvalid));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut bytes = encode(&[(2, &[(0, FLAG_SIGNER)], &[])]);
        bytes.push(0xFF);
        assert_eq!(parse_payload(&bytes).unwrap_err(), err(WardenError::PayloadInvalid));
    }

    #[test]
    fn data_len_past_end_rejected() {
        // n_ixs=1, program_idx=2, n_accts=0, data_len=5, but only 2 data bytes.
        let bytes = vec![1, 2, 0, 5, 0, 0xAA, 0xBB];
        assert_eq!(parse_payload(&bytes).unwrap_err(), err(WardenError::PayloadInvalid));
    }

    #[test]
    fn unknown_flag_bit_rejected() {
        let bytes = encode(&[(2, &[(3, 0b100)], &[])]); // bit 2 set
        assert_eq!(parse_payload(&bytes).unwrap_err(), err(WardenError::PayloadInvalid));
    }

    #[test]
    fn writable_smart_account_rejected() {
        let bytes = encode(&[(2, &[(LOGICAL_SMART_ACCOUNT, FLAG_WRITABLE)], &[])]);
        assert_eq!(parse_payload(&bytes).unwrap_err(), err(WardenError::PayloadInvalid));
    }

    #[test]
    fn writable_smart_account_with_signer_also_rejected() {
        let bytes = encode(&[(2, &[(LOGICAL_SMART_ACCOUNT, FLAG_SIGNER | FLAG_WRITABLE)], &[])]);
        assert_eq!(parse_payload(&bytes).unwrap_err(), err(WardenError::PayloadInvalid));
    }

    #[test]
    fn signer_on_slot_two_or_higher_rejected() {
        for idx in [2u8, 5, 200] {
            let bytes = encode(&[(9, &[(idx, FLAG_SIGNER)], &[])]);
            assert_eq!(parse_payload(&bytes).unwrap_err(), err(WardenError::PayloadInvalid), "idx {idx}");
        }
    }

    #[test]
    fn signer_on_slots_zero_and_one_accepted() {
        let bytes = encode(&[(9, &[(LOGICAL_SMART_ACCOUNT, FLAG_SIGNER), (LOGICAL_SIGNER, FLAG_SIGNER)], &[])]);
        assert!(parse_payload(&bytes).is_ok());
    }

    #[test]
    fn duplicate_index_within_one_ix_rejected() {
        let bytes = encode(&[(9, &[(3, 0), (3, FLAG_WRITABLE)], &[])]);
        assert_eq!(parse_payload(&bytes).unwrap_err(), err(WardenError::PayloadInvalid));
    }

    #[test]
    fn same_index_across_different_ixs_allowed() {
        // The duplicate rule is per-inner-instruction, not global.
        let bytes = encode(&[(9, &[(3, 0)], &[]), (9, &[(3, FLAG_WRITABLE)], &[])]);
        assert!(parse_payload(&bytes).is_ok());
    }

    #[test]
    fn classify_spl_token_op_maps_the_deny_tags() {
        assert_eq!(classify_spl_token_op(&[4]), SplTokenOp::DeniedUnconditional); // Approve
        assert_eq!(classify_spl_token_op(&[5]), SplTokenOp::DeniedUnconditional); // Revoke
        assert_eq!(classify_spl_token_op(&[6]), SplTokenOp::DeniedUnconditional); // SetAuthority
        assert_eq!(classify_spl_token_op(&[13]), SplTokenOp::DeniedUnconditional); // ApproveChecked
        assert_eq!(classify_spl_token_op(&[9]), SplTokenOp::CloseAccount);
        assert_eq!(classify_spl_token_op(&[3]), SplTokenOp::Other); // Transfer
        assert_eq!(classify_spl_token_op(&[12]), SplTokenOp::Other); // TransferChecked
        assert_eq!(classify_spl_token_op(&[]), SplTokenOp::Other); // no tag
    }

    /// The deny-list tag constants are re-derived from the pinned `spl-token`
    /// crate's `TokenInstruction` encoding, never memorised — a wrong tag is a
    /// silent hole, not a compile error.
    #[test]
    fn deny_list_tags_match_spl_token() {
        use crate::constants::*;
        use spl_token::instruction::{AuthorityType, TokenInstruction};
        use spl_token::solana_program::program_option::COption;
        assert_eq!(TokenInstruction::Transfer { amount: 0 }.pack()[0], TOKEN_IX_TRANSFER);
        assert_eq!(TokenInstruction::Approve { amount: 0 }.pack()[0], TOKEN_IX_APPROVE);
        assert_eq!(TokenInstruction::Revoke.pack()[0], TOKEN_IX_REVOKE);
        assert_eq!(
            TokenInstruction::SetAuthority {
                authority_type: AuthorityType::AccountOwner,
                new_authority: COption::None,
            }
            .pack()[0],
            TOKEN_IX_SET_AUTHORITY
        );
        assert_eq!(TokenInstruction::CloseAccount.pack()[0], TOKEN_IX_CLOSE_ACCOUNT);
        assert_eq!(
            TokenInstruction::ApproveChecked { amount: 0, decimals: 0 }.pack()[0],
            TOKEN_IX_APPROVE_CHECKED
        );
    }

    #[test]
    fn accounts_hash_is_order_and_flag_sensitive() {
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();
        let base = vec![
            LogicalAccount { key: a, is_signer: true, is_writable: false },
            LogicalAccount { key: b, is_signer: false, is_writable: true },
        ];
        let h = compute_accounts_hash(&base);
        // reorder
        let reordered = vec![base[1], base[0]];
        assert_ne!(h, compute_accounts_hash(&reordered));
        // flip a flag
        let mut flipped = base.clone();
        flipped[0].is_writable = true;
        assert_ne!(h, compute_accounts_hash(&flipped));
        // identical input reproduces
        assert_eq!(h, compute_accounts_hash(&base));
    }
}
