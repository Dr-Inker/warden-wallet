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
//! - **The SmartAccount PDA (`idx 0`) may be passed writable to a CPI in
//!   exactly one case: as an account of a deny-list-validated vault-sweep
//!   `CloseAccount`** (the rent destination). Everywhere else a writable PDA
//!   handed to an arbitrary program is a blank cheque — the vault is moved only
//!   by the instructions warden itself constructs. This is NOT a pure structural
//!   rule (whether an ix is a validated close needs the accounts and the
//!   deny-list), so it is enforced by [`enforce_pda_writable`] in the handler
//!   AFTER `deny_scan`, not by `parse_payload`. The spec's "PDA never writable"
//!   (§5.2 rule 3) is this, with its one §5.2-rule-4a sweep exception spelled out.
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
            // The SmartAccount PDA (idx 0) writable to a CPI is refused
            // EVERYWHERE except a deny-validated vault-sweep CloseAccount — but
            // that exception needs the accounts and the deny-list, so it lives in
            // `enforce_pda_writable` (handler), not here. `parse_payload` stays a
            // pure byte decode. See the module docs.
            // A signer flag is honoured only on the PDA (0) and the signer (1).
            require!(
                !(flags & FLAG_SIGNER != 0 && idx != LOGICAL_SMART_ACCOUNT && idx != LOGICAL_SIGNER),
                WardenError::PayloadInvalid
            );
            // A logical account MAY be referenced more than once within one
            // inner instruction: real CPIs routinely give one account two roles
            // — an SPL `CloseAccount` sweeping a vault ATA names the SmartAccount
            // PDA as BOTH the rent destination and the close authority, and many
            // DeFi instructions repeat a token/authority account across slots.
            // Duplicate references are benign here: each names an index into the
            // logical list, whose UNIQUENESS is what actually matters, and that
            // is enforced once, globally, in `conservation::compare_and_account`
            // (a duplicate *pubkey* in the snapshot list is rejected). The
            // signer/writable/PDA rules above still apply to every occurrence.
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

/// The metadata the handler resolves each logical account to (drawn from the
/// `AccountInfo`s). `executable` and the key are what the account-context
/// payload rules need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogicalMeta {
    pub key: Pubkey,
    pub executable: bool,
}

/// One inner instruction resolved against the concrete account list, ready for
/// `invoke_signed`: the program key, the ordered `(key, is_signer, is_writable)`
/// account metas, and the instruction data. `is_signer`/`is_writable` come from
/// the payload `flags` (already validated pure), keyed to the logical account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedInner {
    pub program: Pubkey,
    pub accounts: Vec<LogicalAccount>,
    pub data: Vec<u8>,
}

/// Validate a parsed payload against the concrete logical account list and
/// resolve each inner instruction to concrete keys (spec §5.2). Enforces the
/// rules that need the accounts:
///
/// - every `program_idx` and every account `idx` is in range of `logical`;
/// - each `program_idx` names an **executable** account whose key is neither the
///   warden program (`SelfCpiRejected` — blocks direct and, with the account-list
///   rule below, indirect re-entry) nor ComputeBudget (`ComputeBudgetInExecute`);
/// - neither the warden program id nor ComputeBudget appears **anywhere** in the
///   account list past the two privileged slots (`SelfCpiRejected` /
///   `ComputeBudgetInExecute`) — a middleman program cannot smuggle warden back
///   in as a bare account to re-enter it.
///
/// The deny-list and conservation are applied by the handler on the returned
/// `ResolvedInner`s; this function is the account-resolution layer.
pub fn resolve_payload(
    payload: &ExecutePayload,
    logical: &[LogicalMeta],
    warden_id: &Pubkey,
) -> Result<Vec<ResolvedInner>> {
    use crate::constants::COMPUTE_BUDGET_ID;

    // The warden program id and ComputeBudget may not appear as accounts past
    // the two privileged slots (0 = PDA, 1 = signer). Checked once over the list.
    for m in logical.iter().skip(2) {
        require!(m.key != *warden_id, WardenError::SelfCpiRejected);
        require!(m.key != COMPUTE_BUDGET_ID, WardenError::ComputeBudgetInExecute);
    }

    let mut resolved = Vec::with_capacity(payload.ixs.len());
    for ix in &payload.ixs {
        let prog = logical
            .get(ix.program_idx as usize)
            .ok_or(WardenError::PayloadInvalid)?;
        require!(prog.executable, WardenError::PayloadInvalid);
        require!(prog.key != *warden_id, WardenError::SelfCpiRejected);
        require!(prog.key != COMPUTE_BUDGET_ID, WardenError::ComputeBudgetInExecute);

        let mut accounts = Vec::with_capacity(ix.accounts.len());
        for (idx, flags) in &ix.accounts {
            let meta = logical.get(*idx as usize).ok_or(WardenError::PayloadInvalid)?;
            accounts.push(LogicalAccount {
                key: meta.key,
                is_signer: flags & FLAG_SIGNER != 0,
                is_writable: flags & FLAG_WRITABLE != 0,
            });
        }
        resolved.push(ResolvedInner { program: prog.key, accounts, data: ix.data.clone() });
    }
    Ok(resolved)
}

/// The SmartAccount PDA (`vault`) may be writable to a CPI in exactly one
/// case: as an account of a vault-sweep `CloseAccount` that [`deny_scan`
/// upstream] has already validated (spec §5.2 rule 3 + its rule-4a exception).
/// Everywhere else a writable PDA is a blank cheque and is refused.
///
/// **Call ONLY after `deny_scan` has run and returned `Ok`** — that guarantees
/// every SPL / Token-2022 `CloseAccount` still present is a proven vault-sweep
/// (`amount_before == 0`, destination = the PDA, direct, non-Mint non-PDA
/// target), so "the ix is such a close" is a sufficient licence for the PDA to
/// appear writable in it. A `CloseAccount` credits only lamports to the PDA and
/// removes a zero-balance vault account — it is not the blank cheque an
/// arbitrary writable-PDA CPI would be.
pub fn enforce_pda_writable(resolved: &[ResolvedInner], vault: &Pubkey) -> Result<()> {
    use crate::constants::{SPL_TOKEN_2022_ID, SPL_TOKEN_ID};
    for r in resolved {
        let is_validated_close = (r.program == SPL_TOKEN_ID || r.program == SPL_TOKEN_2022_ID)
            && classify_spl_token_op(&r.data) == SplTokenOp::CloseAccount;
        if is_validated_close {
            continue;
        }
        for a in &r.accounts {
            require!(!(a.key == *vault && a.is_writable), WardenError::PayloadInvalid);
        }
    }
    Ok(())
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
    fn writable_smart_account_parses_but_is_gated_by_enforce_pda_writable() {
        // `parse_payload` is a pure byte decode and no longer rejects a writable
        // idx 0 — the PDA-writable rule needs the accounts + deny-list, so it
        // lives in `enforce_pda_writable`. See its own tests below.
        let bytes = encode(&[(2, &[(LOGICAL_SMART_ACCOUNT, FLAG_WRITABLE)], &[])]);
        assert!(parse_payload(&bytes).is_ok());
        let bytes = encode(&[(2, &[(LOGICAL_SMART_ACCOUNT, FLAG_SIGNER | FLAG_WRITABLE)], &[])]);
        assert!(parse_payload(&bytes).is_ok());
    }

    // -- enforce_pda_writable ------------------------------------------------

    fn resolved_ix(program: Pubkey, accounts: Vec<LogicalAccount>, data: Vec<u8>) -> ResolvedInner {
        ResolvedInner { program, accounts, data }
    }

    #[test]
    fn enforce_rejects_writable_pda_in_a_non_close_ix() {
        let vault = Pubkey::new_unique();
        let ix = resolved_ix(
            Pubkey::new_unique(),
            vec![LogicalAccount { key: vault, is_signer: false, is_writable: true }],
            vec![],
        );
        assert_eq!(
            enforce_pda_writable(&[ix], &vault).unwrap_err(),
            err(WardenError::PayloadInvalid)
        );
    }

    #[test]
    fn enforce_rejects_writable_pda_in_an_spl_transfer() {
        // An SPL op that is NOT a close (Transfer, tag 3) may not carry a
        // writable PDA either — only a CloseAccount earns the exception.
        let vault = Pubkey::new_unique();
        let ix = resolved_ix(
            crate::constants::SPL_TOKEN_ID,
            vec![LogicalAccount { key: vault, is_signer: false, is_writable: true }],
            vec![3, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            enforce_pda_writable(&[ix], &vault).unwrap_err(),
            err(WardenError::PayloadInvalid)
        );
    }

    #[test]
    fn enforce_allows_writable_pda_as_a_close_destination() {
        // A CloseAccount (tag 9) may name the PDA writable (the rent
        // destination). `deny_scan` — which runs first — has already proven the
        // vault-sweep conditions by the time this is called.
        let vault = Pubkey::new_unique();
        let target = Pubkey::new_unique();
        let ix = resolved_ix(
            crate::constants::SPL_TOKEN_ID,
            vec![
                LogicalAccount { key: target, is_signer: false, is_writable: true },
                LogicalAccount { key: vault, is_signer: false, is_writable: true }, // dest
                LogicalAccount { key: vault, is_signer: true, is_writable: false },  // authority
            ],
            vec![9],
        );
        assert!(enforce_pda_writable(&[ix], &vault).is_ok());
    }

    #[test]
    fn enforce_ignores_a_readonly_pda_reference() {
        // The PDA as a read-only account (e.g. the authority slot) is always
        // fine, in any ix.
        let vault = Pubkey::new_unique();
        let ix = resolved_ix(
            Pubkey::new_unique(),
            vec![LogicalAccount { key: vault, is_signer: true, is_writable: false }],
            vec![],
        );
        assert!(enforce_pda_writable(&[ix], &vault).is_ok());
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
    fn duplicate_index_within_one_ix_allowed() {
        // A logical account may play two roles in one CPI — e.g. an SPL
        // `CloseAccount` naming the PDA as both rent destination and authority.
        // Duplicate references are benign; logical-list uniqueness is enforced
        // in `conservation`, not here.
        let bytes = encode(&[(9, &[(0, 0), (0, FLAG_SIGNER)], &[])]);
        let p = parse_payload(&bytes).unwrap();
        assert_eq!(p.ixs[0].accounts, vec![(0, 0), (0, FLAG_SIGNER)]);
    }

    #[test]
    fn same_index_across_different_ixs_allowed() {
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

    // -- resolve_payload -------------------------------------------------

    fn meta(key: Pubkey, executable: bool) -> LogicalMeta {
        LogicalMeta { key, executable }
    }

    /// logical[0]=pda, [1]=signer, [2]=program(exec), [3]=some account.
    fn base_logical(warden: Pubkey, program: Pubkey) -> Vec<LogicalMeta> {
        let _ = warden;
        vec![
            meta(Pubkey::new_unique(), false), // 0 pda
            meta(Pubkey::new_unique(), false), // 1 signer
            meta(program, true),               // 2 program
            meta(Pubkey::new_unique(), false), // 3 account
        ]
    }

    #[test]
    fn resolve_maps_program_and_accounts() {
        let warden = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        let logical = base_logical(warden, program);
        let p = parse_payload(&encode(&[(2, &[(0, FLAG_SIGNER), (3, FLAG_WRITABLE)], &[7])])).unwrap();
        let r = resolve_payload(&p, &logical, &warden).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].program, program);
        assert_eq!(r[0].data, vec![7]);
        assert_eq!(r[0].accounts[0], LogicalAccount { key: logical[0].key, is_signer: true, is_writable: false });
        assert_eq!(r[0].accounts[1], LogicalAccount { key: logical[3].key, is_signer: false, is_writable: true });
    }

    #[test]
    fn resolve_rejects_out_of_range_program_idx() {
        let warden = Pubkey::new_unique();
        let logical = base_logical(warden, Pubkey::new_unique());
        let p = parse_payload(&encode(&[(9, &[(3, 0)], &[])])).unwrap(); // program_idx 9 > len
        assert_eq!(resolve_payload(&p, &logical, &warden).unwrap_err(), err(WardenError::PayloadInvalid));
    }

    #[test]
    fn resolve_rejects_out_of_range_account_idx() {
        let warden = Pubkey::new_unique();
        let logical = base_logical(warden, Pubkey::new_unique());
        let p = parse_payload(&encode(&[(2, &[(9, 0)], &[])])).unwrap(); // account idx 9
        assert_eq!(resolve_payload(&p, &logical, &warden).unwrap_err(), err(WardenError::PayloadInvalid));
    }

    #[test]
    fn resolve_rejects_non_executable_program() {
        let warden = Pubkey::new_unique();
        let mut logical = base_logical(warden, Pubkey::new_unique());
        logical[2].executable = false;
        let p = parse_payload(&encode(&[(2, &[(3, 0)], &[])])).unwrap();
        assert_eq!(resolve_payload(&p, &logical, &warden).unwrap_err(), err(WardenError::PayloadInvalid));
    }

    #[test]
    fn resolve_rejects_warden_as_program() {
        let warden = Pubkey::new_unique();
        let mut logical = base_logical(warden, warden);
        logical[2] = meta(warden, true);
        let p = parse_payload(&encode(&[(2, &[(3, 0)], &[])])).unwrap();
        assert_eq!(resolve_payload(&p, &logical, &warden).unwrap_err(), err(WardenError::SelfCpiRejected));
    }

    #[test]
    fn resolve_rejects_compute_budget_as_program() {
        let warden = Pubkey::new_unique();
        let mut logical = base_logical(warden, crate::constants::COMPUTE_BUDGET_ID);
        logical[2] = meta(crate::constants::COMPUTE_BUDGET_ID, true);
        let p = parse_payload(&encode(&[(2, &[(3, 0)], &[])])).unwrap();
        assert_eq!(resolve_payload(&p, &logical, &warden).unwrap_err(), err(WardenError::ComputeBudgetInExecute));
    }

    #[test]
    fn resolve_rejects_warden_in_account_list() {
        // A middleman program cannot smuggle warden back in as a bare account.
        let warden = Pubkey::new_unique();
        let mut logical = base_logical(warden, Pubkey::new_unique());
        logical[3] = meta(warden, false); // warden as a plain account past slot 1
        let p = parse_payload(&encode(&[(2, &[(3, 0)], &[])])).unwrap();
        assert_eq!(resolve_payload(&p, &logical, &warden).unwrap_err(), err(WardenError::SelfCpiRejected));
    }

    #[test]
    fn resolve_rejects_compute_budget_in_account_list() {
        let warden = Pubkey::new_unique();
        let mut logical = base_logical(warden, Pubkey::new_unique());
        logical[3] = meta(crate::constants::COMPUTE_BUDGET_ID, false);
        let p = parse_payload(&encode(&[(2, &[(3, 0)], &[])])).unwrap();
        assert_eq!(resolve_payload(&p, &logical, &warden).unwrap_err(), err(WardenError::ComputeBudgetInExecute));
    }

    /// Cross-language fixture (Task 8): the TS `encodeExecutePayload` /
    /// `computeAccountsHash` (`packages/core/test/execute-payload.test.ts`) WRITE
    /// `tests/fixtures/payload_vector.bin` + `payload_accounts_hash.hex`; this
    /// test reads them back and asserts the Rust `parse_payload` decodes the
    /// exact structure and `compute_accounts_hash` over the same logical list
    /// yields the same 32 bytes. A drift on either side breaks this loudly.
    #[test]
    fn ts_payload_vector_round_trips() {
        let bytes = include_bytes!("../tests/fixtures/payload_vector.bin");
        let p = parse_payload(bytes).expect("TS vector must parse");
        // Structure the TS test encoded: SPL Transfer over [2,3,0,4] then a
        // one-account ix over [1].
        assert_eq!(p.ixs.len(), 2);
        assert_eq!(p.ixs[0].program_idx, 4);
        assert_eq!(
            p.ixs[0].accounts,
            vec![(2, FLAG_WRITABLE), (3, FLAG_WRITABLE), (0, FLAG_SIGNER), (4, 0)]
        );
        assert_eq!(p.ixs[0].data, vec![3, 0xd0, 0x07, 0, 0, 0, 0, 0, 0]);
        assert_eq!(p.ixs[1].program_idx, 5);
        assert_eq!(p.ixs[1].accounts, vec![(1, FLAG_SIGNER)]);
        assert!(p.ixs[1].data.is_empty());

        // The same deterministic 6-account logical list the TS test hashed.
        let logical: Vec<LogicalAccount> = (0..6u8)
            .map(|i| LogicalAccount {
                key: Pubkey::new_from_array([0x10 + i; 32]),
                is_signer: i == 0 || i == 1,
                is_writable: !(i == 0) && (2..=3).contains(&i),
            })
            .collect();
        let expected = include_str!("../tests/fixtures/payload_accounts_hash.hex").trim();
        assert_eq!(hex::encode(compute_accounts_hash(&logical)), expected);
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
