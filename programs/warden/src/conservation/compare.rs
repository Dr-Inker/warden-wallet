//! Before/after comparison and value accounting (spec §5.2 rules 2, 2a, 3, 4,
//! 4a, 5).
//!
//! ## Order of checks is part of the contract
//!
//! Per account, in this order, so a given fixture always fails on the same
//! rule and a test asserting an error code is asserting something stable:
//!
//! 1. same key at the same index (the arrays are positional);
//! 2. **runtime program owner** rules — warden-owned writable
//!    (`SelfCpiRejected`), then vault-owned non-token writable
//!    (`UnsupportedAccountKind`). Both are decided on `owner_program`, before
//!    any layout-dependent decode (`SWIG-ACC-C1`);
//! 3. did the account BECOME the vault's? (round 1, Codex C2) —
//!    `NewVaultAccountRejected`;
//! 4. is this a vault-owned token account BEFORE? If not, it is ignored
//!    entirely — a stranger's account changing is none of our business;
//! 5. the mint rules (presence, danger extensions, authority identity), which
//!    since round 1 run BEFORE the close branch and are NOT gated on
//!    `is_writable`;
//! 6. a decoded [`CloseIntent`] for this exact key, or the account must have
//!    survived;
//! 7. field identity, then the after-state policy, then the before-state
//!    policy;
//! 8. lamports unchanged, for non-native accounts (round 1, Codex C4);
//! 9. the amount, into the netter.
//!
//! Two whole-list checks run before any of that: duplicate pubkeys are
//! rejected (round 1, Codex C3), and every mint the vault holds an authority
//! on is compared independently of any token account — including its lamports
//! (round 1 Codex C1, round 2 for the lamports).
//!
//! Two more run after: every [`CloseIntent`] must have been consumed exactly
//! once, and the PDA's lamport gain must cover every vault-destination close's
//! `lamports_before` in full (round 2, Codex — see [`handle_close`]).
//!
//! ## What "vault-owned" means here, and why it is decided in ONE place
//!
//! `before[i].token.owner == *vault` — the **token-level** authority, not the
//! runtime owner. This is the only definition in the crate; `snapshot` is a
//! pure decode precisely so that this predicate cannot drift into two.
//!
//! ## Closes are told, never inferred
//!
//! Spec §5.2 rule 1a: the payload decoder is a *whitelist of closes it can
//! prove*, not a blacklist of closes it dislikes. It can only prove the four
//! vault-sweep conditions for a **direct** `CloseAccount` inner instruction;
//! a close nested inside another program's CPI is invisible to it, so it never
//! emits an intent for one, and the disappearance falls through to rule 2/3
//! here and is rejected. Nothing in this function may infer a close from a
//! disappearance — that inference *is* the vulnerability.
//!
//! Three further hardenings beyond the spec's letter, each of which can only
//! reject more, never allow more:
//!
//! - an intent whose `amount_before` disagrees with the BEFORE snapshot is a
//!   decoder/comparison **desync** and fails loudly;
//! - an intent naming an account that did **not** disappear fails loudly for
//!   the same reason;
//! - every intent must be consumed by exactly one account; a leftover intent
//!   (a duplicate, or one naming an account outside the snapshot set) fails.

use anchor_lang::prelude::*;

use crate::constants::{
    DANGER_NEVER_ALLOWLISTABLE, DANGER_TRANSFER_FEE, NATIVE_MINT, SPL_TOKEN_2022_ID, SPL_TOKEN_ID,
    SYSTEM_PROGRAM_ID, TOKEN_MULTISIG_LEN, TOKEN_MULTISIG_MAX_SIGNERS,
    TOKEN_MULTISIG_SIGNERS_OFFSET, TOKEN_STATE_INITIALIZED, UNSUPPORTED_WRITABLE_OWNERS,
};
use crate::errors::WardenError;

use super::accounting::{Netter, Outflow};
use super::{CloseIntent, MintSnap, Snap, TokenSnap};

/// Compare `before` against `after` and return what left the vault.
///
/// `before` and `after` MUST be the same accounts in the same order — they are
/// two passes over one `remaining_accounts` slice. `pda_lamports_before` /
/// `pda_lamports_after` are the SmartAccount PDA's **own** lamports, tracked
/// separately because the PDA is not in `remaining_accounts` (spec §5.2 rule
/// 2).
pub fn compare_and_account(
    before: &[Snap],
    after: &[Snap],
    vault: &Pubkey,
    closes: &[CloseIntent],
    pda_lamports_before: u64,
    pda_lamports_after: u64,
) -> Result<Outflow> {
    require!(before.len() == after.len(), WardenError::ConservationViolated);

    // Round 1 (Codex C3). The two arrays are compared POSITIONALLY, so the
    // same account appearing at two indices is snapshotted twice and its
    // balance change is counted twice — once as a decrease and once, from the
    // same pair of reads, as whatever the second slot saw. A vault ATA listed
    // twice while 100 tokens leave it nets to 50, not 100. Reject duplicates
    // outright rather than try to reconcile them: the SDK already asserts the
    // logical list is duplicate-free (spec 5.2, `accounts_hash`), so a
    // duplicate reaching here is a malformed payload.
    for (i, x) in before.iter().enumerate() {
        for (j, y) in before.iter().enumerate() {
            require!(i == j || x.key != y.key, WardenError::PayloadInvalid);
        }
    }

    // Round 1 (Codex C1). Every mint the vault holds an authority on is
    // validated INDEPENDENTLY of any token account, and before anything else
    // runs — a standalone writable mint used to be invisible to this function,
    // and the close branch used to `continue` past all mint validation.
    prescan_vault_mints(before, after, vault)?;

    let mut net = Netter::default();
    let mut close_used = vec![false; closes.len()];
    // Round 2 (Codex): Σ `lamports_before` over closes whose destination is the
    // PDA — the inflow the PDA MUST have received. See `handle_close`.
    let mut expected_close_credit: u64 = 0;

    // The PDA's own lamports. Both directions are recorded; the floor is
    // applied once, to the merged SOL figure, in `Netter::finish` — so a
    // vault-sweep close's returned rent genuinely offsets an outflow rather
    // than being silently discarded (spec §5.2 rule 4a).
    if pda_lamports_before > pda_lamports_after {
        net.add_sol_out(
            pda_lamports_before
                .checked_sub(pda_lamports_after)
                .ok_or(WardenError::Overflow)?,
        )?;
    } else {
        net.add_sol_in(
            pda_lamports_after
                .checked_sub(pda_lamports_before)
                .ok_or(WardenError::Overflow)?,
        )?;
    }

    for (i, b) in before.iter().enumerate() {
        // `before.len() == after.len()` was checked above, so this cannot fire.
        let a = after.get(i).ok_or(WardenError::ConservationViolated)?;
        require_keys_eq!(b.key, a.key, WardenError::ConservationViolated);

        // (2) Runtime-owner rules, decided before any layout decode.
        let writable = b.is_writable || a.is_writable;
        require!(
            !(writable && (b.owner_program == crate::ID || a.owner_program == crate::ID)),
            WardenError::SelfCpiRejected
        );
        require!(
            !(writable && (b.owner_program == *vault || a.owner_program == *vault)),
            WardenError::UnsupportedAccountKind
        );
        // GROK-EXP-03 / -05 (2026-08-22). Spec §5.2 rule 3's "no other
        // vault-owned account types may be writable (stake accounts, nonce
        // accounts, program-owned state…)" was keyed above on the runtime
        // owner being the vault PUBKEY — which a Stake / Vote / ProgramData
        // account never is (it is owned by its program; the PDA is only an
        // authority FIELD inside it). Step (4) then skipped it as "not a vault
        // token account", so `Stake::Withdraw` / `Vote::Withdraw` / BPF
        // `SetAuthority` under the PDA's read-only signer moved value this
        // function never saw and the caps never charged. Refuse those owners
        // writable outright, here AND before any CPI runs (the handlers call
        // `reject_unsupported_writable_owners` on the BEFORE snapshot).
        require!(
            !(writable
                && (UNSUPPORTED_WRITABLE_OWNERS.contains(&b.owner_program)
                    || UNSUPPORTED_WRITABLE_OWNERS.contains(&a.owner_program))),
            WardenError::UnsupportedAccountKind
        );
        // WRDF-0104 ROUND 2 (2026-08-23): the SECOND half of
        // `reject_unsupported_writable_owners`, which this positional check used
        // to omit entirely. That function refuses a writable System-owned account
        // carrying DATA (a durable nonce and any other unmodelled System state) —
        // a rule no owner-id list can express, because a nonce's owner is the
        // System program, the same owner as every ordinary wallet. The handlers
        // ran it on the BEFORE snapshot only, so an account that was zero-data
        // System state BEFORE and data-bearing System state AFTER — i.e. a
        // durable nonce CREATED inside the CPI window — passed the pre-CPI barrier
        // honestly and was then skipped by step (4) as "not a vault token
        // account". The claim in that function's docs that the rule is enforced
        // "again positionally in `compare_and_account`" was true of the owner-id
        // half and FALSE of this half. Both halves are now here, both keyed on
        // the same cross-snapshot `writable`, so the two barriers genuinely agree.
        //
        // The condition is deliberately duplicated rather than expressed by
        // calling `reject_unsupported_writable_owners(before)` +
        // `(after)`: that helper tests each snapshot's OWN `is_writable`, whereas
        // this loop uses the OR of the two, which is the stricter (and existing)
        // behaviour for the owner-id half. Keeping one rule shape for both halves
        // is what makes "the two barriers agree" checkable.
        require!(
            !(writable
                && ((b.owner_program == SYSTEM_PROGRAM_ID && b.data_len != 0)
                    || (a.owner_program == SYSTEM_PROGRAM_ID && a.data_len != 0))),
            WardenError::UnsupportedAccountKind
        );

        // (3) Round 1 (Codex C2). Classification used to be BEFORE-driven, so
        // an account that BECAME the vault's during the CPI was never examined
        // at all — a freshly created vault ATA carrying an attacker delegate,
        // or a stranger's account converted to vault ownership, both sailed
        // through. Anything that is the vault's AFTER must have been the same
        // vault-owned token account of the same mint under the same program
        // BEFORE; otherwise the vault just acquired an account whose history
        // this instruction cannot vouch for.
        //
        // (Account CREATION is always funded by the outer fee payer and
        // performed at transaction level, never inside `execute` — spec 5.2
        // rule 4 — so this rejects nothing a well-formed client does.)
        if let Some(at) = a.token.as_ref().filter(|t| t.owner == *vault) {
            let continuous = b
                .token
                .as_ref()
                .is_some_and(|t| t.owner == *vault && t.mint == at.mint)
                && b.owner_program == a.owner_program;
            require!(continuous, WardenError::NewVaultAccountRejected);
        }

        // (4) Only vault-owned token accounts are this function's business.
        let Some(bt) = b.token.as_ref().filter(|t| t.owner == *vault) else {
            continue;
        };

        // (5) The mint rules, BEFORE the close branch (Codex C1) and NOT gated
        // on `is_writable` (Codex C1 / adjudication 3). Gating on writable let
        // a caller opt out of the danger-extension and authority checks simply
        // by passing the vault ATA read-only, and running them after the close
        // branch let a CPI close a zero-balance ATA and rewrite its mint in the
        // same instruction.
        let bm = find_mint(before, &bt.mint)?;
        let am = find_mint(after, &bt.mint)?;
        check_mint(bm, am)?;

        // (6) A decoded close intent, or the account must have survived.
        if let Some(j) = first_unused_intent(closes, &close_used, &b.key) {
            let intent = closes.get(j).ok_or(WardenError::ConservationViolated)?;
            if let Some(used) = close_used.get_mut(j) {
                *used = true;
            }
            expected_close_credit = expected_close_credit
                .checked_add(handle_close(intent, b, a, bt, vault, &mut net)?)
                .ok_or(WardenError::Overflow)?;
            continue;
        }

        let at = a.token.as_ref().ok_or(WardenError::ConservationViolated)?;

        // (7) Field identity: everything except `amount`.
        let identical = a.owner_program == b.owner_program
            && a.data_len == b.data_len
            && at.mint == bt.mint
            && at.owner == bt.owner
            && at.delegate == bt.delegate
            && at.delegated_amount == bt.delegated_amount
            && at.close_authority == bt.close_authority
            && at.state == bt.state
            && at.is_native == bt.is_native
            && at.tlv_hash == bt.tlv_hash
            && at.program == bt.program;
        require!(identical, WardenError::ConservationViolated);

        // ...and policy, in BOTH directions. `delegate`/`close_authority` are
        // checked on the BEFORE snapshot too: a pre-existing delegate is a
        // standing withdrawal right that this instruction would otherwise
        // ratify, and a delegate the CPI *cleared* would read `None` after.
        require!(
            bt.delegate.is_none()
                && at.delegate.is_none()
                && bt.close_authority.is_none()
                && at.close_authority.is_none()
                && at.state == TOKEN_STATE_INITIALIZED,
            WardenError::ConservationViolated
        );

        // (8) Round 1 (Codex C4). Token-2022's `WithdrawExcessLamports`
        // (tag 38) moves an account's lamports while leaving every field this
        // function compares byte-identical, so a vault ATA over-funded with
        // rent could be drained invisibly. For a NON-native account the
        // lamports are not backed by anything the token layout records, so the
        // only correct statement is that they must not move at all. For a
        // native (wrapped-SOL) account they DO back `amount`, which the SOL
        // equation already counts — `is_native`, not the mint key, is the
        // field that says so.
        if bt.is_native.is_none() {
            require!(a.lamports == b.lamports, WardenError::ConservationViolated);
        }

        // (9) The amount — for a native account, the LAMPORTS (WRDF-0011).
        account_amount(&mut net, b, a, bt, at)?;
    }

    // Every intent must have been consumed exactly once. A leftover is a
    // duplicate, or names an account outside the snapshot set, or names an
    // account that was not a vault-owned token account — all desyncs.
    require!(
        close_used.iter().all(|used| *used),
        WardenError::ConservationViolated
    );

    // Round 2 (Codex): the PDA must actually have received every lamport a
    // vault-destination close was supposed to return. The netting in
    // `handle_close` alone would only turn a shortfall into a *capped* SOL
    // outflow; this makes it a reject, which is the right verdict because a
    // short close means value left by a path the equation cannot attribute.
    //
    // This is a sound bound rather than an approximation: the SmartAccount PDA
    // may never be writable to a CPI target (spec §5.2 rule 3, enforced above
    // as `SelfCpiRejected`) and is owned by this program, so **no inner CPI can
    // debit it**. During the CPI window its lamports can only rise, and the
    // rise is therefore entirely attributable to credits — of which the closes
    // are the ones we can name.
    let pda_gain = pda_lamports_after.saturating_sub(pda_lamports_before);
    require!(
        pda_gain >= expected_close_credit,
        WardenError::ConservationViolated
    );

    Ok(net.finish())
}

/// Round 1 (Codex C1): validate every mint the vault holds an authority on,
/// independently of whether any vault token account of it is in the list.
///
/// Two holes this closes. First, a **standalone writable mint**: the vault can
/// be a mint's `mint_authority` without holding a single token of it, and
/// handing that authority away is exactly the irreversible loss the deny-list's
/// `SetAuthority` row exists to prevent — but no token account meant no check.
/// Second, **ordering**: mint validation used to sit after the close branch,
/// so closing the (zero-balance) vault ATA in the same instruction skipped it.
///
/// Unlike [`check_mint`] — which serves mints reached *through* a vault token
/// account — this comparison **does** include the TLV tail hash. The tail-hash
/// false positive spec §5.2 rule 2a warns about is a legitimate `transfer_fee`
/// accrual, and that can only occur on a fee mint; a fee mint backing a vault
/// token account is already rejected outright in 1B
/// (`TransferFeeMintUnsupported`). The residue is a vault-controlled fee mint
/// with **no** vault token account in the list, whose withheld-fee accrual will
/// reject in 1B and must move to a field-wise comparison in 1C when fee mints
/// become legal. Recorded in `docs/program/PHASE1B-MEASUREMENTS.md`.
fn prescan_vault_mints(before: &[Snap], after: &[Snap], vault: &Pubkey) -> Result<()> {
    for (i, b) in before.iter().enumerate() {
        let a = after.get(i).ok_or(WardenError::ConservationViolated)?;
        // WRDF-0012 (rounds 7 & 8): `holds_authority` sees only the FIVE
        // modeled authorities, and the `check_mint` danger gate is only reached
        // for a mint backing a vault token account. So a STANDALONE mint whose
        // vault-held authority lives in an extension `holds_authority` does not
        // model is never scrutinised — and that is true both for an UNMODELED
        // extension (round 7: Pausable, MetadataPointer, …) AND for a
        // RECOGNIZED danger extension whose authority field we do not extract
        // (round 8: `TransferHook` type 14, the confidential-transfer family,
        // …). `PermanentDelegate` (type 12) WAS in that second list until
        // WRDF-0105 round 3 extracted its delegate pubkey; it is now a modelled
        // role, so a read-only such mint is caught by `holds_authority` (and by
        // `execute`'s gate) rather than only by the writable rule below. Fail
        // closed here for a WRITABLE mint carrying EITHER
        // class — a read-only mint cannot be mutated in this transaction, so a
        // normal swap passing a stranger mint read-only is unaffected.
        let unmodelable = |m: &crate::conservation::MintSnap| {
            m.has_unrecognized_ext || (m.dangerous_ext & !DANGER_TRANSFER_FEE) != 0
        };
        let writable_unmodelable_mint = (b.is_writable || a.is_writable)
            && (b.mint.as_ref().is_some_and(unmodelable) || a.mint.as_ref().is_some_and(unmodelable));
        if writable_unmodelable_mint {
            return Err(WardenError::Token2022ExtensionRejected.into());
        }
        let controlled = b.mint.as_ref().is_some_and(|m| m.holds_authority(vault))
            || a.mint.as_ref().is_some_and(|m| m.holds_authority(vault));
        if !controlled {
            continue;
        }
        // A vault-controlled mint that appears from nowhere, disappears, or
        // stops parsing is a reject in either direction.
        let bm = b.mint.as_ref().ok_or(WardenError::ConservationViolated)?;
        let am = a.mint.as_ref().ok_or(WardenError::ConservationViolated)?;
        let identical = am.mint_authority == bm.mint_authority
            && am.freeze_authority == bm.freeze_authority
            && am.transfer_fee_config_authority == bm.transfer_fee_config_authority
            && am.withdraw_withheld_authority == bm.withdraw_withheld_authority
            // WRDF-0105 round 3: `permanent_delegate` is an AUTHORITY field —
            // the strongest of the five, since its holder may move or burn from
            // every token account of the mint. It is compared here beside the
            // other four so it cannot be reassigned under the vault's nose.
            // DEFENCE IN DEPTH, not a new guarantee: this function (unlike
            // `check_mint`) already compares `tlv_hash`, and the delegate lives
            // in that hashed tail, so the tail hash already pinned these bytes.
            // The explicit field survives a future 1C relaxation of the tail
            // hash (which §5.2 rule 2a anticipates, for `withheld_amount`
            // accrual) — that relaxation must not silently unpin the delegate.
            && am.permanent_delegate == bm.permanent_delegate
            && am.decimals == bm.decimals
            && am.is_initialized == bm.is_initialized
            && am.dangerous_ext == bm.dangerous_ext
            && am.program == bm.program
            && am.tlv_hash == bm.tlv_hash
            && a.owner_program == b.owner_program
            && a.data_len == b.data_len
            // Round 2 (Codex): `WithdrawExcessLamports` (tag 38) drains a
            // MINT's over-funded rent just as happily as a token account's,
            // and every field above survives it untouched. A mint has no
            // `amount` to back its lamports, so the only correct statement is
            // that they must not move. Scoped to mints the PDA holds an
            // authority on — a stranger's mint passing through is not ours.
            && a.lamports == b.lamports
            // GROK-EXP-02 / -05 (2026-08-22): `supply` is now compared too, for
            // a mint the vault CONTROLS. Spec §5.2 rule 2a excluded it so "a
            // legitimate mint/burn through an allow-listed adapter" could
            // change it — but 1B ships no such adapter, and the exclusion was
            // exactly the unmetered-issuance hole: a `MintTo` under the PDA's
            // `mint_authority` to a stranger's account changes no vault token
            // account, so nothing else in this function could see it (the
            // direct case is also deny-listed; this catches it NESTED inside a
            // Jupiter hop or a middleman CPI). With this, every field of a
            // vault-controlled mint is frozen across the CPI window. A 1C mint
            // adapter must relax this deliberately, per-opcode, not by
            // deleting the line. `check_mint` (mints reached THROUGH a vault
            // token account, which the vault need not control) still excludes
            // supply: a stranger minting their own token is not ours.
            && am.supply == bm.supply;
        require!(identical, WardenError::ConservationViolated);
    }
    Ok(())
}

/// GROK-EXP-03 / -05 + WRDF-0104: refuse any WRITABLE snapshot whose runtime
/// owner is a program whose accounts carry value or authority conservation does
/// not model — Stake, Vote, BPF Upgradeable Loader, and Loader-v4
/// (`UNSUPPORTED_WRITABLE_OWNERS`) — plus any WRITABLE System-owned account that
/// carries data (a durable nonce and other unmodelled System state; a plain
/// zero-data wallet is allowed). Loader-v4's `SetProgramLength` and a durable
/// nonce's `WithdrawNonceAccount` are the LZR-ACC-C2 unmetered-value shapes the
/// three-owner list left open.
/// Called by the handlers on the BEFORE snapshot so the reject lands before a
/// CPI runs (a test can then assert OUR error code without needing the foreign
/// program's instruction to succeed). Read-only accounts are untouched: a CPI
/// cannot debit or mutate a read-only account, so a stake account passed
/// read-only is harmless (and common — Jupiter routes carry read-only program
/// accounts).
///
/// ## The post-CPI barrier (WRDF-0104 round 2, 2026-08-23)
///
/// [`compare_and_account`] re-applies BOTH rules positionally over the
/// before/after pair, so an account that BECAME unsupported state during the CPI
/// is caught too. That claim used to be written here and was only HALF true: the
/// comparison carried the `UNSUPPORTED_WRITABLE_OWNERS` id check but not the
/// System-owned `data_len` check, which meant a durable nonce CREATED inside the
/// CPI window (zero-data System BEFORE, data-bearing System AFTER) cleared this
/// function honestly and was then ignored downstream as "not a vault token
/// account". Both halves now live in `compare_and_account`'s step (2); this
/// function is the pre-CPI copy. Keep them in step — the regressions
/// `wrdf0104_loader_v4_and_data_bearing_system_writable_rejected` and
/// `wrdf0104_system_state_transitions_are_rejected_positionally` assert each
/// case against BOTH entry points precisely so a future edit to one is caught.
pub fn reject_unsupported_writable_owners(snaps: &[Snap]) -> Result<()> {
    for s in snaps {
        require!(
            !(s.is_writable && UNSUPPORTED_WRITABLE_OWNERS.contains(&s.owner_program)),
            WardenError::UnsupportedAccountKind
        );
        // WRDF-0104 (LZR-ACC-C2): a durable-nonce account is System-owned, so no
        // owner-id rule above can name it — yet `WithdrawNonceAccount` drains its
        // lamports under a signer nonce-authority the PDA could hold, moving value
        // this function's caller never meters (conservation sees no vault delta).
        // Fail closed on the shape instead: a plain System wallet or a
        // to-be-allocated destination carries NO data, so any WRITABLE System-owned
        // account that DOES carry data is refused. Durable nonces (80 B) and any
        // other System-owned state 1B does not model fall inside this narrow net;
        // the common zero-data wallet is untouched.
        require!(
            !(s.is_writable && s.owner_program == SYSTEM_PROGRAM_ID && s.data_len != 0),
            WardenError::UnsupportedAccountKind
        );
    }
    Ok(())
}

/// Fable audit P-1 (2026-09-02): refuse any token account in `snaps` that the
/// vault does NOT own (token-level `owner != vault`) but IS the approved
/// `delegate` of.
///
/// Every rule in this module keys on `TokenSnap::owner == vault` — a foreign
/// token account is skipped by the comparison by design, and `outflow` never
/// sees it. The token program, however, accepts an account's `delegate` as the
/// authority of `Transfer` / `TransferChecked` / `Burn` / `BurnChecked` for up
/// to `delegated_amount`, and `Approve` is the account OWNER's call: any third
/// party can name the SmartAccount PDA as its delegate. `execute` then signs as
/// the PDA for a transfer or burn out of that account — passing the default
/// registry's `ROLE_VAULT_SIGNER` check (authority position is the vault
/// signer), naming no deny-listed tag (3/12/8/15 are all `SplTokenOp::Other`)
/// and debiting no bucket, on the SESSION path. WRDF-0105 closed the five
/// MINT-level roles the PDA can hold; this is the ACCOUNT-level one.
///
/// Called on the BEFORE snapshot only, pre-CPI, so the refusal precedes any
/// signed CPI. An AFTER re-application was tried and dropped as VOID, recorded
/// here so it is not re-added in good faith: the token program clears
/// `delegate` the moment `delegated_amount` reaches zero, so exactly the drain
/// shape — spend the whole approval — leaves no trace in the AFTER snapshot
/// (the harness proved it: a mid-payload `Approve(9_000)` + `Transfer(9_000)`
/// passed the AFTER check). A delegation can only be CREATED inside the payload
/// window by a signer the payload already carries — logical 1, the submitter,
/// approving its OWN account — which is not a third-party loss, so the entry
/// check is the whole rule. `delegated_amount` is deliberately not consulted: a
/// zero-amount delegation grants nothing today, but the field is not what the
/// rule is about, and a value-free reject is the cheaper mistake.
pub fn reject_vault_delegated_foreign_accounts(snaps: &[Snap], vault: &Pubkey) -> Result<()> {
    for s in snaps {
        if let Some(t) = s.token.as_ref() {
            require!(
                !(t.owner != *vault && t.delegate == Some(*vault)),
                WardenError::VaultDelegatedForeignAccountInPayload
            );
        }
    }
    Ok(())
}

/// Codex WRDF-0110 (2026-09-02): does a token-program-owned buffer of exactly
/// `Multisig::LEN` name `member` among its live signers?
///
/// Layout (`spl_token::state::Multisig`, identical in Token-2022): `m: u8`,
/// `n: u8`, `is_initialized: u8`, then `signers: [Pubkey; 11]`. Only the first
/// `n` entries are live; the token program's `validate_owner` walks exactly
/// `signers[..n]`, so the same slice is read here — a stale key in an unused
/// slot is not an authority. `n` is clamped to 11 rather than trusted, and an
/// uninitialized multisig is not an authority to the token program either
/// (`Multisig::unpack` refuses it), so it is not one here.
///
/// A pure byte predicate on purpose: it needs no `Snap`, so the heap-bound
/// execute path can run it over every logical account without allocating,
/// and `snapshot_one`'s 56 call sites keep their signature.
pub fn multisig_names_member(owner_program: &Pubkey, data: &[u8], member: &Pubkey) -> bool {
    if *owner_program != SPL_TOKEN_ID && *owner_program != SPL_TOKEN_2022_ID {
        return false;
    }
    if data.len() != TOKEN_MULTISIG_LEN {
        return false;
    }
    let live = match (data.get(1), data.get(2)) {
        (Some(n), Some(1)) => usize::from(*n).min(TOKEN_MULTISIG_MAX_SIGNERS),
        _ => return false,
    };
    (0..live).any(|i| {
        let start = TOKEN_MULTISIG_SIGNERS_OFFSET.saturating_add(i.saturating_mul(32));
        data.get(start..start.saturating_add(32)) == Some(member.as_ref())
    })
}

/// Codex WRDF-0110 (2026-09-02): refuse any account in `accts` that is a
/// token-program `Multisig` naming the vault PDA among its members.
///
/// The token program accepts a multisig as the owner, delegate, close, mint or
/// freeze authority of anything, satisfied by `m` of its members signing —
/// and the PDA's forwarded signature is one such member signature. That is
/// the third authority shape the PDA can satisfy, after the five mint roles
/// (WRDF-0105, err 6076) and the account delegate (P-1, err 6078): a stranger
/// makes a 1-of-1 multisig with the vault as its member, owns a token account
/// by it, and `execute` signs a Transfer out of it that conservation skips
/// (the source is not vault-owned) and no cap meters. The snapshot could not
/// see it because a 355-byte account is deliberately classified as neither a
/// mint nor a token account (`snapshot::classify`); its `token_parse_failed`
/// is only fatal for accounts that were vault-owned before.
///
/// Pre-CPI, BEFORE only, over the whole logical list including the signer
/// slot. Membership is a property of the multisig account, not of the
/// payload, so a payload that never references it is refused too — same
/// discipline as the mint gate. A multisig whose members are all strangers
/// is untouched (`codex_wrdf0110_stranger_multisig_in_list_still_allowed`).
pub fn reject_vault_multisig_members(accts: &[AccountInfo], vault: &Pubkey) -> Result<()> {
    for ai in accts {
        let data = ai.try_borrow_data()?;
        require!(
            !multisig_names_member(ai.owner, &data, vault),
            WardenError::VaultMultisigMemberInPayload
        );
    }
    Ok(())
}

/// First not-yet-consumed intent naming `key`.
fn first_unused_intent(closes: &[CloseIntent], used: &[bool], key: &Pubkey) -> Option<usize> {
    for (j, c) in closes.iter().enumerate() {
        if c.account == *key && !used.get(j).copied().unwrap_or(true) {
            return Some(j);
        }
    }
    None
}

/// The rule-1a vault-sweep exception, plus rule 4a's backstop.
///
/// Returns the lamport inflow the PDA is **required** to have received on
/// account of this close (`lamports_before` for a vault-destination close, 0
/// otherwise); the caller checks the total against the PDA's actual gain.
///
/// ## Round 2 (Codex): the close path is no longer exempt from the lamport rule
///
/// Step 8's "lamports must not move on a non-native vault token account" sat
/// *after* this branch, and this branch `continue`d — so `WithdrawExcessLamports`
/// (tag 38) could send an over-funded ATA's excess rent to an attacker and the
/// permitted zero-balance `CloseAccount` to the PDA would then sail through,
/// because the token `amount` really was 0 and the destination really was the
/// PDA. The close path cannot reuse step 8's equality (the account is *gone*
/// AFTER, so `a.lamports` is 0 by construction), so it uses the accounting
/// identity instead: **debit `lamports_before` unconditionally and let the
/// PDA's own credit pay it back**.
///
/// That single rule now covers both rule-4a cases without a special case:
/// - **vault destination** — debit `lamports_before`, and the PDA's inflow
///   (already counted by the SOL equation) cancels it exactly, netting zero on
///   the honest path. This is rule 4a's "nothing extra is added" restated as a
///   matched pair rather than as an omission — and unlike an omission, it
///   *detects* the mismatch instead of assuming it away.
/// - **non-vault destination** — the same debit, with nothing to cancel it, is
///   exactly the rule-4a backstop that was already here.
fn handle_close(
    intent: &CloseIntent,
    b: &Snap,
    a: &Snap,
    bt: &TokenSnap,
    vault: &Pubkey,
    net: &mut Netter,
) -> Result<u64> {
    // The account must actually be gone. An intent for a surviving account is
    // a decoder/comparison desync, and letting it pass would skip every field
    // check for that account.
    require!(
        !a.exists && a.token.is_none(),
        WardenError::ConservationViolated
    );
    // The decoder's view of the balance must equal the snapshot's.
    require!(
        intent.amount_before == bt.amount,
        WardenError::ConservationViolated
    );
    // Rule 1a condition 2: nothing of value is swept, only rent.
    require!(bt.amount == 0, WardenError::ConservationViolated);
    // Rule 1a condition 4: never the SmartAccount PDA itself. (It cannot be a
    // mint here — `bt` is a token account.)
    require!(b.key != *vault, WardenError::ConservationViolated);

    // Every closed account's lamports left the account: debit them, always.
    // For a vault-destination close the PDA's matching credit cancels this
    // exactly; for any other destination nothing cancels it, which is rule 4a's
    // backstop. (The decoder rejects a non-vault destination before the CPI
    // ever runs — `DenyListed` — so the two controls stay deliberately
    // redundant and neither is ever the only one.)
    net.add_sol_out(b.lamports)?;
    Ok(if intent.destination == *vault { b.lamports } else { 0 })
}

/// The mint of a vault-owned token account must be in the snapshot set and
/// must decode as a mint (spec §5.2 rule 2a, presence rule — ungated on
/// `is_writable` since round 1).
fn find_mint<'a>(snaps: &'a [Snap], mint: &Pubkey) -> Result<&'a MintSnap> {
    snaps
        .iter()
        .find(|s| s.key == *mint)
        .and_then(|s| s.mint.as_ref())
        .ok_or_else(|| WardenError::MintMissing.into())
}

/// Danger extensions (rule 5) and authority identity (rule 2a).
pub(crate) fn check_mint(bm: &MintSnap, am: &MintSnap) -> Result<()> {
    // Checked on BOTH snapshots: an extension *added* mid-instruction is
    // exactly as fatal as one that was there all along.
    let danger = bm.dangerous_ext | am.dangerous_ext;
    require!(
        (danger & DANGER_NEVER_ALLOWLISTABLE) == 0,
        WardenError::Token2022ExtensionRejected
    );
    require!(
        (danger & DANGER_TRANSFER_FEE) == 0,
        WardenError::TransferFeeMintUnsupported
    );
    // WRDF-0012: an extension the scan does not model may carry a reassignable
    // authority no compared field would see change (tail hash is deliberately
    // never compared for mints). 1B fails closed on such mints; 1C may widen
    // with per-type extraction. Same error code — 1C can split it if needed.
    require!(
        !(bm.has_unrecognized_ext || am.has_unrecognized_ext),
        WardenError::Token2022ExtensionRejected
    );

    // Every authority field, byte for byte — INCLUDING `permanent_delegate`
    // (WRDF-0105 round 3), so the claim in this sentence stays true. That
    // comparison is unreachable in 1B: `DANGER_PERMANENT_DELEGATE` is part of
    // `DANGER_NEVER_ALLOWLISTABLE`, so any mint carrying the extension is
    // already refused by the first `require!` above. It is written anyway so a
    // 1C widening of the danger set cannot silently leave the fifth role
    // uncompared. `supply` is deliberately absent —
    // spec §5.2 rule 2a: a legitimate mint/burn through an allow-listed
    // adapter changes it, so it is recorded but is not by itself a reject.
    // `tlv_hash` is deliberately absent too: a legitimate transfer-fee accrual
    // mutates `withheld_amount` inside the same tail, so a tail-hash
    // comparison would false-positive on the happy path. The authorities above
    // are extracted BY TLV TYPE for that exact reason.
    let identical = am.mint_authority == bm.mint_authority
        && am.freeze_authority == bm.freeze_authority
        && am.transfer_fee_config_authority == bm.transfer_fee_config_authority
        && am.withdraw_withheld_authority == bm.withdraw_withheld_authority
        && am.permanent_delegate == bm.permanent_delegate
        && am.decimals == bm.decimals
        && am.is_initialized == bm.is_initialized
        && am.dangerous_ext == bm.dangerous_ext
        && am.program == bm.program;
    require!(identical, WardenError::ConservationViolated);
    Ok(())
}

/// Route the balance change into the SOL lane (wrapped SOL) or the per-mint
/// lane. A WSOL entry must never appear in `by_mint`: `NATIVE_MINT` is also
/// the cap-lookup key for native SOL, so two entries would debit one bucket
/// twice for one movement.
fn account_amount(net: &mut Netter, b: &Snap, a: &Snap, bt: &TokenSnap, at: &TokenSnap) -> Result<()> {
    // Native is decided by `is_native` — the token program's own, unforgeable
    // marker (WRDF-0008): Token-2022 wraps SOL under its own mint
    // (`NATIVE_MINT_2022`), so a mint-key-only test mis-lanes it. And the two
    // signals must AGREE: under either real token program, `is_native` is set
    // if and only if the mint is that program's native mint, so any mismatch
    // is an impossible-on-chain shape wearing a token account's layout —
    // rejected, never measured. This is also what keeps a native mint key out
    // of `by_mint`, where it would collide with the SOL cap-lookup key.
    let native_mint_key =
        bt.mint == NATIVE_MINT || bt.mint == crate::constants::NATIVE_MINT_2022;
    let native = bt.is_native.is_some();
    require!(native == native_mint_key, WardenError::ConservationViolated);
    if native {
        // WRDF-0011: on a native account, `amount` is a CACHED VIEW of
        // `lamports - rent_reserve` that only moves when something calls
        // `SyncNative`. The lamports are the value. Measuring `amount` let a
        // `SyncNative` + `Transfer` pair drain a legally-donated (unsynced)
        // lamport balance with `amount` ending exactly where it began. The
        // exemption from rule (8)'s lamports-unchanged requirement is matched
        // here by counting the lamport delta itself.
        if a.lamports < b.lamports {
            net.add_sol_out(b.lamports.checked_sub(a.lamports).ok_or(WardenError::Overflow)?)?;
        } else {
            net.add_sol_in(a.lamports.checked_sub(b.lamports).ok_or(WardenError::Overflow)?)?;
        }
        return Ok(());
    }
    if at.amount < bt.amount {
        net.add_mint_out(&bt.mint, bt.amount.checked_sub(at.amount).ok_or(WardenError::Overflow)?)?;
    } else {
        net.add_mint_in(&bt.mint, at.amount.checked_sub(bt.amount).ok_or(WardenError::Overflow)?)?;
    }
    Ok(())
}
