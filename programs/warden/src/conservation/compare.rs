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
//! on is compared independently of any token account (round 1, Codex C1).
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
    DANGER_NEVER_ALLOWLISTABLE, DANGER_TRANSFER_FEE, NATIVE_MINT, TOKEN_STATE_INITIALIZED,
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
            handle_close(intent, b, a, bt, vault, &mut net)?;
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

        // (9) The amount.
        account_amount(&mut net, bt, at)?;
    }

    // Every intent must have been consumed exactly once. A leftover is a
    // duplicate, or names an account outside the snapshot set, or names an
    // account that was not a vault-owned token account — all desyncs.
    require!(
        close_used.iter().all(|used| *used),
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
            && am.decimals == bm.decimals
            && am.is_initialized == bm.is_initialized
            && am.dangerous_ext == bm.dangerous_ext
            && am.program == bm.program
            && am.tlv_hash == bm.tlv_hash
            && a.owner_program == b.owner_program
            && a.data_len == b.data_len;
        require!(identical, WardenError::ConservationViolated);
        // `supply` is still excluded: spec §5.2 rule 2a, re-confirmed in the
        // round-1 adjudication. A legitimate mint/burn changes it.
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
fn handle_close(
    intent: &CloseIntent,
    b: &Snap,
    a: &Snap,
    bt: &TokenSnap,
    vault: &Pubkey,
    net: &mut Netter,
) -> Result<()> {
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

    if intent.destination == *vault {
        // Rule 4a: the rent arrives as an increase in the PDA's own lamports,
        // which the SOL equation already sees. Adding it here as well would
        // double-count it.
    } else {
        // Rule 4a's **backstop**. The decoder rejects a non-vault destination
        // before the CPI ever runs (`DenyListed`), so reaching this line means
        // the floor did not fire — the two controls are deliberately redundant
        // and neither may be the only one. Charge the whole rent as SOL
        // outflow.
        net.add_sol_out(b.lamports)?;
    }
    Ok(())
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

    // Every authority field, byte for byte. `supply` is deliberately absent —
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
fn account_amount(net: &mut Netter, bt: &TokenSnap, at: &TokenSnap) -> Result<()> {
    let native = bt.mint == NATIVE_MINT;
    if at.amount < bt.amount {
        let d = bt.amount.checked_sub(at.amount).ok_or(WardenError::Overflow)?;
        if native {
            net.add_sol_out(d)?;
        } else {
            net.add_mint_out(&bt.mint, d)?;
        }
    } else {
        let d = at.amount.checked_sub(bt.amount).ok_or(WardenError::Overflow)?;
        if native {
            net.add_sol_in(d)?;
        } else {
            net.add_mint_in(&bt.mint, d)?;
        }
    }
    Ok(())
}
