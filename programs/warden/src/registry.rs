//! Registry lookup + per-adapter role validation (Phase 1B Task 3).
//!
//! `registry_allows` is the five-argument gate `execute` (Task 5) calls on the
//! session path: it is never a bare `(program, selector)` match. It (1) finds
//! the entry matching `(program, ix_data)`, (2) requires that entry to be a
//! member of the session's list, and (3) runs the entry's **role validator**
//! against the CPI's account metas. The account slice is required — a match
//! alone cannot prove the vault PDA signs, or that the token program is present.
//!
//! The role validators here check what is decidable from `(ix_data, accounts)`
//! alone. The deeper, snapshot-dependent checks (a source is *the vault's* ATA,
//! conservation of value) belong to `execute`/`conservation`, which hold the
//! before/after state; Jupiter's validator is Task 6's. This split is
//! deliberate: this layer is a fast structural gate, not the value gate.

use anchor_lang::prelude::*;

use crate::constants::SPL_TOKEN_ID;
use crate::state::registry::Registry;

/// `role_rules` bit: the vault PDA must be the SPL Token **authority** (the
/// account at the instruction's authority position) AND sign — not merely appear
/// as some signer. The authority position is selector-specific: `Transfer(3)`
/// puts it at index 2 (`[source, dest, authority]`), `TransferChecked(12)` at
/// index 3 (`[source, mint, dest, authority]`). Checking only "the vault signs
/// somewhere" would accept a transfer of a multisig-owned account where the
/// vault is one of several signers but not the authority (WRDF-0035).
pub const ROLE_VAULT_SIGNER: u8 = 1 << 0;
/// `role_rules` bit: the SPL Token program must be present in the CPI accounts.
pub const ROLE_REQUIRES_TOKEN_PROGRAM: u8 = 1 << 1;

/// A minimal account meta, so `registry_allows` is testable without a full
/// `AccountInfo`. `execute` builds these from its instruction's account list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountMetaLike {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// The session-path adapter gate. Returns `true` iff `(program, ix_data)`
/// matches an entry that is a member of list `list_id` AND that entry's role
/// validator passes against `accounts` and `vault`.
///
/// `list_id == 0` ("no registry") denies every CPI — a session that wants to
/// call `execute` must carry a real list. A match outside the list is a deny.
pub fn registry_allows(
    reg: &Registry,
    list_id: u16,
    program: &Pubkey,
    ix_data: &[u8],
    accounts: &[AccountMetaLike],
    vault: &Pubkey,
) -> bool {
    if list_id == 0 {
        return false;
    }
    let Some(idx) = reg.find_entry(program, ix_data) else {
        return false;
    };
    if !reg.list_contains(list_id, idx) {
        return false;
    }
    let entry = &reg.entries[idx];
    role_validator_passes(
        entry.role_rules,
        &entry.program_id,
        &entry.selector[..entry.disc_len as usize],
        accounts,
        vault,
    )
}

/// The account index of the **authority** for a `(program, selector)` that
/// carries `ROLE_VAULT_SIGNER` — the position the vault PDA must occupy and
/// sign. Keyed by the PAIR, because the authority position is a property of the
/// specific adapter's account layout, not of a selector value alone (the
/// test-mutator's `transfer_out` sighash and SPL `Transfer` are unrelated
/// selectors that both put the authority at index 2). Every adapter that
/// carries `ROLE_VAULT_SIGNER` MUST be listed here; an unlisted one returns
/// `None` and is DENIED (fail closed, WRDF-0041) rather than guessing an index.
fn authority_index(program: &Pubkey, selector: &[u8]) -> Option<usize> {
    use crate::constants::{SYSTEM_PROGRAM_ID, TEST_MUTATOR_ID};
    if *program == SPL_TOKEN_ID {
        return match selector {
            [3] => Some(2),  // Transfer:        [source, dest, authority]
            [12] => Some(3), // TransferChecked: [source, mint, dest, authority]
            _ => None,
        };
    }
    if *program == SYSTEM_PROGRAM_ID && selector == [2, 0, 0, 0] {
        return Some(0); // Transfer: [from(authority), to]
    }
    if *program == TEST_MUTATOR_ID {
        // test-mutator `transfer_out`: [source, destination, authority, token_program].
        if selector == crate::registry_default::sighash("transfer_out") {
            return Some(2);
        }
    }
    None
}

/// The structural half of role validation (what `(program, selector, accounts,
/// vault)` can decide). The value half — that a source is *the vault's own* ATA,
/// and conservation of value — is `execute`/`conservation`'s (Task 5).
fn role_validator_passes(
    role_rules: u8,
    program: &Pubkey,
    selector: &[u8],
    accounts: &[AccountMetaLike],
    vault: &Pubkey,
) -> bool {
    if role_rules & ROLE_VAULT_SIGNER != 0 {
        // The vault must be the AUTHORITY at the adapter's authority position
        // AND sign there (WRDF-0035): "signs somewhere" would accept a
        // multisig-owned transfer where the vault is a co-signer, not the owner.
        // An adapter carrying ROLE_VAULT_SIGNER but not listed in
        // `authority_index` is DENIED (fail closed, WRDF-0041) — never guessed.
        let Some(i) = authority_index(program, selector) else {
            return false;
        };
        let ok = accounts.get(i).is_some_and(|a| a.pubkey == *vault && a.is_signer);
        if !ok {
            return false;
        }
    }
    if role_rules & ROLE_REQUIRES_TOKEN_PROGRAM != 0 {
        let has_token_program = accounts.iter().any(|a| a.pubkey == SPL_TOKEN_ID);
        if !has_token_program {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::registry::{ListMask, RegistryEntry, MAX_REGISTRY_ENTRIES, MAX_SELECTOR_LEN};

    fn pk(n: u8) -> Pubkey {
        let mut b = [0u8; 32];
        b[0] = n;
        Pubkey::new_from_array(b)
    }

    fn meta(pubkey: Pubkey, is_signer: bool, is_writable: bool) -> AccountMetaLike {
        AccountMetaLike { pubkey, is_signer, is_writable }
    }

    /// A registry with a single entry `(program, selector, role_rules)` placed
    /// in list 1.
    fn reg_with(program: Pubkey, selector: &[u8], role_rules: u8) -> Registry {
        let mut reg = Registry {
            version: 1,
            bump: 255,
            _pad: [0; 6],
            authority: pk(200),
            treasury: pk(201),
            n_entries: 1,
            _pad2: [0; 6],
            entries: core::array::from_fn(|_| RegistryEntry {
                program_id: Pubkey::default(),
                selector: [0; MAX_SELECTOR_LEN],
                disc_len: 0,
                role_rules: 0,
                _pad: [0; 6],
            }),
            lists: core::array::from_fn(|_| ListMask { bits: [0; 1] }),
            allocated_lists: 0,
            _reserved: [0; 255],
        };
        let mut sel = [0u8; MAX_SELECTOR_LEN];
        sel[..selector.len()].copy_from_slice(selector);
        reg.entries[0] = RegistryEntry {
            program_id: program,
            selector: sel,
            disc_len: selector.len() as u8,
            role_rules,
            _pad: [0; 6],
        };
        reg.lists[0].set(0); // list id 1 contains entry 0
        reg
    }

    #[test]
    fn list_zero_denies_everything() {
        let spl = pk(1);
        let reg = reg_with(spl, &[3], 0);
        assert!(!registry_allows(&reg, 0, &spl, &[3], &[], &pk(9)));
    }

    #[test]
    fn a_match_in_the_list_with_no_role_rules_passes() {
        let spl = pk(1);
        let reg = reg_with(spl, &[3], 0);
        assert!(registry_allows(&reg, 1, &spl, &[3, 0, 0], &[], &pk(9)));
    }

    #[test]
    fn a_match_outside_the_list_is_denied() {
        let spl = pk(1);
        let reg = reg_with(spl, &[3], 0);
        // entry 0 is only in list 1; list 2 does not contain it.
        assert!(!registry_allows(&reg, 2, &spl, &[3], &[], &pk(9)));
    }

    #[test]
    fn an_unknown_program_or_selector_is_denied() {
        let spl = pk(1);
        let reg = reg_with(spl, &[3], 0);
        assert!(!registry_allows(&reg, 1, &pk(2), &[3], &[], &pk(9)), "wrong program");
        assert!(!registry_allows(&reg, 1, &spl, &[4], &[], &pk(9)), "wrong selector");
    }

    #[test]
    fn role_vault_signer_requires_the_vault_at_the_authority_position() {
        // SPL Transfer(3): authority is index 2 ([source, dest, authority]).
        let spl = crate::constants::SPL_TOKEN_ID;
        let vault = pk(9);
        let reg = reg_with(spl, &[3], ROLE_VAULT_SIGNER);
        let src = meta(pk(5), false, true);
        let dst = meta(pk(6), false, true);
        // vault is the signing authority at index 2 → allow
        assert!(registry_allows(&reg, 1, &spl, &[3], &[src, dst, meta(vault, true, false)], &vault));
        // vault at the authority position but not signing → deny
        assert!(!registry_allows(&reg, 1, &spl, &[3], &[src, dst, meta(vault, false, false)], &vault));
        // a different authority → deny (even if the vault signs elsewhere)
        assert!(!registry_allows(&reg, 1, &spl, &[3], &[src, dst, meta(pk(8), true, false)], &vault));
    }

    #[test]
    fn a_multisig_transfer_with_the_vault_as_a_cosigner_not_the_authority_is_denied() {
        // WRDF-0035: the vault SIGNS but the authority (index 2) is a multisig,
        // so the transfer would move a multisig-owned account, not the vault's.
        // "vault signs somewhere" must NOT accept this.
        let spl = crate::constants::SPL_TOKEN_ID;
        let vault = pk(9);
        let multisig = pk(7);
        let reg = reg_with(spl, &[3], ROLE_VAULT_SIGNER | ROLE_REQUIRES_TOKEN_PROGRAM);
        let accounts = [
            meta(pk(5), false, true),       // 0 source (external)
            meta(pk(6), false, true),       // 1 dest
            meta(multisig, true, false),    // 2 authority = multisig, signs
            meta(vault, true, false),       // 3 vault also signs, but is NOT the authority
            meta(SPL_TOKEN_ID, false, false),
        ];
        assert!(!registry_allows(&reg, 1, &spl, &[3], &accounts, &vault));
    }

    #[test]
    fn role_requires_token_program_needs_it_present() {
        let spl = crate::constants::SPL_TOKEN_ID;
        let vault = pk(9);
        let reg = reg_with(spl, &[3], ROLE_REQUIRES_TOKEN_PROGRAM);
        // No ROLE_VAULT_SIGNER here, so only the token-program presence matters.
        assert!(!registry_allows(&reg, 1, &spl, &[3], &[meta(pk(7), false, false)], &vault));
        assert!(registry_allows(&reg, 1, &spl, &[3], &[meta(SPL_TOKEN_ID, false, false)], &vault));
    }

    #[test]
    fn system_transfer_requires_the_vault_as_the_from_authority_at_index_0() {
        // System Transfer(2) has no SPL authority index; the None fallback
        // requires the vault to be the FIRST account (`from`) and sign.
        let system = Pubkey::default();
        let vault = pk(9);
        let reg = reg_with(system, &[2, 0, 0, 0], ROLE_VAULT_SIGNER);
        assert!(registry_allows(&reg, 1, &system, &[2, 0, 0, 0], &[meta(vault, true, true), meta(pk(6), false, true)], &vault));
        assert!(!registry_allows(&reg, 1, &system, &[2, 0, 0, 0], &[meta(pk(5), true, true), meta(vault, true, true)], &vault), "vault not the from");
    }

    #[test]
    fn the_test_mutator_transfer_out_authority_is_validated_at_index_2() {
        // WRDF-0041: the mutator's transfer_out (8-byte sighash) has its
        // authority at index 2, keyed by the (program, selector) pair — not the
        // wrong index-0 fallback a selector-only dispatch used to pick.
        let mutator = crate::constants::TEST_MUTATOR_ID;
        let sel = crate::registry_default::sighash("transfer_out").to_vec();
        let vault = pk(9);
        let reg = reg_with(mutator, &sel, ROLE_VAULT_SIGNER | ROLE_REQUIRES_TOKEN_PROGRAM);
        let accounts = [
            meta(pk(5), false, true),        // 0 source
            meta(pk(6), false, true),        // 1 destination
            meta(vault, true, false),        // 2 authority = vault, signs
            meta(SPL_TOKEN_ID, false, false),
        ];
        assert!(registry_allows(&reg, 1, &mutator, &sel, &accounts, &vault));
        // vault at index 0 (the source position) → deny
        let bad = [meta(vault, true, true), meta(pk(6), false, true), meta(pk(7), true, false), meta(SPL_TOKEN_ID, false, false)];
        assert!(!registry_allows(&reg, 1, &mutator, &sel, &bad, &vault));
    }

    #[test]
    fn an_adapter_with_role_vault_signer_but_no_known_authority_index_is_denied() {
        // Fail closed (WRDF-0041): a made-up program carrying ROLE_VAULT_SIGNER
        // has no authority_index entry, so it is denied rather than guessed.
        let prog = pk(1); // not SPL/System/mutator
        let vault = pk(9);
        let reg = reg_with(prog, &[9, 9, 9, 9, 9, 9, 9, 9], ROLE_VAULT_SIGNER);
        assert!(!registry_allows(&reg, 1, &prog, &[9, 9, 9, 9, 9, 9, 9, 9], &[meta(vault, true, true)], &vault));
    }

    #[test]
    fn out_of_range_entry_indices_never_leak_into_membership() {
        // A defensive check that list membership never reads past the table.
        let m = ListMask { bits: [u64::MAX; 1] };
        assert!(!m.contains(MAX_REGISTRY_ENTRIES));
    }
}
