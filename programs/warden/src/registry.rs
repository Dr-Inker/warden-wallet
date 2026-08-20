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

/// `role_rules` bit: the vault PDA must appear as a signer in the CPI accounts.
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
    let role_rules = reg.entries[idx].role_rules;
    role_validator_passes(role_rules, accounts, vault)
}

/// The structural half of role validation (what `(accounts, vault)` can decide).
fn role_validator_passes(role_rules: u8, accounts: &[AccountMetaLike], vault: &Pubkey) -> bool {
    if role_rules & ROLE_VAULT_SIGNER != 0 {
        let vault_signs = accounts.iter().any(|a| a.pubkey == *vault && a.is_signer);
        if !vault_signs {
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
            _reserved: [0; 256],
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
    fn role_vault_signer_requires_the_vault_to_sign() {
        let prog = pk(1);
        let vault = pk(9);
        let reg = reg_with(prog, &[3], ROLE_VAULT_SIGNER);
        // vault present but not signing → deny
        assert!(!registry_allows(&reg, 1, &prog, &[3], &[meta(vault, false, true)], &vault));
        // vault signing → allow
        assert!(registry_allows(&reg, 1, &prog, &[3], &[meta(vault, true, true)], &vault));
        // a different signer is not the vault → deny
        assert!(!registry_allows(&reg, 1, &prog, &[3], &[meta(pk(8), true, true)], &vault));
    }

    #[test]
    fn role_requires_token_program_needs_it_present() {
        let prog = pk(1);
        let vault = pk(9);
        let reg = reg_with(prog, &[3], ROLE_REQUIRES_TOKEN_PROGRAM);
        assert!(!registry_allows(&reg, 1, &prog, &[3], &[meta(pk(7), false, false)], &vault));
        assert!(registry_allows(&reg, 1, &prog, &[3], &[meta(SPL_TOKEN_ID, false, false)], &vault));
    }

    #[test]
    fn out_of_range_entry_indices_never_leak_into_membership() {
        // A defensive check that list membership never reads past the table.
        let m = ListMask { bits: [u64::MAX; 1] };
        assert!(!m.contains(MAX_REGISTRY_ENTRIES));
    }
}
