//! The default registry contents (Phase 1B Task 3).
//!
//! One source of truth for what `init_registry` writes, so `packages/core`'s
//! `registry-default.json` (the TS mirror the extension reads) and the on-chain
//! init cannot drift: `registry_default_parity` in `tests/registry.rs` checks
//! the two agree.
//!
//! Two lists:
//! - **list 1 — production**: the adapters a real session may drive.
//! - **list 2 — test**: the `test-mutator` / `test-jup-mock` ops, so the
//!   integration tests can allow-list them without polluting the production list.
//!
//! Jupiter's route discriminators are the Anchor sighashes of the instruction
//! *names*; Task 6 verifies them against the pinned Jupiter v6 IDL. Sighashes
//! are computed at runtime with `solana_sha256_hasher` (the same hasher
//! `create_account` uses), not hard-coded, so a rename cannot silently desync.

use anchor_lang::prelude::*;

use crate::constants::{
    ATA_PROGRAM_ID, JUPITER_V6_ID, MEMO_PROGRAM_ID, SPL_TOKEN_ID, SYSTEM_PROGRAM_ID,
    TEST_JUP_MOCK_ID, TEST_MUTATOR_ID,
};
use crate::registry::{ROLE_REQUIRES_TOKEN_PROGRAM, ROLE_VAULT_SIGNER};
use crate::state::registry::{
    Registry, RegistryEntry, MAX_REGISTRY_ENTRIES, MAX_REGISTRY_LISTS, MAX_SELECTOR_LEN,
};

/// Anchor instruction discriminator: `sha256("global:<name>")[..8]`.
pub fn sighash(name: &str) -> [u8; 8] {
    let mut pre = b"global:".to_vec();
    pre.extend_from_slice(name.as_bytes());
    let full = solana_sha256_hasher::hash(&pre).to_bytes();
    let mut d = [0u8; 8];
    d.copy_from_slice(&full[..8]);
    d
}

/// One default adapter: which program, its selector, and which lists carry it.
pub struct DefaultAdapter {
    pub program_id: Pubkey,
    pub selector: Vec<u8>,
    pub role_rules: u8,
    /// Lists (1..=8) this adapter belongs to.
    pub lists: &'static [u16],
}

/// The full default adapter set, in the fixed order `init_registry` writes them
/// (the entry index is `position` in this vec, which the `ListMask` bits index).
pub fn default_adapters() -> Vec<DefaultAdapter> {
    let token_role = ROLE_VAULT_SIGNER | ROLE_REQUIRES_TOKEN_PROGRAM;
    vec![
        // --- list 1: production -------------------------------------------
        DefaultAdapter { program_id: SPL_TOKEN_ID, selector: vec![3], role_rules: token_role, lists: &[1] }, // Transfer
        DefaultAdapter { program_id: SPL_TOKEN_ID, selector: vec![12], role_rules: token_role, lists: &[1] }, // TransferChecked
        DefaultAdapter { program_id: ATA_PROGRAM_ID, selector: vec![1], role_rules: 0, lists: &[1] }, // CreateIdempotent
        DefaultAdapter { program_id: SYSTEM_PROGRAM_ID, selector: vec![2, 0, 0, 0], role_rules: ROLE_VAULT_SIGNER, lists: &[1] }, // Transfer (u32 tag 2)
        DefaultAdapter { program_id: MEMO_PROGRAM_ID, selector: vec![], role_rules: 0, lists: &[1] }, // tagless
        DefaultAdapter { program_id: JUPITER_V6_ID, selector: sighash("route").to_vec(), role_rules: 0, lists: &[1] },
        DefaultAdapter { program_id: JUPITER_V6_ID, selector: sighash("shared_accounts_route").to_vec(), role_rules: 0, lists: &[1] },
        // --- list 2: test -------------------------------------------------
        DefaultAdapter { program_id: TEST_MUTATOR_ID, selector: sighash("noop").to_vec(), role_rules: 0, lists: &[2] },
        DefaultAdapter { program_id: TEST_MUTATOR_ID, selector: sighash("transfer_out").to_vec(), role_rules: ROLE_VAULT_SIGNER | ROLE_REQUIRES_TOKEN_PROGRAM, lists: &[2] },
        DefaultAdapter { program_id: TEST_JUP_MOCK_ID, selector: sighash("route").to_vec(), role_rules: 0, lists: &[2] },
        DefaultAdapter { program_id: TEST_JUP_MOCK_ID, selector: sighash("shared_accounts_route").to_vec(), role_rules: 0, lists: &[2] },
    ]
}

/// Write the default adapters into a zeroed `Registry` (called by
/// `init_registry`). Sets `n_entries`, packs `entries[..n]`, and sets each
/// list's bitmask. Leaves `version`/`bump`/`authority`/`treasury` to the caller.
pub fn write_defaults(reg: &mut Registry) -> Result<()> {
    let adapters = default_adapters();
    require!(
        adapters.len() <= MAX_REGISTRY_ENTRIES,
        crate::errors::WardenError::RegistryFull
    );
    for (idx, a) in adapters.iter().enumerate() {
        require!(a.selector.len() <= MAX_SELECTOR_LEN, crate::errors::WardenError::PayloadInvalid);
        let mut sel = [0u8; MAX_SELECTOR_LEN];
        sel[..a.selector.len()].copy_from_slice(&a.selector);
        reg.entries[idx] = RegistryEntry {
            program_id: a.program_id,
            selector: sel,
            disc_len: a.selector.len() as u8,
            role_rules: a.role_rules,
            _pad: [0; 6],
        };
        for &list_id in a.lists {
            if let Some(li) = list_id.checked_sub(1) {
                if (li as usize) < MAX_REGISTRY_LISTS {
                    reg.lists[li as usize].set(idx);
                    // Mark this list ALLOCATED (WRDF-0044): it now has ≥1 entry.
                    reg.allocated_lists |= 1u8 << li;
                }
            }
        }
    }
    reg.n_entries = adapters.len() as u16;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sighash_matches_a_known_vector() {
        // Independently: sha256("global:route")[..8]. Recomputed here so a
        // change to the hasher wiring is caught, not just self-consistency.
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"global:route");
        assert_eq!(sighash("route"), h.finalize()[..8]);
    }

    #[test]
    fn write_defaults_marks_only_lists_1_and_2_allocated() {
        // WRDF-0044: allocated_lists records which lists actually got entries.
        let mut reg: Registry = bytemuck::Zeroable::zeroed();
        write_defaults(&mut reg).unwrap();
        assert!(reg.is_allocated_list(1), "list 1 (production) allocated");
        assert!(reg.is_allocated_list(2), "list 2 (test) allocated");
        for id in 3..=8u16 {
            assert!(!reg.is_allocated_list(id), "list {id} is capacity, not allocated");
        }
        assert!(!reg.is_allocated_list(0));
        // Structural validity is broader than allocation.
        assert!(Registry::is_valid_list_id(3) && !reg.is_allocated_list(3));
    }

    /// WRD-DENY-02, static half: the shipped defaults must not even *claim* to
    /// list a pair the fixed deny-list refuses. `execute::deny_scan` runs before
    /// the registry, so a denied listing could never be exercised — but a
    /// registry that advertised `SetAuthority` would be a lie in the one
    /// artifact the extension shows users, and the TS mirror
    /// (`registry-default.json`) would carry it too. Checked over BOTH token
    /// programs, since the deny-list covers both and they share tag numbering.
    #[test]
    fn no_default_adapter_lists_a_denied_token_tag() {
        use crate::constants::{
            SPL_TOKEN_2022_ID, TOKEN_IX_APPROVE, TOKEN_IX_APPROVE_CHECKED, TOKEN_IX_REVOKE,
            TOKEN_IX_SET_AUTHORITY,
        };
        let denied = [
            TOKEN_IX_APPROVE,
            TOKEN_IX_REVOKE,
            TOKEN_IX_SET_AUTHORITY,
            TOKEN_IX_APPROVE_CHECKED,
        ];
        for a in default_adapters() {
            if a.program_id != SPL_TOKEN_ID && a.program_id != SPL_TOKEN_2022_ID {
                continue;
            }
            // A token-program entry keys on its 1-byte instruction tag, so the
            // selector's first byte IS the pair's instruction half.
            let tag = a.selector.first().copied();
            assert!(
                !tag.is_some_and(|t| denied.contains(&t)),
                "default adapter {} selector {:?} names a deny-listed tag",
                a.program_id,
                a.selector
            );
        }
    }

    #[test]
    fn defaults_fit_and_pack_contiguously() {
        let adapters = default_adapters();
        assert!(adapters.len() <= MAX_REGISTRY_ENTRIES);
        // Every adapter belongs to at least one valid list.
        for a in &adapters {
            assert!(!a.lists.is_empty());
            for &l in a.lists {
                assert!(Registry::is_valid_list_id(l), "list {l}");
            }
        }
    }
}
