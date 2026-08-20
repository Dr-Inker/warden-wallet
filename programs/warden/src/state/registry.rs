//! The adapter `Registry` (Phase 1B Task 3).
//!
//! A single global zero-copy PDA (`["registry"]`) that curates which
//! `(program_id, selector)` pairs a session key may drive through `execute`,
//! grouped into named *lists* a session's `program_allowlist_id` references. It
//! is **immutable in 1B** (only `init_registry` writes it; 1C adds a timelocked
//! update).
//!
//! The load-bearing rule this file encodes is the **selector-derivation rule**
//! (spec §5.2 rule 1): a selector is *not* always an 8-byte Anchor sighash.
//! Non-Anchor programs (SPL Token, System, Memo, ATA) key on a single-byte (or
//! fixed-layout) instruction tag, which is why `disc_len` exists and why nothing
//! may assume 8. Matching is always on the **`(program_id, selector)` pair** and
//! the selector's own length — never a selector alone (Anchor sighashes hash the
//! instruction *name only*, so `deposit` collides across unrelated programs).

use anchor_lang::prelude::*;

/// Fixed capacity of the registry's entry table. A `ListMask`'s single `u64`
/// bitmask indexes exactly these 64 slots.
pub const MAX_REGISTRY_ENTRIES: usize = 64;
/// Number of curated lists (`program_allowlist_id` 1..=8; id 0 = "no registry").
pub const MAX_REGISTRY_LISTS: usize = 8;
/// Longest selector we store (an 8-byte Anchor sighash). Shorter tags occupy
/// the low bytes; `disc_len` says how many are significant.
pub const MAX_SELECTOR_LEN: usize = 8;

/// One curated `(program, selector)` adapter. `disc_len` bytes of `selector`
/// are significant (8 = Anchor sighash, 1 = SPL/System tag, 4 = a 4-byte tag);
/// `role_rules` selects the per-adapter account validator (`crate::registry`).
#[zero_copy]
#[repr(C)]
pub struct RegistryEntry {
    pub program_id: Pubkey,
    pub selector: [u8; MAX_SELECTOR_LEN],
    /// Significant bytes of `selector`: 8 Anchor, 1 SPL/System/Memo, 4 for a
    /// 4-byte tag. Never assume 8.
    pub disc_len: u8,
    /// Bitflags selecting the account-role validator (`crate::registry`):
    /// `ROLE_VAULT_SIGNER` (1), `ROLE_REQUIRES_TOKEN_PROGRAM` (2), … A bare
    /// `(program, selector)` match is not sufficient when this is non-zero.
    pub role_rules: u8,
    pub _pad: [u8; 6],
}

impl RegistryEntry {
    pub const LEN: usize = core::mem::size_of::<RegistryEntry>();

    /// Does this entry match `(program, ix_data)`? The selector is the FIRST
    /// `disc_len` bytes of `ix_data`; a shorter `ix_data` cannot match, and the
    /// program id must be exactly equal (selectors collide across programs).
    ///
    /// `disc_len == 0` is reserved for a **tagless** program (e.g. the Memo
    /// program, whose data is a free-form UTF-8 string with no instruction
    /// discriminator): a `disc_len == 0` entry matches ANY data to its program
    /// id. There is deliberately no `program_id == default` "unused" check here:
    /// the System program's id *is* the all-zeros pubkey, so used-ness is a
    /// property of the entry's INDEX (`< n_entries`), enforced by `find_entry`,
    /// not of its program id. `matches` is therefore a pure per-entry predicate.
    pub fn matches(&self, program: &Pubkey, ix_data: &[u8]) -> bool {
        if self.program_id != *program {
            return false;
        }
        let n = self.disc_len as usize;
        if n == 0 {
            return true; // tagless program: program-id match only
        }
        if n > MAX_SELECTOR_LEN || ix_data.len() < n {
            return false;
        }
        ix_data[..n] == self.selector[..n]
    }
}

/// A bitmask over the 64 entry slots — membership of one curated list.
#[zero_copy]
#[repr(C)]
pub struct ListMask {
    pub bits: [u64; 1],
}

impl ListMask {
    pub const LEN: usize = core::mem::size_of::<ListMask>();

    pub fn contains(&self, entry_idx: usize) -> bool {
        if entry_idx >= MAX_REGISTRY_ENTRIES {
            return false;
        }
        (self.bits[0] >> entry_idx) & 1 == 1
    }

    pub fn set(&mut self, entry_idx: usize) {
        if entry_idx < MAX_REGISTRY_ENTRIES {
            self.bits[0] |= 1u64 << entry_idx;
        }
    }
}

/// The global adapter registry. Immutable after `init_registry` in 1B.
#[account(zero_copy)]
#[repr(C)]
pub struct Registry {
    pub version: u8,
    pub bump: u8,
    pub _pad: [u8; 6],
    /// The key authorised to `init_registry` (= warden's upgrade authority at
    /// init: dev keypair on localnet/devnet, Squads multisig on mainnet).
    pub authority: Pubkey,
    /// The drinkerlabs treasury SmartAccount — the swap-fee ATA owner (Task 6).
    /// A first-class field, set at init, never overloaded onto `authority`.
    pub treasury: Pubkey,
    pub n_entries: u16,
    pub _pad2: [u8; 6],
    pub entries: [RegistryEntry; MAX_REGISTRY_ENTRIES],
    /// `lists[k]` = list id `k + 1`; id 0 means "no registry / deny every CPI".
    pub lists: [ListMask; MAX_REGISTRY_LISTS],
    pub _reserved: [u8; 256],
}

impl Registry {
    pub const LEN: usize = 8 + core::mem::size_of::<Registry>();

    /// Index of the entry matching `(program, ix_data)`, if any. Only the first
    /// `n_entries` slots are considered used (entries are packed contiguously by
    /// `init_registry`); scanning past them would let a zeroed slot match a call
    /// to the all-zeros System program id. `n_entries` is clamped defensively.
    pub fn find_entry(&self, program: &Pubkey, ix_data: &[u8]) -> Option<usize> {
        let used = (self.n_entries as usize).min(MAX_REGISTRY_ENTRIES);
        self.entries[..used]
            .iter()
            .position(|e| e.matches(program, ix_data))
    }

    /// Is `entry_idx` a member of list id `list_id` (1..=8)? id 0 is never a
    /// member of anything (it means "no registry").
    pub fn list_contains(&self, list_id: u16, entry_idx: usize) -> bool {
        match list_id.checked_sub(1) {
            Some(i) if (i as usize) < MAX_REGISTRY_LISTS => self.lists[i as usize].contains(entry_idx),
            _ => false, // 0 ("no registry") or past the table
        }
    }

    /// Is `list_id` a usable id for a `grant_session` allowlist? 0 (no
    /// registry) and any id past the table are not.
    pub fn is_valid_list_id(list_id: u16) -> bool {
        (1..=MAX_REGISTRY_LISTS as u16).contains(&list_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Registry is created via `space = Registry::LEN` inside `init_registry`;
    // if this exceeds the 10 KiB `create_account` CPI limit the init would fail
    // at runtime, so pin it well under.
    #[test]
    fn registry_fits_a_single_account() {
        assert!(Registry::LEN < 10_240, "Registry::LEN = {}", Registry::LEN);
    }

    // Zero-copy demands a padding-free Pod layout; hand-sum every field so a
    // reordering or a forgotten `_pad` is caught here, not by a silent
    // misread on-chain (same guard as `SmartAccount`).
    #[test]
    fn registry_len_matches_size_of() {
        let entry = 32 + 8 + 1 + 1 + 6; // program_id, selector, disc_len, role_rules, _pad
        assert_eq!(RegistryEntry::LEN, entry);
        let hand = 1 + 1 + 6            // version, bump, _pad
            + 32 + 32                   // authority, treasury
            + 2 + 6                     // n_entries, _pad2
            + entry * MAX_REGISTRY_ENTRIES
            + 8 * MAX_REGISTRY_LISTS    // lists
            + 256; // _reserved
        assert_eq!(Registry::LEN, 8 + hand);
    }

    fn pk(n: u8) -> Pubkey {
        let mut b = [0u8; 32];
        b[0] = n;
        Pubkey::new_from_array(b)
    }

    fn entry(program: Pubkey, selector: &[u8], role_rules: u8) -> RegistryEntry {
        let mut sel = [0u8; MAX_SELECTOR_LEN];
        sel[..selector.len()].copy_from_slice(selector);
        RegistryEntry {
            program_id: program,
            selector: sel,
            disc_len: selector.len() as u8,
            role_rules,
            _pad: [0; 6],
        }
    }

    #[test]
    fn a_one_byte_tag_entry_matches_its_tag_and_nothing_longer() {
        let spl = pk(1);
        let e = entry(spl, &[3u8], 0); // SPL Token Transfer tag
        assert!(e.matches(&spl, &[3, 100, 0, 0, 0, 0, 0, 0, 0])); // tag + amount
        assert!(e.matches(&spl, &[3])); // bare tag
        assert!(!e.matches(&spl, &[])); // too short
        assert!(!e.matches(&spl, &[4])); // wrong tag
    }

    #[test]
    fn a_one_byte_tag_does_not_match_a_program_whose_first_byte_coincides() {
        // An 8-byte-sighash program whose sighash happens to start with 0x03
        // must not be matched by a 1-byte-tag entry keyed to a DIFFERENT program.
        let spl = pk(1);
        let other = pk(2);
        let e = entry(spl, &[3u8], 0);
        assert!(!e.matches(&other, &[3, 9, 9, 9, 9, 9, 9, 9, 9]), "program id must match exactly");
    }

    #[test]
    fn an_eight_byte_disc_entry_does_not_match_a_one_byte_tag_program() {
        let anchored = pk(3);
        let sighash = [7u8; 8];
        let e = entry(anchored, &sighash, 0);
        assert!(e.matches(&anchored, &sighash));
        assert!(e.matches(&anchored, &[7, 7, 7, 7, 7, 7, 7, 7, 42])); // sighash + args
        assert!(!e.matches(&anchored, &[7])); // a 1-byte call cannot satisfy an 8-byte disc
    }

    #[test]
    fn the_same_selector_under_two_program_ids_is_two_distinct_entries() {
        // Marinade `deposit` and Drift `deposit` share a sighash; the pair keys.
        let marinade = pk(10);
        let drift = pk(11);
        let deposit = [0xf2, 0x23, 0xc6, 0x89, 0x52, 0xe1, 0xf2, 0xb6];
        let em = entry(marinade, &deposit, 0);
        let ed = entry(drift, &deposit, 0);
        assert!(em.matches(&marinade, &deposit) && !em.matches(&drift, &deposit));
        assert!(ed.matches(&drift, &deposit) && !ed.matches(&marinade, &deposit));
    }

    #[test]
    fn a_tagless_disc_len_zero_entry_matches_any_data_to_its_program() {
        let memo = pk(20);
        let e = entry(memo, &[], 0); // disc_len 0
        assert!(e.matches(&memo, b"hello"));
        assert!(e.matches(&memo, &[])); // even empty data
        assert!(!e.matches(&pk(21), b"hello"), "still keyed to its program id");
    }

    #[test]
    fn the_all_zero_system_program_id_is_a_real_key_and_matches() {
        // The System program's id IS Pubkey::default(); a System Transfer entry
        // (u32 tag 2 → 4 bytes) must match, and unused slots must not.
        let system = Pubkey::default();
        let e = entry(system, &[2, 0, 0, 0], 0b10 /* ROLE bits irrelevant here */);
        assert!(e.matches(&system, &[2, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!e.matches(&system, &[4, 0, 0, 0]), "different System tag");
    }

    #[test]
    fn find_entry_ignores_slots_past_n_entries() {
        // A zeroed slot (program default, disc_len 0) would match ANY System
        // call if it were scanned — `n_entries` must exclude it.
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
        // entry 0 is a real SPL Transfer; entries 1..64 are zeroed (default id,
        // disc_len 0) and would match a System call if scanned.
        reg.entries[0] = entry(pk(1), &[3], 0);
        assert_eq!(reg.find_entry(&pk(1), &[3]), Some(0));
        // A call to the all-zeros System program must NOT match a zeroed slot.
        assert_eq!(reg.find_entry(&Pubkey::default(), &[9, 9, 9]), None);
    }

    #[test]
    fn list_membership_and_id_zero_semantics() {
        let mut m = ListMask { bits: [0; 1] };
        m.set(0);
        m.set(63);
        assert!(m.contains(0) && m.contains(63) && !m.contains(1));
        assert!(!m.contains(64)); // out of range
        assert!(!Registry::is_valid_list_id(0)); // "no registry"
        assert!(Registry::is_valid_list_id(1) && Registry::is_valid_list_id(8));
        assert!(!Registry::is_valid_list_id(9));
    }
}
