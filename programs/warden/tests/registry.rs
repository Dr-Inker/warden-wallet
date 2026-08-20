//! Phase 1B Task 3 — `init_registry` + `grant_session` allowlist integration.
//!
//! The pure matching/list logic is unit-tested in `warden::state::registry` and
//! `warden::registry`; this suite proves the on-chain instruction path: the
//! upgrade-authority authorisation, singleton-ness, the default contents, the
//! TS/Rust default parity, and the create→grant allowlist wiring.

mod common;

use common::*;
use litesvm::LiteSVM;
use solana_sdk::{
    instruction::Instruction, message::Message, pubkey::Pubkey, signature::Keypair,
    signer::Signer, transaction::Transaction,
};
use warden::registry_default::default_adapters;
use warden::state::registry::Registry;

fn svm_with_program() -> (LiteSVM, Keypair) {
    setup()
}

fn send(svm: &mut LiteSVM, signers: &[&Keypair], ixs: &[Instruction]) -> Result<(), String> {
    let payer = signers[0].pubkey();
    let tx = Transaction::new(
        &signers.to_vec(),
        Message::new(ixs, Some(&payer)),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ()).map_err(|e| format!("{:?} {:#?}", e.err, e.meta.logs))
}

fn read_registry(svm: &LiteSVM) -> Registry {
    use anchor_lang::Discriminator;
    let (pda, _) = registry_pda();
    let raw = svm.get_account(&pda).expect("registry exists").data;
    assert_eq!(&raw[..8], Registry::DISCRIMINATOR);
    *bytemuck::from_bytes::<Registry>(&raw[8..])
}

// ---------------------------------------------------------------------------
// init_registry — the upgrade-authority-gated singleton
// ---------------------------------------------------------------------------

#[test]
fn init_registry_by_the_upgrade_authority_writes_the_defaults() {
    let (mut svm, payer) = svm_with_program();
    let authority = Keypair::new();
    svm.airdrop(&authority.pubkey(), 1_000_000_000).unwrap();
    set_program_data(&mut svm, Some(authority.pubkey()));
    let treasury = Pubkey::new_unique();

    send(&mut svm, &[&payer, &authority], &[init_registry_ix(payer.pubkey(), authority.pubkey(), treasury)])
        .expect("init_registry by the upgrade authority");

    let reg = read_registry(&svm);
    assert_eq!(reg.version, 1);
    assert_eq!(reg.authority, authority.pubkey());
    assert_eq!(reg.treasury, treasury);
    assert_eq!(reg.n_entries as usize, default_adapters().len());
    // The production SPL Transfer adapter (list 1) resolves.
    let spl = warden::constants::SPL_TOKEN_ID;
    let idx = reg.find_entry(&spl, &[3, 0, 0, 0]).expect("SPL Transfer entry");
    assert!(reg.list_contains(1, idx), "SPL Transfer is in list 1");
    assert!(!reg.list_contains(2, idx), "and not in the test list");
}

#[test]
fn init_registry_by_a_non_authority_is_rejected() {
    let (mut svm, payer) = svm_with_program();
    let real_authority = Keypair::new();
    set_program_data(&mut svm, Some(real_authority.pubkey()));
    // A stranger signs as `authority` — must fail (RegistryUnauthorized 6053).
    let stranger = Keypair::new();
    svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    let err = send(
        &mut svm,
        &[&payer, &stranger],
        &[init_registry_ix(payer.pubkey(), stranger.pubkey(), Pubkey::new_unique())],
    )
    .unwrap_err();
    assert!(err.contains("6053") || err.contains("RegistryUnauthorized"), "{err}");
}

#[test]
fn init_registry_with_no_upgrade_authority_is_rejected() {
    let (mut svm, payer) = svm_with_program();
    set_program_data(&mut svm, None); // frozen program: no upgrade authority
    let signer = Keypair::new();
    svm.airdrop(&signer.pubkey(), 1_000_000_000).unwrap();
    let err = send(
        &mut svm,
        &[&payer, &signer],
        &[init_registry_ix(payer.pubkey(), signer.pubkey(), Pubkey::new_unique())],
    )
    .unwrap_err();
    assert!(err.contains("6053") || err.contains("RegistryUnauthorized"), "{err}");
}

#[test]
fn init_registry_twice_is_rejected() {
    let (mut svm, payer) = svm_with_program();
    let authority = Keypair::new();
    svm.airdrop(&authority.pubkey(), 1_000_000_000).unwrap();
    set_program_data(&mut svm, Some(authority.pubkey()));
    let ix = || init_registry_ix(payer.pubkey(), authority.pubkey(), Pubkey::new_unique());
    send(&mut svm, &[&payer, &authority], &[ix()]).expect("first init");
    let err = send(&mut svm, &[&payer, &authority], &[ix()]).unwrap_err();
    // `init` on an existing account fails (Anchor account-already-in-use / 0x0).
    assert!(!err.is_empty(), "second init must fail");
}

// ---------------------------------------------------------------------------
// create → grant allowlist wiring
// ---------------------------------------------------------------------------

#[test]
fn create_account_with_a_registry_records_its_key() {
    // The create→grant wiring: an account created with the optional registry
    // account stores its key, which is what makes a non-zero `program_allowlist_id`
    // grant legal (grant_session checks `account.registry != default`). The grant
    // rejection paths are covered in tests/sessions.rs
    // (`grant_with_unknown_allowlist_id_rejected`).
    let (mut svm, payer) = svm_with_program();
    let authority = Keypair::new();
    svm.airdrop(&authority.pubkey(), 1_000_000_000).unwrap();
    set_program_data(&mut svm, Some(authority.pubkey()));
    send(&mut svm, &[&payer, &authority], &[init_registry_ix(payer.pubkey(), authority.pubkey(), Pubkey::new_unique())])
        .expect("init_registry");
    let (registry, _) = registry_pda();

    let pk = common::passkey::TestPasskey::new(3);
    let f = SmartAccountFixture { root_pubkey33: pk.pubkey33(), registry: Some(registry), ..Default::default() };
    let account = create_smart_account(&mut svm, &payer, &f, &pk);

    assert_eq!(read_smart_account(&svm, &account).registry, registry, "registry recorded at create");
}

#[test]
fn create_account_without_a_registry_leaves_it_default() {
    let (mut svm, payer) = svm_with_program();
    let pk = common::passkey::TestPasskey::new(3);
    let f = SmartAccountFixture { root_pubkey33: pk.pubkey33(), registry: None, ..Default::default() };
    let account = create_smart_account(&mut svm, &payer, &f, &pk);
    assert_eq!(read_smart_account(&svm, &account).registry, Pubkey::default());
}

// ---------------------------------------------------------------------------
// TS / Rust default parity
// ---------------------------------------------------------------------------

#[test]
fn registry_default_json_matches_the_rust_source_of_truth() {
    let json = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packages/core/src/registry-default.json"
    ))
    .expect("registry-default.json exists");
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    let adapters = v["adapters"].as_array().expect("adapters array");
    let rust = default_adapters();
    assert_eq!(adapters.len(), rust.len(), "adapter count");
    for (i, (j, r)) in adapters.iter().zip(rust.iter()).enumerate() {
        assert_eq!(
            j["program_id"].as_str().unwrap(),
            r.program_id.to_string(),
            "adapter {i} program_id"
        );
        let sel: Vec<u8> = j["selector"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u8).collect();
        assert_eq!(sel, r.selector, "adapter {i} selector");
        assert_eq!(j["disc_len"].as_u64().unwrap() as usize, r.selector.len(), "adapter {i} disc_len");
        assert_eq!(j["role_rules"].as_u64().unwrap() as u8, r.role_rules, "adapter {i} role_rules");
        let lists: Vec<u16> = j["lists"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u16).collect();
        assert_eq!(lists, r.lists, "adapter {i} lists");
    }
}
