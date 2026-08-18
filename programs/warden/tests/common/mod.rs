#![allow(dead_code)]

pub mod passkey;

use anchor_lang::Discriminator;
use litesvm::LiteSVM;
use solana_sdk::{account::Account, pubkey::Pubkey, signature::Keypair, signer::Signer};
use warden::constants::ACCOUNT_SEED;
use warden::state::{RootKey, SmartAccount};

pub fn program_id() -> Pubkey {
    warden::ID
}

pub fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    let so = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy/warden.so"))
        .expect("run `anchor build` first — see docs/TOOLCHAIN.md");
    svm.add_program(program_id(), &so).expect("add_program");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    (svm, payer)
}

pub fn account_pda(owner_seed: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ACCOUNT_SEED, owner_seed], &program_id())
}

/// Fields a test wants to vary when planting a `SmartAccount`.
pub struct SmartAccountFixture {
    pub owner_seed: [u8; 32],
    pub root_pubkey33: [u8; 33],
    /// `false` plants an Ed25519 root instead, to prove the passkey path
    /// refuses to run for it.
    pub root_is_passkey: bool,
    pub origin: String,
    /// Defaults to SHA-256(origin); a test can plant a deliberately wrong one.
    pub rp_id_hash: Option<[u8; 32]>,
    pub cluster_tag: [u8; 32],
    pub generation: u64,
    pub policy_version: u32,
    pub root_nonce: u64,
}

impl Default for SmartAccountFixture {
    fn default() -> Self {
        Self {
            owner_seed: [7u8; 32],
            root_pubkey33: [0u8; 33],
            root_is_passkey: true,
            origin: passkey::TEST_ORIGIN.to_string(),
            rp_id_hash: None,
            cluster_tag: [0x5Au8; 32],
            generation: 1,
            policy_version: 1,
            root_nonce: 0,
        }
    }
}

/// Plant a fully-formed `SmartAccount` directly into the SVM.
///
/// TEMPORARY: Task 4 lands `create_account`, at which point these tests should
/// build the account through the real instruction and this helper should go
/// away. Until then a hand-built account is the only way to exercise
/// `rotate_nonce`, and hand-building it is exactly the `#[account(zero_copy)]`
/// on-wire format: the 8-byte Anchor discriminator followed by the `Pod` bytes
/// (`anchor_discriminator_is_sha256_of_account_name` pins that claim).
pub fn set_smart_account(svm: &mut LiteSVM, f: &SmartAccountFixture) -> Pubkey {
    let (pda, bump) = account_pda(&f.owner_seed);
    let mut acc: SmartAccount = bytemuck::Zeroable::zeroed();
    acc.version = 1;
    acc.bump = bump;
    acc.owner_seed = f.owner_seed;
    if f.root_is_passkey {
        acc.set_root(&RootKey::P256Passkey { pubkey: f.root_pubkey33 });
    } else {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&f.root_pubkey33[..32]);
        acc.set_root(&RootKey::Ed25519 { pubkey: Pubkey::from(pk) });
    }
    let ob = f.origin.as_bytes();
    assert!(ob.len() <= 64, "origin too long for the fixed field");
    acc.origin[..ob.len()].copy_from_slice(ob);
    acc.origin_len = ob.len() as u8;
    acc.rp_id_hash = f.rp_id_hash.unwrap_or_else(|| passkey::rp_id_hash(&f.origin));
    acc.cluster_tag = f.cluster_tag;
    acc.generation = f.generation;
    acc.policy.version = f.policy_version;
    acc.root_nonce = f.root_nonce;

    let mut data = SmartAccount::DISCRIMINATOR.to_vec();
    data.extend_from_slice(bytemuck::bytes_of(&acc));
    assert_eq!(data.len(), SmartAccount::LEN);

    svm.set_account(
        pda,
        Account {
            lamports: 10_000_000_000,
            data,
            owner: program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account");
    pda
}

/// Read a planted account back out of the SVM.
pub fn read_smart_account(svm: &LiteSVM, pda: &Pubkey) -> SmartAccount {
    let raw = svm.get_account(pda).expect("account exists").data;
    assert_eq!(&raw[..8], SmartAccount::DISCRIMINATOR, "discriminator");
    *bytemuck::from_bytes::<SmartAccount>(&raw[8..])
}
