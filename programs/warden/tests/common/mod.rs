#![allow(dead_code)]

pub mod passkey;

use anchor_lang::{AnchorSerialize, Discriminator};
use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::Transaction,
};
use warden::constants::ACCOUNT_SEED;
use warden::instructions::create_account::{CreateAccountArgs, MAX_SESSION_LIFE_SECS, MIN_TIMELOCK_SECS};
use warden::state::{PolicyArgs, RootKey, SmartAccount};

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
///
/// `generation`/`root_nonce` default to 0 because that is what the real
/// `create_account` instruction actually produces (Task 4) — `0` is no
/// longer an arbitrary test convenience, it's what `create_smart_account`
/// below both asserts on input and gets back from LiteSVM. A test that needs
/// a *different* generation/nonce (there is no instruction yet that advances
/// `generation`, and reaching a given `root_nonce` other than 0 or 1 would
/// mean replaying several real ceremonies first) still has `set_smart_account`
/// for exactly that reason — see `root_verify.rs` for which tests do this and
/// why.
pub struct SmartAccountFixture {
    pub owner_seed: [u8; 32],
    pub root_pubkey33: [u8; 33],
    /// `false` plants an Ed25519 root instead, to prove the passkey path
    /// refuses to run for it.
    pub root_is_passkey: bool,
    pub origin: String,
    /// Defaults to SHA-256(origin); a test can plant a deliberately wrong one
    /// via `set_smart_account` (never via `create_smart_account`, which
    /// always recomputes and enforces the real hash, same as the program).
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
            generation: 0,
            policy_version: 1,
            root_nonce: 0,
        }
    }
}

/// A `Policy` that satisfies every `create_account` validation rule and uses
/// no mint caps (every slot unused) — the shape most tests want, since
/// they're exercising the root-verify path, not the policy lattice.
pub fn default_policy_args() -> PolicyArgs {
    PolicyArgs {
        version: 1,
        caps: vec![],
        session_ceiling: vec![],
        large_threshold: vec![],
        timelock_secs: MIN_TIMELOCK_SECS,
        recovery_delay_secs: MIN_TIMELOCK_SECS,
        max_session_life_secs: MAX_SESSION_LIFE_SECS,
        session_ops_ceiling: 0,
    }
}

pub fn create_account_ix(payer: Pubkey, smart_account: Pubkey, args: &CreateAccountArgs) -> Instruction {
    let mut data = Sha256::digest(b"global:create_account")[..8].to_vec();
    args.serialize(&mut data).unwrap();
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(smart_account, false),
            AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
        ],
        data,
    }
}

/// Create a `SmartAccount` through the real `create_account` instruction
/// (Task 4) rather than by hand-writing bytes. Panics with the program's own
/// error on failure — every caller of this helper wants an honest account.
///
/// Only `owner_seed`/`root_*`/`origin`/`cluster_tag` are honoured:
/// `generation`/`root_nonce`/`policy_version` must be at the values
/// `create_account` itself would produce (asserted below) — a fixture that
/// needs anything else cannot be built through the instruction and must use
/// `set_smart_account`.
pub fn create_smart_account(svm: &mut LiteSVM, payer: &Keypair, f: &SmartAccountFixture) -> Pubkey {
    assert_eq!(f.generation, 0, "create_account always sets generation = 0");
    assert_eq!(f.root_nonce, 0, "create_account always sets root_nonce = 0");
    assert_eq!(f.policy_version, 1, "create_account always forces policy.version = 1");
    assert!(f.rp_id_hash.is_none(), "create_account recomputes rp_id_hash from origin itself");

    let (pda, _bump) = account_pda(&f.owner_seed);
    let root = if f.root_is_passkey {
        RootKey::P256Passkey { pubkey: f.root_pubkey33 }
    } else {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&f.root_pubkey33[..32]);
        RootKey::Ed25519 { pubkey: Pubkey::from(pk) }
    };
    let origin = f.origin.as_bytes().to_vec();
    let rp_id_hash = passkey::rp_id_hash(&f.origin);
    let args = CreateAccountArgs {
        owner_seed: f.owner_seed,
        root,
        rp_id_hash,
        origin,
        cluster_tag: f.cluster_tag,
        policy: default_policy_args(),
    };
    let ix = create_account_ix(payer.pubkey(), pda, &args);
    let tx = Transaction::new(&[payer], Message::new(&[ix], Some(&payer.pubkey())), svm.latest_blockhash());
    svm.send_transaction(tx)
        .unwrap_or_else(|e| panic!("create_account must succeed: {:?} {:#?}", e.err, e.meta.logs));
    pda
}

/// Plant a fully-formed `SmartAccount` directly into the SVM, bypassing
/// `create_account` entirely.
///
/// KEPT DELIBERATELY (Task 4 retired most callers to `create_smart_account`
/// above, which goes through the real instruction): three `root_verify.rs`
/// cases still need this because no sequence of real instructions can
/// produce their starting state —
/// - `non_pda_account_rejected`: an account at an address that is NOT the
///   PDA for its own `owner_seed`. `create_account`'s `seeds` constraint
///   derives the address itself, so this is impossible through it by
///   construction, not just inconvenient.
/// - `stale_generation_rejected`: `generation != 0`. No instruction in this
///   program advances `generation` yet (that lands with the policy/guardian
///   work in Phase 1B).
/// - `stale_nonce_far_in_the_past_rejected_as_challenge_mismatch`:
///   `root_nonce == 5`. Reaching this via 5 real `rotate_nonce` ceremonies is
///   *possible*, but would only re-prove what
///   `consecutive_ceremonies_each_consume_one_nonce`/
///   `replay_same_assertion_rejected` already cover; this test's whole point
///   is the "stale by more than one, not just a replay" case, which planting
///   the state directly demonstrates with far less incidental machinery.
///
/// Hand-building the bytes is exactly the `#[account(zero_copy)]` on-wire
/// format: the 8-byte Anchor discriminator followed by the `Pod` bytes
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
