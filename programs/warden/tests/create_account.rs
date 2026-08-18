//! LiteSVM coverage of `create_account` (Task 4).
//!
//! Every test submits a real transaction against the deployed SBF artifact —
//! there is no bypass here; `common::create_smart_account` (used by
//! `root_verify.rs`) is itself built on the same `create_account_ix` these
//! tests call directly, so a regression here is a regression there too.

mod common;

use anchor_lang::Discriminator;
use common::passkey::{self, TEST_ORIGIN};
use common::{account_pda, create_account_ix, default_policy_args};
use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::InstructionError,
    message::Message,
    pubkey::Pubkey,
    signer::Signer,
    transaction::{Transaction, TransactionError},
};
use warden::instructions::create_account::{CreateAccountArgs, MAX_ORIGIN_LEN, MAX_SESSION_LIFE_SECS, MIN_TIMELOCK_SECS};
use warden::state::{MintCap, RootKey, SmartAccount};

mod err {
    // Same numbering scheme as `root_verify.rs`'s `mod err` (6000 +
    // declaration index); these three are appended after
    // `RootKindUnsupported` (6024) so they start at 6025.
    pub const INVALID_ROOT_ASSERTION: u32 = 6003;
    pub const INVALID_ORIGIN: u32 = 6025;
    pub const ZERO_CLUSTER_TAG: u32 = 6026;
    pub const INVALID_POLICY: u32 = 6027;
}

fn honest_args(owner_seed: [u8; 32]) -> CreateAccountArgs {
    CreateAccountArgs {
        owner_seed,
        root: RootKey::P256Passkey { pubkey: [0x11u8; 33] },
        rp_id_hash: passkey::rp_id_hash(TEST_ORIGIN),
        origin: TEST_ORIGIN.as_bytes().to_vec(),
        cluster_tag: [0x5Au8; 32],
        policy: default_policy_args(),
    }
}

fn send(svm: &mut litesvm::LiteSVM, payer: &solana_sdk::signature::Keypair, args: &CreateAccountArgs) -> litesvm::types::TransactionResult {
    let (pda, _) = account_pda(&args.owner_seed);
    let ix = create_account_ix(payer.pubkey(), pda, args);
    let tx = Transaction::new(&[payer], Message::new(&[ix], Some(&payer.pubkey())), svm.latest_blockhash());
    svm.send_transaction(tx)
}

fn expect_reject(args: CreateAccountArgs, expected: u32) {
    let (mut svm, payer) = common::setup();
    let err = send(&mut svm, &payer, &args).expect_err("must be rejected");
    assert_eq!(
        err.err,
        TransactionError::InstructionError(0, InstructionError::Custom(expected)),
        "wrong failure mode; logs={:#?}",
        err.meta.logs
    );
    assert!(
        !err.meta.logs.iter().any(|l| l.contains("panicked")),
        "program panicked instead of returning an error: {:#?}",
        err.meta.logs
    );
    let (pda, _) = account_pda(&args.owner_seed);
    assert!(svm.get_account(&pda).is_none(), "a rejected create_account must not leave an account behind");
}

// ---------------------------------------------------------------------------
// Pinned facts
// ---------------------------------------------------------------------------

/// The hand-encoded discriminator in `common::create_account_ix` is only
/// valid if Anchor's global-instruction discriminator really is
/// SHA-256("global:<snake_case name>")[..8].
#[test]
fn discriminator_is_sha256_of_global_create_account() {
    let ix = create_account_ix(Pubkey::new_unique(), Pubkey::new_unique(), &honest_args([1u8; 32]));
    assert_eq!(&ix.data[..8], &Sha256::digest(b"global:create_account")[..8]);
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn creates_with_defaults() {
    let (mut svm, payer) = common::setup();
    let args = honest_args([3u8; 32]);
    let (pda, expected_bump) = account_pda(&args.owner_seed);

    let ix = create_account_ix(payer.pubkey(), pda, &args);
    let tx_bytes_ix = ix.data.len();
    let tx = Transaction::new(&[&payer], Message::new(&[ix], Some(&payer.pubkey())), svm.latest_blockhash());
    let tx_bytes = bincode::serialize(&tx).unwrap().len();
    let res = svm.send_transaction(tx).unwrap_or_else(|e| panic!("must succeed: {:?} {:#?}", e.err, e.meta.logs));
    println!("create_account CU: {}", res.compute_units_consumed);
    println!("create_account ix data: {tx_bytes_ix} B, serialized tx: {tx_bytes} B");

    let raw = svm.get_account(&pda).expect("account must exist").data;
    assert_eq!(&raw[..8], SmartAccount::DISCRIMINATOR, "discriminator");
    let acc: SmartAccount = *bytemuck::from_bytes(&raw[8..]);

    assert_eq!(acc.version, 1);
    assert_eq!(acc.bump, expected_bump);
    assert_eq!(acc.owner_seed, args.owner_seed);
    assert_eq!(acc.root().unwrap(), args.root);
    assert_eq!(acc.rp_id_hash, args.rp_id_hash);
    assert_eq!(acc.cluster_tag, args.cluster_tag);
    assert_eq!(acc.generation, 0);
    assert_eq!(acc.root_nonce, 0);
    assert_eq!(acc.frozen_at, 0);
    assert_eq!(acc.frozen().unwrap(), warden::state::FrozenState::None);
    assert_eq!(acc.guardians_config, Pubkey::default());
    assert_eq!(acc.registry, Pubkey::default());
    assert!(acc._reserved.iter().all(|b| *b == 0));
    assert_eq!(acc.policy.version, 1, "policy.version is forced to 1 regardless of PolicyArgs.version");

    assert!(res.compute_units_consumed < 100_000, "CU budget: {}", res.compute_units_consumed);
}

// ---------------------------------------------------------------------------
// Origin / rp_id_hash
// ---------------------------------------------------------------------------

#[test]
fn rejects_origin_too_long() {
    let mut args = honest_args([4u8; 32]);
    let mut origin = b"chrome-extension://".to_vec();
    origin.extend(std::iter::repeat(b'a').take(MAX_ORIGIN_LEN)); // total > 64
    args.origin = origin;
    // rp_id_hash must be recomputed to match, or the SHA-256 check (which
    // runs first) would mask the length check this test targets.
    args.rp_id_hash = sha256_of(&args.origin);
    expect_reject(args, err::INVALID_ORIGIN);
}

#[test]
fn rejects_origin_with_embedded_or_trailing_nul() {
    for origin in [
        b"chrome-extension://ab\0cdef".to_vec(),
        b"chrome-extension://abcdef\0".to_vec(),
    ] {
        let mut args = honest_args([5u8; 32]);
        args.rp_id_hash = sha256_of(&origin);
        args.origin = origin;
        expect_reject(args, err::INVALID_ORIGIN);
    }
}

#[test]
fn rejects_rp_id_hash_not_sha256_of_origin() {
    let mut args = honest_args([6u8; 32]);
    args.rp_id_hash[0] ^= 0x01;
    expect_reject(args, err::INVALID_ROOT_ASSERTION);
}

/// SHA-256 of the *bare extension id* (no scheme) must be rejected — same
/// spike 2b finding `root_verify.rs` pins against at the assertion path;
/// `create_account` must not accept a client that got this wrong either.
#[test]
fn rejects_rp_id_hash_of_bare_extension_id() {
    let mut args = honest_args([7u8; 32]);
    let bare = TEST_ORIGIN.strip_prefix("chrome-extension://").unwrap();
    args.rp_id_hash = Sha256::digest(bare.as_bytes()).into();
    expect_reject(args, err::INVALID_ROOT_ASSERTION);
}

#[test]
fn stored_origin_zero_padded_and_len_exact() {
    let (mut svm, payer) = common::setup();
    let short_origin = "chrome-extension://abc";
    let mut args = honest_args([8u8; 32]);
    args.origin = short_origin.as_bytes().to_vec();
    args.rp_id_hash = passkey::rp_id_hash(short_origin);
    let (pda, _) = account_pda(&args.owner_seed);
    send(&mut svm, &payer, &args).unwrap_or_else(|e| panic!("must succeed: {:?} {:#?}", e.err, e.meta.logs));

    let raw = svm.get_account(&pda).unwrap().data;
    let acc: SmartAccount = *bytemuck::from_bytes(&raw[8..]);
    assert_eq!(acc.origin_len as usize, short_origin.len());
    assert_eq!(&acc.origin[..short_origin.len()], short_origin.as_bytes());
    assert!(
        acc.origin[short_origin.len()..].iter().all(|b| *b == 0),
        "bytes beyond origin_len must be zero-padded"
    );
}

// ---------------------------------------------------------------------------
// cluster_tag
// ---------------------------------------------------------------------------

#[test]
fn rejects_zero_cluster_tag() {
    let mut args = honest_args([9u8; 32]);
    args.cluster_tag = [0u8; 32];
    expect_reject(args, err::ZERO_CLUSTER_TAG);
}

// ---------------------------------------------------------------------------
// Policy validation
// ---------------------------------------------------------------------------

#[test]
fn rejects_bad_policy_ordering() {
    let mut args = honest_args([10u8; 32]);
    let mint = Pubkey::new_unique();
    // per_tx > per_day violates the required per_tx <= per_day <= per_30d.
    args.policy.caps[0] = MintCap { mint, per_tx: 500, per_day: 100, per_30d: 1000 };
    expect_reject(args, err::INVALID_POLICY);
}

#[test]
fn rejects_session_ceiling_above_cap() {
    let mut args = honest_args([11u8; 32]);
    let mint = Pubkey::new_unique();
    args.policy.caps[0] = MintCap { mint, per_tx: 100, per_day: 200, per_30d: 1000 };
    args.policy.session_ceiling[0] = MintCap { mint, per_tx: 101, per_day: 200, per_30d: 1000 };
    expect_reject(args, err::INVALID_POLICY);
}

#[test]
fn rejects_timelock_below_one_hour() {
    let mut args = honest_args([12u8; 32]);
    args.policy.timelock_secs = MIN_TIMELOCK_SECS - 1;
    expect_reject(args, err::INVALID_POLICY);
}

#[test]
fn rejects_max_session_life_above_30_days() {
    let mut args = honest_args([13u8; 32]);
    args.policy.max_session_life_secs = MAX_SESSION_LIFE_SECS + 1;
    expect_reject(args, err::INVALID_POLICY);
}

#[test]
fn policy_version_is_forced_to_1_regardless_of_input() {
    let (mut svm, payer) = common::setup();
    let mut args = honest_args([14u8; 32]);
    args.policy.version = 99;
    let (pda, _) = account_pda(&args.owner_seed);
    send(&mut svm, &payer, &args).unwrap_or_else(|e| panic!("must succeed: {:?} {:#?}", e.err, e.meta.logs));
    let raw = svm.get_account(&pda).unwrap().data;
    let acc: SmartAccount = *bytemuck::from_bytes(&raw[8..]);
    assert_eq!(acc.policy.version, 1);
}

// ---------------------------------------------------------------------------
// PDA derivation
// ---------------------------------------------------------------------------

/// Same root key, different `owner_seed` — the PDA must be a function of the
/// seed, never of the root key, so two accounts controlled by the same
/// passkey land at two independent addresses.
#[test]
fn pda_is_hash_of_seed_not_root() {
    let (mut svm, payer) = common::setup();
    let root = RootKey::P256Passkey { pubkey: [0x22u8; 33] };

    let mut a1 = honest_args([15u8; 32]);
    a1.root = root.clone();
    let mut a2 = honest_args([16u8; 32]);
    a2.root = root;

    let (pda1, _) = account_pda(&a1.owner_seed);
    let (pda2, _) = account_pda(&a2.owner_seed);
    assert_ne!(pda1, pda2, "different owner_seed must derive different PDAs");

    send(&mut svm, &payer, &a1).unwrap_or_else(|e| panic!("first create must succeed: {:?} {:#?}", e.err, e.meta.logs));
    send(&mut svm, &payer, &a2).unwrap_or_else(|e| panic!("second create must succeed: {:?} {:#?}", e.err, e.meta.logs));

    let acc1: SmartAccount = *bytemuck::from_bytes(&svm.get_account(&pda1).unwrap().data[8..]);
    let acc2: SmartAccount = *bytemuck::from_bytes(&svm.get_account(&pda2).unwrap().data[8..]);
    assert_eq!(acc1.root().unwrap(), acc2.root().unwrap(), "both accounts share the same root key");
    assert_eq!(acc1.owner_seed, a1.owner_seed);
    assert_eq!(acc2.owner_seed, a2.owner_seed);
}

#[test]
fn double_create_fails() {
    let (mut svm, payer) = common::setup();
    let args = honest_args([17u8; 32]);
    send(&mut svm, &payer, &args).unwrap_or_else(|e| panic!("first create must succeed: {:?} {:#?}", e.err, e.meta.logs));

    // Second create_account for the SAME owner_seed must fail — the PDA
    // already has our discriminator/owner set, so Anchor's `init` refuses
    // before the handler body ever runs again.
    let err = send(&mut svm, &payer, &args).expect_err("second create_account for the same seed must fail");
    assert!(
        !err.meta.logs.iter().any(|l| l.contains("panicked")),
        "program panicked instead of returning an error: {:#?}",
        err.meta.logs
    );

    // The original account must be untouched (still generation 0, still the
    // same root) — a partially-applied double-create would be worse than an
    // outright failure.
    let (pda, _) = account_pda(&args.owner_seed);
    let acc: SmartAccount = *bytemuck::from_bytes(&svm.get_account(&pda).unwrap().data[8..]);
    assert_eq!(acc.generation, 0);
    assert_eq!(acc.root().unwrap(), args.root);
}

/// Local re-implementation of the on-chain SHA-256(origin) check, so tests
/// that deliberately bend `origin` can still supply a *matching* rp_id_hash
/// and isolate the origin-shape check under test from the hash check.
fn sha256_of(origin: &[u8]) -> [u8; 32] {
    Sha256::digest(origin).into()
}
