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
use std::str::FromStr;
use warden::constants::{MAX_MINTS_AT_CREATE, MAX_MINT_CAPS};
use warden::instructions::create_account::{CreateAccountArgs, MAX_ORIGIN_LEN, MAX_SESSION_LIFE_SECS, MIN_TIMELOCK_SECS};
use warden::state::{MintCap, PolicyArgs, RootKey, SmartAccount};

/// Solana's transaction packet limit (`PACKET_DATA_SIZE`) — the number the
/// round-1 review's critical finding measured `create_account` against.
const PACKET_DATA_SIZE: usize = 1232;

mod err {
    // Same numbering scheme as `root_verify.rs`'s `mod err` (6000 +
    // declaration index); these are appended after `RootKindUnsupported`
    // (6024), so the Task 4 additions start at 6025.
    pub const INVALID_ACCOUNT_DATA: u32 = 6009;
    pub const INVALID_ROOT_ASSERTION: u32 = 6003;
    pub const INVALID_ORIGIN: u32 = 6025;
    pub const ZERO_CLUSTER_TAG: u32 = 6026;
    pub const INVALID_POLICY: u32 = 6027;
}

/// A realistic-looking, but not otherwise significant, mint pubkey — these
/// are never read by the program, so any distinct `Pubkey` would do; string
/// literals just make the 2-mint tests read like a real SOL+USDC policy.
fn native_sol_mint() -> Pubkey {
    Pubkey::from_str("So11111111111111111111111111111111111111112").unwrap()
}
fn usdc_mint() -> Pubkey {
    Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap()
}

/// SOL + USDC, each with a cap, a session ceiling, and a large-transfer
/// threshold — the shape a real wallet would configure at creation time.
fn realistic_two_mint_policy() -> PolicyArgs {
    let sol = native_sol_mint();
    let usdc = usdc_mint();
    PolicyArgs {
        version: 1,
        caps: vec![
            MintCap { mint: sol, per_tx: 5_000_000_000, per_day: 20_000_000_000, per_30d: 200_000_000_000 },
            MintCap { mint: usdc, per_tx: 1_000_000_000, per_day: 5_000_000_000, per_30d: 50_000_000_000 },
        ],
        session_ceiling: vec![
            MintCap { mint: sol, per_tx: 1_000_000_000, per_day: 5_000_000_000, per_30d: 50_000_000_000 },
            MintCap { mint: usdc, per_tx: 500_000_000, per_day: 2_000_000_000, per_30d: 20_000_000_000 },
        ],
        large_threshold: vec![
            MintCap { mint: sol, per_tx: 10_000_000_000, per_day: 0, per_30d: 0 },
            MintCap { mint: usdc, per_tx: 2_000_000_000, per_day: 0, per_30d: 0 },
        ],
        timelock_secs: MIN_TIMELOCK_SECS,
        recovery_delay_secs: MIN_TIMELOCK_SECS,
        max_session_life_secs: MAX_SESSION_LIFE_SECS,
        session_ops_ceiling: 10,
    }
}

/// `n` distinct mints, each with a cap, ceiling, and threshold — the
/// heaviest per-mint shape `create_account` supports. Used both for the
/// `MAX_MINTS_AT_CREATE`-mint case (which must fit and does get submitted)
/// and the `MAX_MINT_CAPS`-mint case (which documents why `create_account`
/// caps below the on-chain array width — never submitted, since `expand`
/// rejects more than `MAX_MINTS_AT_CREATE` mints structurally regardless of
/// byte size).
fn n_mints_policy(n: usize) -> PolicyArgs {
    let mints: Vec<Pubkey> = (0..n).map(|_| Pubkey::new_unique()).collect();
    PolicyArgs {
        version: 1,
        caps: mints.iter().map(|m| MintCap { mint: *m, per_tx: 1_000, per_day: 10_000, per_30d: 100_000 }).collect(),
        session_ceiling: mints
            .iter()
            .map(|m| MintCap { mint: *m, per_tx: 500, per_day: 5_000, per_30d: 50_000 })
            .collect(),
        large_threshold: mints.iter().map(|m| MintCap { mint: *m, per_tx: 2_000, per_day: 0, per_30d: 0 }).collect(),
        timelock_secs: MIN_TIMELOCK_SECS,
        recovery_delay_secs: MIN_TIMELOCK_SECS,
        max_session_life_secs: MAX_SESSION_LIFE_SECS,
        session_ops_ceiling: 10,
    }
}

/// Build the full signed transaction for `args` and return
/// `(measured byte length, the transaction)` without submitting it — the
/// wire-size tests need the length before deciding whether to assert
/// success.
fn build_tx(payer: &solana_sdk::signature::Keypair, svm: &litesvm::LiteSVM, args: &CreateAccountArgs) -> (usize, Transaction) {
    let (pda, _) = account_pda(&args.owner_seed);
    let ix = create_account_ix(payer.pubkey(), pda, args);
    let tx = Transaction::new(&[payer], Message::new(&[ix], Some(&payer.pubkey())), svm.latest_blockhash());
    let len = bincode::serialize(&tx).unwrap().len();
    (len, tx)
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
    args.policy.caps = vec![MintCap { mint, per_tx: 500, per_day: 100, per_30d: 1000 }];
    expect_reject(args, err::INVALID_POLICY);
}

#[test]
fn rejects_session_ceiling_above_cap() {
    let mut args = honest_args([11u8; 32]);
    let mint = Pubkey::new_unique();
    args.policy.caps = vec![MintCap { mint, per_tx: 100, per_day: 200, per_30d: 1000 }];
    args.policy.session_ceiling = vec![MintCap { mint, per_tx: 101, per_day: 200, per_30d: 1000 }];
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

// ---------------------------------------------------------------------------
// Wire size (round-1 review, Critical) — PolicyArgs is sparse (Vec<MintCap>,
// each ≤ MAX_MINTS_AT_CREATE), not the fixed 8-slot arrays that made a
// no-mints-configured create_account already exceed the packet limit. These
// two tests are the actual regression test for that finding: they build a
// FULL signed transaction (precompile-free — create_account needs none) and
// assert on its real wire length, not just print it.
// ---------------------------------------------------------------------------

#[test]
fn realistic_two_mint_policy_transaction_fits_the_packet_limit() {
    let (mut svm, payer) = common::setup();
    let mut args = honest_args([30u8; 32]);
    args.policy = realistic_two_mint_policy();
    let (len, tx) = build_tx(&payer, &svm, &args);
    println!("create_account (2 mints, full policy) tx: {len} B");
    assert!(
        len <= PACKET_DATA_SIZE,
        "2-mint create_account transaction is {len} B, over the {PACKET_DATA_SIZE} B packet limit"
    );
    svm.send_transaction(tx).unwrap_or_else(|e| panic!("must succeed: {:?} {:#?}", e.err, e.meta.logs));
}

#[test]
fn max_mints_at_create_transaction_fits_the_packet_limit() {
    let (mut svm, payer) = common::setup();
    let mut args = honest_args([31u8; 32]);
    args.policy = n_mints_policy(MAX_MINTS_AT_CREATE);
    let (len, tx) = build_tx(&payer, &svm, &args);
    println!("create_account ({MAX_MINTS_AT_CREATE} mints, full policy) tx: {len} B");
    let msg = format!(
        "MAX_MINTS_AT_CREATE={MAX_MINTS_AT_CREATE} create_account transaction is {len} B, over the {PACKET_DATA_SIZE} B packet limit — MAX_MINTS_AT_CREATE must be lowered, not this assertion"
    );
    assert!(len <= PACKET_DATA_SIZE, "{msg}");
    svm.send_transaction(tx).unwrap_or_else(|e| panic!("must succeed: {:?} {:#?}", e.err, e.meta.logs));
}

/// Documents the actual measured reason `MAX_MINTS_AT_CREATE` (4) is below
/// `MAX_MINT_CAPS` (8): a `create_account` carrying every on-chain array
/// slot, fully populated (cap + ceiling + threshold per mint), measured on
/// the raw wire — never submitted, since `PolicyArgs::expand` already
/// rejects more than `MAX_MINTS_AT_CREATE` mints structurally regardless of
/// byte size (`rejects_more_mints_than_max_mints_at_create`). If this ever
/// starts passing (e.g. a leaner wire format), that is a signal
/// `MAX_MINTS_AT_CREATE` could be reconsidered, not that this test should
/// simply be deleted.
#[test]
fn full_max_mint_caps_policy_does_not_fit_the_packet_limit() {
    let (svm, payer) = common::setup();
    let mut args = honest_args([38u8; 32]);
    args.policy = n_mints_policy(MAX_MINT_CAPS);
    let (len, _tx) = build_tx(&payer, &svm, &args);
    println!("create_account ({MAX_MINT_CAPS} mints, full policy, NOT submitted) tx: {len} B");
    assert!(
        len > PACKET_DATA_SIZE,
        "a full {MAX_MINT_CAPS}-mint policy measured {len} B, which now fits the {PACKET_DATA_SIZE} B \
         packet limit — MAX_MINTS_AT_CREATE ({MAX_MINTS_AT_CREATE}) could be raised"
    );
}

#[test]
fn rejects_more_mints_than_max_mints_at_create() {
    let mut args = honest_args([32u8; 32]);
    args.policy.caps = (0..(MAX_MINTS_AT_CREATE + 1))
        .map(|_| MintCap { mint: Pubkey::new_unique(), per_tx: 1, per_day: 1, per_30d: 1 })
        .collect();
    expect_reject(args, err::INVALID_ACCOUNT_DATA);
}

// ---------------------------------------------------------------------------
// session_ceiling/large_threshold keyed by mint (round-1 review, Important)
// ---------------------------------------------------------------------------

#[test]
fn rejects_mismatched_mint_ceiling() {
    let mut args = honest_args([33u8; 32]);
    let sol = Pubkey::new_unique();
    let usdc = Pubkey::new_unique();
    args.policy.caps = vec![MintCap { mint: sol, per_tx: 100, per_day: 200, per_30d: 1000 }];
    // usdc has no cap at all — the ceiling names a mint that isn't configured.
    args.policy.session_ceiling = vec![MintCap { mint: usdc, per_tx: 1, per_day: 1, per_30d: 1 }];
    expect_reject(args, err::INVALID_ACCOUNT_DATA);
}

#[test]
fn rejects_orphan_ceiling_with_no_caps_at_all() {
    let mut args = honest_args([34u8; 32]);
    args.policy.session_ceiling = vec![MintCap { mint: Pubkey::new_unique(), per_tx: 1, per_day: 1, per_30d: 1 }];
    expect_reject(args, err::INVALID_ACCOUNT_DATA);
}

#[test]
fn rejects_duplicate_cap_mint() {
    let mut args = honest_args([35u8; 32]);
    let mint = Pubkey::new_unique();
    args.policy.caps = vec![
        MintCap { mint, per_tx: 100, per_day: 200, per_30d: 1000 },
        MintCap { mint, per_tx: 1, per_day: 2, per_30d: 3 },
    ];
    expect_reject(args, err::INVALID_ACCOUNT_DATA);
}

#[test]
fn rejects_duplicate_ceiling_mint() {
    let mut args = honest_args([36u8; 32]);
    let mint = Pubkey::new_unique();
    args.policy.caps = vec![MintCap { mint, per_tx: 100, per_day: 200, per_30d: 1000 }];
    args.policy.session_ceiling = vec![
        MintCap { mint, per_tx: 1, per_day: 1, per_30d: 1 },
        MintCap { mint, per_tx: 2, per_day: 2, per_30d: 2 },
    ];
    expect_reject(args, err::INVALID_ACCOUNT_DATA);
}

/// The keying itself, proven end-to-end through a real create_account
/// transaction and readback — not just at the `PolicyArgs::expand` unit
/// level (`smart_account.rs` has that too). `caps[0]` is USDC, `caps[1]` is
/// SOL; the wire `session_ceiling` names SOL FIRST, which would land at
/// index 0 (USDC's slot) if re-keying were positional instead of by-mint.
#[test]
fn ceiling_stored_at_the_caps_index_not_wire_position() {
    let (mut svm, payer) = common::setup();
    let usdc = Pubkey::new_unique();
    let sol = Pubkey::new_unique();
    let mut args = honest_args([37u8; 32]);
    args.policy.caps = vec![
        MintCap { mint: usdc, per_tx: 50, per_day: 100, per_30d: 500 },
        MintCap { mint: sol, per_tx: 100, per_day: 200, per_30d: 1000 },
    ];
    args.policy.session_ceiling = vec![MintCap { mint: sol, per_tx: 10, per_day: 20, per_30d: 100 }];
    args.policy.large_threshold = vec![MintCap { mint: sol, per_tx: 5, per_day: 0, per_30d: 0 }];
    send(&mut svm, &payer, &args).unwrap_or_else(|e| panic!("must succeed: {:?} {:#?}", e.err, e.meta.logs));

    let (pda, _) = account_pda(&args.owner_seed);
    let raw = svm.get_account(&pda).unwrap().data;
    let acc: SmartAccount = *bytemuck::from_bytes(&raw[8..]);
    assert_eq!(acc.policy.caps[0].mint, usdc);
    assert_eq!(acc.policy.caps[1].mint, sol);
    assert_eq!(acc.policy.session_ceiling[1].mint, sol, "SOL's ceiling must land at SOL's cap index (1)");
    assert_eq!(acc.policy.session_ceiling[1].per_tx, 10);
    assert_eq!(acc.policy.session_ceiling[0].mint, Pubkey::default(), "USDC's slot must stay unused");
    assert_eq!(acc.policy.large_threshold[1].mint, sol, "SOL's threshold must land at SOL's cap index (1)");
    assert_eq!(acc.policy.large_threshold[1].per_tx, 5);
    assert_eq!(acc.policy.large_threshold[0].mint, Pubkey::default());
}

/// Local re-implementation of the on-chain SHA-256(origin) check, so tests
/// that deliberately bend `origin` can still supply a *matching* rp_id_hash
/// and isolate the origin-shape check under test from the hash check.
fn sha256_of(origin: &[u8]) -> [u8; 32] {
    Sha256::digest(origin).into()
}
