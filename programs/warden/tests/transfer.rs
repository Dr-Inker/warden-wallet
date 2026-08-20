//! LiteSVM coverage of `transfer` (Task 7) — the instruction that realises the
//! wallet's headline property: **a phished user loses at most the session
//! cap**, because every outflow, whoever authorizes it, debits the same
//! account-wide day / rolling-30-day buckets.
//!
//! Two authorization shapes share one instruction:
//! ```text
//! session path:  ix[0] = warden::transfer            (session key signs)
//! root path:     ix[0] = Secp256r1SigVerify precompile
//!                ix[1] = warden::transfer            (root: Some(..))
//! ```
//!
//! The root ceremony signs `borsh(TransferBody { native, mint, destination,
//! amount })` where `destination` is **the account actually passed**, which is
//! what `root_transfer_with_substituted_destination_rejected` proves.

mod common;

use anchor_lang::AnchorSerialize;
use common::passkey::{self, TestPasskey, FLAGS_UP_UV, TEST_ORIGIN};
use common::token::{ata, set_mint, set_token_account, token_amount, token_program_id};
use common::{
    bump_generation, clear_policy_cap, create_smart_account, read_session, read_smart_account,
    session_pda, warp_clock, SmartAccountFixture,
};
use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_sdk::{
    account::Account,
    clock::Clock,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::Message,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    sysvar,
    transaction::{Transaction, TransactionError},
};
use warden::constants::{DAY_SECS, NATIVE_MINT, SPL_TOKEN_2022_ID, SPL_TOKEN_ID};
use warden::instructions::create_account::MIN_TIMELOCK_SECS;
use warden::instructions::grant_session::{GrantBody, GrantSessionArgs};
use warden::instructions::transfer::{TransferArgs, TransferBody};
use warden::root_verify::transcript::{
    action_hash, b64url_no_pad, transcript_hash, OP_FREEZE, OP_GRANT_SESSION, OP_TRANSFER_ACTION,
};
use warden::root_verify::RootArgs;
use warden::state::{MintCap, PolicyArgs, SmartAccount, OP_EXECUTE, OP_SIGN_MESSAGE, OP_TRANSFER};

const NOW: i64 = 1_760_000_000;
/// Solana's transaction packet limit (`PACKET_DATA_SIZE`).
const PACKET_DATA_SIZE: usize = 1232;
const ROOT_EXPIRY_OFFSET: i64 = 60;
/// 30 days — the fixture policy's `max_session_life_secs`, so the rolling-30d
/// test can warp several days forward without the session expiring under it.
const SESSION_LIFE: i64 = 30 * DAY_SECS;

/// Lamports the vault is funded with beyond its rent-exempt minimum.
const VAULT_FUNDING: u64 = 100_000_000;

// Account-wide (policy) caps for native SOL, in lamports.
const SOL_PER_TX: u64 = 1_000_000;
const SOL_PER_DAY: u64 = 1_200_000;
const SOL_PER_30D: u64 = 2_000_000;
/// The most a session may ever be granted for SOL.
const SOL_SESSION_PER_TX: u64 = 600_000;
/// `policy.large_threshold[SOL].per_tx` — the ceiling on a DIRECT root
/// transfer. Above it, Phase 1B's `queue` (timelocked) is the only route.
const SOL_LARGE_THRESHOLD: u64 = 800_000;

// Account-wide caps for the SPL fixture mint (6 decimals, so these are raw
// base units).
const TOK_PER_TX: u64 = 1_000;
const TOK_PER_DAY: u64 = 1_200;
const TOK_PER_30D: u64 = 2_000;
const TOK_SESSION_PER_TX: u64 = 600;
const TOK_LARGE_THRESHOLD: u64 = 800;
/// Starting balance of the vault's ATA.
const VAULT_TOKENS: u64 = 10_000;

/// Anchor error codes as literals — the same pinned table as
/// `root_verify.rs`'s `mod err` (6000 + declaration index), whose
/// `pinned_error_codes_match_the_enum_today` is the single place the enum is
/// consulted. Task 7's additions start at 6031.
mod err {
    pub const OVERFLOW: u32 = 6000;
    pub const FROZEN: u32 = 6001;
    pub const UNAUTHORIZED: u32 = 6002;
    pub const CAP_EXCEEDED: u32 = 6006;
    pub const SESSION_EXPIRED: u32 = 6007;
    pub const OP_NOT_ALLOWED: u32 = 6008;
    pub const INVALID_ACCOUNT_DATA: u32 = 6009;
    pub const BAD_INSTRUCTION_LAYOUT: u32 = 6010;
    pub const CHALLENGE_MISMATCH: u32 = 6018;
    pub const RENT_FLOOR: u32 = 6031;
    pub const VAULT_DESTINATION: u32 = 6032;
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// The SPL mint the transfer suite uses. A fixed, off-curve-agnostic address:
/// nothing signs for it (the planted mint has no mint authority).
fn tok_mint() -> Pubkey {
    Pubkey::new_from_array([9u8; 32])
}

/// A mint with an account-level cap but NO `session_ceiling` — used to prove a
/// session cannot move a mint it was never granted.
fn ungranted_mint() -> Pubkey {
    Pubkey::new_from_array([11u8; 32])
}

fn transfer_policy() -> PolicyArgs {
    PolicyArgs {
        version: 1,
        caps: vec![
            MintCap { mint: NATIVE_MINT, per_tx: SOL_PER_TX, per_day: SOL_PER_DAY, per_30d: SOL_PER_30D },
            MintCap { mint: tok_mint(), per_tx: TOK_PER_TX, per_day: TOK_PER_DAY, per_30d: TOK_PER_30D },
            MintCap { mint: ungranted_mint(), per_tx: 10, per_day: 10, per_30d: 10 },
        ],
        session_ceiling: vec![
            MintCap {
                mint: NATIVE_MINT,
                per_tx: SOL_SESSION_PER_TX,
                per_day: SOL_PER_DAY,
                per_30d: SOL_PER_30D,
            },
            MintCap {
                mint: tok_mint(),
                per_tx: TOK_SESSION_PER_TX,
                per_day: TOK_PER_DAY,
                per_30d: TOK_PER_30D,
            },
        ],
        large_threshold: vec![
            MintCap { mint: NATIVE_MINT, per_tx: SOL_LARGE_THRESHOLD, per_day: 0, per_30d: 0 },
            MintCap { mint: tok_mint(), per_tx: TOK_LARGE_THRESHOLD, per_day: 0, per_30d: 0 },
        ],
        timelock_secs: MIN_TIMELOCK_SECS,
        recovery_delay_secs: MIN_TIMELOCK_SECS,
        max_session_life_secs: SESSION_LIFE,
        session_ops_ceiling: OP_TRANSFER | OP_EXECUTE,
    }
}

/// A live SVM with one real, passkey-rooted account holding
/// `transfer_policy`, funded with `VAULT_FUNDING` lamports above rent.
fn live() -> (LiteSVM, Keypair, TestPasskey, Pubkey) {
    let (mut svm, payer) = common::setup();
    warp_clock(&mut svm, NOW);
    let pk = TestPasskey::new(3);
    let f = SmartAccountFixture {
        root_pubkey33: pk.pubkey33(),
        policy: transfer_policy(),
        ..Default::default()
    };
    let account = create_smart_account(&mut svm, &payer, &f, &pk);
    svm.airdrop(&account, VAULT_FUNDING).expect("fund the vault");
    (svm, payer, pk, account)
}

/// `live()` plus the SPL fixtures: the mint, the vault's ATA holding
/// `VAULT_TOKENS`, and an empty destination token account owned by `dest_owner`.
fn live_spl() -> (LiteSVM, Keypair, TestPasskey, Pubkey, Pubkey, Pubkey) {
    let (mut svm, payer, pk, account) = live();
    let mint = tok_mint();
    set_mint(&mut svm, &mint, 6, 1_000_000_000);
    let vault_ata = ata(&account, &mint);
    set_token_account(&mut svm, &vault_ata, &mint, &account, VAULT_TOKENS);
    let dest_owner = Pubkey::new_unique();
    let dest_ata = ata(&dest_owner, &mint);
    set_token_account(&mut svm, &dest_ata, &mint, &dest_owner, 0);
    (svm, payer, pk, account, vault_ata, dest_ata)
}

// ---------------------------------------------------------------------------
// Instruction builders
// ---------------------------------------------------------------------------

/// Anchor's placeholder for an omitted `Option<...>` account: the program id
/// itself (see `anchor-syn`'s optional-account codegen).
fn none_account() -> AccountMeta {
    AccountMeta::new_readonly(common::program_id(), false)
}

#[allow(clippy::too_many_arguments)]
fn transfer_ix(
    signer: Pubkey,
    smart_account: Pubkey,
    session: Option<Pubkey>,
    with_sysvar: bool,
    destination: Pubkey,
    source_ata: Option<Pubkey>,
    token_program: Option<Pubkey>,
    args: &TransferArgs,
) -> Instruction {
    let mut data = Sha256::digest(b"global:transfer")[..8].to_vec();
    args.serialize(&mut data).unwrap();
    Instruction {
        program_id: common::program_id(),
        accounts: vec![
            AccountMeta::new_readonly(signer, true),
            AccountMeta::new(smart_account, false),
            session.map_or_else(none_account, |s| AccountMeta::new(s, false)),
            if with_sysvar {
                AccountMeta::new_readonly(sysvar::instructions::ID, false)
            } else {
                none_account()
            },
            AccountMeta::new(destination, false),
            source_ata.map_or_else(none_account, |s| AccountMeta::new(s, false)),
            token_program.map_or_else(none_account, |t| AccountMeta::new_readonly(t, false)),
        ],
        data,
    }
}

fn grant_ix(payer: Pubkey, smart_account: Pubkey, session: Pubkey, args: &GrantSessionArgs) -> Instruction {
    let mut data = Sha256::digest(b"global:grant_session")[..8].to_vec();
    args.serialize(&mut data).unwrap();
    Instruction {
        program_id: common::program_id(),
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(smart_account, false),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(sysvar::instructions::ID, false),
            AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
            // Optional `registry` (Task 3, WRDF-0044): program-id sentinel = None.
            // These grants are `program_allowlist_id == 0`, so it is never read.
            AccountMeta::new_readonly(common::program_id(), false),
        ],
        data,
    }
}

fn freeze_ix(smart_account: Pubkey, args: &RootArgs) -> Instruction {
    let mut data = Sha256::digest(b"global:freeze")[..8].to_vec();
    args.serialize(&mut data).unwrap();
    Instruction {
        program_id: common::program_id(),
        accounts: vec![
            AccountMeta::new(smart_account, false),
            AccountMeta::new_readonly(sysvar::instructions::ID, false),
        ],
        data,
    }
}

/// Sign the honest transcript for `action_hash` against the account's CURRENT
/// on-chain state, with the ceremony's freshness window relative to whatever
/// time the SVM's clock is at.
fn ceremony(svm: &LiteSVM, account: &Pubkey, pk: &TestPasskey, ah: [u8; 32]) -> (Instruction, RootArgs) {
    let st = read_smart_account(svm, account);
    let clock: Clock = svm.get_sysvar();
    let expiry_ts = clock.unix_timestamp + ROOT_EXPIRY_OFFSET;
    // Signed slot = the slot the client observes (spec §4); read from the SVM
    // so a warped clock still yields a fresh ceremony. The slot-window
    // boundaries are owned by `root_verify.rs`.
    let signed_slot = clock.slot;
    let t = transcript_hash(
        &st.cluster_tag,
        &common::program_id(),
        account,
        st.generation,
        st.policy.version,
        st.root_nonce,
        expiry_ts,
        signed_slot,
        &ah,
    );
    let a = pk.assert_with_client_data(
        passkey::client_data_json(&b64url_no_pad(&t), TEST_ORIGIN),
        passkey::rp_id_hash(TEST_ORIGIN),
        FLAGS_UP_UV,
    );
    let args = RootArgs {
        precompile_ix_index: 0,
        authenticator_data: a.authenticator_data.clone(),
        client_data_json: a.client_data_json.clone(),
        expiry_ts,
        signed_slot,
    };
    (passkey::precompile_ix(&a, &pk.pubkey33()), args)
}

// ---------------------------------------------------------------------------
// Send / assert helpers
// ---------------------------------------------------------------------------

fn send(svm: &mut LiteSVM, signers: &[&Keypair], ixs: &[Instruction]) -> litesvm::types::TransactionResult {
    svm.expire_blockhash();
    let tx = Transaction::new(
        signers,
        Message::new(ixs, Some(&signers[0].pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
}

fn expect_ok(svm: &mut LiteSVM, signers: &[&Keypair], ixs: &[Instruction]) -> litesvm::types::TransactionMetadata {
    send(svm, signers, ixs).unwrap_or_else(|e| panic!("must succeed: {:?} {:#?}", e.err, e.meta.logs))
}

fn expect_reject(svm: &mut LiteSVM, signers: &[&Keypair], ixs: &[Instruction], ix_index: u8, expected: u32) {
    let e = send(svm, signers, ixs).expect_err("must be rejected");
    assert_eq!(
        e.err,
        TransactionError::InstructionError(ix_index, InstructionError::Custom(expected)),
        "wrong failure mode; logs={:#?}",
        e.meta.logs
    );
    assert!(
        !e.meta.logs.iter().any(|l| l.contains("panicked")),
        "program panicked instead of returning an error: {:#?}",
        e.meta.logs
    );
}

fn lamports(svm: &LiteSVM, key: &Pubkey) -> u64 {
    svm.get_account(key).map_or(0, |a| a.lamports)
}

/// Lamports every SOL destination is pre-funded with.
///
/// Solana's runtime rejects any transaction that leaves a *credited* account
/// below the rent-exempt minimum for its size (890,880 lamports for a 0-byte
/// system account) — `InsufficientFundsForRent`, raised after the instruction
/// returns `Ok`, so it is not a program error and cannot be caught by one.
/// Real destinations are existing wallets, so the fixtures fund them rather
/// than scale every cap in this suite above 890,880 lamports.
const DEST_BASE: u64 = 1_000_000_000;

/// A destination that already exists and is rent-exempt.
fn funded_dest(svm: &mut LiteSVM) -> Pubkey {
    let d = Pubkey::new_unique();
    svm.airdrop(&d, DEST_BASE).expect("fund the destination");
    d
}

/// How much a funded destination has actually received.
fn received(svm: &LiteSVM, dest: &Pubkey) -> u64 {
    lamports(svm, dest) - DEST_BASE
}

/// Overwrite an account's lamports, keeping every other field. Used to park
/// the vault just above its rent floor, and to preload a destination near
/// `u64::MAX`.
fn set_lamports(svm: &mut LiteSVM, key: &Pubkey, lamports: u64) {
    let existing = svm.get_account(key).expect("account exists");
    svm.set_account(
        *key,
        Account {
            lamports,
            data: existing.data,
            owner: existing.owner,
            executable: existing.executable,
            rent_epoch: existing.rent_epoch,
        },
    )
    .expect("set_account");
}

fn rent_floor(svm: &LiteSVM) -> u64 {
    svm.minimum_balance_for_rent_exemption(SmartAccount::LEN)
}

// ---------------------------------------------------------------------------
// Grant helper (a real root ceremony, so sessions under test are honest)
// ---------------------------------------------------------------------------

fn grant_body(session_pubkey: Pubkey, ops_mask: u16, caps: Vec<MintCap>, lifetime_cap: Vec<u64>, life: i64) -> GrantBody {
    GrantBody {
        expiry_ts: NOW + life,
        session_pubkey,
        kind: warden::constants::SESSION_KIND_ED25519,
        ops_mask,
        caps,
        lifetime_cap,
        program_allowlist_id: 0,
        label: [0u8; 16],
        // Every session in this suite is granted exactly once, into a PDA
        // that does not exist yet — the all-zero prior-state sentinel.
        prior_authority_hash: [0u8; 32],
    }
}

/// A session cap as Phase 1A allows it: `per_tx` only. `per_day`/`per_30d`
/// MUST be 0 — `grant_session` rejects anything else
/// (`SessionDayCapsUnsupported`), because the day and rolling-30-day bounds
/// are the account-wide buckets every session and the root share.
fn sol_cap() -> MintCap {
    MintCap { mint: NATIVE_MINT, per_tx: SOL_SESSION_PER_TX, per_day: 0, per_30d: 0 }
}

fn tok_cap() -> MintCap {
    MintCap { mint: tok_mint(), per_tx: TOK_SESSION_PER_TX, per_day: 0, per_30d: 0 }
}

/// Grant `body` through a real root ceremony and return the session PDA.
fn grant(svm: &mut LiteSVM, payer: &Keypair, account: &Pubkey, pk: &TestPasskey, body: GrantBody) -> Pubkey {
    let mut body_bytes = Vec::new();
    body.serialize(&mut body_bytes).unwrap();
    let (precompile, root) = ceremony(svm, account, pk, action_hash(OP_GRANT_SESSION, &body_bytes));
    let (session, _) = session_pda(account, &body.session_pubkey);
    let args = GrantSessionArgs { root, body };
    let ixs = vec![precompile, grant_ix(payer.pubkey(), *account, session, &args)];
    expect_ok(svm, &[payer], &ixs);
    session
}

/// The default session: SOL + the fixture mint, transfer-enabled, generous
/// lifetime caps, 10 days of life.
fn grant_default_session(
    svm: &mut LiteSVM,
    payer: &Keypair,
    account: &Pubkey,
    pk: &TestPasskey,
    session_kp: &Keypair,
) -> Pubkey {
    grant(
        svm,
        payer,
        account,
        pk,
        grant_body(
            session_kp.pubkey(),
            OP_TRANSFER,
            vec![sol_cap(), tok_cap()],
            vec![u64::MAX, u64::MAX],
            10 * DAY_SECS,
        ),
    )
}

fn session_sol_ix(session_kp: &Keypair, account: Pubkey, session: Pubkey, dest: Pubkey, amount: u64) -> Instruction {
    let args = TransferArgs { root: None, mint: None, amount };
    transfer_ix(session_kp.pubkey(), account, Some(session), false, dest, None, None, &args)
}

fn session_spl_ix(
    session_kp: &Keypair,
    account: Pubkey,
    session: Pubkey,
    source_ata: Pubkey,
    dest_ata: Pubkey,
    mint: Pubkey,
    amount: u64,
) -> Instruction {
    let args = TransferArgs { root: None, mint: Some(mint), amount };
    transfer_ix(
        session_kp.pubkey(),
        account,
        Some(session),
        false,
        dest_ata,
        Some(source_ata),
        Some(token_program_id()),
        &args,
    )
}

/// Build a ROOT native transfer whose ceremony signs `signed_dest` but whose
/// instruction passes `submitted_dest` — equal in every honest case.
fn root_sol_ixs(
    svm: &LiteSVM,
    payer: &Keypair,
    account: &Pubkey,
    pk: &TestPasskey,
    signed_dest: Pubkey,
    submitted_dest: Pubkey,
    amount: u64,
) -> Vec<Instruction> {
    let body = TransferBody {
        native: true,
        mint: Pubkey::default(),
        destination: signed_dest,
        amount,
    };
    let mut body_bytes = Vec::new();
    body.serialize(&mut body_bytes).unwrap();
    let (precompile, root) = ceremony(svm, account, pk, action_hash(OP_TRANSFER_ACTION, &body_bytes));
    let args = TransferArgs { root: Some(root), mint: None, amount };
    vec![
        precompile,
        transfer_ix(payer.pubkey(), *account, None, true, submitted_dest, None, None, &args),
    ]
}

fn freeze_ixs(svm: &LiteSVM, account: &Pubkey, pk: &TestPasskey) -> Vec<Instruction> {
    let (precompile, root) = ceremony(svm, account, pk, action_hash(OP_FREEZE, &[]));
    vec![precompile, freeze_ix(*account, &root)]
}

// ===========================================================================
// Session path — native SOL
// ===========================================================================

#[test]
fn session_sol_transfer_within_caps() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);
    let dest = funded_dest(&mut svm);

    let vault_before = lamports(&svm, &account);
    let ix = session_sol_ix(&session_kp, account, session, dest, SOL_SESSION_PER_TX);
    let res = expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    println!("transfer (session, SOL) CU: {}", res.compute_units_consumed);

    assert_eq!(received(&svm, &dest), SOL_SESSION_PER_TX, "destination credited");
    assert_eq!(lamports(&svm, &account), vault_before - SOL_SESSION_PER_TX, "vault debited");

    let st = read_smart_account(&svm, &account);
    assert_eq!(st.buckets[0].spent_today, SOL_SESSION_PER_TX, "account-wide day bucket debited");
    let s = read_session(&svm, &session);
    assert_eq!(s.lifetime_spent[0], SOL_SESSION_PER_TX, "session lifetime spend recorded");
    assert!(res.compute_units_consumed < 100_000, "CU budget: {}", res.compute_units_consumed);
}

#[test]
fn session_sol_transfer_tx_fits_1232_bytes() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);
    let ix = session_sol_ix(&session_kp, account, session, Pubkey::new_unique(), 1);
    let tx = Transaction::new(
        &[&payer, &session_kp],
        Message::new(&[ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    let n = bincode::serialize(&tx).unwrap().len();
    println!("transfer (session, SOL) tx bytes: {n}");
    assert!(n <= PACKET_DATA_SIZE, "session SOL transfer must fit the packet limit: {n}");
}

#[test]
fn session_sol_over_per_tx_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);
    let dest = funded_dest(&mut svm);
    let ix = session_sol_ix(&session_kp, account, session, dest, SOL_SESSION_PER_TX + 1);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::CAP_EXCEEDED);
    assert_eq!(received(&svm, &dest), 0, "nothing moved");
}

#[test]
fn session_day_cap_across_two_txs() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);
    let dest = funded_dest(&mut svm);

    // 600k + 600k = 1.2M == per_day exactly.
    for _ in 0..2 {
        let ix = session_sol_ix(&session_kp, account, session, dest, SOL_SESSION_PER_TX);
        expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    }
    assert_eq!(received(&svm, &dest), SOL_PER_DAY);

    // The third would be 1.8M > per_day (1.2M).
    let ix = session_sol_ix(&session_kp, account, session, dest, SOL_SESSION_PER_TX);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::CAP_EXCEEDED);
    assert_eq!(received(&svm, &dest), SOL_PER_DAY, "nothing further moved");
}

/// THE headline property: two independent sessions do NOT get a day cap each.
#[test]
fn two_sessions_share_account_day_cap() {
    let (mut svm, payer, pk, account) = live();
    let a_kp = Keypair::new();
    let b_kp = Keypair::new();
    let a = grant_default_session(&mut svm, &payer, &account, &pk, &a_kp);
    let b = grant_default_session(&mut svm, &payer, &account, &pk, &b_kp);
    let dest = funded_dest(&mut svm);

    let ix = session_sol_ix(&a_kp, account, a, dest, SOL_SESSION_PER_TX);
    expect_ok(&mut svm, &[&payer, &a_kp], &[ix]);
    let ix = session_sol_ix(&b_kp, account, b, dest, SOL_SESSION_PER_TX);
    expect_ok(&mut svm, &[&payer, &b_kp], &[ix]);
    assert_eq!(received(&svm, &dest), SOL_PER_DAY, "1.2M moved between the two sessions");

    // Session B has spent only 600k of its own (unenforced-in-1A) allowance,
    // but the ACCOUNT's day bucket is exhausted — so B is refused.
    let ix = session_sol_ix(&b_kp, account, b, dest, SOL_SESSION_PER_TX);
    expect_reject(&mut svm, &[&payer, &b_kp], &[ix], 0, err::CAP_EXCEEDED);

    let sa = read_session(&svm, &a);
    let sb = read_session(&svm, &b);
    assert_eq!(sa.lifetime_spent[0], SOL_SESSION_PER_TX);
    assert_eq!(sb.lifetime_spent[0], SOL_SESSION_PER_TX, "the rejected transfer is not charged");
}

#[test]
fn session_lifetime_cap_enforced() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant(
        &mut svm,
        &payer,
        &account,
        &pk,
        grant_body(
            session_kp.pubkey(),
            OP_TRANSFER,
            vec![sol_cap()],
            // Lifetime cap is 1 lamport short of two full per_tx transfers.
            vec![SOL_SESSION_PER_TX * 2 - 1],
            10 * DAY_SECS,
        ),
    );
    let dest = funded_dest(&mut svm);
    let ix = session_sol_ix(&session_kp, account, session, dest, SOL_SESSION_PER_TX);
    expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    let ix = session_sol_ix(&session_kp, account, session, dest, SOL_SESSION_PER_TX);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::CAP_EXCEEDED);
    // …but one lamport less fits exactly.
    let ix = session_sol_ix(&session_kp, account, session, dest, SOL_SESSION_PER_TX - 1);
    expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    assert_eq!(read_session(&svm, &session).lifetime_spent[0], SOL_SESSION_PER_TX * 2 - 1);
}

#[test]
fn session_expired_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant(
        &mut svm,
        &payer,
        &account,
        &pk,
        grant_body(session_kp.pubkey(), OP_TRANSFER, vec![sol_cap()], vec![u64::MAX], DAY_SECS),
    );
    warp_clock(&mut svm, NOW + DAY_SECS);
    let ix = session_sol_ix(&session_kp, account, session, Pubkey::new_unique(), 1);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::SESSION_EXPIRED);
}

#[test]
fn session_wrong_generation_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);
    // Key rotation / recovery (Phase 1B) bumps `generation`; no 1A instruction
    // does, so the test-only back door plants it.
    bump_generation(&mut svm, &account, 1);
    let ix = session_sol_ix(&session_kp, account, session, Pubkey::new_unique(), 1);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::UNAUTHORIZED);
}

#[test]
fn session_without_transfer_op_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant(
        &mut svm,
        &payer,
        &account,
        &pk,
        grant_body(session_kp.pubkey(), OP_EXECUTE, vec![sol_cap()], vec![u64::MAX], 10 * DAY_SECS),
    );
    let ix = session_sol_ix(&session_kp, account, session, Pubkey::new_unique(), 1);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::OP_NOT_ALLOWED);
}

#[test]
fn session_signer_must_be_the_session_key() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);
    // `payer` signs the transaction and is named as the instruction's signer,
    // but is not the session's delegate key.
    let args = TransferArgs { root: None, mint: None, amount: 1 };
    let ix = transfer_ix(payer.pubkey(), account, Some(session), false, Pubkey::new_unique(), None, None, &args);
    expect_reject(&mut svm, &[&payer], &[ix], 0, err::UNAUTHORIZED);
}

#[test]
fn session_of_another_account_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);

    // A second, independent account with the same policy and root key.
    let f = SmartAccountFixture {
        salt: [42u8; 32],
        root_pubkey33: pk.pubkey33(),
        policy: transfer_policy(),
        ..Default::default()
    };
    let other = create_smart_account(&mut svm, &payer, &f, &pk);
    svm.airdrop(&other, VAULT_FUNDING).unwrap();

    let ix = session_sol_ix(&session_kp, other, session, Pubkey::new_unique(), 1);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::UNAUTHORIZED);
}

/// The SESSION's own cap lookup: a mint this session was never granted is
/// refused before the account policy is even consulted.
#[test]
fn session_mint_without_session_cap_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);
    // A mint the policy configures no cap for at all.
    let unknown = Pubkey::new_from_array([77u8; 32]);
    let args = TransferArgs { root: None, mint: Some(unknown), amount: 1 };
    let ix = transfer_ix(
        session_kp.pubkey(),
        account,
        Some(session),
        false,
        Pubkey::new_unique(),
        Some(Pubkey::new_unique()),
        Some(token_program_id()),
        &args,
    );
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::CAP_EXCEEDED);
}

/// The ACCOUNT-WIDE policy lookup, reached only when the session's own cap
/// check has already passed: the session still holds a valid SOL cap, but the
/// account's `policy.caps[SOL]` slot has been removed (1B's `set_policy` is
/// the instruction that would do this for real). Without an account cap there
/// is no bucket to debit, and "no cap configured" means **not spendable**, not
/// "unlimited" — which is the property this test exists to pin, since it is
/// the one that would silently invert if `find_cap`'s `None` were ever treated
/// as "no limit".
#[test]
fn session_mint_without_account_cap_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);
    let dest = funded_dest(&mut svm);

    // Sanity: with the policy intact this exact transfer succeeds, so the
    // rejection below can only come from the removed account cap.
    let ix = session_sol_ix(&session_kp, account, session, dest, SOL_SESSION_PER_TX);
    expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);

    // caps[0] is SOL (see `transfer_policy`); the session keeps its own cap.
    clear_policy_cap(&mut svm, &account, 0);
    assert_eq!(
        read_session(&svm, &session).caps[0].per_tx,
        SOL_SESSION_PER_TX,
        "the session's own SOL cap is untouched — the account's is what is gone"
    );

    let ix = session_sol_ix(&session_kp, account, session, dest, SOL_SESSION_PER_TX);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::CAP_EXCEEDED);
    assert_eq!(received(&svm, &dest), SOL_SESSION_PER_TX, "only the first transfer landed");
}

#[test]
fn neither_root_nor_session_rejected() {
    let (mut svm, payer, _pk, account) = live();
    let args = TransferArgs { root: None, mint: None, amount: 1 };
    let ix = transfer_ix(payer.pubkey(), account, None, false, Pubkey::new_unique(), None, None, &args);
    expect_reject(&mut svm, &[&payer], &[ix], 0, err::BAD_INSTRUCTION_LAYOUT);
}

// ===========================================================================
// Native-SOL mechanics
// ===========================================================================

#[test]
fn transfer_to_self_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);
    let ix = session_sol_ix(&session_kp, account, session, account, 1);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::INVALID_ACCOUNT_DATA);
}

#[test]
fn sol_transfer_cannot_breach_rent_floor() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);

    // Park the vault 1,000 lamports above its rent-exempt minimum.
    let floor = rent_floor(&svm);
    set_lamports(&mut svm, &account, floor + 1_000);

    let dest = funded_dest(&mut svm);
    let ix = session_sol_ix(&session_kp, account, session, dest, 1_001);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::RENT_FLOOR);

    // Exactly down to the floor is allowed.
    let ix = session_sol_ix(&session_kp, account, session, dest, 1_000);
    expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    assert_eq!(lamports(&svm, &account), floor);
}

#[test]
fn destination_lamport_overflow_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);

    let dest = Pubkey::new_unique();
    svm.set_account(
        dest,
        Account {
            lamports: u64::MAX,
            data: vec![],
            owner: anchor_lang::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    let ix = session_sol_ix(&session_kp, account, session, dest, 1);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::OVERFLOW);
}

// ===========================================================================
// SPL path
// ===========================================================================

#[test]
fn session_spl_transfer_ok() {
    let (mut svm, payer, pk, account, vault_ata, dest_ata) = live_spl();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);

    let ix = session_spl_ix(&session_kp, account, session, vault_ata, dest_ata, tok_mint(), TOK_SESSION_PER_TX);
    let res = expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    println!("transfer (session, SPL) CU: {}", res.compute_units_consumed);

    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS - TOK_SESSION_PER_TX);
    assert_eq!(token_amount(&svm, &dest_ata), TOK_SESSION_PER_TX);

    let st = read_smart_account(&svm, &account);
    assert_eq!(st.buckets[1].spent_today, TOK_SESSION_PER_TX, "the token's own bucket, not SOL's");
    assert_eq!(st.buckets[0].spent_today, 0, "SOL's bucket untouched");
    assert_eq!(read_session(&svm, &session).lifetime_spent[1], TOK_SESSION_PER_TX);
    assert!(res.compute_units_consumed < 100_000, "CU budget: {}", res.compute_units_consumed);
}

#[test]
fn session_spl_transfer_tx_fits_1232_bytes() {
    let (mut svm, payer, pk, account, vault_ata, dest_ata) = live_spl();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);
    let ix = session_spl_ix(&session_kp, account, session, vault_ata, dest_ata, tok_mint(), 1);
    let tx = Transaction::new(
        &[&payer, &session_kp],
        Message::new(&[ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    let n = bincode::serialize(&tx).unwrap().len();
    println!("transfer (session, SPL) tx bytes: {n}");
    assert!(n <= PACKET_DATA_SIZE, "session SPL transfer must fit the packet limit: {n}");
}

#[test]
fn spl_to_vault_owned_ata_rejected() {
    let (mut svm, payer, pk, account, vault_ata, _dest_ata) = live_spl();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);

    // A SECOND token account of the same mint, also owned by the vault — a
    // "transfer" into it would move nothing out of the wallet while still
    // debiting the caps (spec §5.1).
    let sink = Pubkey::new_unique();
    set_token_account(&mut svm, &sink, &tok_mint(), &account, 0);

    let ix = session_spl_ix(&session_kp, account, session, vault_ata, sink, tok_mint(), 1);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::VAULT_DESTINATION);
}

#[test]
fn spl_destination_of_wrong_mint_rejected() {
    let (mut svm, payer, pk, account, vault_ata, _dest_ata) = live_spl();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);

    let other_mint = Pubkey::new_from_array([13u8; 32]);
    set_mint(&mut svm, &other_mint, 6, 1_000);
    let wrong = Pubkey::new_unique();
    set_token_account(&mut svm, &wrong, &other_mint, &Pubkey::new_unique(), 0);

    let ix = session_spl_ix(&session_kp, account, session, vault_ata, wrong, tok_mint(), 1);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::INVALID_ACCOUNT_DATA);
}

#[test]
fn spl_source_not_owned_by_the_vault_rejected() {
    let (mut svm, payer, pk, account, _vault_ata, dest_ata) = live_spl();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);

    // Someone else's token account, named as the source.
    let stranger = Pubkey::new_unique();
    let their_ata = ata(&stranger, &tok_mint());
    set_token_account(&mut svm, &their_ata, &tok_mint(), &stranger, 5_000);

    let ix = session_spl_ix(&session_kp, account, session, their_ata, dest_ata, tok_mint(), 1);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::INVALID_ACCOUNT_DATA);
}

/// A token account that IS vault-owned but holds a different mint. Distinct
/// from `spl_source_not_owned_by_the_vault_rejected` (right mint, wrong
/// owner): without the source-side mint check, a session granted for a cheap
/// mint could drain an expensive one while debiting the cheap mint's buckets.
#[test]
fn spl_wrong_source_mint_rejected() {
    let (mut svm, payer, pk, account, _vault_ata, dest_ata) = live_spl();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);

    let other_mint = Pubkey::new_from_array([17u8; 32]);
    set_mint(&mut svm, &other_mint, 6, 1_000_000);
    let other_vault_ata = ata(&account, &other_mint);
    set_token_account(&mut svm, &other_vault_ata, &other_mint, &account, VAULT_TOKENS);

    // `mint` argument (and therefore the caps debited) says `tok_mint`, the
    // source holds `other_mint`.
    let ix = session_spl_ix(&session_kp, account, session, other_vault_ata, dest_ata, tok_mint(), 1);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::INVALID_ACCOUNT_DATA);
    assert_eq!(token_amount(&svm, &other_vault_ata), VAULT_TOKENS, "nothing moved");
}

/// Every Warden rule passes and the buckets are debited — then the token
/// program refuses the CPI (the vault ATA holds less than the transfer). The
/// whole transaction must roll back: no consumed nonce, no spent bucket, no
/// `lifetime_spent`, no balance change.
///
/// Solana's runtime discards all account writes on a failed transaction, so
/// this is not a claim about the handler's own bookkeeping — it is the proof
/// that the handler does not do anything *outside* account state (log-then-act,
/// a second transaction, an early commit) that could survive the failure.
#[test]
fn token_cpi_failure_leaves_state_unchanged() {
    let (mut svm, payer, pk, account, vault_ata, dest_ata) = live_spl();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);

    // The vault holds less than the (perfectly legal, within-caps) amount.
    set_token_account(&mut svm, &vault_ata, &tok_mint(), &account, 100);

    // Snapshot BOTH accounts twice over: the raw on-chain bytes (the strongest
    // statement — every field, including ones this test does not name and ones
    // Phase 1B may add) and the decoded structs (so a failure says WHICH field
    // moved instead of "byte arrays differ").
    let before = read_smart_account(&svm, &account);
    let before_raw = svm.get_account(&account).expect("account exists").data;
    let session_before = read_session(&svm, &session);
    let session_before_raw = svm.get_account(&session).expect("session exists").data;

    let ix = session_spl_ix(&session_kp, account, session, vault_ata, dest_ata, tok_mint(), TOK_SESSION_PER_TX);
    let e = send(&mut svm, &[&payer, &session_kp], &[ix]).expect_err("the token CPI must fail");
    assert!(
        matches!(e.err, TransactionError::InstructionError(0, _)),
        "expected the CPI to fail inside our instruction, got {:?}; logs={:#?}",
        e.err,
        e.meta.logs
    );
    assert!(
        !e.meta.logs.iter().any(|l| l.contains("panicked")),
        "program panicked instead of propagating the CPI error: {:#?}",
        e.meta.logs
    );

    let after = read_smart_account(&svm, &account);
    let session_after = read_session(&svm, &session);

    // Every bucket, not just the mint that was being moved: all
    // `MAX_MINT_CAPS` slots and all four fields of each (`day_start`,
    // `spent_today`, `ring_day_index`, `ring`) — `MintBuckets` derives
    // `PartialEq`, so this compares the whole array, and a debit that rolled
    // the day/ring bookkeeping without spending would fail here too.
    assert!(
        after.buckets == before.buckets,
        "every MintBuckets slot must be byte-identical after a failed CPI"
    );
    // The scalars a partial rollback would most plausibly leave behind.
    assert_eq!(after.root_nonce, before.root_nonce, "no nonce consumed");
    assert_eq!(after.generation, before.generation, "generation untouched");
    assert_eq!(after.frozen_kind, before.frozen_kind, "frozen state untouched");
    assert_eq!(after.buckets[1].spent_today, 0, "the token day bucket was rolled back");
    assert_eq!(after.buckets[0].spent_today, 0, "SOL's bucket untouched");

    // The whole SessionKey, not only `lifetime_spent`.
    assert_eq!(
        session_after.lifetime_spent, session_before.lifetime_spent,
        "lifetime_spent was rolled back"
    );
    assert_eq!(session_after.lifetime_cap, session_before.lifetime_cap);
    assert!(session_after.caps == session_before.caps, "session caps unchanged");
    assert_eq!(session_after.expiry_ts, session_before.expiry_ts);
    assert_eq!(session_after.ops_mask, session_before.ops_mask);
    assert_eq!(session_after.generation_at_grant, session_before.generation_at_grant);

    // …and the raw bytes of both accounts, which subsumes every assertion
    // above and covers any field they forgot (or that 1B adds).
    assert_eq!(
        svm.get_account(&account).expect("account exists").data,
        before_raw,
        "the SmartAccount's raw bytes must be unchanged"
    );
    assert_eq!(
        svm.get_account(&session).expect("session exists").data,
        session_before_raw,
        "the SessionKey's raw bytes must be unchanged"
    );

    assert_eq!(token_amount(&svm, &vault_ata), 100, "vault balance unchanged");
    assert_eq!(token_amount(&svm, &dest_ata), 0, "destination balance unchanged");
}

#[test]
fn spl_token_2022_rejected_in_phase_1a() {
    let (mut svm, payer, pk, account, vault_ata, dest_ata) = live_spl();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);

    let args = TransferArgs { root: None, mint: Some(tok_mint()), amount: 1 };
    let ix = transfer_ix(
        session_kp.pubkey(),
        account,
        Some(session),
        false,
        dest_ata,
        Some(vault_ata),
        Some(SPL_TOKEN_2022_ID),
        &args,
    );
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::INVALID_ACCOUNT_DATA);
}

#[test]
fn spl_without_source_or_token_program_rejected() {
    let (mut svm, payer, pk, account, _vault_ata, dest_ata) = live_spl();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);

    let args = TransferArgs { root: None, mint: Some(tok_mint()), amount: 1 };
    let ix = transfer_ix(session_kp.pubkey(), account, Some(session), false, dest_ata, None, None, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::BAD_INSTRUCTION_LAYOUT);
}

// ===========================================================================
// Root path
// ===========================================================================

#[test]
fn root_transfer_within_threshold_debits_buckets() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);
    let dest = funded_dest(&mut svm);

    let nonce_before = read_smart_account(&svm, &account).root_nonce;
    let ixs = root_sol_ixs(&svm, &payer, &account, &pk, dest, dest, SOL_LARGE_THRESHOLD);
    let res = expect_ok(&mut svm, &[&payer], &ixs);
    println!("transfer (root, SOL) CU: {}", res.compute_units_consumed);

    assert_eq!(received(&svm, &dest), SOL_LARGE_THRESHOLD);
    let st = read_smart_account(&svm, &account);
    assert_eq!(st.buckets[0].spent_today, SOL_LARGE_THRESHOLD, "root debits the SAME bucket");
    assert_eq!(st.root_nonce, nonce_before + 1, "the ceremony is consumed");
    assert!(res.compute_units_consumed < 100_000, "CU budget: {}", res.compute_units_consumed);

    // 800k of the 1.2M day cap is gone, so a 600k session transfer no longer
    // fits — the root spend and the session spend share one budget.
    let ix = session_sol_ix(&session_kp, account, session, dest, SOL_SESSION_PER_TX);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::CAP_EXCEEDED);
    // What DOES remain (400k) is still spendable.
    let ix = session_sol_ix(&session_kp, account, session, dest, SOL_PER_DAY - SOL_LARGE_THRESHOLD);
    expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    assert_eq!(received(&svm, &dest), SOL_PER_DAY);
}

/// The root path over SPL: same ceremony, same threshold, same buckets — and
/// the CPI signs as the vault PDA rather than as a session key.
#[test]
fn root_spl_transfer_ok() {
    let (mut svm, payer, pk, account, vault_ata, dest_ata) = live_spl();

    let body = TransferBody {
        native: false,
        mint: tok_mint(),
        destination: dest_ata,
        amount: TOK_LARGE_THRESHOLD,
    };
    let mut body_bytes = Vec::new();
    body.serialize(&mut body_bytes).unwrap();
    let (precompile, root) = ceremony(&svm, &account, &pk, action_hash(OP_TRANSFER_ACTION, &body_bytes));
    let args = TransferArgs { root: Some(root), mint: Some(tok_mint()), amount: TOK_LARGE_THRESHOLD };
    let ix = transfer_ix(
        payer.pubkey(),
        account,
        None,
        true,
        dest_ata,
        Some(vault_ata),
        Some(token_program_id()),
        &args,
    );
    let res = expect_ok(&mut svm, &[&payer], &[precompile, ix]);
    println!("transfer (root, SPL) CU: {}", res.compute_units_consumed);

    assert_eq!(token_amount(&svm, &dest_ata), TOK_LARGE_THRESHOLD);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS - TOK_LARGE_THRESHOLD);
    assert_eq!(read_smart_account(&svm, &account).buckets[1].spent_today, TOK_LARGE_THRESHOLD);
}

/// A mint the policy caps at the account level but gives NO `large_threshold`
/// entry is not directly root-transferable at all — absent means "not
/// allowed", never "unlimited".
#[test]
fn root_spl_transfer_tx_fits_1232_bytes() {
    let (svm, payer, pk, account, vault_ata, dest_ata) = live_spl();
    let body = TransferBody { native: false, mint: tok_mint(), destination: dest_ata, amount: 1 };
    let mut body_bytes = Vec::new();
    body.serialize(&mut body_bytes).unwrap();
    let (precompile, root) = ceremony(&svm, &account, &pk, action_hash(OP_TRANSFER_ACTION, &body_bytes));
    let args = TransferArgs { root: Some(root), mint: Some(tok_mint()), amount: 1 };
    let ix = transfer_ix(
        payer.pubkey(),
        account,
        None,
        true,
        dest_ata,
        Some(vault_ata),
        Some(token_program_id()),
        &args,
    );
    let tx = Transaction::new(
        &[&payer],
        Message::new(&[precompile, ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    let n = bincode::serialize(&tx).unwrap().len();
    println!("transfer (root, SPL) tx bytes: {n}");
    assert!(n <= PACKET_DATA_SIZE, "root SPL transfer must fit the packet limit: {n}");
}

#[test]
fn root_transfer_of_mint_without_threshold_rejected() {
    let (mut svm, payer, pk, account) = live();
    let dest = funded_dest(&mut svm);
    let body = TransferBody { native: false, mint: ungranted_mint(), destination: dest, amount: 1 };
    let mut body_bytes = Vec::new();
    body.serialize(&mut body_bytes).unwrap();
    let (precompile, root) = ceremony(&svm, &account, &pk, action_hash(OP_TRANSFER_ACTION, &body_bytes));
    let args = TransferArgs { root: Some(root), mint: Some(ungranted_mint()), amount: 1 };
    let ix = transfer_ix(
        payer.pubkey(),
        account,
        None,
        true,
        dest,
        Some(Pubkey::new_unique()),
        Some(token_program_id()),
        &args,
    );
    expect_reject(&mut svm, &[&payer], &[precompile, ix], 1, err::CAP_EXCEEDED);
}

#[test]
fn root_transfer_tx_fits_1232_bytes() {
    let (svm, payer, pk, account) = live();
    let dest = Pubkey::new_unique();
    let ixs = root_sol_ixs(&svm, &payer, &account, &pk, dest, dest, 1);
    let tx = Transaction::new(&[&payer], Message::new(&ixs, Some(&payer.pubkey())), svm.latest_blockhash());
    let n = bincode::serialize(&tx).unwrap().len();
    println!("transfer (root, SOL) tx bytes: {n}");
    assert!(n <= PACKET_DATA_SIZE, "root SOL transfer must fit the packet limit: {n}");
}

#[test]
fn root_transfer_over_threshold_rejected() {
    let (mut svm, payer, pk, account) = live();
    let dest = funded_dest(&mut svm);
    // Under the account per_tx cap (1M) but over the large-transfer threshold
    // (800k) — Phase 1B's timelocked `queue` is the only route for this.
    let ixs = root_sol_ixs(&svm, &payer, &account, &pk, dest, dest, SOL_LARGE_THRESHOLD + 1);
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::CAP_EXCEEDED);
    assert_eq!(received(&svm, &dest), 0);
}

/// The assertion is genuine and unexpired; only the destination ACCOUNT
/// differs from the one the ceremony signed. Because the handler rebuilds
/// `TransferBody` from the passed accounts, the recomputed `action_hash` — and
/// therefore the challenge — no longer matches.
#[test]
fn root_transfer_with_substituted_destination_rejected() {
    let (mut svm, payer, pk, account) = live();
    let signed = Pubkey::new_unique();
    let attacker = Pubkey::new_unique();
    let nonce_before = read_smart_account(&svm, &account).root_nonce;

    let ixs = root_sol_ixs(&svm, &payer, &account, &pk, signed, attacker, SOL_LARGE_THRESHOLD);
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::CHALLENGE_MISMATCH);

    assert_eq!(lamports(&svm, &attacker), 0);
    assert_eq!(lamports(&svm, &signed), 0);
    assert_eq!(
        read_smart_account(&svm, &account).root_nonce,
        nonce_before,
        "a rejected ceremony must not consume the nonce"
    );
}

#[test]
fn root_transfer_amount_tamper_rejected() {
    let (mut svm, payer, pk, account) = live();
    let dest = Pubkey::new_unique();
    let body = TransferBody { native: true, mint: Pubkey::default(), destination: dest, amount: 1 };
    let mut body_bytes = Vec::new();
    body.serialize(&mut body_bytes).unwrap();
    let (precompile, root) = ceremony(&svm, &account, &pk, action_hash(OP_TRANSFER_ACTION, &body_bytes));
    // Signed for 1 lamport, submitted for the full threshold.
    let args = TransferArgs { root: Some(root), mint: None, amount: SOL_LARGE_THRESHOLD };
    let ix = transfer_ix(payer.pubkey(), account, None, true, dest, None, None, &args);
    expect_reject(&mut svm, &[&payer], &[precompile, ix], 1, err::CHALLENGE_MISMATCH);
}

#[test]
fn root_transfer_without_sysvar_rejected() {
    let (mut svm, payer, pk, account) = live();
    let dest = Pubkey::new_unique();
    let body = TransferBody { native: true, mint: Pubkey::default(), destination: dest, amount: 1 };
    let mut body_bytes = Vec::new();
    body.serialize(&mut body_bytes).unwrap();
    let (precompile, root) = ceremony(&svm, &account, &pk, action_hash(OP_TRANSFER_ACTION, &body_bytes));
    let args = TransferArgs { root: Some(root), mint: None, amount: 1 };
    let ix = transfer_ix(payer.pubkey(), account, None, false, dest, None, None, &args);
    expect_reject(&mut svm, &[&payer], &[precompile, ix], 1, err::BAD_INSTRUCTION_LAYOUT);
}

/// Both authorization shapes at once is not "extra proof", it is an ambiguous
/// instruction — refused outright.
#[test]
fn root_and_session_together_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);
    let dest = Pubkey::new_unique();
    let body = TransferBody { native: true, mint: Pubkey::default(), destination: dest, amount: 1 };
    let mut body_bytes = Vec::new();
    body.serialize(&mut body_bytes).unwrap();
    let (precompile, root) = ceremony(&svm, &account, &pk, action_hash(OP_TRANSFER_ACTION, &body_bytes));
    let args = TransferArgs { root: Some(root), mint: None, amount: 1 };
    let ix = transfer_ix(payer.pubkey(), account, Some(session), true, dest, None, None, &args);
    expect_reject(&mut svm, &[&payer], &[precompile, ix], 1, err::BAD_INSTRUCTION_LAYOUT);
}

// ===========================================================================
// Freeze interaction
// ===========================================================================

#[test]
fn frozen_blocks_transfer() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);

    let ixs = freeze_ixs(&svm, &account, &pk);
    expect_ok(&mut svm, &[&payer], &ixs);

    let ix = session_sol_ix(&session_kp, account, session, Pubkey::new_unique(), 1);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::FROZEN);
}

/// Owed from Task 6: a root freeze must stop the ROOT's own outflows too, and
/// must stop new delegation — otherwise "freeze" would only bind the delegates
/// while leaving the (possibly phished) root free to drain the vault.
#[test]
fn root_freeze_blocks_transfer_and_grant() {
    let (mut svm, payer, pk, account) = live();
    let ixs = freeze_ixs(&svm, &account, &pk);
    expect_ok(&mut svm, &[&payer], &ixs);

    let dest = Pubkey::new_unique();
    let ixs = root_sol_ixs(&svm, &payer, &account, &pk, dest, dest, 1);
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::FROZEN);
    assert_eq!(lamports(&svm, &dest), 0);

    let session_kp = Keypair::new();
    let body = grant_body(session_kp.pubkey(), OP_TRANSFER, vec![sol_cap()], vec![u64::MAX], DAY_SECS);
    let mut body_bytes = Vec::new();
    body.serialize(&mut body_bytes).unwrap();
    let (precompile, root) = ceremony(&svm, &account, &pk, action_hash(OP_GRANT_SESSION, &body_bytes));
    let (session, _) = session_pda(&account, &session_kp.pubkey());
    let args = GrantSessionArgs { root, body };
    let ixs = vec![precompile, grant_ix(payer.pubkey(), account, session, &args)];
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::FROZEN);
}

// ===========================================================================
// Rolling 30-day window
// ===========================================================================

/// The day bucket resets at UTC midnight; the 30-day ring does not. Day 1 has
/// unused day-cap headroom and is still refused once the rolling window is
/// full.
#[test]
fn rolling_30d_cap_enforced_end_to_end() {
    let (mut svm, payer, pk, account) = live();
    let session_kp = Keypair::new();
    let session = grant_default_session(&mut svm, &payer, &account, &pk, &session_kp);
    let dest = funded_dest(&mut svm);

    // Day 0: spend the whole day cap (1.2M of the 2M 30-day cap).
    for _ in 0..2 {
        let ix = session_sol_ix(&session_kp, account, session, dest, SOL_SESSION_PER_TX);
        expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    }
    let ix = session_sol_ix(&session_kp, account, session, dest, 1);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::CAP_EXCEEDED);

    // Day 1: the day bucket is empty again…
    warp_clock(&mut svm, NOW + DAY_SECS);
    let ix = session_sol_ix(&session_kp, account, session, dest, SOL_SESSION_PER_TX);
    expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    assert_eq!(received(&svm, &dest), SOL_PER_DAY + SOL_SESSION_PER_TX);

    // …but the rolling window now holds 1.8M of 2M, so the next 600k (well
    // within day 1's remaining 600k of day cap) is refused by the 30-day ring.
    let ix = session_sol_ix(&session_kp, account, session, dest, SOL_SESSION_PER_TX);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::CAP_EXCEEDED);
    // The exact remainder still fits.
    let ix = session_sol_ix(&session_kp, account, session, dest, SOL_PER_30D - SOL_PER_DAY - SOL_SESSION_PER_TX);
    expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    assert_eq!(received(&svm, &dest), SOL_PER_30D);

    let st = read_smart_account(&svm, &account);
    assert_eq!(st.buckets[0].ring.iter().sum::<u64>(), SOL_PER_30D);
}

// ===========================================================================
// Pinned facts
// ===========================================================================

#[test]
fn discriminator_is_sha256_of_the_global_name() {
    let args = TransferArgs { root: None, mint: None, amount: 1 };
    let ix = transfer_ix(
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        None,
        false,
        Pubkey::new_unique(),
        None,
        None,
        &args,
    );
    assert_eq!(&ix.data[..8], &Sha256::digest(b"global:transfer")[..8]);
}

/// The op byte is part of every signed transcript — moving it silently
/// invalidates every ceremony a client has already produced.
#[test]
fn op_byte_is_pinned() {
    assert_eq!(OP_TRANSFER_ACTION, 0x05);
    // …and is not the session `ops_mask` bit, which is an unrelated number.
    assert_eq!(OP_TRANSFER, 1);
    assert_eq!(OP_SIGN_MESSAGE, 8);
}

/// The program hardcodes the SPL Token program id (it cannot import the crate
/// — see `constants::SPL_TOKEN_ID`), so the literal is pinned against the real
/// one here, where the crate IS available as a dev-dependency.
#[test]
fn token_program_id_matches_spl_token() {
    assert_eq!(SPL_TOKEN_ID, spl_token::ID);
    assert_eq!(token_program_id(), spl_token::ID);
    assert_eq!(
        SPL_TOKEN_2022_ID,
        Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
    );
    assert_eq!(NATIVE_MINT, spl_token::native_mint::ID);
}
