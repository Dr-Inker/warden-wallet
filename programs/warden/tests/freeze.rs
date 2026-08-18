//! LiteSVM coverage of `freeze` / `unfreeze` (Task 6, 1A scope: root freeze
//! only — `FrozenState::Guardian` is a Phase 1B instruction).
//!
//! Transaction shape (same as `rotate_nonce`'s — no `payer` account, no
//! signer of its own; the fee payer signs the transaction but is not named in
//! either instruction's account list):
//! ```text
//!   ix[0] = Secp256r1SigVerify precompile over (pubkey33, sig64, message)
//!   ix[1] = warden::freeze | warden::unfreeze
//! ```
//! Every ceremony here is a REAL signed assertion produced by the test
//! passkey over the honest transcript for the account's current on-chain
//! state, same as `root_verify.rs`/`sessions.rs`.

mod common;

use anchor_lang::AnchorSerialize;
use common::passkey::{self, TestPasskey, FLAGS_UP_UV, TEST_ORIGIN};
use common::{create_smart_account, read_smart_account, session_pda, warp_clock, SmartAccountFixture};
use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    message::Message,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    sysvar,
    transaction::{Transaction, TransactionError},
};
use warden::constants::SESSION_KIND_ED25519;
use warden::instructions::create_account::MIN_TIMELOCK_SECS;
use warden::instructions::grant_session::{GrantBody, GrantSessionArgs};
use warden::root_verify::transcript::{
    action_hash, b64url_no_pad, transcript_hash, OP_FREEZE, OP_GRANT_SESSION, OP_UNFREEZE,
};
use warden::root_verify::RootArgs;

const NOW: i64 = 1_760_000_000;
/// Solana's transaction packet limit (`PACKET_DATA_SIZE`).
const PACKET_DATA_SIZE: usize = 1232;
/// The `expiry_ts` of the ceremony (≤ 600 s out from whatever `now` is at
/// call time — see `ceremony`, which always signs `now + 60`).
const ROOT_EXPIRY_OFFSET: i64 = 60;

/// Anchor error codes as literals — the same pinned table as
/// `root_verify.rs`'s `mod err` (6000 + declaration index).
/// `root_verify::pinned_error_codes_match_the_enum_today` is the single place
/// the enum itself is consulted; this table is just this suite's copy of it.
mod err {
    pub const FROZEN: u32 = 6001;
    pub const INVALID_ACCOUNT_DATA: u32 = 6009;
    pub const ALREADY_FROZEN: u32 = 6029;
    pub const TIMELOCK_NOT_ELAPSED: u32 = 6030;
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A live SVM with one real, passkey-rooted account, `policy.timelock_secs`
/// at the minimum (1 hour) `create_account` allows — the fixture the
/// timelock tests warp the clock against.
fn live() -> (LiteSVM, Keypair, TestPasskey, Pubkey) {
    let (mut svm, payer) = common::setup();
    warp_clock(&mut svm, NOW);
    let pk = TestPasskey::new(3);
    let f = SmartAccountFixture { root_pubkey33: pk.pubkey33(), ..Default::default() };
    let account = create_smart_account(&mut svm, &payer, &f);
    (svm, payer, pk, account)
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

fn unfreeze_ix(smart_account: Pubkey, args: &RootArgs) -> Instruction {
    let mut data = Sha256::digest(b"global:unfreeze")[..8].to_vec();
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
        ],
        data,
    }
}

/// Sign the honest transcript for `action_hash` against the account's CURRENT
/// on-chain state (generation / policy version / root nonce read back from
/// the SVM, exactly as the extension would). Reads `Clock::get`'s `now` from
/// the SVM itself so the ceremony's freshness window is always relative to
/// whatever time a test has warped to.
fn ceremony(svm: &LiteSVM, account: &Pubkey, pk: &TestPasskey, ah: [u8; 32]) -> (Instruction, RootArgs) {
    let st = read_smart_account(svm, account);
    let now: solana_sdk::clock::Clock = svm.get_sysvar();
    let expiry_ts = now.unix_timestamp + ROOT_EXPIRY_OFFSET;
    let t = transcript_hash(
        &st.cluster_tag,
        &common::program_id(),
        account,
        st.generation,
        st.policy.version,
        st.root_nonce,
        expiry_ts,
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
    };
    (passkey::precompile_ix(&a, &pk.pubkey33()), args)
}

fn freeze_ixs(svm: &LiteSVM, account: &Pubkey, pk: &TestPasskey) -> Vec<Instruction> {
    let (precompile, root) = ceremony(svm, account, pk, action_hash(OP_FREEZE, &[]));
    vec![precompile, freeze_ix(*account, &root)]
}

fn unfreeze_ixs(svm: &LiteSVM, account: &Pubkey, pk: &TestPasskey) -> Vec<Instruction> {
    let (precompile, root) = ceremony(svm, account, pk, action_hash(OP_UNFREEZE, &[]));
    vec![precompile, unfreeze_ix(*account, &root)]
}

/// An empty grant (no caps, no ops) — enough to prove the `frozen` gate blocks
/// `grant_session` outright; the grant's own contents are irrelevant to that
/// gate, which runs before the ceremony is even checked.
fn empty_grant_ixs(
    svm: &LiteSVM,
    payer: Pubkey,
    account: &Pubkey,
    pk: &TestPasskey,
    session_pubkey: Pubkey,
) -> Vec<Instruction> {
    let body = GrantBody {
        expiry_ts: NOW + 86_400,
        session_pubkey,
        kind: SESSION_KIND_ED25519,
        ops_mask: 0,
        caps: vec![],
        lifetime_cap: vec![],
        program_allowlist_id: 0,
        label: [0u8; 16],
    };
    let mut body_bytes = Vec::new();
    body.serialize(&mut body_bytes).unwrap();
    let (precompile, root) = ceremony(svm, account, pk, action_hash(OP_GRANT_SESSION, &body_bytes));
    let (session, _) = session_pda(account, &session_pubkey);
    let args = GrantSessionArgs { root, body };
    vec![precompile, grant_ix(payer, *account, session, &args)]
}

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

// ---------------------------------------------------------------------------
// freeze — happy path
// ---------------------------------------------------------------------------

#[test]
fn freeze_sets_state() {
    let (mut svm, payer, pk, account) = live();
    let before = read_smart_account(&svm, &account);
    assert_eq!(before.frozen_kind, 0, "starts unfrozen");

    let ixs = freeze_ixs(&svm, &account, &pk);
    let res = expect_ok(&mut svm, &[&payer], &ixs);
    println!("freeze CU: {}", res.compute_units_consumed);

    let after = read_smart_account(&svm, &account);
    assert!(matches!(after.frozen().unwrap(), warden::state::FrozenState::Root));
    assert_eq!(after.frozen_at, NOW, "frozen_at records the freeze moment");
    assert_eq!(after.root_nonce, before.root_nonce + 1, "the ceremony is consumed");
    assert!(res.compute_units_consumed < 100_000, "CU budget: {}", res.compute_units_consumed);
}

#[test]
fn freeze_tx_fits_1232_bytes() {
    let (svm, payer, pk, account) = live();
    let ixs = freeze_ixs(&svm, &account, &pk);
    let tx = Transaction::new(&[&payer], Message::new(&ixs, Some(&payer.pubkey())), svm.latest_blockhash());
    let len = bincode::serialize(&tx).unwrap().len();
    println!("freeze tx: {len} B");
    assert!(len <= PACKET_DATA_SIZE, "freeze tx is {len} B, over the {PACKET_DATA_SIZE} B packet limit");
}

// ---------------------------------------------------------------------------
// freeze — rejections
// ---------------------------------------------------------------------------

/// Freezing an already-root-frozen account is rejected, and does not reset
/// `frozen_at` (see `instructions::freeze` module docs on why re-stamping it
/// would let root extend the freeze indefinitely).
#[test]
fn freeze_twice_rejected() {
    let (mut svm, payer, pk, account) = live();
    let ixs = freeze_ixs(&svm, &account, &pk);
    expect_ok(&mut svm, &[&payer], &ixs);
    let frozen_at = read_smart_account(&svm, &account).frozen_at;
    let nonce_before = read_smart_account(&svm, &account).root_nonce;

    let ixs = freeze_ixs(&svm, &account, &pk);
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::ALREADY_FROZEN);

    let after = read_smart_account(&svm, &account);
    assert_eq!(after.frozen_at, frozen_at, "a rejected re-freeze must not touch frozen_at");
    assert_eq!(after.root_nonce, nonce_before, "a rejected freeze must not consume the nonce");
}

// ---------------------------------------------------------------------------
// unfreeze
// ---------------------------------------------------------------------------

#[test]
fn unfreeze_before_timelock_rejected() {
    let (mut svm, payer, pk, account) = live();
    let ixs = freeze_ixs(&svm, &account, &pk);
    expect_ok(&mut svm, &[&payer], &ixs);
    assert_eq!(read_smart_account(&svm, &account).policy.timelock_secs, MIN_TIMELOCK_SECS);

    // One second short of the timelock.
    warp_clock(&mut svm, NOW + MIN_TIMELOCK_SECS - 1);
    let ixs = unfreeze_ixs(&svm, &account, &pk);
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::TIMELOCK_NOT_ELAPSED);
    assert!(matches!(read_smart_account(&svm, &account).frozen().unwrap(), warden::state::FrozenState::Root));
}

#[test]
fn unfreeze_after_timelock_ok() {
    let (mut svm, payer, pk, account) = live();
    let ixs = freeze_ixs(&svm, &account, &pk);
    expect_ok(&mut svm, &[&payer], &ixs);

    // Exactly at the timelock boundary — `now >= unlock_at` must accept `==`.
    warp_clock(&mut svm, NOW + MIN_TIMELOCK_SECS);
    let ixs = unfreeze_ixs(&svm, &account, &pk);
    let res = expect_ok(&mut svm, &[&payer], &ixs);
    println!("unfreeze CU: {}", res.compute_units_consumed);

    let after = read_smart_account(&svm, &account);
    assert!(matches!(after.frozen().unwrap(), warden::state::FrozenState::None));
    assert_eq!(after.frozen_at, 0, "frozen_at resets on unfreeze");
    assert!(res.compute_units_consumed < 100_000, "CU budget: {}", res.compute_units_consumed);
}

#[test]
fn unfreeze_tx_fits_1232_bytes() {
    let (mut svm, payer, pk, account) = live();
    let ixs = freeze_ixs(&svm, &account, &pk);
    expect_ok(&mut svm, &[&payer], &ixs);
    warp_clock(&mut svm, NOW + MIN_TIMELOCK_SECS);
    let ixs = unfreeze_ixs(&svm, &account, &pk);
    let tx = Transaction::new(&[&payer], Message::new(&ixs, Some(&payer.pubkey())), svm.latest_blockhash());
    let len = bincode::serialize(&tx).unwrap().len();
    println!("unfreeze tx: {len} B");
    assert!(len <= PACKET_DATA_SIZE, "unfreeze tx is {len} B, over the {PACKET_DATA_SIZE} B packet limit");
}

#[test]
fn unfreeze_when_not_frozen_rejected() {
    let (mut svm, payer, pk, account) = live();
    let ixs = unfreeze_ixs(&svm, &account, &pk);
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::INVALID_ACCOUNT_DATA);
}

// ---------------------------------------------------------------------------
// Interaction with other instructions
// ---------------------------------------------------------------------------

/// `grant_session` is outflow-enabling and is gated by `frozen` — owed from
/// Task 5, exercised here now that `freeze` exists to reach the state.
#[test]
fn grant_frozen_rejected() {
    let (mut svm, payer, pk, account) = live();
    let ixs = freeze_ixs(&svm, &account, &pk);
    expect_ok(&mut svm, &[&payer], &ixs);

    let session_key = Keypair::new();
    let ixs = empty_grant_ixs(&svm, payer.pubkey(), &account, &pk, session_key.pubkey());
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::FROZEN);
}

/// `rotate_nonce` changes no funds and grants no authority, so it stays
/// available even while the account is frozen — a user who freezes in
/// response to a compromise must still be able to invalidate a stale,
/// outstanding ceremony (see `instructions::rotate_nonce`'s module docs,
/// which never gate it on `frozen` in the first place). This test proves
/// that design choice end-to-end rather than only by code inspection.
#[test]
fn rotate_nonce_still_allowed_when_frozen() {
    let (mut svm, payer, pk, account) = live();
    let ixs = freeze_ixs(&svm, &account, &pk);
    expect_ok(&mut svm, &[&payer], &ixs);
    let nonce_before = read_smart_account(&svm, &account).root_nonce;

    let (precompile, root) = ceremony(&svm, &account, &pk, action_hash(warden::root_verify::transcript::OP_ROTATE_NONCE, &[]));
    let mut data = Sha256::digest(b"global:rotate_nonce")[..8].to_vec();
    root.serialize(&mut data).unwrap();
    let rotate_ix = Instruction {
        program_id: common::program_id(),
        accounts: vec![
            AccountMeta::new(account, false),
            AccountMeta::new_readonly(sysvar::instructions::ID, false),
        ],
        data,
    };
    expect_ok(&mut svm, &[&payer], &[precompile, rotate_ix]);

    let after = read_smart_account(&svm, &account);
    assert_eq!(after.root_nonce, nonce_before + 1, "rotate_nonce still consumes the ceremony while frozen");
    assert!(matches!(after.frozen().unwrap(), warden::state::FrozenState::Root), "still frozen");
}

// ---------------------------------------------------------------------------
// Pinned facts
// ---------------------------------------------------------------------------

#[test]
fn discriminators_are_sha256_of_the_global_names() {
    let ix = freeze_ix(
        Pubkey::new_unique(),
        &RootArgs { precompile_ix_index: 0, authenticator_data: vec![], client_data_json: vec![], expiry_ts: 0 },
    );
    assert_eq!(&ix.data[..8], &Sha256::digest(b"global:freeze")[..8]);
    let ix = unfreeze_ix(
        Pubkey::new_unique(),
        &RootArgs { precompile_ix_index: 0, authenticator_data: vec![], client_data_json: vec![], expiry_ts: 0 },
    );
    assert_eq!(&ix.data[..8], &Sha256::digest(b"global:unfreeze")[..8]);
}

/// `OP_FREEZE`/`OP_UNFREEZE`/`OP_GRANT_SESSION`/`OP_ROTATE_NONCE` must all be
/// distinct — the whole point of binding `op_type` into `action_hash` is that
/// a ceremony signed for one action can never authorize a different one.
#[test]
fn op_bytes_are_distinct() {
    use warden::root_verify::transcript::{OP_REVOKE_SESSION, OP_ROTATE_NONCE};
    let ops = [OP_ROTATE_NONCE, OP_GRANT_SESSION, OP_REVOKE_SESSION, OP_FREEZE, OP_UNFREEZE];
    for (i, a) in ops.iter().enumerate() {
        for b in &ops[i + 1..] {
            assert_ne!(a, b, "op bytes must be pairwise distinct: {ops:?}");
        }
    }
}

/// `OP_FREEZE`/`OP_UNFREEZE` are permanent wire constants the instant any
/// client signs a real ceremony against them (the op byte is part of the
/// signed transcript — spec §4). Pinned as LITERALS, independent of
/// `transcript.rs`'s own `OP_FREEZE`/`OP_UNFREEZE` declarations, the same
/// reason `root_verify.rs`'s error-code table pins against literals rather
/// than the enum: a silent renumber/swap must fail HERE, not just break
/// every already-signed client silently.
#[test]
fn op_bytes_are_pinned() {
    assert_eq!(OP_FREEZE, 0x03, "OP_FREEZE moved — every signed freeze ceremony breaks");
    assert_eq!(OP_UNFREEZE, 0x04, "OP_UNFREEZE moved — every signed unfreeze ceremony breaks");
}
