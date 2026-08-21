//! Phase 1B Task 2A — smoke tests for the `test-mutator` program.
//!
//! These prove the mutator's CPI plumbing works when driven directly, with an
//! ordinary payer as the SPL Token authority and NO warden in the loop. Task 5
//! feeds the same instructions *through* `execute` and asserts each mutation is
//! rejected by conservation; here we only establish that each op does what it
//! claims when nothing is guarding it — otherwise a Task-5 rejection could pass
//! for the wrong reason (a broken mutator, not a working guard).

mod common;

use common::mutator;
use common::token::{ata, set_mint, set_token_account, token_amount, token_program_id};
use litesvm::LiteSVM;
use solana_sdk::{
    account::Account,
    instruction::Instruction,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

const RENT_TOKEN: u64 = 2_039_280;

fn setup() -> (LiteSVM, Keypair, Pubkey) {
    let mut svm = LiteSVM::new().with_mainnet_features();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let mutator = mutator::add_mutator(&mut svm);
    (svm, payer, mutator)
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ix: Instruction) -> Result<(), String> {
    let tx = Transaction::new(
        &[payer],
        Message::new(&[ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .map(|_| ())
        .map_err(|e| format!("{:?} {:#?}", e.err, e.meta.logs))
}

/// Read an SPL token account's raw fields for assertions the balance helper
/// does not expose.
fn unpack(svm: &LiteSVM, addr: &Pubkey) -> spl_token::state::Account {
    use solana_sdk::program_pack::Pack;
    let data = svm.get_account(addr).expect("account exists").data;
    spl_token::state::Account::unpack(&data).expect("valid token account")
}

#[test]
fn noop_succeeds() {
    let (mut svm, payer, _m) = setup();
    send(&mut svm, &payer, mutator::noop()).expect("noop");
}

#[test]
fn transfer_out_moves_the_balance() {
    let (mut svm, payer, _m) = setup();
    let mint = Pubkey::new_unique();
    set_mint(&mut svm, &mint, 6, 1_000_000);
    let src = ata(&payer.pubkey(), &mint);
    let dst = ata(&Pubkey::new_unique(), &mint);
    set_token_account(&mut svm, &src, &mint, &payer.pubkey(), 1_000);
    set_token_account(&mut svm, &dst, &mint, &Pubkey::new_unique(), 0);

    send(&mut svm, &payer, mutator::transfer_out(src, dst, payer.pubkey(), 400)).expect("transfer");
    assert_eq!(token_amount(&svm, &src), 600);
    assert_eq!(token_amount(&svm, &dst), 400);
}

#[test]
fn set_delegate_sets_the_delegate() {
    let (mut svm, payer, _m) = setup();
    let mint = Pubkey::new_unique();
    set_mint(&mut svm, &mint, 6, 1_000_000);
    let src = ata(&payer.pubkey(), &mint);
    set_token_account(&mut svm, &src, &mint, &payer.pubkey(), 1_000);
    let delegate = Pubkey::new_unique();

    send(&mut svm, &payer, mutator::set_delegate(src, delegate, payer.pubkey(), 250)).expect("approve");
    let a = unpack(&svm, &src);
    assert_eq!(a.delegate, spl_token::solana_program::program_option::COption::Some(delegate));
    assert_eq!(a.delegated_amount, 250);
}

#[test]
fn set_close_authority_sets_it() {
    let (mut svm, payer, _m) = setup();
    let mint = Pubkey::new_unique();
    set_mint(&mut svm, &mint, 6, 1_000_000);
    let acct = ata(&payer.pubkey(), &mint);
    set_token_account(&mut svm, &acct, &mint, &payer.pubkey(), 1);
    let new_close = Pubkey::new_unique();

    send(&mut svm, &payer, mutator::set_close_authority(acct, new_close, payer.pubkey())).expect("set close authority");
    assert_eq!(
        unpack(&svm, &acct).close_authority,
        spl_token::solana_program::program_option::COption::Some(new_close)
    );
}

#[test]
fn set_owner_changes_the_owner() {
    let (mut svm, payer, _m) = setup();
    let mint = Pubkey::new_unique();
    set_mint(&mut svm, &mint, 6, 1_000_000);
    let acct = ata(&payer.pubkey(), &mint);
    set_token_account(&mut svm, &acct, &mint, &payer.pubkey(), 1);
    let new_owner = Pubkey::new_unique();

    send(&mut svm, &payer, mutator::set_owner(acct, new_owner, payer.pubkey())).expect("set owner");
    assert_eq!(unpack(&svm, &acct).owner, new_owner);
}

#[test]
fn close_account_closes_and_returns_rent() {
    let (mut svm, payer, _m) = setup();
    let mint = Pubkey::new_unique();
    set_mint(&mut svm, &mint, 6, 1_000_000);
    let acct = ata(&payer.pubkey(), &mint);
    set_token_account(&mut svm, &acct, &mint, &payer.pubkey(), 0);
    let dest = Pubkey::new_unique();
    svm.set_account(dest, Account { lamports: 0, data: vec![], owner: anchor_lang::system_program::ID, executable: false, rent_epoch: 0 }).unwrap();

    send(&mut svm, &payer, mutator::close_account(acct, dest, payer.pubkey())).expect("close");
    assert!(svm.get_account(&acct).map(|a| a.lamports == 0).unwrap_or(true), "account emptied");
    assert!(svm.get_account(&dest).unwrap().lamports >= RENT_TOKEN, "rent went to dest");
}

#[test]
fn close_zero_balance_ata_to_stranger_closes() {
    let (mut svm, payer, _m) = setup();
    let mint = Pubkey::new_unique();
    set_mint(&mut svm, &mint, 6, 1_000_000);
    let acct = ata(&payer.pubkey(), &mint);
    set_token_account(&mut svm, &acct, &mint, &payer.pubkey(), 0);
    let stranger = Pubkey::new_unique();
    svm.set_account(stranger, Account { lamports: 0, data: vec![], owner: anchor_lang::system_program::ID, executable: false, rent_epoch: 0 }).unwrap();

    send(&mut svm, &payer, mutator::close_zero_balance_ata_to_stranger(acct, stranger, payer.pubkey())).expect("close to stranger");
    assert!(svm.get_account(&stranger).unwrap().lamports >= RENT_TOKEN, "rent went to the stranger");
}

#[test]
fn realloc_self_grows_a_mutator_owned_account() {
    let (mut svm, payer, mutator) = setup();
    // Plant an account this program owns, rent-exempt at the LARGER size so the
    // realloc does not need extra lamports (LiteSVM does not auto-fund a grow).
    let state = Pubkey::new_unique();
    let target_len = 128usize;
    svm.set_account(
        state,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(target_len),
            data: vec![0u8; 16],
            owner: mutator,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    send(&mut svm, &payer, mutator::realloc_self(state, target_len as u64)).expect("realloc");
    assert_eq!(svm.get_account(&state).unwrap().data.len(), target_len);
}

#[test]
fn drain_lamports_on_a_foreign_account_fails() {
    // Only an account's OWNER program may reduce its lamports. `source` here is
    // system-owned, so the mutator's direct debit must be rejected by the
    // runtime — this is the whole point of the op (Task 5 proves warden never
    // even lets it run).
    let (mut svm, payer, _m) = setup();
    let source = Pubkey::new_unique();
    svm.set_account(source, Account { lamports: 5_000_000, data: vec![], owner: anchor_lang::system_program::ID, executable: false, rent_epoch: 0 }).unwrap();
    let dest = Pubkey::new_unique();

    let err = send(&mut svm, &payer, mutator::drain_lamports(source, dest, 1_000_000)).unwrap_err();
    // The handler must have RUN and then been rejected — not failed before it
    // (a bad discriminator or decode failure would also leave the source
    // untouched, WRDF-0032). Anchor logs the instruction name on entry.
    assert!(err.contains("Instruction: DrainLamports"), "drain handler must have run: {err}");
    assert!(
        err.contains("ExternalAccountLamportSpend") || err.contains("lamport") || err.contains("owner"),
        "must fail on the foreign-lamport write specifically: {err}"
    );
    assert_eq!(svm.get_account(&source).unwrap().lamports, 5_000_000, "source untouched");
}

#[test]
fn reenter_warden_with_forged_input_fails() {
    // The mutator will happily attempt the CPI; warden must reject the forged
    // instruction. Through `execute` (Task 5) the payload rejects
    // program_idx == warden before this runs; here, as a direct call with an
    // unknown discriminator, warden's dispatcher rejects it. Either way warden
    // is not re-entered into a valid state.
    let (mut svm, payer, _m) = setup();
    // Load warden so the CPI target exists.
    let warden = common::program_id();
    let so = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy/warden.so")).unwrap();
    svm.add_program(warden, &so).unwrap();

    let ix = mutator::reenter_warden(warden, vec![0xde, 0xad, 0xbe, 0xef], vec![]);
    let err = send(&mut svm, &payer, ix).unwrap_err();
    // The mutator handler must have run and attempted the CPI (WRDF-0032): the
    // failure must come from the inner warden invocation, not from the mutator
    // never being reached.
    assert!(err.contains("Instruction: ReenterWarden"), "reenter handler must have run: {err}");
    assert!(
        err.contains(&warden.to_string()),
        "the inner warden CPI must be what failed: {err}"
    );
}

// ---------------------------------------------------------------------------
// Task 6 prerequisite proof: RequestHeapFrame is honoured once the default
// 32 KiB-capped allocator is replaced (this crate's custom-heap allocator).
// ---------------------------------------------------------------------------

fn cb_ix(tag: u8, arg: u32) -> Instruction {
    let mut data = vec![tag];
    data.extend_from_slice(&arg.to_le_bytes());
    Instruction {
        program_id: solana_sdk::pubkey!("ComputeBudget111111111111111111111111111111"),
        accounts: vec![],
        data,
    }
}
fn heap_frame_ix(bytes: u32) -> Instruction {
    cb_ix(1, bytes) // RequestHeapFrame
}
fn cu_limit_ix(units: u32) -> Instruction {
    cb_ix(2, units) // SetComputeUnitLimit
}

fn send_ixs(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction]) -> Result<(), String> {
    let tx = Transaction::new(
        &[payer],
        Message::new(ixs, Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ()).map_err(|e| format!("{:?} {:#?}", e.err, e.meta.logs))
}

#[test]
fn heap_hog_fits_the_default_frame_under_the_custom_allocator() {
    // ~31 KiB is under the default 32 KiB heap and must succeed with no frame —
    // proving the custom bump allocator is a working allocator, not just an
    // unbounded one.
    let (mut svm, payer, _mutator) = setup();
    send_ixs(&mut svm, &payer, &[cu_limit_ix(400_000), mutator::heap_hog(31 * 1024)])
        .expect("31 KiB on default frame");
}

#[test]
fn heap_hog_past_default_frame_needs_a_request_heap_frame() {
    // 100 KiB exceeds the default 32 KiB: it must FAIL without a frame and
    // SUCCEED with a 128 KiB RequestHeapFrame — the exact relief that was inert
    // under the entrypoint's capped default allocator (Task 5 sweep). This is
    // the on-chain evidence that the Task 6 account-cap lift is real.
    let (mut svm, payer, _mutator) = setup();
    let without = send_ixs(
        &mut svm,
        &payer,
        &[cu_limit_ix(400_000), mutator::heap_hog(100 * 1024)],
    );
    assert!(without.is_err(), "100 KiB must fail on the default 32 KiB heap");

    let with = send_ixs(
        &mut svm,
        &payer,
        &[cu_limit_ix(400_000), heap_frame_ix(128 * 1024), mutator::heap_hog(100 * 1024)],
    );
    assert!(with.is_ok(), "100 KiB must succeed with a 128 KiB heap frame: {with:?}");
}

#[test]
fn every_instruction_discriminator_is_the_anchor_hash() {
    // Guard against a silently-wrong discriminator: each must equal
    // sha256("global:<name>")[..8]. (The helper computes exactly this, so the
    // real value of the test is catching a rename mismatch between the program
    // and the harness.)
    use sha2::{Digest, Sha256};
    for name in [
        "noop", "transfer_out", "set_delegate", "set_close_authority", "set_owner",
        "close_account", "close_zero_balance_ata_to_stranger", "realloc_self",
        "drain_lamports", "reenter_warden",
    ] {
        let mut h = Sha256::new();
        h.update(b"global:");
        h.update(name.as_bytes());
        let expect = &h.finalize()[..8];
        assert_eq!(&mutator::instruction_discriminator(name)[..], expect, "disc for {name}");
    }
    let _ = token_program_id();
}
