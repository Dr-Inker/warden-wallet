//! Phase 1B Task 4 — the `Stage` chunk-upload lifecycle, on-chain.
//!
//! Covers the happy path (open → chunk(s) → finalize → readback), the content
//! integrity checks (wrong-hash / incomplete / non-sequential), the
//! generation/policy binding recorded at finalize, the measured `stage_chunk`
//! payload cap (pinned exactly), and the two distinct Squads-v3 buffer failure
//! mechanisms as separate regressions:
//!   - **ND-SQD3-LO-01** (creator-less seed → squat): closed *by construction* —
//!     the PDA binds the creator, so a stranger cannot occupy the victim's
//!     address at all (`stranger_cannot_occupy_the_victims_stage_address`,
//!     `two_creators_stage_same_content_at_distinct_addresses`).
//!   - **Certora H-01** (lifecycle orphan): any stage — finalized or not —
//!     becomes permissionlessly closable after `expiry_ts`, rent to its creator
//!     (`unfinalized_stage_closed_by_anyone_after_expiry`,
//!     `finalized_stage_closed_by_anyone_after_expiry`).
//! Consume-once (an `execute` closing a finalized stage) is Task 5's.

mod common;

use common::*;
use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    sysvar,
    transaction::Transaction,
};
use anchor_lang::system_program;

use anchor_lang::{AccountDeserialize, AnchorSerialize};
use warden::constants::STAGE_CHUNK_PAYLOAD_CAP;
use warden::instructions::stage::{StageChunkArgs, StageOpenArgs};
use warden::state::Stage;

const PACKET_DATA_SIZE: usize = 1232;
const NOW: i64 = 1_760_000_000;

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn svm_at_now() -> (LiteSVM, Keypair) {
    let (mut svm, payer) = setup();
    warp_clock(&mut svm, NOW);
    (svm, payer)
}

/// The PDA binds account, **creator** (WRDF-0045) and content hash.
fn stage_pda(account: &Pubkey, creator: &Pubkey, hash: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"stage", account.as_ref(), creator.as_ref(), hash.as_ref()],
        &program_id(),
    )
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    solana_keccak_hasher::hashv(&[bytes]).to_bytes()
}

fn disc(name: &str) -> Vec<u8> {
    Sha256::digest(format!("global:{name}").as_bytes())[..8].to_vec()
}

fn open_ix(creator: Pubkey, account: Pubkey, args: &StageOpenArgs) -> Instruction {
    let (stage, _) = stage_pda(&account, &creator, &args.hash);
    let mut data = disc("stage_open");
    args.serialize(&mut data).unwrap();
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(creator, true),
            AccountMeta::new(stage, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

fn chunk_ix(creator: Pubkey, stage: Pubkey, args: &StageChunkArgs) -> Instruction {
    let mut data = disc("stage_chunk");
    args.serialize(&mut data).unwrap();
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(creator, true),
            AccountMeta::new(stage, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

fn finalize_ix(creator: Pubkey, stage: Pubkey, smart_account: Pubkey) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new_readonly(creator, true),
            AccountMeta::new(stage, false),
            AccountMeta::new_readonly(smart_account, false),
        ],
        data: disc("stage_finalize"),
    }
}

fn close_ix(closer: Pubkey, stage: Pubkey, creator: Pubkey) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(closer, true),
            AccountMeta::new(stage, false),
            AccountMeta::new(creator, false),
        ],
        data: disc("stage_close"),
    }
}

fn send(svm: &mut LiteSVM, signers: &[&Keypair], ixs: &[Instruction]) -> Result<(), String> {
    // Fresh blockhash per submission so two byte-identical instructions (a
    // retried open, a double finalize) get distinct signatures instead of
    // being rejected as AlreadyProcessed.
    svm.expire_blockhash();
    let payer = signers[0].pubkey();
    let tx = Transaction::new(
        &signers.to_vec(),
        Message::new(ixs, Some(&payer)),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .map(|_| ())
        .map_err(|e| format!("{:?} {:#?}", e.err, e.meta.logs))
}

fn read_stage(svm: &LiteSVM, pda: &Pubkey) -> Stage {
    let raw = svm.get_account(pda).expect("stage exists").data;
    Stage::try_deserialize(&mut raw.as_slice()).expect("valid Stage")
}

fn funded(svm: &mut LiteSVM) -> Keypair {
    let k = Keypair::new();
    svm.airdrop(&k.pubkey(), 10_000_000_000).unwrap();
    k
}

/// Open + fully upload a stage for `account` under `creator`, returning its PDA.
fn staged(svm: &mut LiteSVM, creator: &Keypair, account: Pubkey, payload: &[u8]) -> Pubkey {
    let hash = keccak(payload);
    let args = StageOpenArgs { account, hash, len: payload.len() as u32, expiry_ts: NOW + 1000 };
    let (stage, _) = stage_pda(&account, &creator.pubkey(), &hash);
    send(svm, &[creator], &[open_ix(creator.pubkey(), account, &args)]).expect("open");
    send(
        svm,
        &[creator],
        &[chunk_ix(creator.pubkey(), stage, &StageChunkArgs { offset: 0, bytes: payload.to_vec() })],
    )
    .expect("chunk");
    stage
}

/// A planted, canonical SmartAccount with a chosen `generation`/`policy_version`.
fn plant_account(svm: &mut LiteSVM, seed: u8, generation: u64, policy_version: u32) -> Pubkey {
    let pk = passkey::TestPasskey::new(seed);
    let f = SmartAccountFixture {
        root_pubkey33: pk.pubkey33(),
        policy: default_policy_args(),
        generation,
        policy_version,
        ..Default::default()
    };
    set_smart_account(svm, &f)
}

// ---------------------------------------------------------------------------
// happy path
// ---------------------------------------------------------------------------

#[test]
fn open_chunk_finalize_records_and_reads_back() {
    let (mut svm, payer) = svm_at_now();
    let account = plant_account(&mut svm, 3, 7, 4);
    let payload: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    let hash = keccak(&payload);
    let (stage, bump) = stage_pda(&account, &payer.pubkey(), &hash);

    let args = StageOpenArgs { account, hash, len: payload.len() as u32, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).expect("open");

    let s = read_stage(&svm, &stage);
    assert_eq!(s.version, 1);
    assert_eq!(s.bump, bump);
    assert_eq!(s.account, account);
    assert_eq!(s.creator, payer.pubkey());
    assert_eq!(s.hash, hash);
    assert_eq!(s.len, 200);
    assert_eq!(s.written, 0);
    assert!(!s.finalized);

    send(
        &mut svm,
        &[&payer],
        &[chunk_ix(payer.pubkey(), stage, &StageChunkArgs { offset: 0, bytes: payload.clone() })],
    )
    .expect("chunk");
    assert_eq!(read_stage(&svm, &stage).written, 200);

    send(&mut svm, &[&payer], &[finalize_ix(payer.pubkey(), stage, account)]).expect("finalize");
    let s = read_stage(&svm, &stage);
    assert!(s.finalized, "finalized");
    assert_eq!(s.written, s.len);
    assert_eq!(s.generation, 7, "records the account's live generation");
    assert_eq!(s.policy_version, 4, "records the account's live policy_version");
    assert_eq!(s.data, payload, "payload readable");
}

#[test]
fn multi_chunk_sequential_upload() {
    let (mut svm, payer) = svm_at_now();
    let account = plant_account(&mut svm, 3, 1, 1);
    let payload: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
    let hash = keccak(&payload);
    let (stage, _) = stage_pda(&account, &payer.pubkey(), &hash);
    let args = StageOpenArgs { account, hash, len: 300, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).expect("open");

    for (off, end) in [(0usize, 128usize), (128, 256), (256, 300)] {
        let bytes = payload[off..end].to_vec();
        send(
            &mut svm,
            &[&payer],
            &[chunk_ix(payer.pubkey(), stage, &StageChunkArgs { offset: off as u32, bytes })],
        )
        .unwrap_or_else(|e| panic!("chunk {off}..{end}: {e}"));
    }
    send(&mut svm, &[&payer], &[finalize_ix(payer.pubkey(), stage, account)]).expect("finalize");
    assert_eq!(read_stage(&svm, &stage).data, payload);
}

// ---------------------------------------------------------------------------
// integrity / validation
// ---------------------------------------------------------------------------

#[test]
fn finalize_with_wrong_content_rejected() {
    // Open under H = keccak(A), upload B (same length, different bytes); the
    // re-hash at finalize does not match the address.
    let (mut svm, payer) = svm_at_now();
    let account = plant_account(&mut svm, 3, 1, 1);
    let a: Vec<u8> = vec![0xAA; 64];
    let b: Vec<u8> = vec![0xBB; 64];
    let hash = keccak(&a);
    let (stage, _) = stage_pda(&account, &payer.pubkey(), &hash);
    let args = StageOpenArgs { account, hash, len: 64, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).expect("open");
    send(&mut svm, &[&payer], &[chunk_ix(payer.pubkey(), stage, &StageChunkArgs { offset: 0, bytes: b })]).expect("chunk");
    let err = send(&mut svm, &[&payer], &[finalize_ix(payer.pubkey(), stage, account)]).unwrap_err();
    assert!(err.contains("StageInvalid"), "{err}");
}

#[test]
fn finalize_incomplete_rejected() {
    let (mut svm, payer) = svm_at_now();
    let account = plant_account(&mut svm, 3, 1, 1);
    let payload = vec![9u8; 100];
    let hash = keccak(&payload);
    let (stage, _) = stage_pda(&account, &payer.pubkey(), &hash);
    let args = StageOpenArgs { account, hash, len: 100, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).expect("open");
    // only 50 of 100 bytes
    send(&mut svm, &[&payer], &[chunk_ix(payer.pubkey(), stage, &StageChunkArgs { offset: 0, bytes: vec![9u8; 50] })]).expect("chunk");
    let err = send(&mut svm, &[&payer], &[finalize_ix(payer.pubkey(), stage, account)]).unwrap_err();
    assert!(err.contains("StageInvalid"), "{err}");
}

#[test]
fn non_sequential_chunk_rejected() {
    let (mut svm, payer) = svm_at_now();
    let account = Pubkey::new_unique();
    let hash = keccak(&vec![1u8; 100]);
    let (stage, _) = stage_pda(&account, &payer.pubkey(), &hash);
    let args = StageOpenArgs { account, hash, len: 100, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).expect("open");
    // offset 10 != written 0
    let err = send(&mut svm, &[&payer], &[chunk_ix(payer.pubkey(), stage, &StageChunkArgs { offset: 10, bytes: vec![1u8; 10] })]).unwrap_err();
    assert!(err.contains("StageInvalid"), "{err}");
}

#[test]
fn chunk_past_len_rejected() {
    let (mut svm, payer) = svm_at_now();
    let account = Pubkey::new_unique();
    let hash = keccak(&vec![2u8; 32]);
    let (stage, _) = stage_pda(&account, &payer.pubkey(), &hash);
    let args = StageOpenArgs { account, hash, len: 32, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).expect("open");
    let err = send(&mut svm, &[&payer], &[chunk_ix(payer.pubkey(), stage, &StageChunkArgs { offset: 0, bytes: vec![2u8; 33] })]).unwrap_err();
    assert!(err.contains("StageInvalid"), "{err}");
}

#[test]
fn oversized_len_rejected_at_open() {
    let (mut svm, payer) = svm_at_now();
    let account = Pubkey::new_unique();
    let hash = [3u8; 32];
    let args = StageOpenArgs { account, hash, len: (Stage::MAX_DATA_LEN as u32) + 1, expiry_ts: NOW + 1000 };
    let err = send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).unwrap_err();
    assert!(err.contains("StageInvalid"), "{err}");
}

#[test]
fn double_finalize_rejected() {
    let (mut svm, payer) = svm_at_now();
    let account = plant_account(&mut svm, 3, 1, 1);
    let payload = vec![5u8; 40];
    let stage = staged(&mut svm, &payer, account, &payload);
    send(&mut svm, &[&payer], &[finalize_ix(payer.pubkey(), stage, account)]).expect("finalize 1");
    let err = send(&mut svm, &[&payer], &[finalize_ix(payer.pubkey(), stage, account)]).unwrap_err();
    assert!(err.contains("StageInvalid"), "{err}");
}

#[test]
fn chunk_after_finalize_rejected() {
    let (mut svm, payer) = svm_at_now();
    let account = plant_account(&mut svm, 3, 1, 1);
    let payload = vec![6u8; 40];
    let stage = staged(&mut svm, &payer, account, &payload);
    send(&mut svm, &[&payer], &[finalize_ix(payer.pubkey(), stage, account)]).expect("finalize");
    // len is full anyway, but the finalized guard must fire first.
    let err = send(&mut svm, &[&payer], &[chunk_ix(payer.pubkey(), stage, &StageChunkArgs { offset: 40, bytes: vec![6u8; 1] })]).unwrap_err();
    assert!(err.contains("StageInvalid"), "{err}");
}

#[test]
fn finalize_with_mismatched_smart_account_rejected() {
    // The passed SmartAccount's key must equal stage.account (Anchor constraint).
    let (mut svm, payer) = svm_at_now();
    let account = plant_account(&mut svm, 3, 1, 1);
    let other = plant_account(&mut svm, 5, 2, 2);
    let payload = vec![8u8; 40];
    let stage = staged(&mut svm, &payer, account, &payload);
    let err = send(&mut svm, &[&payer], &[finalize_ix(payer.pubkey(), stage, other)]).unwrap_err();
    assert!(err.contains("StageInvalid"), "{err}");
}

#[test]
fn finalize_rejects_noncanonical_smart_account() {
    // WRDF-0046: reach the stored-owner_seed/bump re-derivation. Plant a
    // Warden-owned, correctly-discriminated SmartAccount whose stored owner_seed
    // derives address P, but place its bytes at a DIFFERENT address Q, and bind
    // the stage to Q. Anchor's `key() == stage.account` passes (Q == Q), so
    // finalize reaches the manual `create_program_address` check, which rejects
    // because re-deriving from owner_seed yields P ≠ Q.
    let (mut svm, payer) = svm_at_now();
    let canonical = plant_account(&mut svm, 9, 1, 1); // real account at its PDA P
    let bytes = svm.get_account(&canonical).unwrap().data;
    let q = Pubkey::new_unique(); // a non-canonical address
    svm.set_account(
        q,
        Account { lamports: 10_000_000_000, data: bytes, owner: program_id(), executable: false, rent_epoch: 0 },
    )
    .unwrap();

    let payload = vec![7u8; 48];
    let stage = staged(&mut svm, &payer, q, &payload); // stage.account = Q
    let err = send(&mut svm, &[&payer], &[finalize_ix(payer.pubkey(), stage, q)]).unwrap_err();
    assert!(err.contains("Unauthorized"), "the re-derivation must reject a non-canonical copy: {err}");
}

// ---------------------------------------------------------------------------
// close semantics
// ---------------------------------------------------------------------------

#[test]
fn creator_closes_before_finalize_and_gets_rent() {
    let (mut svm, payer) = svm_at_now();
    let account = Pubkey::new_unique();
    let hash = keccak(&vec![1u8; 50]);
    let (stage, _) = stage_pda(&account, &payer.pubkey(), &hash);
    let args = StageOpenArgs { account, hash, len: 50, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).expect("open");
    let before = svm.get_account(&payer.pubkey()).unwrap().lamports;
    send(&mut svm, &[&payer], &[close_ix(payer.pubkey(), stage, payer.pubkey())]).expect("close");
    assert!(svm.get_account(&stage).map(|a| a.lamports == 0).unwrap_or(true), "stage closed");
    let after = svm.get_account(&payer.pubkey()).unwrap().lamports;
    assert!(after > before, "creator recovered rent (minus fee): {before} -> {after}");
}

#[test]
fn stranger_cannot_close_before_expiry() {
    let (mut svm, payer) = svm_at_now();
    let stranger = funded(&mut svm);
    let account = Pubkey::new_unique();
    let hash = keccak(&vec![1u8; 50]);
    let (stage, _) = stage_pda(&account, &payer.pubkey(), &hash);
    let args = StageOpenArgs { account, hash, len: 50, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).expect("open");
    // stranger tries to close (rent still routed to creator=payer), before expiry.
    let err = send(&mut svm, &[&stranger], &[close_ix(stranger.pubkey(), stage, payer.pubkey())]).unwrap_err();
    assert!(err.contains("Unauthorized"), "{err}");
    assert!(svm.get_account(&stage).is_some(), "stage survives");
}

#[test]
fn unfinalized_stage_closed_by_anyone_after_expiry() {
    let (mut svm, payer) = svm_at_now();
    let stranger = funded(&mut svm);
    let account = Pubkey::new_unique();
    let hash = keccak(&vec![1u8; 50]);
    let (stage, _) = stage_pda(&account, &payer.pubkey(), &hash);
    let args = StageOpenArgs { account, hash, len: 50, expiry_ts: NOW + 100 };
    send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).expect("open");
    warp_clock(&mut svm, NOW + 200); // past expiry
    let creator_before = svm.get_account(&payer.pubkey()).unwrap().lamports;
    send(&mut svm, &[&stranger], &[close_ix(stranger.pubkey(), stage, payer.pubkey())]).expect("stranger closes after expiry");
    let creator_after = svm.get_account(&payer.pubkey()).unwrap().lamports;
    assert!(creator_after > creator_before, "rent refunds the creator, not the closer");
    assert!(svm.get_account(&stage).map(|a| a.lamports == 0).unwrap_or(true), "stage closed");
}

#[test]
fn finalized_stage_closed_by_anyone_after_expiry() {
    // Certora H-01 lifecycle GC: a FINALIZED but unconsumed stage that expires
    // is still permissionlessly closable, rent to its creator — no finalized
    // stage can be parked forever.
    let (mut svm, payer) = svm_at_now();
    let stranger = funded(&mut svm);
    let account = plant_account(&mut svm, 3, 1, 1);
    let payload = vec![4u8; 60];
    let hash = keccak(&payload);
    let (stage, _) = stage_pda(&account, &payer.pubkey(), &hash);
    let args = StageOpenArgs { account, hash, len: 60, expiry_ts: NOW + 100 };
    send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).expect("open");
    send(&mut svm, &[&payer], &[chunk_ix(payer.pubkey(), stage, &StageChunkArgs { offset: 0, bytes: payload })]).expect("chunk");
    send(&mut svm, &[&payer], &[finalize_ix(payer.pubkey(), stage, account)]).expect("finalize");
    assert!(read_stage(&svm, &stage).finalized);

    warp_clock(&mut svm, NOW + 200);
    let creator_before = svm.get_account(&payer.pubkey()).unwrap().lamports;
    send(&mut svm, &[&stranger], &[close_ix(stranger.pubkey(), stage, payer.pubkey())]).expect("finalized+expired closes");
    let creator_after = svm.get_account(&payer.pubkey()).unwrap().lamports;
    assert!(creator_after > creator_before, "rent refunds the creator");
    assert!(svm.get_account(&stage).map(|a| a.lamports == 0).unwrap_or(true), "closed");
}

#[test]
fn close_to_wrong_creator_rejected() {
    let (mut svm, payer) = svm_at_now();
    let account = Pubkey::new_unique();
    let hash = keccak(&vec![1u8; 50]);
    let (stage, _) = stage_pda(&account, &payer.pubkey(), &hash);
    let args = StageOpenArgs { account, hash, len: 50, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).expect("open");
    let thief = funded(&mut svm);
    // rent-destination account != stage.creator
    let err = send(&mut svm, &[&payer], &[close_ix(payer.pubkey(), stage, thief.pubkey())]).unwrap_err();
    assert!(err.contains("StageInvalid"), "{err}");
}

// ---------------------------------------------------------------------------
// ND-SQD3-LO-01 — squat closed by construction (creator in the seeds, WRDF-0045)
// ---------------------------------------------------------------------------

#[test]
fn stranger_cannot_occupy_the_victims_stage_address() {
    // A stranger who observes the victim's payload and opens a stage for the
    // same (account, content) lands at THEIR OWN address, not the victim's. The
    // victim's stage_open at ["stage", account, victim, hash] succeeds
    // immediately and unconditionally — there is no shared address to squat, so
    // no re-squat race, ever.
    let (mut svm, victim) = svm_at_now();
    let stranger = funded(&mut svm);
    let account = Pubkey::new_unique();
    let payload = vec![0xEEu8; 128];
    let hash = keccak(&payload);
    let (victim_stage, _) = stage_pda(&account, &victim.pubkey(), &hash);
    let (stranger_stage, _) = stage_pda(&account, &stranger.pubkey(), &hash);
    assert_ne!(victim_stage, stranger_stage, "creator in seeds ⇒ distinct addresses");

    let args = StageOpenArgs { account, hash, len: 128, expiry_ts: NOW + 3600 };
    // Stranger opens their stage first.
    send(&mut svm, &[&stranger], &[open_ix(stranger.pubkey(), account, &args)]).expect("stranger opens own stage");
    // Victim opens theirs — unaffected, no reclaim needed.
    send(&mut svm, &[&victim], &[open_ix(victim.pubkey(), account, &args)]).expect("victim opens own stage");
    assert_eq!(read_stage(&svm, &victim_stage).creator, victim.pubkey());
    assert_eq!(read_stage(&svm, &stranger_stage).creator, stranger.pubkey());
}

#[test]
fn two_creators_stage_same_content_at_distinct_addresses() {
    let (mut svm, a) = svm_at_now();
    let b = funded(&mut svm);
    let account = Pubkey::new_unique();
    let payload = vec![0x11u8; 96];
    let hash = keccak(&payload);
    let (pa, _) = stage_pda(&account, &a.pubkey(), &hash);
    let (pb, _) = stage_pda(&account, &b.pubkey(), &hash);
    assert_ne!(pa, pb);
    let args = StageOpenArgs { account, hash, len: 96, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&a], &[open_ix(a.pubkey(), account, &args)]).expect("A opens");
    send(&mut svm, &[&b], &[open_ix(b.pubkey(), account, &args)]).expect("B opens");
    assert_eq!(read_stage(&svm, &pa).creator, a.pubkey());
    assert_eq!(read_stage(&svm, &pb).creator, b.pubkey());
}

#[test]
fn stranger_cannot_chunk_or_early_close_victims_stage() {
    // Creator-only chunk / early-close, even when the stranger names the
    // victim's stage pubkey directly.
    let (mut svm, victim) = svm_at_now();
    let stranger = funded(&mut svm);
    let account = Pubkey::new_unique();
    let hash = keccak(&vec![1u8; 64]);
    let (stage, _) = stage_pda(&account, &victim.pubkey(), &hash);
    let args = StageOpenArgs { account, hash, len: 64, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&victim], &[open_ix(victim.pubkey(), account, &args)]).expect("victim opens");

    // A stranger's chunk names the victim's stage but signs as themselves; the
    // seeds constraint (stage.creator == victim) makes the passed stage the
    // victim's, and the creator-only handler check rejects the stranger.
    let e1 = send(&mut svm, &[&stranger], &[chunk_ix(stranger.pubkey(), stage, &StageChunkArgs { offset: 0, bytes: vec![1u8; 10] })]).unwrap_err();
    assert!(e1.contains("Unauthorized"), "chunk: {e1}");
    let e2 = send(&mut svm, &[&stranger], &[close_ix(stranger.pubkey(), stage, victim.pubkey())]).unwrap_err();
    assert!(e2.contains("Unauthorized"), "early close: {e2}");
}

#[test]
fn open_rejects_expiry_beyond_max_ttl() {
    let (mut svm, payer) = svm_at_now();
    let account = Pubkey::new_unique();
    let hash = [4u8; 32];
    let args = StageOpenArgs { account, hash, len: 32, expiry_ts: NOW + 3601 };
    let err = send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).unwrap_err();
    assert!(err.contains("StageInvalid"), "{err}");
}

#[test]
fn open_rejects_past_expiry() {
    let (mut svm, payer) = svm_at_now();
    let account = Pubkey::new_unique();
    let hash = [5u8; 32];
    let args = StageOpenArgs { account, hash, len: 32, expiry_ts: NOW - 1 };
    let err = send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).unwrap_err();
    assert!(err.contains("StageInvalid"), "{err}");
}

// ---------------------------------------------------------------------------
// measured payload cap (pinned exactly; spec §5.1 / §12.3, WRDF-0047)
// ---------------------------------------------------------------------------

#[test]
fn stage_chunk_payload_cap_is_measured() {
    // Binary-search the largest payload a single stage_chunk transaction can
    // carry under the fixed 3-account layout (disc + offset:u32 + len:u32 +
    // payload) against the 1,232 B packet. SIZE only — no send.
    let (svm, payer) = svm_at_now();
    let account = Pubkey::new_unique();
    let hash = [7u8; 32];
    let (stage, _) = stage_pda(&account, &payer.pubkey(), &hash);
    let measure = |n: usize| -> usize {
        let ix = chunk_ix(payer.pubkey(), stage, &StageChunkArgs { offset: 0, bytes: vec![0u8; n] });
        let tx = Transaction::new(&[&payer], Message::new(&[ix], Some(&payer.pubkey())), svm.latest_blockhash());
        bincode::serialize(&tx).unwrap().len()
    };
    let mut lo = 0usize;
    let mut hi = Stage::MAX_DATA_LEN;
    while lo < hi {
        let mid = lo + (hi - lo + 1) / 2;
        if measure(mid) <= PACKET_DATA_SIZE {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let cap = lo;
    println!("MEASURED stage_chunk payload cap: {cap} B (tx at cap = {} B)", measure(cap));
    // Pin the exact number: a serialization/layout drift that moves it must
    // fail here and force the constant + PHASE1B-MEASUREMENTS.md to move too.
    assert_eq!(cap, 979, "the measured stage_chunk payload cap");
    assert_eq!(
        cap, STAGE_CHUNK_PAYLOAD_CAP,
        "the client contract constant must equal the measured cap"
    );
    assert_eq!(measure(979), PACKET_DATA_SIZE, "the tx at the cap is exactly the packet");
    assert!(measure(980) > PACKET_DATA_SIZE, "one byte past the cap overflows");
}

/// Pins the exact 3-account chunk layout so a stray extra account cannot creep
/// in and silently shrink the cap.
#[test]
fn stage_chunk_layout_is_exactly_three_accounts() {
    let (_svm, payer) = svm_at_now();
    let account = Pubkey::new_unique();
    let (stage, _) = stage_pda(&account, &payer.pubkey(), &[0u8; 32]);
    let ix = chunk_ix(payer.pubkey(), stage, &StageChunkArgs { offset: 0, bytes: vec![0u8; 1] });
    assert_eq!(ix.accounts.len(), 3, "creator, stage, system");
    assert_eq!(ix.accounts[2].pubkey, system_program::ID);
    assert!(!ix.accounts.iter().any(|m| m.pubkey == sysvar::instructions::ID));
}
