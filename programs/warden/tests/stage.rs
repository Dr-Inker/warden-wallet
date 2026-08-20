//! Phase 1B Task 4 — the `Stage` chunk-upload lifecycle, on-chain.
//!
//! Covers the happy path (open → chunk(s) → finalize → readback), the content
//! integrity checks (wrong-hash / incomplete / non-sequential), the
//! generation/policy binding recorded at finalize, the measured `stage_chunk`
//! payload cap (replacing the PROVISIONAL 985 B), and the content-address
//! squat class (ND-SQD3-LO-01 / Certora H-01): a stranger who pre-opens
//! `["stage", victim, hash]` is time-boxed by `expiry_ts`, pays their own rent,
//! and cannot touch the victim's own stage. Consume-once (an `execute` closing
//! a finalized stage) is Task 5's, exercised there.

mod common;

use common::*;
use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_sdk::{
    clock::Clock,
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

fn stage_pda(account: &Pubkey, hash: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"stage", account.as_ref(), hash.as_ref()], &program_id())
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    solana_keccak_hasher::hashv(&[bytes]).to_bytes()
}

fn disc(name: &str) -> Vec<u8> {
    Sha256::digest(format!("global:{name}").as_bytes())[..8].to_vec()
}

fn open_ix(creator: Pubkey, account: Pubkey, args: &StageOpenArgs) -> Instruction {
    let (stage, _) = stage_pda(&account, &args.hash);
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

/// Open + fully upload + finalize a stage for `account`, returning its PDA.
fn staged(svm: &mut LiteSVM, creator: &Keypair, account: Pubkey, payload: &[u8]) -> Pubkey {
    let hash = keccak(payload);
    let args = StageOpenArgs { account, hash, len: payload.len() as u32, expiry_ts: NOW + 1000 };
    let (stage, _) = stage_pda(&account, &hash);
    send(svm, &[creator], &[open_ix(creator.pubkey(), account, &args)]).expect("open");
    send(
        svm,
        &[creator],
        &[chunk_ix(creator.pubkey(), stage, &StageChunkArgs { offset: 0, bytes: payload.to_vec() })],
    )
    .expect("chunk");
    stage
}

/// A planted SmartAccount with a chosen `generation`/`policy_version`, for the
/// finalize binding test.
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
    let (stage, bump) = stage_pda(&account, &hash);

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
    let (stage, _) = stage_pda(&account, &hash);
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
    let (stage, _) = stage_pda(&account, &hash);
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
    let (stage, _) = stage_pda(&account, &hash);
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
    let (stage, _) = stage_pda(&account, &hash);
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
    let (stage, _) = stage_pda(&account, &hash);
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
    // The passed SmartAccount must be the one the stage is bound to.
    let (mut svm, payer) = svm_at_now();
    let account = plant_account(&mut svm, 3, 1, 1);
    let other = plant_account(&mut svm, 5, 2, 2);
    let payload = vec![8u8; 40];
    let stage = staged(&mut svm, &payer, account, &payload);
    let err = send(&mut svm, &[&payer], &[finalize_ix(payer.pubkey(), stage, other)]).unwrap_err();
    assert!(err.contains("StageInvalid"), "{err}");
}

// ---------------------------------------------------------------------------
// close semantics
// ---------------------------------------------------------------------------

#[test]
fn creator_closes_before_finalize_and_gets_rent() {
    let (mut svm, payer) = svm_at_now();
    let account = Pubkey::new_unique();
    let hash = keccak(&vec![1u8; 50]);
    let (stage, _) = stage_pda(&account, &hash);
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
    let (stage, _) = stage_pda(&account, &hash);
    let args = StageOpenArgs { account, hash, len: 50, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).expect("open");
    // stranger tries to close (rent still routed to creator=payer), before expiry.
    let err = send(&mut svm, &[&stranger], &[close_ix(stranger.pubkey(), stage, payer.pubkey())]).unwrap_err();
    assert!(err.contains("Unauthorized"), "{err}");
    assert!(svm.get_account(&stage).is_some(), "stage survives");
}

#[test]
fn anyone_closes_after_expiry_rent_to_creator() {
    let (mut svm, payer) = svm_at_now();
    let stranger = funded(&mut svm);
    let account = Pubkey::new_unique();
    let hash = keccak(&vec![1u8; 50]);
    let (stage, _) = stage_pda(&account, &hash);
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
fn close_to_wrong_creator_rejected() {
    let (mut svm, payer) = svm_at_now();
    let account = Pubkey::new_unique();
    let hash = keccak(&vec![1u8; 50]);
    let (stage, _) = stage_pda(&account, &hash);
    let args = StageOpenArgs { account, hash, len: 50, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&payer], &[open_ix(payer.pubkey(), account, &args)]).expect("open");
    let thief = funded(&mut svm);
    // rent-destination account != stage.creator
    let err = send(&mut svm, &[&payer], &[close_ix(payer.pubkey(), stage, thief.pubkey())]).unwrap_err();
    assert!(err.contains("StageInvalid"), "{err}");
}

// ---------------------------------------------------------------------------
// content-address squat — ND-SQD3-LO-01 / Certora H-01 (WRD-BUF-*)
// ---------------------------------------------------------------------------

#[test]
fn stranger_pre_opens_stage_at_our_hash_is_time_boxed() {
    // (i) A stranger observes the victim's payload, computes its hash, and opens
    // ["stage", victim, H] first. The victim's own open then fails on the
    // already-initialised PDA — but only until expiry, after which anyone may
    // close it and the victim succeeds.
    let (mut svm, victim) = svm_at_now();
    let stranger = funded(&mut svm);
    let account = Pubkey::new_unique(); // the victim's SmartAccount
    let payload = vec![0xEEu8; 128];
    let hash = keccak(&payload);
    let (stage, _) = stage_pda(&account, &hash);

    // Stranger squats with the max expiry.
    let squat = StageOpenArgs { account, hash, len: 128, expiry_ts: NOW + 3600 };
    send(&mut svm, &[&stranger], &[open_ix(stranger.pubkey(), account, &squat)]).expect("stranger squats");

    // Victim's own open of the same content-address fails (already in use).
    let victim_args = StageOpenArgs { account, hash, len: 128, expiry_ts: NOW + 1000 };
    let err = send(&mut svm, &[&victim], &[open_ix(victim.pubkey(), account, &victim_args)]).unwrap_err();
    assert!(!err.is_empty(), "victim's re-open must fail while the squat stands");

    // The squat is time-boxed. After expiry anyone closes it (rent to stranger).
    warp_clock(&mut svm, NOW + 3601);
    send(&mut svm, &[&victim], &[close_ix(victim.pubkey(), stage, stranger.pubkey())]).expect("anyone closes after expiry");

    // Now the victim can open it for real (fresh expiry against the warped clock).
    let reopen = StageOpenArgs { account, hash, len: 128, expiry_ts: NOW + 3601 + 1000 };
    send(&mut svm, &[&victim], &[open_ix(victim.pubkey(), account, &reopen)]).expect("victim opens after reclaim");
    assert_eq!(read_stage(&svm, &stage).creator, victim.pubkey());
}

#[test]
fn squat_rent_returns_to_the_squatter() {
    // (ii) Squatting costs the attacker: the rent they locked returns to THEM
    // on close, never to the victim.
    let (mut svm, victim) = svm_at_now();
    let stranger = funded(&mut svm);
    let account = Pubkey::new_unique();
    let payload = vec![0x11u8; 96];
    let hash = keccak(&payload);
    let (stage, _) = stage_pda(&account, &hash);
    let squat = StageOpenArgs { account, hash, len: 96, expiry_ts: NOW + 100 };
    send(&mut svm, &[&stranger], &[open_ix(stranger.pubkey(), account, &squat)]).expect("squat");

    let stranger_before = svm.get_account(&stranger.pubkey()).unwrap().lamports;
    let victim_before = svm.get_account(&victim.pubkey()).unwrap().lamports;
    warp_clock(&mut svm, NOW + 200);
    // Victim pays the fee to clean up; rent must still go to the stranger.
    send(&mut svm, &[&victim], &[close_ix(victim.pubkey(), stage, stranger.pubkey())]).expect("close");
    let stranger_after = svm.get_account(&stranger.pubkey()).unwrap().lamports;
    let victim_after = svm.get_account(&victim.pubkey()).unwrap().lamports;
    assert!(stranger_after > stranger_before, "squatter reabsorbs their own rent");
    assert!(victim_after < victim_before, "victim only paid the cleanup fee, gained no rent");
}

#[test]
fn stranger_cannot_chunk_or_early_close_victims_stage() {
    // (iii) When the VICTIM created the stage, a stranger can neither chunk into
    // it nor close it before expiry.
    let (mut svm, victim) = svm_at_now();
    let stranger = funded(&mut svm);
    let account = Pubkey::new_unique();
    let hash = keccak(&vec![1u8; 64]);
    let (stage, _) = stage_pda(&account, &hash);
    let args = StageOpenArgs { account, hash, len: 64, expiry_ts: NOW + 1000 };
    send(&mut svm, &[&victim], &[open_ix(victim.pubkey(), account, &args)]).expect("victim opens");

    let e1 = send(&mut svm, &[&stranger], &[chunk_ix(stranger.pubkey(), stage, &StageChunkArgs { offset: 0, bytes: vec![1u8; 10] })]).unwrap_err();
    assert!(e1.contains("Unauthorized"), "chunk: {e1}");
    let e2 = send(&mut svm, &[&stranger], &[close_ix(stranger.pubkey(), stage, victim.pubkey())]).unwrap_err();
    assert!(e2.contains("Unauthorized"), "early close: {e2}");
}

#[test]
fn open_rejects_expiry_beyond_max_ttl() {
    // (iv) The squat window is bounded: an expiry further out than the TTL is
    // refused, so no stage can be parked indefinitely.
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
// measured payload cap (replaces the PROVISIONAL 985 B; spec §5.1 / §12.3)
// ---------------------------------------------------------------------------

#[test]
fn stage_chunk_payload_cap_is_measured() {
    // Binary-search the largest payload a single stage_chunk transaction can
    // carry under the fixed 3-account layout (disc + offset:u32 + len:u32 +
    // payload) against the 1,232 B packet. SIZE only — no send.
    let (svm, payer) = svm_at_now();
    let account = Pubkey::new_unique();
    let hash = [7u8; 32];
    let (stage, _) = stage_pda(&account, &hash);
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
    assert_eq!(measure(cap), 1232.min(measure(cap)), "cap tx is within the packet");
    assert!(measure(cap) <= PACKET_DATA_SIZE, "cap fits");
    assert!(measure(cap + 1) > PACKET_DATA_SIZE, "cap is the boundary");
    // Sanity: the spec's provisional estimate was ~977 B under this encoding.
    assert!(
        (900..=1000).contains(&cap),
        "measured cap {cap} B is outside the expected band — record it in PHASE1B-MEASUREMENTS.md and update this band"
    );
}

/// The instructions sysvar is NOT part of the stage lifecycle (staging carries
/// no root ceremony); this pins that the 3-account chunk layout is exactly the
/// spec's, so a stray extra account cannot creep in and silently shrink the cap.
#[test]
fn stage_chunk_layout_is_exactly_three_accounts() {
    let (_svm, payer) = svm_at_now();
    let account = Pubkey::new_unique();
    let (stage, _) = stage_pda(&account, &[0u8; 32]);
    let ix = chunk_ix(payer.pubkey(), stage, &StageChunkArgs { offset: 0, bytes: vec![0u8; 1] });
    assert_eq!(ix.accounts.len(), 3, "creator, stage, system");
    assert_eq!(ix.accounts[2].pubkey, system_program::ID);
    // sysvar import kept meaningful: assert the layout does NOT include it.
    assert!(!ix.accounts.iter().any(|m| m.pubkey == sysvar::instructions::ID));
}
