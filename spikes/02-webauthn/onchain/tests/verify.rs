//! Spike 2b step 3: run the real assertion through LiteSVM.
//!
//! Transaction shape (the one Phase 1 will use):
//!   ix[0] = Secp256r1SigVerify precompile over (pubkey33, sig64, message)
//!   ix[1] = our program, with the Instructions sysvar as account 0
use litesvm::LiteSVM;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    sysvar,
    transaction::Transaction,
};
use std::{fs, path::PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The `.so` lands in the target dir of whichever workspace built it. The spike
/// crate is currently its own workspace root (see Cargo.toml), so
/// `<crate>/target/deploy` is the normal location; the repo-root `target/deploy`
/// is checked too so this keeps working if/when the spike rejoins the root
/// workspace.
fn program_so() -> Vec<u8> {
    let candidates = [
        manifest_dir().join("target/deploy/spike_p256.so"),
        manifest_dir().join("../../../target/deploy/spike_p256.so"),
    ];
    for c in &candidates {
        if let Ok(b) = fs::read(c) {
            return b;
        }
    }
    panic!("spike_p256.so not found; run `cargo-build-sbf --manifest-path spikes/02-webauthn/onchain/Cargo.toml` first. Looked in: {candidates:?}");
}

struct Raw {
    pk: Vec<u8>,
    sig: Vec<u8>,
    sig_as_signed: Vec<u8>,
    low_s_normalization_needed: bool,
    msg: Vec<u8>,
    auth: Vec<u8>,
    cdj: Vec<u8>,
    rp: Vec<u8>,
    origin: Vec<u8>,
    chal: Vec<u8>,
}

fn load_raw() -> Raw {
    let p = manifest_dir().join("../out/raw.json");
    let v: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("{}: {e} — run Task 4 step 1 (ts/src/prep.ts) first", p.display())),
    )
    .unwrap();
    let hx = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
    Raw {
        pk: hx("pubkey33"),
        sig: hx("sig64"),
        sig_as_signed: hx("sig64AsSigned"),
        low_s_normalization_needed: v["lowSNormalizationNeeded"].as_bool().unwrap(),
        msg: hx("message"),
        auth: hx("authenticatorData"),
        cdj: hx("clientDataJSON"),
        rp: hx("rpIdHash"),
        origin: v["origin"].as_str().unwrap().as_bytes().to_vec(),
        chal: v["challenge"].as_str().unwrap().as_bytes().to_vec(),
    }
}

/// Serialize the program's instruction data. `chal` is a parameter so the
/// negative test can pass a wrong challenge.
fn ix_data(r: &Raw, chal: &[u8], precompile_ix_index: u8) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&r.pk);
    data.extend_from_slice(&r.rp);
    data.extend_from_slice(&(r.origin.len() as u16).to_le_bytes());
    data.extend_from_slice(&r.origin);
    data.extend_from_slice(&(chal.len() as u16).to_le_bytes());
    data.extend_from_slice(chal);
    data.push(precompile_ix_index);
    data.extend_from_slice(&(r.auth.len() as u16).to_le_bytes());
    data.extend_from_slice(&r.auth);
    data.extend_from_slice(&r.cdj);
    data
}

fn build(chal: &[u8]) -> (LiteSVM, Transaction) {
    build_with(chal, None)
}

/// `sig_override` replaces the 64-byte signature handed to the precompile.
fn build_with(chal: &[u8], sig_override: Option<Vec<u8>>) -> (LiteSVM, Transaction) {
    let r = load_raw();
    let sig = sig_override.unwrap_or_else(|| r.sig.clone());
    let mut svm = LiteSVM::new();
    let pid = Pubkey::new_unique();
    svm.add_program(pid, &program_so()).expect("add_program");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let pre = solana_secp256r1_program::new_secp256r1_instruction_with_signature(
        &r.msg,
        &sig.try_into().unwrap(),
        &r.pk.clone().try_into().unwrap(),
    );
    let ours = Instruction {
        program_id: pid,
        accounts: vec![AccountMeta::new_readonly(sysvar::instructions::ID, false)],
        data: ix_data(&r, chal, 0),
    };
    let tx = Transaction::new(
        &[&payer],
        Message::new(&[pre, ours], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    (svm, tx)
}

#[test]
fn binds_real_assertion() {
    let r = load_raw();
    let (mut svm, tx) = build(&r.chal);
    // Transaction-size evidence for spike 03 (tx budget).
    println!(
        "precompile ix data: {} B, our ix data: {} B, serialized tx: {} B",
        tx.message.instructions[0].data.len(),
        tx.message.instructions[1].data.len(),
        bincode::serialize(&tx).unwrap().len()
    );
    let res = svm.send_transaction(tx).expect("tx should succeed");
    println!("logs: {:#?}", res.logs);
    println!("CU used: {}", res.compute_units_consumed);
    assert!(
        res.compute_units_consumed < 100_000,
        "CU budget blown: {}",
        res.compute_units_consumed
    );
}

#[test]
fn rejects_wrong_challenge() {
    let (mut svm, tx) = build(b"AAAA");
    let res = svm.send_transaction(tx);
    let err = res.expect_err("tx with a wrong challenge must fail");
    // Must fail for the *right* reason: our program (instruction index 1)
    // rejecting with InvalidArgument — not because the precompile is missing
    // or the program failed to load.
    assert_eq!(
        err.err,
        solana_sdk::transaction::TransactionError::InstructionError(
            1,
            solana_sdk::instruction::InstructionError::InvalidArgument
        ),
        "unexpected failure mode: {:?} logs={:#?}",
        err.err,
        err.meta.logs
    );
    assert!(
        err.meta.logs.iter().any(|l| l.contains("challenge mismatch")),
        "expected the challenge-mismatch log, got {:#?}",
        err.meta.logs
    );
}

/// Proves the precompile really runs (and is not silently skipped by LiteSVM):
/// a single flipped byte in the signature must kill the whole transaction.
#[test]
fn precompile_rejects_tampered_signature() {
    let r = load_raw();
    let mut bad = r.sig.clone();
    bad[0] ^= 0x01;
    let (mut svm, tx) = build_with(&r.chal, Some(bad));
    let err = svm
        .send_transaction(tx)
        .expect_err("tampered signature must fail");
    println!("tampered-signature error: {:?}", err.err);
}

/// Proves the low-S requirement is real: this authenticator emitted a high-S
/// signature, and the precompile must reject it un-normalized.
#[test]
fn precompile_rejects_high_s_signature() {
    let r = load_raw();
    if !r.low_s_normalization_needed {
        eprintln!("SKIP: this sample was already low-S, nothing to prove");
        return;
    }
    let (mut svm, tx) = build_with(&r.chal, Some(r.sig_as_signed.clone()));
    let err = svm
        .send_transaction(tx)
        .expect_err("high-S signature must be rejected by the precompile");
    println!("high-S error: {:?}", err.err);
}
