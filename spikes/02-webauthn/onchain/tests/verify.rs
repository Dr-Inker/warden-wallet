//! Spike 2b step 3: run the real assertion through LiteSVM.
//!
//! Transaction shape (the one Phase 1 will use):
//!   ix[0] = Secp256r1SigVerify precompile over (pubkey33, sig64, message)
//!   ix[1] = our program, with the Instructions sysvar as account 0
use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    sysvar,
    transaction::{Transaction, TransactionError},
};
use std::{fs, path::PathBuf};

const OUR_IX_INDEX: u8 = 1;

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
    /// rpIdHash as it appears in the SIGNED authenticatorData. Only ever used to
    /// be *compared against* an independently derived value — never as the
    /// program's expected input (that would make the check tautological).
    rp_from_auth_data: Vec<u8>,
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
        rp_from_auth_data: hx("rpIdHashFromAuthData"),
        origin: v["origin"].as_str().unwrap().as_bytes().to_vec(),
        chal: v["challenge"].as_str().unwrap().as_bytes().to_vec(),
    }
}

/// The expected rpIdHash, derived here in Rust from the ORIGIN STRING — the
/// trusted constant a wallet account would hold. It is deliberately NOT read
/// out of `authenticatorData`; see `rp_id_hash_is_sha256_of_the_full_origin`.
fn expected_rp_id_hash(origin: &[u8]) -> Vec<u8> {
    Sha256::digest(origin).to_vec()
}

// ---------------------------------------------------------------------------
// Precompile instruction construction
// ---------------------------------------------------------------------------

/// Hand-built secp256r1 precompile instruction, so the negative tests can bend
/// the parts `new_secp256r1_instruction_with_signature` hard-codes.
/// Layout (confirmed against solana-secp256r1-program 3.0.0):
/// `[num_signatures u8][padding u8][14-byte offsets] * n` then
/// `pubkey(33) || signature(64) || message(n)`.
fn build_precompile_ix(
    pk: &[u8],
    sig: &[u8],
    msg: &[u8],
    num_signatures: u8,
    entry_instruction_index: u16,
    msg_offset_override: Option<u16>,
) -> Instruction {
    let offsets_start = 2usize;
    let data_start = offsets_start + 14 * num_signatures as usize;
    let pk_off = data_start;
    let sig_off = pk_off + 33;
    let msg_off = sig_off + 64;
    let mut d = vec![num_signatures, 0u8];
    for _ in 0..num_signatures {
        d.extend_from_slice(&(sig_off as u16).to_le_bytes());
        d.extend_from_slice(&entry_instruction_index.to_le_bytes());
        d.extend_from_slice(&(pk_off as u16).to_le_bytes());
        d.extend_from_slice(&entry_instruction_index.to_le_bytes());
        d.extend_from_slice(&msg_offset_override.unwrap_or(msg_off as u16).to_le_bytes());
        d.extend_from_slice(&(msg.len() as u16).to_le_bytes());
        d.extend_from_slice(&entry_instruction_index.to_le_bytes());
    }
    d.extend_from_slice(pk);
    d.extend_from_slice(sig);
    d.extend_from_slice(msg);
    Instruction {
        program_id: solana_secp256r1_program::ID,
        accounts: vec![],
        data: d,
    }
}

// ---------------------------------------------------------------------------
// Transaction builder
// ---------------------------------------------------------------------------

/// Everything a negative test might want to bend. `Default` = the honest path.
struct Case {
    /// challenge the program is told to expect
    chal: Option<Vec<u8>>,
    /// pubkey the program is told to expect
    expected_pk: Option<Vec<u8>>,
    /// rpIdHash the program is told to expect
    expected_rp: Option<Vec<u8>>,
    /// authenticatorData handed to OUR instruction (precompile keeps the real one)
    our_auth: Option<Vec<u8>>,
    /// signature handed to the PRECOMPILE
    sig: Option<Vec<u8>>,
    num_signatures: u8,
    entry_instruction_index: u16,
    msg_offset_override: Option<u16>,
    /// truncate our instruction data to this many bytes
    truncate_our_data: Option<usize>,
    /// instruction index our program is told to inspect
    precompile_ix_index: u8,
}

impl Default for Case {
    fn default() -> Self {
        Self {
            chal: None,
            expected_pk: None,
            expected_rp: None,
            our_auth: None,
            sig: None,
            num_signatures: 1,
            entry_instruction_index: u16::MAX,
            msg_offset_override: None,
            truncate_our_data: None,
            precompile_ix_index: 0,
        }
    }
}

fn build(case: Case) -> (LiteSVM, Transaction, Raw) {
    let r = load_raw();
    let mut svm = LiteSVM::new();
    let pid = Pubkey::new_unique();
    svm.add_program(pid, &program_so()).expect("add_program");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let sig = case.sig.clone().unwrap_or_else(|| r.sig.clone());
    let pre = build_precompile_ix(
        &r.pk,
        &sig,
        &r.msg,
        case.num_signatures,
        case.entry_instruction_index,
        case.msg_offset_override,
    );

    let chal = case.chal.clone().unwrap_or_else(|| r.chal.clone());
    let expected_pk = case.expected_pk.clone().unwrap_or_else(|| r.pk.clone());
    let expected_rp = case
        .expected_rp
        .clone()
        .unwrap_or_else(|| expected_rp_id_hash(&r.origin));
    let our_auth = case.our_auth.clone().unwrap_or_else(|| r.auth.clone());

    let mut data = Vec::new();
    data.extend_from_slice(&expected_pk);
    data.extend_from_slice(&expected_rp);
    data.extend_from_slice(&(r.origin.len() as u16).to_le_bytes());
    data.extend_from_slice(&r.origin);
    data.extend_from_slice(&(chal.len() as u16).to_le_bytes());
    data.extend_from_slice(&chal);
    data.push(case.precompile_ix_index);
    data.extend_from_slice(&(our_auth.len() as u16).to_le_bytes());
    data.extend_from_slice(&our_auth);
    data.extend_from_slice(&r.cdj);
    if let Some(n) = case.truncate_our_data {
        data.truncate(n);
    }

    let ours = Instruction {
        program_id: pid,
        accounts: vec![AccountMeta::new_readonly(sysvar::instructions::ID, false)],
        data,
    };
    let tx = Transaction::new(
        &[&payer],
        Message::new(&[pre, ours], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    (svm, tx, r)
}

/// Assert our program (instruction index 1) rejected with `InvalidArgument` and
/// emitted `log_fragment`.
fn assert_our_program_rejected(
    err: litesvm::types::FailedTransactionMetadata,
    expected: InstructionError,
    log_fragment: &str,
) {
    assert_eq!(
        err.err,
        TransactionError::InstructionError(OUR_IX_INDEX as u8, expected.clone()),
        "unexpected failure mode: {:?} logs={:#?}",
        err.err,
        err.meta.logs
    );
    assert!(
        err.meta.logs.iter().any(|l| l.contains(log_fragment)),
        "expected a log containing {log_fragment:?}, got {:#?}",
        err.meta.logs
    );
    assert!(
        !err.meta.logs.iter().any(|l| l.contains("panicked")),
        "program panicked instead of returning an error: {:#?}",
        err.meta.logs
    );
}

/// `PrecompileError` discriminants as they surface through
/// `InstructionError::Custom`, from `solana-precompile-error` 3.x:
/// 0 `InvalidPublicKey`, 1 `InvalidRecoveryId`, 2 `InvalidSignature`,
/// 3 `InvalidDataOffsets`, 4 `InvalidInstructionDataSize`.
const PRECOMPILE_INVALID_SIGNATURE: u32 = 2;
const PRECOMPILE_INVALID_DATA_OFFSETS: u32 = 3;

/// Assert the PRECOMPILE (instruction index 0) rejected with exactly
/// `Custom(expected_code)`, and that our program never ran at all.
fn assert_precompile_rejected(err: litesvm::types::FailedTransactionMetadata, expected_code: u32) {
    assert_eq!(
        err.err,
        TransactionError::InstructionError(0, InstructionError::Custom(expected_code)),
        "expected instruction 0 to fail with Custom({expected_code}), logs={:#?}",
        err.meta.logs
    );
    assert!(
        !err.meta.logs.iter().any(|l| l.contains("webauthn root assertion bound OK")),
        "our program must not have run: {:#?}",
        err.meta.logs
    );
    assert!(
        err.meta.logs.is_empty(),
        "instruction 1 should never have been reached, so no program logs are expected: {:#?}",
        err.meta.logs
    );
    assert!(
        !err.meta.logs.iter().any(|l| l.contains("panicked")),
        "nothing may panic: {:#?}",
        err.meta.logs
    );
}

// ---------------------------------------------------------------------------
// Evidence about the RP ID (finding 1)
// ---------------------------------------------------------------------------

/// Chrome's effective RP ID for a `chrome-extension://` origin is the FULL
/// ORIGIN STRING, not the bare extension id. Proven here, independently of
/// anything `prep.ts` wrote.
#[test]
fn rp_id_hash_is_sha256_of_the_full_origin() {
    let r = load_raw();
    let origin = String::from_utf8(r.origin.clone()).unwrap();
    let bare_id = origin.strip_prefix("chrome-extension://").unwrap();

    let h_origin = Sha256::digest(origin.as_bytes()).to_vec();
    let h_bare = Sha256::digest(bare_id.as_bytes()).to_vec();

    println!("signed rpIdHash        = {}", hex::encode(&r.rp_from_auth_data));
    println!("SHA256(full origin)    = {}", hex::encode(&h_origin));
    println!("SHA256(bare ext id)    = {}", hex::encode(&h_bare));

    assert_eq!(
        h_origin, r.rp_from_auth_data,
        "signed rpIdHash is not SHA-256 of the full origin string"
    );
    assert_ne!(
        h_bare, r.rp_from_auth_data,
        "SHA-256 of the bare extension id must NOT match — if it does, the finding needs revisiting"
    );
}

/// The hand-built precompile instruction must be byte-identical to the one the
/// official crate builds — this is what licenses the negative tests below to
/// bend individual fields.
#[test]
fn hand_built_precompile_ix_matches_crate() {
    let r = load_raw();
    let crate_ix = solana_secp256r1_program::new_secp256r1_instruction_with_signature(
        &r.msg,
        &r.sig.clone().try_into().unwrap(),
        &r.pk.clone().try_into().unwrap(),
    );
    let ours = build_precompile_ix(&r.pk, &r.sig, &r.msg, 1, u16::MAX, None);
    assert_eq!(crate_ix.program_id, ours.program_id);
    assert_eq!(crate_ix.data, ours.data);
    // documented offsets for the 1-signature case
    assert_eq!(u16::from_le_bytes([ours.data[6], ours.data[7]]), 16, "public_key_offset");
    assert_eq!(u16::from_le_bytes([ours.data[2], ours.data[3]]), 49, "signature_offset");
    assert_eq!(u16::from_le_bytes([ours.data[10], ours.data[11]]), 113, "message_data_offset");
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn binds_real_assertion() {
    let (mut svm, tx, _r) = build(Case::default());
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

// ---------------------------------------------------------------------------
// clientDataJSON / authenticatorData negatives
// ---------------------------------------------------------------------------

#[test]
fn rejects_wrong_challenge() {
    let (mut svm, tx, _r) = build(Case {
        chal: Some(b"AAAA".to_vec()),
        ..Default::default()
    });
    let err = svm.send_transaction(tx).expect_err("wrong challenge must fail");
    assert_our_program_rejected(err, InstructionError::InvalidArgument, "challenge mismatch");
}

#[test]
fn rejects_wrong_rpid_hash() {
    let r = load_raw();
    let mut rp = expected_rp_id_hash(&r.origin);
    rp[0] ^= 0x01;
    let (mut svm, tx, _r) = build(Case {
        expected_rp: Some(rp),
        ..Default::default()
    });
    let err = svm.send_transaction(tx).expect_err("wrong rpIdHash must fail");
    assert_our_program_rejected(err, InstructionError::InvalidArgument, "rpIdHash mismatch");
}

/// Belt-and-braces: SHA-256 of the *bare extension id* — the value a naive
/// implementation of the spec would use — must be rejected outright.
#[test]
fn rejects_rpid_hash_of_bare_extension_id() {
    let r = load_raw();
    let origin = String::from_utf8(r.origin.clone()).unwrap();
    let bare_id = origin.strip_prefix("chrome-extension://").unwrap().to_string();
    let (mut svm, tx, _r) = build(Case {
        expected_rp: Some(Sha256::digest(bare_id.as_bytes()).to_vec()),
        ..Default::default()
    });
    let err = svm.send_transaction(tx).expect_err("SHA256(bare id) must not match");
    assert_our_program_rejected(err, InstructionError::InvalidArgument, "rpIdHash mismatch");
}

// ---------------------------------------------------------------------------
// Binding negatives (finding 3)
// ---------------------------------------------------------------------------

/// The precompile keeps verifying the REAL (authenticatorData, clientDataJSON)
/// pair, but our instruction is handed a different authenticatorData — same
/// rpIdHash and flags (so checks 1 and 2 still pass), different signCount. The
/// program must notice that `auth || SHA256(cdj)` no longer equals the bytes the
/// precompile verified.
#[test]
fn rejects_message_not_bound_to_precompile() {
    let r = load_raw();
    let mut auth = r.auth.clone();
    auth[33] ^= 0xFF; // signCount byte — not inspected by the program, but part of the message
    assert_eq!(&auth[..33], &r.auth[..33], "rpIdHash and flags must be untouched");
    let (mut svm, tx, _r) = build(Case {
        our_auth: Some(auth),
        ..Default::default()
    });
    let err = svm.send_transaction(tx).expect_err("unbound message must fail");
    assert_our_program_rejected(err, InstructionError::InvalidArgument, "message mismatch");
}

/// The precompile verified a valid signature — under a key that is not the one
/// the program was told to expect.
#[test]
fn rejects_wrong_pubkey() {
    let r = load_raw();
    let mut pk = r.pk.clone();
    pk[32] ^= 0x01;
    let (mut svm, tx, _r) = build(Case {
        expected_pk: Some(pk),
        ..Default::default()
    });
    let err = svm.send_transaction(tx).expect_err("wrong pubkey must fail");
    assert_our_program_rejected(err, InstructionError::InvalidArgument, "pubkey mismatch");
}

/// A precompile instruction carrying two signature entries verifies fine, but
/// our program only inspects the first one — so it must refuse the shape
/// outright rather than silently ignore entry #2.
#[test]
fn rejects_multi_signature_precompile_ix() {
    let (mut svm, tx, _r) = build(Case {
        num_signatures: 2,
        ..Default::default()
    });
    let err = svm
        .send_transaction(tx)
        .expect_err("num_signatures != 1 must fail");
    assert_our_program_rejected(
        err,
        InstructionError::InvalidArgument,
        "unexpected precompile instruction shape",
    );
}

/// Offsets that point at ANOTHER instruction (index 0 rather than the
/// "this instruction" sentinel 0xFFFF). The precompile is happy — it is
/// instruction 0, so it reads back its own bytes — but our program must refuse,
/// because otherwise the verified bytes could be made to live somewhere it does
/// not inspect.
#[test]
fn rejects_foreign_instruction_index() {
    let (mut svm, tx, _r) = build(Case {
        entry_instruction_index: 0,
        ..Default::default()
    });
    let err = svm
        .send_transaction(tx)
        .expect_err("non-0xFFFF instruction index must fail");
    assert_our_program_rejected(
        err,
        InstructionError::InvalidArgument,
        "precompile references another instruction",
    );
}

/// Malformed precompile offsets (message offset past the end of the instruction
/// data). The precompile reads the same offsets we do, so it rejects first,
/// with exactly `PrecompileError::InvalidDataOffsets` — nothing panics and our
/// program never runs.
#[test]
fn malformed_precompile_offsets_error_without_panic() {
    let (mut svm, tx, _r) = build(Case {
        msg_offset_override: Some(60_000),
        ..Default::default()
    });
    let err = svm
        .send_transaction(tx)
        .expect_err("out-of-range offsets must fail");
    assert_precompile_rejected(err, PRECOMPILE_INVALID_DATA_OFFSETS);
}

/// Our program's own bounds guards: truncated instruction data must produce a
/// clean `InvalidInstructionData`, never a panic/abort.
#[test]
fn truncated_instruction_data_errors_without_panic() {
    // 33 (pk) + 32 (rp) + 2 = 67 bytes in, mid-way through the origin field.
    for n in [0usize, 10, 33, 65, 67, 80, 120, 200] {
        let (mut svm, tx, _r) = build(Case {
            truncate_our_data: Some(n),
            ..Default::default()
        });
        let err = svm
            .send_transaction(tx)
            .expect_err(&format!("truncated data (n={n}) must fail"));
        assert_eq!(
            err.err,
            TransactionError::InstructionError(OUR_IX_INDEX, InstructionError::InvalidInstructionData),
            "n={n}: unexpected error, logs={:#?}",
            err.meta.logs
        );
        assert!(
            !err.meta.logs.iter().any(|l| l.contains("panicked")),
            "n={n}: program panicked: {:#?}",
            err.meta.logs
        );
    }
}

/// Pointing the program at an instruction index that is not the precompile.
#[test]
fn rejects_non_precompile_instruction_index() {
    let (mut svm, tx, _r) = build(Case {
        precompile_ix_index: 1, // our own instruction
        ..Default::default()
    });
    let err = svm
        .send_transaction(tx)
        .expect_err("pointing at a non-precompile instruction must fail");
    assert_our_program_rejected(
        err,
        InstructionError::InvalidArgument,
        "not the secp256r1 precompile",
    );
}

// ---------------------------------------------------------------------------
// Precompile-level negatives — the controls that prove it really runs
// ---------------------------------------------------------------------------

#[test]
fn precompile_rejects_tampered_signature() {
    let r = load_raw();
    let mut bad = r.sig.clone();
    bad[0] ^= 0x01;
    let (mut svm, tx, _r) = build(Case {
        sig: Some(bad),
        ..Default::default()
    });
    let err = svm
        .send_transaction(tx)
        .expect_err("tampered signature must fail");
    assert_precompile_rejected(err, PRECOMPILE_INVALID_SIGNATURE);
}

/// This authenticator emitted a high-S signature; the precompile must reject it
/// un-normalized (SEC1 malleability guard).
#[test]
fn precompile_rejects_high_s_signature() {
    let r = load_raw();
    if !r.low_s_normalization_needed {
        eprintln!("SKIP: this sample was already low-S, nothing to prove");
        return;
    }
    let (mut svm, tx, _r) = build(Case {
        sig: Some(r.sig_as_signed.clone()),
        ..Default::default()
    });
    let err = svm
        .send_transaction(tx)
        .expect_err("high-S signature must be rejected by the precompile");
    assert_precompile_rejected(err, PRECOMPILE_INVALID_SIGNATURE);
}
