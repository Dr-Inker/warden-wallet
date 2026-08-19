//! **L0 — harness fidelity** (spec §17). The test substrate must actually
//! enforce the cryptography.
//!
//! Every other negative in this repo uses an *honestly produced* signature and
//! bends something else (the challenge, the origin, the precompile offsets,
//! the account state). Not one of them would notice if the secp256r1
//! precompile stopped verifying signatures — `litesvm`'s `precompiles` feature
//! is not a default, `LiteSVM::default()` starts with every runtime feature
//! off, and a dependency bump that dropped either would leave
//! `root_verify::precompile::bind_precompile` — which checks *binding*, never
//! the curve — as the only gate on the root of trust.
//!
//! So this file asserts **both directions against the same transaction shape**,
//! and only the pair proves anything:
//!
//! - a valid signature ⇒ the transaction **succeeds** and `root_nonce` is
//!   consumed (rules out "the precompile rejects everything", which would make
//!   the negative below pass for the wrong reason);
//! - a **forged** signature ⇒ **exactly `InstructionError(0, Custom(2))`**
//!   (`PrecompileError::InvalidSignature`), i.e. the failure comes from the
//!   *runtime, at the precompile instruction*, and warden's own instruction at
//!   index 1 never runs at all.
//!
//! Note what is deliberately NOT here: "an honest signature over a different
//! message". That is a **binding** test — it proves `bind_precompile` compares
//! the message — and it lives in `root_verify.rs`
//! (`message_mismatch_rejected`). It would pass with the precompile disabled,
//! so it can never stand in for the forged-signature gate.
//!
//! Complementary, never a substitute: `.claude/test-gate.sh` asserts
//! `cargo tree -e features -p warden` still resolves `litesvm feature
//! "precompiles"`. That is feature-RESOLUTION evidence; this file is the
//! runtime evidence.

mod common;

use anchor_lang::AnchorSerialize;
use common::passkey::{self, TestPasskey, FLAGS_UP_UV};
use common::{create_smart_account, current_slot, read_smart_account, SmartAccountFixture};
use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_sdk::{
    clock::Clock,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::Message,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    sysvar,
    transaction::{Transaction, TransactionError},
};
use warden::root_verify::transcript::{action_hash, b64url_no_pad, transcript_hash, OP_ROTATE_NONCE};
use warden::root_verify::RootArgs;

const NOW: i64 = 1_760_000_000;
const NOW_SLOT: u64 = 350_000_000;

/// `PrecompileError::InvalidSignature` is the **third** variant of
/// `solana_precompile_error::PrecompileError`
/// (`InvalidPublicKey`, `InvalidRecoveryId`, `InvalidSignature`,
/// `InvalidDataOffsets`, `InvalidInstructionDataSize`), and the runtime surfaces
/// a precompile failure as `InstructionError::Custom(index)`. Pinned as a
/// literal, deliberately: deriving it from the enum would make this assertion
/// re-derive the very thing under test, and the numeric value is what a client
/// actually sees on-chain.
const PRECOMPILE_INVALID_SIGNATURE: u32 = 2;

fn rotate_nonce_ix(smart_account: Pubkey, args: &RootArgs) -> Instruction {
    let mut data = Sha256::digest(b"global:rotate_nonce")[..8].to_vec();
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

struct Built {
    svm: LiteSVM,
    tx: Transaction,
    account: Pubkey,
}

/// One complete, honest `rotate_nonce` ceremony — then `bend` gets the last
/// word on the 64 signature bytes handed to the precompile.
///
/// Everything except those 64 bytes is identical across all four tests below:
/// same key, same account, same `authenticatorData`, same `clientDataJSON`,
/// same transcript, same precompile instruction layout, same account order. So
/// the ONLY variable is whether the signature is a real ECDSA signature over
/// the message, which is exactly what this file is trying to isolate.
fn build(bend: impl FnOnce(&mut [u8; 64])) -> Built {
    let (mut svm, payer) = common::setup();
    let mut c: Clock = svm.get_sysvar();
    c.unix_timestamp = NOW;
    c.slot = NOW_SLOT;
    svm.set_sysvar(&c);

    let pk = TestPasskey::new(3);
    let mut fixture = SmartAccountFixture::default();
    fixture.root_pubkey33 = pk.pubkey33();
    let account = create_smart_account(&mut svm, &payer, &fixture);

    let expiry_ts = NOW + 60;
    let signed_slot = current_slot(&svm);
    let challenge = b64url_no_pad(&transcript_hash(
        &fixture.cluster_tag,
        &common::program_id(),
        &account,
        fixture.generation,
        fixture.policy_version,
        fixture.root_nonce,
        expiry_ts,
        signed_slot,
        &action_hash(OP_ROTATE_NONCE, &[]),
    ));
    let assertion = pk.assert_with_client_data(
        passkey::client_data_json(&challenge, &fixture.origin),
        passkey::rp_id_hash(&fixture.origin),
        FLAGS_UP_UV,
    );

    let mut signature = assertion.signature64_low_s;
    bend(&mut signature);

    // Hand-built rather than via the official crate's builder, because the
    // builder takes the signature as an argument anyway and the hand-built
    // encoding is pinned byte-for-byte against it by
    // `root_verify::hand_built_precompile_ix_matches_crate`. The offsets,
    // instruction indices and payload are therefore known-good and only the
    // signature bytes differ.
    let precompile = passkey::precompile_ix_custom(
        &pk.pubkey33(),
        &signature,
        &assertion.message,
        1,
        u16::MAX,
    );

    let args = RootArgs {
        precompile_ix_index: 0,
        authenticator_data: assertion.authenticator_data.clone(),
        client_data_json: assertion.client_data_json.clone(),
        expiry_ts,
        signed_slot,
    };
    let tx = Transaction::new(
        &[&payer],
        Message::new(
            &[precompile, rotate_nonce_ix(account, &args)],
            Some(&payer.pubkey()),
        ),
        svm.latest_blockhash(),
    );
    Built { svm, tx, account }
}

fn expect_precompile_rejection(mut b: Built, what: &str) {
    let before = read_smart_account(&b.svm, &b.account).root_nonce;
    let err = b
        .svm
        .send_transaction(b.tx)
        .expect_err("a signature the runtime cannot verify must be rejected");
    assert_eq!(
        err.err,
        TransactionError::InstructionError(0, InstructionError::Custom(PRECOMPILE_INVALID_SIGNATURE)),
        "{what}: expected the RUNTIME to reject the precompile instruction at index 0 with \
         PrecompileError::InvalidSignature. Any other failure — and in particular one at \
         instruction index 1 — means warden's own instruction ran, i.e. the precompile is not \
         verifying signatures. logs={:#?}",
        err.meta.logs
    );
    assert_eq!(
        read_smart_account(&b.svm, &b.account).root_nonce,
        before,
        "{what}: the ceremony must not be consumed"
    );
}

// ---------------------------------------------------------------------------
// Direction 1 — a valid signature must SUCCEED
// ---------------------------------------------------------------------------

/// Without this, every negative below would also pass against a substrate that
/// rejected *all* precompile instructions unconditionally.
#[test]
fn valid_signature_transaction_succeeds() {
    let mut b = build(|_sig| {});
    let before = read_smart_account(&b.svm, &b.account).root_nonce;
    let res = b
        .svm
        .send_transaction(b.tx)
        .expect("an honestly signed ceremony must be accepted by the precompile");
    assert!(
        !res.logs.iter().any(|l| l.contains("panicked")),
        "logs={:#?}",
        res.logs
    );
    assert_eq!(
        read_smart_account(&b.svm, &b.account).root_nonce,
        before + 1,
        "the ceremony must be consumed on success"
    );
}

// ---------------------------------------------------------------------------
// Direction 2 — a forged signature must be rejected BY THE PRECOMPILE
// ---------------------------------------------------------------------------

/// 64 bytes that are not a signature at all. The pattern is fixed rather than
/// random so a failure is reproducible; it is well-formed as a scalar pair
/// (both halves are below the group order) so the precompile has to actually
/// do the curve arithmetic to reject it, rather than bailing out on an
/// encoding check.
#[test]
fn forged_signature_rejected_by_precompile() {
    expect_precompile_rejection(
        build(|sig| {
            for (i, b) in sig.iter_mut().enumerate() {
                // 0x01,0x02,… in both halves: comfortably non-zero and far
                // below n, so neither half is rejected as out-of-range.
                *b = (i % 32) as u8 + 1;
            }
        }),
        "a 64-byte pattern that is not a signature",
    );
}

/// The subtler forgery: a genuine signature with **one bit** flipped. Nothing
/// about its shape is wrong — it is the right length, both scalars are in
/// range, and it was produced by the real key over the real message — so only
/// an actual ECDSA verification can tell it apart from the accepted one in
/// `valid_signature_transaction_succeeds`.
#[test]
fn flipped_bit_signature_rejected_by_precompile() {
    expect_precompile_rejection(
        build(|sig| {
            // Flip the lowest bit of `s`. `s` is low-S and far from the
            // boundary, so `s ^ 1` is still low-S and still in range: the
            // rejection cannot come from the malleability check.
            sig[63] ^= 1;
        }),
        "a valid signature with one bit flipped",
    );
}

/// High-S: `(r, s)` → `(r, n - s)`, still a mathematically valid ECDSA
/// signature for the same key and message, rejected by the precompile anyway.
///
/// This is the case Chrome produced on the very first real sample in spike 2b,
/// which is why low-S normalization is the extension's job in production (spec
/// §4) and why the harness's `TestPasskey::sign` normalizes. Pinning the
/// rejection here means a substrate that quietly stopped enforcing
/// malleability would fail the gate rather than make the extension's
/// normalization look optional.
#[test]
fn high_s_signature_rejected_by_precompile() {
    expect_precompile_rejection(
        build(|sig| *sig = passkey::to_high_s(sig)),
        "the high-S form of a valid signature",
    );
}

/// The harness's own claim about `to_high_s` — that it changes only `s`, and
/// changes it to `n - s` — checked without involving the SVM at all, so a
/// broken helper cannot make `high_s_signature_rejected_by_precompile` pass
/// for the wrong reason (e.g. by producing an out-of-range scalar the
/// precompile rejects on an encoding check instead).
#[test]
fn to_high_s_only_negates_s() {
    let pk = TestPasskey::new(3);
    let low = pk.sign(b"a message");
    let high = passkey::to_high_s(&low);
    assert_eq!(low[..32], high[..32], "r must be untouched");
    assert_ne!(low[32..], high[32..], "s must change");
    assert!(!passkey::is_high_s(&low), "TestPasskey::sign must normalize to low-S");
    assert!(passkey::is_high_s(&high), "to_high_s must produce the high-S form");
    assert_eq!(passkey::to_high_s(&high), low, "negating twice is the identity");
}

/// Sanity on the ONE thing the two directions share and must not silently
/// diverge on: the account is a real, freshly created one whose stored root
/// key is the key the precompile is handed. If these ever came apart, the
/// positive direction would fail for a reason that has nothing to do with the
/// signature.
#[test]
fn positive_and_negative_share_the_same_account_and_key() {
    let a = build(|_| {});
    let b = build(|sig| sig[63] ^= 1);
    assert_eq!(a.account, b.account);
    assert_eq!(
        read_smart_account(&a.svm, &a.account).root_pubkey,
        read_smart_account(&b.svm, &b.account).root_pubkey
    );
}

/// Keeps this file honest about which keypair the ceremony belongs to: the
/// payer signs the transaction, but nothing about the payer authorizes the
/// root action — only the precompile-verified P-256 assertion does.
#[test]
fn payer_signature_alone_does_not_authorize_the_root_action() {
    let mut b = build(|sig| sig[63] ^= 1);
    // A brand-new payer with plenty of lamports changes nothing: the rejection
    // is at instruction 0, before warden runs.
    let interloper = Keypair::new();
    b.svm.airdrop(&interloper.pubkey(), 10_000_000_000).unwrap();
    expect_precompile_rejection(b, "a well-funded payer over a forged assertion");
}
