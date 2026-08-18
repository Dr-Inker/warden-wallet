//! End-to-end LiteSVM coverage of the root passkey path.
//!
//! Transaction shape (the one the extension will build):
//! ```text
//!   ix[0] = Secp256r1SigVerify precompile over (pubkey33, sig64, message)
//!   ix[1] = warden::rotate_nonce, with the Instructions sysvar as account 1
//! ```
//! Every negative case here is a *real signed assertion* — the passkey signs
//! whatever hostile `clientDataJSON` the case asks for — so the tests exercise
//! the program's checks rather than the signer's cooperation.

mod common;

use anchor_lang::{AnchorSerialize, Discriminator};
use common::passkey::{self, TestPasskey, FLAGS_UP_UV, TEST_ORIGIN};
use common::{read_smart_account, set_smart_account, SmartAccountFixture};
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
use warden::errors::WardenError;
use warden::root_verify::transcript::{action_hash, b64url_no_pad, transcript_hash, OP_ROTATE_NONCE};
use warden::root_verify::RootArgs;
use warden::state::SmartAccount;

const NOW: i64 = 1_760_000_000;

fn code(e: WardenError) -> u32 {
    u32::from(e)
}

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

fn set_clock(svm: &mut LiteSVM, unix_timestamp: i64) {
    let mut c: Clock = svm.get_sysvar();
    c.unix_timestamp = unix_timestamp;
    svm.set_sysvar(&c);
}

/// The challenge the passkey must sign for `rotate_nonce` against a given
/// account state. Computed with the program's own transcript function — the
/// pinned unit vectors in `transcript.rs` are what stop that from being
/// circular.
#[allow(clippy::too_many_arguments)]
fn rotate_nonce_challenge(
    cluster_tag: &[u8; 32],
    account: &Pubkey,
    generation: u64,
    policy_version: u32,
    root_nonce: u64,
    expiry_ts: i64,
) -> Vec<u8> {
    let t = transcript_hash(
        cluster_tag,
        &common::program_id(),
        account,
        generation,
        policy_version,
        root_nonce,
        expiry_ts,
        &action_hash(OP_ROTATE_NONCE, &[]),
    );
    b64url_no_pad(&t)
}

/// Everything a negative test may bend. `Default` is the honest path.
struct Case {
    fixture: SmartAccountFixture,
    /// Authenticator flags actually signed.
    flags: u8,
    /// Origin written into `clientDataJSON` (the account keeps its own).
    signed_origin: String,
    /// Replace the whole `clientDataJSON` (challenge substituted for `{CHAL}`).
    client_data_template: Option<String>,
    /// `clientDataJSON` handed to OUR instruction, when it must differ from
    /// the signed one.
    our_client_data: Option<Vec<u8>>,
    /// rpIdHash actually signed (defaults to SHA-256 of `signed_origin`).
    signed_rp_id_hash: Option<[u8; 32]>,
    expiry_ts: i64,
    /// Transcript inputs the signer *believes*; bending one breaks the binding.
    challenge_nonce: Option<u64>,
    challenge_generation: Option<u64>,
    challenge_cluster_tag: Option<[u8; 32]>,
    precompile_ix_index: Option<u8>,
    num_signatures: u8,
    entry_instruction_index: u16,
    /// Build the precompile by hand instead of via the official crate.
    hand_built_precompile: bool,
    /// Put a decoy secp256r1 instruction (different key) at index 0.
    decoy_precompile_first: bool,
    /// Put an unrelated (non-precompile) instruction at index 0.
    filler_ix_first: bool,
    /// Put our instruction FIRST and the precompile after it.
    precompile_after_ours: bool,
    /// Plant the account at a non-PDA address.
    account_at_wrong_address: bool,
    now: i64,
}

impl Default for Case {
    fn default() -> Self {
        Self {
            fixture: SmartAccountFixture::default(),
            flags: FLAGS_UP_UV,
            signed_origin: TEST_ORIGIN.to_string(),
            client_data_template: None,
            our_client_data: None,
            signed_rp_id_hash: None,
            expiry_ts: NOW + 60,
            challenge_nonce: None,
            challenge_generation: None,
            challenge_cluster_tag: None,
            precompile_ix_index: None,
            num_signatures: 1,
            entry_instruction_index: u16::MAX,
            hand_built_precompile: false,
            decoy_precompile_first: false,
            filler_ix_first: false,
            precompile_after_ours: false,
            account_at_wrong_address: false,
            now: NOW,
        }
    }
}

struct Built {
    svm: LiteSVM,
    tx: Transaction,
    account: Pubkey,
    /// Index of OUR instruction in the transaction.
    our_ix_index: u8,
}

fn build(case: Case) -> Built {
    let (mut svm, payer) = common::setup();
    set_clock(&mut svm, case.now);

    let pk = TestPasskey::new(3);
    let mut fixture = case.fixture;
    fixture.root_pubkey33 = pk.pubkey33();
    let account = if case.account_at_wrong_address {
        // Plant a byte-identical account body at an address that is NOT the
        // PDA for its own `owner_seed`.
        let pda = set_smart_account(&mut svm, &fixture);
        let raw = svm.get_account(&pda).unwrap();
        let imposter = Keypair::new().pubkey();
        svm.set_account(
            imposter,
            Account {
                lamports: raw.lamports,
                data: raw.data.clone(),
                owner: raw.owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        imposter
    } else {
        set_smart_account(&mut svm, &fixture)
    };

    let challenge = rotate_nonce_challenge(
        &case.challenge_cluster_tag.unwrap_or(fixture.cluster_tag),
        &account,
        case.challenge_generation.unwrap_or(fixture.generation),
        fixture.policy_version,
        case.challenge_nonce.unwrap_or(fixture.root_nonce),
        case.expiry_ts,
    );

    let cdj = match &case.client_data_template {
        Some(t) => t
            .replace("{CHAL}", std::str::from_utf8(&challenge).unwrap())
            .into_bytes(),
        None => passkey::client_data_json(&challenge, &case.signed_origin),
    };
    let rp = case
        .signed_rp_id_hash
        .unwrap_or_else(|| passkey::rp_id_hash(&case.signed_origin));
    let assertion = pk.assert_with_client_data(cdj, rp, case.flags);

    let real_precompile = if case.hand_built_precompile {
        passkey::precompile_ix_custom(
            &pk.pubkey33(),
            &assertion.signature64_low_s,
            &assertion.message,
            case.num_signatures,
            case.entry_instruction_index,
        )
    } else {
        passkey::precompile_ix(&assertion, &pk.pubkey33())
    };

    let args = RootArgs {
        precompile_ix_index: 0,
        authenticator_data: assertion.authenticator_data.clone(),
        client_data_json: case
            .our_client_data
            .clone()
            .unwrap_or_else(|| assertion.client_data_json.clone()),
        expiry_ts: case.expiry_ts,
    };

    let (ixs, our_ix_index, default_precompile_index) = if case.precompile_after_ours {
        let ours = rotate_nonce_ix(account, &args);
        (vec![ours, real_precompile], 0u8, 1u8)
    } else if case.filler_ix_first {
        // A 0-lamport self-transfer, hand-encoded to avoid pulling a second
        // copy of the instruction types in: system program id is the all-zero
        // pubkey, and `SystemInstruction::Transfer` is variant 2 + u64 LE.
        let mut filler_data = 2u32.to_le_bytes().to_vec();
        filler_data.extend_from_slice(&0u64.to_le_bytes());
        let filler = Instruction {
            program_id: Pubkey::default(),
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(payer.pubkey(), false),
            ],
            data: filler_data,
        };
        (vec![filler, real_precompile, rotate_nonce_ix(account, &args)], 2u8, 1u8)
    } else if case.decoy_precompile_first {
        // A second, fully valid secp256r1 instruction over a DIFFERENT key.
        let decoy_key = TestPasskey::new(9);
        let decoy = passkey::precompile_ix(
            &decoy_key.assert_with_client_data(b"{}".to_vec(), [0u8; 32], FLAGS_UP_UV),
            &decoy_key.pubkey33(),
        );
        (vec![decoy, real_precompile, rotate_nonce_ix(account, &args)], 2u8, 1u8)
    } else {
        (vec![real_precompile, rotate_nonce_ix(account, &args)], 1u8, 0u8)
    };

    // Re-encode our instruction now that the precompile index is known.
    let final_args = RootArgs {
        precompile_ix_index: case.precompile_ix_index.unwrap_or(default_precompile_index),
        ..args
    };
    let mut ixs = ixs;
    ixs[our_ix_index as usize] = rotate_nonce_ix(account, &final_args);

    let tx = Transaction::new(
        &[&payer],
        Message::new(&ixs, Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    Built {
        svm,
        tx,
        account,
        our_ix_index,
    }
}

fn expect_reject(case: Case, expected: WardenError) {
    let mut b = build(case);
    let ix_index = b.our_ix_index;
    let before = read_smart_account(&b.svm, &b.account).root_nonce;
    let err = b.svm.send_transaction(b.tx).expect_err("must be rejected");
    assert_eq!(
        err.err,
        TransactionError::InstructionError(ix_index, InstructionError::Custom(code(expected))),
        "wrong failure mode; logs={:#?}",
        err.meta.logs
    );
    assert!(
        !err.meta.logs.iter().any(|l| l.contains("panicked")),
        "program panicked instead of returning an error: {:#?}",
        err.meta.logs
    );
    assert_eq!(
        read_smart_account(&b.svm, &b.account).root_nonce,
        before,
        "a rejected assertion must not consume the nonce"
    );
}

// ---------------------------------------------------------------------------
// Pinned facts the rest of the suite rests on
// ---------------------------------------------------------------------------

/// The hand-built account bytes in `common::set_smart_account` are only valid
/// if Anchor's discriminator really is SHA-256("account:<Name>")[..8].
#[test]
fn anchor_discriminator_is_sha256_of_account_name() {
    assert_eq!(
        SmartAccount::DISCRIMINATOR,
        &Sha256::digest(b"account:SmartAccount")[..8]
    );
}

/// The program hard-codes the precompile id as a literal; prove it is the id
/// the official crate uses.
#[test]
fn secp256r1_id_matches_the_crate() {
    assert_eq!(
        warden::root_verify::precompile::SECP256R1_ID,
        solana_secp256r1_program::ID
    );
}

/// The hand-built precompile instruction must be byte-identical to the
/// official crate's for the honest case — that is what licenses the negative
/// tests to bend individual fields of it.
#[test]
fn hand_built_precompile_ix_matches_crate() {
    let pk = TestPasskey::new(3);
    let a = pk.assert_(b"AAAA", TEST_ORIGIN, passkey::rp_id_hash(TEST_ORIGIN), FLAGS_UP_UV);
    let crate_ix = passkey::precompile_ix(&a, &pk.pubkey33());
    let ours = passkey::precompile_ix_custom(
        &pk.pubkey33(),
        &a.signature64_low_s,
        &a.message,
        1,
        u16::MAX,
    );
    assert_eq!(crate_ix.program_id, ours.program_id);
    assert_eq!(crate_ix.data, ours.data);
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn rotate_nonce_ok_and_nonce_increments() {
    let mut b = build(Case::default());
    let tx_bytes = bincode::serialize(&b.tx).unwrap().len();
    let before = read_smart_account(&b.svm, &b.account);
    let res = b.svm.send_transaction(b.tx).expect("honest assertion must succeed");
    println!("root_verify CU: {}", res.compute_units_consumed);
    println!("serialized tx: {tx_bytes} B");
    let after = read_smart_account(&b.svm, &b.account);
    assert_eq!(after.root_nonce, before.root_nonce + 1, "nonce must be consumed");
    assert_eq!(after.generation, before.generation, "nothing else may change");
    assert!(
        res.compute_units_consumed < 100_000,
        "CU budget blown: {}",
        res.compute_units_consumed
    );
}

/// Two ceremonies in a row against the same account, each over the nonce the
/// previous one left behind.
#[test]
fn consecutive_ceremonies_each_consume_one_nonce() {
    for start in [0u64, 1] {
        let mut b = build(Case {
            fixture: SmartAccountFixture {
                root_nonce: start,
                ..Default::default()
            },
            challenge_nonce: Some(start),
            ..Default::default()
        });
        b.svm.send_transaction(b.tx).expect("must succeed");
        assert_eq!(read_smart_account(&b.svm, &b.account).root_nonce, start + 1);
    }
}

// ---------------------------------------------------------------------------
// Replay / freshness
// ---------------------------------------------------------------------------

/// Re-submitting the very same transaction data against the account it already
/// advanced. The nonce is inside the signed challenge, so the second attempt
/// is reported as a replay of a consumed ceremony, not a bare mismatch.
#[test]
fn replay_same_assertion_rejected() {
    expect_reject(
        Case {
            fixture: SmartAccountFixture {
                root_nonce: 5,
                ..Default::default()
            },
            // Assertion signed for nonce 4; the account has already moved to 5.
            challenge_nonce: Some(4),
            ..Default::default()
        },
        WardenError::NonceMismatch,
    );
}

/// A challenge over a nonce that is neither current nor the previous one is
/// simply wrong, not a replay.
#[test]
fn stale_nonce_far_in_the_past_rejected_as_challenge_mismatch() {
    expect_reject(
        Case {
            fixture: SmartAccountFixture {
                root_nonce: 5,
                ..Default::default()
            },
            challenge_nonce: Some(0),
            ..Default::default()
        },
        WardenError::ChallengeMismatch,
    );
}

#[test]
fn expired_rejected() {
    expect_reject(
        Case {
            expiry_ts: NOW - 1,
            ..Default::default()
        },
        WardenError::Expired,
    );
}

#[test]
fn future_expiry_beyond_600s_rejected() {
    expect_reject(
        Case {
            expiry_ts: NOW + 601,
            ..Default::default()
        },
        WardenError::Expired,
    );
}

#[test]
fn expiry_exactly_at_the_600s_boundary_accepted() {
    let mut b = build(Case {
        expiry_ts: NOW + 600,
        ..Default::default()
    });
    b.svm.send_transaction(b.tx).expect("600s must still be inside the window");
}

// ---------------------------------------------------------------------------
// Transcript binding
// ---------------------------------------------------------------------------

#[test]
fn wrong_cluster_tag_rejected() {
    expect_reject(
        Case {
            challenge_cluster_tag: Some([0xEEu8; 32]),
            ..Default::default()
        },
        WardenError::ChallengeMismatch,
    );
}

#[test]
fn stale_generation_rejected() {
    expect_reject(
        Case {
            fixture: SmartAccountFixture {
                generation: 4,
                ..Default::default()
            },
            challenge_generation: Some(3),
            ..Default::default()
        },
        WardenError::ChallengeMismatch,
    );
}

// ---------------------------------------------------------------------------
// authenticatorData
// ---------------------------------------------------------------------------

#[test]
fn wrong_rp_id_hash_rejected() {
    let mut wrong = passkey::rp_id_hash(TEST_ORIGIN);
    wrong[0] ^= 0x01;
    expect_reject(
        Case {
            signed_rp_id_hash: Some(wrong),
            ..Default::default()
        },
        WardenError::RpIdHashMismatch,
    );
}

/// SHA-256 of the *bare extension id* — the naive reading of the WebAuthn
/// spec — must be rejected (spike 2b finding 1).
#[test]
fn rp_id_hash_of_bare_extension_id_rejected() {
    let bare = TEST_ORIGIN.strip_prefix("chrome-extension://").unwrap();
    expect_reject(
        Case {
            signed_rp_id_hash: Some(Sha256::digest(bare.as_bytes()).into()),
            ..Default::default()
        },
        WardenError::RpIdHashMismatch,
    );
}

#[test]
fn up_only_rejected() {
    expect_reject(
        Case {
            flags: 0x01,
            ..Default::default()
        },
        WardenError::UserVerificationRequired,
    );
}

// ---------------------------------------------------------------------------
// clientDataJSON — the strict scanner, exercised through a real signature
// ---------------------------------------------------------------------------

#[test]
fn wrong_origin_rejected() {
    expect_reject(
        Case {
            fixture: SmartAccountFixture {
                origin: "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                ..Default::default()
            },
            // Signed for a different origin, with a matching rpIdHash, so only
            // the clientDataJSON origin check can catch it.
            signed_origin: TEST_ORIGIN.to_string(),
            signed_rp_id_hash: Some(passkey::rp_id_hash(
                "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )),
            ..Default::default()
        },
        WardenError::OriginMismatch,
    );
}

/// THE SPIKE HOLE, closed on-chain: the top-level origin is the attacker's and
/// ours appears only inside a nested object. The old substring matcher
/// accepted this.
#[test]
fn nested_origin_rejected_on_chain() {
    expect_reject(
        Case {
            client_data_template: Some(format!(
                r#"{{"type":"webauthn.get","challenge":"{{CHAL}}","origin":"https://evil.example","x":{{"origin":"{TEST_ORIGIN}"}}}}"#
            )),
            ..Default::default()
        },
        WardenError::OriginMismatch,
    );
}

#[test]
fn duplicate_origin_rejected_on_chain() {
    expect_reject(
        Case {
            client_data_template: Some(format!(
                r#"{{"type":"webauthn.get","challenge":"{{CHAL}}","origin":"https://evil.example","origin":"{TEST_ORIGIN}"}}"#
            )),
            ..Default::default()
        },
        WardenError::ClientDataDuplicateKey,
    );
}

#[test]
fn cross_origin_true_rejected_on_chain() {
    expect_reject(
        Case {
            client_data_template: Some(format!(
                r#"{{"type":"webauthn.get","challenge":"{{CHAL}}","origin":"{TEST_ORIGIN}","crossOrigin":true}}"#
            )),
            ..Default::default()
        },
        WardenError::CrossOriginNotAllowed,
    );
}

#[test]
fn webauthn_create_type_rejected_on_chain() {
    expect_reject(
        Case {
            client_data_template: Some(format!(
                r#"{{"type":"webauthn.create","challenge":"{{CHAL}}","origin":"{TEST_ORIGIN}"}}"#
            )),
            ..Default::default()
        },
        WardenError::ClientDataTypeMismatch,
    );
}

#[test]
fn oversized_client_data_rejected_on_chain() {
    let pad = "x".repeat(512);
    expect_reject(
        Case {
            client_data_template: Some(format!(
                r#"{{"type":"webauthn.get","challenge":"{{CHAL}}","origin":"{TEST_ORIGIN}","pad":"{pad}"}}"#
            )),
            ..Default::default()
        },
        WardenError::ClientDataTooLong,
    );
}

/// A legitimately escaped origin must still work — the substring matcher
/// falsely rejected this and would have locked users out.
#[test]
fn escaped_origin_accepted_on_chain() {
    let escaped = TEST_ORIGIN.replace('/', r"\/");
    let mut b = build(Case {
        client_data_template: Some(format!(
            r#"{{"type":"webauthn.get","challenge":"{{CHAL}}","origin":"{escaped}","crossOrigin":false}}"#
        )),
        ..Default::default()
    });
    b.svm
        .send_transaction(b.tx)
        .expect("an escaped-but-equal origin must be accepted");
}

// ---------------------------------------------------------------------------
// Precompile binding
// ---------------------------------------------------------------------------

/// The account's stored root key is not the key the precompile verified.
#[test]
fn wrong_pubkey_rejected() {
    let other = TestPasskey::new(11);
    let mut fixture = SmartAccountFixture::default();
    // `build` overwrites `root_pubkey33`, so plant the mismatch by making the
    // account's stored key belong to a different passkey afterwards.
    fixture.owner_seed = [8u8; 32];
    let (mut svm, payer) = common::setup();
    set_clock(&mut svm, NOW);
    fixture.root_pubkey33 = other.pubkey33();
    let account = set_smart_account(&mut svm, &fixture);

    let signer = TestPasskey::new(3);
    let challenge = rotate_nonce_challenge(
        &fixture.cluster_tag,
        &account,
        fixture.generation,
        fixture.policy_version,
        fixture.root_nonce,
        NOW + 60,
    );
    let a = signer.assert_(
        &challenge,
        TEST_ORIGIN,
        passkey::rp_id_hash(TEST_ORIGIN),
        FLAGS_UP_UV,
    );
    let args = RootArgs {
        precompile_ix_index: 0,
        authenticator_data: a.authenticator_data.clone(),
        client_data_json: a.client_data_json.clone(),
        expiry_ts: NOW + 60,
    };
    let tx = Transaction::new(
        &[&payer],
        Message::new(
            &[
                passkey::precompile_ix(&a, &signer.pubkey33()),
                rotate_nonce_ix(account, &args),
            ],
            Some(&payer.pubkey()),
        ),
        svm.latest_blockhash(),
    );
    let err = svm.send_transaction(tx).expect_err("must be rejected");
    assert_eq!(
        err.err,
        TransactionError::InstructionError(
            1,
            InstructionError::Custom(code(WardenError::PrecompileBindingMismatch))
        ),
        "logs={:#?}",
        err.meta.logs
    );
}

/// Two signature entries in one precompile instruction would leave a second,
/// unexamined (key, message) pair verified inside our "proof".
#[test]
fn two_signature_precompile_rejected() {
    expect_reject(
        Case {
            hand_built_precompile: true,
            num_signatures: 2,
            ..Default::default()
        },
        WardenError::BadInstructionLayout,
    );
}

/// `*_instruction_index != 0xFFFF` means the precompile verified data living
/// in a different instruction — one we never inspect.
#[test]
fn foreign_ix_index_rejected() {
    expect_reject(
        Case {
            hand_built_precompile: true,
            entry_instruction_index: 0,
            ..Default::default()
        },
        WardenError::PrecompileBindingMismatch,
    );
}

/// The `clientDataJSON` in our instruction differs from the signed one (an
/// extra, semantically irrelevant key), so every clientData check passes but
/// the SHA-256 in the precompile message does not match.
#[test]
fn message_mismatch_rejected() {
    let (mut svm, payer) = common::setup();
    set_clock(&mut svm, NOW);
    let pk = TestPasskey::new(3);
    let mut fixture = SmartAccountFixture::default();
    fixture.root_pubkey33 = pk.pubkey33();
    let account = set_smart_account(&mut svm, &fixture);
    let challenge = rotate_nonce_challenge(
        &fixture.cluster_tag,
        &account,
        fixture.generation,
        fixture.policy_version,
        fixture.root_nonce,
        NOW + 60,
    );
    let signed = passkey::client_data_json(&challenge, TEST_ORIGIN);
    let a = pk.assert_with_client_data(signed, passkey::rp_id_hash(TEST_ORIGIN), FLAGS_UP_UV);
    let mut swapped = String::from_utf8(a.client_data_json.clone()).unwrap();
    swapped = swapped.replace("}", r#","extra":1}"#);
    let args = RootArgs {
        precompile_ix_index: 0,
        authenticator_data: a.authenticator_data.clone(),
        client_data_json: swapped.into_bytes(),
        expiry_ts: NOW + 60,
    };
    let tx = Transaction::new(
        &[&payer],
        Message::new(
            &[
                passkey::precompile_ix(&a, &pk.pubkey33()),
                rotate_nonce_ix(account, &args),
            ],
            Some(&payer.pubkey()),
        ),
        svm.latest_blockhash(),
    );
    let err = svm.send_transaction(tx).expect_err("must be rejected");
    assert_eq!(
        err.err,
        TransactionError::InstructionError(
            1,
            InstructionError::Custom(code(WardenError::PrecompileBindingMismatch))
        ),
        "logs={:#?}",
        err.meta.logs
    );
    assert_eq!(read_smart_account(&svm, &account).root_nonce, 0);
}

/// Naming an instruction that is not a secp256r1 precompile.
#[test]
fn foreign_program_at_named_index_rejected() {
    expect_reject(
        Case {
            filler_ix_first: true,
            // Index 0 is a system-program transfer, not a precompile.
            precompile_ix_index: Some(0),
            ..Default::default()
        },
        WardenError::PrecompileNotFound,
    );
}

#[test]
fn precompile_ix_index_out_of_range_rejected() {
    expect_reject(
        Case {
            precompile_ix_index: Some(9),
            ..Default::default()
        },
        WardenError::PrecompileNotFound,
    );
}

/// The named precompile must come strictly before us, so it has already been
/// verified by the runtime when we read it.
#[test]
fn precompile_after_our_ix_rejected() {
    expect_reject(
        Case {
            precompile_after_ours: true,
            ..Default::default()
        },
        WardenError::PrecompileNotFound,
    );
}

/// With two valid secp256r1 instructions in the transaction, only the one we
/// name binds: naming the real one succeeds, naming the decoy (a different
/// key over different bytes) is rejected.
#[test]
fn two_precompile_ixs_only_named_one_binds() {
    let mut b = build(Case {
        decoy_precompile_first: true,
        precompile_ix_index: Some(1),
        ..Default::default()
    });
    b.svm
        .send_transaction(b.tx)
        .expect("naming the real precompile must succeed");

    expect_reject(
        Case {
            decoy_precompile_first: true,
            precompile_ix_index: Some(0),
            ..Default::default()
        },
        WardenError::PrecompileBindingMismatch,
    );
}

// ---------------------------------------------------------------------------
// Account binding
// ---------------------------------------------------------------------------

/// An account whose address is not the PDA for its own `owner_seed` must be
/// refused even though its bytes are byte-identical to a real one.
#[test]
fn non_pda_account_rejected() {
    expect_reject(
        Case {
            account_at_wrong_address: true,
            ..Default::default()
        },
        WardenError::Unauthorized,
    );
}

/// The passkey path must refuse an Ed25519-root account outright rather than
/// misread 32 of its 33 stored bytes as a compressed point.
#[test]
fn ed25519_root_rejected_on_passkey_path() {
    expect_reject(
        Case {
            fixture: SmartAccountFixture {
                root_is_passkey: false,
                ..Default::default()
            },
            ..Default::default()
        },
        WardenError::RootKindUnsupported,
    );
}
