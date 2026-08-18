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
use common::{create_smart_account, read_smart_account, set_smart_account, SmartAccountFixture};
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

/// Anchor error codes as **literals**, independent of the program's enum.
///
/// Deriving the expected code from `WardenError` would mean the assertions
/// re-derive the very thing under test: reordering the enum would silently
/// renumber every code and every test would keep passing while every deployed
/// client broke. These are the values as of commit `3db010a`
/// (`6000 + declaration index`, Anchor's `ERROR_CODE_OFFSET`); Task 7's TS
/// client must use the same numbers.
/// `pinned_error_codes_match_the_enum_today` is the only place the enum is
/// consulted, and it fails loudly on any reorder or insertion.
mod err {
    pub const OVERFLOW: u32 = 6000;
    pub const FROZEN: u32 = 6001;
    pub const UNAUTHORIZED: u32 = 6002;
    pub const INVALID_ROOT_ASSERTION: u32 = 6003;
    pub const NONCE_MISMATCH: u32 = 6004;
    pub const EXPIRED: u32 = 6005;
    pub const CAP_EXCEEDED: u32 = 6006;
    pub const SESSION_EXPIRED: u32 = 6007;
    pub const OP_NOT_ALLOWED: u32 = 6008;
    pub const INVALID_ACCOUNT_DATA: u32 = 6009;
    pub const BAD_INSTRUCTION_LAYOUT: u32 = 6010;
    pub const CLIENT_DATA_TOO_LONG: u32 = 6011;
    pub const CLIENT_DATA_MALFORMED: u32 = 6012;
    pub const CLIENT_DATA_DUPLICATE_KEY: u32 = 6013;
    pub const CLIENT_DATA_MISSING_KEY: u32 = 6014;
    pub const CLIENT_DATA_TYPE_MISMATCH: u32 = 6015;
    pub const CROSS_ORIGIN_NOT_ALLOWED: u32 = 6016;
    pub const ORIGIN_MISMATCH: u32 = 6017;
    pub const CHALLENGE_MISMATCH: u32 = 6018;
    pub const AUTH_DATA_TOO_SHORT: u32 = 6019;
    pub const RP_ID_HASH_MISMATCH: u32 = 6020;
    pub const USER_VERIFICATION_REQUIRED: u32 = 6021;
    pub const PRECOMPILE_NOT_FOUND: u32 = 6022;
    pub const PRECOMPILE_BINDING_MISMATCH: u32 = 6023;
    pub const ROOT_KIND_UNSUPPORTED: u32 = 6024;
    // Appended by Task 4 (`create_account`) and Task 5 (sessions). They are
    // pinned here — the one table this suite's
    // `pinned_error_codes_match_the_enum_today` checks against the enum — even
    // though this file never raises them, so an insertion anywhere in
    // `WardenError` is caught by ONE test rather than by whichever suite
    // happens to assert on the renumbered variant.
    pub const INVALID_ORIGIN: u32 = 6025;
    pub const ZERO_CLUSTER_TAG: u32 = 6026;
    pub const INVALID_POLICY: u32 = 6027;
    pub const PROGRAM_ALLOWLIST_UNSUPPORTED: u32 = 6028;
}

/// The pinned table above must describe the enum as it stands today. If this
/// fails, `WardenError` was reordered or a variant was inserted rather than
/// appended — every already-shipped client's error handling just changed
/// meaning, and the table (and the TS client) must be updated deliberately.
#[test]
fn pinned_error_codes_match_the_enum_today() {
    let pairs: [(u32, WardenError, &str); 29] = [
        (err::OVERFLOW, WardenError::Overflow, "Overflow"),
        (err::FROZEN, WardenError::Frozen, "Frozen"),
        (err::UNAUTHORIZED, WardenError::Unauthorized, "Unauthorized"),
        (err::INVALID_ROOT_ASSERTION, WardenError::InvalidRootAssertion, "InvalidRootAssertion"),
        (err::NONCE_MISMATCH, WardenError::NonceMismatch, "NonceMismatch"),
        (err::EXPIRED, WardenError::Expired, "Expired"),
        (err::CAP_EXCEEDED, WardenError::CapExceeded, "CapExceeded"),
        (err::SESSION_EXPIRED, WardenError::SessionExpired, "SessionExpired"),
        (err::OP_NOT_ALLOWED, WardenError::OpNotAllowed, "OpNotAllowed"),
        (err::INVALID_ACCOUNT_DATA, WardenError::InvalidAccountData, "InvalidAccountData"),
        (err::BAD_INSTRUCTION_LAYOUT, WardenError::BadInstructionLayout, "BadInstructionLayout"),
        (err::CLIENT_DATA_TOO_LONG, WardenError::ClientDataTooLong, "ClientDataTooLong"),
        (err::CLIENT_DATA_MALFORMED, WardenError::ClientDataMalformed, "ClientDataMalformed"),
        (err::CLIENT_DATA_DUPLICATE_KEY, WardenError::ClientDataDuplicateKey, "ClientDataDuplicateKey"),
        (err::CLIENT_DATA_MISSING_KEY, WardenError::ClientDataMissingKey, "ClientDataMissingKey"),
        (err::CLIENT_DATA_TYPE_MISMATCH, WardenError::ClientDataTypeMismatch, "ClientDataTypeMismatch"),
        (err::CROSS_ORIGIN_NOT_ALLOWED, WardenError::CrossOriginNotAllowed, "CrossOriginNotAllowed"),
        (err::ORIGIN_MISMATCH, WardenError::OriginMismatch, "OriginMismatch"),
        (err::CHALLENGE_MISMATCH, WardenError::ChallengeMismatch, "ChallengeMismatch"),
        (err::AUTH_DATA_TOO_SHORT, WardenError::AuthDataTooShort, "AuthDataTooShort"),
        (err::RP_ID_HASH_MISMATCH, WardenError::RpIdHashMismatch, "RpIdHashMismatch"),
        (err::USER_VERIFICATION_REQUIRED, WardenError::UserVerificationRequired, "UserVerificationRequired"),
        (err::PRECOMPILE_NOT_FOUND, WardenError::PrecompileNotFound, "PrecompileNotFound"),
        (err::PRECOMPILE_BINDING_MISMATCH, WardenError::PrecompileBindingMismatch, "PrecompileBindingMismatch"),
        (err::ROOT_KIND_UNSUPPORTED, WardenError::RootKindUnsupported, "RootKindUnsupported"),
        (err::INVALID_ORIGIN, WardenError::InvalidOrigin, "InvalidOrigin"),
        (err::ZERO_CLUSTER_TAG, WardenError::ZeroClusterTag, "ZeroClusterTag"),
        (err::INVALID_POLICY, WardenError::InvalidPolicy, "InvalidPolicy"),
        (
            err::PROGRAM_ALLOWLIST_UNSUPPORTED,
            WardenError::ProgramAllowlistUnsupported,
            "ProgramAllowlistUnsupported",
        ),
    ];
    for (pinned, variant, name) in pairs {
        assert_eq!(
            pinned,
            u32::from(variant),
            "WardenError::{name} moved: pinned {pinned}, enum says {}",
            u32::from(variant)
        );
    }
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
        // PDA for its own `owner_seed` — impossible through `create_account`
        // itself (its `seeds` constraint derives the address), so this one
        // test genuinely needs raw state (see `non_pda_account_rejected`).
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
    } else if fixture.generation != 0 || fixture.root_nonce != 0 {
        // No instruction advances `generation` yet, and reaching a
        // `root_nonce` other than 0 by replaying real ceremonies would only
        // duplicate what `consecutive_ceremonies_each_consume_one_nonce` and
        // `replay_same_assertion_rejected` already prove (see
        // `stale_generation_rejected` and
        // `stale_nonce_far_in_the_past_rejected_as_challenge_mismatch`) — raw
        // state is the more precise, lower-noise way to reach these two
        // deliberately "impossible via any implemented instruction" shapes.
        set_smart_account(&mut svm, &fixture)
    } else {
        create_smart_account(&mut svm, &payer, &fixture)
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

/// The two instructions of one honest ceremony against a planted account, at a
/// given `root_nonce`. Used by the multi-step tests, which need to submit more
/// than one transaction against a single live SVM.
fn ceremony_ixs(
    account: Pubkey,
    pk: &TestPasskey,
    f: &SmartAccountFixture,
    root_nonce: u64,
    expiry_ts: i64,
) -> Vec<Instruction> {
    let challenge = rotate_nonce_challenge(
        &f.cluster_tag,
        &account,
        f.generation,
        f.policy_version,
        root_nonce,
        expiry_ts,
    );
    let a = pk.assert_with_client_data(
        passkey::client_data_json(&challenge, &f.origin),
        passkey::rp_id_hash(&f.origin),
        FLAGS_UP_UV,
    );
    let args = RootArgs {
        precompile_ix_index: 0,
        authenticator_data: a.authenticator_data.clone(),
        client_data_json: a.client_data_json.clone(),
        expiry_ts,
    };
    vec![
        passkey::precompile_ix(&a, &pk.pubkey33()),
        rotate_nonce_ix(account, &args),
    ]
}

/// A live SVM with one planted, passkey-rooted account.
fn live_account() -> (LiteSVM, Keypair, TestPasskey, SmartAccountFixture, Pubkey) {
    let (mut svm, payer) = common::setup();
    set_clock(&mut svm, NOW);
    let pk = TestPasskey::new(3);
    let mut f = SmartAccountFixture::default();
    f.root_pubkey33 = pk.pubkey33();
    let account = create_smart_account(&mut svm, &payer, &f);
    (svm, payer, pk, f, account)
}

/// Wrap instructions in a transaction against a FRESH blockhash, so a repeat
/// submission is a genuinely new transaction and cannot be turned away by the
/// runtime's duplicate-signature cache — the rejection must come from the
/// program.
fn send_fresh(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction]) -> litesvm::types::TransactionResult {
    svm.expire_blockhash();
    let tx = Transaction::new(
        &[payer],
        Message::new(ixs, Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
}

fn expect_reject(case: Case, expected: u32) {
    let mut b = build(case);
    let ix_index = b.our_ix_index;
    let before = read_smart_account(&b.svm, &b.account).root_nonce;
    let err = b.svm.send_transaction(b.tx).expect_err("must be rejected");
    assert_eq!(
        err.err,
        TransactionError::InstructionError(ix_index, InstructionError::Custom(expected)),
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

/// Two full ceremonies against ONE account on ONE live SVM: the first signs
/// over nonce 0, the second over the nonce the first left behind. This is the
/// property the extension depends on — a user can act twice in a row.
#[test]
fn consecutive_ceremonies_each_consume_one_nonce() {
    let (mut svm, payer, pk, f, account) = live_account();
    for n in 0..2u64 {
        assert_eq!(read_smart_account(&svm, &account).root_nonce, n);
        let ixs = ceremony_ixs(account, &pk, &f, n, NOW + 60);
        send_fresh(&mut svm, &payer, &ixs)
            .unwrap_or_else(|e| panic!("ceremony {n} must succeed: {:?} {:#?}", e.err, e.meta.logs));
        assert_eq!(read_smart_account(&svm, &account).root_nonce, n + 1);
    }
}

// ---------------------------------------------------------------------------
// Replay / freshness
// ---------------------------------------------------------------------------

/// THE REAL REPLAY: one honest ceremony succeeds, then the byte-identical
/// assertion is resubmitted against the same account on the same SVM under a
/// fresh blockhash. The consumed nonce is what must turn it away — nothing
/// else about the transaction has changed.
#[test]
fn replay_same_assertion_rejected() {
    let (mut svm, payer, pk, f, account) = live_account();
    let ixs = ceremony_ixs(account, &pk, &f, 0, NOW + 60);

    send_fresh(&mut svm, &payer, &ixs).expect("first submission must succeed");
    assert_eq!(read_smart_account(&svm, &account).root_nonce, 1);

    let e = send_fresh(&mut svm, &payer, &ixs).expect_err("replay must be rejected");
    assert_eq!(
        e.err,
        TransactionError::InstructionError(1, InstructionError::Custom(err::NONCE_MISMATCH)),
        "logs={:#?}",
        e.meta.logs
    );
    assert!(!e.meta.logs.iter().any(|l| l.contains("panicked")));
    assert_eq!(
        read_smart_account(&svm, &account).root_nonce,
        1,
        "a rejected replay must not consume a second nonce"
    );

    // And the account is still usable: a fresh ceremony over nonce 1 works.
    let next = ceremony_ixs(account, &pk, &f, 1, NOW + 60);
    send_fresh(&mut svm, &payer, &next).expect("a fresh ceremony must still succeed after a replay");
    assert_eq!(read_smart_account(&svm, &account).root_nonce, 2);
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
        err::CHALLENGE_MISMATCH,
    );
}

#[test]
fn expired_rejected() {
    expect_reject(
        Case {
            expiry_ts: NOW - 1,
            ..Default::default()
        },
        err::EXPIRED,
    );
}

#[test]
fn future_expiry_beyond_600s_rejected() {
    expect_reject(
        Case {
            expiry_ts: NOW + 601,
            ..Default::default()
        },
        err::EXPIRED,
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
        err::CHALLENGE_MISMATCH,
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
        err::CHALLENGE_MISMATCH,
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
        err::RP_ID_HASH_MISMATCH,
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
        err::RP_ID_HASH_MISMATCH,
    );
}

#[test]
fn up_only_rejected() {
    expect_reject(
        Case {
            flags: 0x01,
            ..Default::default()
        },
        err::USER_VERIFICATION_REQUIRED,
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
        err::ORIGIN_MISMATCH,
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
        err::ORIGIN_MISMATCH,
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
        err::CLIENT_DATA_DUPLICATE_KEY,
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
        err::CROSS_ORIGIN_NOT_ALLOWED,
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
        err::CLIENT_DATA_TYPE_MISMATCH,
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
        err::CLIENT_DATA_TOO_LONG,
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
    let account = create_smart_account(&mut svm, &payer, &fixture);

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
            InstructionError::Custom(err::PRECOMPILE_BINDING_MISMATCH)
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
        err::BAD_INSTRUCTION_LAYOUT,
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
        err::PRECOMPILE_BINDING_MISMATCH,
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
    let account = create_smart_account(&mut svm, &payer, &fixture);
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
            InstructionError::Custom(err::PRECOMPILE_BINDING_MISMATCH)
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
        err::PRECOMPILE_NOT_FOUND,
    );
}

#[test]
fn precompile_ix_index_out_of_range_rejected() {
    expect_reject(
        Case {
            precompile_ix_index: Some(9),
            ..Default::default()
        },
        err::PRECOMPILE_NOT_FOUND,
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
        err::PRECOMPILE_NOT_FOUND,
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
        err::PRECOMPILE_BINDING_MISMATCH,
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
        err::UNAUTHORIZED,
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
        err::ROOT_KIND_UNSUPPORTED,
    );
}
