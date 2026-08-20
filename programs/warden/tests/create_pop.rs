//! **Proof of possession at `create_account`** (Phase 1B Task 2b) — the suite
//! that closes Phase 1A's squatting hole.
//!
//! Two independent properties, and every test here targets one of them:
//!
//! 1. **The address is a function of the root key.** `owner_seed =
//!    Keccak256("WARDEN/seed/v1" ‖ root_pubkey33 ‖ salt)` is computed
//!    on-chain, so a front-runner who copies the victim's `salt` and swaps in
//!    their own root lands somewhere else entirely.
//! 2. **The creation is authenticated.** A real WebAuthn assertion over
//!    `action_hash(0x06, borsh(CreateBody))` is mandatory, so a front-runner
//!    who keeps the victim's root key — the only way to reach the victim's
//!    address — cannot produce the ceremony.
//!
//! The pre-fix RED evidence for exactly these tests is in task-2b-report.md:
//! against commit `d0072fd` an attacker with their own passkey landed the
//! victim's PDA and locked the victim out, and the test that proved it is the
//! direct ancestor of `squat_race_attacker_cannot_reach_the_victims_address`
//! below.
//!
//! Transaction shape throughout:
//! ```text
//!   ix[0] = Secp256r1SigVerify precompile over (pubkey33, sig64, message)
//!   ix[1] = warden::create_account
//! ```

mod common;

use anchor_lang::AnchorSerialize;
use common::passkey::{self, TestPasskey, TEST_ORIGIN};
use common::{
    account_pda_for, create_account_ix, create_args, default_policy_args, read_smart_account,
    sign_create,
};
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
use warden::constants::{MAX_MINTS_AT_CREATE, MAX_ROOT_SLOT_AGE};
use warden::instructions::create_account::{derive_owner_seed, CreateAccountArgs};
use warden::root_verify::RootArgs;
use warden::state::{MintCap, PolicyArgs, RootKey};

const NOW: i64 = 1_760_000_000;
const NOW_SLOT: u64 = 350_000_000;
/// Solana's transaction packet limit (`PACKET_DATA_SIZE`).
const PACKET_DATA_SIZE: usize = 1232;

/// Same pinned literals as `root_verify.rs`'s `mod err`; that suite's
/// `pinned_error_codes_match_the_enum_today` is the single place the enum is
/// consulted.
mod err {
    pub const INVALID_ROOT_KEY: u32 = 6034;
    pub const CHALLENGE_MISMATCH: u32 = 6018;
    pub const PRECOMPILE_NOT_FOUND: u32 = 6022;
    pub const PRECOMPILE_BINDING_MISMATCH: u32 = 6023;
    pub const ROOT_SLOT_STALE: u32 = 6036;
    pub const ROOT_REQUIRES_TOP_LEVEL: u32 = 6038;
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn setup_at_now() -> (LiteSVM, Keypair) {
    let (mut svm, payer) = common::setup();
    let mut c: Clock = svm.get_sysvar();
    c.unix_timestamp = NOW;
    c.slot = NOW_SLOT;
    svm.set_sysvar(&c);
    (svm, payer)
}

fn args_for(pk: &TestPasskey, salt: [u8; 32]) -> CreateAccountArgs {
    create_args(
        RootKey::P256Passkey { pubkey: pk.pubkey33() },
        salt,
        TEST_ORIGIN,
        [0x5Au8; 32],
        default_policy_args(),
    )
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction]) -> litesvm::types::TransactionResult {
    svm.expire_blockhash();
    let tx = Transaction::new(&[payer], Message::new(ixs, Some(&payer.pubkey())), svm.latest_blockhash());
    svm.send_transaction(tx)
}

fn expect_custom(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction], ix_index: u8, code: u32) {
    let err = send(svm, payer, ixs).expect_err("must be rejected");
    assert_eq!(
        err.err,
        TransactionError::InstructionError(ix_index, InstructionError::Custom(code)),
        "wrong failure mode; logs={:#?}",
        err.meta.logs
    );
    assert!(
        !err.meta.logs.iter().any(|l| l.contains("panicked")),
        "program panicked instead of returning an error: {:#?}",
        err.meta.logs
    );
}

/// `n` distinct mints with cap + ceiling + threshold each — the heaviest
/// per-mint shape, reused from `create_account.rs`'s wire-size tests.
fn n_mints_policy(n: usize) -> PolicyArgs {
    let mints: Vec<Pubkey> = (0..n).map(|_| Pubkey::new_unique()).collect();
    let mut p = default_policy_args();
    p.caps = mints.iter().map(|m| MintCap { mint: *m, per_tx: 1_000, per_day: 10_000, per_30d: 100_000 }).collect();
    p.session_ceiling = mints.iter().map(|m| MintCap { mint: *m, per_tx: 500, per_day: 5_000, per_30d: 50_000 }).collect();
    p.large_threshold = mints.iter().map(|m| MintCap { mint: *m, per_tx: 2_000, per_day: 0, per_30d: 0 }).collect();
    p
}

// ---------------------------------------------------------------------------
// The ceremony is mandatory
// ---------------------------------------------------------------------------

/// The whole instruction, with a perfectly well-formed `RootArgs`, but no
/// secp256r1 instruction anywhere in the transaction: `bind_precompile`
/// refuses because the named index is not before ours (it *is* ours).
#[test]
fn create_without_a_ceremony_is_rejected() {
    let (mut svm, payer) = setup_at_now();
    let pk = TestPasskey::new(3);
    let mut args = args_for(&pk, [1u8; 32]);
    let (pda, ixs) = sign_create(&svm, payer.pubkey(), &pk, &mut args, solana_sdk::pubkey::Pubkey::default());

    // Drop the precompile: a REAL, correctly-signed assertion is still in the
    // instruction data, so the only thing missing is the runtime's
    // verification of it. That is exactly the attack a squatter would mount.
    expect_custom(&mut svm, &payer, &ixs[1..], 0, err::PRECOMPILE_NOT_FOUND);
    assert!(svm.get_account(&pda).is_none(), "nothing may be created");
}

/// A ceremony signed by a passkey that is NOT the root key in the arguments.
/// The address still derives from the *argument* key, so this is the shape a
/// squatter must produce to reach a chosen address — and the precompile
/// binding refuses it.
#[test]
fn create_with_an_assertion_by_the_wrong_passkey_is_rejected() {
    let (mut svm, payer) = setup_at_now();
    let victim = TestPasskey::new(3);
    let attacker = TestPasskey::new(9);

    let mut args = args_for(&victim, [1u8; 32]);
    // `sign_create` signs with `attacker` but derives the address (and the
    // transcript) from `args.root_key`, which is the victim's.
    let (pda, ixs) = sign_create(&svm, payer.pubkey(), &attacker, &mut args, solana_sdk::pubkey::Pubkey::default());

    expect_custom(&mut svm, &payer, &ixs, 1, err::PRECOMPILE_BINDING_MISMATCH);
    assert!(svm.get_account(&pda).is_none(), "nothing may be created");
}

/// A root ceremony reached through a CPI is refused at transaction level
/// (`require_top_level`), like every other root path — with the byte-identical
/// ceremony succeeding top-level as the control.
#[test]
fn create_through_a_middleman_cpi_is_rejected() {
    let (mut svm, payer) = setup_at_now();
    let middleman = common::add_middleman(&mut svm);
    let pk = TestPasskey::new(3);
    let mut args = args_for(&pk, [2u8; 32]);
    let (pda, ixs) = sign_create(&svm, payer.pubkey(), &pk, &mut args, solana_sdk::pubkey::Pubkey::default());
    let (precompile_ix, warden_ix) = (ixs[0].clone(), ixs[1].clone());

    // ---- (a) through the middleman: rejected -----------------------------
    let mut forward_data = Sha256::digest(b"global:forward")[..8].to_vec();
    forward_data.extend_from_slice(&(warden_ix.data.len() as u32).to_le_bytes());
    forward_data.extend_from_slice(&warden_ix.data);
    let mut accounts = vec![AccountMeta::new_readonly(common::program_id(), false)];
    accounts.extend(warden_ix.accounts.iter().cloned());
    let forward_ix = Instruction { program_id: middleman, accounts, data: forward_data };
    expect_custom(&mut svm, &payer, &[precompile_ix.clone(), forward_ix], 1, err::ROOT_REQUIRES_TOP_LEVEL);
    assert!(svm.get_account(&pda).is_none(), "nothing may be created");

    // ---- (b) the SAME ceremony, top-level: accepted ----------------------
    send(&mut svm, &payer, &[precompile_ix, warden_ix])
        .expect("the identical ceremony must succeed when it is not wrapped in a CPI");
    assert!(svm.get_account(&pda).is_some());
}

/// `signed_slot` is inside the create transcript too: a ceremony aged past
/// `MAX_ROOT_SLOT_AGE` is refused, so a squatter cannot hoard an intercepted
/// creation assertion and land it later.
#[test]
fn a_stale_creation_ceremony_is_rejected() {
    let (mut svm, payer) = setup_at_now();
    let pk = TestPasskey::new(3);
    let mut args = args_for(&pk, [3u8; 32]);
    let (pda, ixs) = sign_create(&svm, payer.pubkey(), &pk, &mut args, solana_sdk::pubkey::Pubkey::default());
    svm.warp_to_slot(NOW_SLOT + MAX_ROOT_SLOT_AGE);
    expect_custom(&mut svm, &payer, &ixs, 1, err::ROOT_SLOT_STALE);
    assert!(svm.get_account(&pda).is_none());
}

// ---------------------------------------------------------------------------
// The ceremony binds every argument
// ---------------------------------------------------------------------------

/// Sign for one salt, submit another. Both the signed `CreateBody.salt` and
/// the transcript's `account` change, so the challenge cannot match.
#[test]
fn a_substituted_salt_is_a_challenge_mismatch() {
    let (mut svm, payer) = setup_at_now();
    let pk = TestPasskey::new(3);
    let mut args = args_for(&pk, [4u8; 32]);
    let (_pda, _ixs) = sign_create(&svm, payer.pubkey(), &pk, &mut args, solana_sdk::pubkey::Pubkey::default());

    // Keep the assertion, change the salt, and submit at the address the NEW
    // salt derives (submitting at the old address would only trip Anchor's
    // seeds constraint, which is a weaker statement).
    let mut swapped = args.clone();
    swapped.salt = [5u8; 32];
    let (new_pda, _) = account_pda_for(&pk.pubkey33(), &swapped.salt);
    let ixs = vec![
        // The precompile from the original ceremony, rebuilt verbatim.
        precompile_from(&args, &pk),
        create_account_ix(payer.pubkey(), new_pda, &swapped),
    ];
    expect_custom(&mut svm, &payer, &ixs, 1, err::CHALLENGE_MISMATCH);
    assert!(svm.get_account(&new_pda).is_none());
}

/// Sign for one policy, submit another. The address is unchanged, so this
/// isolates `CreateBody.policy_hash`.
#[test]
fn a_substituted_policy_is_a_challenge_mismatch() {
    let (mut svm, payer) = setup_at_now();
    let pk = TestPasskey::new(3);
    let mut args = args_for(&pk, [6u8; 32]);
    let (pda, _ixs) = sign_create(&svm, payer.pubkey(), &pk, &mut args, solana_sdk::pubkey::Pubkey::default());

    let mut swapped = args.clone();
    swapped.policy.max_session_life_secs -= 1; // still a VALID policy — just not the signed one
    let ixs = vec![precompile_from(&args, &pk), create_account_ix(payer.pubkey(), pda, &swapped)];
    expect_custom(&mut svm, &payer, &ixs, 1, err::CHALLENGE_MISMATCH);
    assert!(svm.get_account(&pda).is_none());
}

/// Same, for `cluster_tag` — which is both a `CreateBody` field and a
/// transcript field.
#[test]
fn a_substituted_cluster_tag_is_a_challenge_mismatch() {
    let (mut svm, payer) = setup_at_now();
    let pk = TestPasskey::new(3);
    let mut args = args_for(&pk, [7u8; 32]);
    let (pda, _ixs) = sign_create(&svm, payer.pubkey(), &pk, &mut args, solana_sdk::pubkey::Pubkey::default());

    let mut swapped = args.clone();
    swapped.cluster_tag = [0x11u8; 32];
    let ixs = vec![precompile_from(&args, &pk), create_account_ix(payer.pubkey(), pda, &swapped)];
    expect_custom(&mut svm, &payer, &ixs, 1, err::CHALLENGE_MISMATCH);
    assert!(svm.get_account(&pda).is_none());
}

/// Rebuild the precompile instruction for an already-signed `args` — the
/// substitution tests keep the assertion and change the instruction beside it.
fn precompile_from(args: &CreateAccountArgs, pk: &TestPasskey) -> Instruction {
    let a = &args.root_assertion;
    let mut message = a.authenticator_data.clone();
    message.extend_from_slice(&Sha256::digest(&a.client_data_json));
    let assertion = passkey::Assertion {
        authenticator_data: a.authenticator_data.clone(),
        client_data_json: a.client_data_json.clone(),
        signature64_low_s: pk.sign(&message),
        message,
    };
    passkey::precompile_ix(&assertion, &pk.pubkey33())
}

// ---------------------------------------------------------------------------
// The squat race (the reason this task exists)
// ---------------------------------------------------------------------------

/// **THE headline test.** The attacker sees the victim's `salt` in flight and
/// front-runs with it. Two outcomes, and both must hold:
///
/// (a) with the attacker's OWN root key the transaction succeeds — but at a
///     DIFFERENT address, because the seed hashes the root key. The victim's
///     address is untouched and the victim's own creation still lands.
/// (b) with the VICTIM's root key (the only way to reach the victim's address)
///     the attacker cannot produce the assertion, so nothing lands at all.
///
/// Against `d0072fd` (pre-fix) the ancestor of this test showed the attacker
/// taking the victim's address outright and locking the victim out.
#[test]
fn squat_race_attacker_cannot_reach_the_victims_address() {
    let (mut svm, payer) = setup_at_now();
    let victim = TestPasskey::new(3);
    let attacker = TestPasskey::new(9);
    let observed_salt = [0xABu8; 32];

    let (victim_pda, _) = account_pda_for(&victim.pubkey33(), &observed_salt);

    // ---- (a) attacker's own root, victim's salt: lands ELSEWHERE ---------
    let mut a_args = args_for(&attacker, observed_salt);
    let (attacker_pda, a_ixs) = sign_create(&svm, payer.pubkey(), &attacker, &mut a_args, solana_sdk::pubkey::Pubkey::default());
    assert_ne!(
        attacker_pda, victim_pda,
        "same salt + different root MUST derive a different address"
    );
    send(&mut svm, &payer, &a_ixs).expect("the attacker may of course create their OWN account");

    // ---- (b) victim's root, victim's salt, attacker's signature: nothing --
    let mut b_args = args_for(&victim, observed_salt);
    let (b_pda, b_ixs) = sign_create(&svm, payer.pubkey(), &attacker, &mut b_args, solana_sdk::pubkey::Pubkey::default());
    assert_eq!(b_pda, victim_pda, "with the victim's root the address IS the victim's");
    expect_custom(&mut svm, &payer, &b_ixs, 1, err::PRECOMPILE_BINDING_MISMATCH);

    // ...and with no ceremony at all, likewise.
    expect_custom(&mut svm, &payer, &b_ixs[1..], 0, err::PRECOMPILE_NOT_FOUND);
    assert!(svm.get_account(&victim_pda).is_none(), "the victim's address is still free");

    // ---- the victim's own creation lands, unaffected ---------------------
    let mut v_args = args_for(&victim, observed_salt);
    let (v_pda, v_ixs) = sign_create(&svm, payer.pubkey(), &victim, &mut v_args, solana_sdk::pubkey::Pubkey::default());
    assert_eq!(v_pda, victim_pda);
    send(&mut svm, &payer, &v_ixs).expect("the victim's own create must land");
    let acc = read_smart_account(&svm, &victim_pda);
    assert_eq!(
        acc.root().unwrap(),
        RootKey::P256Passkey { pubkey: victim.pubkey33() },
        "the victim's address is rooted to the VICTIM's passkey"
    );
    assert_eq!(
        acc.owner_seed,
        derive_owner_seed(&victim.pubkey33(), &observed_salt),
        "the stored seed is the derived one"
    );
}

/// A creation assertion is single-use in the strongest sense available: it
/// names an address, so it cannot be re-pointed at a second salt.
#[test]
fn the_creating_assertion_cannot_be_replayed_for_a_second_salt() {
    let (mut svm, payer) = setup_at_now();
    let pk = TestPasskey::new(3);
    let mut args = args_for(&pk, [0x10u8; 32]);
    let (pda, ixs) = sign_create(&svm, payer.pubkey(), &pk, &mut args, solana_sdk::pubkey::Pubkey::default());
    send(&mut svm, &payer, &ixs).expect("first create must land");

    // The same RootArgs, re-pointed at a second salt / second address.
    let mut second = args.clone();
    second.salt = [0x11u8; 32];
    let (second_pda, _) = account_pda_for(&pk.pubkey33(), &second.salt);
    assert_ne!(second_pda, pda);
    let replay = vec![precompile_from(&args, &pk), create_account_ix(payer.pubkey(), second_pda, &second)];
    expect_custom(&mut svm, &payer, &replay, 1, err::CHALLENGE_MISMATCH);
    assert!(svm.get_account(&second_pda).is_none());
}

// ---------------------------------------------------------------------------
// Off-curve roots (the Phase-1A `validate_root` gap, now closed end to end)
// ---------------------------------------------------------------------------

/// x = 1 is a well-formed compressed-point ENCODING of a point that is not on
/// P-256. `validate_root` accepts the encoding by design
/// (`create_account::tests::root_encoding_check_alone_still_admits_an_off_curve_x`)
/// — but no signature can exist under a point the runtime cannot decompress,
/// so the transaction dies at the precompile instruction and the account is
/// never created. This is the end-to-end half of that unit test, and it is
/// what retires the Phase-1A "encoding only" gap.
#[test]
fn off_curve_root_cannot_be_created_because_no_assertion_verifies() {
    let (mut svm, payer) = setup_at_now();
    let signer = TestPasskey::new(3);
    let mut off_curve = [0u8; 33];
    off_curve[0] = 0x02;
    off_curve[32] = 1; // x = 1, off the curve

    let mut args = args_for(&signer, [0x20u8; 32]);
    args.root_key = RootKey::P256Passkey { pubkey: off_curve };
    // A ceremony signed by a real key, but claiming the off-curve root: the
    // precompile is handed `off_curve` as the public key.
    let (pda, mut ixs) = sign_create(&svm, payer.pubkey(), &signer, &mut args, solana_sdk::pubkey::Pubkey::default());
    ixs[0] = passkey::precompile_ix_custom(
        &off_curve,
        &[0u8; 64],
        &{
            let mut m = args.root_assertion.authenticator_data.clone();
            m.extend_from_slice(&Sha256::digest(&args.root_assertion.client_data_json));
            m
        },
        1,
        u16::MAX,
    );

    let err = send(&mut svm, &payer, &ixs).expect_err("an off-curve root cannot be proven");
    // The RUNTIME rejects at the precompile instruction (index 0) — warden's
    // own instruction never executes.
    assert_eq!(
        err.err,
        TransactionError::InstructionError(0, InstructionError::Custom(2)),
        "expected PrecompileError::InvalidSignature; logs={:#?}",
        err.meta.logs
    );
    assert!(svm.get_account(&pda).is_none());
}

/// The complementary cheap rejection: an encoding `validate_root` *can* refuse
/// still fails with its own error rather than reaching the precompile — the
/// division of labour, stated as a test.
#[test]
fn a_malformed_root_encoding_is_still_refused_by_validate_root() {
    let (mut svm, payer) = setup_at_now();
    let pk = TestPasskey::new(3);
    let mut bad = pk.pubkey33();
    bad[0] = 0x04; // uncompressed-point prefix
    let mut args = args_for(&pk, [0x21u8; 32]);
    args.root_key = RootKey::P256Passkey { pubkey: bad };
    let (_pda, ixs) = sign_create(&svm, payer.pubkey(), &pk, &mut args, solana_sdk::pubkey::Pubkey::default());
    expect_custom(&mut svm, &payer, &ixs, 1, err::INVALID_ROOT_KEY);
}

// ---------------------------------------------------------------------------
// The created account, and the ceremony chain that follows it
// ---------------------------------------------------------------------------

/// Creation consumes its own nonce, so the account starts at `root_nonce = 1`
/// and the NEXT ceremony must be built at nonce 1 — proven by actually running
/// one (`rotate_nonce`) rather than by reading a field.
#[test]
fn creation_consumes_its_nonce_and_the_next_ceremony_starts_at_one() {
    let (mut svm, payer) = setup_at_now();
    let pk = TestPasskey::new(3);
    let mut args = args_for(&pk, [0x30u8; 32]);
    let (pda, ixs) = sign_create(&svm, payer.pubkey(), &pk, &mut args, solana_sdk::pubkey::Pubkey::default());
    send(&mut svm, &payer, &ixs).expect("create must land");
    assert_eq!(read_smart_account(&svm, &pda).root_nonce, 1);

    // A rotate_nonce ceremony at nonce 1.
    let ah = warden::root_verify::transcript::action_hash(
        warden::root_verify::transcript::OP_ROTATE_NONCE,
        &[],
    );
    let clock: Clock = svm.get_sysvar();
    let t = warden::root_verify::transcript::transcript_hash(
        &args.cluster_tag,
        &common::program_id(),
        &pda,
        0,
        1,
        1,
        clock.unix_timestamp + 60,
        clock.slot,
        &ah,
    );
    let a = pk.assert_(
        &warden::root_verify::transcript::b64url_no_pad(&t),
        TEST_ORIGIN,
        passkey::rp_id_hash(TEST_ORIGIN),
        passkey::FLAGS_UP_UV,
    );
    let rargs = RootArgs {
        precompile_ix_index: 0,
        authenticator_data: a.authenticator_data.clone(),
        client_data_json: a.client_data_json.clone(),
        expiry_ts: clock.unix_timestamp + 60,
        signed_slot: clock.slot,
    };
    let mut data = Sha256::digest(b"global:rotate_nonce")[..8].to_vec();
    rargs.serialize(&mut data).unwrap();
    let rotate = Instruction {
        program_id: common::program_id(),
        accounts: vec![
            AccountMeta::new(pda, false),
            AccountMeta::new_readonly(sysvar::instructions::ID, false),
        ],
        data,
    };
    send(&mut svm, &payer, &[passkey::precompile_ix(&a, &pk.pubkey33()), rotate])
        .expect("a ceremony at nonce 1 must be accepted right after creation");
    assert_eq!(read_smart_account(&svm, &pda).root_nonce, 2);
}

// ---------------------------------------------------------------------------
// Byte budget — the hard gate (plan Global Constraints)
// ---------------------------------------------------------------------------

/// The measured cost of proof of possession, at 0 / 1 / 2 / `MAX_MINT_CAPS`
/// mints. **`MAX_MINTS_AT_CREATE` is derived from this measurement**, not the
/// other way round: if a policy shape does not fit, the constant drops.
///
/// Numbers are recorded in docs/program/PHASE1A-MEASUREMENTS.md ("Task 2b").
#[test]
fn create_with_pop_transaction_sizes_are_measured_and_bounded() {
    let (svm, payer) = setup_at_now();
    let pk = TestPasskey::new(3);
    // Measure the WORST shape: a registry IS attached (Task 3, WRDF-0036), which
    // adds a distinct account key (+32 B) over the None sentinel — the None case
    // reuses the program id already in the message and is strictly smaller. If
    // the registry-bearing shape fits, so does the registry-less one.
    let registry = solana_sdk::pubkey::Pubkey::new_unique();
    let mut fits: Vec<usize> = Vec::new();
    for n in 0..=8usize {
        let mut args = args_for(&pk, [n as u8; 32]);
        args.policy = n_mints_policy(n);
        let (_pda, ixs) = sign_create(&svm, payer.pubkey(), &pk, &mut args, registry);
        let tx = Transaction::new(&[&payer], Message::new(&ixs, Some(&payer.pubkey())), svm.latest_blockhash());
        let len = bincode::serialize(&tx).unwrap().len();
        println!("create_account + PoP + registry, {n} mints: {len} B");
        if len <= PACKET_DATA_SIZE {
            fits.push(n);
        }
    }
    let largest = *fits.last().expect("a zero-mint create with a registry must fit");
    println!("largest mint count that fits with PoP: {largest}");
    assert_eq!(
        largest, MAX_MINTS_AT_CREATE,
        "MAX_MINTS_AT_CREATE ({MAX_MINTS_AT_CREATE}) must equal the largest mint count that actually \
         fits the {PACKET_DATA_SIZE} B packet ({largest}) — change the constant, not this assertion"
    );
}

/// The `MAX_MINTS_AT_CREATE` shape is not merely small enough on paper: it is
/// submitted and must succeed.
#[test]
fn max_mints_at_create_with_pop_actually_lands() {
    let (mut svm, payer) = setup_at_now();
    let pk = TestPasskey::new(3);
    let mut args = args_for(&pk, [0x40u8; 32]);
    args.policy = n_mints_policy(MAX_MINTS_AT_CREATE);
    let (pda, ixs) = sign_create(&svm, payer.pubkey(), &pk, &mut args, solana_sdk::pubkey::Pubkey::default());
    let tx = Transaction::new(&[&payer], Message::new(&ixs, Some(&payer.pubkey())), svm.latest_blockhash());
    let len = bincode::serialize(&tx).unwrap().len();
    assert!(len <= PACKET_DATA_SIZE, "{MAX_MINTS_AT_CREATE}-mint create with PoP is {len} B");
    let res = svm
        .send_transaction(tx)
        .unwrap_or_else(|e| panic!("must succeed: {:?} {:#?}", e.err, e.meta.logs));
    println!("create_account + PoP ({MAX_MINTS_AT_CREATE} mints) CU: {}, tx: {len} B", res.compute_units_consumed);
    assert_eq!(read_smart_account(&svm, &pda).policy.caps[MAX_MINTS_AT_CREATE - 1].mint, args.policy.caps[MAX_MINTS_AT_CREATE - 1].mint);
}
