#![allow(dead_code)]

pub mod passkey;
pub mod token;

use anchor_lang::{AccountDeserialize, AnchorSerialize, Discriminator};
use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_sdk::{
    account::Account,
    clock::Clock,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::Transaction,
};
use warden::constants::{ACCOUNT_SEED, MAX_MINTS_AT_CREATE, SESSION_SEED};
use warden::instructions::create_account::{
    derive_owner_seed, CreateAccountArgs, CreateBody, MAX_SESSION_LIFE_SECS, MIN_TIMELOCK_SECS,
};
use warden::root_verify::transcript::{action_hash, b64url_no_pad, transcript_hash, OP_CREATE};
use warden::root_verify::RootArgs;
use warden::state::{PolicyArgs, RootKey, SessionKey, SmartAccount};

pub fn program_id() -> Pubkey {
    warden::ID
}

/// Program id of the test-only middleman that CPIs into warden — see
/// `programs/test-middleman`. Pinned as a literal here so the test suite does
/// not need the crate as a dependency.
pub fn middleman_program_id() -> Pubkey {
    Pubkey::from_str_const("FHWwDX1az7eAtFsogaRrFcoZkZhBEzSS3QMXPwovSiMN")
}

pub fn setup() -> (LiteSVM, Keypair) {
    // `LiteSVM::new()` runs with EVERY runtime feature DISABLED
    // (`FeatureSet::default()`), which is not the chain this program deploys
    // to: `sol_big_mod_exp` — the syscall `create_account`'s P-256 on-curve
    // check uses — is feature-gated and simply absent there
    // ("unsupported BPF instruction"). `with_mainnet_features()` pins the
    // harness to the features actually active on mainnet-beta, which is both
    // the honest oracle for CU measurements and the only set in which the
    // program runs at all.
    let mut svm = LiteSVM::new().with_mainnet_features();
    let so = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy/warden.so"))
        .expect("run `anchor build` first — see docs/TOOLCHAIN.md");
    svm.add_program(program_id(), &so).expect("add_program");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    (svm, payer)
}

pub fn account_pda(owner_seed: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ACCOUNT_SEED, owner_seed], &program_id())
}

/// The address `create_account` will derive for `(root_pubkey33, salt)` —
/// `["account", Keccak256("WARDEN/seed/v1" ‖ root_pubkey33 ‖ salt)]`.
///
/// Tests derive it with the program's own `derive_owner_seed`; the pinned
/// vector `create_account::tests::owner_seed_matches_pinned_vector` (computed
/// with an INDEPENDENT Keccak) is what stops that from being circular.
pub fn account_pda_for(root_pubkey33: &[u8; 33], salt: &[u8; 32]) -> (Pubkey, u8) {
    account_pda(&derive_owner_seed(root_pubkey33, salt))
}

/// Set the SVM's `Clock` sysvar `unix_timestamp` — the only way `Clock::get()`
/// on-chain observes a different "now" than wall-clock time. Every root
/// ceremony and every `freeze`/`unfreeze` timelock check reads this, not
/// slots (Global Constraints: "Time source"). Named `warp_clock` (not
/// `set_clock`) because most calls are advancing time forward past a
/// timelock, not merely pinning it once at setup — `freeze.rs` uses it for
/// exactly that (advance past `policy.timelock_secs`, then `unfreeze`).
pub fn warp_clock(svm: &mut LiteSVM, unix_timestamp: i64) {
    let mut c: Clock = svm.get_sysvar();
    c.unix_timestamp = unix_timestamp;
    svm.set_sysvar(&c);
}

/// The `Clock` sysvar's current `slot` — what a root ceremony must sign as its
/// `signed_slot` (spec §4, rev 8: `signed_slot <= Clock::slot < signed_slot +
/// MAX_ROOT_SLOT_AGE`).
///
/// Every ceremony helper in the suite reads this rather than hardcoding a
/// value, so a test that never mentions slots gets a fresh, valid one by
/// default and only the freshness tests bend it.
pub fn current_slot(svm: &LiteSVM) -> u64 {
    let c: Clock = svm.get_sysvar();
    c.slot
}

/// Load the test-only middleman program (`programs/test-middleman`) into an
/// existing SVM. Only the `stack_height` tests need it, so it is not part of
/// `setup`.
pub fn add_middleman(svm: &mut LiteSVM) -> Pubkey {
    let so = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/deploy/test_middleman.so"
    ))
    .expect("run `anchor build` first — see docs/TOOLCHAIN.md");
    let id = middleman_program_id();
    svm.add_program(id, &so).expect("add_program(test_middleman)");
    id
}

/// Fields a test wants to vary when planting a `SmartAccount`.
///
/// `generation` defaults to 0 and **`root_nonce` defaults to 1** because that
/// is what the real `create_account` instruction produces since Phase 1B Task
/// 2b: creation itself is a root ceremony, and it consumes its own nonce. The
/// defaults are not test conveniences — `create_smart_account` asserts them on
/// input and gets them back from LiteSVM. A test that needs a *different*
/// generation/nonce (there is no instruction yet that advances `generation`,
/// and reaching a given `root_nonce` other than 1 or 2 would mean replaying
/// several real ceremonies first) still has `set_smart_account` for exactly
/// that reason — see `root_verify.rs` for which tests do this and why.
pub struct SmartAccountFixture {
    /// The 32 client-chosen random bytes that, TOGETHER WITH the root key,
    /// derive `owner_seed` and therefore the address (Phase 1B Task 2b).
    /// Replaces 1A's `owner_seed` field: the seed is no longer a client input.
    pub salt: [u8; 32],
    pub root_pubkey33: [u8; 33],
    /// `false` plants an Ed25519 root instead, to prove the passkey path
    /// refuses to run for it.
    pub root_is_passkey: bool,
    pub origin: String,
    /// Defaults to SHA-256(origin); a test can plant a deliberately wrong one
    /// via `set_smart_account` (never via `create_smart_account`, which
    /// always recomputes and enforces the real hash, same as the program).
    pub rp_id_hash: Option<[u8; 32]>,
    pub cluster_tag: [u8; 32],
    pub generation: u64,
    pub policy_version: u32,
    pub root_nonce: u64,
    /// The policy `create_account` is asked to install. Defaults to
    /// `default_policy_args()` (no mints, `session_ops_ceiling = 0`), which is
    /// what the root-verify suite wants; the sessions suite overrides it with
    /// a policy that actually configures `session_ceiling` entries and an ops
    /// ceiling, since `grant_session` validates against exactly those.
    pub policy: PolicyArgs,
}

impl Default for SmartAccountFixture {
    fn default() -> Self {
        Self {
            salt: [7u8; 32],
            root_pubkey33: [0u8; 33],
            root_is_passkey: true,
            origin: passkey::TEST_ORIGIN.to_string(),
            rp_id_hash: None,
            cluster_tag: [0x5Au8; 32],
            generation: 0,
            policy_version: 1,
            root_nonce: 1,
            policy: default_policy_args(),
        }
    }
}

/// A `Policy` that satisfies every `create_account` validation rule and uses
/// no mint caps (every slot unused) — the shape most tests want, since
/// they're exercising the root-verify path, not the policy lattice.
pub fn default_policy_args() -> PolicyArgs {
    PolicyArgs {
        version: 1,
        caps: vec![],
        session_ceiling: vec![],
        large_threshold: vec![],
        timelock_secs: MIN_TIMELOCK_SECS,
        recovery_delay_secs: MIN_TIMELOCK_SECS,
        max_session_life_secs: MAX_SESSION_LIFE_SECS,
        session_ops_ceiling: 0,
    }
}

/// The `create_account` instruction itself. Since Phase 1B Task 2b it carries
/// the Instructions sysvar (the root ceremony needs it) and `args` carries a
/// `root_assertion` — see `sign_create`, which fills that in with a real
/// assertion. Calling this with a placeholder assertion is what the
/// "no ceremony" negative tests want.
pub fn create_account_ix(payer: Pubkey, smart_account: Pubkey, args: &CreateAccountArgs) -> Instruction {
    let mut data = Sha256::digest(b"global:create_account")[..8].to_vec();
    args.serialize(&mut data).unwrap();
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(smart_account, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
            AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
        ],
        data,
    }
}

/// A syntactically valid but *unsigned* `RootArgs`, for building a
/// `create_account` that carries no real ceremony. `sign_create` overwrites it.
pub fn placeholder_root_args() -> RootArgs {
    RootArgs {
        precompile_ix_index: 0,
        authenticator_data: passkey::authenticator_data(passkey::rp_id_hash(passkey::TEST_ORIGIN), passkey::FLAGS_UP_UV),
        client_data_json: passkey::client_data_json(&[b'A'; 43], passkey::TEST_ORIGIN),
        expiry_ts: 0,
        signed_slot: 0,
    }
}

/// Assemble a `CreateAccountArgs` with a placeholder assertion — the shape
/// every test starts from before `sign_create` signs it.
pub fn create_args(
    root: RootKey,
    salt: [u8; 32],
    origin: &str,
    cluster_tag: [u8; 32],
    policy: PolicyArgs,
) -> CreateAccountArgs {
    CreateAccountArgs {
        root_key: root,
        root_assertion: placeholder_root_args(),
        salt,
        rp_id_hash: passkey::rp_id_hash(origin),
        origin: origin.as_bytes().to_vec(),
        cluster_tag,
        policy,
    }
}

/// Produce a REAL root ceremony for `args`, write it into
/// `args.root_assertion`, and return `(derived pda, [precompile_ix,
/// create_account_ix])` — the two-instruction transaction the extension will
/// build.
///
/// The ceremony is honest **for whatever `args` says**, deliberately: a
/// negative test that bends `origin`, `cluster_tag` or the policy still gets a
/// correctly-signed assertion over the bent value, so the failure it observes
/// is the program's own rule and not an incidental `ChallengeMismatch`. To
/// test the binding itself, sign first and mutate `args` afterwards (see
/// `create_pop.rs`).
///
/// `pk` is the key that SIGNS. It is not required to be `args.root_key` — the
/// squat-race tests need exactly that mismatch, and the program must reject it
/// at the precompile binding.
pub fn sign_create(
    svm: &LiteSVM,
    payer: Pubkey,
    pk: &passkey::TestPasskey,
    args: &mut CreateAccountArgs,
) -> (Pubkey, Vec<Instruction>) {
    let clock: Clock = svm.get_sysvar();
    let expiry_ts = clock.unix_timestamp + 60;
    let signed_slot = clock.slot;

    let root33 = match &args.root_key {
        RootKey::P256Passkey { pubkey } => *pubkey,
        RootKey::Ed25519 { pubkey } => {
            let mut b = [0u8; 33];
            b[1..33].copy_from_slice(pubkey.as_ref());
            b
        }
    };
    let (pda, _bump) = account_pda_for(&root33, &args.salt);

    // The signed document, rebuilt exactly the way the handler rebuilds it.
    let rp_id_hash: [u8; 32] = Sha256::digest(&args.origin).into();
    let mut policy_bytes = Vec::new();
    args.policy.serialize(&mut policy_bytes).unwrap();
    let body = CreateBody {
        salt: args.salt,
        rp_id_hash,
        origin: args.origin.clone(),
        cluster_tag: args.cluster_tag,
        policy_hash: solana_keccak_hasher::hashv(&[&policy_bytes]).to_bytes(),
    };
    let mut body_bytes = Vec::new();
    body.serialize(&mut body_bytes).unwrap();

    // A newborn account's transcript state: generation 0, policy_version 1,
    // root_nonce 0 — the values the handler hardcodes.
    let t = transcript_hash(
        &args.cluster_tag,
        &program_id(),
        &pda,
        0,
        1,
        0,
        expiry_ts,
        signed_slot,
        &action_hash(OP_CREATE, &body_bytes),
    );
    let origin_str = String::from_utf8_lossy(&args.origin).into_owned();
    let assertion = pk.assert_(&b64url_no_pad(&t), &origin_str, rp_id_hash, passkey::FLAGS_UP_UV);

    args.root_assertion = RootArgs {
        precompile_ix_index: 0,
        authenticator_data: assertion.authenticator_data.clone(),
        client_data_json: assertion.client_data_json.clone(),
        expiry_ts,
        signed_slot,
    };
    let ixs = vec![
        passkey::precompile_ix(&assertion, &pk.pubkey33()),
        create_account_ix(payer, pda, args),
    ];
    (pda, ixs)
}

/// Create a `SmartAccount` through the real `create_account` instruction —
/// including the mandatory root ceremony (Phase 1B Task 2b).
///
/// `pk` must be the passkey the fixture's `root_pubkey33` names: it both roots
/// the account and signs the creating assertion. Every suite in this repo
/// builds its accounts through here, so the ceremony is exercised on every
/// single test run rather than only in `create_pop.rs`.
///
/// **Policies with more than `MAX_MINTS_AT_CREATE` mints.** Since proof of
/// possession landed, a `create_account` transaction only has room for
/// `MAX_MINTS_AT_CREATE` mints (see `constants::MAX_MINTS_AT_CREATE` for the
/// measured table). Suites that need a richer policy — `transfer.rs` needs SOL
/// **and** a token, `sessions.rs` needs three mints — get it the way a real
/// wallet will: the account is created for real, with a real ceremony, at its
/// real derived address, carrying the scalar policy and as many mints as fit;
/// the remaining caps are then written in directly, standing in for the Phase
/// 1C `set_policy` instruction that does not exist yet. Only the extra caps
/// are planted — never the account, the root, the seed or the nonce.
///
/// Only `salt`/`root_*`/`origin`/`cluster_tag`/`policy` are honoured:
/// `generation`/`policy_version` must be at the values `create_account` itself
/// produces, and `root_nonce` must be 1 — the creating ceremony is consumed,
/// so a freshly created account starts at nonce 1, not 0. A fixture that needs
/// anything else cannot be built through the instruction and must use
/// `set_smart_account`.
pub fn create_smart_account(
    svm: &mut LiteSVM,
    payer: &Keypair,
    f: &SmartAccountFixture,
    pk: &passkey::TestPasskey,
) -> Pubkey {
    assert_eq!(f.generation, 0, "create_account always sets generation = 0");
    assert_eq!(
        f.root_nonce, 1,
        "create_account CONSUMES its own ceremony: a created account starts at root_nonce = 1"
    );
    assert_eq!(f.policy_version, 1, "create_account always forces policy.version = 1");
    assert!(f.rp_id_hash.is_none(), "create_account recomputes rp_id_hash from origin itself");
    assert!(f.root_is_passkey, "create_account refuses an Ed25519 root; plant it instead");
    assert_eq!(
        pk.pubkey33(),
        f.root_pubkey33,
        "the signing passkey must be the fixture's root key"
    );

    let over_packet_budget = f.policy.caps.len() > MAX_MINTS_AT_CREATE
        || f.policy.session_ceiling.len() > MAX_MINTS_AT_CREATE
        || f.policy.large_threshold.len() > MAX_MINTS_AT_CREATE;
    let creatable = if over_packet_budget {
        // Same scalars, no mints — everything `create_account` can carry.
        PolicyArgs {
            caps: vec![],
            session_ceiling: vec![],
            large_threshold: vec![],
            ..f.policy.clone()
        }
    } else {
        f.policy.clone()
    };

    let mut args = create_args(
        RootKey::P256Passkey { pubkey: f.root_pubkey33 },
        f.salt,
        &f.origin,
        f.cluster_tag,
        creatable,
    );
    let (pda, ixs) = sign_create(svm, payer.pubkey(), pk, &mut args);
    let tx = Transaction::new(&[payer], Message::new(&ixs, Some(&payer.pubkey())), svm.latest_blockhash());
    svm.send_transaction(tx)
        .unwrap_or_else(|e| panic!("create_account must succeed: {:?} {:#?}", e.err, e.meta.logs));

    if over_packet_budget {
        write_policy(svm, &pda, &f.policy);
    }
    pda
}

/// **TEST-ONLY back door**, and a narrow one: overwrite only the `policy`
/// field of an account created by the real instruction, leaving every other
/// byte — root, seed, bump, nonce, buckets, lamports — exactly as
/// `create_account` wrote it.
///
/// Stands in for Phase 1C's `set_policy`. See `create_smart_account` for why
/// it is needed at all (`MAX_MINTS_AT_CREATE` is a packet bound, and the
/// transfer/sessions suites need more mints than one packet holds).
pub fn write_policy(svm: &mut LiteSVM, pda: &Pubkey, policy: &PolicyArgs) {
    let existing = svm.get_account(pda).expect("account exists");
    let mut acc = read_smart_account(svm, pda);
    acc.policy = policy.expand().expect("fixture policy must expand");
    acc.policy.version = 1;
    let mut data = SmartAccount::DISCRIMINATOR.to_vec();
    data.extend_from_slice(bytemuck::bytes_of(&acc));
    assert_eq!(data.len(), SmartAccount::LEN);
    svm.set_account(
        *pda,
        Account {
            lamports: existing.lamports,
            data,
            owner: existing.owner,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account");
}

/// Plant a fully-formed `SmartAccount` directly into the SVM, bypassing
/// `create_account` entirely.
///
/// KEPT DELIBERATELY (Task 4 retired most callers to `create_smart_account`
/// above, which goes through the real instruction): three `root_verify.rs`
/// cases still need this because no sequence of real instructions can
/// produce their starting state —
/// - `non_pda_account_rejected`: an account at an address that is NOT the
///   PDA for its own `owner_seed`. `create_account`'s `seeds` constraint
///   derives the address itself, so this is impossible through it by
///   construction, not just inconvenient.
/// - `stale_generation_rejected`: `generation != 0`. No instruction in this
///   program advances `generation` yet (that lands with the policy/guardian
///   work in Phase 1B).
/// - `stale_nonce_far_in_the_past_rejected_as_challenge_mismatch`:
///   `root_nonce == 5`. Reaching this via 5 real `rotate_nonce` ceremonies is
///   *possible*, but would only re-prove what
///   `consecutive_ceremonies_each_consume_one_nonce`/
///   `replay_same_assertion_rejected` already cover; this test's whole point
///   is the "stale by more than one, not just a replay" case, which planting
///   the state directly demonstrates with far less incidental machinery.
///
/// Hand-building the bytes is exactly the `#[account(zero_copy)]` on-wire
/// format: the 8-byte Anchor discriminator followed by the `Pod` bytes
/// (`anchor_discriminator_is_sha256_of_account_name` pins that claim).
pub fn set_smart_account(svm: &mut LiteSVM, f: &SmartAccountFixture) -> Pubkey {
    // The seed is derived exactly as `create_account` derives it, so a planted
    // account is addressed the same way a real one is — `root_verify.rs`'s PDA
    // re-derivation check must pass for it. (The Ed25519 fixture hashes the
    // same 33 bytes it stores; it never goes through `create_account`, and the
    // only property that matters is self-consistency between the address and
    // the stored `owner_seed`.)
    let owner_seed = derive_owner_seed(&f.root_pubkey33, &f.salt);
    let (pda, bump) = account_pda(&owner_seed);
    let mut acc: SmartAccount = bytemuck::Zeroable::zeroed();
    acc.version = 1;
    acc.bump = bump;
    acc.owner_seed = owner_seed;
    if f.root_is_passkey {
        acc.set_root(&RootKey::P256Passkey { pubkey: f.root_pubkey33 });
    } else {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&f.root_pubkey33[..32]);
        acc.set_root(&RootKey::Ed25519 { pubkey: Pubkey::from(pk) });
    }
    let ob = f.origin.as_bytes();
    assert!(ob.len() <= 64, "origin too long for the fixed field");
    acc.origin[..ob.len()].copy_from_slice(ob);
    acc.origin_len = ob.len() as u8;
    acc.rp_id_hash = f.rp_id_hash.unwrap_or_else(|| passkey::rp_id_hash(&f.origin));
    acc.cluster_tag = f.cluster_tag;
    acc.generation = f.generation;
    acc.policy = f.policy.expand().expect("fixture policy must expand");
    acc.policy.version = f.policy_version;
    acc.root_nonce = f.root_nonce;

    let mut data = SmartAccount::DISCRIMINATOR.to_vec();
    data.extend_from_slice(bytemuck::bytes_of(&acc));
    assert_eq!(data.len(), SmartAccount::LEN);

    svm.set_account(
        pda,
        Account {
            lamports: 10_000_000_000,
            data,
            owner: program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account");
    pda
}

/// Read a planted account back out of the SVM.
pub fn read_smart_account(svm: &LiteSVM, pda: &Pubkey) -> SmartAccount {
    let raw = svm.get_account(pda).expect("account exists").data;
    assert_eq!(&raw[..8], SmartAccount::DISCRIMINATOR, "discriminator");
    *bytemuck::from_bytes::<SmartAccount>(&raw[8..])
}

// ---------------------------------------------------------------------------
// Sessions (Task 5)
// ---------------------------------------------------------------------------

pub fn session_pda(smart_account: &Pubkey, session_pubkey: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[SESSION_SEED, smart_account.as_ref(), session_pubkey.as_ref()],
        &program_id(),
    )
}

/// Read a `SessionKey` PDA back out of the SVM through Anchor's own
/// deserializer (so the discriminator is checked, not assumed).
pub fn read_session(svm: &LiteSVM, pda: &Pubkey) -> SessionKey {
    let raw = svm.get_account(pda).expect("session account exists").data;
    SessionKey::try_deserialize(&mut raw.as_slice()).expect("valid SessionKey")
}

/// **TEST-ONLY back door.** Overwrite a `SessionKey` PDA's bytes in place,
/// keeping its lamports and owner.
///
/// Needed because Phase 1A has no instruction that *spends* from a session:
/// `lifetime_spent` is only ever written by the transfer path, which lands in
/// Task 6. The re-grant tests (`regrant_merges_by_mint_and_preserves_spent`,
/// `regrant_lower_lifetime_than_spent_rejected`) must start from a session
/// with a non-zero spend history, and planting it is the only way to reach
/// that state today. Nothing in the program does this; when Task 6 lands, the
/// same assertions could be re-derived from real transfers instead.
pub fn write_session(svm: &mut LiteSVM, pda: &Pubkey, session: &SessionKey) {
    let existing = svm.get_account(pda).expect("session account exists");
    let mut data = SessionKey::DISCRIMINATOR.to_vec();
    session.serialize(&mut data).unwrap();
    assert_eq!(data.len(), SessionKey::LEN, "SessionKey::LEN must match the serialized size");
    svm.set_account(
        *pda,
        Account {
            lamports: existing.lamports,
            data,
            owner: existing.owner,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account");
}

/// **TEST-ONLY back door.** Zero out `policy.caps[idx]` (and its parallel
/// bucket) in place, leaving every other byte untouched.
///
/// Needed because Phase 1A has no `set_policy` instruction (it lands in 1B):
/// there is no honest sequence of instructions that removes an account-level
/// cap while a session still holds one for the same mint. That combination is
/// exactly what `transfer::session_mint_without_account_cap_rejected` needs in
/// order to reach the ACCOUNT-WIDE policy lookup — with an intact policy, a
/// mint a session cannot spend is refused earlier, at the session's own cap
/// lookup, and the policy lookup is never exercised.
pub fn clear_policy_cap(svm: &mut LiteSVM, pda: &Pubkey, idx: usize) {
    let existing = svm.get_account(pda).expect("account exists");
    let mut acc = read_smart_account(svm, pda);
    acc.policy.caps[idx] = warden::state::MintCap::default();
    acc.buckets[idx] = warden::state::MintBuckets::default();
    let mut data = SmartAccount::DISCRIMINATOR.to_vec();
    data.extend_from_slice(bytemuck::bytes_of(&acc));
    assert_eq!(data.len(), SmartAccount::LEN);
    svm.set_account(
        *pda,
        Account {
            lamports: existing.lamports,
            data,
            owner: existing.owner,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account");
}

/// **TEST-ONLY back door.** Advance a `SmartAccount`'s `generation` by
/// `delta`, leaving every other byte untouched.
///
/// Needed because no Phase 1A instruction bumps `generation` — the key
/// rotation / recovery paths that do land in Phase 1B. Used by
/// `revoke_close_then_regrant_gets_current_generation` to prove a re-grant
/// picks up the *current* generation rather than the one baked in at first
/// creation.
pub fn bump_generation(svm: &mut LiteSVM, pda: &Pubkey, delta: u64) -> u64 {
    let existing = svm.get_account(pda).expect("account exists");
    let mut acc = read_smart_account(svm, pda);
    acc.generation = acc.generation.checked_add(delta).unwrap();
    let generation = acc.generation;
    let mut data = SmartAccount::DISCRIMINATOR.to_vec();
    data.extend_from_slice(bytemuck::bytes_of(&acc));
    assert_eq!(data.len(), SmartAccount::LEN);
    svm.set_account(
        *pda,
        Account {
            lamports: existing.lamports,
            data,
            owner: existing.owner,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account");
    generation
}
