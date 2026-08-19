//! LiteSVM coverage of `grant_session` / `revoke_session_root` /
//! `revoke_session_self` (Task 5).
//!
//! Transaction shape for the two root-authorized paths (the one the extension
//! will build):
//! ```text
//!   ix[0] = Secp256r1SigVerify precompile over (pubkey33, sig64, message)
//!   ix[1] = warden::grant_session | warden::revoke_session_root
//! ```
//! Every ceremony here is a REAL signed assertion produced by the test
//! passkey over the honest transcript for the account's current on-chain
//! state — the negative cases bend the *grant body*, not the signature, so
//! they exercise the program's own rules rather than a cooperative signer.
//!
//! **Byte budget is a hard gate here.** LiteSVM has no wire layer and will
//! happily execute a transaction that a real validator would drop before
//! execution, so `grant_tx_fits_1232_bytes_with_2_caps` measures the real
//! serialized transaction and asserts the limit rather than printing it.

mod common;

use anchor_lang::{AnchorSerialize, Discriminator};
use common::passkey::{self, TestPasskey, FLAGS_UP_UV, TEST_ORIGIN};
use common::{
    bump_generation, create_smart_account, read_session, read_smart_account, session_pda,
    write_session, SmartAccountFixture,
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
use std::str::FromStr;
use warden::constants::{MAX_CAPS_PER_GRANT, MAX_MINT_CAPS, SESSION_KIND_ED25519};
use warden::instructions::create_account::MIN_TIMELOCK_SECS;
use warden::instructions::grant_session::{GrantBody, GrantSessionArgs};
use warden::instructions::revoke_session::{RevokeBody, RevokeSessionRootArgs};
use warden::root_verify::transcript::{
    action_hash, b64url_no_pad, transcript_hash, OP_GRANT_SESSION, OP_REVOKE_SESSION,
};
use warden::root_verify::RootArgs;
use warden::state::{MintCap, PolicyArgs, SessionKey, OP_EXECUTE, OP_SIGN_MESSAGE, OP_SWAP, OP_TRANSFER};

const NOW: i64 = 1_760_000_000;
/// Solana's transaction packet limit (`PACKET_DATA_SIZE`).
const PACKET_DATA_SIZE: usize = 1232;
/// The `expiry_ts` of the *ceremony* (≤ 600 s out), not of the session.
const ROOT_EXPIRY: i64 = NOW + 60;
/// The fixture policy's `max_session_life_secs`: 7 days.
const SESSION_LIFE: i64 = 7 * 86_400;

/// Anchor error codes as literals — the same pinned table as
/// `root_verify.rs`'s `mod err` (6000 + declaration index), whose
/// `pinned_error_codes_match_the_enum_today` is the single place the enum is
/// consulted. Task 4's additions start at 6025.
mod err {
    pub const UNAUTHORIZED: u32 = 6002;
    pub const NONCE_MISMATCH: u32 = 6004;
    pub const EXPIRED: u32 = 6005;
    pub const CAP_EXCEEDED: u32 = 6006;
    pub const OP_NOT_ALLOWED: u32 = 6008;
    pub const INVALID_ACCOUNT_DATA: u32 = 6009;
    pub const BAD_INSTRUCTION_LAYOUT: u32 = 6010;
    pub const INVALID_POLICY: u32 = 6027;
    pub const CHALLENGE_MISMATCH: u32 = 6018;
    pub const PROGRAM_ALLOWLIST_UNSUPPORTED: u32 = 6028;
    pub const SESSION_DAY_CAPS_UNSUPPORTED: u32 = 6033;
    pub const SESSION_PRIOR_STATE_MISMATCH: u32 = 6035;
}

// ---------------------------------------------------------------------------
// Fixture policy
// ---------------------------------------------------------------------------

fn sol_mint() -> Pubkey {
    Pubkey::from_str("So11111111111111111111111111111111111111112").unwrap()
}
fn usdc_mint() -> Pubkey {
    Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap()
}
/// A mint the policy gives an account-level cap but NO `session_ceiling`
/// entry — "sessions may not touch this mint".
fn ungranted_mint() -> Pubkey {
    Pubkey::from_str("DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263").unwrap()
}

/// SOL + USDC grantable to sessions, plus one mint that is capped at the
/// account level but has no session ceiling. `session_ops_ceiling` allows
/// transfer/execute/swap but not sign-message.
fn session_policy() -> PolicyArgs {
    let sol = sol_mint();
    let usdc = usdc_mint();
    PolicyArgs {
        version: 1,
        caps: vec![
            MintCap { mint: sol, per_tx: 5_000_000_000, per_day: 20_000_000_000, per_30d: 200_000_000_000 },
            MintCap { mint: usdc, per_tx: 1_000_000_000, per_day: 5_000_000_000, per_30d: 50_000_000_000 },
            MintCap { mint: ungranted_mint(), per_tx: 1_000, per_day: 2_000, per_30d: 3_000 },
        ],
        session_ceiling: vec![
            MintCap { mint: sol, per_tx: 1_000_000_000, per_day: 5_000_000_000, per_30d: 50_000_000_000 },
            MintCap { mint: usdc, per_tx: 500_000_000, per_day: 2_000_000_000, per_30d: 20_000_000_000 },
        ],
        large_threshold: vec![],
        timelock_secs: MIN_TIMELOCK_SECS,
        recovery_delay_secs: MIN_TIMELOCK_SECS,
        max_session_life_secs: SESSION_LIFE,
        session_ops_ceiling: OP_TRANSFER | OP_EXECUTE | OP_SWAP,
    }
}

/// The heaviest cap a session may be granted for each mint: `per_tx` exactly
/// at the policy ceiling, with `per_day`/`per_30d` **zero**.
///
/// Phase 1A rejects a session cap that sets either
/// (`SessionDayCapsUnsupported`, `grant_with_session_day_caps_rejected`):
/// day and rolling-30-day limits are account-wide, so a per-session copy would
/// be stored and enforced by nothing. The bound a session gives you is
/// `per_tx x (calls) <= lifetime_cap`, under the account's own day/30d
/// buckets.
fn sol_cap() -> MintCap {
    MintCap { mint: sol_mint(), per_tx: 1_000_000_000, per_day: 0, per_30d: 0 }
}
fn usdc_cap() -> MintCap {
    MintCap { mint: usdc_mint(), per_tx: 500_000_000, per_day: 0, per_30d: 0 }
}

fn label(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let b = s.as_bytes();
    assert!(b.len() <= 16);
    out[..b.len()].copy_from_slice(b);
    out
}

/// A realistic 2-cap grant: SOL + USDC at the policy ceiling, transfer+swap,
/// six days of life. This is the body the byte-budget test measures.
fn two_cap_body(session_pubkey: Pubkey) -> GrantBody {
    GrantBody {
        expiry_ts: NOW + 6 * 86_400,
        session_pubkey,
        kind: SESSION_KIND_ED25519,
        ops_mask: OP_TRANSFER | OP_SWAP,
        caps: vec![sol_cap(), usdc_cap()],
        lifetime_cap: vec![100_000_000_000, 40_000_000_000],
        program_allowlist_id: 0,
        label: label("trading-bot"),
        // Default: a FRESH grant. Re-grant tests overwrite this with
        // `prior_hash(&svm, &session)` — see `regrant_*`.
        prior_authority_hash: [0u8; 32],
    }
}

fn one_cap_body(session_pubkey: Pubkey) -> GrantBody {
    GrantBody {
        caps: vec![sol_cap()],
        lifetime_cap: vec![100_000_000_000],
        ..two_cap_body(session_pubkey)
    }
}

/// The value `GrantBody.prior_authority_hash` must carry for a RE-grant: the
/// retained authority of the session as it stands right now
/// (milestone-review binding — see `grant_session`'s module docs).
fn prior_hash(svm: &LiteSVM, session: &Pubkey) -> [u8; 32] {
    read_session(svm, session).authority_hash()
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn set_clock(svm: &mut LiteSVM, unix_timestamp: i64) {
    let mut c: Clock = svm.get_sysvar();
    c.unix_timestamp = unix_timestamp;
    svm.set_sysvar(&c);
}

/// A live SVM with one real, passkey-rooted account carrying `session_policy`.
fn live() -> (LiteSVM, Keypair, TestPasskey, Pubkey) {
    let (mut svm, payer) = common::setup();
    set_clock(&mut svm, NOW);
    let pk = TestPasskey::new(3);
    let f = SmartAccountFixture {
        root_pubkey33: pk.pubkey33(),
        policy: session_policy(),
        ..Default::default()
    };
    let account = create_smart_account(&mut svm, &payer, &f, &pk);
    (svm, payer, pk, account)
}

fn grant_ix(payer: Pubkey, smart_account: Pubkey, session: Pubkey, args: &GrantSessionArgs) -> Instruction {
    let mut data = Sha256::digest(b"global:grant_session")[..8].to_vec();
    args.serialize(&mut data).unwrap();
    Instruction {
        program_id: common::program_id(),
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(smart_account, false),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(sysvar::instructions::ID, false),
            AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
        ],
        data,
    }
}

fn revoke_root_ix(
    payer: Pubkey,
    smart_account: Pubkey,
    session: Pubkey,
    args: &RevokeSessionRootArgs,
) -> Instruction {
    let mut data = Sha256::digest(b"global:revoke_session_root")[..8].to_vec();
    args.serialize(&mut data).unwrap();
    Instruction {
        program_id: common::program_id(),
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(smart_account, false),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(sysvar::instructions::ID, false),
        ],
        data,
    }
}

fn revoke_self_ix(
    payer: Pubkey,
    session_signer: Pubkey,
    smart_account: Pubkey,
    session: Pubkey,
) -> Instruction {
    let data = Sha256::digest(b"global:revoke_session_self")[..8].to_vec();
    Instruction {
        program_id: common::program_id(),
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(session_signer, true),
            AccountMeta::new_readonly(smart_account, false),
            AccountMeta::new(session, false),
        ],
        data,
    }
}

/// Sign the honest transcript for `action_hash` against the account's CURRENT
/// on-chain state (generation / policy version / root nonce read back from the
/// SVM, exactly as the extension would).
fn ceremony(svm: &LiteSVM, account: &Pubkey, pk: &TestPasskey, ah: [u8; 32]) -> (Instruction, RootArgs) {
    let st = read_smart_account(svm, account);
    // Signed slot = the slot the client observes (spec §4). This suite pins
    // `expiry_ts` to a constant and never warps the clock, so reading the
    // SVM's live slot is both the honest client behaviour and always fresh.
    let clock: solana_sdk::clock::Clock = svm.get_sysvar();
    let signed_slot = clock.slot;
    let t = transcript_hash(
        &st.cluster_tag,
        &common::program_id(),
        account,
        st.generation,
        st.policy.version,
        st.root_nonce,
        ROOT_EXPIRY,
        signed_slot,
        &ah,
    );
    let a = pk.assert_with_client_data(
        passkey::client_data_json(&b64url_no_pad(&t), TEST_ORIGIN),
        passkey::rp_id_hash(TEST_ORIGIN),
        FLAGS_UP_UV,
    );
    let args = RootArgs {
        precompile_ix_index: 0,
        authenticator_data: a.authenticator_data.clone(),
        client_data_json: a.client_data_json.clone(),
        expiry_ts: ROOT_EXPIRY,
        signed_slot,
    };
    (passkey::precompile_ix(&a, &pk.pubkey33()), args)
}

/// Sign `signed` but SUBMIT `submitted`. The session account is derived from
/// the submitted body so Anchor's own `seeds` constraint is satisfied and the
/// rejection has to come from the challenge binding, not from the PDA check.
fn grant_ixs_tampered(
    svm: &LiteSVM,
    payer: &Keypair,
    account: &Pubkey,
    pk: &TestPasskey,
    signed: &GrantBody,
    submitted: GrantBody,
) -> Vec<Instruction> {
    let mut body_bytes = Vec::new();
    signed.serialize(&mut body_bytes).unwrap();
    let (precompile, root) = ceremony(svm, account, pk, action_hash(OP_GRANT_SESSION, &body_bytes));
    let (session, _) = session_pda(account, &submitted.session_pubkey);
    let args = GrantSessionArgs { root, body: submitted };
    vec![precompile, grant_ix(payer.pubkey(), *account, session, &args)]
}

fn grant_ixs(
    svm: &LiteSVM,
    payer: &Keypair,
    account: &Pubkey,
    pk: &TestPasskey,
    body: GrantBody,
) -> Vec<Instruction> {
    grant_ixs_tampered(svm, payer, account, pk, &body.clone(), body)
}

/// `session_account` and `submitted_payer` are passed separately from the
/// SIGNED `session_pubkey`/`refund_to` so the adversarial tests can point the
/// instruction at a different session, or at a different rent destination,
/// than the ceremony authorized.
#[allow(clippy::too_many_arguments)]
fn revoke_root_ixs_with(
    svm: &LiteSVM,
    account: &Pubkey,
    pk: &TestPasskey,
    signed_session_pubkey: Pubkey,
    signed_refund_to: Pubkey,
    session_account: Pubkey,
    submitted_payer: Pubkey,
) -> Vec<Instruction> {
    let body = RevokeBody { session_pubkey: signed_session_pubkey, refund_to: signed_refund_to };
    let mut payload = Vec::new();
    body.serialize(&mut payload).unwrap();
    let (precompile, root) = ceremony(svm, account, pk, action_hash(OP_REVOKE_SESSION, &payload));
    let args = RevokeSessionRootArgs { root, body };
    vec![precompile, revoke_root_ix(submitted_payer, *account, session_account, &args)]
}

/// The honest shape: the ceremony names the session being closed and the
/// payer as the rent destination.
fn revoke_root_ixs(
    svm: &LiteSVM,
    payer: &Keypair,
    account: &Pubkey,
    pk: &TestPasskey,
    session_pubkey: Pubkey,
    session_account: Pubkey,
) -> Vec<Instruction> {
    revoke_root_ixs_with(
        svm,
        account,
        pk,
        session_pubkey,
        payer.pubkey(),
        session_account,
        payer.pubkey(),
    )
}

fn send(svm: &mut LiteSVM, signers: &[&Keypair], ixs: &[Instruction]) -> litesvm::types::TransactionResult {
    svm.expire_blockhash();
    let tx = Transaction::new(
        signers,
        Message::new(ixs, Some(&signers[0].pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
}

fn expect_ok(svm: &mut LiteSVM, signers: &[&Keypair], ixs: &[Instruction]) -> litesvm::types::TransactionMetadata {
    send(svm, signers, ixs).unwrap_or_else(|e| panic!("must succeed: {:?} {:#?}", e.err, e.meta.logs))
}

fn expect_reject(svm: &mut LiteSVM, signers: &[&Keypair], ixs: &[Instruction], ix_index: u8, expected: u32) {
    let e = send(svm, signers, ixs).expect_err("must be rejected");
    assert_eq!(
        e.err,
        TransactionError::InstructionError(ix_index, InstructionError::Custom(expected)),
        "wrong failure mode; logs={:#?}",
        e.meta.logs
    );
    assert!(
        !e.meta.logs.iter().any(|l| l.contains("panicked")),
        "program panicked instead of returning an error: {:#?}",
        e.meta.logs
    );
}

/// A grant that is rejected must leave no session behind and must not consume
/// the account's `root_nonce`.
fn expect_grant_reject(body: GrantBody, expected: u32) {
    let (mut svm, payer, pk, account) = live();
    let nonce_before = read_smart_account(&svm, &account).root_nonce;
    let (session, _) = session_pda(&account, &body.session_pubkey);
    let ixs = grant_ixs(&svm, &payer, &account, &pk, body);
    expect_reject(&mut svm, &[&payer], &ixs, 1, expected);
    assert!(svm.get_account(&session).is_none_or(|a| a.data.is_empty()), "no session PDA may survive a rejected grant");
    assert_eq!(
        read_smart_account(&svm, &account).root_nonce,
        nonce_before,
        "a rejected grant must not consume the nonce"
    );
}

fn is_closed(svm: &LiteSVM, pda: &Pubkey) -> bool {
    svm.get_account(pda).is_none_or(|a| a.lamports == 0 && a.data.is_empty())
}

// ---------------------------------------------------------------------------
// Pinned facts
// ---------------------------------------------------------------------------

/// The hand-encoded discriminators above are only valid if Anchor's
/// global-instruction discriminator really is SHA-256("global:<name>")[..8],
/// and the account discriminator SHA-256("account:<Name>")[..8] (which
/// `common::read_session`/`write_session` rely on).
#[test]
fn discriminators_are_sha256_of_the_global_names() {
    let ix = grant_ix(
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        &GrantSessionArgs {
            root: RootArgs {
                precompile_ix_index: 0,
                authenticator_data: vec![],
                client_data_json: vec![],
                expiry_ts: 0,
                signed_slot: 0,
            },
            body: two_cap_body(Pubkey::new_unique()),
        },
    );
    assert_eq!(&ix.data[..8], &Sha256::digest(b"global:grant_session")[..8]);
    assert_eq!(
        &revoke_self_ix(Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique()).data[..8],
        &Sha256::digest(b"global:revoke_session_self")[..8]
    );
    let revoke_root = revoke_root_ix(
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        &RevokeSessionRootArgs {
            root: RootArgs {
                precompile_ix_index: 0,
                authenticator_data: vec![],
                client_data_json: vec![],
                expiry_ts: 0,
                signed_slot: 0,
            },
            body: RevokeBody { session_pubkey: Pubkey::new_unique(), refund_to: Pubkey::new_unique() },
        },
    );
    assert_eq!(&revoke_root.data[..8], &Sha256::digest(b"global:revoke_session_root")[..8]);
    assert_eq!(SessionKey::DISCRIMINATOR, &Sha256::digest(b"account:SessionKey")[..8]);
}

// ---------------------------------------------------------------------------
// Grant — happy path
// ---------------------------------------------------------------------------

#[test]
fn grant_ok_and_readback() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let body = two_cap_body(session_key.pubkey());
    let (session, expected_bump) = session_pda(&account, &session_key.pubkey());

    let ixs = grant_ixs(&svm, &payer, &account, &pk, body.clone());
    let res = expect_ok(&mut svm, &[&payer], &ixs);
    println!("grant_session CU: {}", res.compute_units_consumed);

    let s = read_session(&svm, &session);
    assert_eq!(s.version, 1);
    assert_eq!(s.bump, expected_bump);
    assert_eq!(s.account, account);
    assert_eq!(s.pubkey, session_key.pubkey());
    assert_eq!(s.kind, SESSION_KIND_ED25519);
    assert_eq!(s.expiry_ts, body.expiry_ts);
    assert_eq!(s.ops_mask, body.ops_mask);
    assert_eq!(s.generation_at_grant, 0);
    assert_eq!(s.program_allowlist_id, 0);
    assert_eq!(s.label, body.label);
    assert!(s.caps[0] == sol_cap(), "slot 0 holds the SOL cap as granted");
    assert!(s.caps[1] == usdc_cap(), "slot 1 holds the USDC cap as granted");
    assert_eq!(s.lifetime_cap[0], 100_000_000_000);
    assert_eq!(s.lifetime_cap[1], 40_000_000_000);
    assert!(s.lifetime_spent.iter().all(|v| *v == 0));
    assert!(s.caps[2..].iter().all(|c| c.mint == Pubkey::default()), "unused slots stay empty");
    assert!(s._reserved.iter().all(|b| *b == 0));

    assert_eq!(
        read_smart_account(&svm, &account).root_nonce,
        2,
        "the ceremony is consumed (creation itself already consumed nonce 0)"
    );
    assert!(res.compute_units_consumed < 100_000, "CU budget: {}", res.compute_units_consumed);
}

/// A grant sitting exactly ON the policy ceiling for both mints is accepted,
/// and the ceiling is looked up BY MINT: `Policy`'s arrays are keyed by the
/// `caps` slot index, so a positional read of the grant's second cap would
/// have compared USDC against SOL's (much larger) ceiling.
#[test]
fn grant_at_exactly_the_ceiling_accepted() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let ixs = grant_ixs(&svm, &payer, &account, &pk, two_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);
    let (session, _) = session_pda(&account, &session_key.pubkey());
    let s = read_session(&svm, &session);
    assert_eq!(s.caps[1].per_tx, usdc_cap().per_tx, "USDC got USDC's ceiling, not SOL's");
}

#[test]
fn grant_expiry_at_the_max_life_boundary_accepted() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let body = GrantBody { expiry_ts: NOW + SESSION_LIFE, ..one_cap_body(session_key.pubkey()) };
    let ixs = grant_ixs(&svm, &payer, &account, &pk, body);
    expect_ok(&mut svm, &[&payer], &ixs);
}

// ---------------------------------------------------------------------------
// Grant — byte budget (HARD GATE: LiteSVM does not enforce 1,232 B)
// ---------------------------------------------------------------------------

/// The whole reason `MAX_CAPS_PER_GRANT` is 2. Builds the REAL transaction —
/// secp256r1 precompile instruction from a real test-passkey assertion with a
/// canonical Chrome-shaped `clientDataJSON`, plus the grant instruction with
/// two full `MintCap`s — and asserts the serialized length, then submits it.
#[test]
fn grant_tx_fits_1232_bytes_with_2_caps() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let ixs = grant_ixs(&svm, &payer, &account, &pk, two_cap_body(session_key.pubkey()));

    // Sanity: the `clientDataJSON` inside the grant really is the canonical
    // Chrome shape (~161 B), not a trimmed test-only string that would
    // flatter the budget. Rebuilt here from a dummy transcript because the
    // real one is buried inside the already-encoded instruction data; the
    // challenge is a fixed-width 43-char base64url digest either way.
    let cdj_len = passkey::client_data_json(&b64url_no_pad(&[0u8; 32]), TEST_ORIGIN).len();
    assert!(cdj_len >= 150, "clientDataJSON is only {cdj_len} B — not a realistic Chrome shape");

    let tx = Transaction::new(&[&payer], Message::new(&ixs, Some(&payer.pubkey())), svm.latest_blockhash());
    let len = bincode::serialize(&tx).unwrap().len();
    println!(
        "grant_session ({MAX_CAPS_PER_GRANT} caps) tx: {len} B (precompile ix {} B data, grant ix {} B data, clientDataJSON {cdj_len} B)",
        ixs[0].data.len(),
        ixs[1].data.len()
    );
    assert!(
        len <= PACKET_DATA_SIZE,
        "a {MAX_CAPS_PER_GRANT}-cap grant transaction is {len} B, over the {PACKET_DATA_SIZE} B packet limit — \
         MAX_CAPS_PER_GRANT must be lowered (or the grant staged), not this assertion"
    );
    svm.send_transaction(tx).unwrap_or_else(|e| panic!("must succeed: {:?} {:#?}", e.err, e.meta.logs));
}

/// The limit is ENFORCED by the program, not merely advised by the constant:
/// a 3-cap grant is rejected on-chain even though LiteSVM would have carried
/// the bytes.
#[test]
fn grant_with_3_caps_rejected() {
    let session_key = Keypair::new();
    let mut body = two_cap_body(session_key.pubkey());
    body.caps.push(MintCap { mint: ungranted_mint(), per_tx: 1, per_day: 0, per_30d: 0 });
    body.lifetime_cap.push(1);
    assert!(body.caps.len() > MAX_CAPS_PER_GRANT);
    expect_grant_reject(body, err::BAD_INSTRUCTION_LAYOUT);
}

// ---------------------------------------------------------------------------
// Grant — rejections
// ---------------------------------------------------------------------------

/// Replaying an already-consumed ceremony: the first grant succeeds, the
/// byte-identical transaction is resubmitted under a fresh blockhash, and the
/// consumed `root_nonce` is what must turn it away.
#[test]
fn grant_needs_fresh_nonce() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let ixs = grant_ixs(&svm, &payer, &account, &pk, two_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);
    assert_eq!(read_smart_account(&svm, &account).root_nonce, 2);
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::NONCE_MISMATCH);
}

#[test]
fn grant_over_ceiling_rejected() {
    let session_key = Keypair::new();
    let mut body = one_cap_body(session_key.pubkey());
    body.caps[0].per_tx = sol_cap().per_tx + 1;
    expect_grant_reject(body, err::CAP_EXCEEDED);
}

/// Phase 1A stores no per-session day/30-day accounting, so a grant that
/// *claims* one is refused outright rather than accepted and ignored. Both
/// fields are covered, separately and together — an "only `per_30d` set" grant
/// is exactly the shape a client would produce by copying the account policy
/// wholesale.
///
/// This replaces the former `grant_over_ceiling_per_30d_rejected`: with both
/// fields pinned to 0, "over the ceiling" is unreachable for them, and
/// `grant_over_ceiling_rejected` (per_tx) still covers the ceiling rule
/// itself.
#[test]
fn grant_with_session_day_caps_rejected() {
    for (per_day, per_30d) in [(1u64, 0u64), (0, 1), (5_000_000_000, 50_000_000_000)] {
        let session_key = Keypair::new();
        let mut body = one_cap_body(session_key.pubkey());
        body.caps[0].per_day = per_day;
        body.caps[0].per_30d = per_30d;
        expect_grant_reject(body, err::SESSION_DAY_CAPS_UNSUPPORTED);
    }
}

/// A mint with an account-level cap but no `session_ceiling` entry is not
/// grantable at all — an absent ceiling means "no sessions", never
/// "unlimited".
#[test]
fn grant_mint_without_session_ceiling_rejected() {
    let session_key = Keypair::new();
    let mut body = one_cap_body(session_key.pubkey());
    body.caps = vec![MintCap { mint: ungranted_mint(), per_tx: 1, per_day: 0, per_30d: 0 }];
    body.lifetime_cap = vec![1];
    expect_grant_reject(body, err::CAP_EXCEEDED);
}

#[test]
fn grant_ops_over_ceiling_rejected() {
    let session_key = Keypair::new();
    let mut body = one_cap_body(session_key.pubkey());
    body.ops_mask = OP_TRANSFER | OP_SIGN_MESSAGE; // sign-message is outside the ceiling
    expect_grant_reject(body, err::OP_NOT_ALLOWED);
}

#[test]
fn grant_expiry_too_long_rejected() {
    let session_key = Keypair::new();
    let body = GrantBody { expiry_ts: NOW + SESSION_LIFE + 1, ..one_cap_body(session_key.pubkey()) };
    expect_grant_reject(body, err::INVALID_POLICY);
}

#[test]
fn grant_expiry_not_in_the_future_rejected() {
    let session_key = Keypair::new();
    let body = GrantBody { expiry_ts: NOW, ..one_cap_body(session_key.pubkey()) };
    expect_grant_reject(body, err::EXPIRED);
}

#[test]
fn duplicate_mint_in_grant_rejected() {
    let session_key = Keypair::new();
    let mut body = two_cap_body(session_key.pubkey());
    body.caps[1] = sol_cap(); // both slots now name SOL
    expect_grant_reject(body, err::INVALID_ACCOUNT_DATA);
}

#[test]
fn grant_mismatched_cap_and_lifetime_lengths_rejected() {
    let session_key = Keypair::new();
    let mut body = two_cap_body(session_key.pubkey());
    body.lifetime_cap.pop();
    expect_grant_reject(body, err::BAD_INSTRUCTION_LAYOUT);
}

#[test]
fn grant_non_ed25519_kind_rejected() {
    let session_key = Keypair::new();
    let body = GrantBody { kind: 1, ..one_cap_body(session_key.pubkey()) };
    expect_grant_reject(body, err::INVALID_ACCOUNT_DATA);
}

// ---------------------------------------------------------------------------
// Re-grant / merge semantics
// ---------------------------------------------------------------------------

/// Grant SOL + USDC, plant a spend history (no instruction spends yet — see
/// `common::write_session`), then re-grant SOL alone with a wider cap: the SOL
/// slot is replaced in place, its `lifetime_spent` survives, the untouched
/// USDC slot keeps everything, and the scalar fields are replaced.
#[test]
fn regrant_merges_by_mint_and_preserves_spent() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let (session, _) = session_pda(&account, &session_key.pubkey());

    let ixs = grant_ixs(&svm, &payer, &account, &pk, two_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);

    let mut s = read_session(&svm, &session);
    s.lifetime_spent[0] = 7_000_000_000; // SOL
    s.lifetime_spent[1] = 3_000_000_000; // USDC
    write_session(&mut svm, &session, &s);

    let regrant = GrantBody {
        expiry_ts: NOW + 2 * 86_400,
        ops_mask: OP_TRANSFER,
        caps: vec![MintCap { per_tx: 1, per_day: 0, per_30d: 0, ..sol_cap() }],
        lifetime_cap: vec![123_000_000_000],
        program_allowlist_id: 0,
        label: label("relabelled"),
        // The USDC cap this body does not mention survives the merge, so the
        // ceremony must bind the state it survives from.
        prior_authority_hash: prior_hash(&svm, &session),
        ..two_cap_body(session_key.pubkey())
    };
    let ixs = grant_ixs(&svm, &payer, &account, &pk, regrant.clone());
    expect_ok(&mut svm, &[&payer], &ixs);

    let s = read_session(&svm, &session);
    // SOL: replaced in place, spend preserved.
    assert_eq!(s.caps[0].mint, sol_mint());
    assert_eq!(
        (s.caps[0].per_tx, s.caps[0].per_day, s.caps[0].per_30d),
        (1, 0, 0),
        "per_tx replaced in place; day/30d stay 0 (SessionDayCapsUnsupported)"
    );
    assert_eq!(s.lifetime_cap[0], 123_000_000_000);
    assert_eq!(s.lifetime_spent[0], 7_000_000_000, "a re-grant is not a spend reset");
    // USDC: untouched by a grant that did not mention it.
    assert!(s.caps[1] == usdc_cap(), "USDC slot untouched");
    assert_eq!(s.lifetime_cap[1], 40_000_000_000);
    assert_eq!(s.lifetime_spent[1], 3_000_000_000);
    // No new slot was consumed.
    assert!(s.caps[2..].iter().all(|c| c.mint == Pubkey::default()));
    // Scalars replaced.
    assert_eq!(s.expiry_ts, regrant.expiry_ts);
    assert_eq!(s.ops_mask, OP_TRANSFER);
    // Still 0 — `program_allowlist_id` is pinned to 0 until the Phase 1B
    // adapter registry exists (`grant_with_unknown_allowlist_id_rejected`);
    // that the field is genuinely *replaced* from the signed body is covered
    // by `grant_body_tamper_rejected_field_by_field`.
    assert_eq!(s.program_allowlist_id, 0);
    assert_eq!(s.label, label("relabelled"));
}

#[test]
fn regrant_lower_lifetime_than_spent_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let (session, _) = session_pda(&account, &session_key.pubkey());

    let ixs = grant_ixs(&svm, &payer, &account, &pk, one_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);

    let mut s = read_session(&svm, &session);
    s.lifetime_spent[0] = 500;
    write_session(&mut svm, &session, &s);

    let body = GrantBody {
        lifetime_cap: vec![499],
        prior_authority_hash: prior_hash(&svm, &session),
        ..one_cap_body(session_key.pubkey())
    };
    let ixs = grant_ixs(&svm, &payer, &account, &pk, body);
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::CAP_EXCEEDED);
    // Untouched by the rejection.
    assert_eq!(read_session(&svm, &session).lifetime_cap[0], 100_000_000_000);
}

/// A second grant for a mint the session does not yet hold takes the next
/// empty slot rather than overwriting the first.
#[test]
fn regrant_new_mint_takes_the_next_empty_slot() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let (session, _) = session_pda(&account, &session_key.pubkey());

    let ixs = grant_ixs(&svm, &payer, &account, &pk, one_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);

    let body = GrantBody {
        caps: vec![usdc_cap()],
        lifetime_cap: vec![40_000_000_000],
        prior_authority_hash: prior_hash(&svm, &session),
        ..one_cap_body(session_key.pubkey())
    };
    let ixs = grant_ixs(&svm, &payer, &account, &pk, body);
    expect_ok(&mut svm, &[&payer], &ixs);

    let s = read_session(&svm, &session);
    assert_eq!(s.caps[0].mint, sol_mint());
    assert_eq!(s.caps[1].mint, usdc_mint());
    assert_eq!(s.lifetime_cap[0], 100_000_000_000);
    assert_eq!(s.lifetime_cap[1], 40_000_000_000);
    assert_eq!(MAX_MINT_CAPS, 8, "a session holds 8 slots regardless of MAX_CAPS_PER_GRANT");
}

/// A live root ceremony re-blesses the session against the account's CURRENT
/// generation — even without closing and re-creating the PDA.
#[test]
fn regrant_refreshes_generation_at_grant() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let (session, _) = session_pda(&account, &session_key.pubkey());

    let ixs = grant_ixs(&svm, &payer, &account, &pk, one_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);
    assert_eq!(read_session(&svm, &session).generation_at_grant, 0);

    let generation = bump_generation(&mut svm, &account, 3);
    let body = GrantBody {
        prior_authority_hash: prior_hash(&svm, &session),
        ..one_cap_body(session_key.pubkey())
    };
    let ixs = grant_ixs(&svm, &payer, &account, &pk, body);
    expect_ok(&mut svm, &[&payer], &ixs);
    assert_eq!(read_session(&svm, &session).generation_at_grant, generation);
}

/// Milestone-review finding (Important). THE attack the binding closes: the
/// root signs a body naming SOL only, believing that is all the session
/// holds, while the on-chain session also holds USDC — which the merge would
/// keep, and the refreshed `generation_at_grant` would re-bless. The
/// prior-state hash the signer computes from the session they *believe* in
/// does not match the one on chain, so the ceremony is refused.
#[test]
fn regrant_cannot_silently_retain_caps_the_signer_never_saw() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let (session, _) = session_pda(&account, &session_key.pubkey());

    // Reality: SOL + USDC.
    let ixs = grant_ixs(&svm, &payer, &account, &pk, two_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);

    // What the signer believes: SOL only. Same session, one fewer cap.
    let mut believed = read_session(&svm, &session);
    believed.caps[1] = MintCap::default();
    believed.lifetime_cap[1] = 0;
    assert_ne!(
        believed.authority_hash(),
        prior_hash(&svm, &session),
        "the belief must actually differ from reality, or this test proves nothing"
    );

    let body = GrantBody {
        prior_authority_hash: believed.authority_hash(),
        ..one_cap_body(session_key.pubkey())
    };
    let ixs = grant_ixs(&svm, &payer, &account, &pk, body);
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::SESSION_PRIOR_STATE_MISMATCH);

    // Nothing moved: the USDC cap is still exactly what it was.
    let s = read_session(&svm, &session);
    assert!(s.caps[1] == usdc_cap());
    assert_eq!(s.lifetime_cap[1], 40_000_000_000);
}

/// The all-zero sentinel means "this PDA does not exist yet". Reusing it for
/// a re-grant is the simplest form of the same attack.
#[test]
fn regrant_with_the_fresh_sentinel_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let (session, _) = session_pda(&account, &session_key.pubkey());

    let ixs = grant_ixs(&svm, &payer, &account, &pk, two_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);

    // `one_cap_body` defaults `prior_authority_hash` to the fresh sentinel.
    let ixs = grant_ixs(&svm, &payer, &account, &pk, one_cap_body(session_key.pubkey()));
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::SESSION_PRIOR_STATE_MISMATCH);
    assert_eq!(read_session(&svm, &session).expiry_ts, NOW + 6 * 86_400, "unchanged");
}

/// And the converse: a FIRST grant must carry the sentinel, not some
/// invented digest.
#[test]
fn fresh_grant_with_a_non_zero_prior_hash_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let body = GrantBody {
        prior_authority_hash: [0x77u8; 32],
        ..one_cap_body(session_key.pubkey())
    };
    let ixs = grant_ixs(&svm, &payer, &account, &pk, body);
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::SESSION_PRIOR_STATE_MISMATCH);
}

/// A re-grant that shows the signer the true prior state still works — the
/// binding is a correctness gate, not a ban on re-granting.
#[test]
fn regrant_with_the_true_prior_hash_is_accepted() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let (session, _) = session_pda(&account, &session_key.pubkey());

    let ixs = grant_ixs(&svm, &payer, &account, &pk, two_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);

    let body = GrantBody {
        expiry_ts: NOW + 3 * 86_400,
        prior_authority_hash: prior_hash(&svm, &session),
        ..one_cap_body(session_key.pubkey())
    };
    let ixs = grant_ixs(&svm, &payer, &account, &pk, body);
    expect_ok(&mut svm, &[&payer], &ixs);
    assert_eq!(read_session(&svm, &session).expiry_ts, NOW + 3 * 86_400);
}

/// Milestone-review finding (Important): an `ops_mask` bit this program has
/// not assigned a meaning to would silently become authority the day a later
/// version assigns it. Unreachable via the ceiling in 1A (`create_account`
/// refuses such a ceiling outright), so this is the belt-and-braces half.
#[test]
fn grant_with_an_unassigned_ops_mask_bit_rejected() {
    let session_key = Keypair::new();
    let body = GrantBody { ops_mask: 1 << 4, ..one_cap_body(session_key.pubkey()) };
    expect_grant_reject(body, err::OP_NOT_ALLOWED);
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

#[test]
fn revoke_by_root_ok() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let (session, _) = session_pda(&account, &session_key.pubkey());
    let ixs = grant_ixs(&svm, &payer, &account, &pk, two_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);

    let ixs = revoke_root_ixs(&svm, &payer, &account, &pk, session_key.pubkey(), session);
    let tx_bytes = bincode::serialize(&Transaction::new(
        &[&payer],
        Message::new(&ixs, Some(&payer.pubkey())),
        svm.latest_blockhash(),
    ))
    .unwrap()
    .len();
    let before = read_smart_account(&svm, &account).root_nonce;
    let res = expect_ok(&mut svm, &[&payer], &ixs);
    println!("revoke_session_root CU: {}", res.compute_units_consumed);
    println!("revoke_session_root tx: {tx_bytes} B");

    assert!(is_closed(&svm, &session), "the session PDA must be closed");
    assert_eq!(read_smart_account(&svm, &account).root_nonce, before + 1);
    assert!(tx_bytes <= PACKET_DATA_SIZE, "revoke tx is {tx_bytes} B, over {PACKET_DATA_SIZE} B");
}

#[test]
fn revoke_by_session_self_ok() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let (session, _) = session_pda(&account, &session_key.pubkey());
    let ixs = grant_ixs(&svm, &payer, &account, &pk, two_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);
    let nonce = read_smart_account(&svm, &account).root_nonce;

    let ix = revoke_self_ix(payer.pubkey(), session_key.pubkey(), account, session);
    let tx_bytes = bincode::serialize(&Transaction::new(
        &[&payer, &session_key],
        Message::new(std::slice::from_ref(&ix), Some(&payer.pubkey())),
        svm.latest_blockhash(),
    ))
    .unwrap()
    .len();
    let res = expect_ok(&mut svm, &[&payer, &session_key], &[ix]);
    println!("revoke_session_self CU: {}", res.compute_units_consumed);
    println!("revoke_session_self tx: {tx_bytes} B");

    assert!(is_closed(&svm, &session), "the session PDA must be closed");
    assert_eq!(
        read_smart_account(&svm, &account).root_nonce,
        nonce,
        "the self path consumes no root ceremony"
    );
}

#[test]
fn revoke_by_stranger_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let (session, _) = session_pda(&account, &session_key.pubkey());
    let ixs = grant_ixs(&svm, &payer, &account, &pk, two_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);

    let stranger = Keypair::new();
    svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    let ix = revoke_self_ix(payer.pubkey(), stranger.pubkey(), account, session);
    expect_reject(&mut svm, &[&payer, &stranger], &[ix], 0, err::UNAUTHORIZED);
    assert!(!is_closed(&svm, &session), "the session must survive a stranger's attempt");
    assert_eq!(read_session(&svm, &session).pubkey, session_key.pubkey());
}

/// A root ceremony authorizes revoking exactly ONE named session pubkey.
/// Pointing the instruction at a different (equally real) session of the same
/// account must fail even though the assertion itself is perfectly valid.
#[test]
fn revoke_by_root_wrong_session_account_rejected() {
    let (mut svm, payer, pk, account) = live();
    let victim = Keypair::new();
    let other = Keypair::new();
    for k in [&victim, &other] {
        let ixs = grant_ixs(&svm, &payer, &account, &pk, one_cap_body(k.pubkey()));
        expect_ok(&mut svm, &[&payer], &ixs);
    }
    let (other_pda, _) = session_pda(&account, &other.pubkey());

    // Ceremony authorizes `victim`, instruction points at `other`'s PDA.
    let ixs = revoke_root_ixs(&svm, &payer, &account, &pk, victim.pubkey(), other_pda);
    expect_reject(&mut svm, &[&payer], &ixs, 1, err::UNAUTHORIZED);
    assert!(!is_closed(&svm, &other_pda));
}

/// Close, bump the account's generation (Phase 1B's rotation/recovery does
/// this for real — see `common::bump_generation`), then grant the SAME session
/// pubkey again: the new PDA must carry the CURRENT generation, not the one it
/// held before it was closed.
#[test]
fn revoke_close_then_regrant_gets_current_generation() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let (session, _) = session_pda(&account, &session_key.pubkey());

    let ixs = grant_ixs(&svm, &payer, &account, &pk, two_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);
    assert_eq!(read_session(&svm, &session).generation_at_grant, 0);

    let ix = revoke_self_ix(payer.pubkey(), session_key.pubkey(), account, session);
    expect_ok(&mut svm, &[&payer, &session_key], &[ix]);
    assert!(is_closed(&svm, &session));

    let generation = bump_generation(&mut svm, &account, 2);
    let ixs = grant_ixs(&svm, &payer, &account, &pk, one_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);

    let s = read_session(&svm, &session);
    assert_eq!(s.generation_at_grant, generation);
    assert_eq!(s.caps[0].mint, sol_mint());
    assert_eq!(s.caps[1].mint, Pubkey::default(), "a closed-and-recreated session starts empty");
    assert!(s.lifetime_spent.iter().all(|v| *v == 0));
}

// ---------------------------------------------------------------------------
// Round-1 review fixes
// ---------------------------------------------------------------------------

/// `program_allowlist_id` names an entry in an adapter registry that does not
/// exist yet, so the only value Phase 1A can honour is 0 ("no allowlist").
/// Accepting any other id would silently store a dangling reference that
/// Phase 1B would then have to interpret.
#[test]
fn grant_with_unknown_allowlist_id_rejected() {
    let session_key = Keypair::new();
    let body = GrantBody { program_allowlist_id: 1, ..one_cap_body(session_key.pubkey()) };
    expect_grant_reject(body, err::PROGRAM_ALLOWLIST_UNSUPPORTED);
}

/// The root ceremony authorizes WHERE THE RENT GOES as well as what is
/// revoked: an otherwise-valid assertion resubmitted with a different `payer`
/// (the `close` destination) must be turned away, so a signed-but-unlanded
/// revoke cannot be front-run for its lamports.
#[test]
fn revoke_by_root_substituted_refund_rejected() {
    let (mut svm, payer, pk, account) = live();
    let session_key = Keypair::new();
    let (session, _) = session_pda(&account, &session_key.pubkey());
    let ixs = grant_ixs(&svm, &payer, &account, &pk, one_cap_body(session_key.pubkey()));
    expect_ok(&mut svm, &[&payer], &ixs);

    let thief = Keypair::new();
    svm.airdrop(&thief.pubkey(), 1_000_000_000).unwrap();
    // Ceremony says "refund to payer"; the submitted instruction says "refund
    // to thief", and the thief signs as payer.
    let ixs = revoke_root_ixs_with(
        &svm,
        &account,
        &pk,
        session_key.pubkey(),
        payer.pubkey(),
        session,
        thief.pubkey(),
    );
    expect_reject(&mut svm, &[&thief], &ixs, 1, err::UNAUTHORIZED);
    assert!(!is_closed(&svm, &session), "the session must survive a refund substitution");
}

/// EVERY field of `GrantBody` is inside the signed `action_hash`. For each one
/// in turn: sign the honest body, submit with that ONE field altered, and
/// require the program to reject it. A field accidentally left out of the hash
/// would show up here as exactly one passing-through variant.
#[test]
fn grant_body_tamper_rejected_field_by_field() {
    let session_key = Keypair::new();
    let other_session = Keypair::new().pubkey();
    let honest = two_cap_body(session_key.pubkey());

    let variants: Vec<(&str, GrantBody)> = vec![
        ("session_pubkey", GrantBody { session_pubkey: other_session, ..honest.clone() }),
        ("kind", GrantBody { kind: 1, ..honest.clone() }),
        ("expiry_ts", GrantBody { expiry_ts: honest.expiry_ts - 1, ..honest.clone() }),
        ("ops_mask", GrantBody { ops_mask: OP_TRANSFER, ..honest.clone() }),
        (
            "caps",
            GrantBody {
                caps: vec![MintCap { per_tx: sol_cap().per_tx - 1, ..sol_cap() }, usdc_cap()],
                ..honest.clone()
            },
        ),
        (
            "lifetime_cap",
            GrantBody { lifetime_cap: vec![1, 40_000_000_000], ..honest.clone() },
        ),
        ("program_allowlist_id", GrantBody { program_allowlist_id: 1, ..honest.clone() }),
        ("label", GrantBody { label: label("tampered"), ..honest.clone() }),
    ];

    for (field, tampered) in variants {
        assert!(tampered != honest, "the {field} variant does not actually differ");
        let (mut svm, payer, pk, account) = live();
        let ixs = grant_ixs_tampered(&svm, &payer, &account, &pk, &honest, tampered);
        let e = send(&mut svm, &[&payer], &ixs).err().unwrap_or_else(|| {
            panic!("tampering with `{field}` was ACCEPTED — that field is outside the action hash")
        });
        assert_eq!(
            e.err,
            TransactionError::InstructionError(1, InstructionError::Custom(err::CHALLENGE_MISMATCH)),
            "tampering with `{field}` must fail the challenge binding, not something else; logs={:#?}",
            e.meta.logs
        );
    }
}
