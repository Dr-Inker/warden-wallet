//! LiteSVM coverage of `execute` (Task 5) — running a payload of inner CPIs
//! under the conservation regime, on both the session and the root path, with
//! real SPL Token / test-mutator CPIs so the reject-on-mutation branch is
//! proven end to end through a CPI (not only by the pure `conservation` unit
//! tests).
//!
//! Layout of the two authorization shapes, same convention as `transfer`:
//! ```text
//! session path:  ix[0] = warden::execute            (session key signs)
//! root path:     ix[0] = Secp256r1SigVerify precompile
//!                ix[1] = warden::execute            (root: Some(..))
//! ```
//! The root ceremony signs `borsh(ExecuteBody { payload_hash, accounts_hash })`
//! where both hashes are rebuilt from the bytes and the logical account list
//! actually passed — which `lazorkit_account_reorder_under_captured_assertion_
//! rejected` exercises against a reordered list.

mod common;

use anchor_lang::{AnchorSerialize, Discriminator};
use common::passkey::{self, TestPasskey, FLAGS_UP_UV, TEST_ORIGIN};
use common::token::{ata, set_mint, set_token_account, token_amount};
use common::{
    create_smart_account, init_registry_ix, read_smart_account, registry_pda, session_pda,
    set_program_data, warp_clock, SmartAccountFixture,
};
use common::mutator::{self, add_mutator};
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
use warden::constants::{
    COMPUTE_BUDGET_ID, MAX_EXECUTE_ACCOUNTS_TOTAL, NATIVE_MINT, SPL_TOKEN_ID, STAGE_SEED,
};
use warden::instructions::create_account::MIN_TIMELOCK_SECS;
use warden::instructions::execute::{ExecuteArgs, ExecuteBody};
use warden::payload::{FLAG_SIGNER, FLAG_WRITABLE};
use warden::root_verify::transcript::{
    action_hash, b64url_no_pad, transcript_hash, OP_EXECUTE_ACTION,
};
use warden::root_verify::RootArgs;
use warden::state::{MintCap, PolicyArgs, SessionKey, Stage, OP_EXECUTE, OP_TRANSFER};

const NOW: i64 = 1_760_000_000;
const PACKET: usize = 1232;

// Cap tiers. SOL and one SPL mint; per-tx / day / 30d generously above the
// small amounts moved here so the boundary tests are the ones that bind.
const SOL_PER_TX: u64 = 5_000_000_000;
const SOL_DAY: u64 = 20_000_000_000;
const TOK_PER_TX: u64 = 1_000_000;
const TOK_DAY: u64 = 10_000_000;

const VAULT_FUNDING: u64 = 50_000_000_000;
const VAULT_TOKENS: u64 = 5_000_000;
const ROOT_EXPIRY_OFFSET: i64 = 300;
const SESSION_LIFE: i64 = 7 * 86_400;

fn tok_mint() -> Pubkey {
    Pubkey::new_from_array([9u8; 32])
}

fn exec_policy() -> PolicyArgs {
    PolicyArgs {
        version: 1,
        caps: vec![
            MintCap { mint: NATIVE_MINT, per_tx: SOL_PER_TX, per_day: SOL_DAY, per_30d: SOL_DAY },
            MintCap { mint: tok_mint(), per_tx: TOK_PER_TX, per_day: TOK_DAY, per_30d: TOK_DAY },
        ],
        session_ceiling: vec![
            MintCap { mint: NATIVE_MINT, per_tx: SOL_PER_TX, per_day: SOL_DAY, per_30d: SOL_DAY },
            MintCap { mint: tok_mint(), per_tx: TOK_PER_TX, per_day: TOK_DAY, per_30d: TOK_DAY },
        ],
        large_threshold: vec![
            MintCap { mint: NATIVE_MINT, per_tx: SOL_PER_TX, per_day: 0, per_30d: 0 },
            MintCap { mint: tok_mint(), per_tx: TOK_PER_TX, per_day: 0, per_30d: 0 },
        ],
        timelock_secs: MIN_TIMELOCK_SECS,
        recovery_delay_secs: MIN_TIMELOCK_SECS,
        max_session_life_secs: SESSION_LIFE,
        session_ops_ceiling: OP_TRANSFER | OP_EXECUTE,
    }
}

/// A live SVM with a passkey-rooted account bound to the on-chain default
/// `Registry` (lists 1 = production, 2 = test), funded with SOL and holding a
/// vault ATA of `tok_mint()`. Returns `(svm, payer, passkey, account, registry,
/// mutator_program_id, vault_ata)`.
fn live() -> (LiteSVM, Keypair, TestPasskey, Pubkey, Pubkey, Pubkey, Pubkey) {
    let (mut svm, payer) = common::setup();
    warp_clock(&mut svm, NOW);
    let mutator_id = add_mutator(&mut svm);

    // Registry init'd by the upgrade authority (init_registry reads ProgramData).
    let authority = Keypair::new();
    svm.airdrop(&authority.pubkey(), 1_000_000_000).unwrap();
    set_program_data(&mut svm, Some(authority.pubkey()));
    let (registry, _) = registry_pda();
    let init = init_registry_ix(payer.pubkey(), authority.pubkey(), Pubkey::new_unique());
    send(&mut svm, &[&payer, &authority], &[init]).expect("init_registry");

    let pk = TestPasskey::new(3);
    let f = SmartAccountFixture {
        root_pubkey33: pk.pubkey33(),
        policy: exec_policy(),
        registry: Some(registry),
        ..Default::default()
    };
    let account = create_smart_account(&mut svm, &payer, &f, &pk);
    svm.airdrop(&account, VAULT_FUNDING).expect("fund the vault");

    let mint = tok_mint();
    set_mint(&mut svm, &mint, 6, 1_000_000_000);
    let vault_ata = ata(&account, &mint);
    set_token_account(&mut svm, &vault_ata, &mint, &account, VAULT_TOKENS);

    (svm, payer, pk, account, registry, mutator_id, vault_ata)
}

// ---------------------------------------------------------------------------
// Payload encoding (mirrors payload.rs's test encoder)
// ---------------------------------------------------------------------------

/// One inner instruction: `(program_idx, &[(idx, flags)], data)`.
type Inner<'a> = (u8, &'a [(u8, u8)], &'a [u8]);

fn encode_payload(ixs: &[Inner]) -> Vec<u8> {
    let mut out = vec![ixs.len() as u8];
    for (program_idx, accts, data) in ixs {
        out.push(*program_idx);
        out.push(accts.len() as u8);
        for (idx, flags) in *accts {
            out.push(*idx);
            out.push(*flags);
        }
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

// ---------------------------------------------------------------------------
// Instruction / ceremony builders
// ---------------------------------------------------------------------------

fn none_account() -> AccountMeta {
    AccountMeta::new_readonly(common::program_id(), false)
}

/// A logical account as `accounts_hash`/the handler sees it (order matters).
struct Logical {
    key: Pubkey,
    is_signer: bool,
    is_writable: bool,
}

/// Build the `execute` instruction and the ordered logical account list it
/// implies. `signer` is a readonly signer (never the fee payer, so its
/// message-level writability does not perturb the hash); `smart_account` is
/// writable non-signer; each `remaining` meta contributes its own flags.
#[allow(clippy::too_many_arguments)]
fn execute_ix(
    signer: Pubkey,
    smart_account: Pubkey,
    session: Option<Pubkey>,
    with_sysvar: bool,
    stage: Option<Pubkey>,
    registry: Option<Pubkey>,
    stage_creator: Option<Pubkey>,
    remaining: &[AccountMeta],
    args: &ExecuteArgs,
) -> (Instruction, Vec<Logical>) {
    let mut data = Sha256::digest(b"global:execute")[..8].to_vec();
    args.serialize(&mut data).unwrap();
    let mut accounts = vec![
        AccountMeta::new(smart_account, false),
        AccountMeta::new_readonly(signer, true),
        session.map_or_else(none_account, |s| AccountMeta::new(s, false)),
        if with_sysvar {
            AccountMeta::new_readonly(sysvar::instructions::ID, false)
        } else {
            none_account()
        },
        stage.map_or_else(none_account, |s| AccountMeta::new(s, false)),
        registry.map_or_else(none_account, |r| AccountMeta::new_readonly(r, false)),
        stage_creator.map_or_else(none_account, |c| AccountMeta::new(c, false)),
    ];
    accounts.extend_from_slice(remaining);

    let mut logical = vec![
        Logical { key: smart_account, is_signer: false, is_writable: true },
        Logical { key: signer, is_signer: true, is_writable: false },
    ];
    for m in remaining {
        logical.push(Logical { key: m.pubkey, is_signer: m.is_signer, is_writable: m.is_writable });
    }
    (Instruction { program_id: common::program_id(), accounts, data }, logical)
}

fn accounts_hash(logical: &[Logical]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(logical.len() * 34);
    for a in logical {
        buf.extend_from_slice(a.key.as_ref());
        buf.push(a.is_signer as u8);
        buf.push(a.is_writable as u8);
    }
    solana_keccak_hasher::hashv(&[&buf]).to_bytes()
}

/// Sign the honest transcript for `ah` against the account's CURRENT state.
fn ceremony(svm: &LiteSVM, account: &Pubkey, pk: &TestPasskey, ah: [u8; 32]) -> (Instruction, RootArgs) {
    let st = read_smart_account(svm, account);
    let clock: Clock = svm.get_sysvar();
    let expiry_ts = clock.unix_timestamp + ROOT_EXPIRY_OFFSET;
    let signed_slot = clock.slot;
    let t = transcript_hash(
        &st.cluster_tag,
        &common::program_id(),
        account,
        st.generation,
        st.policy.version,
        st.root_nonce,
        expiry_ts,
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
        expiry_ts,
        signed_slot,
    };
    (passkey::precompile_ix(&a, &pk.pubkey33()), args)
}

/// `action_hash(0x07, borsh(ExecuteBody{ keccak(payload), accounts_hash }))`.
fn execute_action_hash(payload: &[u8], logical: &[Logical]) -> [u8; 32] {
    let body = ExecuteBody {
        payload_hash: solana_keccak_hasher::hashv(&[payload]).to_bytes(),
        accounts_hash: accounts_hash(logical),
    };
    let mut bytes = Vec::new();
    body.serialize(&mut bytes).unwrap();
    action_hash(OP_EXECUTE_ACTION, &bytes)
}

// ---------------------------------------------------------------------------
// Session helper — plant a session PDA with the ops/allowlist/caps we need
// ---------------------------------------------------------------------------

/// Create a session PDA (via a minimal airdrop-then-plant) bound to `account`,
/// carrying `ops_mask`, `program_allowlist_id`, and per-tx/lifetime caps for
/// SOL and the token mint. Planting mirrors `write_session`'s test back-door
/// (Phase 1A has no instruction that spends from a session, and grant does not
/// let us reach an arbitrary cap/allowlist shape cheaply).
fn plant_session(
    svm: &mut LiteSVM,
    account: &Pubkey,
    ops_mask: u16,
    allowlist_id: u16,
) -> (Pubkey, Keypair) {
    let session_kp = Keypair::new();
    let (pda, bump) = session_pda(account, &session_kp.pubkey());
    let generation = read_smart_account(svm, account).generation;

    let mut caps = [MintCap::default(); 8];
    caps[0] = MintCap { mint: NATIVE_MINT, per_tx: SOL_PER_TX, per_day: 0, per_30d: 0 };
    caps[1] = MintCap { mint: tok_mint(), per_tx: TOK_PER_TX, per_day: 0, per_30d: 0 };
    let mut lifetime_cap = [0u64; 8];
    lifetime_cap[0] = SOL_DAY;
    lifetime_cap[1] = TOK_DAY;

    let session = SessionKey {
        version: 1,
        bump,
        account: *account,
        pubkey: session_kp.pubkey(),
        kind: 0,
        expiry_ts: NOW + SESSION_LIFE,
        ops_mask,
        generation_at_grant: generation,
        caps,
        lifetime_cap,
        lifetime_spent: [0u64; 8],
        program_allowlist_id: allowlist_id,
        label: [0u8; 16],
        _reserved: [0u8; 64],
    };
    // Plant an empty account at the PDA first so `write_session` (which reads
    // existing lamports/owner) has something to overwrite.
    let mut data = SessionKey::DISCRIMINATOR.to_vec();
    session.serialize(&mut data).unwrap();
    svm.set_account(
        pda,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(data.len()),
            data,
            owner: common::program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("plant session");
    (pda, session_kp)
}

// ---------------------------------------------------------------------------
// Send / assert helpers
// ---------------------------------------------------------------------------

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
    match send(svm, signers, ixs) {
        Ok(m) => m,
        Err(e) => panic!("expected success, got {:?}\n{:#?}", e.err, e.meta.logs),
    }
}

fn expect_reject(svm: &mut LiteSVM, signers: &[&Keypair], ixs: &[Instruction], ix_index: u8, code: u32) {
    match send(svm, signers, ixs) {
        Ok(_) => panic!("expected reject with custom {code}, got success"),
        Err(e) => match e.err {
            TransactionError::InstructionError(i, InstructionError::Custom(c)) => {
                assert_eq!(i, ix_index, "instruction index; logs:\n{:#?}", e.meta.logs);
                assert_eq!(c, code, "custom error code; logs:\n{:#?}", e.meta.logs);
            }
            other => panic!("expected Custom({code}) at ix {ix_index}, got {other:?}\n{:#?}", e.meta.logs),
        },
    }
}

fn dest_ata(svm: &mut LiteSVM) -> Pubkey {
    let owner = Pubkey::new_unique();
    let mint = tok_mint();
    let d = ata(&owner, &mint);
    set_token_account(svm, &d, &mint, &owner, 0);
    d
}

/// The mint of a writable vault-owned token account must be present in the
/// snapshot list (spec §5.2 rule 2a) — passed read-only, referenced by no
/// payload index, only snapshotted.
fn mint_meta() -> AccountMeta {
    AccountMeta::new_readonly(tok_mint(), false)
}

fn spl_transfer_remaining(vault_ata: Pubkey, dest: Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(vault_ata, false),                    // logical 2
        AccountMeta::new(dest, false),                         // logical 3
        AccountMeta::new_readonly(SPL_TOKEN_ID, false),        // logical 4 (program + role meta)
        mint_meta(),                                           // logical 5 (rule 2a presence)
    ]
}

/// The one SPL-Transfer inner instruction, logical indices matching
/// `spl_transfer_remaining`: source=2, dest=3, authority=PDA(0), token prog=4.
fn spl_transfer_payload(amount: u64) -> Vec<u8> {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    encode_payload(&[(
        4,
        &[(2, FLAG_WRITABLE), (3, FLAG_WRITABLE), (0, FLAG_SIGNER), (4, 0)],
        &data,
    )])
}

// ===========================================================================
// Happy paths
// ===========================================================================

#[test]
fn session_execute_spl_transfer_within_caps() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let dest = dest_ata(&mut svm);
    // list 1 = production, which carries SPL Transfer with the token role.
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);

    let payload = spl_transfer_payload(400_000);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _logical) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &spl_transfer_remaining(vault_ata, dest), &args);

    expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS - 400_000);
    assert_eq!(token_amount(&svm, &dest), 400_000);
}

#[test]
fn root_execute_spl_transfer_bounded_by_threshold() {
    let (mut svm, payer, pk, account, _registry, _mut, vault_ata) = live();
    let submitter = Keypair::new();
    let dest = dest_ata(&mut svm);
    let payload = spl_transfer_payload(700_000);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    // Build once to get the logical list for the hash, then attach the ceremony.
    let (_probe, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &spl_transfer_remaining(vault_ata, dest), &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &spl_transfer_remaining(vault_ata, dest), &args);

    expect_ok(&mut svm, &[&payer, &submitter], &[precompile, ix]);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS - 700_000);
    assert_eq!(token_amount(&svm, &dest), 700_000);
}

#[test]
fn inline_execute_spl_transfer_tx_fits_1232_bytes() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let dest = dest_ata(&mut svm);
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let payload = spl_transfer_payload(400_000);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &spl_transfer_remaining(vault_ata, dest), &args);
    let tx = Transaction::new(
        &[&payer, &session_kp],
        Message::new(&[ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    let size = bincode::serialize(&tx).unwrap().len();
    assert!(size <= PACKET, "inline execute tx is {size} B, over the {PACKET} B packet");
}

// ===========================================================================
// Session-path gating
// ===========================================================================

#[test]
fn execute_program_not_in_registry_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let dest = dest_ata(&mut svm);
    // list 2 = test list: it does NOT contain SPL Transfer (that is list 1).
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 2);
    let payload = spl_transfer_payload(400_000);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &spl_transfer_remaining(vault_ata, dest), &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::REGISTRY_DENIED);
}

#[test]
fn execute_list_zero_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let dest = dest_ata(&mut svm);
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 0);
    let payload = spl_transfer_payload(400_000);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &spl_transfer_remaining(vault_ata, dest), &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::REGISTRY_DENIED);
}

#[test]
fn execute_without_op_execute_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let dest = dest_ata(&mut svm);
    // Session may transfer but not execute.
    let (session, session_kp) = plant_session(&mut svm, &account, OP_TRANSFER, 1);
    let payload = spl_transfer_payload(400_000);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &spl_transfer_remaining(vault_ata, dest), &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::OP_NOT_ALLOWED);
}

#[test]
fn execute_over_per_tx_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let dest = dest_ata(&mut svm);
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    // TOK_PER_TX = 1_000_000; move more.
    let payload = spl_transfer_payload(1_000_001);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &spl_transfer_remaining(vault_ata, dest), &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::CAP_EXCEEDED);
}

// ===========================================================================
// Structural rejects
// ===========================================================================

#[test]
fn execute_both_auth_shapes_rejected() {
    let (mut svm, payer, pk, account, registry, _mut, vault_ata) = live();
    let dest = dest_ata(&mut svm);
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let payload = spl_transfer_payload(1);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(session_kp.pubkey(), account, Some(session), true, None, Some(registry), None, &spl_transfer_remaining(vault_ata, dest), &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    // Both a root AND a session present → BadInstructionLayout.
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), true, None, Some(registry), None, &spl_transfer_remaining(vault_ata, dest), &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[precompile, ix], 1, err::BAD_INSTRUCTION_LAYOUT);
}

#[test]
fn execute_both_payload_sources_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let dest = dest_ata(&mut svm);
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    // A REAL, finalized stage (so Anchor deserializes it) presented ALONGSIDE
    // an inline payload — the handler's XOR check fires BadInstructionLayout
    // rather than an Anchor account-not-initialized error.
    let payload = spl_transfer_payload(1);
    let (stage, creator) = stage_payload(&mut svm, &payer, &account, &payload);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, Some(stage), Some(registry), Some(creator), &spl_transfer_remaining(vault_ata, dest), &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::BAD_INSTRUCTION_LAYOUT);
}

#[test]
fn execute_pda_writable_flag_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let dest = dest_ata(&mut svm);
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    // Payload hands the PDA (idx 0) to a CPI as WRITABLE — parse_payload rejects.
    let payload = encode_payload(&[(4, &[(0, FLAG_WRITABLE)], &[3, 0, 0, 0, 0, 0, 0, 0, 0])]);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &spl_transfer_remaining(vault_ata, dest), &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::PAYLOAD_INVALID);
}

#[test]
fn execute_self_cpi_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, _vault_ata) = live();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    // Warden itself passed as a remaining account (logical 2) and named as the
    // inner program → SelfCpiRejected (resolve rejects warden past slot 1).
    let remaining = vec![AccountMeta::new_readonly(common::program_id(), false)];
    let payload = encode_payload(&[(2, &[], &[0u8])]);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::SELF_CPI_REJECTED);
}

#[test]
fn execute_compute_budget_inside_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, _vault_ata) = live();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let remaining = vec![AccountMeta::new_readonly(COMPUTE_BUDGET_ID, false)];
    let payload = encode_payload(&[(2, &[], &[2u8])]);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::COMPUTE_BUDGET_IN_EXECUTE);
}

// NOTE: `MAX_EXECUTE_ACCOUNTS_TOTAL` / `MAX_EXECUTE_WRITABLE` are enforced in
// the handler (a length comparison, `TooManyExecuteAccounts` /
// `TooManyExecuteWritable`) but are deliberately NOT boundary-tested here: a
// tx carrying 49+ accounts trips a panic inside this LiteSVM/solana build's
// compute-budget message sanitizer ("program id index is sanitized") before
// the program ever runs — a harness limit, not a program one. Both caps are
// PROVISIONAL and owed a Task 5 CU/byte measurement sweep (see
// PHASE1B-MEASUREMENTS.md), which is where the real boundary values — and
// their on-chain boundary tests — belong. `_ = MAX_EXECUTE_ACCOUNTS_TOTAL;`
// keeps the constant referenced from a lower-count sanity assert below.
#[test]
fn execute_account_caps_are_provisional_and_ordered() {
    // A sanity floor on the constants until the sweep pins them: the writable
    // cap cannot exceed the total, and both are positive.
    assert!(warden::constants::MAX_EXECUTE_WRITABLE <= MAX_EXECUTE_ACCOUNTS_TOTAL);
    assert!(MAX_EXECUTE_ACCOUNTS_TOTAL > 0);
}

// ===========================================================================
// The fixed deny-list (direct payload instructions), on BOTH paths
// ===========================================================================

/// A direct SPL `Approve` inner instruction — deny-listed unconditionally.
fn spl_approve_payload() -> Vec<u8> {
    // Approve(4): [source, delegate, authority]. amount arg = 8 bytes.
    let mut data = vec![4u8];
    data.extend_from_slice(&1u64.to_le_bytes());
    encode_payload(&[(4, &[(2, FLAG_WRITABLE), (3, 0), (0, FLAG_SIGNER)], &data)])
}

#[test]
fn session_direct_approve_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let delegate = Pubkey::new_unique();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let remaining = vec![
        AccountMeta::new(vault_ata, false),
        AccountMeta::new_readonly(delegate, false),
        AccountMeta::new_readonly(SPL_TOKEN_ID, false),
    ];
    let args = ExecuteArgs { root: None, payload: Some(spl_approve_payload()) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::DENY_LISTED);
}

#[test]
fn root_direct_approve_rejected() {
    let (mut svm, payer, pk, account, _registry, _mut, vault_ata) = live();
    let submitter = Keypair::new();
    let delegate = Pubkey::new_unique();
    let remaining = vec![
        AccountMeta::new(vault_ata, false),
        AccountMeta::new_readonly(delegate, false),
        AccountMeta::new_readonly(SPL_TOKEN_ID, false),
    ];
    let payload = spl_approve_payload();
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args);
    // Root path skips the registry entirely, so the deny-list is the ONLY thing
    // standing between a root ceremony and an Approve — this is the case a
    // registry-sited deny would miss.
    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::DENY_LISTED);
}

// ===========================================================================
// CloseAccount — three layers, never conflated
// ===========================================================================

/// A direct SPL `CloseAccount(9)` of `target`, rent to `dest`. Account order
/// [account, destination, authority]; logical idxs 2, dest_idx, 0.
fn spl_close_payload(dest_idx: u8) -> Vec<u8> {
    encode_payload(&[(4, &[(2, FLAG_WRITABLE), (dest_idx, FLAG_WRITABLE), (0, FLAG_SIGNER)], &[9u8])])
}

#[test]
fn direct_close_zero_balance_to_vault_pda_allowed() {
    // Run on the ROOT path: the default registry does not list SPL
    // `CloseAccount`, so a session-path sweep would be `RegistryDenied` before
    // it could prove the vault-sweep exception. The deny-list permits the close
    // (emitting a CloseIntent) and conservation accounts for the returned rent
    // as a single PDA inflow — that is what this test proves end to end.
    let (mut svm, payer, pk, account, _registry, _mut, _vault_ata) = live();
    let submitter = Keypair::new();
    let empty = ata(&Pubkey::new_unique(), &tok_mint());
    set_token_account(&mut svm, &empty, &tok_mint(), &account, 0);
    // The rent destination AND the close authority are BOTH the SmartAccount
    // PDA (logical idx 0) — the PDA is never passed as a separate writable
    // remaining account (which conservation would reject as warden-owned
    // writable). It is writable at the message level via the named
    // `smart_account`, so SPL can credit it; the returned rent shows up as the
    // tracked PDA-lamport inflow (spec §5.2 rule 4a).
    let remaining = vec![
        AccountMeta::new(empty, false),                 // logical 2 = target
        AccountMeta::new_readonly(SPL_TOKEN_ID, false), // logical 3 = program
        mint_meta(),                                    // logical 4 = mint (rule 2a)
    ];
    // Program idx 3; SPL close order [account=2, destination=0, authority=0].
    // idx 0 is the PDA as BOTH the writable rent destination and the signing
    // authority — the one case the PDA may be writable to a CPI (enforced by
    // enforce_pda_writable because this is a deny-validated CloseAccount).
    let payload = encode_payload(&[(3, &[(2, FLAG_WRITABLE), (0, FLAG_WRITABLE), (0, FLAG_SIGNER)], &[9u8])]);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args);
    expect_ok(&mut svm, &[&payer, &submitter], &[precompile, ix]);
    // The account is gone; its rent returned to the vault.
    assert!(svm.get_account(&empty).map(|a| a.lamports == 0).unwrap_or(true));
}

#[test]
fn direct_close_to_stranger_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, _vault_ata) = live();
    let empty = ata(&Pubkey::new_unique(), &tok_mint());
    set_token_account(&mut svm, &empty, &tok_mint(), &account, 0);
    let stranger = Pubkey::new_unique();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let remaining = vec![
        AccountMeta::new(empty, false),
        AccountMeta::new(stranger, false),
        AccountMeta::new_readonly(SPL_TOKEN_ID, false),
    ];
    let args = ExecuteArgs { root: None, payload: Some(spl_close_payload(3)) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::DENY_LISTED);
}

#[test]
fn direct_close_nonzero_amount_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    // vault_ata holds VAULT_TOKENS > 0. Destination is the PDA via idx 0 (the
    // vault-sweep shape) so the ONLY thing wrong is the non-zero balance —
    // `DenyListed`, not a duplicate-account or destination error.
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let remaining = vec![
        AccountMeta::new(vault_ata, false),             // logical 2 = target
        AccountMeta::new_readonly(SPL_TOKEN_ID, false), // logical 3 = program
    ];
    // SPL close [account=2, destination=0 (PDA), authority=0].
    let payload = encode_payload(&[(3, &[(2, FLAG_WRITABLE), (0, FLAG_WRITABLE), (0, FLAG_SIGNER)], &[9u8])]);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::DENY_LISTED);
}

// ===========================================================================
// Conservation through a real mutator CPI (root path reaches conservation
// directly; the mutator's nested SPL op is invisible to the deny-list)
// ===========================================================================

/// Build a root `execute` around a single mutator instruction, returning the
/// two-instruction vector. The mutator ix's accounts become the logical
/// `remaining`; the payload references them by logical index.
fn root_mutator_ixs(
    svm: &LiteSVM,
    submitter: &Keypair,
    pk: &TestPasskey,
    account: Pubkey,
    mutator_id: Pubkey,
    inner_accounts: &[(u8, u8)],
    inner_data: &[u8],
    remaining: &[AccountMeta],
) -> Vec<Instruction> {
    // logical: [0]=PDA, [1]=signer, [2..]=remaining. The mutator program is a
    // remaining account named as program_idx.
    let mutator_idx = 2u8 + remaining.iter().position(|m| m.pubkey == mutator_id).unwrap() as u8;
    let payload = encode_payload(&[(mutator_idx, inner_accounts, inner_data)]);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, remaining, &args_shape);
    let (precompile, root) = ceremony(svm, &account, pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, None, None, None, remaining, &args);
    vec![precompile, ix]
}

#[test]
fn execute_set_delegate_via_mutator_rejected_by_conservation() {
    let (mut svm, payer, pk, account, _registry, mutator_id, vault_ata) = live();
    let submitter = Keypair::new();
    let delegate = Pubkey::new_unique();
    // mutator set_delegate accounts: [source, delegate, authority, token_program].
    let remaining = vec![
        AccountMeta::new(vault_ata, false),                    // logical 2 source
        AccountMeta::new_readonly(delegate, false),            // logical 3 delegate
        AccountMeta::new_readonly(SPL_TOKEN_ID, false),        // logical 4 token program
        AccountMeta::new_readonly(mutator_id, false),          // logical 5 mutator (program_idx)
        mint_meta(),                                           // logical 6 mint (rule 2a)
    ];
    let inner_accounts = [(2, FLAG_WRITABLE), (3, 0), (0, FLAG_SIGNER), (4, 0)];
    let mut data = mutator::instruction_discriminator("set_delegate").to_vec();
    data.extend_from_slice(&1u64.to_le_bytes());
    let ixs = root_mutator_ixs(&svm, &submitter, &pk, account, mutator_id, &inner_accounts, &data, &remaining);
    expect_reject(&mut svm, &[&payer, &submitter], &ixs, 1, err::CONSERVATION_VIOLATED);
}

#[test]
fn nested_close_via_mutator_rejected_by_conservation() {
    let (mut svm, payer, pk, account, _registry, mutator_id, _vault_ata) = live();
    // A zero-balance vault ATA the mutator closes INSIDE its own CPI, to the
    // vault PDA. The decoder never sees this nested close, emits no intent, and
    // conservation rejects the unexplained disappearance — ConservationViolated,
    // NOT DenyListed. This is the assertion that proves nested closes are not
    // silently exempted.
    let empty = ata(&Pubkey::new_unique(), &tok_mint());
    set_token_account(&mut svm, &empty, &tok_mint(), &account, 0);
    let submitter = Keypair::new();
    // The nested close's rent destination is a STRANGER (writable) — not the
    // PDA — so the payload carries no writable PDA of its own; the point of this
    // test is that the close happens INSIDE the mutator's CPI, invisible to the
    // decoder, so conservation (not the deny-list, not enforce_pda_writable)
    // rejects the unexplained disappearance.
    let stranger = Pubkey::new_unique();
    let remaining = vec![
        AccountMeta::new(empty, false),                        // logical 2 account
        AccountMeta::new(stranger, false),                     // logical 3 destination (stranger)
        AccountMeta::new_readonly(SPL_TOKEN_ID, false),        // logical 4 token program
        AccountMeta::new_readonly(mutator_id, false),          // logical 5 mutator
        mint_meta(),                                           // logical 6 mint (rule 2a)
    ];
    let inner_accounts = [(2, FLAG_WRITABLE), (3, FLAG_WRITABLE), (0, FLAG_SIGNER), (4, 0)];
    let data = mutator::instruction_discriminator("close_account").to_vec();
    let ixs = root_mutator_ixs(&svm, &submitter, &pk, account, mutator_id, &inner_accounts, &data, &remaining);
    expect_reject(&mut svm, &[&payer, &submitter], &ixs, 1, err::CONSERVATION_VIOLATED);
}

#[test]
fn reenter_warden_via_mutator_rejected() {
    let (mut svm, payer, pk, account, _registry, mutator_id, _vault_ata) = live();
    // The mutator holds warden as a remaining account and tries to CPI into it.
    // resolve_payload rejects warden appearing anywhere past slot 1.
    let submitter = Keypair::new();
    let remaining = vec![
        AccountMeta::new_readonly(common::program_id(), false), // logical 2 = warden (smuggled)
        AccountMeta::new_readonly(mutator_id, false),           // logical 3 = mutator
    ];
    let inner_accounts = [(2, 0)];
    let data = {
        // reenter_warden(data): borsh Vec<u8> (u32 len + bytes).
        let mut d = mutator::instruction_discriminator("reenter_warden").to_vec();
        d.extend_from_slice(&0u32.to_le_bytes());
        d
    };
    let ixs = root_mutator_ixs(&svm, &submitter, &pk, account, mutator_id, &inner_accounts, &data, &remaining);
    expect_reject(&mut svm, &[&payer, &submitter], &ixs, 1, err::SELF_CPI_REJECTED);
}

// ===========================================================================
// Frozen / prior-art / staged
// ===========================================================================

#[test]
fn execute_frozen_rejected() {
    let (mut svm, payer, pk, account, _registry, _mut, vault_ata) = live();
    // Freeze the account via a real root freeze ceremony.
    freeze_account(&mut svm, &payer, &pk, &account);
    let submitter = Keypair::new();
    let dest = dest_ata(&mut svm);
    let payload = spl_transfer_payload(1);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &spl_transfer_remaining(vault_ata, dest), &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, None, None, None, &spl_transfer_remaining(vault_ata, dest), &args);
    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::FROZEN);
}

#[test]
fn lazorkit_account_reorder_under_captured_assertion_rejected() {
    let (mut svm, payer, pk, account, _registry, _mut, vault_ata) = live();
    let submitter = Keypair::new();
    let dest = dest_ata(&mut svm);
    let payload = spl_transfer_payload(700_000);
    // Sign over the HONEST logical list…
    let honest = spl_transfer_remaining(vault_ata, dest);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &honest, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    // …then SUBMIT a reordered remaining list (source/dest swapped). accounts_hash
    // over the reordered list differs, so the rebuilt challenge mismatches.
    let reordered = vec![
        AccountMeta::new(dest, false),
        AccountMeta::new(vault_ata, false),
        AccountMeta::new_readonly(SPL_TOKEN_ID, false),
        mint_meta(),
    ];
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, None, None, None, &reordered, &args);
    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::CHALLENGE_MISMATCH);
}

#[test]
fn staged_execute_ok_and_consumes_stage() {
    let (mut svm, payer, pk, account, _registry, _mut, vault_ata) = live();
    let submitter = Keypair::new();
    let dest = dest_ata(&mut svm);
    let payload = spl_transfer_payload(700_000);
    let remaining = spl_transfer_remaining(vault_ata, dest);
    let (stage, creator) = stage_payload(&mut svm, &payer, &account, &payload);

    let args_shape = ExecuteArgs { root: None, payload: None };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, Some(stage), None, Some(creator), &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: None };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, Some(stage), None, Some(creator), &remaining, &args);

    expect_ok(&mut svm, &[&payer, &submitter], &[precompile, ix]);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS - 700_000);
    // Stage consumed (closed): the account no longer exists.
    assert!(svm.get_account(&stage).map(|a| a.lamports == 0).unwrap_or(true), "stage should be closed on success");
}

#[test]
fn staged_execute_expired_rejected() {
    let (mut svm, payer, pk, account, _registry, _mut, vault_ata) = live();
    let submitter = Keypair::new();
    let dest = dest_ata(&mut svm);
    let payload = spl_transfer_payload(700_000);
    let remaining = spl_transfer_remaining(vault_ata, dest);
    let (stage, creator) = stage_payload(&mut svm, &payer, &account, &payload);
    // Warp past the stage's expiry (STAGE_MAX_TTL_SECS = 3600).
    warp_clock(&mut svm, NOW + 4000);

    let args_shape = ExecuteArgs { root: None, payload: None };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, Some(stage), None, Some(creator), &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: None };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, Some(stage), None, Some(creator), &remaining, &args);
    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::STAGE_EXPIRED);
}

// ===========================================================================
// Round-1 review fixes: logical-list uniqueness (WRDF-0053) + Jupiter fail-close
// (WRDF-0051)
// ===========================================================================

#[test]
fn execute_signer_aliased_in_remaining_rejected() {
    // The session signer key appears AGAIN as a remaining account → two logical
    // indices for one runtime account. Rejected before hashing/auth/CPI.
    let (mut svm, payer, _pk, account, registry, _mut, _vault_ata) = live();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let remaining = vec![AccountMeta::new_readonly(session_kp.pubkey(), false)];
    let args = ExecuteArgs { root: None, payload: Some(encode_payload(&[])) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::DUPLICATE_LOGICAL_ACCOUNT);
}

#[test]
fn execute_pda_aliased_in_remaining_rejected() {
    // The SmartAccount PDA (logical 0) appears AGAIN, read-only, in remaining —
    // an alias resolve/enforce_pda_writable would NOT catch (it is not writable
    // and not the warden program). The whole-list uniqueness check does.
    let (mut svm, payer, _pk, account, registry, _mut, _vault_ata) = live();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let remaining = vec![AccountMeta::new_readonly(account, false)];
    let args = ExecuteArgs { root: None, payload: Some(encode_payload(&[])) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::DUPLICATE_LOGICAL_ACCOUNT);
}

#[test]
fn session_jupiter_via_generic_execute_rejected() {
    // Jupiter is fail-closed in generic execute (WRDF-0051): even though the
    // production registry (list 1) lists its route selector, the handler rejects
    // the Jupiter v6 program id up front so it can only be reached via `swap`.
    let (mut svm, payer, _pk, account, registry, _mut, _vault_ata) = live();
    // Plant an executable at the REAL Jupiter v6 id so resolve passes and the
    // fail-close (not a "not executable" reject) is what fires.
    let jup_so = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/deploy/test_jup_mock.so"
    ))
    .expect("run anchor build first");
    svm.add_program(warden::constants::JUPITER_V6_ID, &jup_so).expect("plant jupiter");
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let remaining = vec![AccountMeta::new_readonly(warden::constants::JUPITER_V6_ID, false)];
    // program_idx 2 = Jupiter; data = its route sighash (enough to resolve).
    let payload = encode_payload(&[(2, &[], &warden::registry_default::sighash("route"))]);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::JUPITER_VIA_SWAP_ONLY);
}

// ---------------------------------------------------------------------------
// Freeze + stage helpers
// ---------------------------------------------------------------------------

fn freeze_account(svm: &mut LiteSVM, payer: &Keypair, pk: &TestPasskey, account: &Pubkey) {
    use warden::root_verify::transcript::OP_FREEZE;
    let (precompile, root) = ceremony(svm, account, pk, action_hash(OP_FREEZE, &[]));
    let mut data = Sha256::digest(b"global:freeze")[..8].to_vec();
    root.serialize(&mut data).unwrap();
    let ix = Instruction {
        program_id: common::program_id(),
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new_readonly(sysvar::instructions::ID, false),
        ],
        data,
    };
    expect_ok(svm, &[payer], &[precompile, ix]);
}

/// Open → chunk → finalize a stage holding `payload`, returning
/// `(stage_pda, creator)`.
fn stage_payload(svm: &mut LiteSVM, payer: &Keypair, account: &Pubkey, payload: &[u8]) -> (Pubkey, Pubkey) {
    let creator = payer.pubkey();
    let hash = solana_keccak_hasher::hashv(&[payload]).to_bytes();
    let (stage, _bump) = Pubkey::find_program_address(
        &[STAGE_SEED, account.as_ref(), creator.as_ref(), &hash],
        &common::program_id(),
    );
    let clock: Clock = svm.get_sysvar();
    let expiry_ts = clock.unix_timestamp + 1800;

    // stage_open(args)
    let mut open_data = Sha256::digest(b"global:stage_open")[..8].to_vec();
    (StageOpenArgsMirror { account: *account, hash, len: payload.len() as u32, expiry_ts })
        .serialize(&mut open_data)
        .unwrap();
    let open = Instruction {
        program_id: common::program_id(),
        accounts: vec![
            AccountMeta::new(creator, true),
            AccountMeta::new(stage, false),
            AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
        ],
        data: open_data,
    };
    expect_ok(svm, &[payer], &[open]);

    // stage_chunk(offset, bytes) — one chunk (payload is small).
    let mut chunk_data = Sha256::digest(b"global:stage_chunk")[..8].to_vec();
    (StageChunkArgsMirror { offset: 0, bytes: payload.to_vec() }).serialize(&mut chunk_data).unwrap();
    let chunk = Instruction {
        program_id: common::program_id(),
        accounts: vec![
            AccountMeta::new(creator, true),
            AccountMeta::new(stage, false),
            AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
        ],
        data: chunk_data,
    };
    expect_ok(svm, &[payer], &[chunk]);

    // stage_finalize()
    let finalize_data = Sha256::digest(b"global:stage_finalize")[..8].to_vec();
    let finalize = Instruction {
        program_id: common::program_id(),
        accounts: vec![
            AccountMeta::new_readonly(creator, true),
            AccountMeta::new(stage, false),
            AccountMeta::new_readonly(*account, false),
        ],
        data: finalize_data,
    };
    expect_ok(svm, &[payer], &[finalize]);

    let _ = Stage::HEADER_LEN; // touch the type so the import is load-bearing
    (stage, creator)
}

// Local borsh mirrors of the stage arg structs (avoids importing private types).
#[derive(AnchorSerialize)]
struct StageOpenArgsMirror {
    account: Pubkey,
    hash: [u8; 32],
    len: u32,
    expiry_ts: i64,
}
#[derive(AnchorSerialize)]
struct StageChunkArgsMirror {
    offset: u32,
    bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Error codes (mirror of tests/root_verify.rs::err, only the ones used here)
// ---------------------------------------------------------------------------
mod err {
    pub const FROZEN: u32 = 6001;
    pub const CAP_EXCEEDED: u32 = 6006;
    pub const OP_NOT_ALLOWED: u32 = 6008;
    pub const BAD_INSTRUCTION_LAYOUT: u32 = 6010;
    pub const CHALLENGE_MISMATCH: u32 = 6018;
    pub const CONSERVATION_VIOLATED: u32 = 6039;
    pub const SELF_CPI_REJECTED: u32 = 6044;
    pub const PAYLOAD_INVALID: u32 = 6045;
    pub const REGISTRY_DENIED: u32 = 6046;
    pub const STAGE_EXPIRED: u32 = 6048;
    pub const COMPUTE_BUDGET_IN_EXECUTE: u32 = 6049;
    pub const DENY_LISTED: u32 = 6050;
    pub const TOO_MANY_EXECUTE_ACCOUNTS: u32 = 6056;
    pub const JUPITER_VIA_SWAP_ONLY: u32 = 6058;
    pub const DUPLICATE_LOGICAL_ACCOUNT: u32 = 6059;
}
