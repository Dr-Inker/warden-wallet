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
    COMPUTE_BUDGET_ID, MAX_EXECUTE_ACCOUNTS_TOTAL, NATIVE_MINT, SPL_TOKEN_2022_ID, SPL_TOKEN_ID,
    STAGE_SEED,
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

// `MAX_EXECUTE_ACCOUNTS_TOTAL` / `MAX_EXECUTE_WRITABLE` are MEASURED values
// (Task 5 sweep): the binding constraint is SBF heap (22-writable OK, 24 OOM
// on the default 32 KiB; heap frames inert under Anchor's capped allocator),
// so the caps sit one inside the verified shape. Boundary tests live in the
// measurement section below (`execute_writable_cap_boundary`,
// `execute_total_cap_boundary`, `over_cap_shapes_reject_cleanly_...`).
#[test]
fn execute_account_caps_are_measured_and_ordered() {
    // The re-sweep-pinned values (PHASE1B-MEASUREMENTS §Task 6 heap lift): 32
    // total / 28 writable, verified with the wrapper's heap frame under
    // warden's custom allocator (30 writable = 113k CU proven, well under the
    // 360k ceiling), covering the ~30-account Jupiter target with headroom.
    // The harness's message sanitizer caps buildable txs at ~34 remaining, so
    // every boundary case here stays <= 33 remaining.
    assert_eq!(MAX_EXECUTE_ACCOUNTS_TOTAL, 32);
    assert_eq!(warden::constants::MAX_EXECUTE_WRITABLE, 28);
    assert!(warden::constants::MAX_EXECUTE_WRITABLE <= MAX_EXECUTE_ACCOUNTS_TOTAL);
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
fn root_signer_substitution_rejected() {
    // WRDF-0055: the root submitter is CEREMONY-BOUND — it is logical[1], so
    // its pubkey (and effective flags) are inside accounts_hash. A ceremony
    // signed for submitter A, submitted by substitute B, must fail the
    // challenge rebuild, not execute with a different logical[1].
    let (mut svm, payer, pk, account, _registry, _mut, vault_ata) = live();
    let signed_for = Keypair::new();
    let substitute = Keypair::new();
    let dest = dest_ata(&mut svm);
    let payload = spl_transfer_payload(700_000);
    let remaining = spl_transfer_remaining(vault_ata, dest);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    // Sign over the logical list containing SIGNED_FOR at logical[1]…
    let (_p, logical) =
        execute_ix(signed_for.pubkey(), account, None, true, None, None, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    // …then submit with SUBSTITUTE as the signer account.
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) =
        execute_ix(substitute.pubkey(), account, None, true, None, None, None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &substitute], &[precompile, ix], 1, err::CHALLENGE_MISMATCH);
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

// ===========================================================================
// Task 5 measurement sweep — CU + bytes per shape (PHASE1B-MEASUREMENTS.md).
//
// Replaces the PROVISIONAL account caps with evidence: every measured shape
// must stay ≤ 60 % of the 600k-CU budget the extension requests (spec §5.2),
// i.e. ≤ 360k CU. LiteSVM does NOT enforce the 1,232-B packet, so byte
// figures are measured separately per serializer (legacy / v0 / v0+ALT) and
// recorded even when a shape only fits with an ALT.
// ===========================================================================

/// Top-level `SetComputeUnitLimit` (tag 2 ‖ u32 LE) — hand-encoded so the
/// suite needs no compute-budget crate; the tag is a stable wire fact.
fn cu_limit_ix(limit: u32) -> Instruction {
    let mut data = vec![2u8];
    data.extend_from_slice(&limit.to_le_bytes());
    Instruction { program_id: COMPUTE_BUDGET_ID, accounts: vec![], data }
}

/// The measured shape: `n_writable` vault token accounts (first is the CPI
/// source) + `extra` appended read-only accounts, one real SPL-transfer CPI.
/// Returns (consumed CU, legacy bytes, v0 bytes, v0+ALT bytes).
fn measure_shape(
    n_writable: usize,
    extra: Vec<AccountMeta>,
    staged: bool,
) -> (u64, usize, usize, usize) {
    let (mut svm, payer, _pk, account, registry, _mut, _vault_ata) = live();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let mint = tok_mint();
    let dest = dest_ata(&mut svm);

    // n writable vault token accounts of the one mint; ata[0] is the source.
    let mut atas = Vec::with_capacity(n_writable);
    for _ in 0..n_writable {
        let a = Pubkey::new_unique();
        set_token_account(&mut svm, &a, &mint, &account, 1_000_000);
        atas.push(a);
    }

    let mut remaining: Vec<AccountMeta> =
        atas.iter().map(|a| AccountMeta::new(*a, false)).collect();
    remaining.push(AccountMeta::new(dest, false)); // logical 2 + n
    remaining.push(AccountMeta::new_readonly(SPL_TOKEN_ID, false)); // 3 + n
    remaining.push(mint_meta()); // 4 + n
    remaining.extend(extra);

    let n = n_writable as u8;
    let mut data = vec![3u8];
    data.extend_from_slice(&1_000u64.to_le_bytes());
    let payload = encode_payload(&[(
        3 + n,
        &[(2, FLAG_WRITABLE), (2 + n, FLAG_WRITABLE), (0, FLAG_SIGNER), (3 + n, 0)],
        &data,
    )]);

    let (args, stage, creator) = if staged {
        let (stage, creator) = stage_payload(&mut svm, &payer, &account, &payload);
        (ExecuteArgs { root: None, payload: None }, Some(stage), Some(creator))
    } else {
        (ExecuteArgs { root: None, payload: Some(payload) }, None, None)
    };
    let (ix, _l) = execute_ix(
        session_kp.pubkey(),
        account,
        Some(session),
        false,
        stage,
        Some(registry),
        creator,
        &remaining,
        &args,
    );

    // Byte figures for the execute transaction WITHOUT the CB instruction
    // (the wrapper adds ~40 B for it uniformly; the shape comparison is what
    // matters). ALT covers every remaining account, the realistic client move.
    let blockhash = svm.latest_blockhash();
    let legacy_tx = Transaction::new(
        &[&payer, &session_kp],
        Message::new(std::slice::from_ref(&ix), Some(&payer.pubkey())),
        blockhash,
    );
    let legacy_bytes = bincode::serialize(&legacy_tx).unwrap().len();
    let v0_bytes = v0_tx_size(&ix, &payer, &session_kp, blockhash, &[]);
    let alt = solana_sdk::message::AddressLookupTableAccount {
        key: Pubkey::new_unique(),
        addresses: remaining.iter().map(|m| m.pubkey).collect(),
    };
    let alt_bytes = v0_tx_size(&ix, &payer, &session_kp, blockhash, &[alt]);

    let meta = expect_ok(&mut svm, &[&payer, &session_kp], &[cu_limit_ix(600_000), ix]);
    (meta.compute_units_consumed, legacy_bytes, v0_bytes, alt_bytes)
}

fn v0_tx_size(
    ix: &Instruction,
    payer: &Keypair,
    session_kp: &Keypair,
    blockhash: solana_sdk::hash::Hash,
    alts: &[solana_sdk::message::AddressLookupTableAccount],
) -> usize {
    use solana_sdk::message::{v0, VersionedMessage};
    use solana_sdk::transaction::VersionedTransaction;
    let m = v0::Message::try_compile(&payer.pubkey(), std::slice::from_ref(ix), alts, blockhash)
        .expect("v0 compile");
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(m), &[payer, session_kp])
        .expect("v0 sign");
    bincode::serialize(&tx).unwrap().len()
}

/// A stranger-owned SPL token account (read-only ballast for the read-heavy
/// shape — parsed by the snapshot, ignored by the comparison).
fn stranger_token_meta(svm: &mut LiteSVM) -> AccountMeta {
    let a = Pubkey::new_unique();
    set_token_account(svm, &a, &tok_mint(), &Pubkey::new_unique(), 5);
    AccountMeta::new_readonly(a, false)
}

/// A stranger-owned Token-2022 token account carrying a ~151-B TLV tail
/// (AccountType byte + one well-formed unmodeled entry) — measures the
/// snapshot's tail-hash cost.
fn t22_tail_account(svm: &mut LiteSVM) -> AccountMeta {
    use solana_sdk::{account::Account, program_pack::Pack};
    use spl_token::state::{Account as SplAccount, AccountState};
    let a = SplAccount {
        mint: tok_mint(),
        owner: Pubkey::new_unique(),
        amount: 5,
        delegate: solana_sdk::program_option::COption::None,
        state: AccountState::Initialized,
        is_native: solana_sdk::program_option::COption::None,
        delegated_amount: 0,
        close_authority: solana_sdk::program_option::COption::None,
    };
    let mut data = vec![0u8; SplAccount::LEN];
    a.pack_into_slice(&mut data);
    data.push(2); // AccountType::Account at offset 165
    data.extend_from_slice(&100u16.to_le_bytes()); // unmodeled TLV type
    data.extend_from_slice(&146u16.to_le_bytes()); // len
    data.extend_from_slice(&[0xAB; 146]);
    let key = Pubkey::new_unique();
    svm.set_account(
        key,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(data.len()),
            data,
            owner: SPL_TOKEN_2022_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("plant t22");
    AccountMeta::new_readonly(key, false)
}

const CU_BUDGET_CEILING: u64 = 360_000; // 60 % of the 600k the extension requests
/// The heap frame the production wrapper injects for large `execute` shapes
/// (client contract, same shape as the CU-limit injection). Warden's custom
/// allocator (src/heap.rs) makes it effective; without it a >~24-account shape
/// OOMs fail-closed.
const EXEC_HEAP_FRAME: u32 = 128 * 1024;

/// Top-level `RequestHeapFrame` (tag 1 ‖ u32 LE bytes, multiple of 1024,
/// ≤ 256 KiB) — the wrapper adds this for large shapes, exactly as it adds
/// `SetComputeUnitLimit` (spec §5.2's compute-budget hoisting).
fn heap_frame_ix(bytes: u32) -> Instruction {
    let mut data = vec![1u8];
    data.extend_from_slice(&bytes.to_le_bytes());
    Instruction { program_id: COMPUTE_BUDGET_ID, accounts: vec![], data }
}

/// Panic-safe probe of one writable-N shape: builds a fresh SVM, runs the
/// shape with an optional heap frame, and classifies the outcome — the
/// harness's own message sanitizer panics somewhere past ~42 remaining
/// accounts, and that must read as HARNESS-CEILING, not as a program result.
fn probe_shape(n_writable: usize, heap_bytes: Option<u32>) -> String {
    let out = std::panic::catch_unwind(|| {
        let (mut svm, payer, _pk, account, registry, _mut, _vault_ata) = live();
        let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
        let mint = tok_mint();
        let dest = dest_ata(&mut svm);
        let mut atas = Vec::new();
        for _ in 0..n_writable {
            let a = Pubkey::new_unique();
            set_token_account(&mut svm, &a, &mint, &account, 1_000_000);
            atas.push(a);
        }
        let mut remaining: Vec<AccountMeta> =
            atas.iter().map(|a| AccountMeta::new(*a, false)).collect();
        remaining.push(AccountMeta::new(dest, false));
        remaining.push(AccountMeta::new_readonly(SPL_TOKEN_ID, false));
        remaining.push(mint_meta());
        let n = n_writable as u8;
        let mut data = vec![3u8];
        data.extend_from_slice(&1_000u64.to_le_bytes());
        let payload = encode_payload(&[(
            3 + n,
            &[(2, FLAG_WRITABLE), (2 + n, FLAG_WRITABLE), (0, FLAG_SIGNER), (3 + n, 0)],
            &data,
        )]);
        let args = ExecuteArgs { root: None, payload: Some(payload) };
        let (ix, _l) = execute_ix(
            session_kp.pubkey(), account, Some(session), false, None, Some(registry), None,
            &remaining, &args,
        );
        let mut ixs = vec![cu_limit_ix(600_000)];
        if let Some(h) = heap_bytes {
            ixs.push(heap_frame_ix(h));
        }
        ixs.push(ix);
        match send(&mut svm, &[&payer, &session_kp], &ixs) {
            Ok(m) => format!("OK cu={}", m.compute_units_consumed),
            Err(e) => {
                let oom = e.meta.logs.iter().any(|l| l.contains("out of memory"));
                if oom { "OOM (32KiB default heap)".into() } else { format!("ERR {:?}", e.err) }
            }
        }
    });
    out.unwrap_or_else(|_| "HARNESS-CEILING (litesvm sanitizer panic)".into())
}

/// TEMP re-sweep with warden's custom allocator: probe the NEW ceiling when a
/// top-level heap frame is present. Ignored by default so the committed suite
/// keeps the pinned caps; run explicitly with `--ignored` while sizing them.
#[test]
#[ignore]
fn resweep_writable_n_with_heap_frame() {
    println!("\n| writable N | no frame | 128 KiB frame | 200 KiB frame |");
    println!("|---|---|---|---|");
    for n in [24usize, 30, 36, 40, 44, 50] {
        let none = probe_shape(n, None);
        let f128 = probe_shape(n, Some(128 * 1024));
        let f200 = probe_shape(n, Some(200 * 1024));
        println!("| {n} | {none} | {f128} | {f200} |");
    }
}

#[test]
fn measure_sweep_writable_n() {
    // Strict in-cap shapes (CU + bytes). The heap-ceiling probe that SET the
    // caps (22-writable OK / 24 OOM on the default 32 KiB heap, heap frame
    // inert under Anchor's capped allocator) is recorded in
    // PHASE1B-MEASUREMENTS.md; with the measured caps in force those shapes
    // now reject at the cap check — pinned by
    // `over_cap_shapes_reject_cleanly_before_the_heap_ceiling` below.
    let mut worst = 0u64;
    println!("\n| shape | CU | legacy B | v0 B | v0+ALT B |");
    println!("|---|---|---|---|---|");
    for n in [10usize, 19] {
        let (cu, lb, vb, ab) = measure_shape(n, vec![], false);
        println!("| {n} writable vault ATAs, 1 SPL-transfer CPI | {cu} | {lb} | {vb} | {ab} |");
        worst = worst.max(cu);
        assert!(cu <= CU_BUDGET_CEILING, "n={n} consumed {cu} CU");
    }
    println!("| worst strict shape CU | {worst} | | | |");
}

#[test]
fn over_cap_shapes_reject_cleanly_before_the_heap_ceiling() {
    // Over-cap shapes must fail the cheap count check (6056/6057) BEFORE any
    // snapshot allocation, whether or not a heap frame is present — so a client
    // can never reach the allocator with more accounts than the cap allows.
    for n in [28usize, 29, 30] {
        for frame in [None, Some(EXEC_HEAP_FRAME)] {
            let out = probe_shape(n, frame);
            assert!(
                out.contains("Custom(6057)") || out.contains("Custom(6056)"),
                "n={n} frame={frame:?}: expected a clean cap rejection, got {out}"
            );
            assert!(!out.contains("OOM"), "n={n} reached the allocator: {out}");
        }
    }
}

#[test]
fn execute_writable_cap_boundary() {
    // 27 vault ATAs + writable dest = 28 writable (== MAX_EXECUTE_WRITABLE)
    // passes WITH the wrapper's heap frame (custom allocator, src/heap.rs);
    // 28 ATAs + dest = 29 → TooManyExecuteWritable at the count check.
    let at = probe_shape(27, Some(EXEC_HEAP_FRAME));
    assert!(at.starts_with("OK"), "at writable cap (28) must pass with a frame: {at}");
    let over = probe_shape(28, Some(EXEC_HEAP_FRAME));
    assert!(over.contains("Custom(6057)"), "one over the writable cap: {over}");
    // And WITHOUT the frame the at-cap shape fails CLOSED, never silently:
    let no_frame = probe_shape(27, None);
    assert!(!no_frame.starts_with("OK"), "28-writable must need the frame: {no_frame}");
}

#[test]
fn execute_total_cap_boundary() {
    // 1 writable source + writable dest + SPL + mint + N read-only strangers:
    // 32 remaining (== MAX_EXECUTE_ACCOUNTS_TOTAL) passes with a frame, 33
    // rejects 6056 at the count check.
    let ok = probe_total(28, Some(EXEC_HEAP_FRAME)); // 1W src + dest + spl + mint + 28 RO = 32
    assert!(ok.starts_with("OK"), "at-total-cap shape (32) must pass with a frame: {ok}");
    let over = probe_total(29, Some(EXEC_HEAP_FRAME)); // 33 remaining
    assert!(over.contains("Custom(6056)"), "one over the total cap: {over}");
}

/// Panic-safe probe of a total-cap shape: 1 writable vault source + writable
/// dest + SPL + mint + `n_readonly` stranger token accounts.
fn probe_total(n_readonly: usize, heap_bytes: Option<u32>) -> String {
    let out = std::panic::catch_unwind(move || {
        let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
        let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
        let dest = dest_ata(&mut svm);
        let mut remaining = vec![
            AccountMeta::new(vault_ata, false),
            AccountMeta::new(dest, false),
            AccountMeta::new_readonly(SPL_TOKEN_ID, false),
            mint_meta(),
        ];
        for _ in 0..n_readonly {
            remaining.push(stranger_token_meta(&mut svm));
        }
        let mut data = vec![3u8];
        data.extend_from_slice(&1_000u64.to_le_bytes());
        let payload = encode_payload(&[(
            4,
            &[(2, FLAG_WRITABLE), (3, FLAG_WRITABLE), (0, FLAG_SIGNER), (4, 0)],
            &data,
        )]);
        let args = ExecuteArgs { root: None, payload: Some(payload) };
        let (ix, _l) = execute_ix(
            session_kp.pubkey(), account, Some(session), false, None, Some(registry), None,
            &remaining, &args,
        );
        let mut ixs = vec![cu_limit_ix(600_000)];
        if let Some(h) = heap_bytes { ixs.push(heap_frame_ix(h)); }
        ixs.push(ix);
        match send(&mut svm, &[&payer, &session_kp], &ixs) {
            Ok(m) => format!("OK cu={}", m.compute_units_consumed),
            Err(e) => format!("ERR {:?}", e.err),
        }
    });
    out.unwrap_or_else(|_| "HARNESS-CEILING".into())
}

#[test]
fn measure_read_heavy_shape() {
    // 4 writable vault ATAs + 16 read-only stranger token accounts
    // (23 remaining incl. dest/program/mint — one inside the measured total
    // cap, read-heavy in shape).
    let (cu, lb, vb, ab) = measure_read_heavy_inner(16);
    println!("\n| read-heavy: 4 writable + 16 read-only token accts (23 remaining) | {cu} CU | legacy {lb} B | v0 {vb} B | v0+ALT {ab} B |");
    assert!(cu <= CU_BUDGET_CEILING, "read-heavy consumed {cu} CU");
}

fn measure_read_heavy_inner(n_readonly: usize) -> (u64, usize, usize, usize) {
    // measure_shape with strangers appended requires planting them in ITS svm;
    // duplicate the minimal body here with the extras planted in place.
    let (mut svm, payer, _pk, account, registry, _mut, _vault_ata) = live();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let mint = tok_mint();
    let dest = dest_ata(&mut svm);
    let n_writable = 4usize;
    let mut atas = Vec::new();
    for _ in 0..n_writable {
        let a = Pubkey::new_unique();
        set_token_account(&mut svm, &a, &mint, &account, 1_000_000);
        atas.push(a);
    }
    let mut remaining: Vec<AccountMeta> =
        atas.iter().map(|a| AccountMeta::new(*a, false)).collect();
    remaining.push(AccountMeta::new(dest, false));
    remaining.push(AccountMeta::new_readonly(SPL_TOKEN_ID, false));
    remaining.push(mint_meta());
    for _ in 0..n_readonly {
        remaining.push(stranger_token_meta(&mut svm));
    }
    let n = n_writable as u8;
    let mut data = vec![3u8];
    data.extend_from_slice(&1_000u64.to_le_bytes());
    let payload = encode_payload(&[(
        3 + n,
        &[(2, FLAG_WRITABLE), (2 + n, FLAG_WRITABLE), (0, FLAG_SIGNER), (3 + n, 0)],
        &data,
    )]);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) = execute_ix(
        session_kp.pubkey(), account, Some(session), false, None, Some(registry), None,
        &remaining, &args,
    );
    let blockhash = svm.latest_blockhash();
    let legacy_bytes = bincode::serialize(&Transaction::new(
        &[&payer, &session_kp],
        Message::new(std::slice::from_ref(&ix), Some(&payer.pubkey())),
        blockhash,
    ))
    .unwrap()
    .len();
    let v0_bytes = v0_tx_size(&ix, &payer, &session_kp, blockhash, &[]);
    let alt = solana_sdk::message::AddressLookupTableAccount {
        key: Pubkey::new_unique(),
        addresses: remaining.iter().map(|m| m.pubkey).collect(),
    };
    let alt_bytes = v0_tx_size(&ix, &payer, &session_kp, blockhash, &[alt]);
    let meta = expect_ok(&mut svm, &[&payer, &session_kp], &[cu_limit_ix(600_000), ix]);
    (meta.compute_units_consumed, legacy_bytes, v0_bytes, alt_bytes)
}

#[test]
fn measure_t22_tail_shape() {
    // 4 writable vault ATAs + 10 T22 accounts each carrying a ~151-B TLV tail.
    let (mut svm, payer, _pk, account, registry, _mut, _vault_ata) = live();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let mint = tok_mint();
    let dest = dest_ata(&mut svm);
    let mut atas = Vec::new();
    for _ in 0..4usize {
        let a = Pubkey::new_unique();
        set_token_account(&mut svm, &a, &mint, &account, 1_000_000);
        atas.push(a);
    }
    let mut remaining: Vec<AccountMeta> =
        atas.iter().map(|a| AccountMeta::new(*a, false)).collect();
    remaining.push(AccountMeta::new(dest, false));
    remaining.push(AccountMeta::new_readonly(SPL_TOKEN_ID, false));
    remaining.push(mint_meta());
    for _ in 0..10 {
        remaining.push(t22_tail_account(&mut svm));
    }
    let mut data = vec![3u8];
    data.extend_from_slice(&1_000u64.to_le_bytes());
    let payload = encode_payload(&[(
        7,
        &[(2, FLAG_WRITABLE), (6, FLAG_WRITABLE), (0, FLAG_SIGNER), (7, 0)],
        &data,
    )]);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) = execute_ix(
        session_kp.pubkey(), account, Some(session), false, None, Some(registry), None,
        &remaining, &args,
    );
    let meta = expect_ok(&mut svm, &[&payer, &session_kp], &[cu_limit_ix(600_000), ix]);
    println!("\n| T22-tail: 4 writable + 10 T22 (151-B TLV) | {} CU |", meta.compute_units_consumed);
    assert!(meta.compute_units_consumed <= CU_BUDGET_CEILING);
}

#[test]
fn measure_staged_vs_inline() {
    let (cu_inline, _lb, _vb, _ab) = measure_shape(19, vec![], false);
    let (cu_staged, _lb2, _vb2, _ab2) = measure_shape(19, vec![], true);
    println!("\n| 19-writable inline | {cu_inline} CU |\n| 19-writable staged | {cu_staged} CU |");
    assert!(cu_inline <= CU_BUDGET_CEILING && cu_staged <= CU_BUDGET_CEILING);
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
