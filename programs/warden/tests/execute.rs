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
use solana_sdk::program_pack::Pack;
use common::passkey::{self, TestPasskey, FLAGS_UP_UV, TEST_ORIGIN};
use common::token::{ata, set_mint, set_token_account, token_amount};
use common::{
    bump_generation, bump_policy_version, create_smart_account, init_registry_ix,
    read_smart_account, registry_pda, session_pda, set_program_data, warp_clock,
    SmartAccountFixture,
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
    COMPUTE_BUDGET_ID, DAY_SECS, MAX_EXECUTE_ACCOUNTS_TOTAL, NATIVE_MINT, RING_DAYS,
    SPL_TOKEN_2022_ID, SPL_TOKEN_ID, STAGE_SEED,
};
use warden::instructions::create_account::MIN_TIMELOCK_SECS;
use warden::instructions::execute::{ExecuteArgs, ExecuteBody};
use warden::payload::{FLAG_SIGNER, FLAG_WRITABLE};
use warden::root_verify::transcript::{
    action_hash, b64url_no_pad, transcript_hash, OP_EXECUTE_ACTION,
};
use warden::root_verify::RootArgs;
use warden::state::{
    MintCap, PolicyArgs, Registry, RegistryEntry, SessionKey, Stage, MAX_SELECTOR_LEN, OP_EXECUTE,
    OP_TRANSFER,
};

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

/// Today's slot in the account-wide rolling-30-day ring, computed exactly the
/// way `buckets::debit` computes it (`day_number.rem_euclid(RING_DAYS)`) and
/// from the SVM's OWN clock, so a bucket assertion cannot drift from the
/// harness's notion of "now".
fn ring_slot_today(svm: &LiteSVM) -> usize {
    let clock: Clock = svm.get_sysvar();
    clock.unix_timestamp.div_euclid(DAY_SECS).rem_euclid(RING_DAYS as i64) as usize
}

/// A second vault-owned token account of `tok_mint()`, funded with
/// `VAULT_TOKENS`. Addressed as an ATA of a fresh owner (the same shape
/// `direct_close_zero_balance_to_vault_pda_allowed` uses) — `execute` does not
/// require a vault token account to be the canonical ATA, only that it is
/// vault-owned and that its mint rides in the account list (rule 2a).
fn second_vault_ata(svm: &mut LiteSVM, account: &Pubkey) -> Pubkey {
    let a = ata(&Pubkey::new_unique(), &tok_mint());
    set_token_account(svm, &a, &tok_mint(), account, VAULT_TOKENS);
    a
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
    // WRD-CAP-09: the root path is METERED, not merely bounded — the outflow
    // lands in the SAME account-wide buckets a session debits (bucket 1 =
    // `tok_mint()`, per `exec_policy`), day bucket and 30-day ring alike. Ten
    // root ceremonies therefore share one day cap, which is the whole point of
    // routing every path through `buckets::debit`.
    let st = read_smart_account(&svm, &account);
    assert_eq!(st.buckets[1].spent_today, 700_000, "the token's account-wide day bucket");
    assert_eq!(
        st.buckets[1].ring[ring_slot_today(&svm)],
        700_000,
        "today's rolling-30-day ring slot"
    );
    assert_eq!(st.buckets[0].spent_today, 0, "SOL's bucket untouched");
}

/// WRD-CAP-09, the other side of the same rung: one unit over
/// `large_threshold.per_tx` is refused. Identical to
/// `root_execute_spl_transfer_bounded_by_threshold` except for the amount, so
/// the amount is demonstrably the only thing that binds.
#[test]
fn root_execute_over_large_threshold_rejected() {
    let (mut svm, payer, pk, account, _registry, _mut, vault_ata) = live();
    let submitter = Keypair::new();
    let dest = dest_ata(&mut svm);
    // The vault holds VAULT_TOKENS (5_000_000), so the CPI itself would
    // succeed: what refuses this is the cap check after conservation, and the
    // whole transaction — CPI effects included — reverts.
    let payload = spl_transfer_payload(TOK_PER_TX + 1);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_probe, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &spl_transfer_remaining(vault_ata, dest), &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &spl_transfer_remaining(vault_ata, dest), &args);

    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::CAP_EXCEEDED);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS, "the CPI was rolled back");
    assert_eq!(token_amount(&svm, &dest), 0);
    assert_eq!(read_smart_account(&svm, &account).buckets[1].spent_today, 0, "nothing debited");
}

/// WRD-CAP-09: a mint ABSENT from `large_threshold` is "not allowed", never
/// "unlimited" — the root path's `find_cap(...).ok_or(CapExceeded)` (spec
/// §5.2.4). A fresh mint with a funded vault ATA moves a trivially small
/// amount and is still refused.
#[test]
fn root_execute_mint_absent_from_large_threshold_rejected() {
    let (mut svm, payer, pk, account, _registry, _mut, _vault_ata) = live();
    let submitter = Keypair::new();
    // `exec_policy` configures NATIVE_MINT and `tok_mint()` only.
    let other = Pubkey::new_from_array([0x5Cu8; 32]);
    set_mint(&mut svm, &other, 6, 1_000_000_000);
    let src = ata(&account, &other);
    set_token_account(&mut svm, &src, &other, &account, 1_000_000);
    let dest_owner = Pubkey::new_unique();
    let dest = ata(&dest_owner, &other);
    set_token_account(&mut svm, &dest, &other, &dest_owner, 0);

    // Same logical shape as `spl_transfer_remaining`: source 2, dest 3,
    // program 4, mint 5 (rule 2a presence for the writable vault-owned source).
    let remaining = vec![
        AccountMeta::new(src, false),
        AccountMeta::new(dest, false),
        AccountMeta::new_readonly(SPL_TOKEN_ID, false),
        AccountMeta::new_readonly(other, false),
    ];
    let payload = spl_transfer_payload(1_000);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_probe, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args);

    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::CAP_EXCEEDED);
    assert_eq!(token_amount(&svm, &src), 1_000_000, "the CPI was rolled back");
}

/// WRD-EXEC-02: per-mint caps are summed across ACCOUNTS, not charged
/// per token account. Two vault ATAs of ONE mint, each moving 600_000 in the
/// same payload, coalesce to a single 1_200_000 charge — over the 1_000_000
/// per-tx cap — even though neither leg alone would exceed it. Then the same
/// shape at 2 × 400_000 succeeds with ONE coalesced 800_000 bucket debit.
#[test]
fn execute_two_vault_atas_of_one_mint_share_one_per_tx() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let second = second_vault_ata(&mut svm, &account);
    let dest = dest_ata(&mut svm);
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);

    // logical: 2 = vault_ata, 3 = second, 4 = dest, 5 = SPL Token, 6 = mint.
    let remaining = vec![
        AccountMeta::new(vault_ata, false),
        AccountMeta::new(second, false),
        AccountMeta::new(dest, false),
        AccountMeta::new_readonly(SPL_TOKEN_ID, false),
        mint_meta(),
    ];
    let two_transfers = |amount: u64| -> Vec<u8> {
        let mut data = vec![3u8];
        data.extend_from_slice(&amount.to_le_bytes());
        encode_payload(&[
            (5, &[(2, FLAG_WRITABLE), (4, FLAG_WRITABLE), (0, FLAG_SIGNER), (5, 0)], &data),
            (5, &[(3, FLAG_WRITABLE), (4, FLAG_WRITABLE), (0, FLAG_SIGNER), (5, 0)], &data),
        ])
    };

    // 600_000 + 600_000 = 1_200_000 > TOK_PER_TX (1_000_000).
    let args = ExecuteArgs { root: None, payload: Some(two_transfers(600_000)) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::CAP_EXCEEDED);
    // Nothing moved: the reject reverts the whole transaction, both CPIs included.
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS);
    assert_eq!(token_amount(&svm, &second), VAULT_TOKENS);

    // 400_000 + 400_000 = 800_000 fits — and lands as ONE debit, not two.
    let args = ExecuteArgs { root: None, payload: Some(two_transfers(400_000)) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args);
    expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS - 400_000);
    assert_eq!(token_amount(&svm, &second), VAULT_TOKENS - 400_000);
    assert_eq!(token_amount(&svm, &dest), 800_000);
    let st = read_smart_account(&svm, &account);
    assert_eq!(st.buckets[1].spent_today, 800_000, "one coalesced per-mint debit");
    assert_eq!(st.buckets[1].ring[ring_slot_today(&svm)], 800_000);
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

/// A direct SPL `SetAuthority(6)` over `logical[2]`, signed by the vault PDA.
/// Account order `[account_or_mint, current_authority]`; args are
/// `authority_type: u8` then `COption<Pubkey>`.
fn spl_set_authority_payload(new_authority: &Pubkey) -> Vec<u8> {
    let mut data = vec![6u8, 2u8]; // SetAuthority, AuthorityType::AccountOwner
    data.push(1); // COption::Some
    data.extend_from_slice(new_authority.as_ref());
    encode_payload(&[(4, &[(2, FLAG_WRITABLE), (0, FLAG_SIGNER)], &data)])
}

/// WRD-DENY-01, integration half: `SetAuthority` — the tag that would hand the
/// vault's token account to a stranger outright — is refused on the ROOT path,
/// which skips the registry entirely. Mirrors `root_direct_approve_rejected`
/// with only the inner tag changed, so the tag is demonstrably what binds.
#[test]
fn root_direct_set_authority_rejected() {
    let (mut svm, payer, pk, account, _registry, _mut, vault_ata) = live();
    let submitter = Keypair::new();
    let new_authority = Pubkey::new_unique();
    let remaining = vec![
        AccountMeta::new(vault_ata, false),                    // logical 2 = target
        AccountMeta::new_readonly(new_authority, false),       // logical 3 (unreferenced)
        AccountMeta::new_readonly(SPL_TOKEN_ID, false),        // logical 4 = program
    ];
    let payload = spl_set_authority_payload(&new_authority);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::DENY_LISTED);
    // The authority never moved — the reject is before the CPI, not after it.
    let t = spl_token::state::Account::unpack(&svm.get_account(&vault_ata).unwrap().data).unwrap();
    assert_eq!(t.owner, account, "the vault ATA's owner is unchanged");
}

// ===========================================================================
// WRD-DENY-02 — the deny-list runs BEFORE the registry, and no listing
// overrides it
// ===========================================================================

/// **TEST-ONLY back door**: make `(program, selector)` a member of list
/// `list_id` in the already-init'd registry, leaving every other byte —
/// `version`/`bump`/`authority`/`treasury` and the default entries — exactly as
/// `init_registry` wrote them.
///
/// Stands in for the Phase-1C timelocked registry update, which is the only way
/// a listing for a deny-listed pair could ever appear on chain. Its whole
/// purpose is to build the state the ordering claim is about: a registry that
/// SAYS yes to a pair the fixed deny-list says no to.
///
/// If the pair is ALREADY an entry, that entry's index is added to the list
/// rather than a duplicate appended — `Registry::find_entry` returns the FIRST
/// match, so a duplicate slot would be unreachable and the back door would
/// silently do nothing.
fn list_registry_entry(svm: &mut LiteSVM, registry: &Pubkey, program: Pubkey, selector: &[u8], list_id: u16) {
    let existing = svm.get_account(registry).expect("registry exists");
    assert_eq!(&existing.data[..8], Registry::DISCRIMINATOR, "registry discriminator");
    let mut reg: Registry = *bytemuck::from_bytes::<Registry>(&existing.data[8..]);
    let mut sel = [0u8; MAX_SELECTOR_LEN];
    sel[..selector.len()].copy_from_slice(selector);
    let idx = match reg.find_entry(&program, selector) {
        Some(i) => i,
        None => {
            let i = reg.n_entries as usize;
            reg.entries[i] = RegistryEntry {
                program_id: program,
                selector: sel,
                disc_len: selector.len() as u8,
                role_rules: 0,
                _pad: [0; 6],
            };
            reg.n_entries = reg.n_entries.checked_add(1).expect("registry entry count");
            i
        }
    };
    let li = list_id.checked_sub(1).expect("list ids are 1-based") as usize;
    reg.lists[li].set(idx);
    reg.allocated_lists |= 1u8 << li;

    let mut data = Registry::DISCRIMINATOR.to_vec();
    data.extend_from_slice(bytemuck::bytes_of(&reg));
    assert_eq!(data.len(), Registry::LEN);
    svm.set_account(
        *registry,
        Account {
            lamports: existing.lamports,
            data,
            owner: existing.owner,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account (registry)");
}

/// WRD-DENY-02: even a registry that explicitly lists SPL `SetAuthority` for
/// the session's own allowlist cannot re-enable it. The verdict must be
/// `DenyListed` — NOT `RegistryDenied` — which is the observable proof that the
/// decoder runs BEFORE the registry lookup and that no listing, however it got
/// there, is consulted for a denied pair.
#[test]
fn registry_listing_set_authority_still_fails_closed() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    // The adversarial state: list 1 (the session's list) now carries
    // (SPL Token, SetAuthority).
    list_registry_entry(&mut svm, &registry, SPL_TOKEN_ID, &[6u8], 1);
    let new_authority = Pubkey::new_unique();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let remaining = vec![
        AccountMeta::new(vault_ata, false),
        AccountMeta::new_readonly(new_authority, false),
        AccountMeta::new_readonly(SPL_TOKEN_ID, false),
    ];
    let args = ExecuteArgs { root: None, payload: Some(spl_set_authority_payload(&new_authority)) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::DENY_LISTED);
    let t = spl_token::state::Account::unpack(&svm.get_account(&vault_ata).unwrap().data).unwrap();
    assert_eq!(t.owner, account, "the vault ATA's owner is unchanged");
}

/// Control for the test above: the back door itself works — a listing the
/// deny-list does NOT cover really is honoured by the registry gate. Without
/// this, `registry_listing_set_authority_still_fails_closed` could pass because
/// the planted entry was inert rather than because the deny-list outranked it.
#[test]
fn registry_listing_control_a_planted_entry_is_honoured() {
    let (mut svm, payer, _pk, account, registry, mutator_id, _vault_ata) = live();
    // `test-mutator`'s `noop` is in list 2, NOT list 1 — a list-1 session is
    // refused it…
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let remaining = vec![AccountMeta::new_readonly(mutator_id, false)];
    let inner: [(u8, u8); 0] = [];
    let data = mutator::instruction_discriminator("noop").to_vec();
    let payload = encode_payload(&[(2, &inner, &data)]);
    let args = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::REGISTRY_DENIED);

    // …and after the same back door adds it to list 1, it runs.
    list_registry_entry(&mut svm, &registry, mutator_id, &data, 1);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args);
    expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
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

/// WRD-STAGE-02: a `Stage` is captured at the account's CURRENT
/// `policy_version`, so a policy change voids it exactly as it voids an
/// outstanding session (spec §5.3 item 6).
///
/// Deliberately the SESSION path: `policy_version` is one of the fields inside
/// the ROOT transcript, so a root variant of this test would fail
/// `ChallengeMismatch` on the rebuilt challenge and never reach the stage's own
/// binding. On the session path the stale stage is the ONLY defect.
#[test]
fn staged_execute_with_stale_policy_version_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let dest = dest_ata(&mut svm);
    let payload = spl_transfer_payload(400_000);
    let remaining = spl_transfer_remaining(vault_ata, dest);
    // Staged at policy version 1…
    let (stage, creator) = stage_payload(&mut svm, &payer, &account, &payload);
    // …then the policy moves under it (1C's `set_policy`, stood in for by the
    // back door — nothing in 1B bumps the version).
    let bumped = bump_policy_version(&mut svm, &account, 1);
    assert_eq!(bumped, 2, "the stage was captured at version 1");
    // Planted AFTER the bump so nothing else about the session is stale.
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);

    let args = ExecuteArgs { root: None, payload: None };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, Some(stage), Some(registry), Some(creator), &remaining, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::STAGE_INVALID);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS, "nothing executed");
    assert!(
        svm.get_account(&stage).map(|a| a.lamports > 0).unwrap_or(false),
        "the stage survives a rejected consume"
    );
}

/// WRD-STAGE-02: same clause for `generation` — a rotation or recovery voids an
/// outstanding stage. The session is planted AFTER the bump so its
/// `generation_at_grant` matches the account and `stage.generation !=
/// account.generation` is the only thing wrong.
#[test]
fn staged_execute_with_stale_generation_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let dest = dest_ata(&mut svm);
    let payload = spl_transfer_payload(400_000);
    let remaining = spl_transfer_remaining(vault_ata, dest);
    let (stage, creator) = stage_payload(&mut svm, &payer, &account, &payload);
    let generation = bump_generation(&mut svm, &account, 1);
    assert_eq!(generation, 1, "the stage was captured at generation 0");
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);

    let args = ExecuteArgs { root: None, payload: None };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, Some(stage), Some(registry), Some(creator), &remaining, &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::STAGE_INVALID);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS, "nothing executed");
    assert!(
        svm.get_account(&stage).map(|a| a.lamports > 0).unwrap_or(false),
        "the stage survives a rejected consume"
    );
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
// GROK-EXP-02 / -04 regressions (2026-08-22). Grok's `audit_repro_*` fixtures
// asserted the VULNERABLE behaviour at 9a427aa (a successful drain / a
// successful empty execute); inverted here to the defensive error codes per
// the memo's instruction. No successful-drain fixture is kept.
// ---------------------------------------------------------------------------

fn set_mint_with_authority(svm: &mut LiteSVM, mint: &Pubkey, authority: &Pubkey, decimals: u8, supply: u64) {
    use solana_sdk::program_option::COption;
    use spl_token::state::Mint;
    let m = Mint {
        mint_authority: COption::Some(*authority),
        supply,
        decimals,
        is_initialized: true,
        freeze_authority: COption::None,
    };
    let mut data = vec![0u8; Mint::LEN];
    m.pack_into_slice(&mut data);
    svm.set_account(
        *mint,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(Mint::LEN),
            data,
            owner: SPL_TOKEN_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account (mint with authority)");
}

/// Plant a mint whose `freeze_authority` is `authority` (mint authority left
/// unset) — the PDA-controlled-mint shape WRDF-0105's freeze route needs.
fn set_mint_with_freeze_authority(svm: &mut LiteSVM, mint: &Pubkey, authority: &Pubkey, decimals: u8, supply: u64) {
    use solana_sdk::program_option::COption;
    use spl_token::state::Mint;
    let m = Mint {
        mint_authority: COption::None,
        supply,
        decimals,
        is_initialized: true,
        freeze_authority: COption::Some(*authority),
    };
    let mut data = vec![0u8; Mint::LEN];
    m.pack_into_slice(&mut data);
    svm.set_account(
        *mint,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(Mint::LEN),
            data,
            owner: SPL_TOKEN_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account (mint with freeze authority)");
}

/// WRDF-0105 (SWIG-ACC-C2), the forwarding-CPI route: a ROOT `execute` whose
/// account list carries a mint the PDA is FREEZE authority of is refused
/// (`VaultControlledMintInPayload`) even when the payload's direct instruction
/// is a perfectly ordinary SPL transfer — because a forwarding program could
/// have used the propagated PDA signer to `FreezeAccount` a third-party token
/// account of that mint, an authority action conservation never sees. The mint
/// rides in the list unreferenced by the payload; the pre-CPI snapshot gate
/// still refuses it, and nothing moves.
#[test]
fn wrdf0105_root_execute_with_vault_freeze_authority_mint_rejected() {
    let (mut svm, payer, pk, account, _registry, _mut, vault_ata) = live();
    let submitter = Keypair::new();
    let dest = dest_ata(&mut svm);
    let evil_mint = Pubkey::new_from_array([0x55; 32]);
    set_mint_with_freeze_authority(&mut svm, &evil_mint, &account, 6, 1_000);

    // Innocuous payload: a plain SPL transfer of `tok_mint()` within caps. The
    // vault-controlled mint is appended to the account list (logical 6) but no
    // inner instruction references it — this is the forwarding-CPI scenario.
    let mut remaining = spl_transfer_remaining(vault_ata, dest);
    remaining.push(AccountMeta::new_readonly(evil_mint, false)); // logical 6
    let payload = spl_transfer_payload(400_000);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args);

    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::VAULT_CONTROLLED_MINT_IN_PAYLOAD);
    // Nothing moved: the reject is pre-CPI.
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS, "the transfer never ran");
    assert_eq!(token_amount(&svm, &dest), 0);
}

/// WRDF-0105 stays NARROW: a mint the PDA does NOT control (mint/freeze
/// authority is a stranger) riding in the same account list does not trip the
/// gate — the identical innocuous SPL transfer succeeds. Identical to the test
/// above except for who holds the mint's authorities, so that is demonstrably
/// the only thing the gate keys on.
#[test]
fn wrdf0105_root_execute_with_stranger_controlled_mint_allowed() {
    let (mut svm, payer, pk, account, _registry, _mut, vault_ata) = live();
    let submitter = Keypair::new();
    let dest = dest_ata(&mut svm);
    let stranger = Pubkey::new_unique();
    let stranger_mint = Pubkey::new_from_array([0x56; 32]);
    // mint_authority = a stranger, not the PDA.
    set_mint_with_authority(&mut svm, &stranger_mint, &stranger, 6, 1_000);

    let mut remaining = spl_transfer_remaining(vault_ata, dest);
    remaining.push(AccountMeta::new_readonly(stranger_mint, false)); // logical 6
    let payload = spl_transfer_payload(400_000);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args);

    expect_ok(&mut svm, &[&payer, &submitter], &[precompile, ix]);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS - 400_000, "the transfer ran normally");
    assert_eq!(token_amount(&svm, &dest), 400_000);
}

// ---------------------------------------------------------------------------
// WRDF-0105 ROUND 2 (2026-08-23): the Token-2022 EXTENSION authorities.
//
// The first cut of the gate tested `mint_authority` and `freeze_authority` — 2
// of the 4 authority roles `MintSnap` models. Token-2022 keeps the other two in
// the mint's TLV tail: `transfer_fee_config_authority` and
// `withdraw_withheld_authority`. The concrete hole: Token-2022's
// `WithdrawWithheldTokensFromAccounts` (outer tag 26 — `classify_spl_token_op`
// falls through to `Other`, so `deny_scan` does not name it) takes a READ-ONLY
// mint, WRITABLE source/receiver token accounts, and the mint's
// `withdraw_withheld_authority` AS SIGNER. Under a root payload with the PDA
// signer, the read-only mint stays byte-identical, the non-vault source/receiver
// accounts are skipped by conservation, outflow is zero and no bucket is debited
// — value moves entirely unmetered, which is exactly what WRD-EXEC-09's
// unconditional 1B rejection exists to prevent.
// ---------------------------------------------------------------------------

/// Plant a **Token-2022** mint carrying a well-formed 108-byte
/// `TransferFeeConfig` TLV entry, so all four authority roles are settable
/// independently. Byte layout re-derived from `conservation/snapshot.rs`'s module
/// docs (and pinned unit-side by
/// `conservation::tests::wrdf0105_holds_authority_covers_all_four_roles_including_t22_extensions`):
///
/// ```text
///   [0..82)    classic Mint base (mint_authority, supply, decimals, init, freeze)
///   [82..165)  zero padding — the T22 crate REQUIRES this to be all zeroes
///   [165]      AccountType::Mint = 1
///   [166..]    TLV: type u16 LE ‖ len u16 LE ‖ value
///                type 1 = TransferFeeConfig, len 108
///                  value[0..32)  transfer_fee_config_authority  (all-zero = None)
///                  value[32..64) withdraw_withheld_authority    (all-zero = None)
///                  value[64..72) withheld_amount
///                  value[72..108) older/newer transfer fee
/// ```
fn set_t22_transfer_fee_mint(
    svm: &mut LiteSVM,
    mint: &Pubkey,
    mint_authority: Option<Pubkey>,
    freeze_authority: Option<Pubkey>,
    transfer_fee_config_authority: Option<Pubkey>,
    withdraw_withheld_authority: Option<Pubkey>,
) {
    use solana_sdk::program_option::COption;
    use spl_token::state::Mint;
    let opt = |k: Option<Pubkey>| match k {
        Some(k) => COption::Some(k),
        None => COption::None,
    };
    let m = Mint {
        mint_authority: opt(mint_authority),
        supply: 1_000,
        decimals: 6,
        is_initialized: true,
        freeze_authority: opt(freeze_authority),
    };
    let mut data = vec![0u8; Mint::LEN];
    m.pack_into_slice(&mut data);
    data.resize(165, 0); // [82..165) padding
    data.push(1); // AccountType::Mint
    let mut value = vec![0u8; 108];
    // `OptionalNonZeroPubkey`, NOT a COption: a bare 32-byte key, all-zero = None.
    value[0..32].copy_from_slice(transfer_fee_config_authority.unwrap_or_default().as_ref());
    value[32..64].copy_from_slice(withdraw_withheld_authority.unwrap_or_default().as_ref());
    data.extend_from_slice(&1u16.to_le_bytes()); // TransferFeeConfig
    data.extend_from_slice(&(value.len() as u16).to_le_bytes());
    data.extend_from_slice(&value);
    assert_eq!(data.len(), 166 + 4 + 108);
    svm.set_account(
        *mint,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(data.len()),
            data,
            owner: SPL_TOKEN_2022_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account (T22 transfer-fee mint)");
}

/// The shared body of the round-2 WRDF-0105 cases: an innocuous root `execute`
/// SPL transfer whose account list additionally carries `extra_mint`
/// READ-ONLY — the shape `WithdrawWithheldTokensFromAccounts` needs, and the
/// shape a forwarding hop needs. Returns the transaction outcome so each case
/// can assert reject-or-accept.
fn root_execute_with_extra_readonly_mint(extra_mint: Pubkey, plant: impl FnOnce(&mut LiteSVM, &Pubkey)) -> (LiteSVM, Keypair, Keypair, Pubkey, Pubkey, Instruction, Instruction) {
    let (mut svm, payer, pk, account, _registry, _mut, vault_ata) = live();
    let submitter = Keypair::new();
    let dest = dest_ata(&mut svm);
    plant(&mut svm, &account);
    let mut remaining = spl_transfer_remaining(vault_ata, dest);
    // READ-ONLY: `WithdrawWithheldTokensFromAccounts` passes the mint read-only,
    // and so does a freeze. Writability is deliberately NOT what the gate keys on.
    remaining.push(AccountMeta::new_readonly(extra_mint, false)); // logical 6
    let payload = spl_transfer_payload(400_000);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args);
    (svm, payer, submitter, vault_ata, dest, precompile, ix)
}

/// WRDF-0105 round 2, the case Codex demonstrated: a READ-ONLY Token-2022 mint
/// whose `withdraw_withheld_authority` is the vault PDA. The old two-field gate
/// waved it through (`mint_authority` and `freeze_authority` are a stranger's);
/// `MintSnap::holds_authority` sees it, so the root `execute` is refused
/// `VaultControlledMintInPayload` before any CPI runs.
#[test]
fn wrdf0105_root_execute_with_vault_withdraw_withheld_authority_mint_rejected() {
    let evil_mint = Pubkey::new_from_array([0x57; 32]);
    let stranger = Pubkey::new_unique();
    let (mut svm, payer, submitter, vault_ata, dest, precompile, ix) =
        root_execute_with_extra_readonly_mint(evil_mint, |svm, account| {
            set_t22_transfer_fee_mint(svm, &evil_mint, Some(stranger), Some(stranger), Some(stranger), Some(*account));
        });
    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::VAULT_CONTROLLED_MINT_IN_PAYLOAD);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS, "the transfer never ran");
    assert_eq!(token_amount(&svm, &dest), 0);
}

/// WRDF-0105 round 2, the fourth role: a READ-ONLY Token-2022 mint whose
/// `transfer_fee_config_authority` is the vault PDA. `SetTransferFee` /
/// `SetTransferFeeConfigAuthority` under a PDA signer are the same class of
/// unmetered authority action, and the same two-field gate missed them.
#[test]
fn wrdf0105_root_execute_with_vault_transfer_fee_config_authority_mint_rejected() {
    let evil_mint = Pubkey::new_from_array([0x58; 32]);
    let stranger = Pubkey::new_unique();
    let (mut svm, payer, submitter, vault_ata, dest, precompile, ix) =
        root_execute_with_extra_readonly_mint(evil_mint, |svm, account| {
            set_t22_transfer_fee_mint(svm, &evil_mint, Some(stranger), Some(stranger), Some(*account), Some(stranger));
        });
    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::VAULT_CONTROLLED_MINT_IN_PAYLOAD);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS, "the transfer never ran");
    assert_eq!(token_amount(&svm, &dest), 0);
}

/// WRDF-0105 round 2 stays NARROW — the Token-2022 half of
/// `wrdf0105_root_execute_with_stranger_controlled_mint_allowed`. A Token-2022
/// transfer-fee mint whose ALL FOUR authority roles belong to a stranger rides in
/// the very same account list, built by the very same helper, and the identical
/// innocuous transfer still succeeds. So the widened gate keys on WHO holds the
/// authority, never on "is a Token-2022 mint present" or "does it carry a
/// transfer-fee extension" — and, together with the two rejects above, the
/// helper's bytes are demonstrably parsed rather than ignored.
#[test]
fn wrdf0105_root_execute_with_stranger_t22_all_four_authorities_allowed() {
    let mint = Pubkey::new_from_array([0x59; 32]);
    let s1 = Pubkey::new_unique();
    let s2 = Pubkey::new_unique();
    let s3 = Pubkey::new_unique();
    let s4 = Pubkey::new_unique();
    let (mut svm, payer, submitter, vault_ata, dest, precompile, ix) =
        root_execute_with_extra_readonly_mint(mint, |svm, _account| {
            set_t22_transfer_fee_mint(svm, &mint, Some(s1), Some(s2), Some(s3), Some(s4));
        });
    expect_ok(&mut svm, &[&payer, &submitter], &[precompile, ix]);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS - 400_000, "the transfer ran normally");
    assert_eq!(token_amount(&svm, &dest), 400_000);
}

// ---------------------------------------------------------------------------
// WRDF-0105 ROUND 3 (2026-08-23): the Token-2022 PERMANENT DELEGATE.
//
// Round 2 widened the gate from a hand-rolled two-field test to
// `MintSnap::holds_authority` — but that predicate itself only knew FOUR roles
// (`mint_authority`, `freeze_authority`, `transfer_fee_config_authority`,
// `withdraw_withheld_authority`). Token-2022 has a FIFTH: `PermanentDelegate`
// (extension type 12), a single `OptionalNonZeroPubkey` that the token program
// accepts as the transfer/burn authority over EVERY token account of the mint,
// forever. `snapshot.rs` recognised the extension only by OR-ing
// `DANGER_PERMANENT_DELEGATE` into `dangerous_ext` and THREW THE PUBKEY AWAY.
//
// The concrete hole Codex demonstrated: `compare.rs::prescan_vault_mints`
// rejects an "unmodelable" danger mint only when it is WRITABLE, Token-2022
// `TransferChecked` (tag 12) takes its mint READ-ONLY, `classify_spl_token_op`
// maps tag 12 to `Other` so `deny_scan` never names it, and the token program
// honours the permanent delegate as the source account's authority. So a ROOT
// payload could pass a read-only mint whose PermanentDelegate is the
// SmartAccount PDA, name logical slot 0 (the PDA) as the propagated signer, and
// move tokens between THIRD-PARTY token accounts: conservation skips both (not
// vault-owned), `outflow` is zero, and no bucket is debited. Value moves that
// nothing meters.
// ---------------------------------------------------------------------------

/// Plant a **Token-2022** mint carrying a well-formed 32-byte
/// `PermanentDelegate` TLV entry (extension type 12). Same byte layout as
/// [`set_t22_transfer_fee_mint`], different extension:
///
/// ```text
///   [0..82)    classic Mint base
///   [82..165)  zero padding
///   [165]      AccountType::Mint = 1
///   [166..]    TLV: type u16 LE = 12 ‖ len u16 LE = 32 ‖ value
///                value[0..32) delegate  — OptionalNonZeroPubkey, all-zero = None
/// ```
fn set_t22_permanent_delegate_mint(
    svm: &mut LiteSVM,
    mint: &Pubkey,
    delegate: Option<Pubkey>,
    supply: u64,
) {
    use solana_sdk::program_option::COption;
    use spl_token::state::Mint;
    let m = Mint {
        // Every CLASSIC role deliberately unset: whatever this mint trips must
        // be the permanent delegate and nothing else.
        mint_authority: COption::None,
        supply,
        decimals: 6,
        is_initialized: true,
        freeze_authority: COption::None,
    };
    let mut data = vec![0u8; Mint::LEN];
    m.pack_into_slice(&mut data);
    data.resize(165, 0); // [82..165) padding
    data.push(1); // AccountType::Mint
    data.extend_from_slice(&12u16.to_le_bytes()); // ExtensionType::PermanentDelegate
    data.extend_from_slice(&32u16.to_le_bytes());
    data.extend_from_slice(delegate.unwrap_or_default().as_ref());
    assert_eq!(data.len(), 166 + 4 + 32);
    svm.set_account(
        *mint,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(data.len()),
            data,
            owner: SPL_TOKEN_2022_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account (T22 permanent-delegate mint)");
}

/// A **Token-2022**-owned 165-byte token account of `mint`, token-level owner
/// `owner`. `PermanentDelegate` is a mint-only extension and requires no
/// account-side extension, so the base layout is what the token program reads.
fn set_t22_token_account(
    svm: &mut LiteSVM,
    address: &Pubkey,
    mint: &Pubkey,
    owner: &Pubkey,
    amount: u64,
) {
    use solana_sdk::program_option::COption;
    use spl_token::state::{Account as SplAccount, AccountState};
    let a = SplAccount {
        mint: *mint,
        owner: *owner,
        amount,
        delegate: COption::None,
        state: AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    };
    let mut data = vec![0u8; SplAccount::LEN];
    a.pack_into_slice(&mut data);
    svm.set_account(
        *address,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(SplAccount::LEN),
            data,
            owner: SPL_TOKEN_2022_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account (T22 token account)");
}

/// WRDF-0105 round 3, the gate case: a READ-ONLY Token-2022 mint whose
/// `PermanentDelegate` is the vault PDA — and whose four modelled roles are all
/// unset — rides in a ROOT `execute` account list. The round-2 gate waved it
/// through (the delegate pubkey was discarded at snapshot time); with the
/// delegate extracted and added to `holds_authority`, the whole `execute` is
/// refused `VaultControlledMintInPayload` before any CPI runs.
#[test]
fn wrdf0105_root_execute_with_vault_permanent_delegate_mint_rejected() {
    let evil_mint = Pubkey::new_from_array([0x5a; 32]);
    let (mut svm, payer, submitter, vault_ata, dest, precompile, ix) =
        root_execute_with_extra_readonly_mint(evil_mint, |svm, account| {
            set_t22_permanent_delegate_mint(svm, &evil_mint, Some(*account), 1_000);
        });
    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::VAULT_CONTROLLED_MINT_IN_PAYLOAD);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS, "the transfer never ran");
    assert_eq!(token_amount(&svm, &dest), 0);
}

/// WRDF-0105 round 3 stays NARROW: the identical Token-2022 mint, built by the
/// identical helper, whose `PermanentDelegate` is a STRANGER still rides through
/// generic `execute` and the innocuous transfer succeeds. So the fifth role is a
/// WHO test like the other four, not a blanket "reject every Token-2022 danger
/// mint" (which is what WRD-EXEC-09's unconditional form would have been, and
/// which would have broken
/// `wrdf0105_root_execute_with_stranger_t22_all_four_authorities_allowed`).
#[test]
fn wrdf0105_root_execute_with_stranger_permanent_delegate_mint_allowed() {
    let mint = Pubkey::new_from_array([0x5b; 32]);
    let stranger = Pubkey::new_unique();
    let (mut svm, payer, submitter, vault_ata, dest, precompile, ix) =
        root_execute_with_extra_readonly_mint(mint, |svm, _account| {
            set_t22_permanent_delegate_mint(svm, &mint, Some(stranger), 1_000);
        });
    expect_ok(&mut svm, &[&payer, &submitter], &[precompile, ix]);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS - 400_000, "the transfer ran normally");
    assert_eq!(token_amount(&svm, &dest), 400_000);
}

/// WRDF-0105 round 3, **the exploit itself**, end to end through a real
/// Token-2022 CPI: a ROOT `execute` whose payload is a single Token-2022
/// `TransferChecked` (tag 12) moving tokens between two THIRD-PARTY token
/// accounts — neither is vault-owned, so conservation skips both — using the
/// SmartAccount PDA (logical slot 0, the propagated signer) as the transfer
/// authority purely by virtue of being the mint's `PermanentDelegate`.
///
/// At the vulnerable base this transaction SUCCEEDS: the mint is read-only so
/// `prescan_vault_mints`'s writable-only danger rule does not fire, tag 12
/// classifies as `Other` so `deny_scan` does not name it, both token accounts
/// are non-vault so `outflow` is zero and no bucket is debited. With the fifth
/// role modelled, the pre-dispatch gate refuses it before the CPI, so the exact
/// error is `VaultControlledMintInPayload` and both balances are untouched.
#[test]
fn wrdf0105_root_execute_t22_transfer_checked_under_pda_permanent_delegate_rejected() {
    let (mut svm, payer, pk, account, _registry, _mut, _vault_ata) = live();
    let submitter = Keypair::new();

    // A mint whose PermanentDelegate is the vault PDA, and two token accounts of
    // it owned by strangers. Nothing here belongs to the vault.
    let evil_mint = Pubkey::new_from_array([0x5c; 32]);
    set_t22_permanent_delegate_mint(&mut svm, &evil_mint, Some(account), 10_000);
    let victim_owner = Pubkey::new_unique();
    let thief_owner = Pubkey::new_unique();
    let victim = Pubkey::new_from_array([0x5d; 32]);
    let thief = Pubkey::new_from_array([0x5e; 32]);
    set_t22_token_account(&mut svm, &victim, &evil_mint, &victim_owner, 9_000);
    set_t22_token_account(&mut svm, &thief, &evil_mint, &thief_owner, 0);

    // logical 2 = source (w), 3 = mint (READ-ONLY, as TransferChecked wants),
    // 4 = destination (w), 5 = the Token-2022 program.
    let remaining = vec![
        AccountMeta::new(victim, false),
        AccountMeta::new_readonly(evil_mint, false),
        AccountMeta::new(thief, false),
        AccountMeta::new_readonly(SPL_TOKEN_2022_ID, false),
    ];
    // TransferChecked: tag 12 ‖ amount u64 LE ‖ decimals u8.
    // Accounts: source, mint, destination, authority — authority = logical 0,
    // the SmartAccount PDA, carrying the propagated signer.
    let mut data = vec![12u8];
    data.extend_from_slice(&9_000u64.to_le_bytes());
    data.push(6);
    let payload = encode_payload(&[(
        5,
        &[(2, FLAG_WRITABLE), (3, 0), (4, FLAG_WRITABLE), (0, FLAG_SIGNER)],
        &data,
    )]);

    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args);

    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::VAULT_CONTROLLED_MINT_IN_PAYLOAD);
    // The refusal is pre-CPI: not one token moved between the third parties.
    assert_eq!(token_amount(&svm, &victim), 9_000, "the victim was not drained");
    assert_eq!(token_amount(&svm, &thief), 0, "the attacker received nothing");
}

/// GROK-EXP-02: a root `execute` MintTo of a mint the PDA controls, to a
/// stranger ATA, is now on the fixed deny-list — refused before any supply
/// change, on the root path that skips the registry. WRDF-0105 ORDERING PROOF:
/// this list also carries the vault-controlled mint (`mint_authority == PDA`),
/// so if the WRDF-0105 gate ran before `deny_scan` the verdict would flip to
/// `VaultControlledMintInPayload`; it stays `DenyListed`, proving `deny_scan`
/// runs first and the existing direct-MintTo assertions are undisturbed.
#[test]
fn grok_exp02_root_mint_to_stranger_is_deny_listed() {
    let (mut svm, payer, pk, account, _registry, _mut, _vault_ata) = live();
    let mint = Pubkey::new_from_array([0x44; 32]);
    set_mint_with_authority(&mut svm, &mint, &account, 6, 1_000);
    let attacker = Pubkey::new_unique();
    let dest = ata(&attacker, &mint);
    set_token_account(&mut svm, &dest, &mint, &attacker, 0);

    let submitter = Keypair::new();
    let remaining = vec![
        AccountMeta::new(mint, false),                  // logical 2 mint
        AccountMeta::new(dest, false),                  // logical 3 dest
        AccountMeta::new_readonly(SPL_TOKEN_ID, false), // logical 4 program
    ];
    let mut mint_to = vec![7u8]; // TokenInstruction::MintTo
    mint_to.extend_from_slice(&42_000u64.to_le_bytes());
    let payload = encode_payload(&[(
        4,
        &[(2, FLAG_WRITABLE), (3, FLAG_WRITABLE), (0, FLAG_SIGNER), (4, 0)],
        &mint_to,
    )]);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args);

    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::DENY_LISTED);
    assert_eq!(token_amount(&svm, &dest), 0, "no tokens minted");
    let m = spl_token::state::Mint::unpack(&svm.get_account(&mint).unwrap().data).unwrap();
    assert_eq!(m.supply, 1_000, "supply unchanged");
}

/// GROK-EXP-04: an empty session `execute` (allowlist 0, payload `[0]`) is now
/// refused by the payload gate before the list-id / registry check is even
/// reached — `PayloadInvalid`, not a silent success.
#[test]
fn grok_exp04_empty_payload_list0_is_rejected() {
    let (mut svm, payer, _pk, account, _registry, _mut, _vault_ata) = live();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 0);
    let args = ExecuteArgs { root: None, payload: Some(vec![0]) };
    let (ix, _l) =
        execute_ix(session_kp.pubkey(), account, Some(session), false, None, None, None, &[], &args);
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::PAYLOAD_INVALID);
}

/// GROK-EXP-04, staged half: a finalized 1-byte `[0]` stage must NOT be
/// consume-closed by an empty execute — the reject happens before consume, so
/// the Stage survives for a legitimate `stage_close`.
#[test]
fn grok_exp04_empty_staged_payload_does_not_consume_stage() {
    let (mut svm, payer, pk, account, _registry, _mut, _vault_ata) = live();
    let submitter = Keypair::new();
    let (stage, creator) = stage_payload(&mut svm, &payer, &account, &[0u8]);
    let args_shape = ExecuteArgs { root: None, payload: None };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, Some(stage), None, Some(creator), &[], &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&[0u8], &logical));
    let args = ExecuteArgs { root: Some(root), payload: None };
    let (ix, _l) =
        execute_ix(submitter.pubkey(), account, None, true, Some(stage), None, Some(creator), &[], &args);
    // This is the ROOT path, so the ceremony's nonce is also at stake: the
    // reject happens before `verify_and_consume`, and the whole transaction
    // reverts regardless — so the user's assertion is not burned by a failed
    // staged execute and can be retried (WRD-STAGE-02).
    let nonce_before = read_smart_account(&svm, &account).root_nonce;
    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::PAYLOAD_INVALID);
    assert!(
        svm.get_account(&stage).map(|a| a.lamports > 0).unwrap_or(false),
        "the stage must survive an empty execute"
    );
    assert_eq!(
        read_smart_account(&svm, &account).root_nonce,
        nonce_before,
        "a failed staged execute must not consume the root nonce either"
    );
}

/// Negative control kept from Grok's memo: the session path denies MintTo too.
/// It now fails on the deny-list (which runs before the registry), earlier than
/// the `RegistryDenied` the memo observed — a strictly stronger verdict.
#[test]
fn grok_exp02_session_mint_to_is_deny_listed() {
    let (mut svm, payer, _pk, account, registry, _mut, _vault_ata) = live();
    let mint = Pubkey::new_from_array([0x44; 32]);
    set_mint_with_authority(&mut svm, &mint, &account, 6, 1_000);
    let attacker = Pubkey::new_unique();
    let dest = ata(&attacker, &mint);
    set_token_account(&mut svm, &dest, &mint, &attacker, 0);
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let remaining = vec![
        AccountMeta::new(mint, false),
        AccountMeta::new(dest, false),
        AccountMeta::new_readonly(SPL_TOKEN_ID, false),
    ];
    let mut mint_to = vec![7u8];
    mint_to.extend_from_slice(&42_000u64.to_le_bytes());
    let payload = encode_payload(&[(
        4,
        &[(2, FLAG_WRITABLE), (3, FLAG_WRITABLE), (0, FLAG_SIGNER), (4, 0)],
        &mint_to,
    )]);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) = execute_ix(
        session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args,
    );
    expect_reject(&mut svm, &[&payer, &session_kp], &[ix], 0, err::DENY_LISTED);
}

/// GROK-EXP-03 through generic root `execute`: a writable Stake-owned remaining
/// account is refused before any CPI — `UnsupportedAccountKind` — even though
/// no inner instruction targets it. Proves the conservation owner-reject
/// without needing a live Stake CPI.
#[test]
fn grok_exp03_writable_stake_owned_remaining_rejected() {
    let (mut svm, payer, pk, account, _registry, mutator_id, _vault_ata) = live();
    let stake_acct = Pubkey::new_unique();
    svm.set_account(
        stake_acct,
        Account {
            lamports: 10_000_000_000,
            data: vec![0u8; 200],
            owner: warden::constants::STAKE_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    let submitter = Keypair::new();
    // One honest mutator noop, plus the writable stake account riding in
    // remaining (not referenced by the payload — the pre-CPI snapshot scan
    // still refuses it).
    let remaining = vec![
        AccountMeta::new(stake_acct, false),           // logical 2 (writable, stake-owned)
        AccountMeta::new_readonly(mutator_id, false),  // logical 3 mutator
    ];
    let inner: [(u8, u8); 0] = [];
    let data = mutator::instruction_discriminator("noop").to_vec();
    let payload = encode_payload(&[(3, &inner, &data)]);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args);
    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::UNSUPPORTED_ACCOUNT_KIND);
}

// ---------------------------------------------------------------------------
// WRDF-0105 ROUND 4 / Grok review (2026-08-23): the CLASS, not the instance.
//
// Rounds 1–3 each closed one more *instance* of the same shape: a role the
// snapshot did not extract, reachable through a READ-ONLY mint. The class is
// structural, not enumerative — `execute`'s gate consults ONLY
// `MintSnap::holds_authority`, which knows five roles; `scan_extensions`
// extracts authority pubkeys for ONLY `TransferFeeConfig` and
// `PermanentDelegate`. `TransferHook` (14) and the confidential family (4/5/16/
// 17/24) set a danger bit and NO pubkey; every other extension type falls to
// `unrecognized_ext`. And `prescan_vault_mints` — the "different axis" the old
// comment pointed at — only refuses an unmodelable mint when it is WRITABLE.
//
// So a READ-ONLY mint whose PDA-held authority lives in an unmodelled extension
// was caught by NOTHING. Scope, per a second static review against
// spl-token-2022 10.0.0 (the runtime LiteSVM 0.12.0 embeds), stated honestly
// rather than dramatically:
//
//   * `ConfidentialTransferMint.authority` (types 4/5) is the one confirmed
//     LIVE read-only bypass today: `ApproveAccount` takes the mint READ-ONLY
//     and sets a third party's token account `approved`. That is an unmetered
//     third-party ACCOUNT-STATE change — NOT a demonstrated transfer or burn.
//   * `TransferHook.authority` is a real unextracted role, but exercising it
//     mutates the mint, so a WRITABLE mint is required and
//     `prescan_vault_mints` already refuses it. Belt-and-braces here, not a
//     live hole. (`TransferHook.program_id` is an executable target, not a
//     signer role — correctly not extracted.)
//   * The ~11 catch-all roles are the same story: authority-exercise mutates or
//     closes the mint, so they are predicate omissions, not present bypasses.
//
// The STRUCTURAL argument is what justifies the rule anyway: rounds 1–3 each
// closed one instance, and the enumeration missed the next one every time —
// most expensively `PermanentDelegate`, which WAS proven (in
// `wrdf0105_root_execute_permanent_delegate_third_party_drain_rejected`) to
// move 9,000 tokens of a third party with zero recorded outflow and no cap
// debited.
//
// The fix keeps `holds_authority` as the "vault-controlled" test and ADDS a
// second, orthogonal refusal in the generic-`execute` gate: any mint whose
// authority semantics the snapshot cannot represent at all is refused
// regardless of who holds what, with its OWN error
// (`UnmodelableMintExtensionInPayload`) so an on-chain reader can tell the two
// refusals apart. Tests 1–2 below are the redness cases; tests 3–5 are the
// CONTROLS that pin the narrowness property (a stranger-held mint using an
// extension we HAVE modelled still works).
// ---------------------------------------------------------------------------

/// Plant a **Token-2022** mint carrying ONE arbitrary TLV entry of `ext_type`
/// with `value` as its body, and every classic authority role unset. Same byte
/// layout as [`set_t22_transfer_fee_mint`] / [`set_t22_permanent_delegate_mint`],
/// generalised over the extension type so an UNMODELLED extension can be built
/// without teaching the helper about it:
///
/// ```text
///   [0..82)    classic Mint base (all authorities None)
///   [82..165)  zero padding — the T22 crate REQUIRES this to be all zeroes
///   [165]      AccountType::Mint = 1
///   [166..]    TLV: type u16 LE ‖ len u16 LE ‖ value
/// ```
fn set_t22_mint_with_ext(svm: &mut LiteSVM, mint: &Pubkey, ext_type: u16, value: &[u8]) {
    use solana_sdk::program_option::COption;
    use spl_token::state::Mint;
    let m = Mint {
        // Every CLASSIC role deliberately unset, and (below) every extension
        // authority is a STRANGER: whatever this mint trips cannot be
        // `holds_authority`, so the reject provably comes from the new rule.
        mint_authority: COption::None,
        supply: 1_000,
        decimals: 6,
        is_initialized: true,
        freeze_authority: COption::None,
    };
    let mut data = vec![0u8; Mint::LEN];
    m.pack_into_slice(&mut data);
    data.resize(165, 0); // [82..165) padding
    data.push(1); // AccountType::Mint
    data.extend_from_slice(&ext_type.to_le_bytes());
    data.extend_from_slice(&(value.len() as u16).to_le_bytes());
    data.extend_from_slice(value);
    assert_eq!(data.len(), 166 + 4 + value.len());
    svm.set_account(
        *mint,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(data.len()),
            data,
            owner: SPL_TOKEN_2022_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account (T22 mint with one TLV extension)");
}

/// REDNESS 1 — a READ-ONLY Token-2022 mint carrying a `ConfidentialTransferMint`
/// (type 4) extension in a ROOT `execute` account list is refused
/// `UnmodelableMintExtensionInPayload`.
///
/// This is the mask entry doing REAL work today. `ConfidentialTransferMint`'s
/// value begins with `authority: OptionalNonZeroPubkey` — a genuine Solana
/// signer role that `scan_extensions` collapses to `DANGER_CONFIDENTIAL` with
/// NO pubkey extracted, so `holds_authority` cannot see it. Token-2022
/// `ApproveAccount` takes the mint **READ-ONLY** and lets that authority set a
/// third party's token account to `approved` — so `prescan_vault_mints`'s
/// writable-mint fallback never fires either. Scope stated honestly: that is an
/// unmetered third-party ACCOUNT-STATE change, not a demonstrated transfer or
/// burn primitive.
///
/// The authority here is a STRANGER precisely so the reject cannot be
/// attributed to `holds_authority`: the mint is refused because the snapshot
/// cannot MODEL it, not because of who holds it.
#[test]
fn wrdf0105r4_root_execute_with_readonly_confidential_mint_rejected() {
    let conf_mint = Pubkey::new_from_array([0x5f; 32]);
    let stranger_authority = Pubkey::new_unique();
    // `{ authority: OptionalNonZeroPubkey (32), auto_approve_new_accounts:
    // PodBool (1), auditor_elgamal_pubkey: OptionalNonZeroElGamalPubkey (32) }`.
    let mut value = vec![0u8; 65];
    value[0..32].copy_from_slice(stranger_authority.as_ref());
    let (mut svm, payer, submitter, vault_ata, dest, precompile, ix) =
        root_execute_with_extra_readonly_mint(conf_mint, |svm, _account| {
            // 4 = ExtensionType::ConfidentialTransferMint.
            set_t22_mint_with_ext(svm, &conf_mint, 4, &value);
        });
    expect_reject(
        &mut svm,
        &[&payer, &submitter],
        &[precompile, ix],
        1,
        err::UNMODELABLE_MINT_EXTENSION_IN_PAYLOAD,
    );
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS, "the transfer never ran");
    assert_eq!(token_amount(&svm, &dest), 0);
}

/// REDNESS 1b — the same refusal for a READ-ONLY `TransferHook` (type 14) mint.
///
/// Recorded with its scope stated precisely, because it is easy to overclaim:
/// `TransferHook.program_id` is an EXECUTABLE target, not a signer role, so not
/// extracting it grants nothing and is correct. `TransferHook.authority` IS a
/// real reassignable role, but exercising it (`UpdateTransferHook`) MUTATES the
/// mint, which makes the mint WRITABLE and therefore trips the existing
/// `prescan_vault_mints` rule at `conservation/compare.rs`. So this test does
/// **not** pin a live read-only bypass — it pins the fail-closed rule's
/// belt-and-braces coverage of a danger class whose authority pubkey the
/// snapshot does not extract, on a path (`execute`) that forwards the PDA
/// signer into arbitrary nested CPIs.
#[test]
fn wrdf0105r4_root_execute_with_readonly_transfer_hook_mint_rejected() {
    let hook_mint = Pubkey::new_from_array([0x5c; 32]);
    let stranger_authority = Pubkey::new_unique();
    let stranger_program = Pubkey::new_unique();
    let mut value = vec![0u8; 64];
    value[0..32].copy_from_slice(stranger_authority.as_ref());
    value[32..64].copy_from_slice(stranger_program.as_ref());
    let (mut svm, payer, submitter, vault_ata, dest, precompile, ix) =
        root_execute_with_extra_readonly_mint(hook_mint, |svm, _account| {
            // 14 = ExtensionType::TransferHook.
            set_t22_mint_with_ext(svm, &hook_mint, 14, &value);
        });
    expect_reject(
        &mut svm,
        &[&payer, &submitter],
        &[precompile, ix],
        1,
        err::UNMODELABLE_MINT_EXTENSION_IN_PAYLOAD,
    );
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS, "the transfer never ran");
    assert_eq!(token_amount(&svm, &dest), 0);
}

/// REDNESS 2 — a READ-ONLY Token-2022 mint carrying an extension type the scan
/// does not model AT ALL is refused `UnmodelableMintExtensionInPayload`.
///
/// `MintCloseAuthority` is type 3, a real Token-2022 extension that
/// `scan_extensions`'s `match` has no arm for, so it lands in the `_ =>
/// unrecognized_ext = true` catch-all. Its value is a single
/// `OptionalNonZeroPubkey` close authority — REASSIGNABLE, and invisible to
/// `holds_authority`.
///
/// Scope, stated precisely rather than dramatically: under spl-token-2022
/// 10.0.0 this role (and the other ~10 unextracted ones —
/// `InterestBearingConfig.rate_authority`, `MetadataPointer.authority`,
/// `TokenMetadata.update_authority`, `GroupPointer`/`GroupMemberPointer`
/// `.authority`, `TokenGroup.update_authority`,
/// `ScaledUiAmountConfig.authority`, `PausableConfig.authority`,
/// `ConfidentialTransferFeeConfig.authority`) is a predicate OMISSION but not a
/// presently-demonstrated read-only bypass: exercising any of them mutates or
/// closes the authority-bearing mint, so the mint is WRITABLE and
/// `prescan_vault_mints` already refuses it. What this test pins is that the
/// rule is STRUCTURAL rather than enumerative — it needs no list of which
/// extension is dangerous, so a Token-2022 extension invented tomorrow, whose
/// authority semantics may well NOT require a writable mint, is covered on the
/// day it ships instead of after the next review round finds it.
#[test]
fn wrdf0105r4_root_execute_with_readonly_unmodelled_ext_mint_rejected() {
    let odd_mint = Pubkey::new_from_array([0x5d; 32]);
    let stranger_close_authority = Pubkey::new_unique();
    let mut value = vec![0u8; 32];
    value[0..32].copy_from_slice(stranger_close_authority.as_ref());
    let (mut svm, payer, submitter, vault_ata, dest, precompile, ix) =
        root_execute_with_extra_readonly_mint(odd_mint, |svm, _account| {
            // 3 = ExtensionType::MintCloseAuthority — a REAL type with no arm
            // in `scan_extensions`, so `unrecognized_ext` is what it sets.
            set_t22_mint_with_ext(svm, &odd_mint, 3, &value);
        });
    expect_reject(
        &mut svm,
        &[&payer, &submitter],
        &[precompile, ix],
        1,
        err::UNMODELABLE_MINT_EXTENSION_IN_PAYLOAD,
    );
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS, "the transfer never ran");
    assert_eq!(token_amount(&svm, &dest), 0);
}

/// CONTROL (narrowness C) — a plain CLASSIC-SPL mint with no TLV tail at all,
/// and no authorities whatsoever, still rides through generic `execute`.
///
/// This is not a redness case: it passes at the vulnerable base too. It exists
/// so the two rejects above cannot be explained by "any extra mint in the list
/// is now refused". Narrowness controls A and B — the stranger-held
/// `TransferFeeConfig` and `PermanentDelegate` mints, both extensions whose
/// authority field IS extracted — are
/// `wrdf0105_root_execute_with_stranger_t22_all_four_authorities_allowed` and
/// `wrdf0105_root_execute_with_stranger_permanent_delegate_mint_allowed`, which
/// must keep passing UNCHANGED.
#[test]
fn wrdf0105r4_root_execute_with_plain_classic_spl_mint_still_allowed() {
    use solana_sdk::program_option::COption;
    use spl_token::state::Mint;
    let plain_mint = Pubkey::new_from_array([0x5e; 32]);
    let (mut svm, payer, submitter, vault_ata, dest, precompile, ix) =
        root_execute_with_extra_readonly_mint(plain_mint, |svm, _account| {
            let m = Mint {
                mint_authority: COption::None,
                supply: 1_000,
                decimals: 6,
                is_initialized: true,
                freeze_authority: COption::None,
            };
            let mut data = vec![0u8; Mint::LEN];
            m.pack_into_slice(&mut data);
            svm.set_account(
                plain_mint,
                Account {
                    lamports: svm.minimum_balance_for_rent_exemption(Mint::LEN),
                    data,
                    owner: SPL_TOKEN_ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .expect("set_account (plain classic SPL mint)");
        });
    expect_ok(&mut svm, &[&payer, &submitter], &[precompile, ix]);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS - 400_000, "the transfer ran normally");
    assert_eq!(token_amount(&svm, &dest), 400_000);
}

// ---------------------------------------------------------------------------
// FABLE AUDIT P-1 (2026-09-02): the ACCOUNT-level delegate, not the mint's.
//
// WRDF-0105 closed the five MINT-level authority roles the PDA can hold. It
// never looked at the token-ACCOUNT-level `delegate` field: classic SPL Token
// `Approve` lets the owner of ANY token account name the SmartAccount PDA as
// its delegate for `delegated_amount` tokens, and the token program then
// accepts the PDA as the authority of `Transfer` (tag 3), `TransferChecked`
// (12), `Burn` (8) and `BurnChecked` (15) from that account. Every one of those
// tags is `SplTokenOp::Other` to `classify_spl_token_op`, so `deny_scan` never
// names them; list 1 of the default registry carries [3] and [12] with
// `ROLE_VAULT_SIGNER`, which checks ONLY that the authority position IS the
// vault and IS a signer — it does not ask whether the source is the vault's;
// and conservation skips every account whose token-level owner is not the
// vault (`compare.rs` step 4), so `outflow` is zero and no bucket is debited.
//
// Concretely: a third party that approved the PDA as delegate (a pattern a
// user's OTHER wallet might legitimately use to let the smart account manage
// it) can be drained by a SESSION key — the least-privileged path — with no
// cap, no bucket and no conservation record. The redness tests below prove the
// drain end to end at the vulnerable base through a real SPL CPI; the fix is a
// pre-CPI reject of any token account in the list that the vault does not own
// but is the delegate of (`VaultDelegatedForeignAccountInPayload`), applied to
// the BEFORE snapshot. (An AFTER re-application was tried and is VOID: the
// token program clears `delegate` when the approval is fully spent, so the
// drain shape leaves no trace — see `reject_vault_delegated_foreign_accounts`.)
// ---------------------------------------------------------------------------

/// Plant a classic SPL token account of `mint`, token-level owner `owner`, with
/// `delegate` approved for `delegated_amount` — the state `Approve` leaves
/// behind, planted directly so no `Approve` has to ride through `execute`.
fn set_delegated_token_account(
    svm: &mut LiteSVM,
    address: &Pubkey,
    mint: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    delegate: &Pubkey,
    delegated_amount: u64,
) {
    use solana_sdk::program_option::COption;
    use spl_token::state::{Account as SplAccount, AccountState};
    let a = SplAccount {
        mint: *mint,
        owner: *owner,
        amount,
        delegate: COption::Some(*delegate),
        state: AccountState::Initialized,
        is_native: COption::None,
        delegated_amount,
        close_authority: COption::None,
    };
    let mut data = vec![0u8; SplAccount::LEN];
    a.pack_into_slice(&mut data);
    svm.set_account(
        *address,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(SplAccount::LEN),
            data,
            owner: SPL_TOKEN_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account (delegated token account)");
}

/// REDNESS 1 — **the exploit, on the SESSION path**: a session key with the
/// production allowlist (list 1) runs a plain SPL `Transfer` whose SOURCE is a
/// third party's token account that has the vault PDA as its delegate, naming
/// logical 0 (the PDA) as the authority. At the vulnerable base this SUCCEEDS
/// — registry role check satisfied (authority position is the vault signer),
/// nothing deny-listed, conservation skips both non-vault accounts, no cap
/// debited — and 9,000 of the victim's tokens land in the thief's account.
/// With the fix the whole `execute` is refused before any CPI, with its own
/// error, and neither balance moves.
#[test]
fn fable_p1_session_transfer_from_vault_delegated_stranger_account_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);

    let victim_owner = Pubkey::new_unique();
    let victim = Pubkey::new_from_array([0x61; 32]);
    set_delegated_token_account(&mut svm, &victim, &tok_mint(), &victim_owner, 9_000, &account, 9_000);
    let thief = dest_ata(&mut svm);

    // Same shape as the honest transfer, with the victim where the vault ATA
    // would be: source=2 (w), dest=3 (w), authority=PDA(0), token program=4.
    let remaining = spl_transfer_remaining(victim, thief);
    let payload = spl_transfer_payload(9_000);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) = execute_ix(
        session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args,
    );

    expect_reject(
        &mut svm,
        &[&payer, &session_kp],
        &[ix],
        0,
        err::VAULT_DELEGATED_FOREIGN_ACCOUNT_IN_PAYLOAD,
    );
    assert_eq!(token_amount(&svm, &victim), 9_000, "the victim was not drained");
    assert_eq!(token_amount(&svm, &thief), 0, "the thief received nothing");
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS, "the vault is untouched either way");
}

/// REDNESS 2 — the same hole on the ROOT path with `Burn` (tag 8), which has no
/// destination at all: the delegate simply destroys the third party's tokens.
/// `Burn` takes the mint WRITABLE; it is a plain classic mint whose authorities
/// are a stranger's, so neither WRDF-0105 gate fires and `supply` is
/// deliberately not a conservation field — at the base the burn goes through.
#[test]
fn fable_p1_root_burn_from_vault_delegated_stranger_account_rejected() {
    let (mut svm, payer, pk, account, _registry, _mut, _vault_ata) = live();
    let submitter = Keypair::new();

    let stranger = Pubkey::new_unique();
    let mint = Pubkey::new_from_array([0x62; 32]);
    set_mint_with_authority(&mut svm, &mint, &stranger, 6, 100_000);
    let victim_owner = Pubkey::new_unique();
    let victim = Pubkey::new_from_array([0x63; 32]);
    set_delegated_token_account(&mut svm, &victim, &mint, &victim_owner, 9_000, &account, 9_000);

    // Burn accounts: source (w), mint (w), authority — authority = logical 0.
    let remaining = vec![
        AccountMeta::new(victim, false),                // logical 2 source
        AccountMeta::new(mint, false),                  // logical 3 mint
        AccountMeta::new_readonly(SPL_TOKEN_ID, false), // logical 4 program
    ];
    let mut burn = vec![8u8];
    burn.extend_from_slice(&9_000u64.to_le_bytes());
    let payload = encode_payload(&[(
        4,
        &[(2, FLAG_WRITABLE), (3, FLAG_WRITABLE), (0, FLAG_SIGNER), (4, 0)],
        &burn,
    )]);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args);

    expect_reject(
        &mut svm,
        &[&payer, &submitter],
        &[precompile, ix],
        1,
        err::VAULT_DELEGATED_FOREIGN_ACCOUNT_IN_PAYLOAD,
    );
    assert_eq!(token_amount(&svm, &victim), 9_000, "nothing was burned");
    let m = spl_token::state::Mint::unpack(&svm.get_account(&mint).unwrap().data).unwrap();
    assert_eq!(m.supply, 100_000, "supply unchanged");
}

/// CONTROL (narrowness) — a third party's token account delegated to SOMEONE
/// ELSE, riding read-only beside an ordinary vault transfer, does not trip the
/// rule: the gate keys on WHO the delegate is, exactly like the WRDF-0105 mint
/// gate keys on who holds the mint roles. Passes at the base too; it exists so
/// the rejects above cannot be explained by "any delegated account is refused".
#[test]
fn fable_p1_stranger_account_delegated_to_third_party_still_allowed() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let dest = dest_ata(&mut svm);

    let other_delegate = Pubkey::new_unique();
    let bystander = Pubkey::new_from_array([0x65; 32]);
    set_delegated_token_account(
        &mut svm, &bystander, &tok_mint(), &Pubkey::new_unique(), 9_000, &other_delegate, 9_000,
    );

    let mut remaining = spl_transfer_remaining(vault_ata, dest);
    remaining.push(AccountMeta::new_readonly(bystander, false)); // logical 6, unreferenced
    let payload = spl_transfer_payload(400_000);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) = execute_ix(
        session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args,
    );
    expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS - 400_000);
    assert_eq!(token_amount(&svm, &dest), 400_000);
    assert_eq!(token_amount(&svm, &bystander), 9_000);
}

// ---------------------------------------------------------------------------
// Codex sol@max round over the P-1 fix (thread 06aac9dfd711-20260902T044843Z):
// WRDF-0109 — the rule ran over `before`, which snapshots ONLY `remaining`;
// logical[1] (the `Signer`, an arbitrary keypair address) was never looked at.
// WRDF-0110 — an SPL Multisig naming the vault PDA among its signers is a
// third authority shape (after mint roles and the account delegate) the PDA
// can satisfy; a 355-byte account classifies as "neither" and rides through.
// ---------------------------------------------------------------------------

/// `execute_ix` with the signer slot passed WRITABLE — what an attacker whose
/// keypair address is a token account must do for it to be a Transfer source.
/// Nothing in the handler pins logical[1] read-only; the harness default is a
/// convention, not a rule.
#[allow(clippy::too_many_arguments)]
fn execute_ix_writable_signer(
    signer: Pubkey,
    smart_account: Pubkey,
    session: Option<Pubkey>,
    with_sysvar: bool,
    registry: Option<Pubkey>,
    remaining: &[AccountMeta],
    args: &ExecuteArgs,
) -> (Instruction, Vec<Logical>) {
    let (mut ix, mut logical) =
        execute_ix(signer, smart_account, session, with_sysvar, None, registry, None, remaining, args);
    ix.accounts[1] = AccountMeta::new(signer, true);
    logical[1].is_writable = true;
    (ix, logical)
}

/// Plant an SPL Token `Multisig` (355 B, owned by the token program):
/// `m`-of-`signers.len()`, initialized.
fn set_multisig(svm: &mut LiteSVM, address: &Pubkey, m: u8, signers: &[Pubkey]) {
    use spl_token::state::Multisig;
    let mut ms = Multisig { m, n: signers.len() as u8, is_initialized: true, signers: [Pubkey::default(); 11] };
    ms.signers[..signers.len()].copy_from_slice(signers);
    let mut data = vec![0u8; Multisig::LEN];
    ms.pack_into_slice(&mut data);
    svm.set_account(
        *address,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(Multisig::LEN),
            data,
            owner: SPL_TOKEN_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account (multisig)");
}

/// Plant a classic SPL token account with NO delegate (the shape `InitializeAccount`
/// leaves behind), token-level owner `owner`.
fn set_plain_token_account(svm: &mut LiteSVM, address: &Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) {
    use solana_sdk::program_option::COption;
    use spl_token::state::{Account as SplAccount, AccountState};
    let a = SplAccount {
        mint: *mint,
        owner: *owner,
        amount,
        delegate: COption::None,
        state: AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    };
    let mut data = vec![0u8; SplAccount::LEN];
    a.pack_into_slice(&mut data);
    svm.set_account(
        *address,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(SplAccount::LEN),
            data,
            owner: SPL_TOKEN_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account (plain token account)");
}

/// The P-1 exploit moved to the SIGNER slot, ROOT path: the submitter's own
/// keypair address IS the vault-delegated token account (logical 1, passed
/// writable) and is the Transfer source. At the WRD-EXEC-13 base this drains
/// the account: the rule only ever saw `remaining`.
#[test]
fn codex_wrdf0109_root_transfer_from_vault_delegated_account_at_signer_slot_rejected() {
    let (mut svm, payer, pk, account, _registry, _mut, _vault_ata) = live();
    let submitter = Keypair::new();
    let victim_owner = Pubkey::new_unique();
    // The signer slot is the victim account: a keypair address the submitter
    // controls, whose token-level owner is a stranger and whose delegate is the vault.
    set_delegated_token_account(&mut svm, &submitter.pubkey(), &tok_mint(), &victim_owner, 9_000, &account, 9_000);
    let thief = dest_ata(&mut svm);

    // Transfer: source = logical 1 (w), dest = 2 (w), authority = PDA (0), program = 3.
    let remaining = vec![
        AccountMeta::new(thief, false),                 // logical 2
        AccountMeta::new_readonly(SPL_TOKEN_ID, false), // logical 3
        mint_meta(),                                    // logical 4
    ];
    let mut data = vec![3u8];
    data.extend_from_slice(&9_000u64.to_le_bytes());
    let payload = encode_payload(&[(
        3,
        &[(1, FLAG_WRITABLE), (2, FLAG_WRITABLE), (0, FLAG_SIGNER), (3, 0)],
        &data,
    )]);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix_writable_signer(submitter.pubkey(), account, None, true, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix_writable_signer(submitter.pubkey(), account, None, true, None, &remaining, &args);

    expect_reject(
        &mut svm,
        &[&payer, &submitter],
        &[precompile, ix],
        1,
        err::VAULT_DELEGATED_FOREIGN_ACCOUNT_IN_PAYLOAD,
    );
    assert_eq!(token_amount(&svm, &submitter.pubkey()), 9_000, "the victim account at the signer slot was not drained");
    assert_eq!(token_amount(&svm, &thief), 0, "the thief received nothing");
}

/// Same hole on the SESSION path: the session key's own address is the
/// delegated account.
#[test]
fn codex_wrdf0109_session_transfer_from_vault_delegated_account_at_signer_slot_rejected() {
    let (mut svm, payer, _pk, account, registry, _mut, _vault_ata) = live();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let victim_owner = Pubkey::new_unique();
    set_delegated_token_account(&mut svm, &session_kp.pubkey(), &tok_mint(), &victim_owner, 9_000, &account, 9_000);
    let thief = dest_ata(&mut svm);

    let remaining = vec![
        AccountMeta::new(thief, false),                 // logical 2
        AccountMeta::new_readonly(SPL_TOKEN_ID, false), // logical 3
        mint_meta(),                                    // logical 4
    ];
    let mut data = vec![3u8];
    data.extend_from_slice(&9_000u64.to_le_bytes());
    let payload = encode_payload(&[(
        3,
        &[(1, FLAG_WRITABLE), (2, FLAG_WRITABLE), (0, FLAG_SIGNER), (3, 0)],
        &data,
    )]);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) = execute_ix_writable_signer(
        session_kp.pubkey(), account, Some(session), false, Some(registry), &remaining, &args,
    );

    expect_reject(
        &mut svm,
        &[&payer, &session_kp],
        &[ix],
        0,
        err::VAULT_DELEGATED_FOREIGN_ACCOUNT_IN_PAYLOAD,
    );
    assert_eq!(token_amount(&svm, &session_kp.pubkey()), 9_000, "the victim account at the signer slot was not drained");
    assert_eq!(token_amount(&svm, &thief), 0, "the thief received nothing");
}

/// WRDF-0110 — the MULTISIG authority shape, ROOT path: a 1-of-1 SPL Multisig
/// `M` whose only member is the vault PDA owns a stranger's token account;
/// `Transfer(source, dest, authority = M, signers = [PDA])` under the PDA's
/// forwarded signature moves the tokens. At the base: `M` is 355 B, so the
/// snapshot classifies it as "neither" (`token_parse_failed`, tolerated for a
/// read-only non-vault account), the source is not vault-owned, no delegate is
/// set, and nothing is metered. Fails closed pre-CPI with its own error.
#[test]
fn codex_wrdf0110_root_transfer_via_vault_member_multisig_rejected() {
    let (mut svm, payer, pk, account, _registry, _mut, _vault_ata) = live();
    let submitter = Keypair::new();
    let multisig = Pubkey::new_from_array([0x71; 32]);
    set_multisig(&mut svm, &multisig, 1, &[account]);
    let victim = Pubkey::new_from_array([0x72; 32]);
    set_plain_token_account(&mut svm, &victim, &tok_mint(), &multisig, 9_000);
    let thief = dest_ata(&mut svm);

    // Transfer: source (w), dest (w), authority = M (read-only, not a signer),
    // then the multisig member signer = PDA (0); program = 5.
    let remaining = vec![
        AccountMeta::new(victim, false),                // logical 2
        AccountMeta::new(thief, false),                 // logical 3
        AccountMeta::new_readonly(multisig, false),     // logical 4
        AccountMeta::new_readonly(SPL_TOKEN_ID, false), // logical 5
        mint_meta(),                                    // logical 6
    ];
    let mut data = vec![3u8];
    data.extend_from_slice(&9_000u64.to_le_bytes());
    let payload = encode_payload(&[(
        5,
        &[(2, FLAG_WRITABLE), (3, FLAG_WRITABLE), (4, 0), (0, FLAG_SIGNER), (5, 0)],
        &data,
    )]);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) =
        execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix(submitter.pubkey(), account, None, true, None, None, None, &remaining, &args);

    expect_reject(&mut svm, &[&payer, &submitter], &[precompile, ix], 1, err::VAULT_MULTISIG_MEMBER_IN_PAYLOAD);
    assert_eq!(token_amount(&svm, &victim), 9_000, "the multisig-owned account was not drained");
    assert_eq!(token_amount(&svm, &thief), 0, "the thief received nothing");
}

/// WRDF-0110, the MID-PAYLOAD variant: the multisig does not exist yet when
/// the BEFORE gate runs. The submitter's keypair address `M` (logical 1,
/// writable signer, pre-funded with rent) is a plain System account; the
/// payload runs `Allocate(355)` + `Assign(token program)` +
/// `InitializeMultisig2(M, [PDA])`, then the Transfer. Unlike the delegate
/// shape (the token program clears a spent delegate), a multisig is never
/// erased by the token program, so an AFTER re-application is not void here —
/// it is the only barrier. Refused after the CPIs with the same error.
#[test]
fn codex_wrdf0110_root_multisig_created_inside_payload_rejected() {
    let (mut svm, payer, pk, account, _registry, _mut, _vault_ata) = live();
    let multisig_kp = Keypair::new();
    let multisig = multisig_kp.pubkey();
    svm.airdrop(&multisig, 10_000_000).expect("pre-fund the future multisig");
    let victim = Pubkey::new_from_array([0x74; 32]);
    set_plain_token_account(&mut svm, &victim, &tok_mint(), &multisig, 9_000);
    let thief = dest_ata(&mut svm);

    let remaining = vec![
        AccountMeta::new(victim, false),                                      // logical 2
        AccountMeta::new(thief, false),                                       // logical 3
        AccountMeta::new_readonly(SPL_TOKEN_ID, false),                       // logical 4
        mint_meta(),                                                          // logical 5
        AccountMeta::new_readonly(anchor_lang::system_program::ID, false),    // logical 6
    ];
    // System: Allocate { space } = enum index 8; Assign { owner } = index 1.
    let mut allocate = 8u32.to_le_bytes().to_vec();
    allocate.extend_from_slice(&355u64.to_le_bytes());
    let mut assign = 1u32.to_le_bytes().to_vec();
    assign.extend_from_slice(SPL_TOKEN_ID.as_ref());
    // SPL Token: InitializeMultisig2 { m } = tag 19; accounts [multisig (w), ...signer pubkeys].
    let init_ms = vec![19u8, 1u8];
    let mut transfer = vec![3u8];
    transfer.extend_from_slice(&9_000u64.to_le_bytes());
    let payload = encode_payload(&[
        (6, &[(1, FLAG_WRITABLE | FLAG_SIGNER)], &allocate),
        (6, &[(1, FLAG_WRITABLE | FLAG_SIGNER)], &assign),
        (4, &[(1, FLAG_WRITABLE), (0, 0)], &init_ms),
        (4, &[(2, FLAG_WRITABLE), (3, FLAG_WRITABLE), (1, 0), (0, FLAG_SIGNER), (4, 0)], &transfer),
    ]);
    let args_shape = ExecuteArgs { root: None, payload: Some(payload.clone()) };
    let (_p, logical) = execute_ix_writable_signer(multisig, account, None, true, None, &remaining, &args_shape);
    let (precompile, root) = ceremony(&svm, &account, &pk, execute_action_hash(&payload, &logical));
    let args = ExecuteArgs { root: Some(root), payload: Some(payload) };
    let (ix, _l) = execute_ix_writable_signer(multisig, account, None, true, None, &remaining, &args);

    expect_reject(&mut svm, &[&payer, &multisig_kp], &[precompile, ix], 1, err::VAULT_MULTISIG_MEMBER_IN_PAYLOAD);
    assert_eq!(token_amount(&svm, &victim), 9_000, "the account owned by the in-payload multisig was not drained");
    assert_eq!(token_amount(&svm, &thief), 0, "the thief received nothing");
    assert!(svm.get_account(&multisig).unwrap().data.is_empty(), "the whole tx reverted: no multisig exists");
}

/// CONTROL (narrowness) — a multisig whose members are all strangers, riding
/// read-only beside an honest vault transfer, is untouched: the gate keys on
/// WHO the members are, not on "any multisig in the list". Passes at the base.
#[test]
fn codex_wrdf0110_stranger_multisig_in_list_still_allowed() {
    let (mut svm, payer, _pk, account, registry, _mut, vault_ata) = live();
    let (session, session_kp) = plant_session(&mut svm, &account, OP_EXECUTE, 1);
    let dest = dest_ata(&mut svm);
    let bystander = Pubkey::new_from_array([0x73; 32]);
    set_multisig(&mut svm, &bystander, 2, &[Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique()]);

    let mut remaining = spl_transfer_remaining(vault_ata, dest);
    remaining.push(AccountMeta::new_readonly(bystander, false)); // logical 6, unreferenced
    let payload = spl_transfer_payload(400_000);
    let args = ExecuteArgs { root: None, payload: Some(payload) };
    let (ix, _l) = execute_ix(
        session_kp.pubkey(), account, Some(session), false, None, Some(registry), None, &remaining, &args,
    );
    expect_ok(&mut svm, &[&payer, &session_kp], &[ix]);
    assert_eq!(token_amount(&svm, &vault_ata), VAULT_TOKENS - 400_000);
    assert_eq!(token_amount(&svm, &dest), 400_000);
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
    pub const STAGE_INVALID: u32 = 6047;
    pub const STAGE_EXPIRED: u32 = 6048;
    pub const COMPUTE_BUDGET_IN_EXECUTE: u32 = 6049;
    pub const DENY_LISTED: u32 = 6050;
    pub const TOO_MANY_EXECUTE_ACCOUNTS: u32 = 6056;
    pub const JUPITER_VIA_SWAP_ONLY: u32 = 6058;
    pub const DUPLICATE_LOGICAL_ACCOUNT: u32 = 6059;
    pub const UNSUPPORTED_ACCOUNT_KIND: u32 = 6040;
    pub const VAULT_CONTROLLED_MINT_IN_PAYLOAD: u32 = 6076;
    pub const UNMODELABLE_MINT_EXTENSION_IN_PAYLOAD: u32 = 6077;
    pub const VAULT_DELEGATED_FOREIGN_ACCOUNT_IN_PAYLOAD: u32 = 6078;
    pub const VAULT_MULTISIG_MEMBER_IN_PAYLOAD: u32 = 6079;
}
