//! LiteSVM coverage of `swap` (Task 6) — `execute` specialised to Jupiter v6,
//! driven against `test-jup-mock` (a REAL CPI at the real v6 account/arg
//! layout; the warden `.so` is built `--features test-jup` so `SWAP_TARGET_
//! PROGRAM` == the mock).
//!
//! The adapter's job (spec §5.2.7): pin the program + discriminator, require
//! `platform_fee_bps == 85`, decode the route's declared `in_amount` and bound
//! it by `max_in ≤ caps` BEFORE the CPI, pin the source/dest/fee accounts, then
//! net-check the outflow (in_mint ≤ max_in) and the out-ATA gain (≥ min_out).

mod common;

use common::jup::{self, RouteAccounts};
use common::passkey::{self, TestPasskey, FLAGS_UP_UV, TEST_ORIGIN};
use common::token::{ata, set_mint, set_token_account, token_amount};
use common::{
    create_smart_account, init_registry_ix, read_smart_account, registry_pda, session_pda,
    set_program_data, warp_clock, SmartAccountFixture,
};
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
use anchor_lang::{AnchorSerialize, Discriminator};
use warden::instructions::create_account::MIN_TIMELOCK_SECS;
use warden::instructions::swap::{SwapArgs, SwapBody, SWAP_VARIANT_ROUTE, SWAP_VARIANT_SHARED};
use warden::root_verify::transcript::{action_hash, b64url_no_pad, transcript_hash, OP_SWAP_ACTION};
use warden::root_verify::RootArgs;
use warden::state::{MintCap, PolicyArgs, SessionKey, OP_SWAP};

const NOW: i64 = 1_760_000_000;
const PACKET: usize = 1232;

fn in_mint() -> Pubkey {
    Pubkey::new_from_array([21u8; 32])
}
fn out_mint() -> Pubkey {
    Pubkey::new_from_array([22u8; 32])
}

const IN_PER_TX: u64 = 5_000_000;
const IN_DAY: u64 = 50_000_000;
const VAULT_IN: u64 = 10_000_000;
const POOL_OUT: u64 = 10_000_000;
const ROOT_EXPIRY_OFFSET: i64 = 300;
const SESSION_LIFE: i64 = 7 * 86_400;

fn swap_policy() -> PolicyArgs {
    PolicyArgs {
        version: 1,
        caps: vec![
            MintCap { mint: in_mint(), per_tx: IN_PER_TX, per_day: IN_DAY, per_30d: IN_DAY },
            MintCap { mint: out_mint(), per_tx: IN_PER_TX, per_day: IN_DAY, per_30d: IN_DAY },
        ],
        session_ceiling: vec![
            MintCap { mint: in_mint(), per_tx: IN_PER_TX, per_day: IN_DAY, per_30d: IN_DAY },
            MintCap { mint: out_mint(), per_tx: IN_PER_TX, per_day: IN_DAY, per_30d: IN_DAY },
        ],
        large_threshold: vec![
            MintCap { mint: in_mint(), per_tx: IN_PER_TX, per_day: 0, per_30d: 0 },
            MintCap { mint: out_mint(), per_tx: IN_PER_TX, per_day: 0, per_30d: 0 },
        ],
        timelock_secs: MIN_TIMELOCK_SECS,
        recovery_delay_secs: MIN_TIMELOCK_SECS,
        max_session_life_secs: SESSION_LIFE,
        session_ops_ceiling: OP_SWAP,
    }
}

struct Live {
    svm: LiteSVM,
    payer: Keypair,
    pk: TestPasskey,
    account: Pubkey,
    registry: Pubkey,
    treasury_owner: Pubkey,
    vault_in: Pubkey,
    vault_out: Pubkey,
    treasury_ata: Pubkey,
    pool_out: Pubkey,
    pool_in: Pubkey,
}

/// A live account bound to a registry whose treasury owns the fee ATA, funded
/// vault in/out ATAs, and a pre-funded mock pool.
fn live() -> Live {
    let (mut svm, payer) = common::setup();
    warp_clock(&mut svm, NOW);
    jup::add_jup_mock(&mut svm);

    // Registry init'd by the upgrade authority, its treasury = a chosen owner.
    let authority = Keypair::new();
    svm.airdrop(&authority.pubkey(), 1_000_000_000).unwrap();
    set_program_data(&mut svm, Some(authority.pubkey()));
    let (registry, _) = registry_pda();
    let treasury_owner = Pubkey::new_unique();
    send(&mut svm, &[&payer, &authority], &[init_registry_ix(payer.pubkey(), authority.pubkey(), treasury_owner)])
        .expect("init_registry");

    let pk = TestPasskey::new(3);
    let f = SmartAccountFixture { root_pubkey33: pk.pubkey33(), policy: swap_policy(), registry: Some(registry), ..Default::default() };
    let account = create_smart_account(&mut svm, &payer, &f, &pk);

    set_mint(&mut svm, &in_mint(), 6, 1_000_000_000);
    set_mint(&mut svm, &out_mint(), 6, 1_000_000_000);
    let vault_in = ata(&account, &in_mint());
    let vault_out = ata(&account, &out_mint());
    set_token_account(&mut svm, &vault_in, &in_mint(), &account, VAULT_IN);
    set_token_account(&mut svm, &vault_out, &out_mint(), &account, 0);

    // Treasury fee ATA (owned by registry.treasury), out_mint.
    let treasury_ata = ata(&treasury_owner, &out_mint());
    set_token_account(&mut svm, &treasury_ata, &out_mint(), &treasury_owner, 0);

    // Mock pool ATAs (pool authority PDA), pre-funded with out_mint.
    let (pool, _) = jup::pool_authority();
    let pool_out = ata(&pool, &out_mint());
    let pool_in = ata(&pool, &in_mint());
    set_token_account(&mut svm, &pool_out, &out_mint(), &pool, POOL_OUT);
    set_token_account(&mut svm, &pool_in, &in_mint(), &pool, 0);

    Live { svm, payer, pk, account, registry, treasury_owner, vault_in, vault_out, treasury_ata, pool_out, pool_in }
}

impl Live {
    fn route_accounts(&self, fee_account: Pubkey, extra: Option<Pubkey>) -> RouteAccounts {
        RouteAccounts {
            user_transfer_authority: self.account, // the vault PDA
            user_source_ata: self.vault_in,
            user_destination_ata: self.vault_out,
            destination_mint: out_mint(),
            platform_fee_account: fee_account,
            pool_out_ata: self.pool_out,
            pool_in_sink: self.pool_in,
            extra,
        }
    }
}

fn none_account() -> AccountMeta {
    AccountMeta::new_readonly(common::program_id(), false)
}

/// Route metas with the authority position forced to NON-signer (the vault PDA
/// cannot sign at the tx level; warden signs it for the CPI via invoke_signed),
/// and the `in_mint` account appended so conservation's rule-2a presence check
/// (the vault in-ATA's mint must be in the list) is satisfied — `out_mint` is
/// already present as the route's `destination_mint`. The trailing mint is
/// past every position the mock reads, so it is inert to the CPI.
fn swap_remaining(variant: u8, a: &RouteAccounts) -> Vec<AccountMeta> {
    let (mut metas, auth_idx) = match variant {
        SWAP_VARIANT_ROUTE => (jup::route_metas(a), 1usize),
        _ => (jup::shared_route_metas(a), 2usize),
    };
    metas[auth_idx].is_signer = false;
    metas.push(AccountMeta::new_readonly(in_mint(), false));
    metas
}

struct Logical {
    key: Pubkey,
    is_signer: bool,
    is_writable: bool,
}

#[allow(clippy::too_many_arguments)]
fn swap_ix(
    signer: Pubkey,
    account: Pubkey,
    session: Option<Pubkey>,
    with_sysvar: bool,
    stage: Option<Pubkey>,
    registry: Pubkey,
    stage_creator: Option<Pubkey>,
    remaining: &[AccountMeta],
    args: &SwapArgs,
) -> (Instruction, Vec<Logical>) {
    let mut data = Sha256::digest(b"global:swap")[..8].to_vec();
    args.serialize(&mut data).unwrap();
    let mut accounts = vec![
        AccountMeta::new(account, false),
        AccountMeta::new_readonly(signer, true),
        session.map_or_else(none_account, |s| AccountMeta::new(s, false)),
        if with_sysvar { AccountMeta::new_readonly(sysvar::instructions::ID, false) } else { none_account() },
        stage.map_or_else(none_account, |s| AccountMeta::new(s, false)),
        AccountMeta::new_readonly(registry, false),
        stage_creator.map_or_else(none_account, |c| AccountMeta::new(c, false)),
    ];
    accounts.extend_from_slice(remaining);

    let mut logical = vec![
        Logical { key: account, is_signer: false, is_writable: true },
        Logical { key: signer, is_signer: true, is_writable: false },
    ];
    for m in remaining {
        // Message-level writability is the UNION across the account list: the
        // vault PDA sits at the route authority position (read-only there) AND
        // as the writable `smart_account`, so its effective is_writable — which
        // is what warden hashes — is true. Mirror that here.
        logical.push(Logical {
            key: m.pubkey,
            is_signer: m.is_signer,
            is_writable: m.is_writable || m.pubkey == account,
        });
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

fn ceremony(svm: &LiteSVM, account: &Pubkey, pk: &TestPasskey, ah: [u8; 32]) -> (Instruction, RootArgs) {
    let st = read_smart_account(svm, account);
    let clock: Clock = svm.get_sysvar();
    let expiry_ts = clock.unix_timestamp + ROOT_EXPIRY_OFFSET;
    let signed_slot = clock.slot;
    let t = transcript_hash(
        &st.cluster_tag, &common::program_id(), account, st.generation, st.policy.version,
        st.root_nonce, expiry_ts, signed_slot, &ah,
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

#[allow(clippy::too_many_arguments)]
fn swap_action_hash(disc: [u8; 8], in_m: Pubkey, out_m: Pubkey, max_in: u64, min_out: u64, route_data: &[u8], logical: &[Logical]) -> [u8; 32] {
    let route_hash = solana_keccak_hasher::hashv(&[route_data]).to_bytes();
    let body = SwapBody { in_mint: in_m, out_mint: out_m, max_in, min_out, discriminator: disc, route_hash, accounts_hash: accounts_hash(logical) };
    let mut b = Vec::new();
    body.serialize(&mut b).unwrap();
    action_hash(OP_SWAP_ACTION, &b)
}

fn plant_session(svm: &mut LiteSVM, account: &Pubkey, ops_mask: u16) -> (Pubkey, Keypair) {
    let kp = Keypair::new();
    let (pda, bump) = session_pda(account, &kp.pubkey());
    let generation = read_smart_account(svm, account).generation;
    let mut caps = [MintCap::default(); 8];
    caps[0] = MintCap { mint: in_mint(), per_tx: IN_PER_TX, per_day: 0, per_30d: 0 };
    caps[1] = MintCap { mint: out_mint(), per_tx: IN_PER_TX, per_day: 0, per_30d: 0 };
    let mut lifetime_cap = [0u64; 8];
    lifetime_cap[0] = IN_DAY;
    lifetime_cap[1] = IN_DAY;
    let session = SessionKey {
        version: 1, bump, account: *account, pubkey: kp.pubkey(), kind: 0,
        expiry_ts: NOW + SESSION_LIFE, ops_mask, generation_at_grant: generation, caps,
        lifetime_cap, lifetime_spent: [0u64; 8], program_allowlist_id: 0, label: [0u8; 16], _reserved: [0u8; 64],
    };
    let mut data = SessionKey::DISCRIMINATOR.to_vec();
    session.serialize(&mut data).unwrap();
    svm.set_account(pda, Account {
        lamports: svm.minimum_balance_for_rent_exemption(data.len()), data,
        owner: common::program_id(), executable: false, rent_epoch: 0,
    }).expect("plant session");
    (pda, kp)
}

fn send(svm: &mut LiteSVM, signers: &[&Keypair], ixs: &[Instruction]) -> litesvm::types::TransactionResult {
    svm.expire_blockhash();
    let tx = Transaction::new(signers, Message::new(ixs, Some(&signers[0].pubkey())), svm.latest_blockhash());
    svm.send_transaction(tx)
}

fn expect_ok(svm: &mut LiteSVM, signers: &[&Keypair], ixs: &[Instruction]) {
    if let Err(e) = send(svm, signers, ixs) {
        panic!("expected success, got {:?}\n{:#?}", e.err, e.meta.logs);
    }
}

fn expect_reject(svm: &mut LiteSVM, signers: &[&Keypair], ixs: &[Instruction], ix_index: u8, code: u32) {
    match send(svm, signers, ixs) {
        Ok(_) => panic!("expected reject with custom {code}, got success"),
        Err(e) => match e.err {
            TransactionError::InstructionError(i, InstructionError::Custom(c)) => {
                assert_eq!(i, ix_index, "ix index; logs:\n{:#?}", e.meta.logs);
                assert_eq!(c, code, "custom code; logs:\n{:#?}", e.meta.logs);
            }
            other => panic!("expected Custom({code}) at {ix_index}, got {other:?}\n{:#?}", e.meta.logs),
        },
    }
}

// ===========================================================================
// Session path
// ===========================================================================

fn session_swap_args(l: &Live, variant: u8, in_amount: u64, quoted_out: u64, max_in: u64, min_out: u64, misbehave: u8) -> SwapArgs {
    let data = match variant {
        SWAP_VARIANT_ROUTE => jup::route_data(in_amount, quoted_out, misbehave),
        _ => jup::shared_route_data(in_amount, quoted_out, misbehave),
    };
    SwapArgs { root: None, variant, in_mint: in_mint(), out_mint: out_mint(), max_in, min_out, route_data: Some(data) }
}

#[test]
fn session_route_swap_honest() {
    let mut l = live();
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, 1_000_000, 900_000, 1_000_000, 900_000, 0);
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_ok(&mut l.svm, &[&l.payer, &kp], &[ix]);
    assert_eq!(token_amount(&l.svm, &l.vault_in), VAULT_IN - 1_000_000, "in taken");
    assert_eq!(token_amount(&l.svm, &l.vault_out), 900_000, "min_out credited");
    assert!(token_amount(&l.svm, &l.treasury_ata) >= 1, "fee reached treasury");
}

#[test]
fn session_shared_route_swap_honest() {
    let mut l = live();
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_SHARED, &ra);
    let args = session_swap_args(&l, SWAP_VARIANT_SHARED, 800_000, 700_000, 800_000, 700_000, 0);
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_ok(&mut l.svm, &[&l.payer, &kp], &[ix]);
    assert_eq!(token_amount(&l.svm, &l.vault_in), VAULT_IN - 800_000);
    assert_eq!(token_amount(&l.svm, &l.vault_out), 700_000);
}

#[test]
fn swap_min_out_not_met_rejected() {
    // misbehave 1 credits quoted_out - 1 < min_out.
    let mut l = live();
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, 1_000_000, 900_000, 1_000_000, 900_000, 1);
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::SWAP_MIN_OUT_NOT_MET);
}

#[test]
fn swap_second_writable_vault_source_rejected() {
    // WRDF-0065: a SECOND writable vault-owned in-mint account passed to the
    // route is rejected BEFORE the CPI — no writable vault token account other
    // than the pinned source/dest may enter the PDA-signed call, so the
    // round-trip-through-a-second-account class is closed by construction.
    let mut l = live();
    let second = ata(&Pubkey::new_unique(), &in_mint());
    set_token_account(&mut l.svm, &second, &in_mint(), &l.account, 1_000);
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(l.treasury_ata, Some(second));
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, 1_000_000, 900_000, 1_000_000, 900_000, 2);
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::SWAP_EXTRA_WRITABLE_VAULT);
}

#[test]
fn swap_second_writable_vault_out_rejected() {
    // WRDF-0065/0060: a second writable vault-owned OUT-mint account (the shape
    // that would let a route offset the declared destination's gain) is likewise
    // rejected before the CPI.
    let mut l = live();
    let second_out = ata(&Pubkey::new_unique(), &out_mint());
    set_token_account(&mut l.svm, &second_out, &out_mint(), &l.account, 500_000);
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(l.treasury_ata, Some(second_out));
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, 1_000_000, 900_000, 1_000_000, 900_000, 0);
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::SWAP_EXTRA_WRITABLE_VAULT);
}

#[test]
fn swap_delegate_set_rejected() {
    // misbehave 4 sets a delegate on the source ATA — conservation rejects it.
    let mut l = live();
    let delegate = Pubkey::new_unique();
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(l.treasury_ata, Some(delegate));
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, 1_000_000, 900_000, 1_000_000, 900_000, 4);
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::CONSERVATION_VIOLATED);
}

#[test]
fn swap_fee_to_non_treasury_rejected() {
    // The caller substitutes a non-treasury account into the fee slot.
    let mut l = live();
    let stranger_owner = Pubkey::new_unique();
    let stranger_fee = ata(&stranger_owner, &out_mint());
    set_token_account(&mut l.svm, &stranger_fee, &out_mint(), &stranger_owner, 0);
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(stranger_fee, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, 1_000_000, 900_000, 1_000_000, 900_000, 0);
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::SWAP_FEE_ACCOUNT_NOT_TREASURY);
}

#[test]
fn swap_bad_platform_fee_bps_rejected() {
    // A route with platform_fee_bps != 85 in its data.
    let mut l = live();
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    // Build data with platform_fee_bps = 0 (last byte).
    let mut data = jup::route_data(1_000_000, 900_000, 0);
    *data.last_mut().unwrap() = 0u8;
    let args = SwapArgs { root: None, variant: SWAP_VARIANT_ROUTE, in_mint: in_mint(), out_mint: out_mint(), max_in: 1_000_000, min_out: 900_000, route_data: Some(data) };
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::SWAP_PLATFORM_FEE_BPS);
}

#[test]
fn swap_bad_discriminator_rejected() {
    let mut l = live();
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let mut data = jup::route_data(1_000_000, 900_000, 0);
    data[0] ^= 0xFF; // corrupt the discriminator
    let args = SwapArgs { root: None, variant: SWAP_VARIANT_ROUTE, in_mint: in_mint(), out_mint: out_mint(), max_in: 1_000_000, min_out: 900_000, route_data: Some(data) };
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::SWAP_BAD_DISCRIMINATOR);
}

#[test]
fn swap_source_not_vault_rejected() {
    // A source ATA owned by a stranger, not the vault.
    let mut l = live();
    let stranger = Pubkey::new_unique();
    let bad_source = ata(&stranger, &in_mint());
    set_token_account(&mut l.svm, &bad_source, &in_mint(), &stranger, 1_000_000);
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let mut ra = l.route_accounts(l.treasury_ata, None);
    ra.user_source_ata = bad_source;
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, 1_000_000, 900_000, 1_000_000, 900_000, 0);
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::SWAP_SOURCE_NOT_VAULT_ATA);
}

#[test]
fn swap_declared_max_in_over_cap_rejected() {
    // max_in exceeds the session per_tx — rejected BEFORE the CPI.
    let mut l = live();
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let over = IN_PER_TX + 1;
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, over, 900_000, over, 900_000, 0);
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::CAP_EXCEEDED);
}

#[test]
fn swap_declared_in_over_max_in_rejected() {
    // The route's decoded in_amount exceeds the authorized max_in.
    let mut l = live();
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    // route declares in_amount 1_000_000 but max_in is 500_000.
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, 1_000_000, 900_000, 500_000, 900_000, 0);
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::SWAP_MAX_IN_EXCEEDED);
}

#[test]
fn swap_out_mint_not_allowed_rejected() {
    // A session whose caps do not include the out_mint and out_mint is not a
    // default-allowed mint. Plant a session with only the in_mint cap.
    let mut l = live();
    let kp = Keypair::new();
    let (pda, bump) = session_pda(&l.account, &kp.pubkey());
    let generation = read_smart_account(&l.svm, &l.account).generation;
    let mut caps = [MintCap::default(); 8];
    caps[0] = MintCap { mint: in_mint(), per_tx: IN_PER_TX, per_day: 0, per_30d: 0 };
    let mut lifetime_cap = [0u64; 8];
    lifetime_cap[0] = IN_DAY;
    let session = SessionKey {
        version: 1, bump, account: l.account, pubkey: kp.pubkey(), kind: 0, expiry_ts: NOW + SESSION_LIFE,
        ops_mask: OP_SWAP, generation_at_grant: generation, caps, lifetime_cap, lifetime_spent: [0u64; 8],
        program_allowlist_id: 0, label: [0u8; 16], _reserved: [0u8; 64],
    };
    let mut data = SessionKey::DISCRIMINATOR.to_vec();
    session.serialize(&mut data).unwrap();
    l.svm.set_account(pda, Account { lamports: l.svm.minimum_balance_for_rent_exemption(data.len()), data, owner: common::program_id(), executable: false, rent_epoch: 0 }).unwrap();

    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, 1_000_000, 900_000, 1_000_000, 900_000, 0);
    let (ix, _lg) = swap_ix(kp.pubkey(), l.account, Some(pda), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::SWAP_OUT_MINT_NOT_ALLOWED);
}

#[test]
fn swap_without_op_swap_rejected() {
    let mut l = live();
    let (session, kp) = plant_session(&mut l.svm, &l.account, warden::state::OP_TRANSFER);
    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, 1_000_000, 900_000, 1_000_000, 900_000, 0);
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::OP_NOT_ALLOWED);
}

#[test]
fn session_swap_tx_fits_1232_bytes() {
    let mut l = live();
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, 1_000_000, 900_000, 1_000_000, 900_000, 0);
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    let tx = Transaction::new(&[&l.payer, &kp], Message::new(&[ix], Some(&l.payer.pubkey())), l.svm.latest_blockhash());
    let size = bincode::serialize(&tx).unwrap().len();
    assert!(size <= PACKET, "session swap tx is {size} B, over {PACKET}");
}

// ===========================================================================
// Root path
// ===========================================================================

#[test]
fn root_route_swap_honest_bounded() {
    let mut l = live();
    let submitter = Keypair::new();
    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let disc = jup::instruction_discriminator("route");
    let shape = SwapArgs { root: None, variant: SWAP_VARIANT_ROUTE, in_mint: in_mint(), out_mint: out_mint(), max_in: 1_000_000, min_out: 900_000, route_data: Some(jup::route_data(1_000_000, 900_000, 0)) };
    let route_data = jup::route_data(1_000_000, 900_000, 0);
    let (_p, logical) = swap_ix(submitter.pubkey(), l.account, None, true, None, l.registry, None, &remaining, &shape);
    let (precompile, root) = ceremony(&l.svm, &l.account, &l.pk, swap_action_hash(disc, in_mint(), out_mint(), 1_000_000, 900_000, &route_data, &logical));
    let args = SwapArgs { root: Some(root), ..shape };
    let (ix, _l2) = swap_ix(submitter.pubkey(), l.account, None, true, None, l.registry, None, &remaining, &args);
    expect_ok(&mut l.svm, &[&l.payer, &submitter], &[precompile, ix]);
    assert_eq!(token_amount(&l.svm, &l.vault_in), VAULT_IN - 1_000_000);
    assert_eq!(token_amount(&l.svm, &l.vault_out), 900_000);
}

#[test]
fn root_swap_account_reorder_rejected() {
    // A captured root assertion replayed against a reordered account list.
    let mut l = live();
    let submitter = Keypair::new();
    let ra = l.route_accounts(l.treasury_ata, None);
    let honest = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let disc = jup::instruction_discriminator("route");
    let shape = SwapArgs { root: None, variant: SWAP_VARIANT_ROUTE, in_mint: in_mint(), out_mint: out_mint(), max_in: 1_000_000, min_out: 900_000, route_data: Some(jup::route_data(1_000_000, 900_000, 0)) };
    let route_data = jup::route_data(1_000_000, 900_000, 0);
    let (_p, logical) = swap_ix(submitter.pubkey(), l.account, None, true, None, l.registry, None, &honest, &shape);
    let (precompile, root) = ceremony(&l.svm, &l.account, &l.pk, swap_action_hash(disc, in_mint(), out_mint(), 1_000_000, 900_000, &route_data, &logical));
    // Submit a reordered remaining list (swap two filler positions).
    let mut reordered = honest.clone();
    reordered.swap(7, 4);
    let args = SwapArgs { root: Some(root), ..shape };
    let (ix, _l2) = swap_ix(submitter.pubkey(), l.account, None, true, None, l.registry, None, &reordered, &args);
    expect_reject(&mut l.svm, &[&l.payer, &submitter], &[precompile, ix], 1, err::CHALLENGE_MISMATCH);
}

#[test]
fn swap_native_in_mint_rejected() {
    // Native (wrapped-SOL) swaps are unsupported in 1B (WRDF-0061).
    let mut l = live();
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let args = SwapArgs {
        root: None, variant: SWAP_VARIANT_ROUTE,
        in_mint: warden::constants::NATIVE_MINT, out_mint: out_mint(),
        max_in: 1_000_000, min_out: 900_000,
        route_data: Some(jup::route_data(1_000_000, 900_000, 0)),
    };
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::SWAP_NATIVE_UNSUPPORTED);
}

#[test]
fn swap_min_out_boundary_rejected() {
    // min_out one unit above the actual net out gain is rejected (WRDF-0060 net
    // rule, boundary). The net-OFFSET logic — a second vault out account debited
    // to fake the declared dest's local gain — is proven two ways: the pure
    // `swap::tests::net_vault_mint_delta_sums_across_vault_accounts_and_offsets`
    // unit test, and `swap_second_writable_vault_out_rejected` (WRDF-0065 rejects
    // the second writable vault out account before the CPI can even run).
    let mut l = live();
    let (session, kp) = plant_session(&mut l.svm, &l.account, OP_SWAP);
    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    // Pool credits 900_000 to the dest; ask for min_out 900_001 (net gain is one short).
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, 1_000_000, 900_000, 1_000_000, 900_001, 0);
    let (ix, _l) = swap_ix(kp.pubkey(), l.account, Some(session), false, None, l.registry, None, &remaining, &args);
    expect_reject(&mut l.svm, &[&l.payer, &kp], &[ix], 0, err::SWAP_MIN_OUT_NOT_MET);
}

#[test]
fn swap_lifetime_headroom_checked_before_cpi() {
    // WRDF-0062: the FULL max_in must clear the session lifetime BEFORE the CPI.
    // Plant a session whose lifetime is nearly exhausted so max_in does not fit.
    let mut l = live();
    let kp = Keypair::new();
    let (pda, bump) = session_pda(&l.account, &kp.pubkey());
    let generation = read_smart_account(&l.svm, &l.account).generation;
    let mut caps = [MintCap::default(); 8];
    caps[0] = MintCap { mint: in_mint(), per_tx: IN_PER_TX, per_day: 0, per_30d: 0 };
    caps[1] = MintCap { mint: out_mint(), per_tx: IN_PER_TX, per_day: 0, per_30d: 0 };
    let mut lifetime_cap = [0u64; 8];
    lifetime_cap[0] = 1_000_000;
    lifetime_cap[1] = IN_DAY;
    let mut lifetime_spent = [0u64; 8];
    lifetime_spent[0] = 900_000; // only 100k of lifetime left; max_in 1_000_000 overshoots
    let session = SessionKey {
        version: 1, bump, account: l.account, pubkey: kp.pubkey(), kind: 0, expiry_ts: NOW + SESSION_LIFE,
        ops_mask: OP_SWAP, generation_at_grant: generation, caps, lifetime_cap, lifetime_spent,
        program_allowlist_id: 0, label: [0u8; 16], _reserved: [0u8; 64],
    };
    let mut data = SessionKey::DISCRIMINATOR.to_vec();
    session.serialize(&mut data).unwrap();
    l.svm.set_account(pda, Account { lamports: l.svm.minimum_balance_for_rent_exemption(data.len()), data, owner: common::program_id(), executable: false, rent_epoch: 0 }).unwrap();

    let ra = l.route_accounts(l.treasury_ata, None);
    let remaining = swap_remaining(SWAP_VARIANT_ROUTE, &ra);
    let args = session_swap_args(&l, SWAP_VARIANT_ROUTE, 1_000_000, 900_000, 1_000_000, 900_000, 0);
    let (ix, _lg) = swap_ix(kp.pubkey(), l.account, Some(pda), false, None, l.registry, None, &remaining, &args);
    // WRDF-0067: prove the check is PRE-CPI — the failure must carry CapExceeded
    // AND the mock must NOT have been invoked (its "Instruction: Route" log is
    // absent). A post-CPI check would return the same error but only after the
    // mock ran, so the log presence is what distinguishes the two orderings.
    match send(&mut l.svm, &[&l.payer, &kp], &[ix]) {
        Ok(_) => panic!("expected CapExceeded"),
        Err(e) => {
            match e.err {
                TransactionError::InstructionError(0, InstructionError::Custom(c)) => {
                    assert_eq!(c, err::CAP_EXCEEDED, "logs:\n{:#?}", e.meta.logs);
                }
                other => panic!("expected Custom(CapExceeded), got {other:?}"),
            }
            assert!(
                !e.meta.logs.iter().any(|l| l.contains("Instruction: Route")),
                "the mock ran — the cap check was NOT pre-CPI:\n{:#?}",
                e.meta.logs
            );
        }
    }
}

// ---------------------------------------------------------------------------
mod err {
    pub const OP_NOT_ALLOWED: u32 = 6008;
    pub const CAP_EXCEEDED: u32 = 6006;
    pub const CHALLENGE_MISMATCH: u32 = 6018;
    pub const CONSERVATION_VIOLATED: u32 = 6039;
    pub const SWAP_BAD_DISCRIMINATOR: u32 = 6061;
    pub const SWAP_PLATFORM_FEE_BPS: u32 = 6063;
    pub const SWAP_SOURCE_NOT_VAULT_ATA: u32 = 6065;
    pub const SWAP_FEE_ACCOUNT_NOT_TREASURY: u32 = 6067;
    pub const SWAP_MAX_IN_EXCEEDED: u32 = 6068;
    pub const SWAP_MIN_OUT_NOT_MET: u32 = 6069;
    pub const SWAP_OUT_MINT_NOT_ALLOWED: u32 = 6070;
    pub const SWAP_NATIVE_UNSUPPORTED: u32 = 6072;
    pub const SWAP_EXTRA_WRITABLE_VAULT: u32 = 6074;
}
