//! Spike 3b step 2: measure the CU cost of the conservation-snapshot pass
//! over N writable token accounts, in LiteSVM.
//!
//! Token account bytes are packed BY HAND at the fixed SPL Token layout
//! offsets (see src/lib.rs module doc for why: spl-token/spl-token-2022 pull
//! a semver-incompatible solana-program 2.3.0, so this test avoids importing
//! their types entirely, same as the on-chain program does).
use litesvm::LiteSVM;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::{fs, path::PathBuf, str::FromStr};

const SPL_TOKEN_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SPL_TOKEN_2022_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const TOKEN_ACCOUNT_LEN: usize = 165;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn program_so() -> Vec<u8> {
    let candidates = [
        manifest_dir().join("target/deploy/spike_conserve.so"),
        manifest_dir().join("../../../target/deploy/spike_conserve.so"),
    ];
    for c in &candidates {
        if let Ok(b) = fs::read(c) {
            return b;
        }
    }
    panic!(
        "spike_conserve.so not found; run `cargo-build-sbf --manifest-path spikes/03-txbudget/onchain/Cargo.toml` first. Looked in: {candidates:?}"
    );
}

/// Hand-packs the 165-byte SPL Token `Account` layout at fixed offsets (see
/// src/lib.rs module doc / task brief for the offset table).
fn pack_token_account(
    mint: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    has_delegate: bool,
    has_close_authority: bool,
    state: u8,
) -> [u8; TOKEN_ACCOUNT_LEN] {
    let mut b = [0u8; TOKEN_ACCOUNT_LEN];
    b[0..32].copy_from_slice(&mint.to_bytes());
    b[32..64].copy_from_slice(&owner.to_bytes());
    b[64..72].copy_from_slice(&amount.to_le_bytes());
    if has_delegate {
        b[72..76].copy_from_slice(&1u32.to_le_bytes());
        b[76..108].copy_from_slice(&Pubkey::new_unique().to_bytes());
    }
    b[108] = state; // AccountState::Initialized = 1
                     // is_native (109..121) left as COption::None (all zero)
                     // delegated_amount (121..129) left at 0
    if has_close_authority {
        b[129..133].copy_from_slice(&1u32.to_le_bytes());
        b[133..165].copy_from_slice(&Pubkey::new_unique().to_bytes());
    }
    b
}

/// A Token-2022 account: the same 165-byte base, `AccountType::Account` (2) at
/// byte 165, then 99 bytes of dummy TLV filler — 265 bytes total, a 100-byte
/// "TLV tail" (byte 165 onward) for the program's tlv_hash to cover.
fn pack_token2022_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut v = pack_token_account(mint, owner, amount, false, false, 1).to_vec();
    v.push(2u8); // AccountType::Account
    v.extend(std::iter::repeat(0xABu8).take(99));
    assert_eq!(v.len(), 265);
    v
}

struct Harness {
    svm: LiteSVM,
    pid: Pubkey,
    payer: Keypair,
    vault: Pubkey,
}

fn setup() -> Harness {
    let mut svm = LiteSVM::new();
    let pid = Pubkey::new_unique();
    svm.add_program(pid, &program_so()).expect("add_program");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let vault = Pubkey::new_unique();
    Harness { svm, pid, payer, vault }
}

/// Adds `n` vault-owned SPL Token accounts (each holding 1_000_000 of a fresh
/// mint) as writable metas, returning the metas to attach to the instruction.
fn add_spl_accounts(h: &mut Harness, n: usize) -> Vec<AccountMeta> {
    let spl_token_id = Pubkey::from_str(SPL_TOKEN_ID).unwrap();
    let rent = h.svm.minimum_balance_for_rent_exemption(TOKEN_ACCOUNT_LEN);
    let mut metas = Vec::with_capacity(n);
    for _ in 0..n {
        let key = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let data = pack_token_account(&mint, &h.vault, 1_000_000, false, false, 1).to_vec();
        h.svm
            .set_account(
                key,
                Account { lamports: rent, data, owner: spl_token_id, executable: false, rent_epoch: 0 },
            )
            .unwrap();
        metas.push(AccountMeta::new(key, false));
    }
    metas
}

fn add_token2022_account(h: &mut Harness) -> AccountMeta {
    let spl_token_2022_id = Pubkey::from_str(SPL_TOKEN_2022_ID).unwrap();
    let mint = Pubkey::new_unique();
    let data = pack_token2022_account(&mint, &h.vault, 500_000);
    let rent = h.svm.minimum_balance_for_rent_exemption(data.len());
    let key = Pubkey::new_unique();
    h.svm
        .set_account(
            key,
            Account { lamports: rent, data, owner: spl_token_2022_id, executable: false, rent_epoch: 0 },
        )
        .unwrap();
    AccountMeta::new(key, false)
}

fn send(h: &mut Harness, mut metas: Vec<AccountMeta>, data: Vec<u8>) -> Result<u64, String> {
    let mut all = vec![AccountMeta::new_readonly(h.vault, false)];
    all.append(&mut metas);
    let ix = Instruction { program_id: h.pid, accounts: all, data };
    let tx = Transaction::new(&[&h.payer], Message::new(&[ix], Some(&h.payer.pubkey())), h.svm.latest_blockhash());
    match h.svm.send_transaction(tx) {
        Ok(meta) => Ok(meta.compute_units_consumed),
        Err(f) => {
            // LiteSVM reports CU consumed even on failure.
            println!("failed tx CU={} err={:?} logs={:#?}", f.meta.compute_units_consumed, f.err, f.meta.logs);
            Err(format!("{:?}", f.err))
        }
    }
}

// ---------------------------------------------------------------------------
// CU sweep: N in {10, 20, 30} vault-owned SPL Token accounts, happy path.
// ---------------------------------------------------------------------------

#[test]
fn cu_sweep_by_n() {
    let mut results = Vec::new();
    for &n in &[10usize, 20, 30] {
        let mut h = setup();
        let metas = add_spl_accounts(&mut h, n);
        let cu = send(&mut h, metas, vec![0]).expect("happy path must succeed");
        println!("N={n:>2} vault-owned SPL token accounts -> compute_units_consumed={cu}");
        results.push((n, cu));
    }
    let (n30, cu30) = *results.last().unwrap();
    assert_eq!(n30, 30);
    assert!(cu30 < 200_000, "CU budget blown at N=30: {cu30}");

    // Linear-fit per-account extrapolation from the N=10 and N=30 points.
    let (n_lo, cu_lo) = results[0];
    let (n_hi, cu_hi) = results[2];
    let per_account = (cu_hi as f64 - cu_lo as f64) / (n_hi as f64 - n_lo as f64);
    let base = cu_lo as f64 - per_account * n_lo as f64;
    println!("linear fit: base={base:.1} CU, per-account={per_account:.1} CU (from N=10..30 two-point fit)");
}

// ---------------------------------------------------------------------------
// Token-2022 account with a 100-byte TLV tail: exercises the tlv_hash path.
// ---------------------------------------------------------------------------

#[test]
fn cu_with_token2022_tlv_tail() {
    let mut h = setup();
    let mut metas = add_spl_accounts(&mut h, 10);
    metas.push(add_token2022_account(&mut h));
    let cu = send(&mut h, metas, vec![0]).expect("happy path with Token-2022 TLV account must succeed");
    println!("N=10 SPL + 1 Token-2022 (265 B, 100 B TLV tail) -> compute_units_consumed={cu}");
    assert!(cu < 200_000, "CU budget blown: {cu}");
}

// ---------------------------------------------------------------------------
// Negative path: data[0] = 1 -> Custom(99), after snapshotting succeeds.
// ---------------------------------------------------------------------------

#[test]
fn negative_path_returns_custom_99() {
    let mut h = setup();
    let metas = add_spl_accounts(&mut h, 10);
    let err = send(&mut h, metas, vec![1]).expect_err("data[0]=1 must fail");
    assert!(err.contains("Custom(99)"), "expected Custom(99), got {err}");
}

// ---------------------------------------------------------------------------
// Mutation-detection path (cheap variant): an account owned (at the SPL-Token
// `owner` field level) by someone OTHER than `vault` must be ignored, not
// rejected — the program only enforces conservation for vault-owned accounts.
// ---------------------------------------------------------------------------

#[test]
fn non_vault_owned_account_is_ignored() {
    let mut h = setup();
    let spl_token_id = Pubkey::from_str(SPL_TOKEN_ID).unwrap();
    let mut metas = add_spl_accounts(&mut h, 10);

    // A token account that is NOT owned by `vault` (owned by some other party).
    let not_vault = Pubkey::new_unique();
    let rent = h.svm.minimum_balance_for_rent_exemption(TOKEN_ACCOUNT_LEN);
    let key = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    // has_close_authority=true would trip the mutation check if this account
    // were mistakenly treated as vault-owned — proves it's actually skipped.
    let data = pack_token_account(&mint, &not_vault, 1_000_000, false, true, 1).to_vec();
    h.svm
        .set_account(key, Account { lamports: rent, data, owner: spl_token_id, executable: false, rent_epoch: 0 })
        .unwrap();
    metas.push(AccountMeta::new(key, false));

    let cu = send(&mut h, metas, vec![0]).expect("non-vault-owned account must be ignored, not rejected");
    println!("N=10 vault-owned + 1 non-vault-owned (with close_authority set) -> compute_units_consumed={cu}");
}
