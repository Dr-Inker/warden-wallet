//! Phase 1B Task 2B — smoke tests for the `test-jup-mock` program.
//!
//! These prove the mock routes in→out through its pool and that each of the
//! five `misbehave` modes is observable, driven with an ordinary payer as
//! `user_transfer_authority` (no warden). Task 6 feeds the same `route` /
//! `shared_accounts_route` instructions through `swap` and asserts each
//! misbehaviour is rejected — so, as with the mutator, these smoke tests keep a
//! Task-6 rejection from passing for a broken-mock reason.

mod common;

use common::jup::{self, RouteAccounts};
use common::token::{ata, set_mint, set_token_account, token_amount};
use litesvm::LiteSVM;
use solana_sdk::{
    instruction::Instruction,
    message::Message,
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

/// A fully-wired routing scene: two mints, the caller's source/destination
/// ATAs, the treasury fee ATA, and the mock's pool ATAs (owned by the pool PDA
/// and pre-funded with output tokens).
struct Scene {
    svm: LiteSVM,
    payer: Keypair,
    in_mint: Pubkey,
    out_mint: Pubkey,
    source: Pubkey,
    destination: Pubkey,
    treasury: Pubkey,
    pool_out: Pubkey,
    pool_in: Pubkey,
}

fn scene(source_balance: u64) -> Scene {
    let mut svm = LiteSVM::new().with_mainnet_features();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    jup::add_jup_mock(&mut svm);
    let (pool, _) = jup::pool_authority();

    let in_mint = Pubkey::new_unique();
    let out_mint = Pubkey::new_unique();
    set_mint(&mut svm, &in_mint, 6, 1_000_000_000);
    set_mint(&mut svm, &out_mint, 6, 1_000_000_000);

    let source = ata(&payer.pubkey(), &in_mint);
    let destination = ata(&payer.pubkey(), &out_mint);
    let treasury = ata(&Pubkey::new_unique(), &out_mint);
    let pool_out = ata(&pool, &out_mint);
    let pool_in = ata(&pool, &in_mint);

    set_token_account(&mut svm, &source, &in_mint, &payer.pubkey(), source_balance);
    set_token_account(&mut svm, &destination, &out_mint, &payer.pubkey(), 0);
    set_token_account(&mut svm, &treasury, &out_mint, &Pubkey::new_unique(), 0);
    set_token_account(&mut svm, &pool_out, &out_mint, &pool, 1_000_000); // pre-funded
    set_token_account(&mut svm, &pool_in, &in_mint, &pool, 0);

    Scene { svm, payer, in_mint, out_mint, source, destination, treasury, pool_out, pool_in }
}

impl Scene {
    fn accounts(&self, extra: Option<Pubkey>) -> RouteAccounts {
        RouteAccounts {
            user_transfer_authority: self.payer.pubkey(),
            user_source_ata: self.source,
            user_destination_ata: self.destination,
            destination_mint: self.out_mint,
            platform_fee_account: self.treasury,
            pool_out_ata: self.pool_out,
            pool_in_sink: self.pool_in,
            extra,
        }
    }

    fn send(&mut self, ix: Instruction) -> Result<(), String> {
        let tx = Transaction::new(
            &[&self.payer],
            Message::new(&[ix], Some(&self.payer.pubkey())),
            self.svm.latest_blockhash(),
        );
        self.svm
            .send_transaction(tx)
            .map(|_| ())
            .map_err(|e| format!("{:?} {:#?}", e.err, e.meta.logs))
    }

    fn delegate_of(&self, addr: &Pubkey) -> COption<Pubkey> {
        let data = self.svm.get_account(addr).unwrap().data;
        spl_token::state::Account::unpack(&data).unwrap().delegate
    }
}

#[test]
fn honest_route_moves_in_credits_out_and_fees_treasury() {
    let mut s = scene(1_000);
    let a = s.accounts(None);
    s.send(jup::route(&a, 400, 380, 0)).expect("honest route");

    assert_eq!(token_amount(&s.svm, &s.source), 600, "400 in taken");
    assert_eq!(token_amount(&s.svm, &s.destination), 380, "min_out credited");
    assert!(token_amount(&s.svm, &s.treasury) >= 1, "fee reached treasury");
}

#[test]
fn shared_accounts_route_also_routes() {
    let mut s = scene(1_000);
    let a = s.accounts(None);
    s.send(jup::shared_accounts_route(&a, 250, 200, 0)).expect("shared route");
    assert_eq!(token_amount(&s.svm, &s.source), 750);
    assert_eq!(token_amount(&s.svm, &s.destination), 200);
}

#[test]
fn misbehave_1_credits_less_than_min_out() {
    let mut s = scene(1_000);
    let a = s.accounts(None);
    s.send(jup::route(&a, 400, 380, 1)).expect("route runs");
    assert_eq!(token_amount(&s.svm, &s.destination), 379, "credited min_out - 1");
}

#[test]
fn misbehave_2_debits_a_second_source_ata() {
    let mut s = scene(1_000);
    // A second vault ATA of the in_mint that the mock will also drain.
    let second = ata(&Pubkey::new_unique(), &s.in_mint);
    set_token_account(&mut s.svm, &second, &s.in_mint, &s.payer.pubkey(), 500);
    let a = s.accounts(Some(second));
    s.send(jup::route(&a, 400, 380, 2)).expect("route runs");
    assert_eq!(token_amount(&s.svm, &s.source), 600, "primary source debited");
    assert_eq!(token_amount(&s.svm, &second), 499, "second source also debited");
}

#[test]
fn fee_goes_to_the_passed_account_so_a_substituted_one_is_observable() {
    // Plan "misbehave 3" is a CALLER account substitution, not a mock branch
    // (WRDF-0033): the mock honestly pays whatever is in the platform_fee_account
    // slot, so putting a non-treasury account there sends the fee there and
    // starves the treasury. Task 6 asserts warden's pre-CPI meta check
    // (platform_fee_account == Registry.treasury) rejects this before the CPI.
    let mut s = scene(1_000);
    let wrong_fee = ata(&Pubkey::new_unique(), &s.out_mint);
    set_token_account(&mut s.svm, &wrong_fee, &s.out_mint, &Pubkey::new_unique(), 0);
    let mut a = s.accounts(None);
    a.platform_fee_account = wrong_fee; // substitute a non-treasury account
    s.send(jup::route(&a, 400, 380, 0)).expect("route runs");
    assert_eq!(token_amount(&s.svm, &s.source), 600, "in_amount taken");
    assert_eq!(token_amount(&s.svm, &s.destination), 380, "min_out credited");
    assert_eq!(token_amount(&s.svm, &s.treasury), 0, "treasury got no fee");
    assert!(token_amount(&s.svm, &wrong_fee) >= 1, "fee went to the substituted account");
}

#[test]
fn misbehave_4_sets_a_delegate_on_the_source() {
    let mut s = scene(1_000);
    let delegate = Pubkey::new_unique();
    let a = s.accounts(Some(delegate));
    s.send(jup::route(&a, 400, 380, 4)).expect("route runs");
    assert_eq!(s.delegate_of(&s.source), COption::Some(delegate), "delegate set on source");
}

#[test]
fn route_and_shared_discriminators_are_the_anchor_hash() {
    use sha2::{Digest, Sha256};
    for name in ["route", "shared_accounts_route"] {
        let mut h = Sha256::new();
        h.update(b"global:");
        h.update(name.as_bytes());
        assert_eq!(&jup::instruction_discriminator(name)[..], &h.finalize()[..8], "disc {name}");
    }
}
