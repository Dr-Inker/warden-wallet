//! Executable ABI contract for the browser's devnet root create/transfer builders.
//! Fixture signatures come from Node/OpenSSL. These exact instruction bytes
//! must execute against Warden in LiteSVM with the real P-256 precompile.
mod common;
use serde_json::Value;
use solana_sdk::{clock::Clock, instruction::{AccountMeta, Instruction}, pubkey::Pubkey, signer::Signer, transaction::Transaction};
use std::str::FromStr;

fn instructions(fixture: &Value, operation: &str, payer: Pubkey) -> Vec<Instruction> {
    fixture[operation]["instructions"].as_array().unwrap().iter().map(|ix| Instruction {
        program_id: Pubkey::from_str(ix["programId"].as_str().unwrap()).unwrap(),
        accounts: ix["keys"].as_array().unwrap().iter().map(|m| {
            let key = if m["pubkey"] == fixture["payer"] { payer } else { Pubkey::from_str(m["pubkey"].as_str().unwrap()).unwrap() };
            AccountMeta { pubkey: key, is_signer: m["isSigner"].as_bool().unwrap(), is_writable: m["isWritable"].as_bool().unwrap() }
        }).collect(),
        data: hex::decode(ix["data"].as_str().unwrap()).unwrap(),
    }).collect()
}

#[test]
fn browser_create_and_root_transfer_execute_and_bind_recipient() {
    let f: Value = serde_json::from_str(include_str!("../../../packages/core/test/fixtures/devnet-root.json")).unwrap();
    let (mut svm, payer) = common::setup();
    let mut clock = svm.get_sysvar::<Clock>();
    clock.slot = 350_000_000;
    clock.unix_timestamp = 1_760_000_000;
    svm.set_sysvar(&clock);
    let account = Pubkey::from_str(f["wallet"]["address"].as_str().unwrap()).unwrap();
    let destination = Pubkey::from_str(f["destination"].as_str().unwrap()).unwrap();
    let create = instructions(&f, "create", payer.pubkey());
    let tx = Transaction::new_signed_with_payer(&create, Some(&payer.pubkey()), &[&payer], svm.latest_blockhash());
    let create_bytes = bincode::serialize(&tx).unwrap().len();
    assert!(create_bytes <= 1232, "create: {create_bytes} bytes");
    svm.send_transaction(tx).unwrap_or_else(|e| panic!("create failed: {:?} {:?}", e.err, e.meta.logs));
    let created = svm.get_account(&account).unwrap();
    assert_eq!(created.data.len(), 4120);
    assert_eq!(u64::from_le_bytes(created.data[536..544].try_into().unwrap()), 1);
    svm.airdrop(&account, 50_000_000).unwrap();
    svm.airdrop(&destination, 1_000_000).unwrap();
    let before_account = svm.get_balance(&account).unwrap();
    let before_destination = svm.get_balance(&destination).unwrap();
    let transfer = instructions(&f, "transfer", payer.pubkey());
    let mut substituted = transfer.clone();
    substituted[1].accounts[4].pubkey = payer.pubkey();
    let hostile = Transaction::new_signed_with_payer(&substituted, Some(&payer.pubkey()), &[&payer], svm.latest_blockhash());
    assert!(svm.send_transaction(hostile).is_err(), "a substituted recipient must fail");
    assert_eq!(svm.get_balance(&account).unwrap(), before_account);
    let tx = Transaction::new_signed_with_payer(&transfer, Some(&payer.pubkey()), &[&payer], svm.latest_blockhash());
    let transfer_bytes = bincode::serialize(&tx).unwrap().len();
    assert!(transfer_bytes <= 1232, "transfer: {transfer_bytes} bytes");
    svm.send_transaction(tx).unwrap_or_else(|e| panic!("transfer failed: {:?} {:?}", e.err, e.meta.logs));
    assert_eq!(svm.get_balance(&account).unwrap(), before_account - 1_000_000);
    assert_eq!(svm.get_balance(&destination).unwrap(), before_destination + 1_000_000);
    let data = svm.get_account(&account).unwrap().data;
    assert_eq!(u64::from_le_bytes(data[536..544].try_into().unwrap()), 2);
    println!("devnet browser ABI: create={create_bytes}B transfer={transfer_bytes}B; recipient +1000000, vault -1000000 lamports");
}
