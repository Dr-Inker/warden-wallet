mod common;
use sha2::{Digest, Sha256};
use solana_sdk::{instruction::Instruction, message::Message, signer::Signer, transaction::Transaction};
#[test]
fn ping_succeeds() {
    let (mut svm, payer) = common::setup();
    let disc = Sha256::digest(b"global:ping")[..8].to_vec();
    let ix = Instruction {
        program_id: common::program_id(),
        accounts: vec![],
        data: disc,
    };
    let tx = Transaction::new(
        &[&payer],
        Message::new(&[ix], Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    assert!(svm.send_transaction(tx).is_ok());
}
