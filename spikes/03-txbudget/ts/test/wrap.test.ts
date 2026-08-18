import { describe, it, expect } from "vitest";
import { Keypair, PublicKey, SystemProgram, TransactionMessage } from "@solana/web3.js";
import { wrapForExecute } from "../src/wrap.js";
describe("wrapForExecute", () => {
  it("wraps a small transfer inline", () => {
    const acct = Keypair.generate().publicKey, sess = Keypair.generate(), prog = Keypair.generate().publicKey;
    const ix = SystemProgram.transfer({ fromPubkey: acct, toPubkey: Keypair.generate().publicKey, lamports: 1n });
    // payerKey = acct (not sess): a dApp builds the ORIGINAL tx assuming the smart-account
    // pubkey itself pays + signs, exactly like an EOA. Using sess as payer here (as an earlier
    // draft of this test did) makes the original message carry 2 required signatures (acct as
    // instruction signer + sess as payer) while the wrapped message needs only 1 (session key;
    // the PDA no longer signs directly, invoke_signed does), so the wrapped tx becomes SMALLER
    // purely from the dropped 64-byte signature, masking the real per-instruction wrap overhead
    // this test is meant to measure. See spikes/03-txbudget/result.md self-review note.
    const msg = new TransactionMessage({ payerKey: acct, recentBlockhash: "11111111111111111111111111111111", instructions: [ix] }).compileToV0Message();
    const r = wrapForExecute(msg, prog, acct, sess.publicKey);
    expect(r.inline).not.toBeNull();
    expect(r.bytesInline).toBeLessThan(400);
    expect(r.bytesInline).toBeGreaterThan(r.bytesOriginal);
  });
});
