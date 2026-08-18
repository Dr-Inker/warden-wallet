import { describe, it, expect } from "vitest";
import { ComputeBudgetInstruction, ComputeBudgetProgram, Keypair, PublicKey, SystemProgram, TransactionInstruction, TransactionMessage } from "@solana/web3.js";
import { wrapForExecute, decodeExecuteData, maxStageChunkPayloadBytes } from "../src/wrap.js";

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
    // Budget is looser than the original 400 B: a default top-level ComputeBudgetProgram
    // .setComputeUnitLimit instruction is now always added when the dApp tx carries none (round 1
    // fix, Important #2), which costs a new 32-byte program-id account key + its own compiled
    // instruction entry (~40 B). 500 B keeps meaningful headroom while still catching regressions.
    expect(r.bytesInline).toBeLessThan(500);
    expect(r.bytesInline).toBeGreaterThan(r.bytesOriginal);
  });

  it("round-trips: decoding the packed execute payload (instruction-local indices) recovers the exact original inner-instruction keys, flags, and data", () => {
    // Two distinct instructions with overlapping AND distinct accounts, so `order` (the outer
    // execute ix's deduped remaining-accounts list) has non-trivial structure and compileToV0Message
    // has real global reordering to do (signer/writable sorting) — this is the scenario where a
    // wrong index space (either the round-0 off-by-2 bug, or round-1's incorrect "index the
    // compiled message's global list" fix) would silently point at the wrong pubkey instead of
    // throwing, so only a round-trip decode actually catches it.
    const acct = Keypair.generate().publicKey, sess = Keypair.generate(), prog = Keypair.generate().publicKey;
    const other1 = Keypair.generate().publicKey, other2 = Keypair.generate().publicKey;
    const otherProgram = Keypair.generate().publicKey;
    const ix1 = SystemProgram.transfer({ fromPubkey: acct, toPubkey: other1, lamports: 5n });
    const ix2 = new TransactionInstruction({
      programId: otherProgram,
      keys: [
        { pubkey: other1, isSigner: false, isWritable: true },
        { pubkey: other2, isSigner: false, isWritable: false },
        { pubkey: acct, isSigner: true, isWritable: true },
      ],
      data: Buffer.from([9, 8, 7, 6, 5]),
    });
    const msg = new TransactionMessage({ payerKey: acct, recentBlockhash: "11111111111111111111111111111111", instructions: [ix1, ix2] }).compileToV0Message();
    const r = wrapForExecute(msg, prog, acct, sess.publicKey);
    expect(r.inline).not.toBeNull();
    const compiled = r.inline!.message;

    // Decode indices against the INSTRUCTION-LOCAL key list (controller ruling, round 2 review):
    // decompile the compiled message and use the execute instruction's OWN `.keys` array — this
    // is exactly what an on-chain consumer (Anchor's remaining_accounts) would see, not the
    // message's global deduped/reordered account-key list.
    const redecompiled = TransactionMessage.decompile(compiled);
    const executeIx = redecompiled.instructions.find(ix => ix.programId.equals(prog));
    expect(executeIx).toBeDefined();
    const localKeys = executeIx!.keys.map(k => k.pubkey);

    const decoded = decodeExecuteData(executeIx!.data);
    expect(decoded).toHaveLength(2);

    const originalInner = [ix1, ix2];
    for (let i = 0; i < decoded.length; i++) {
      const orig = originalInner[i];
      const resolvedProgram = localKeys[decoded[i].programIdx];
      expect(resolvedProgram.equals(orig.programId)).toBe(true);
      expect(decoded[i].accounts).toHaveLength(orig.keys.length);
      for (let j = 0; j < orig.keys.length; j++) {
        const resolvedKey = localKeys[decoded[i].accounts[j].idx];
        expect(resolvedKey.equals(orig.keys[j].pubkey)).toBe(true);
        expect(decoded[i].accounts[j].isWritable).toBe(orig.keys[j].isWritable);
        // The packed per-account isSigner flag intentionally mirrors the ORIGINAL inner
        // instruction's flag exactly, even for `acct` (the smart account/PDA) — this is what
        // makes invoke_signed work: the CPI'd instruction's account meta must say is_signer:true
        // for the PDA if the target program (e.g. SystemProgram.transfer) requires it, and the
        // runtime honors that because the calling program supplied matching seeds via
        // invoke_signed. (The *outer transaction*-level requirement that `acct` itself provide a
        // real ed25519 signature is a separate thing, forced off in wrapForExecute's `metas` — it
        // does not affect this per-instruction packed payload.)
        expect(decoded[i].accounts[j].isSigner).toBe(orig.keys[j].isSigner);
      }
      expect(Buffer.from(decoded[i].data).equals(orig.data)).toBe(true);
    }
  });

  it("hoists a ComputeBudget instruction already present in the source tx to top level, instead of CPI-wrapping it", () => {
    const acct = Keypair.generate().publicKey, sess = Keypair.generate(), prog = Keypair.generate().publicKey;
    const cuIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 314_159 }); // distinctive, not the 600_000 default
    const transferIx = SystemProgram.transfer({ fromPubkey: acct, toPubkey: Keypair.generate().publicKey, lamports: 1n });
    const msg = new TransactionMessage({ payerKey: acct, recentBlockhash: "11111111111111111111111111111111", instructions: [cuIx, transferIx] }).compileToV0Message();
    const r = wrapForExecute(msg, prog, acct, sess.publicKey);
    expect(r.inline).not.toBeNull();

    const redecompiled = TransactionMessage.decompile(r.inline!.message);
    // Exactly one top-level ComputeBudget instruction (the hoisted original, not an extra default
    // one added alongside it), and it must carry the SOURCE tx's own units value (314_159), proving
    // it was hoisted rather than replaced by the 600_000 default.
    const topLevelCu = redecompiled.instructions.filter(ix => ix.programId.equals(ComputeBudgetProgram.programId));
    expect(topLevelCu).toHaveLength(1);
    expect(ComputeBudgetInstruction.decodeSetComputeUnitLimit(topLevelCu[0]).units).toBe(314_159);

    // Exactly one execute instruction, and it must NOT reference the ComputeBudget program
    // anywhere in its packed payload (i.e. it wasn't also CPI-wrapped).
    const executeIxs = redecompiled.instructions.filter(ix => ix.programId.equals(prog));
    expect(executeIxs).toHaveLength(1);
    const localKeys = executeIxs[0].keys.map(k => k.pubkey);
    const decoded = decodeExecuteData(executeIxs[0].data);
    expect(decoded).toHaveLength(1); // only the transfer — the ComputeBudget ix was excluded from wrapping
    expect(localKeys[decoded[0].programIdx].equals(SystemProgram.programId)).toBe(true);
    for (const acc of decoded[0].accounts) {
      expect(localKeys[acc.idx].equals(ComputeBudgetProgram.programId)).toBe(false);
    }
  });

  it("dedups `order` when a dApp instruction references `account` itself — no duplicate meta, resolves to instruction-local index 0", () => {
    // Round 3 review: `account` (or `sessionKey`) can legitimately show up again among an inner
    // instruction's OWN keys (e.g. referenced as an informational/owner account by some dApp
    // instruction that isn't the primary funding instruction) — without dedup this would produce
    // a SECOND `account` entry in `order`, which `outerKeys` would then also carry, silently
    // shifting every account after it by one index and corrupting the whole instruction-local
    // index space.
    const acct = Keypair.generate().publicKey, sess = Keypair.generate(), prog = Keypair.generate().publicKey;
    const other = Keypair.generate().publicKey;
    const dummyProgram = Keypair.generate().publicKey;
    const ix = new TransactionInstruction({
      programId: dummyProgram,
      keys: [
        { pubkey: other, isSigner: false, isWritable: true },
        { pubkey: acct, isSigner: false, isWritable: false }, // references the wallet itself
      ],
      data: Buffer.from([1, 2, 3]),
    });
    const msg = new TransactionMessage({ payerKey: acct, recentBlockhash: "11111111111111111111111111111111", instructions: [ix] }).compileToV0Message();
    const r = wrapForExecute(msg, prog, acct, sess.publicKey);
    expect(r.inline).not.toBeNull();

    const redecompiled = TransactionMessage.decompile(r.inline!.message);
    const executeIx = redecompiled.instructions.find(i => i.programId.equals(prog));
    expect(executeIx).toBeDefined();
    const localKeys = executeIx!.keys.map(k => k.pubkey);

    // Expected instruction-local key list: [account, sessionKey, dummyProgram, other] — `acct`
    // must NOT appear a second time even though the inner instruction explicitly listed it.
    expect(localKeys).toHaveLength(4);
    expect(localKeys.filter(k => k.equals(acct))).toHaveLength(1);
    expect(localKeys[0].equals(acct)).toBe(true);

    const decoded = decodeExecuteData(executeIx!.data);
    expect(decoded).toHaveLength(1);
    // The inner instruction's 2nd account (acct itself) must decode to instruction-local index 0.
    expect(decoded[0].accounts[1].idx).toBe(0);
    expect(localKeys[decoded[0].accounts[1].idx].equals(acct)).toBe(true);
  });
});

describe("maxStageChunkPayloadBytes / stagedChunks", () => {
  it("derives a plausible stage_chunk payload cap (not a hardcoded magic number) — PROVISIONAL, see result.md", () => {
    const prog = Keypair.generate().publicKey;
    const maxPayload = maxStageChunkPayloadBytes(prog);
    // Sanity bounds: a stage_chunk tx has ~1 signature (64B) + ~4 accounts (128B) + blockhash
    // (32B) + small structural overhead, leaving comfortably more than half of 1,232B for payload,
    // but strictly less than the whole budget once the 8-byte header + fixed overhead is spent.
    expect(maxPayload).toBeGreaterThan(700);
    expect(maxPayload).toBeLessThan(1200);
  });

  it("a synthetic ~3000-byte inner-instruction payload forces staging and yields the expected chunk count", () => {
    const acct = Keypair.generate().publicKey, sess = Keypair.generate(), prog = Keypair.generate().publicKey;
    const bigProgram = Keypair.generate().publicKey;
    const bigData = Buffer.alloc(3000, 7);
    const ix = new TransactionInstruction({ programId: bigProgram, keys: [{ pubkey: acct, isSigner: true, isWritable: true }], data: bigData });
    const msg = new TransactionMessage({ payerKey: acct, recentBlockhash: "11111111111111111111111111111111", instructions: [ix] }).compileToV0Message();
    const r = wrapForExecute(msg, prog, acct, sess.publicKey);
    expect(r.inline).toBeNull();

    // Expected packed-payload length for this single instruction:
    // 2 (op + n_ixs) + 1 (program_idx) + 1 (n_accts) + 1*(1+1) (per-account idx+flags) + 2 (data_len) + 3000 (data)
    const expectedPartsLen = 2 + 1 + 1 + 1 * 2 + 2 + bigData.length;
    const maxPayload = maxStageChunkPayloadBytes(prog);
    expect(r.stagedChunks).toBe(Math.ceil(expectedPartsLen / maxPayload));
    expect(r.stagedChunks).toBeGreaterThanOrEqual(3); // ~3000 B / <1200 B-per-chunk ⇒ at least 3
  });
});

describe("u8 overflow guards (round 3 review)", () => {
  it("throws rather than silently truncating when there are more than 255 inner instructions (n_ixs is a packed u8)", () => {
    const acct = Keypair.generate().publicKey, sess = Keypair.generate(), prog = Keypair.generate().publicKey;
    const dummyProgram = Keypair.generate().publicKey;
    // 256 near-identical instructions sharing the same program + single account, so the OUTER
    // account count stays tiny (well under the separate 256-account limit) — isolates the n_ixs
    // guard specifically, rather than incidentally tripping the account-index guard too.
    const instructions = Array.from({ length: 256 }, (_, i) =>
      new TransactionInstruction({ programId: dummyProgram, keys: [{ pubkey: acct, isSigner: false, isWritable: false }], data: Buffer.from([i & 0xff]) })
    );
    const msg = new TransactionMessage({ payerKey: acct, recentBlockhash: "11111111111111111111111111111111", instructions }).compileToV0Message();
    expect(() => wrapForExecute(msg, prog, acct, sess.publicKey)).toThrow(/256 inner instructions.*exceeds u8/);
  });

  it("throws rather than silently truncating when a single instruction has more than 255 accounts (n_accts is a packed u8)", () => {
    const acct = Keypair.generate().publicKey, sess = Keypair.generate(), prog = Keypair.generate().publicKey;
    const dummyProgram = Keypair.generate().publicKey;
    // The `ix.keys.length > 0xff` guard being tested cares about this ONE instruction's raw key
    // ARRAY LENGTH, not its unique-account count — so repeat just 2 unique pubkeys 128× each
    // rather than using 256 distinct ones. That keeps the whole ORIGINAL message's unique account
    // count tiny, staying well under @solana/web3.js's own separate ~256-unique-static-key cap
    // (compileToV0Message throws "Max static account keys length exceeded" past that), which
    // would otherwise fail while constructing this test's input, before wrapForExecute ever runs.
    const keyA = Keypair.generate().publicKey, keyB = Keypair.generate().publicKey;
    const manyKeys = Array.from({ length: 256 }, (_, i) => ({ pubkey: i % 2 === 0 ? keyA : keyB, isSigner: false, isWritable: false }));
    const ix = new TransactionInstruction({ programId: dummyProgram, keys: manyKeys, data: Buffer.alloc(0) });
    const msg = new TransactionMessage({ payerKey: acct, recentBlockhash: "11111111111111111111111111111111", instructions: [ix] }).compileToV0Message();
    expect(() => wrapForExecute(msg, prog, acct, sess.publicKey)).toThrow(/256 accounts.*exceeds u8/);
  });
});
