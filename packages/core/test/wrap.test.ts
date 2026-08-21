import { describe, it, expect } from "vitest";
import {
  PublicKey,
  Keypair,
  TransactionInstruction,
  TransactionMessage,
  ComputeBudgetProgram,
} from "@solana/web3.js";
import {
  wrapForExecute,
  buildExecuteAccountMetas,
  decodeExecutePayload,
  computeAccountsHash,
  DEFAULT_COMPUTE_UNIT_LIMIT,
  HEAP_FRAME_BYTES,
  HEAP_FRAME_TRIGGER_REMAINING,
  MAX_EXECUTE_ACCOUNTS_TOTAL,
  FLAG_WRITABLE,
  type LogicalAccount,
} from "../src/index.js";

const BLOCKHASH = "11111111111111111111111111111111";
const hex = (b: Uint8Array): string => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");

const wardenProgram = new PublicKey("6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2");
const smartAccount = Keypair.generate().publicKey;
const signer = Keypair.generate().publicKey;

/** A dApp message with two token-ish instructions to two programs, sharing an
 *  account, plus (optionally) a ComputeBudget instruction. */
function dappMsg(withComputeBudget: boolean) {
  const progA = Keypair.generate().publicKey;
  const progB = Keypair.generate().publicKey;
  const shared = Keypair.generate().publicKey;
  const dest = Keypair.generate().publicKey;
  const ixs: TransactionInstruction[] = [];
  if (withComputeBudget) ixs.push(ComputeBudgetProgram.setComputeUnitLimit({ units: 250_000 }));
  ixs.push(
    new TransactionInstruction({
      programId: progA,
      keys: [
        { pubkey: shared, isSigner: false, isWritable: true },
        { pubkey: smartAccount, isSigner: true, isWritable: false }, // PDA as authority-signer
      ],
      data: Buffer.from([1, 2, 3]),
    }),
  );
  ixs.push(
    new TransactionInstruction({
      programId: progB,
      keys: [
        { pubkey: shared, isSigner: false, isWritable: true },
        { pubkey: dest, isSigner: false, isWritable: true },
      ],
      data: Buffer.from([9]),
    }),
  );
  return { msg: new TransactionMessage({ payerKey: signer, recentBlockhash: BLOCKHASH, instructions: ixs }).compileToV0Message(), progA, progB, shared, dest };
}

describe("wrapForExecute", () => {
  it("builds a payload whose logical indices round-trip and whose PDA is index 0", () => {
    const { msg } = dappMsg(false);
    const r = wrapForExecute(msg, { wardenProgram, smartAccount, signer });
    // logical[0] = PDA, logical[1] = signer.
    expect(hex(r.logical[0]!.key)).toBe(hex(smartAccount.toBytes()));
    expect(hex(r.logical[1]!.key)).toBe(hex(signer.toBytes()));
    expect(r.logical[0]!.isSigner).toBe(false); // PDA never a tx signer
    // The decoded payload references the same indices we can re-derive.
    const decoded = decodeExecutePayload(r.payload);
    expect(decoded).toEqual(r.decoded);
    // Every inner-ix account index is in range of the logical list.
    for (const ix of decoded.ixs) {
      expect(ix.programIndex).toBeLessThan(r.logical.length);
      for (const a of ix.accounts) expect(a.index).toBeLessThan(r.logical.length);
    }
    // The PDA, wherever a dApp ix referenced it, is index 0 and never writable
    // in the payload flags.
    for (const ix of decoded.ixs) {
      for (const a of ix.accounts) {
        if (a.index === 0) expect(a.flags & FLAG_WRITABLE).toBe(0);
      }
    }
  });

  it("hoists a dApp ComputeBudget ix, or injects a default limit when absent", () => {
    const withCb = wrapForExecute(dappMsg(true).msg, { wardenProgram, smartAccount, signer });
    expect(withCb.computeBudgetIxs.length).toBe(1);
    expect(withCb.computeBudgetIxs[0]!.programId.equals(ComputeBudgetProgram.programId)).toBe(true);
    // No ComputeBudget ended up inside the payload's inner instructions.
    for (const ix of withCb.decoded.ixs) {
      expect(withCb.logical[ix.programIndex]!.key).not.toEqual(ComputeBudgetProgram.programId.toBytes());
    }
    const withoutCb = wrapForExecute(dappMsg(false).msg, { wardenProgram, smartAccount, signer });
    expect(withoutCb.computeBudgetIxs.length).toBe(1); // default injected
  });

  it("dedups the shared account into ONE logical slot", () => {
    const { msg } = dappMsg(false);
    const r = wrapForExecute(msg, { wardenProgram, smartAccount, signer });
    const keys = r.logical.map((l) => hex(l.key));
    expect(new Set(keys).size).toBe(keys.length); // no duplicate logical keys
  });

  // -------------------------------------------------------------------------
  // The decompile-parity property: the logical list and accountsHash are
  // IDENTICAL regardless of which named optionals are present in the outer
  // instruction — because the optionals are NOT in the logical list.
  // -------------------------------------------------------------------------
  it("accountsHash is identical across every present/absent optional combination", () => {
    const { msg } = dappMsg(false);
    const r = wrapForExecute(msg, { wardenProgram, smartAccount, signer });
    const baseHash = hex(r.accountsHash);

    const session = Keypair.generate().publicKey;
    const ixSysvar = Keypair.generate().publicKey;
    const stage = Keypair.generate().publicKey;
    const registry = Keypair.generate().publicKey;
    const stageCreator = Keypair.generate().publicKey;

    const combos = [
      {},
      { session },
      { ixSysvar },
      { session, registry },
      { ixSysvar, stage, stageCreator },
      { session, ixSysvar, stage, registry, stageCreator },
    ];
    for (const opt of combos) {
      const metas = buildExecuteAccountMetas({ wardenProgram, smartAccount, signer, remaining: r.remaining, ...opt });
      // The remaining accounts are always the LAST r.remaining.length entries,
      // in the same order, so the logical list rebuilt from them is unchanged.
      const remaining = metas.slice(metas.length - r.remaining.length);
      const logical: LogicalAccount[] = [
        { key: smartAccount.toBytes(), isSigner: false, isWritable: true },
        // Default payer === signer, so the runtime (and the SDK) hash logical[1]
        // as writable — the fee-payer coalescing (WRDF-0071).
        { key: signer.toBytes(), isSigner: true, isWritable: true },
        ...remaining.map((m) => ({ key: m.pubkey.toBytes(), isSigner: m.isSigner, isWritable: m.isWritable })),
      ];
      expect(hex(computeAccountsHash(logical))).toBe(baseHash);
    }
  });

  it("buildExecuteAccountMetas places optionals in the exact handler order", () => {
    const session = Keypair.generate().publicKey;
    const registry = Keypair.generate().publicKey;
    const r = wrapForExecute(dappMsg(false).msg, { wardenProgram, smartAccount, signer });
    const metas = buildExecuteAccountMetas({ wardenProgram, smartAccount, signer, session, registry, remaining: r.remaining });
    // [smart_account, signer, session, ix_sysvar(sentinel), stage(sentinel), registry, stage_creator(sentinel), ...remaining]
    expect(metas[0]!.pubkey.equals(smartAccount)).toBe(true);
    expect(metas[1]!.pubkey.equals(signer)).toBe(true);
    expect(metas[2]!.pubkey.equals(session)).toBe(true);
    expect(metas[3]!.pubkey.equals(wardenProgram)).toBe(true); // ix_sysvar omitted → sentinel
    expect(metas[4]!.pubkey.equals(wardenProgram)).toBe(true); // stage omitted → sentinel
    expect(metas[5]!.pubkey.equals(registry)).toBe(true);
    expect(metas[6]!.pubkey.equals(wardenProgram)).toBe(true); // stage_creator omitted → sentinel
    expect(metas.length).toBe(7 + r.remaining.length);
  });

  it("injects the documented default compute-unit limit", () => {
    const r = wrapForExecute(dappMsg(false).msg, { wardenProgram, smartAccount, signer });
    const limit = r.computeBudgetIxs.find((ix) => ix.data[0] === 2)!;
    // SetComputeUnitLimit is tag 2 ‖ u32 LE.
    expect(limit).toBeDefined();
    const data = limit.data;
    const units = data[1]! | (data[2]! << 8) | (data[3]! << 16) | (data[4]! << 24);
    expect(units >>> 0).toBe(DEFAULT_COMPUTE_UNIT_LIMIT);
  });

  // -------------------------------------------------------------------------
  // WRDF-0071 — fee-payer privilege coalescing. The runtime promotes the fee
  // payer to signer+writable and the handler hashes the logical list from those
  // RUNTIME flags. The SDK must hash whichever logical account is the payer as
  // writable, or a signed root ceremony fails ChallengeMismatch.
  // -------------------------------------------------------------------------
  it("hashes logical[1] writable when signer is the payer, read-only for a separate relayer", () => {
    const { msg } = dappMsg(false);
    const selfPay = wrapForExecute(msg, { wardenProgram, smartAccount, signer }); // payer defaults to signer
    expect(selfPay.logical[1]!.isWritable).toBe(true);

    const relayer = Keypair.generate().publicKey;
    const relayed = wrapForExecute(msg, { wardenProgram, smartAccount, signer, payer: relayer });
    expect(relayed.logical[1]!.isWritable).toBe(false); // relayer is not in the logical list

    // Different payer → different signed hash. This is the bug's fingerprint.
    expect(hex(selfPay.accountsHash)).not.toBe(hex(relayed.accountsHash));
  });

  // WRDF-0074 — a third-party signer must be REJECTED, never silently stripped.
  it("rejects an inner instruction that requires a third-party signer", () => {
    const cosigner = Keypair.generate().publicKey;
    const prog = Keypair.generate().publicKey;
    const ix = new TransactionInstruction({
      programId: prog,
      keys: [{ pubkey: cosigner, isSigner: true, isWritable: false }],
      data: Buffer.from([1]),
    });
    const msg = new TransactionMessage({ payerKey: signer, recentBlockhash: BLOCKHASH, instructions: [ix] }).compileToV0Message();
    expect(() => wrapForExecute(msg, { wardenProgram, smartAccount, signer })).toThrow(/third-party signer/);
  });

  // WRDF-0073 — the general wrapper refuses a writable PDA (the sanctioned
  // writable-PDA close is a warden-native op, not a wrapped foreign message).
  it("rejects an inner instruction that names the SmartAccount PDA writable", () => {
    const prog = Keypair.generate().publicKey;
    const ix = new TransactionInstruction({
      programId: prog,
      keys: [{ pubkey: smartAccount, isSigner: false, isWritable: true }],
      data: Buffer.from([9]),
    });
    const msg = new TransactionMessage({ payerKey: signer, recentBlockhash: BLOCKHASH, instructions: [ix] }).compileToV0Message();
    expect(() => wrapForExecute(msg, { wardenProgram, smartAccount, signer })).toThrow(/SmartAccount PDA writable/);
  });

  // WRDF-0072 — large shapes get a RequestHeapFrame; small ones do not; and a
  // dApp that supplied only a compute-unit PRICE still gets a limit injected.
  it("injects a RequestHeapFrame only for large shapes and enforces account caps", () => {
    const small = wrapForExecute(dappMsg(false).msg, { wardenProgram, smartAccount, signer });
    expect(small.computeBudgetIxs.some((ix) => ix.data[0] === 1)).toBe(false); // no heap frame

    // A shape with many distinct writable accounts crosses the trigger.
    const prog = Keypair.generate().publicKey;
    const keys = Array.from({ length: HEAP_FRAME_TRIGGER_REMAINING }, () => ({
      pubkey: Keypair.generate().publicKey,
      isSigner: false,
      isWritable: true,
    }));
    const bigIx = new TransactionInstruction({ programId: prog, keys, data: Buffer.from([0]) });
    const bigMsg = new TransactionMessage({ payerKey: signer, recentBlockhash: BLOCKHASH, instructions: [bigIx] }).compileToV0Message();
    const big = wrapForExecute(bigMsg, { wardenProgram, smartAccount, signer });
    const frame = big.computeBudgetIxs.find((ix) => ix.data[0] === 1)!;
    expect(frame).toBeDefined();
    const bytes = (frame.data[1]! | (frame.data[2]! << 8) | (frame.data[3]! << 16) | (frame.data[4]! << 24)) >>> 0;
    expect(bytes).toBe(HEAP_FRAME_BYTES);
  });

  it("keeps a dApp price setting AND still injects a compute-unit limit", () => {
    const price = ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 5 });
    const prog = Keypair.generate().publicKey;
    const ix = new TransactionInstruction({ programId: prog, keys: [{ pubkey: Keypair.generate().publicKey, isSigner: false, isWritable: true }], data: Buffer.from([1]) });
    const msg = new TransactionMessage({ payerKey: signer, recentBlockhash: BLOCKHASH, instructions: [price, ix] }).compileToV0Message();
    const r = wrapForExecute(msg, { wardenProgram, smartAccount, signer });
    expect(r.computeBudgetIxs.some((i) => i.data[0] === 3)).toBe(true); // price preserved
    expect(r.computeBudgetIxs.some((i) => i.data[0] === 2)).toBe(true); // limit injected
  });

  it("rejects a shape past the on-chain account cap", () => {
    const prog = Keypair.generate().publicKey;
    const keys = Array.from({ length: MAX_EXECUTE_ACCOUNTS_TOTAL + 1 }, () => ({
      pubkey: Keypair.generate().publicKey,
      isSigner: false,
      isWritable: false,
    }));
    const ix = new TransactionInstruction({ programId: prog, keys, data: Buffer.from([0]) });
    const msg = new TransactionMessage({ payerKey: signer, recentBlockhash: BLOCKHASH, instructions: [ix] }).compileToV0Message();
    expect(() => wrapForExecute(msg, { wardenProgram, smartAccount, signer })).toThrow(/MAX_EXECUTE_ACCOUNTS_TOTAL/);
  });
});
