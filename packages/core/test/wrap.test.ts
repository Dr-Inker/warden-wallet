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
        { pubkey: smartAccount, isSigner: false, isWritable: true }, // PDA authority
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
        { key: signer.toBytes(), isSigner: true, isWritable: false },
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
    const data = r.computeBudgetIxs[0]!.data;
    // SetComputeUnitLimit is tag 2 ‖ u32 LE.
    expect(data[0]).toBe(2);
    const units = data[1]! | (data[2]! << 8) | (data[3]! << 16) | (data[4]! << 24);
    expect(units >>> 0).toBe(DEFAULT_COMPUTE_UNIT_LIMIT);
  });
});
