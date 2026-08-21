import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { FIXTURES_DIR, coalescedWrap, serializeLogical } from "../scripts/fixtures-data.js";
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
  MIN_COMPUTE_UNIT_LIMIT,
  HEAP_FRAME_FLOOR_BYTES,
  MAX_EXECUTE_ACCOUNTS_TOTAL,
  MAX_EXECUTE_WRITABLE,
  FLAG_WRITABLE,
  type LogicalAccount,
} from "../src/index.js";

const BLOCKHASH = "11111111111111111111111111111111";
const hex = (b: Uint8Array): string => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const CB = ComputeBudgetProgram.programId;
const heapFrame = (ixs: TransactionInstruction[]) => ixs.find((i) => i.programId.equals(CB) && i.data[0] === 1);
const cuLimit = (ixs: TransactionInstruction[]) => ixs.find((i) => i.programId.equals(CB) && i.data[0] === 2);
const readU32 = (d: Uint8Array) => (d[1]! | (d[2]! << 8) | (d[3]! << 16) | (d[4]! << 24)) >>> 0;

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

/** An inner instruction naming `keys` under a fresh program. */
function ixMsg(keys: Array<{ pubkey: PublicKey; isSigner: boolean; isWritable: boolean }>, payerKey = signer) {
  const ix = new TransactionInstruction({ programId: Keypair.generate().publicKey, keys, data: Buffer.from([0]) });
  return new TransactionMessage({ payerKey, recentBlockhash: BLOCKHASH, instructions: [ix] }).compileToV0Message();
}

describe("wrapForExecute", () => {
  it("builds a payload whose logical indices round-trip and whose PDA is index 0", () => {
    const { msg } = dappMsg(false);
    const r = wrapForExecute(msg, { wardenProgram, smartAccount, signer });
    expect(hex(r.logical[0]!.key)).toBe(hex(smartAccount.toBytes()));
    expect(hex(r.logical[1]!.key)).toBe(hex(signer.toBytes()));
    expect(r.logical[0]!.isSigner).toBe(false); // PDA never a tx signer
    const decoded = decodeExecutePayload(r.payload);
    expect(decoded).toEqual(r.decoded);
    for (const ix of decoded.ixs) {
      expect(ix.programIndex).toBeLessThan(r.logical.length);
      for (const a of ix.accounts) expect(a.index).toBeLessThan(r.logical.length);
    }
    for (const ix of decoded.ixs) {
      for (const a of ix.accounts) {
        if (a.index === 0) expect(a.flags & FLAG_WRITABLE).toBe(0);
      }
    }
  });

  it("hoists a dApp ComputeBudget ix, or injects a default limit when absent", () => {
    const withCb = wrapForExecute(dappMsg(true).msg, { wardenProgram, smartAccount, signer });
    expect(cuLimit(withCb.computeBudgetIxs)).toBeDefined(); // dApp's 250k kept
    expect(readU32(cuLimit(withCb.computeBudgetIxs)!.data)).toBe(250_000);
    for (const ix of withCb.decoded.ixs) {
      expect(withCb.logical[ix.programIndex]!.key).not.toEqual(CB.toBytes()); // never inside the payload
    }
    const withoutCb = wrapForExecute(dappMsg(false).msg, { wardenProgram, smartAccount, signer });
    expect(readU32(cuLimit(withoutCb.computeBudgetIxs)!.data)).toBe(DEFAULT_COMPUTE_UNIT_LIMIT);
  });

  it("dedups the shared account into ONE logical slot", () => {
    const { msg } = dappMsg(false);
    const r = wrapForExecute(msg, { wardenProgram, smartAccount, signer });
    const keys = r.logical.map((l) => hex(l.key));
    expect(new Set(keys).size).toBe(keys.length);
  });

  // The decompile-parity property: accountsHash is IDENTICAL regardless of which
  // named optionals are present, as long as they do not ALIAS a logical account.
  it("accountsHash is identical across every present/absent non-aliasing optional combination", () => {
    const { msg } = dappMsg(false);
    const base = wrapForExecute(msg, { wardenProgram, smartAccount, signer });
    const baseHash = hex(base.accountsHash);

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
      const r = wrapForExecute(msg, { wardenProgram, smartAccount, signer, ...opt });
      expect(hex(r.accountsHash)).toBe(baseHash);
    }
  });

  it("buildExecuteAccountMetas places optionals in the exact handler order", () => {
    const session = Keypair.generate().publicKey;
    const registry = Keypair.generate().publicKey;
    const r = wrapForExecute(dappMsg(false).msg, { wardenProgram, smartAccount, signer });
    const metas = buildExecuteAccountMetas({ wardenProgram, smartAccount, signer, session, registry, remaining: r.remaining });
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
    expect(readU32(cuLimit(r.computeBudgetIxs)!.data)).toBe(DEFAULT_COMPUTE_UNIT_LIMIT);
  });

  // -------------------------------------------------------------------------
  // WRDF-0071 — fee-payer / named-optional privilege coalescing. The handler
  // hashes runtime flags; the SDK must derive them from the compiled instruction.
  // -------------------------------------------------------------------------
  it("hashes logical[1] writable when signer is the payer, read-only for a separate relayer", () => {
    const { msg } = dappMsg(false);
    const selfPay = wrapForExecute(msg, { wardenProgram, smartAccount, signer }); // payer defaults to signer
    expect(selfPay.logical[1]!.isWritable).toBe(true);

    const relayer = Keypair.generate().publicKey;
    const relayed = wrapForExecute(msg, { wardenProgram, smartAccount, signer, payer: relayer });
    expect(relayed.logical[1]!.isWritable).toBe(false);
    expect(hex(selfPay.accountsHash)).not.toBe(hex(relayed.accountsHash));
  });

  // WRDF-0071 round 2 — a named optional that ALIASES the signer (stageCreator ==
  // signer, writable) coalesces logical[1] to writable even under a relayer payer.
  it("hashes logical[1] writable when a writable named optional aliases the signer", () => {
    const { msg } = dappMsg(false);
    const relayer = Keypair.generate().publicKey;
    const noAlias = wrapForExecute(msg, { wardenProgram, smartAccount, signer, payer: relayer });
    const aliased = wrapForExecute(msg, { wardenProgram, smartAccount, signer, payer: relayer, stageCreator: signer });
    expect(noAlias.logical[1]!.isWritable).toBe(false);
    expect(aliased.logical[1]!.isWritable).toBe(true); // stage_creator is a writable optional
    expect(hex(noAlias.accountsHash)).not.toBe(hex(aliased.accountsHash));
  });

  // WRDF-0074 — reject a third-party signer fail-closed.
  it("rejects an inner instruction that requires a third-party signer", () => {
    const cosigner = Keypair.generate().publicKey;
    const msg = ixMsg([{ pubkey: cosigner, isSigner: true, isWritable: false }]);
    expect(() => wrapForExecute(msg, { wardenProgram, smartAccount, signer })).toThrow(/third-party signer/);
  });

  // WRDF-0073 — the general wrapper refuses a writable PDA.
  it("rejects an inner instruction that names the SmartAccount PDA writable", () => {
    const msg = ixMsg([{ pubkey: smartAccount, isSigner: false, isWritable: true }]);
    expect(() => wrapForExecute(msg, { wardenProgram, smartAccount, signer })).toThrow(/SmartAccount PDA writable/);
  });

  // -------------------------------------------------------------------------
  // WRDF-0072 — a heap frame is ALWAYS present (heap is driven by instruction
  // count, not account count), sized to the shape.
  // -------------------------------------------------------------------------
  it("always attaches a RequestHeapFrame at or above the measured floor", () => {
    const small = wrapForExecute(dappMsg(false).msg, { wardenProgram, smartAccount, signer });
    const f = heapFrame(small.computeBudgetIxs);
    expect(f).toBeDefined();
    expect(readU32(f!.data)).toBeGreaterThanOrEqual(HEAP_FRAME_FLOOR_BYTES);

    // A many-instruction shape (remainingLen == 1, but 40 inner ixs) still gets a
    // frame — the pre-fix account-count trigger would have skipped it.
    const shared = Keypair.generate().publicKey;
    const prog = Keypair.generate().publicKey;
    const ixs = Array.from({ length: 40 }, () =>
      new TransactionInstruction({ programId: prog, keys: [{ pubkey: shared, isSigner: false, isWritable: true }], data: Buffer.from([0]) }),
    );
    const bigMsg = new TransactionMessage({ payerKey: signer, recentBlockhash: BLOCKHASH, instructions: ixs }).compileToV0Message();
    const big = wrapForExecute(bigMsg, { wardenProgram, smartAccount, signer });
    expect(big.remaining.length).toBe(2); // shared + program only
    expect(heapFrame(big.computeBudgetIxs)).toBeDefined();
  });

  it("keeps a dApp price setting AND still injects a validated compute-unit limit", () => {
    const price = ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 5 });
    const ix = new TransactionInstruction({ programId: Keypair.generate().publicKey, keys: [{ pubkey: Keypair.generate().publicKey, isSigner: false, isWritable: true }], data: Buffer.from([1]) });
    const msg = new TransactionMessage({ payerKey: signer, recentBlockhash: BLOCKHASH, instructions: [price, ix] }).compileToV0Message();
    const r = wrapForExecute(msg, { wardenProgram, smartAccount, signer });
    expect(r.computeBudgetIxs.some((i) => i.data[0] === 3)).toBe(true); // price preserved
    expect(cuLimit(r.computeBudgetIxs)).toBeDefined(); // limit injected
    expect(heapFrame(r.computeBudgetIxs)).toBeDefined();
  });

  // WRDF-0076 — an undersized (or malformed) compute-unit limit is rejected, not
  // rubber-stamped by tag presence.
  it("rejects a dApp compute-unit limit below the measured floor", () => {
    const tiny = ComputeBudgetProgram.setComputeUnitLimit({ units: 1 });
    const ix = new TransactionInstruction({ programId: Keypair.generate().publicKey, keys: [{ pubkey: Keypair.generate().publicKey, isSigner: false, isWritable: true }], data: Buffer.from([1]) });
    const msg = new TransactionMessage({ payerKey: signer, recentBlockhash: BLOCKHASH, instructions: [tiny, ix] }).compileToV0Message();
    expect(() => wrapForExecute(msg, { wardenProgram, smartAccount, signer })).toThrow(/below the floor/);
  });

  it("rejects a configured default limit below the floor", () => {
    expect(() =>
      wrapForExecute(dappMsg(false).msg, { wardenProgram, smartAccount, signer, defaultComputeUnitLimit: MIN_COMPUTE_UNIT_LIMIT - 1 }),
    ).toThrow(/below the floor/);
  });

  // -------------------------------------------------------------------------
  // WRDF-0077 — caps are counted from EFFECTIVE (post-coalescing) privileges. A
  // read-only remaining account chosen as the payer is promoted to writable.
  // -------------------------------------------------------------------------
  it("counts a payer-promoted remaining account against the writable cap", () => {
    const writables = Array.from({ length: MAX_EXECUTE_WRITABLE }, () => ({ pubkey: Keypair.generate().publicKey, isSigner: false, isWritable: true }));
    const readonlyPayer = Keypair.generate().publicKey;
    const keys = [...writables, { pubkey: readonlyPayer, isSigner: false, isWritable: false }];
    // The dApp message's own payer stays `signer`; readonlyPayer is a read-only
    // dApp account that becomes the OUTER execute fee payer and is promoted there.
    const msg = ixMsg(keys);
    // Raw writable count is exactly the cap (28); promoting the payer makes 29.
    expect(() => wrapForExecute(msg, { wardenProgram, smartAccount, signer, payer: readonlyPayer })).toThrow(/MAX_EXECUTE_WRITABLE/);
  });

  it("rejects a shape past the on-chain account cap", () => {
    const keys = Array.from({ length: MAX_EXECUTE_ACCOUNTS_TOTAL + 2 }, () => ({ pubkey: Keypair.generate().publicKey, isSigner: false, isWritable: false }));
    const msg = ixMsg(keys);
    expect(() => wrapForExecute(msg, { wardenProgram, smartAccount, signer })).toThrow(/MAX_EXECUTE_ACCOUNTS_TOTAL/);
  });

  // WRDF-0079 — a wrapped instruction that needs the root/session signer WRITABLE
  // is rejected fail-closed (the payload would request a privilege the outer meta
  // does not hold). Covers the separate-relayer path the reviewer named.
  it("rejects an inner instruction that names the root/session signer writable", () => {
    const msg = ixMsg([{ pubkey: signer, isSigner: true, isWritable: true }]);
    const relayer = Keypair.generate().publicKey;
    expect(() => wrapForExecute(msg, { wardenProgram, smartAccount, signer, payer: relayer })).toThrow(/signer writable/);
  });

  // Every payload privilege is a subset of the effective outer logical meta.
  it("holds the payload⊆outer privilege-subset invariant on a normal shape", () => {
    const { msg } = dappMsg(false);
    const r = wrapForExecute(msg, { wardenProgram, smartAccount, signer });
    for (const ix of r.decoded.ixs) {
      for (const a of ix.accounts) {
        const m = r.logical[a.index]!;
        if (a.flags & FLAG_WRITABLE) expect(m.isWritable).toBe(true);
        // index 0 (the PDA) signs via invoke_signed, not an outer signature.
        if (a.flags & 1 && a.index !== 0) expect(m.isSigner).toBe(true); // FLAG_SIGNER
      }
    }
  });

  // -------------------------------------------------------------------------
  // WRDF-0080 — a caller-supplied RequestHeapFrame is preserved ONLY if it clears
  // the runtime's alignment + range rules and covers the shape; else rejected.
  // -------------------------------------------------------------------------
  it("validates a caller-supplied heap frame against the runtime range and alignment", () => {
    const frameIx = (bytes: number) => {
      const d = Buffer.alloc(5);
      d[0] = 1; // RequestHeapFrame tag
      d.writeUInt32LE(bytes >>> 0, 1);
      return new TransactionInstruction({ programId: CB, keys: [], data: d });
    };
    const withFrame = (bytes: number) => {
      const ix = new TransactionInstruction({ programId: Keypair.generate().publicKey, keys: [{ pubkey: Keypair.generate().publicKey, isSigner: false, isWritable: true }], data: Buffer.from([1]) });
      const msg = new TransactionMessage({ payerKey: signer, recentBlockhash: BLOCKHASH, instructions: [frameIx(bytes), ix] }).compileToV0Message();
      return () => wrapForExecute(msg, { wardenProgram, smartAccount, signer });
    };
    // The measured floor (128 KiB) is a valid, adequate, aligned frame — kept.
    const kept = withFrame(HEAP_FRAME_FLOOR_BYTES)();
    expect(heapFrame(kept.computeBudgetIxs)).toBeDefined();
    expect(readU32(heapFrame(kept.computeBudgetIxs)!.data)).toBe(HEAP_FRAME_FLOOR_BYTES);
    // The maximum valid frame is kept.
    expect(readU32(heapFrame(withFrame(256 * 1024)().computeBudgetIxs)!.data)).toBe(256 * 1024);
    // Over the ceiling, misaligned, and below the shape's need all reject.
    expect(withFrame(256 * 1024 + 1024)).toThrow(/outside the runtime range/);
    expect(withFrame(256 * 1024 - 1)).toThrow(/multiple of 1024/);
    expect(withFrame(64 * 1024)).toThrow(/smaller than this shape needs/); // < 128 KiB floor need
  });

  // The returned executeAccountMetas ARE the logical source of truth: rebuilding
  // the hash from them (positions 0,1,7..) reproduces accountsHash exactly.
  it("accountsHash is reproducible from the returned executeAccountMetas", () => {
    const stage = Keypair.generate().publicKey;
    const registry = Keypair.generate().publicKey;
    const r = wrapForExecute(dappMsg(false).msg, { wardenProgram, smartAccount, signer, stage, registry });
    const m = r.executeAccountMetas;
    const logical: LogicalAccount[] = [m[0]!, m[1]!, ...m.slice(7)].map((x) => ({ key: x.pubkey.toBytes(), isSigner: x.isSigner, isWritable: x.isWritable }));
    expect(hex(computeAccountsHash(logical))).toBe(hex(r.accountsHash));
  });

  // ---------------------------------------------------------------------------
  // WRDF-0081 — an INDEPENDENT cross-boundary oracle for the coalesced hash. The
  // committed golden `payload_coalesced_logical.bin` (+ hash) is a READ-ONLY
  // vector written only by scripts/gen-fixtures.ts; the Rust test
  // (`payload::tests::ts_coalesced_logical_hash_matches`) reads the SAME bytes and
  // recomputes with the handler's OWN `compute_accounts_hash`. Here we assert
  // `wrapForExecute` reproduces the golden byte-for-byte AND independently pin the
  // expected logical list, so a coalescing regression fails both lanes (and the
  // gate's `git diff` guard) instead of self-updating the golden.
  // ---------------------------------------------------------------------------
  it("reproduces the committed coalesced-logical golden and its pinned structure", () => {
    const r = coalescedWrap();
    // Pin the COMPLETE effective logical list against LITERAL byte patterns —
    // NOT identities imported from the generator (WRDF-0081). Inputs are
    // smart=0x11, signer=0x22 (== payer), program=0x33, account=0x44; the dApp ix
    // is [acct(0x44,writable), smart(0x11,signer)] so wrapForExecute's remaining
    // insertion order is [program 0x33, account 0x44].
    const lit = (byte: number) => hex(new Uint8Array(32).fill(byte));
    const expected = [
      { key: lit(0x11), isSigner: false, isWritable: true }, // smart_account (PDA)
      { key: lit(0x22), isSigner: true, isWritable: true }, // signer == payer → coalesced writable
      { key: lit(0x33), isSigner: false, isWritable: false }, // program id
      { key: lit(0x44), isSigner: false, isWritable: true }, // the writable dApp account
    ];
    expect(r.logical.map((a) => ({ key: hex(a.key), isSigner: a.isSigner, isWritable: a.isWritable }))).toEqual(expected);

    // The committed golden bytes encode exactly that pinned list, and Rust
    // recomputes the hash over the same bytes with the handler's function.
    const committedLogical = new Uint8Array(readFileSync(resolve(FIXTURES_DIR, "payload_coalesced_logical.bin")));
    const committedHash = readFileSync(resolve(FIXTURES_DIR, "payload_coalesced_hash.hex"), "utf8").trim();
    expect(hex(serializeLogical(r.logical))).toBe(hex(committedLogical));
    expect(hex(r.accountsHash)).toBe(committedHash);
  });

  // WRDF-0081 — importing the fixtures-data module must have NO filesystem effect.
  // The old `if (!process.env.VITEST) generate()` wrote the goldens on any
  // non-Vitest import; now generation lives only in the gen-fixtures runner behind
  // a main-module check, and this module's top level is side-effect-free. Re-run
  // its top level (resetModules + fresh import) and assert the committed goldens
  // are byte-unchanged — if the top level wrote anything, these would differ.
  it("re-importing fixtures-data does not write the golden fixtures", async () => {
    const { vi } = await import("vitest");
    const names = [
      "payload_vector.bin",
      "payload_accounts_hash.hex",
      "payload_writable_pda_close.bin",
      "payload_coalesced_logical.bin",
      "payload_coalesced_hash.hex",
    ];
    const snapshot = () => names.map((n) => hex(new Uint8Array(readFileSync(resolve(FIXTURES_DIR, n)))));
    const before = snapshot();
    vi.resetModules();
    const mod = await import("../scripts/fixtures-data.js");
    expect(typeof mod.generate).toBe("function"); // present, but never auto-invoked
    expect(snapshot()).toEqual(before);
  });
});
