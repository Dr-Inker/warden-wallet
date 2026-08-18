import { PublicKey, TransactionMessage, VersionedTransaction, VersionedMessage, MessageV0, AddressLookupTableAccount, TransactionInstruction, ComputeBudgetProgram, SystemProgram, Keypair } from "@solana/web3.js";
export const MAX_TX_BYTES = 1232;

/** execute ix data: u8 op=2 | u8 n_ixs | for each: u8 program_idx | u8 n_accts | n_accts×(u8 acct_idx | u8 flags) | u16 data_len | data
 *
 *  Indices refer to the OUTER COMPILED message's account-key list — i.e. exactly the order
 *  `compiled.getAccountKeys({ addressLookupTableAccounts }).keySegments().flat()` returns: static
 *  account keys first, then LUT-resolved writable keys, then LUT-resolved readonly keys. This is
 *  the same resolution order Solana runtime uses for on-chain account-index lookups.
 *
 *  IMPORTANT (fixed 2026-08-18, round 1 review — was Critical): indices must be computed AFTER
 *  compiling the outer message, from the compiled message itself. `compileToV0Message` dedups
 *  accounts across all instructions + the payer, then re-sorts them into
 *  [signer+writable, signer+readonly, non-signer+writable, non-signer+readonly] before appending
 *  LUT-resolved keys — it does NOT preserve the insertion order of any locally-built account list.
 *  Indexing into a local `order` array (as an earlier version of this file did) silently produces
 *  garbage indices that happen to still decode as *some* valid account, just not the one that was
 *  meant — that class of bug won't fail a naive smoke test, only a signer trying to actually
 *  execute the instruction (or a round-trip decode test, see wrap.test.ts). */

/** Flattened account-key list in the exact order the compiled message resolves indices against. */
export function compiledAccountKeys(compiled: MessageV0, luts: AddressLookupTableAccount[] = []): PublicKey[] {
  return compiled.getAccountKeys({ addressLookupTableAccounts: luts }).keySegments().flat();
}

export type DecodedExecuteIx = {
  programIdx: number;
  accounts: { idx: number; isSigner: boolean; isWritable: boolean }[];
  data: Uint8Array;
};

/** Inverse of the packing below — decodes an `execute` instruction's data payload back into
 *  per-inner-instruction {programIdx, accounts[], data}. Used to round-trip-verify wrapping
 *  (wrap.test.ts) rather than trusting the packer against itself. */
export function decodeExecuteData(data: Uint8Array): DecodedExecuteIx[] {
  if (data.length < 2 || data[0] !== 2) throw new Error(`decodeExecuteData: expected op=2 header, got ${data[0]}`);
  const nIxs = data[1];
  let o = 2;
  const out: DecodedExecuteIx[] = [];
  for (let i = 0; i < nIxs; i++) {
    const programIdx = data[o++];
    const nAccts = data[o++];
    const accounts: DecodedExecuteIx["accounts"] = [];
    for (let a = 0; a < nAccts; a++) {
      const idx = data[o++];
      const flags = data[o++];
      accounts.push({ idx, isSigner: !!(flags & 1), isWritable: !!(flags & 2) });
    }
    const dataLen = data[o] | (data[o + 1] << 8);
    o += 2;
    out.push({ programIdx, accounts, data: data.slice(o, o + dataLen) });
    o += dataLen;
  }
  return out;
}

const chunkPayloadCache = new Map<string, number>();

/** Serializes a representative `stage_chunk` instruction (1 signer/payer, 3 accounts: payer,
 *  stage PDA, System Program; data = 8-byte header [offset:u32,len:u32] + payload) at increasing
 *  payload sizes and binary-searches the largest payload that keeps the whole transaction ≤
 *  MAX_TX_BYTES. Replaces the previous unexplained "900 B" constant with a measured number
 *  (fixed 2026-08-18, round 1 review — was Important). Memoized per program id since the result
 *  only depends on wardenProgram's pubkey (a fixed 32 bytes either way) and MAX_TX_BYTES. */
export function maxStageChunkPayloadBytes(wardenProgram: PublicKey): number {
  const cacheKey = wardenProgram.toBase58();
  const cached = chunkPayloadCache.get(cacheKey);
  if (cached !== undefined) return cached;

  const payer = Keypair.generate().publicKey;
  const stagePda = Keypair.generate().publicKey;
  // @solana/web3.js's MessageV0.serializeInstructions() pre-allocates a fixed PACKET_DATA_SIZE
  // (1232B) scratch buffer and THROWS ("encoding overruns Uint8Array") rather than returning a
  // big length once the instructions section alone would overrun it — which happens well before
  // any payload size we'd otherwise want to explore in a doubling search. Any payload that throws
  // is unambiguously over MAX_TX_BYTES (the whole tx can never be smaller than its instructions
  // section), so treat it as +Infinity rather than letting the search crash.
  const bytesFor = (payloadLen: number): number => {
    try {
      const data = Buffer.alloc(8 + payloadLen); // u32 offset + u32 len header + payload
      const ix = new TransactionInstruction({
        programId: wardenProgram,
        keys: [
          { pubkey: payer, isSigner: true, isWritable: true },
          { pubkey: stagePda, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data,
      });
      const msg = new TransactionMessage({ payerKey: payer, recentBlockhash: "11111111111111111111111111111111", instructions: [ix] }).compileToV0Message();
      return new VersionedTransaction(msg).serialize().length;
    } catch {
      return Infinity;
    }
  };
  let lo = 0, hi = 1;
  while (bytesFor(hi) <= MAX_TX_BYTES) hi *= 2;
  while (lo < hi - 1) {
    const mid = Math.floor((lo + hi) / 2);
    if (bytesFor(mid) <= MAX_TX_BYTES) lo = mid; else hi = mid;
  }
  chunkPayloadCache.set(cacheKey, lo);
  return lo;
}

export function wrapForExecute(msg: VersionedMessage, wardenProgram: PublicKey, account: PublicKey, sessionKey: PublicKey, luts: AddressLookupTableAccount[] = []) {
  const decompiled = TransactionMessage.decompile(msg, { addressLookupTableAccounts: luts });
  const allInner: TransactionInstruction[] = decompiled.instructions;

  // Compute-budget instructions must stay TOP-LEVEL in the outer message, never CPI'd through
  // `execute` — the runtime only honors SetComputeUnitLimit/SetComputeUnitPrice when they appear
  // directly in the transaction's top-level instruction list, not inside a CPI (fixed 2026-08-18,
  // round 1 review — was Important). Hoist any the dApp tx already carries; if it carries none,
  // add a default limit so the measured shape matches what Phase 1 will actually build.
  const computeBudgetIxs = allInner.filter(ix => ix.programId.equals(ComputeBudgetProgram.programId));
  const inner = allInner.filter(ix => !ix.programId.equals(ComputeBudgetProgram.programId));
  const topLevel = computeBudgetIxs.length > 0 ? computeBudgetIxs : [ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 })];

  // Build the outer `execute` instruction's account metas: every unique account touched by the
  // (non-compute-budget) inner instructions, deduped, PDA forced to non-signer (it authorizes via
  // invoke_signed inside the program, not an ed25519 signature).
  const metas = new Map<string, { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }>();
  const key = (p: PublicKey) => p.toBase58();
  for (const ix of inner) {
    metas.set(key(ix.programId), { pubkey: ix.programId, isSigner: false, isWritable: false });
    for (const k of ix.keys) {
      const cur = metas.get(key(k.pubkey));
      const isSigner = k.pubkey.equals(account) ? false : (cur?.isSigner || k.isSigner); // PDA signs via invoke_signed
      metas.set(key(k.pubkey), { pubkey: k.pubkey, isSigner, isWritable: cur?.isWritable || k.isWritable });
    }
  }
  const order = [...metas.values()];
  const outerKeys = [{ pubkey: account, isSigner: false, isWritable: true }, { pubkey: sessionKey, isSigner: true, isWritable: true }, ...order];

  // Pass 1: compile with placeholder (empty) data purely to learn the FINAL compiled account
  // ordering. compileToV0Message's ordering depends only on each instruction's `keys` (pubkey +
  // isSigner + isWritable) and payerKey — never on instruction data — so this ordering is
  // identical to the one the real (data-filled) compile below produces.
  const probeIx = new TransactionInstruction({ programId: wardenProgram, keys: outerKeys, data: Buffer.alloc(0) });
  const probeCompiled = new TransactionMessage({ payerKey: sessionKey, recentBlockhash: decompiled.recentBlockhash, instructions: [...topLevel, probeIx] }).compileToV0Message(luts);
  const orderedKeys = compiledAccountKeys(probeCompiled, luts);
  const idx = (p: PublicKey): number => {
    const i = orderedKeys.findIndex(k => k.equals(p));
    if (i < 0) throw new Error(`wrapForExecute: account ${p.toBase58()} missing from compiled outer message`);
    if (i > 0xff) throw new Error(`wrapForExecute: account index ${i} for ${p.toBase58()} exceeds u8 (255) — too many accounts to wrap with this scheme`);
    return i;
  };

  const parts: number[] = [2, inner.length];
  for (const ix of inner) {
    if (ix.keys.length > 0xff) throw new Error(`wrapForExecute: instruction has ${ix.keys.length} accounts, exceeds u8`);
    parts.push(idx(ix.programId), ix.keys.length);
    for (const k of ix.keys) parts.push(idx(k.pubkey), (k.isSigner ? 1 : 0) | (k.isWritable ? 2 : 0));
    if (ix.data.length > 0xffff) throw new Error(`wrapForExecute: instruction data length ${ix.data.length} exceeds u16`);
    parts.push(ix.data.length & 0xff, ix.data.length >> 8, ...ix.data);
  }

  // Pass 2: the real outer instruction, now with the actual packed data. Same `outerKeys` ⇒ same
  // account ordering as pass 1, so the indices computed above stay valid.
  const outer = new TransactionInstruction({ programId: wardenProgram, keys: outerKeys, data: Buffer.from(parts) });
  const compiled = new TransactionMessage({ payerKey: sessionKey, recentBlockhash: decompiled.recentBlockhash, instructions: [...topLevel, outer] }).compileToV0Message(luts);
  const tx = new VersionedTransaction(compiled);
  // Same PACKET_DATA_SIZE-scratch-buffer limitation as maxStageChunkPayloadBytes above: a packed
  // payload large enough overruns web3.js's internal instructions-serialization buffer and
  // THROWS rather than returning a big length. That's still an unambiguous "does not fit inline"
  // result, so treat it as +Infinity instead of letting the whole measurement crash.
  let bytesInline: number;
  try {
    bytesInline = tx.serialize().length;
  } catch {
    bytesInline = Infinity;
  }
  let bytesOriginal: number;
  try {
    bytesOriginal = new VersionedTransaction(msg).serialize().length;
  } catch {
    bytesOriginal = Infinity;
  }
  const inline = bytesInline <= MAX_TX_BYTES ? tx : null;
  const stagedChunks = inline ? 0 : Math.ceil(Buffer.from(parts).length / maxStageChunkPayloadBytes(wardenProgram));
  return { inline, stagedChunks, bytesInline, bytesOriginal };
}
