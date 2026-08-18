import { PublicKey, TransactionMessage, VersionedTransaction, VersionedMessage, AddressLookupTableAccount, TransactionInstruction, ComputeBudgetProgram, SystemProgram, Keypair } from "@solana/web3.js";
export const MAX_TX_BYTES = 1232;

/** execute ix data: u8 op=2 | u8 n_ixs | for each: u8 program_idx | u8 n_accts | n_accts×(u8 acct_idx | u8 flags) | u16 data_len | data
 *
 *  CONTRACT (controller ruling, round 2 review, 2026-08-18): indices are INSTRUCTION-LOCAL, not
 *  message-global. Index i refers to the i-th account meta of the `execute` instruction itself —
 *  i.e. position i in `outer.keys` = [account, sessionKey, ...order] (0 = account, 1 = sessionKey,
 *  2.. = order). This is what the on-chain `execute` handler actually receives: Anchor's
 *  `remaining_accounts` (and any instruction's account list in general) is populated from that
 *  ONE instruction's own `accountKeyIndexes`, resolved in the instruction's own original key
 *  order — the program never sees the transaction MESSAGE's global deduped/reordered key list,
 *  only its own instruction's account slice, in the order that instruction specified.
 *
 *  This is stable across compilation: `TransactionMessage.compileToV0Message` may dedupe and
 *  globally re-sort the MESSAGE's account-key list (signer+writable, signer+readonly,
 *  non-signer+writable, non-signer+readonly, then LUT keys), but it does so by computing, for
 *  EACH instruction independently, where each of that instruction's own keys landed in the new
 *  global list — `accountKeyIndexes[j]` = the message-global slot of `outer.keys[j]`. The
 *  instruction's own key ORDER (position j) never changes, only which global slot each position
 *  maps to. So `outer.keys[j]` is exactly what the runtime hands the program as the j-th account
 *  for this instruction, regardless of any global reordering — indexing by instruction-local
 *  position is correct by construction and needs no post-compile lookup at all.
 *
 *  HISTORY: an earlier version of this file (round 0, the task brief's own code) indexed a bare
 *  `order` array that omitted the 2-slot `[account, sessionKey]` prefix baked into `outer.keys`,
 *  producing indices off by 2 — a real bug, but the fix is "index outer.keys, the full
 *  instruction-local list," NOT "index the compiled message's global list" (round 1 review's
 *  fix, since reverted — global indices are what a DIFFERENT on-chain design, one that reads
 *  `remaining_accounts` positions against the outer message directly rather than via Anchor's
 *  per-instruction resolution, would need; that is not this program's contract). Both mistakes
 *  are exactly the kind a byte-count-only test cannot catch — only a round-trip decode against
 *  the correct index space does (see wrap.test.ts). After compiling, `wrapForExecute` decompiles
 *  the result and ASSERTS the execute instruction's resolved key order equals `outer.keys`
 *  exactly, precisely to guard this contract going forward. */

export type DecodedExecuteIx = {
  programIdx: number;
  accounts: { idx: number; isSigner: boolean; isWritable: boolean }[];
  data: Uint8Array;
};

/** Inverse of the packing below — decodes an `execute` instruction's data payload back into
 *  per-inner-instruction {programIdx, accounts[], data}. `programIdx`/`accounts[].idx` are
 *  INSTRUCTION-LOCAL indices (see contract above) — resolve them against the execute
 *  instruction's OWN key list (`outer.keys`, or equivalently the decompiled instruction's
 *  `.keys`), never against the message's global account-key list. Used to round-trip-verify
 *  wrapping (wrap.test.ts) rather than trusting the packer against itself. */
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

/** Serializes a representative `stage_chunk` instruction and binary-searches the largest payload
 *  that keeps the whole transaction ≤ MAX_TX_BYTES. Replaces the previous unexplained "900 B"
 *  constant with a measured number (round 1 review — was Important).
 *
 *  Spec §5.1 ("stage_open(hash,len) / stage_chunk(off,bytes) / stage_finalize / stage_close —
 *  any payer") specifies ONLY the signer (any payer) — it does NOT specify the Stage PDA, the
 *  System Program, or an 8-byte header. The account shape below (payer signer, Stage PDA
 *  writable, System Program) and the 8-byte header (offset:u32, len:u32) + payload are an
 *  ASSUMED layout per controller ruling (round 3 review, 2026-08-18), not something §5.1 actually
 *  pins down — so the measured cap below is PROVISIONAL until Phase 1 fixes the real
 *  `stage_chunk` account list/order and data layout (see result.md). Memoized per program id
 *  since the result only depends on wardenProgram's pubkey (a fixed 32 bytes either way) and
 *  MAX_TX_BYTES. */
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
      const data = Buffer.alloc(8 + payloadLen); // u32 offset + u32 len header + payload (assumed shape, not from §5.1 — see doc comment above)
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
  // directly in the transaction's top-level instruction list, not inside a CPI (round 1 review —
  // was Important). Hoist any the dApp tx already carries; if it carries none, add a default
  // limit so the measured shape matches what Phase 1 will actually build.
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
  // A dApp instruction may itself reference `account` (e.g. as an owner/destination field) or
  // `sessionKey` (coincidentally, or because the wrap-time session key happens to collide with
  // some address the inner instruction cares about) — both already have fixed, always-present
  // prefix entries below, so they're excluded from `order` here rather than kept and duplicated
  // (round 3 review — a duplicate entry would silently shift every later account's index by one,
  // corrupting the instruction-local index space this file's whole contract depends on). Their
  // writable flags are merged into the prefix entries rather than assumed away — currently always
  // a no-op since both prefix entries already claim the strongest permission (writable:true), but
  // computed explicitly so this stays correct if that default ever changes. `account`'s isSigner
  // stays forced false and `sessionKey`'s stays forced true regardless of what any inner
  // instruction asked for, per the invoke_signed/session-key model above the metas loop.
  const accountMeta = metas.get(key(account));
  const sessionMeta = metas.get(key(sessionKey));
  const order = [...metas.values()].filter(m => !m.pubkey.equals(account) && !m.pubkey.equals(sessionKey));
  // outerKeys IS the index space (see contract above): position 0 = account, 1 = sessionKey,
  // 2.. = order. No compilation step is needed to learn these indices — they're fixed the moment
  // this array is built, and stay valid regardless of how compileToV0Message reorders the
  // MESSAGE's global account-key list, because that reordering is per-instruction-index-preserving.
  const outerKeys = [
    { pubkey: account, isSigner: false, isWritable: true || !!accountMeta?.isWritable },
    { pubkey: sessionKey, isSigner: true, isWritable: true || !!sessionMeta?.isWritable },
    ...order,
  ];
  const idx = (p: PublicKey): number => {
    const i = outerKeys.findIndex(k => k.pubkey.equals(p));
    if (i < 0) throw new Error(`wrapForExecute: account ${p.toBase58()} missing from outer.keys`);
    if (i > 0xff) throw new Error(`wrapForExecute: account index ${i} for ${p.toBase58()} exceeds u8 (255) — too many accounts to wrap with this scheme`);
    return i;
  };

  // n_ixs is a single u8 byte in the packed header — silently truncating (256 wraps to 0 when
  // Buffer.from() coerces each array element to a byte) would corrupt every instruction after the
  // wrap point, so this must throw rather than truncate (round 3 review — the same class of bug
  // as the account-index overflow check below, just for the instruction count instead).
  if (inner.length > 0xff) throw new Error(`wrapForExecute: ${inner.length} inner instructions, exceeds u8 (255) — too many instructions to wrap with this scheme`);
  const parts: number[] = [2, inner.length];
  for (const ix of inner) {
    if (ix.keys.length > 0xff) throw new Error(`wrapForExecute: instruction has ${ix.keys.length} accounts, exceeds u8`);
    parts.push(idx(ix.programId), ix.keys.length);
    for (const k of ix.keys) parts.push(idx(k.pubkey), (k.isSigner ? 1 : 0) | (k.isWritable ? 2 : 0));
    if (ix.data.length > 0xffff) throw new Error(`wrapForExecute: instruction data length ${ix.data.length} exceeds u16`);
    parts.push(ix.data.length & 0xff, ix.data.length >> 8, ...ix.data);
  }

  const outer = new TransactionInstruction({ programId: wardenProgram, keys: outerKeys, data: Buffer.from(parts) });
  const compiled = new TransactionMessage({ payerKey: sessionKey, recentBlockhash: decompiled.recentBlockhash, instructions: [...topLevel, outer] }).compileToV0Message(luts);

  // Contract check (round 2 review): compilation must preserve the execute instruction's
  // instruction-local key order exactly, or every packed index above is meaningless. Decompile
  // and assert outer.keys (what we packed indices against) equals the execute instruction's
  // resolved key list (what the on-chain program will actually receive), pubkey-for-pubkey, in
  // order.
  const redecompiled = TransactionMessage.decompile(compiled, { addressLookupTableAccounts: luts });
  const executeIx = redecompiled.instructions.find(ix => ix.programId.equals(wardenProgram));
  if (!executeIx) throw new Error("wrapForExecute: internal error — execute instruction missing after compile/decompile round-trip");
  if (executeIx.keys.length !== outerKeys.length || !executeIx.keys.every((k, i) => k.pubkey.equals(outerKeys[i].pubkey))) {
    throw new Error(
      `wrapForExecute: internal error — compiled execute instruction's key order diverged from outer.keys ` +
      `(expected [${outerKeys.map(k => k.pubkey.toBase58()).join(",")}], got [${executeIx.keys.map(k => k.pubkey.toBase58()).join(",")}]) — ` +
      `instruction-local indexing contract violated, packed indices would be wrong`
    );
  }

  const tx = new VersionedTransaction(compiled);
  // @solana/web3.js's MessageV0.serializeInstructions() pre-allocates a fixed PACKET_DATA_SIZE
  // (1232B) scratch buffer and THROWS rather than returning a big length once the instructions
  // section alone would overrun it. That's still an unambiguous "does not fit inline" result, so
  // treat it as +Infinity instead of letting the whole measurement crash.
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
  // executeAccountCount = outerKeys.length, i.e. the wrapped `execute` instruction's OWN account
  // list length (round 5 review — Important): this is the honest "how many accounts does the
  // execute instruction itself carry" number, distinct from the original message's total key
  // count (`totalKeys` in measure.ts) and from any writable-only subset of either. See result.md
  // "Round 5 fix" for why the previous `writableAccounts` metric in measure.ts was mislabeled.
  return { inline, stagedChunks, bytesInline, bytesOriginal, executeAccountCount: outerKeys.length };
}
