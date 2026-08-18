import { PublicKey, TransactionMessage, VersionedTransaction, VersionedMessage, MessageV0, AddressLookupTableAccount, TransactionInstruction } from "@solana/web3.js";
export const MAX_TX_BYTES = 1232;
/** execute ix data: u8 op=2 | u8 n_ixs | for each: u8 program_idx | u8 n_accts | n_accts×(u8 acct_idx | u8 flags) | u16 data_len | data
 *  Indices refer to the OUTER compiled message account list, so wrapping adds only ~ (4 + 2·accts + data) bytes per instruction. */
export function wrapForExecute(msg: VersionedMessage, wardenProgram: PublicKey, account: PublicKey, sessionKey: PublicKey, luts: AddressLookupTableAccount[] = []) {
  const decompiled = TransactionMessage.decompile(msg, { addressLookupTableAccounts: luts });
  const inner: TransactionInstruction[] = decompiled.instructions;
  // Build the outer instruction: warden execute, with every inner account as a remaining account (dedup), PDA as non-signer.
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
  const idx = (p: PublicKey) => order.findIndex(m => m.pubkey.equals(p));
  const parts: number[] = [2, inner.length];
  for (const ix of inner) {
    parts.push(idx(ix.programId), ix.keys.length);
    for (const k of ix.keys) parts.push(idx(k.pubkey), (k.isSigner ? 1 : 0) | (k.isWritable ? 2 : 0));
    parts.push(ix.data.length & 0xff, ix.data.length >> 8, ...ix.data);
  }
  const outer = new TransactionInstruction({ programId: wardenProgram, keys: [{ pubkey: account, isSigner: false, isWritable: true }, { pubkey: sessionKey, isSigner: true, isWritable: true }, ...order], data: Buffer.from(parts) });
  const compiled = new TransactionMessage({ payerKey: sessionKey, recentBlockhash: decompiled.recentBlockhash, instructions: [outer] }).compileToV0Message(luts);
  const tx = new VersionedTransaction(compiled);
  const bytesInline = tx.serialize().length + 64 * 0; // signatures already counted by serialize (1 sig placeholder)
  const bytesOriginal = new VersionedTransaction(msg).serialize().length;
  const inline = bytesInline <= MAX_TX_BYTES ? tx : null;
  const stagedChunks = inline ? 0 : Math.ceil(Buffer.from(parts).length / 900); // ~900 B payload per stage_chunk tx
  return { inline, stagedChunks, bytesInline, bytesOriginal };
}
