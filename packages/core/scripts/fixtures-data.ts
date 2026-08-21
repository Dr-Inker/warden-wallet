//! DATA-ONLY definitions for the cross-language golden fixtures under
//! `programs/warden/tests/fixtures/`. This module imports NO `node:fs` and has NO
//! top-level side effect, so importing it CANNOT write to disk — the structural
//! close of WRDF-0081's "writer runs on import" footgun. It exposes the
//! deterministic inputs and `goldenContents()` (the exact bytes/hex each golden
//! must hold); the ONLY writer is the `gen-fixtures.ts` runner, which takes those
//! contents and an injectable write sink.
//!
//! The test suite READS the committed goldens and asserts `wrapForExecute` /
//! `encodeExecutePayload` reproduce them byte-for-byte against independently-
//! pinned literal expectations; the gate runs `git diff --exit-code` over the
//! fixtures dir, so a wrapper regression fails CI instead of self-updating.
//!
//! All inputs are DETERMINISTIC (fixed byte patterns), so regeneration is
//! reproducible. (`node:url`/`node:path` here compute a path STRING only — no fs.)

import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { PublicKey, TransactionInstruction, TransactionMessage } from "@solana/web3.js";
import {
  encodeExecutePayload,
  computeAccountsHash,
  wrapForExecute,
  FLAG_SIGNER,
  FLAG_WRITABLE,
  type ExecutePayload,
  type LogicalAccount,
} from "../src/index.js";

export const FIXTURES_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../../programs/warden/tests/fixtures");
const BLOCKHASH = "11111111111111111111111111111111";
const fill = (n: number, b: number): Uint8Array => new Uint8Array(n).fill(b);
const fixedKey = (b: number): PublicKey => new PublicKey(new Uint8Array(32).fill(b));
export const hex = (b: Uint8Array): string => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");

/** Serialize a logical list as the handler hashes it: pubkey ‖ is_signer ‖ is_writable. */
export function serializeLogical(logical: LogicalAccount[]): Uint8Array {
  const buf = new Uint8Array(logical.length * 34);
  let o = 0;
  for (const a of logical) {
    buf.set(a.key, o); o += 32;
    buf[o++] = a.isSigner ? 1 : 0;
    buf[o++] = a.isWritable ? 1 : 0;
  }
  return buf;
}

// --- payload_vector: a 2-instruction payload + a deterministic 6-account list ---
export const PAYLOAD_VECTOR: ExecutePayload = {
  ixs: [
    {
      programIndex: 4,
      accounts: [
        { index: 2, flags: FLAG_WRITABLE },
        { index: 3, flags: FLAG_WRITABLE },
        { index: 0, flags: FLAG_SIGNER },
        { index: 4, flags: 0 },
      ],
      data: Uint8Array.from([3, 0xd0, 0x07, 0, 0, 0, 0, 0, 0]), // SPL Transfer, amount 2000
    },
    { programIndex: 5, accounts: [{ index: 1, flags: FLAG_SIGNER }], data: Uint8Array.from([]) },
  ],
};
export const PAYLOAD_VECTOR_LOGICAL: LogicalAccount[] = Array.from({ length: 6 }, (_, i) => ({
  key: fill(32, 0x10 + i),
  isSigner: i === 0 || i === 1,
  isWritable: i === 0 ? false : i >= 2 && i <= 3,
}));

// --- payload_writable_pda_close: the sanctioned writable-PDA CloseAccount ---
export const CLOSE_PAYLOAD: ExecutePayload = {
  ixs: [
    {
      programIndex: 3,
      accounts: [
        { index: 2, flags: FLAG_WRITABLE },
        { index: 0, flags: FLAG_WRITABLE }, // rent destination = PDA
        { index: 0, flags: FLAG_SIGNER }, // owner = PDA
      ],
      data: Uint8Array.from([9]),
    },
  ],
};

// --- payload_coalesced_logical: wrapForExecute output for a payer==signer shape ---
export const WARDEN_PROGRAM = new PublicKey("6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2");
export const COALESCED_SMART = fixedKey(0x11);
export const COALESCED_SIGNER = fixedKey(0x22); // also the default payer
const COALESCED_PROG = fixedKey(0x33);
const COALESCED_ACCT = fixedKey(0x44);
/** The deterministic wrap result the coalesced-hash oracle pins. */
export function coalescedWrap() {
  const dIx = new TransactionInstruction({
    programId: COALESCED_PROG,
    keys: [
      { pubkey: COALESCED_ACCT, isSigner: false, isWritable: true },
      { pubkey: COALESCED_SMART, isSigner: true, isWritable: false }, // PDA authority-signer
    ],
    data: Buffer.from([7, 7]),
  });
  const dMsg = new TransactionMessage({ payerKey: COALESCED_SIGNER, recentBlockhash: BLOCKHASH, instructions: [dIx] }).compileToV0Message();
  return wrapForExecute(dMsg, { wardenProgram: WARDEN_PROGRAM, smartAccount: COALESCED_SMART, signer: COALESCED_SIGNER });
}

/** The exact content every golden fixture must hold, keyed by file name. A pure
 *  function of the deterministic inputs — no filesystem access. The `gen-fixtures`
 *  runner writes these; the tests read the committed files and compare against them. */
export function goldenContents(): Record<string, Uint8Array | string> {
  const r = coalescedWrap();
  return {
    "payload_vector.bin": encodeExecutePayload(PAYLOAD_VECTOR),
    "payload_accounts_hash.hex": hex(computeAccountsHash(PAYLOAD_VECTOR_LOGICAL)),
    "payload_writable_pda_close.bin": encodeExecutePayload(CLOSE_PAYLOAD),
    "payload_coalesced_logical.bin": serializeLogical(r.logical),
    "payload_coalesced_hash.hex": hex(r.accountsHash),
  };
}
// NO top-level side effects and NO `node:fs` import: importing this module cannot
// write. The `gen-fixtures.ts` runner is the sole writer.
