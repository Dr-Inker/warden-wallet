//! Maintenance script — the SOLE writer of the cross-language golden fixtures
//! under `programs/warden/tests/fixtures/`. Run it deliberately when a fixture's
//! definition changes:
//!
//!   pnpm --filter @warden/core gen:fixtures
//!
//! The test suite NEVER writes these files; it reads them and asserts that
//! `wrapForExecute` / `encodeExecutePayload` reproduce them byte-for-byte against
//! independently-pinned expectations (WRDF-0081). The gate then runs
//! `git diff --exit-code` over the fixtures dir, so a wrapper regression that
//! would change the golden bytes fails CI instead of silently self-updating.
//!
//! All inputs are DETERMINISTIC (fixed byte patterns), so regeneration is
//! reproducible. Importing this module never writes (guarded on !VITEST); only
//! running it as a script does.

import { writeFileSync, mkdirSync } from "node:fs";
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

/** Write every golden fixture. */
export function generate(): void {
  mkdirSync(FIXTURES_DIR, { recursive: true });
  writeFileSync(resolve(FIXTURES_DIR, "payload_vector.bin"), encodeExecutePayload(PAYLOAD_VECTOR));
  writeFileSync(resolve(FIXTURES_DIR, "payload_accounts_hash.hex"), hex(computeAccountsHash(PAYLOAD_VECTOR_LOGICAL)));
  writeFileSync(resolve(FIXTURES_DIR, "payload_writable_pda_close.bin"), encodeExecutePayload(CLOSE_PAYLOAD));
  const r = coalescedWrap();
  writeFileSync(resolve(FIXTURES_DIR, "payload_coalesced_logical.bin"), serializeLogical(r.logical));
  writeFileSync(resolve(FIXTURES_DIR, "payload_coalesced_hash.hex"), hex(r.accountsHash));
  // eslint-disable-next-line no-console
  console.log(`wrote 5 fixtures to ${FIXTURES_DIR}`);
}

// Only WRITE when run as a script — never on import (e.g. from a test).
if (!process.env.VITEST) generate();
