//! Browser-only C23 MAIN-world request fixture. Never copied into the product build.

import {
  ComputeBudgetProgram,
  PublicKey,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";

import { ProviderPageRequestOwner } from "../src/page/provider-request-owner.js";

const WARDEN_PROGRAM = new PublicKey(
  "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2",
);
const MEMO_PROGRAM = new PublicKey(
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
);
const OWNER_SEED = new Uint8Array(32).fill(0x11);
const [SMART_ACCOUNT] = PublicKey.findProgramAddressSync(
  [new TextEncoder().encode("account"), OWNER_SEED],
  WARDEN_PROGRAM,
);
const SOURCE_BLOCKHASH = new PublicKey(new Uint8Array(32).fill(0x77)).toBase58();
const MEMO = "C23 exact-byte browser success";

const sourceMessage = new TransactionMessage({
  payerKey: SMART_ACCOUNT,
  recentBlockhash: SOURCE_BLOCKHASH,
  instructions: [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
    ComputeBudgetProgram.requestHeapFrame({ bytes: 128 * 1_024 }),
    new TransactionInstruction({
      programId: MEMO_PROGRAM,
      keys: [],
      data: new TextEncoder().encode(MEMO) as TransactionInstruction["data"],
    }),
  ],
}).compileToV0Message();
const sourceTransaction = new VersionedTransaction(sourceMessage).serialize();
const owner = new ProviderPageRequestOwner(window);

function observation(
  state: "pending" | "signed" | "failed",
  signedTransaction: Uint8Array | null,
  error: string | null,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    state,
    sourceTransaction: [...sourceTransaction],
    signedTransaction: signedTransaction === null ? null : [...signedTransaction],
    error,
    pendingCount: owner.pendingCount,
    href: location.href,
    navigationEntries: performance.getEntriesByType("navigation").length,
  });
}

Object.assign(globalThis, {
  __wardenPageSignStatus: observation("pending", null, null),
});

void owner.signTransaction({
  accountAddress: SMART_ACCOUNT.toBase58(),
  transaction: sourceTransaction,
  chain: "solana:devnet",
  options: {
    preflightCommitment: "confirmed",
    minContextSlot: 0,
  },
}).then(
  (signedTransaction) => {
    Object.assign(globalThis, {
      __wardenPageSignStatus: observation("signed", signedTransaction, null),
    });
  },
  (error: unknown) => {
    Object.assign(globalThis, {
      __wardenPageSignStatus: observation(
        "failed",
        null,
        error instanceof Error ? `${error.name}: ${error.message}` : String(error),
      ),
    });
  },
);
