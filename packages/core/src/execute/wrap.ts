//! `wrapForExecute` — turn a dApp's compiled transaction into the accounts,
//! payload bytes and `accountsHash` warden's `execute` needs. The productionised
//! port of `spikes/03-txbudget/ts/wrap.ts`, adapted to the Task-5 ABI: the
//! payload has NO op-prefix (the op is the Anchor discriminator on the outer
//! instruction), and the LOGICAL account list is
//! `[smart_account, signer] ++ remaining_accounts` — the named optionals
//! (`session` / `ix_sysvar` / `stage` / `registry` / `stage_creator`) are
//! physical accounts of the outer instruction but are NOT in the logical list,
//! so the payload indices and the `accountsHash` are identical no matter which
//! optionals are present (the decompile-parity property).
//!
//! ## Instruction-local (logical) indices — the load-bearing contract
//!
//! `compileToV0Message` may dedupe and globally re-sort the message's account
//! keys, but for EACH instruction it records where that instruction's OWN keys
//! landed, preserving the instruction's key ORDER. The runtime hands a program
//! its instruction's account slice in that original order — so a payload index
//! `j` naming `logical[j]` is stable across compilation with no post-compile
//! lookup. `wrapForExecute` still compiles-then-decompiles and asserts the outer
//! instruction's resolved keys equal the logical list, to guard the contract.

import { PublicKey } from "@solana/web3.js";
import type {
  AddressLookupTableAccount,
  TransactionInstruction,
  VersionedMessage,
} from "@solana/web3.js";
import {
  ComputeBudgetProgram,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import {
  encodeExecutePayload,
  computeAccountsHash,
  FLAG_SIGNER,
  FLAG_WRITABLE,
  type ExecutePayload,
  type LogicalAccount,
} from "./payload.js";
import { MAX_EXECUTE_ACCOUNTS_TOTAL, MAX_EXECUTE_WRITABLE } from "../constants.js";

/** The default compute-unit limit the wrapper injects when the dApp tx carries
 *  no ComputeBudget instruction of its own (spec §5.2). */
export const DEFAULT_COMPUTE_UNIT_LIMIT = 600_000;

/** ComputeBudget instruction discriminators (data[0]), for tag-wise
 *  normalization — a dApp may supply any subset and the wrapper must satisfy
 *  each budget dimension independently, never treat one tag as covering all. */
const CB_REQUEST_HEAP_FRAME = 1;
const CB_SET_COMPUTE_UNIT_LIMIT = 2;

/** `execute`'s account caps are HEAP-bound (PHASE1B-MEASUREMENTS §"Task 5"/
 *  §"Task 6 heap lift"): the handler snapshots the WHOLE logical list twice, so
 *  the default 32 KiB SBF heap OOMs (fail-closed) at ~24 accounts. The custom
 *  allocator (`src/heap.rs`) makes a top-level `RequestHeapFrame` effective; the
 *  client contract is that the wrapper injects one sized for any large shape,
 *  the same way it injects the CU limit. Omitting it is a fail-closed revert,
 *  not a loss — but the SDK must not hand back a transaction that reverts. */
export const HEAP_FRAME_BYTES = 128 * 1024;
/** Inject the heap frame once `remaining_accounts` reaches this count. The
 *  measured safe point on the default heap is 25 remaining (83.8k CU); 27
 *  OOMs. 22 keeps a conservative margin, and a 128 KiB frame is measured to
 *  carry the full 33-remaining / 30-writable shape at 113k CU. */
export const HEAP_FRAME_TRIGGER_REMAINING = 22;

export interface WrapOptions {
  wardenProgram: PublicKey;
  /** The SmartAccount PDA — logical[0], forced non-signer (it signs via
   *  invoke_signed), writable. */
  smartAccount: PublicKey;
  /** The session/root signer — logical[1], signer. Read-only UNLESS it is also
   *  the outer transaction's fee payer (the common self-submit case), in which
   *  case the runtime promotes it to writable and the handler hashes it that
   *  way — see `payer`. */
  signer: PublicKey;
  /** The outer transaction's fee payer. Defaults to `signer` (self-submit). The
   *  runtime always coalesces the fee payer to signer+writable, and the handler
   *  hashes the logical list from those RUNTIME flags (execute.rs:317). So the
   *  SDK MUST hash whichever logical account is the payer as writable, or a root
   *  ceremony signed over this hash fails ChallengeMismatch (WRDF-0071/0055).
   *  A separate relayer that is NOT in the logical list leaves logical[1]
   *  read-only — pass that relayer here and build the outer tx with the same
   *  `payerKey`. */
  payer?: PublicKey;
  /** Address lookup tables to resolve the dApp message and to compile with. */
  luts?: AddressLookupTableAccount[];
  /** Compute-unit limit to inject when the dApp tx has none. */
  defaultComputeUnitLimit?: number;
}

export interface WrapResult {
  /** The `ExecutePayload` bytes (no op-prefix) — the `execute` instruction's
   *  args payload. */
  payload: Uint8Array;
  /** The decoded payload (for inspection / staging). */
  decoded: ExecutePayload;
  /** The logical account list `[smart_account, signer] ++ remaining`, in logical
   *  order — what `accountsHash` and the payload indices refer to. */
  logical: LogicalAccount[];
  /** The `remaining_accounts` (logical[2..]) as web3 account metas, to append
   *  after the named accounts when building the outer instruction. */
  remaining: Array<{ pubkey: PublicKey; isSigner: boolean; isWritable: boolean }>;
  /** `Keccak256` over the logical list — what the root `ExecuteBody` binds. */
  accountsHash: Uint8Array;
  /** ComputeBudget instructions to place TOP-LEVEL in the outer transaction
   *  (never inside the payload), normalized per budget dimension: the dApp's own
   *  settings preserved, a `SetComputeUnitLimit` guaranteed (default injected if
   *  absent), and an adequate `RequestHeapFrame` injected for large shapes. */
  computeBudgetIxs: TransactionInstruction[];
}

const b58 = (p: PublicKey): string => p.toBase58();

/**
 * Wrap a dApp's compiled message for `execute`. Decompiles it, hoists any
 * ComputeBudget instructions top-level (adding a default limit if none),
 * dedupes the touched accounts into the logical `remaining` list (PDA forced
 * non-signer), encodes the payload with logical indices, and computes the
 * `accountsHash`.
 */
export function wrapForExecute(dappMsg: VersionedMessage, opts: WrapOptions): WrapResult {
  const luts = opts.luts ?? [];
  const payer = opts.payer ?? opts.signer;
  const decompiled = TransactionMessage.decompile(dappMsg, { addressLookupTableAccounts: luts });
  const allInner = decompiled.instructions;

  // ComputeBudget instructions are honored only top-level, never inside a CPI —
  // hoist any the dApp carries; the rest are the inner instructions we wrap.
  const cbId = ComputeBudgetProgram.programId;
  const dappComputeBudgetIxs = allInner.filter((ix) => ix.programId.equals(cbId));
  const inner = allInner.filter((ix) => !ix.programId.equals(cbId));

  // Fail-closed on shapes the ABI cannot honor, rather than silently rewriting
  // them into something that means something else (WRDF-0074/0073):
  //   * A third-party SIGNER — the program propagates a signer only for logical
  //     slots 0/1 (the PDA and the root/session signer). Zeroing the bit so the
  //     parser accepts it would hand the invoked program a non-signer where the
  //     dApp required a signer — different, silent semantics. Reject.
  //   * The SmartAccount PDA passed WRITABLE — the only sanctioned writable-PDA
  //     shape is a deny-validated CloseAccount, a warden-native sweep built by a
  //     dedicated helper, never carried in a wrapped foreign dApp message.
  //     Silently clearing the bit would likewise change the CPI's semantics.
  for (const ix of inner) {
    for (const k of ix.keys) {
      if (k.isSigner && !k.pubkey.equals(opts.smartAccount) && !k.pubkey.equals(opts.signer)) {
        throw new Error(
          `wrapForExecute: inner instruction requires a third-party signer ${b58(k.pubkey)}; ` +
            "the execute ABI propagates a signer only for the PDA and the root/session signer",
        );
      }
      if (k.pubkey.equals(opts.smartAccount) && k.isWritable) {
        throw new Error(
          "wrapForExecute: a wrapped instruction names the SmartAccount PDA writable; " +
            "the only permitted writable-PDA shape is a deny-validated CloseAccount, built by a dedicated helper",
        );
      }
    }
  }

  // Dedup every account the inner instructions touch (their program ids too).
  // The PDA is forced non-signer (invoke_signed authorizes it). Both
  // `smart_account` and `signer`, if a dApp ix references them, are EXCLUDED
  // from `remaining` (they already have fixed logical slots 0/1) — keeping them
  // would shift every later index by one and corrupt the logical index space.
  const metas = new Map<string, { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }>();
  for (const ix of inner) {
    const pk = b58(ix.programId);
    if (!metas.has(pk)) metas.set(pk, { pubkey: ix.programId, isSigner: false, isWritable: false });
    for (const k of ix.keys) {
      const cur = metas.get(b58(k.pubkey));
      // No non-privileged signer survives the reject above, so remaining signer
      // flags are always false; the PDA is forced non-signer regardless.
      const isSigner = k.pubkey.equals(opts.smartAccount) ? false : (cur?.isSigner ?? false) || k.isSigner;
      metas.set(b58(k.pubkey), {
        pubkey: k.pubkey,
        isSigner,
        isWritable: (cur?.isWritable ?? false) || k.isWritable,
      });
    }
  }
  const remaining = [...metas.values()].filter(
    (m) => !m.pubkey.equals(opts.smartAccount) && !m.pubkey.equals(opts.signer),
  );

  // Client-side account caps (mirror the on-chain `TooManyExecuteAccounts` /
  // `TooManyExecuteWritable`), so an over-cap shape fails here with a clear
  // message instead of reverting on-chain.
  if (remaining.length > MAX_EXECUTE_ACCOUNTS_TOTAL) {
    throw new Error(
      `wrapForExecute: ${remaining.length} remaining accounts exceed MAX_EXECUTE_ACCOUNTS_TOTAL (${MAX_EXECUTE_ACCOUNTS_TOTAL})`,
    );
  }
  const writableRemaining = remaining.filter((m) => m.isWritable).length;
  if (writableRemaining > MAX_EXECUTE_WRITABLE) {
    throw new Error(
      `wrapForExecute: ${writableRemaining} writable remaining accounts exceed MAX_EXECUTE_WRITABLE (${MAX_EXECUTE_WRITABLE})`,
    );
  }

  // The logical list: fixed prefix + remaining. `accountsHash` and payload
  // indices are over THIS list, and the handler hashes it from the RUNTIME
  // AccountInfo flags — so the fee payer, which the runtime coalesces to
  // signer+writable, must be hashed that way here too (WRDF-0071). In the common
  // self-submit case payer === signer, so logical[1] is writable.
  const isPayer = (key: PublicKey): boolean => key.equals(payer);
  const logical: LogicalAccount[] = [
    { key: opts.smartAccount.toBytes(), isSigner: false, isWritable: true },
    { key: opts.signer.toBytes(), isSigner: true, isWritable: isPayer(opts.signer) },
    ...remaining.map((m) => ({
      key: m.pubkey.toBytes(),
      isSigner: m.isSigner || isPayer(m.pubkey),
      isWritable: m.isWritable || isPayer(m.pubkey),
    })),
  ];

  // Logical index of a pubkey (0 = smart_account, 1 = signer, 2+k = remaining).
  const logicalIndex = new Map<string, number>();
  logicalIndex.set(b58(opts.smartAccount), 0);
  logicalIndex.set(b58(opts.signer), 1);
  remaining.forEach((m, k) => logicalIndex.set(b58(m.pubkey), 2 + k));
  const idxOf = (p: PublicKey): number => {
    const i = logicalIndex.get(b58(p));
    if (i === undefined) throw new Error(`wrapForExecute: ${b58(p)} not in the logical list`);
    if (i > 0xff) throw new Error(`wrapForExecute: logical index ${i} exceeds u8 — too many accounts`);
    return i;
  };

  if (inner.length > 0xff) throw new Error(`wrapForExecute: ${inner.length} inner instructions exceed u8`);
  const decoded: ExecutePayload = {
    ixs: inner.map((ix) => ({
      programIndex: idxOf(ix.programId),
      // Third-party signers and a writable PDA were rejected above, so every
      // surviving flag maps straight through: a signer bit appears only on the
      // PDA/signer (both accepted by the parser), and the PDA is never writable.
      accounts: ix.keys.map((k) => ({
        index: idxOf(k.pubkey),
        flags: (k.isSigner ? FLAG_SIGNER : 0) | (k.isWritable ? FLAG_WRITABLE : 0),
      })),
      data: Uint8Array.from(ix.data),
    })),
  };
  const payload = encodeExecutePayload(decoded);
  const accountsHash = computeAccountsHash(logical);

  // Budget instructions, normalized so every dimension is satisfied
  // independently and a large shape gets its mandatory heap frame.
  const computeBudgetIxs = normalizeComputeBudget(dappComputeBudgetIxs, {
    remainingLen: remaining.length,
    defaultComputeUnitLimit: opts.defaultComputeUnitLimit ?? DEFAULT_COMPUTE_UNIT_LIMIT,
  });

  return { payload, decoded, logical, remaining, accountsHash, computeBudgetIxs };
}

/** Read the `u32 LE` byte count from a `RequestHeapFrame` instruction's data. */
function heapFrameBytes(ix: TransactionInstruction): number {
  const d = ix.data;
  if (d.length < 5) throw new Error("wrapForExecute: malformed RequestHeapFrame (data < 5 bytes)");
  return (d[1]! | (d[2]! << 8) | (d[3]! << 16) | (d[4]! << 24)) >>> 0;
}

/**
 * Normalize the dApp's hoisted ComputeBudget instructions so each budget
 * dimension is satisfied on its own (WRDF-0072). A dApp may supply any subset
 * (e.g. only a compute-unit PRICE), so the wrapper must NOT treat the presence
 * of one ComputeBudget instruction as covering the others:
 *  - preserve everything the dApp set (price, limit, data-size, heap);
 *  - ensure exactly one `SetComputeUnitLimit` (inject the default if absent);
 *  - ensure an adequate `RequestHeapFrame` for large shapes — `execute`'s caps
 *    are HEAP-bound and a shape past ~24 accounts OOMs (fail-closed) without one.
 * Duplicate limit/heap requests, or a dApp heap frame smaller than the shape
 * needs, are rejected rather than silently resolved.
 */
export function normalizeComputeBudget(
  dappCbIxs: TransactionInstruction[],
  opts: { remainingLen: number; defaultComputeUnitLimit: number },
): TransactionInstruction[] {
  const limits = dappCbIxs.filter((ix) => ix.data[0] === CB_SET_COMPUTE_UNIT_LIMIT);
  const frames = dappCbIxs.filter((ix) => ix.data[0] === CB_REQUEST_HEAP_FRAME);
  if (limits.length > 1) throw new Error("wrapForExecute: multiple SetComputeUnitLimit instructions");
  if (frames.length > 1) throw new Error("wrapForExecute: multiple RequestHeapFrame instructions");

  const out = [...dappCbIxs];
  if (limits.length === 0) {
    out.push(ComputeBudgetProgram.setComputeUnitLimit({ units: opts.defaultComputeUnitLimit }));
  }

  const needFrame = opts.remainingLen >= HEAP_FRAME_TRIGGER_REMAINING;
  if (needFrame) {
    if (frames.length === 0) {
      out.push(ComputeBudgetProgram.requestHeapFrame({ bytes: HEAP_FRAME_BYTES }));
    } else if (heapFrameBytes(frames[0]!) < HEAP_FRAME_BYTES) {
      throw new Error(
        `wrapForExecute: dApp RequestHeapFrame (${heapFrameBytes(frames[0]!)} B) is smaller than this shape needs (${HEAP_FRAME_BYTES} B)`,
      );
    }
  }
  return out;
}

/**
 * Assemble the outer `execute` instruction's PHYSICAL account metas in the exact
 * order the handler's `#[derive(Accounts)]` expects:
 * `[smart_account, signer, session?, ix_sysvar?, stage?, registry?,
 * stage_creator?, ...remaining]`. Omitted optionals are Anchor's program-id
 * sentinel. The logical list (and `accountsHash`) is INDEPENDENT of which
 * optionals are present — that is the decompile-parity property this order
 * preserves.
 */
export function buildExecuteAccountMetas(params: {
  wardenProgram: PublicKey;
  smartAccount: PublicKey;
  signer: PublicKey;
  session?: PublicKey;
  ixSysvar?: PublicKey;
  stage?: PublicKey;
  registry?: PublicKey;
  stageCreator?: PublicKey;
  remaining: Array<{ pubkey: PublicKey; isSigner: boolean; isWritable: boolean }>;
}): Array<{ pubkey: PublicKey; isSigner: boolean; isWritable: boolean }> {
  const sentinel = params.wardenProgram;
  const opt = (p: PublicKey | undefined, isWritable: boolean) =>
    p ? { pubkey: p, isSigner: false, isWritable } : { pubkey: sentinel, isSigner: false, isWritable: false };
  return [
    { pubkey: params.smartAccount, isSigner: false, isWritable: true },
    { pubkey: params.signer, isSigner: true, isWritable: false },
    opt(params.session, true),
    opt(params.ixSysvar, false),
    opt(params.stage, true),
    opt(params.registry, false),
    opt(params.stageCreator, true),
    ...params.remaining,
  ];
}

/** Serialized byte length of a v0 transaction carrying `ixs`, for size checks. */
export function v0TxBytes(
  payerKey: PublicKey,
  recentBlockhash: string,
  ixs: TransactionInstruction[],
  luts: AddressLookupTableAccount[] = [],
): number {
  const msg = new TransactionMessage({ payerKey, recentBlockhash, instructions: ixs }).compileToV0Message(luts);
  return new VersionedTransaction(msg).serialize().length;
}
