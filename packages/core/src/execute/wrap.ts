//! `wrapForExecute` — turn a dApp's compiled transaction into the accounts,
//! payload bytes and `accountsHash` warden's `execute` needs. The productionised
//! port of `spikes/03-txbudget/ts/wrap.ts`, adapted to the Task-5 ABI: the
//! payload has NO op-prefix (the op is the Anchor discriminator on the outer
//! instruction), and the LOGICAL account list is
//! `[smart_account, signer] ++ remaining_accounts` — the named optionals
//! (`session` / `ix_sysvar` / `stage` / `registry` / `stage_creator`) are
//! physical accounts of the outer instruction but are NOT in the logical list.
//!
//! ## One source of truth: the compiled outer instruction (WRDF-0071/0077)
//!
//! The handler hashes the logical list from the **runtime** `AccountInfo` flags
//! (`execute.rs:317`), and Solana's message compilation coalesces every account's
//! privileges across the WHOLE transaction: the fee payer is promoted to
//! signer+writable, and a key that appears in two positions (e.g. the `signer`
//! also passed as a writable `stage_creator`) is writable everywhere. Any SDK
//! that hashes a hand-reconstructed list — with the raw dApp flags, or guessing
//! the coalescing — drifts from what the handler will hash and fails
//! `ChallengeMismatch`. So `wrapForExecute` builds the COMPLETE outer execute
//! instruction (named optionals + the real fee payer + remaining), compiles it,
//! decompiles it, and derives BOTH the `accountsHash` and the account caps from
//! the effective (coalesced) instruction metas. There is exactly one place the
//! logical privileges are computed, and it is the compiler the caller will use.
//!
//! ## Instruction-local (logical) indices — the load-bearing contract
//!
//! `compileToV0Message` may dedupe and globally re-sort the message's account
//! keys, but for EACH instruction it records where that instruction's OWN keys
//! landed, preserving the instruction's key ORDER. So a payload index `j` naming
//! `logical[j]` is stable across compilation, and the effective metas come back
//! in the same order they were built.

import { PublicKey } from "@solana/web3.js";
import type {
  AddressLookupTableAccount,
  VersionedMessage,
} from "@solana/web3.js";
import {
  ComputeBudgetProgram,
  TransactionInstruction,
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
 *  no `SetComputeUnitLimit` of its own (spec §5.2). */
export const DEFAULT_COMPUTE_UNIT_LIMIT = 600_000;
/** The floor a compute-unit limit must clear. MEASURED: the execute handler
 *  alone worst-cases at ~113k CU (PHASE1B-MEASUREMENTS §"Task 6 heap lift",
 *  30-writable), before ANY inner-CPI cost — so a limit below this cannot
 *  complete regardless of the wrapped work (WRDF-0076). Per-shape sizing that
 *  also accounts for inner-CPI cost is the caller's job (via simulation); the
 *  wrapper enforces only this hard, shape-independent floor. */
export const MIN_COMPUTE_UNIT_LIMIT = 120_000;
/** Solana's hard ceiling for `SetComputeUnitLimit`. */
export const MAX_COMPUTE_UNIT_LIMIT = 1_400_000;

/** ComputeBudget instruction discriminators (data[0]). */
const CB_REQUEST_HEAP_FRAME = 1;
const CB_SET_COMPUTE_UNIT_LIMIT = 2;

/** The measured-safe heap-frame floor: 128 KiB carries the largest measured
 *  execute shape (33-remaining / 30-writable) at 113k CU. A frame is ALWAYS
 *  requested for execute (WRDF-0072) — the heap is driven by inner-instruction
 *  count, not account count, and a bump allocator that never frees, so account
 *  count alone is not a safe trigger. */
export const HEAP_FRAME_FLOOR_BYTES = 128 * 1024;
/** Solana's hard ceiling for `RequestHeapFrame`. */
export const HEAP_FRAME_MAX_BYTES = 256 * 1024;
/** Agave's minimum for `RequestHeapFrame` (the default frame). A requested heap
 *  size is accepted by the runtime only when `MIN ≤ bytes ≤ MAX` AND it is a
 *  multiple of 1024 (solana-compute-budget-instruction). A caller-supplied frame
 *  the wrapper preserves must clear the same rules or the runtime rejects the
 *  whole transaction before execute runs (WRDF-0080). */
export const MIN_HEAP_FRAME_BYTES = 32 * 1024;
/** `RequestHeapFrame` byte counts must be a multiple of this. */
const HEAP_FRAME_ALIGN = 1024;

/** A placeholder blockhash for the INTERNAL privilege-resolution compile only —
 *  32 zero bytes. Privilege coalescing is independent of the blockhash, so the
 *  caller re-compiles the final transaction with a real one, reusing the
 *  returned `executeAccountMetas` verbatim. */
const DUMMY_BLOCKHASH = "11111111111111111111111111111111";

export interface AccountMetaLite {
  pubkey: PublicKey;
  isSigner: boolean;
  isWritable: boolean;
}

export interface WrapOptions {
  wardenProgram: PublicKey;
  /** The SmartAccount PDA — logical[0], forced non-signer (it signs via
   *  invoke_signed), writable. */
  smartAccount: PublicKey;
  /** The session/root signer — logical[1], signer. Writable iff it is also the
   *  fee payer or aliases a writable named optional (the compiler decides; the
   *  wrapper reads the result, it does not guess). */
  signer: PublicKey;
  /** The outer transaction's fee payer. Defaults to `signer` (self-submit). A
   *  separate relayer that is not otherwise in the logical list leaves logical[1]
   *  read-only — pass that relayer here AND build the final tx with the same
   *  `payerKey`. */
  payer?: PublicKey;
  // ---- named optionals of the outer execute instruction (physical 2..6) ----
  /** Session path: the session key account. */
  session?: PublicKey;
  /** Root path: the Instructions sysvar. */
  ixSysvar?: PublicKey;
  /** Staged path: the Stage account. */
  stage?: PublicKey;
  /** Session path: the account's adapter Registry. */
  registry?: PublicKey;
  /** Staged path: the stage's recorded creator (rent-refund destination). */
  stageCreator?: PublicKey;
  /** Address lookup tables to resolve the dApp message with. */
  luts?: AddressLookupTableAccount[];
  /** Compute-unit limit to inject when the dApp tx has none. */
  defaultComputeUnitLimit?: number;
}

export interface WrapResult {
  /** The `ExecutePayload` bytes (no op-prefix) — the `execute` args payload. */
  payload: Uint8Array;
  /** The decoded payload (for inspection / staging). */
  decoded: ExecutePayload;
  /** The logical account list `[smart_account, signer] ++ remaining`, in logical
   *  order, with the EFFECTIVE (post-compile) privilege flags — what
   *  `accountsHash` and the payload indices refer to. */
  logical: LogicalAccount[];
  /** The `remaining_accounts` (logical[2..]) as effective metas. */
  remaining: AccountMetaLite[];
  /** The COMPLETE outer `execute` instruction account metas (physical order
   *  `[smart_account, signer, session?, …, ...remaining]`, omitted optionals as
   *  the program-id sentinel), with effective flags. Build the final transaction
   *  with THESE and the same fee payer — they are the list `accountsHash` binds. */
  executeAccountMetas: AccountMetaLite[];
  /** `Keccak256` over the logical list — what the root `ExecuteBody` binds. */
  accountsHash: Uint8Array;
  /** ComputeBudget instructions to place TOP-LEVEL in the outer transaction
   *  (never inside the payload), normalized per budget dimension: the dApp's own
   *  settings preserved, a validated `SetComputeUnitLimit` guaranteed, and a
   *  sized `RequestHeapFrame` always present. */
  computeBudgetIxs: TransactionInstruction[];
}

const b58 = (p: PublicKey): string => p.toBase58();

/**
 * Wrap a dApp's compiled message for `execute`. Decompiles it, hoists and
 * normalizes ComputeBudget top-level, dedupes the touched accounts into the
 * logical `remaining` list (rejecting shapes the ABI cannot honor), builds the
 * complete outer execute instruction, compiles+decompiles it to obtain the
 * runtime-coalesced privileges, and derives the `accountsHash` and account caps
 * from those effective metas.
 */
export function wrapForExecute(dappMsg: VersionedMessage, opts: WrapOptions): WrapResult {
  const luts = opts.luts ?? [];
  const payer = opts.payer ?? opts.signer;
  const decompiled = TransactionMessage.decompile(dappMsg, { addressLookupTableAccounts: luts });
  const allInner = decompiled.instructions;

  const cbId = ComputeBudgetProgram.programId;
  const dappComputeBudgetIxs = allInner.filter((ix) => ix.programId.equals(cbId));
  const inner = allInner.filter((ix) => !ix.programId.equals(cbId));

  // Fail-closed on shapes the ABI cannot honor, rather than silently rewriting
  // them into something that means something else (WRDF-0074/0073):
  //   * a third-party SIGNER — the program propagates a signer only for logical
  //     slots 0/1 (the PDA and the root/session signer);
  //   * the SmartAccount PDA passed WRITABLE — the only sanctioned writable-PDA
  //     shape is a deny-validated CloseAccount, which the general foreign-dApp
  //     wrapper does not build (a writable idx-0 is expressible through the raw
  //     `encodeExecutePayload` codec; a typed vault-sweep builder is a deferred
  //     client deliverable, WRDF-0078).
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
            "the only permitted writable-PDA shape is a deny-validated CloseAccount, not a wrapped foreign instruction",
        );
      }
      // The root/session signer is logical[1] and is granted READ-ONLY in the
      // outer instruction (`buildExecuteAccountMetas` slot 1). It is the
      // authorizer, not a vault funding source — a wrapped instruction that
      // needs it writable is not a supported execute shape, and its payload
      // would request a privilege the outer AccountInfo does not hold, so the
      // CPI would fail. Reject it fail-closed rather than emit that mismatch
      // (WRDF-0079), symmetric with the third-party-signer and writable-PDA rules.
      if (k.pubkey.equals(opts.signer) && k.isWritable) {
        throw new Error(
          "wrapForExecute: a wrapped instruction names the root/session signer writable; " +
            "the signer is logical[1] and read-only in execute — a writable-signer shape is unsupported",
        );
      }
    }
  }

  // Dedup every account the inner instructions touch (their program ids too).
  // The PDA is forced non-signer. Both `smart_account` and `signer`, if a dApp
  // ix references them, are EXCLUDED from `remaining` (fixed logical slots 0/1).
  const metas = new Map<string, AccountMetaLite>();
  for (const ix of inner) {
    const pk = b58(ix.programId);
    if (!metas.has(pk)) metas.set(pk, { pubkey: ix.programId, isSigner: false, isWritable: false });
    for (const k of ix.keys) {
      const cur = metas.get(b58(k.pubkey));
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

  // Logical index of a pubkey (0 = smart_account, 1 = signer, 2+k = remaining).
  // Fixed by construction and stable across compilation.
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

  // The payload: logical indices + the inner instruction's own requested flags
  // (what the CPI needs). Third-party signers and a writable PDA were rejected
  // above, so every surviving flag maps straight through and the parser accepts it.
  if (inner.length > 0xff) throw new Error(`wrapForExecute: ${inner.length} inner instructions exceed u8`);
  const decoded: ExecutePayload = {
    ixs: inner.map((ix) => ({
      programIndex: idxOf(ix.programId),
      accounts: ix.keys.map((k) => ({
        index: idxOf(k.pubkey),
        flags: (k.isSigner ? FLAG_SIGNER : 0) | (k.isWritable ? FLAG_WRITABLE : 0),
      })),
      data: Uint8Array.from(ix.data),
    })),
  };
  const payload = encodeExecutePayload(decoded);

  // Normalize the budget instructions, sizing the heap frame from the actual
  // heap drivers (inner-instruction count, account references, payload bytes).
  const totalAcctRefs = inner.reduce((n, ix) => n + ix.keys.length, 0);
  const computeBudgetIxs = normalizeComputeBudget(dappComputeBudgetIxs, {
    remainingLen: remaining.length,
    innerIxCount: inner.length,
    totalAcctRefs,
    payloadLen: payload.length,
    defaultComputeUnitLimit: opts.defaultComputeUnitLimit ?? DEFAULT_COMPUTE_UNIT_LIMIT,
  });

  // Build the complete outer execute instruction and resolve its EFFECTIVE
  // privileges through the compiler (the one source of truth).
  const builtMetas = buildExecuteAccountMetas({
    wardenProgram: opts.wardenProgram,
    smartAccount: opts.smartAccount,
    signer: opts.signer,
    session: opts.session,
    ixSysvar: opts.ixSysvar,
    stage: opts.stage,
    registry: opts.registry,
    stageCreator: opts.stageCreator,
    remaining,
  });
  const effectiveMetas = resolveEffectivePrivileges(opts.wardenProgram, payer, computeBudgetIxs, builtMetas);

  // Effective logical list = physical [0], [1], and [7..] (the 5 named optionals
  // at [2..6] are NOT in the logical list). Everything the handler hashes.
  const NAMED = 7;
  const effRemaining = effectiveMetas.slice(NAMED);
  const logicalMetas: AccountMetaLite[] = [effectiveMetas[0]!, effectiveMetas[1]!, ...effRemaining];
  const logical: LogicalAccount[] = logicalMetas.map((m) => ({
    key: m.pubkey.toBytes(),
    isSigner: m.isSigner,
    isWritable: m.isWritable,
  }));
  const accountsHash = computeAccountsHash(logical);

  // Privilege-subset guard (WRDF-0079): every privilege a payload reference
  // requests MUST be granted by the effective outer logical meta, or the CPI
  // fails at runtime. The rejects above and the writability OR-ed into remaining
  // make this hold by construction; assert it so any future regression is caught
  // here, at the client, rather than as an opaque on-chain revert.
  for (const ix of decoded.ixs) {
    for (const a of ix.accounts) {
      const m = logical[a.index]!;
      if ((a.flags & FLAG_WRITABLE) !== 0 && !m.isWritable) {
        throw new Error(`wrapForExecute: payload writes logical[${a.index}] but the outer meta is read-only`);
      }
      // logical[0] (the PDA) signs via invoke_signed, not via an outer-tx
      // signature, so its outer meta is correctly non-signer — exempt it.
      if ((a.flags & FLAG_SIGNER) !== 0 && a.index !== 0 && !m.isSigner) {
        throw new Error(`wrapForExecute: payload signs logical[${a.index}] but the outer meta is not a signer`);
      }
    }
  }

  // Account caps, counted from the EFFECTIVE (post-coalescing) remaining metas —
  // a read-only remaining account chosen as the payer, or aliased to a writable
  // named optional, is writable at runtime and must count here (WRDF-0077).
  if (effRemaining.length > MAX_EXECUTE_ACCOUNTS_TOTAL) {
    throw new Error(
      `wrapForExecute: ${effRemaining.length} remaining accounts exceed MAX_EXECUTE_ACCOUNTS_TOTAL (${MAX_EXECUTE_ACCOUNTS_TOTAL})`,
    );
  }
  const writableRemaining = effRemaining.filter((m) => m.isWritable).length;
  if (writableRemaining > MAX_EXECUTE_WRITABLE) {
    throw new Error(
      `wrapForExecute: ${writableRemaining} writable remaining accounts exceed MAX_EXECUTE_WRITABLE (${MAX_EXECUTE_WRITABLE})`,
    );
  }

  return {
    payload,
    decoded,
    logical,
    remaining: effRemaining,
    executeAccountMetas: effectiveMetas,
    accountsHash,
    computeBudgetIxs,
  };
}

/**
 * Compile the outer transaction (`[...computeBudgetIxs, executeIx]`) with the
 * real fee payer and decompile it, returning the execute instruction's account
 * metas with the runtime-coalesced privilege flags in build order. The compile
 * is privilege-resolution only (a placeholder blockhash, no LUTs — LUT membership
 * changes encoding, never signer/writable semantics), so the caller re-compiles
 * the sendable transaction with a real blockhash and these very metas.
 */
function resolveEffectivePrivileges(
  wardenProgram: PublicKey,
  payer: PublicKey,
  computeBudgetIxs: TransactionInstruction[],
  builtMetas: AccountMetaLite[],
): AccountMetaLite[] {
  const executeIx = new TransactionInstruction({
    programId: wardenProgram,
    keys: builtMetas.map((m) => ({ pubkey: m.pubkey, isSigner: m.isSigner, isWritable: m.isWritable })),
    data: Buffer.alloc(8), // discriminator placeholder; data does not affect coalescing
  });
  const msg = new TransactionMessage({
    payerKey: payer,
    recentBlockhash: DUMMY_BLOCKHASH,
    instructions: [...computeBudgetIxs, executeIx],
  }).compileToV0Message();
  const dec = TransactionMessage.decompile(msg);
  const eff = dec.instructions.find((ix) => ix.programId.equals(wardenProgram));
  if (!eff || eff.keys.length !== builtMetas.length) {
    throw new Error("wrapForExecute: internal privilege resolution lost the execute instruction");
  }
  // Order is preserved per-instruction; assert pubkey identity as a guard.
  return eff.keys.map((k, i) => {
    if (!k.pubkey.equals(builtMetas[i]!.pubkey)) {
      throw new Error(`wrapForExecute: effective meta ${i} pubkey drift`);
    }
    return { pubkey: k.pubkey, isSigner: k.isSigner, isWritable: k.isWritable };
  });
}

/** Strictly decode a `SetComputeUnitLimit` (tag 2 ‖ u32 LE, exactly 5 bytes). */
function decodeComputeUnitLimit(ix: TransactionInstruction): number {
  const d = ix.data;
  if (d.length !== 5) throw new Error(`wrapForExecute: malformed SetComputeUnitLimit (${d.length} bytes, expected 5)`);
  return (d[1]! | (d[2]! << 8) | (d[3]! << 16) | (d[4]! << 24)) >>> 0;
}

/** Read the `u32 LE` byte count from a `RequestHeapFrame` (tag 1 ‖ u32 LE). */
function decodeHeapFrameBytes(ix: TransactionInstruction): number {
  const d = ix.data;
  if (d.length !== 5) throw new Error(`wrapForExecute: malformed RequestHeapFrame (${d.length} bytes, expected 5)`);
  return (d[1]! | (d[2]! << 8) | (d[3]! << 16) | (d[4]! << 24)) >>> 0;
}

/** The heap frame this shape needs. The on-chain path holds two capacity-`n_ixs`
 *  Vecs (`parse_payload`, `resolve_payload`) plus two full logical snapshots, on
 *  a bump allocator that never frees — so the peak is driven by the INNER
 *  INSTRUCTION count (not the account count) and the payload size. Estimated with
 *  generous per-item sizes, doubled for the two coexisting copies, clamped to the
 *  measured-safe floor and Solana's ceiling. Always ≥ the floor: a frame is
 *  requested for every execute (WRDF-0072). */
function heapFrameFor(p: { remainingLen: number; innerIxCount: number; totalAcctRefs: number; payloadLen: number }): number {
  const est = 2 * (p.innerIxCount * 64 + p.totalAcctRefs * 48 + p.payloadLen) + 2 * (p.remainingLen + 2) * 96 + 16 * 1024;
  const rounded = Math.ceil(est / 1024) * 1024;
  return Math.min(HEAP_FRAME_MAX_BYTES, Math.max(HEAP_FRAME_FLOOR_BYTES, rounded));
}

/**
 * Normalize the dApp's hoisted ComputeBudget instructions so every budget
 * dimension is satisfied on its own (WRDF-0072/0076). A dApp may supply any
 * subset, so the wrapper must NOT treat one ComputeBudget instruction as covering
 * the others:
 *  - preserve everything the dApp set that we do not have to override (price,
 *    data-size);
 *  - decode and VALIDATE the `SetComputeUnitLimit`: reject a malformed one, a
 *    duplicate, or a value below the measured floor / above the ceiling; inject a
 *    validated default if the dApp supplied none;
 *  - ALWAYS attach a sized `RequestHeapFrame` (execute's heap is bump-allocated
 *    and driven by instruction count, so a large-shape OOM is fail-closed without
 *    one); reject a dApp frame that is malformed, duplicated, or too small.
 */
export function normalizeComputeBudget(
  dappCbIxs: TransactionInstruction[],
  opts: {
    remainingLen: number;
    innerIxCount: number;
    totalAcctRefs: number;
    payloadLen: number;
    defaultComputeUnitLimit: number;
  },
): TransactionInstruction[] {
  const limits = dappCbIxs.filter((ix) => ix.data[0] === CB_SET_COMPUTE_UNIT_LIMIT);
  const frames = dappCbIxs.filter((ix) => ix.data[0] === CB_REQUEST_HEAP_FRAME);
  if (limits.length > 1) throw new Error("wrapForExecute: multiple SetComputeUnitLimit instructions");
  if (frames.length > 1) throw new Error("wrapForExecute: multiple RequestHeapFrame instructions");

  const validateUnits = (units: number, src: string) => {
    if (units < MIN_COMPUTE_UNIT_LIMIT) {
      throw new Error(`wrapForExecute: ${src} compute-unit limit ${units} is below the floor ${MIN_COMPUTE_UNIT_LIMIT}`);
    }
    if (units > MAX_COMPUTE_UNIT_LIMIT) {
      throw new Error(`wrapForExecute: ${src} compute-unit limit ${units} exceeds the ceiling ${MAX_COMPUTE_UNIT_LIMIT}`);
    }
  };

  const passthrough = dappCbIxs.filter((ix) => ix.data[0] !== CB_REQUEST_HEAP_FRAME); // frames re-derived below
  const out: TransactionInstruction[] = [];
  for (const ix of passthrough) {
    if (ix.data[0] === CB_SET_COMPUTE_UNIT_LIMIT) validateUnits(decodeComputeUnitLimit(ix), "dApp");
    out.push(ix);
  }
  if (limits.length === 0) {
    validateUnits(opts.defaultComputeUnitLimit, "default");
    out.push(ComputeBudgetProgram.setComputeUnitLimit({ units: opts.defaultComputeUnitLimit }));
  }

  const needBytes = heapFrameFor(opts); // always a multiple of 1024 in [floor, max]
  if (frames.length === 0) {
    out.push(ComputeBudgetProgram.requestHeapFrame({ bytes: needBytes }));
  } else {
    // A caller-supplied frame is preserved ONLY if it clears every runtime rule
    // the on-chain ComputeBudget program enforces AND covers this shape — else
    // the runtime rejects the whole tx before execute (WRDF-0080).
    const have = decodeHeapFrameBytes(frames[0]!);
    if (have % HEAP_FRAME_ALIGN !== 0) {
      throw new Error(`wrapForExecute: dApp RequestHeapFrame (${have} B) is not a multiple of ${HEAP_FRAME_ALIGN}`);
    }
    if (have < MIN_HEAP_FRAME_BYTES || have > HEAP_FRAME_MAX_BYTES) {
      throw new Error(`wrapForExecute: dApp RequestHeapFrame (${have} B) is outside the runtime range [${MIN_HEAP_FRAME_BYTES}, ${HEAP_FRAME_MAX_BYTES}]`);
    }
    if (have < needBytes) {
      throw new Error(`wrapForExecute: dApp RequestHeapFrame (${have} B) is smaller than this shape needs (${needBytes} B)`);
    }
    out.push(frames[0]!); // valid, in-range, aligned, adequate — keep the dApp's own
  }
  return out;
}

/**
 * Assemble the outer `execute` instruction's PHYSICAL account metas in the exact
 * order the handler's `#[derive(Accounts)]` expects:
 * `[smart_account, signer, session?, ix_sysvar?, stage?, registry?,
 * stage_creator?, ...remaining]`. Omitted optionals are Anchor's program-id
 * sentinel. These are the metas BEFORE runtime privilege coalescing —
 * `wrapForExecute` compiles them to obtain the effective flags; callers who want
 * the coalesced, ready-to-send metas should use `WrapResult.executeAccountMetas`.
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
  remaining: AccountMetaLite[];
}): AccountMetaLite[] {
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
