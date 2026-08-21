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

/** The default compute-unit limit the wrapper injects when the dApp tx carries
 *  no ComputeBudget instruction of its own (spec §5.2). */
export const DEFAULT_COMPUTE_UNIT_LIMIT = 600_000;

export interface WrapOptions {
  wardenProgram: PublicKey;
  /** The SmartAccount PDA — logical[0], forced non-signer (it signs via
   *  invoke_signed), writable. */
  smartAccount: PublicKey;
  /** The session/root signer — logical[1], signer, read-only. */
  signer: PublicKey;
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
   *  (never inside the payload). Either the dApp's own, or one default limit. */
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
  const decompiled = TransactionMessage.decompile(dappMsg, { addressLookupTableAccounts: luts });
  const allInner = decompiled.instructions;

  // ComputeBudget instructions are honored only top-level, never inside a CPI —
  // hoist any the dApp carries; add a default limit if it carries none.
  const cbId = ComputeBudgetProgram.programId;
  const computeBudgetIxs = allInner.filter((ix) => ix.programId.equals(cbId));
  const inner = allInner.filter((ix) => !ix.programId.equals(cbId));
  const hoisted =
    computeBudgetIxs.length > 0
      ? computeBudgetIxs
      : [ComputeBudgetProgram.setComputeUnitLimit({ units: opts.defaultComputeUnitLimit ?? DEFAULT_COMPUTE_UNIT_LIMIT })];

  // Dedup every account the inner instructions touch (their program ids too).
  // The PDA is forced non-signer (invoke_signed authorizes it); the signer's
  // flags are handled by the fixed prefix below. Both `smart_account` and
  // `signer`, if a dApp ix references them, are EXCLUDED from `remaining` (they
  // already have fixed logical slots 0/1) — keeping them would shift every later
  // index by one and corrupt the logical index space.
  const metas = new Map<string, { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }>();
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

  // The logical list: fixed prefix + remaining. smart_account is non-signer
  // writable; signer is signer read-only (the outer submitter). accountsHash and
  // payload indices are over THIS list.
  const logical: LogicalAccount[] = [
    { key: opts.smartAccount.toBytes(), isSigner: false, isWritable: true },
    { key: opts.signer.toBytes(), isSigner: true, isWritable: false },
    ...remaining.map((m) => ({ key: m.pubkey.toBytes(), isSigner: m.isSigner, isWritable: m.isWritable })),
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
      accounts: ix.keys.map((k) => ({
        index: idxOf(k.pubkey),
        // The PDA (index 0) is never writable to a CPI; a signer flag is honored
        // only on 0/1. Match the handler: force those here so encode succeeds and
        // the on-chain parser accepts the bytes.
        flags:
          (k.isSigner && !k.pubkey.equals(opts.smartAccount) && !k.pubkey.equals(opts.signer) ? 0 : k.isSigner ? FLAG_SIGNER : 0) |
          (k.isWritable && !k.pubkey.equals(opts.smartAccount) ? FLAG_WRITABLE : 0),
      })),
      data: Uint8Array.from(ix.data),
    })),
  };
  const payload = encodeExecutePayload(decoded);
  const accountsHash = computeAccountsHash(logical);

  return { payload, decoded, logical, remaining, accountsHash, computeBudgetIxs: hoisted };
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
